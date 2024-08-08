use mio::{net::UnixStream, Interest};
use rosenpass_util::{
    io::{IoResultKindHintExt, TryIoResultKindHintExt},
    length_prefix_encoding::{
        decoder::{self as lpe_decoder, LengthPrefixDecoder},
        encoder::{self as lpe_encoder, LengthPrefixEncoder},
    },
};
use zeroize::Zeroize;

use crate::{api::Server, app_server::MioTokenDispenser, protocol::CryptoServer};

use super::super::{CryptoServerApiState, MAX_REQUEST_LEN, MAX_RESPONSE_LEN};

#[derive(Debug)]
pub struct MioConnection {
    io: UnixStream,
    invalid_read: bool,
    read_buffer: LengthPrefixDecoder<[u8; MAX_REQUEST_LEN]>,
    write_buffer: LengthPrefixEncoder<[u8; MAX_RESPONSE_LEN]>,
    api_state: CryptoServerApiState,
}

impl MioConnection {
    pub fn new(
        mut io: UnixStream,
        registry: &mio::Registry,
        token_dispenser: &mut MioTokenDispenser, // TODO: We should actually start using tokens…
    ) -> std::io::Result<Self> {
        registry.register(
            &mut io,
            token_dispenser.dispense(),
            Interest::READABLE | Interest::WRITABLE,
        )?;

        let invalid_read = false;
        let read_buffer = LengthPrefixDecoder::new([0u8; MAX_REQUEST_LEN]);
        let write_buffer = LengthPrefixEncoder::from_buffer([0u8; MAX_RESPONSE_LEN]);
        let api_state = CryptoServerApiState::new();
        Ok(Self {
            io,
            invalid_read,
            read_buffer,
            write_buffer,
            api_state,
        })
    }

    pub fn poll(&mut self, crypto: &mut Option<CryptoServer>) -> anyhow::Result<()> {
        self.flush_write_buffer()?;
        if self.write_buffer.exhausted() {
            self.recv(crypto)?;
        }
        Ok(())
    }

    // This is *exclusively* called by recv if the read_buffer holds a message
    fn handle_incoming_message(&mut self, crypto: &mut Option<CryptoServer>) -> anyhow::Result<()> {
        // Unwrap is allowed because recv() confirms before the call that a message was
        // received
        let req = self.read_buffer.message().unwrap().unwrap();

        // TODO: The API should not return anyhow::Result
        let response_len = self
            .api_state
            .acquire_backend(crypto)
            .handle_message(req, self.write_buffer.buffer_bytes_mut())?;
        self.read_buffer.zeroize(); // clear for new message to read
        self.write_buffer
            .restart_write_with_new_message(response_len)?;

        self.flush_write_buffer()?;
        Ok(())
    }

    fn flush_write_buffer(&mut self) -> anyhow::Result<()> {
        if self.write_buffer.exhausted() {
            return Ok(());
        }

        loop {
            use lpe_encoder::WriteToIoReturn as Ret;
            use std::io::ErrorKind as K;

            match self
                .write_buffer
                .write_to_stdio(&self.io)
                .io_err_kind_hint()
            {
                // Done
                Ok(Ret { done: true, .. }) => {
                    self.write_buffer.zeroize(); // clear for new message to write
                    break;
                }

                // Would block
                Ok(Ret {
                    bytes_written: 0, ..
                }) => break,
                Err((_e, K::WouldBlock)) => break,

                // Just continue
                Ok(_) => continue, /* Ret { bytes_written > 0, done = false } acc. to previous cases*/
                Err((_e, K::Interrupted)) => continue,

                // Other errors
                Err((e, _ek)) => Err(e)?,
            }
        }

        Ok(())
    }

    fn recv(&mut self, crypto: &mut Option<CryptoServer>) -> anyhow::Result<()> {
        if !self.write_buffer.exhausted() || self.invalid_read {
            return Ok(());
        }

        loop {
            use lpe_decoder::{ReadFromIoError as E, ReadFromIoReturn as Ret};
            use std::io::ErrorKind as K;

            match self
                .read_buffer
                .read_from_stdio(&self.io)
                .try_io_err_kind_hint()
            {
                // We actually received a proper message
                // (Impl below match to appease borrow checker)
                Ok(Ret {
                    message: Some(_msg),
                    ..
                }) => {}

                // Message does not fit in buffer
                Err((e @ E::MessageTooLargeError { .. }, _)) => {
                    log::warn!("Received message on API that was too big to fit in our buffers; \
                        looks like the client is broken. Stopping to process messages of the client.\n\
                        Error: {e:?}");
                    // TODO: We should properly close down the socket in this case, but to do that,
                    // we need to have the facilities in the Rosenpass IO handling system to close
                    // open connections.
                    // Just leaving the API connections dangling for now.
                    // This should be fixed for non-experimental use of the API.
                    self.invalid_read = true;
                    break;
                }

                // Would block
                Ok(Ret { bytes_read: 0, .. }) => break,
                Err((_, Some(K::WouldBlock))) => break,

                // Just keep going
                Ok(Ret { bytes_read: _, .. }) => continue,
                Err((_, Some(K::Interrupted))) => continue,

                // Other IO Error (just pass on to the caller)
                Err((E::IoError(e), _)) => Err(e)?,
            };

            self.handle_incoming_message(crypto)?;
            break; // Handle just one message, leave some room for other IO handlers
        }

        Ok(())
    }
}
