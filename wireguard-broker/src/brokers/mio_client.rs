use anyhow::{bail, Context};
use mio::Interest;
use rosenpass_secret_memory::Secret;
use rosenpass_to::{ops::copy_slice_least_src, To};
use rosenpass_util::io::{IoResultKindHintExt, TryIoResultKindHintExt};
use rosenpass_util::length_prefix_encoding::decoder::LengthPrefixDecoder;
use rosenpass_util::length_prefix_encoding::encoder::LengthPrefixEncoder;
use std::borrow::{Borrow, BorrowMut};
use std::os::fd::AsFd;

use crate::api::client::{
    BrokerClient, BrokerClientIo, BrokerClientPollResponseError, BrokerClientSetPskError,
};
use crate::{SerializedBrokerConfig, WireGuardBroker, WireguardBrokerMio};

#[derive(Debug)]
pub struct MioBrokerClient {
    inner: BrokerClient<MioBrokerClientIo>,
    mio_token: Option<mio::Token>,
}

#[derive(Debug)]
struct SecretBuffer<const N: usize>(pub Secret<N>);

impl<const N: usize> SecretBuffer<N> {
    fn new() -> Self {
        Self(Secret::zero())
    }
}

impl<const N: usize> Borrow<[u8]> for SecretBuffer<N> {
    fn borrow(&self) -> &[u8] {
        self.0.secret()
    }
}

impl<const N: usize> BorrowMut<[u8]> for SecretBuffer<N> {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.0.secret_mut()
    }
}

type ReadBuffer = LengthPrefixDecoder<SecretBuffer<4096>>;
type WriteBuffer = LengthPrefixEncoder<SecretBuffer<4096>>;

#[derive(Debug)]
struct MioBrokerClientIo {
    socket: mio::net::UnixStream,
    read_buffer: ReadBuffer,
    write_buffer: WriteBuffer,
}

impl MioBrokerClient {
    pub fn new(socket: mio::net::UnixStream) -> Self {
        let read_buffer = LengthPrefixDecoder::new(SecretBuffer::new());
        let write_buffer = LengthPrefixEncoder::from_buffer(SecretBuffer::new());
        let io = MioBrokerClientIo {
            socket,
            read_buffer,
            write_buffer,
        };
        let inner = BrokerClient::new(io);
        Self {
            inner,
            mio_token: None,
        }
    }

    fn poll(&mut self) -> anyhow::Result<()> {
        self.inner.io_mut().flush()?;

        // This sucks
        let res = self.inner.poll_response();
        match res {
            Ok(None) => Ok(()),
            Ok(Some(Ok(()))) => Ok(()),
            Ok(Some(Err(e))) => {
                log::warn!("Error from PSK broker: {e:?}");
                Ok(())
            }
            Err(BrokerClientPollResponseError::IoError(e)) => Err(e),
            Err(BrokerClientPollResponseError::InvalidMessage) => bail!("Invalid message"),
        }
    }
}

impl WireGuardBroker for MioBrokerClient {
    type Error = anyhow::Error;

    fn set_psk(&mut self, config: SerializedBrokerConfig<'_>) -> anyhow::Result<()> {
        use BrokerClientSetPskError::*;
        let e = self.inner.set_psk(config);
        match e {
            Ok(()) => Ok(()),
            Err(IoError(e)) => Err(e),
            Err(IfaceOutOfBounds) => bail!("Interface name size is out of bounds."),
            Err(MsgError) => bail!("Error with encoding/decoding message."),
            Err(BrokerError(e)) => bail!("Broker error: {:?}", e),
        }
    }
}

impl WireguardBrokerMio for MioBrokerClient {
    type MioError = anyhow::Error;

    fn register(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
    ) -> Result<(), Self::MioError> {
        self.mio_token = Some(token);
        registry.register(
            &mut self.inner.io_mut().socket,
            token,
            Interest::READABLE | Interest::WRITABLE,
        )?;
        Ok(())
    }

    fn process_poll(&mut self) -> Result<(), Self::MioError> {
        self.poll()?;
        Ok(())
    }

    fn unregister(&mut self, registry: &mio::Registry) -> Result<(), Self::MioError> {
        self.mio_token = None;
        registry.deregister(&mut self.inner.io_mut().socket)?;
        Ok(())
    }

    fn mio_token(&self) -> Option<mio::Token> {
        self.mio_token
    }
}

impl BrokerClientIo for MioBrokerClientIo {
    type SendError = anyhow::Error;
    type RecvError = anyhow::Error;

    fn send_msg(&mut self, buf: &[u8]) -> Result<(), Self::SendError> {
        // Clear write buffer (blocking write)
        self.flush_blocking()?;
        assert!(self.write_buffer.exhausted(), "flush_blocking() should have put the write buffer in exhausted state. Developer error!");

        // Emplace new message in write buffer
        copy_slice_least_src(buf).to(self.write_buffer.buffer_bytes_mut());
        self.write_buffer
            .restart_write_with_new_message(buf.len())?;

        // Give the write buffer a chance to clear
        self.flush()?;

        Ok(())
    }

    fn recv_msg(&mut self) -> Result<Option<&[u8]>, Self::RecvError> {
        use std::io::ErrorKind as K;
        loop {
            match self
                .read_buffer
                .read_from_stdio(&self.socket)
                .try_io_err_kind_hint()
            {
                Ok(_) => {} // Moved down in the loop
                Err((_, Some(K::WouldBlock))) => break Ok(None),
                Err((_, Some(K::Interrupted))) => continue,
                Err((e, _)) => break Err(e)?,
            }

            // OK case moved here to appease borrow checker
            break Ok(self.read_buffer.message()?);
        }
    }
}

impl MioBrokerClientIo {
    fn flush_blocking(&mut self) -> anyhow::Result<()> {
        self.flush()?;
        if self.write_buffer.exhausted() {
            return Ok(());
        }

        log::warn!("Could not flush PSK broker write buffer in non-blocking mode. Flushing in blocking mode!");
        use rustix::io::{fcntl_getfd, fcntl_setfd, FdFlags};

        // Build O_NONBLOCK
        let o_nonblock = {
            let v = libc::O_NONBLOCK;
            let v = v.try_into().context(
                "Could not cast O_NONBLOCK (`{v}`) from libc int (i32?) to rustix int (u32?)",
            )?;
            FdFlags::from_bits(v).context(
                "Could not cast O_NONBLOCK (`{v}`) from rustix int to rustix::io::FdFlags",
            )?
        };

        // Determine previous and new file descriptor flags
        let flags_orig = fcntl_getfd(self.socket.as_fd())?;
        let mut flags_blocking = flags_orig;
        flags_blocking.insert(o_nonblock);

        // Set file descriptor flags
        fcntl_setfd(self.socket.as_fd(), flags_blocking)?;

        // Blocking write
        let res = loop {
            if self.write_buffer.exhausted() {
                break Ok(());
            }

            match self.flush() {
                Ok(_) => {}
                Err(e) => break Err(e),
            }
        };

        // Restore file descriptor flags
        fcntl_setfd(self.socket.as_fd(), flags_orig)?;

        Ok(res?)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        use std::io::ErrorKind as K;
        loop {
            match self
                .write_buffer
                .write_to_stdio(&self.socket)
                .io_err_kind_hint()
            {
                Ok(_) => break Ok(()),
                Err((_, K::WouldBlock)) => break Ok(()),
                Err((_, K::Interrupted)) => continue,
                Err((e, _)) => return Err(e)?,
            }
        }
    }
}
