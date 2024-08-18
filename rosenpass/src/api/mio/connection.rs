use std::borrow::{Borrow, BorrowMut};
use std::collections::VecDeque;
use std::os::fd::OwnedFd;

use mio::net::UnixStream;
use rosenpass_secret_memory::Secret;
use rosenpass_util::mio::ReadWithFileDescriptors;
use rosenpass_util::{
    io::{IoResultKindHintExt, TryIoResultKindHintExt},
    length_prefix_encoding::{
        decoder::{self as lpe_decoder, LengthPrefixDecoder},
        encoder::{self as lpe_encoder, LengthPrefixEncoder},
    },
    mio::interest::RW as MIO_RW,
};
use zeroize::Zeroize;

use crate::api::MAX_REQUEST_FDS;
use crate::{api::Server, app_server::AppServer};

use super::super::{ApiHandler, ApiHandlerContext};

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
// TODO: Unfortunately, zerocopy is quite particular about alignment, hence the 4096
type ReadBuffer = LengthPrefixDecoder<SecretBuffer<4096>>;
type WriteBuffer = LengthPrefixEncoder<SecretBuffer<4096>>;
type ReadFdBuffer = VecDeque<OwnedFd>;

#[derive(Debug)]
struct MioConnectionBuffers {
    read_buffer: ReadBuffer,
    write_buffer: WriteBuffer,
    read_fd_buffer: ReadFdBuffer,
}

#[derive(Debug)]
pub struct MioConnection {
    io: UnixStream,
    invalid_read: bool,
    buffers: Option<MioConnectionBuffers>,
    api_handler: ApiHandler,
}

impl MioConnection {
    pub fn new(app_server: &mut AppServer, mut io: UnixStream) -> std::io::Result<Self> {
        app_server.mio_poll.registry().register(
            &mut io,
            app_server.mio_token_dispenser.dispense(),
            MIO_RW,
        )?;

        let invalid_read = false;
        let read_buffer = LengthPrefixDecoder::new(SecretBuffer::new());
        let write_buffer = LengthPrefixEncoder::from_buffer(SecretBuffer::new());
        let read_fd_buffer = VecDeque::new();
        let buffers = Some(MioConnectionBuffers {
            read_buffer,
            write_buffer,
            read_fd_buffer,
        });
        let api_state = ApiHandler::new();
        Ok(Self {
            io,
            invalid_read,
            buffers,
            api_handler: api_state,
        })
    }

    pub fn shoud_close(&self) -> bool {
        let exhausted = self
            .buffers
            .as_ref()
            .map(|b| b.write_buffer.exhausted())
            .unwrap_or(false);
        self.invalid_read && exhausted
    }

    pub fn close(mut self, app_server: &mut AppServer) -> anyhow::Result<()> {
        app_server.mio_poll.registry().deregister(&mut self.io)?;
        Ok(())
    }
}

pub trait MioConnectionContext {
    fn mio_connection(&self) -> &MioConnection;
    fn app_server(&self) -> &AppServer;
    fn mio_connection_mut(&mut self) -> &mut MioConnection;
    fn app_server_mut(&mut self) -> &mut AppServer;

    fn poll(&mut self) -> anyhow::Result<()> {
        macro_rules! short {
            ($e:expr) => {
                match $e {
                    None => return Ok(()),
                    Some(()) => {}
                }
            };
        }

        // All of these functions return an error, None ("operation incomplete")
        // or some ("operation complete, keep processing")
        short!(self.flush_write_buffer()?); // Flush last message
        short!(self.recv()?); // Receive new message
        short!(self.handle_incoming_message()?); // Process new message with API
        short!(self.flush_write_buffer()?); // Begin flushing response

        Ok(())
    }

    fn handle_incoming_message(&mut self) -> anyhow::Result<Option<()>> {
        self.with_buffers_stolen(|this, bufs| {
            // Acquire request & response. Caller is responsible to make sure
            // that read buffer holds a message and that write buffer is cleared.
            // Hence the unwraps and assertions
            assert!(bufs.write_buffer.exhausted());
            let req = bufs.read_buffer.message().unwrap().unwrap();
            let req_fds = &mut bufs.read_fd_buffer;
            let res = bufs.write_buffer.buffer_bytes_mut();

            // Call API handler
            // Transitive trait implementations: MioConnectionContext -> ApiHandlerContext -> as ApiServer
            let response_len = this.handle_message(req, req_fds, res)?;

            bufs.write_buffer
                .restart_write_with_new_message(response_len)?;
            bufs.read_buffer.zeroize(); // clear for new message to read
            bufs.read_fd_buffer.clear();

            Ok(Some(()))
        })
    }

    fn flush_write_buffer(&mut self) -> anyhow::Result<Option<()>> {
        if self.write_buf_mut().exhausted() {
            return Ok(Some(()));
        }

        use lpe_encoder::WriteToIoReturn as Ret;
        use std::io::ErrorKind as K;

        loop {
            let conn = self.mio_connection_mut();
            let bufs = conn.buffers.as_mut().unwrap();

            let sock = &conn.io;
            let write_buf = &mut bufs.write_buffer;

            match write_buf.write_to_stdio(sock).io_err_kind_hint() {
                // Done
                Ok(Ret { done: true, .. }) => {
                    write_buf.zeroize(); // clear for new message to write
                    break Ok(Some(()));
                }

                // Would block
                Ok(Ret {
                    bytes_written: 0, ..
                }) => break Ok(None),
                Err((_e, K::WouldBlock)) => break Ok(None),

                // Just continue
                Ok(_) => continue, /* Ret { bytes_written > 0, done = false } acc. to previous cases*/
                Err((_e, K::Interrupted)) => continue,

                // Other errors
                Err((e, _ek)) => Err(e)?,
            }
        }
    }

    fn recv(&mut self) -> anyhow::Result<Option<()>> {
        if !self.write_buf_mut().exhausted() || self.mio_connection().invalid_read {
            return Ok(None);
        }

        use lpe_decoder::{ReadFromIoError as E, ReadFromIoReturn as Ret};
        use std::io::ErrorKind as K;

        loop {
            let conn = self.mio_connection_mut();
            let bufs = conn.buffers.as_mut().unwrap();

            let read_buf = &mut bufs.read_buffer;
            let read_fd_buf = &mut bufs.read_fd_buffer;

            let sock = &conn.io;
            let fd_passing_sock = ReadWithFileDescriptors::<MAX_REQUEST_FDS, UnixStream, _, _>::new(
                sock,
                read_fd_buf,
            );

            match read_buf
                .read_from_stdio(fd_passing_sock)
                .try_io_err_kind_hint()
            {
                // We actually received a proper message
                // (Impl below match to appease borrow checker)
                Ok(Ret {
                    message: Some(_msg),
                    ..
                }) => break Ok(Some(())),

                // Message does not fit in buffer
                Err((e @ E::MessageTooLargeError { .. }, _)) => {
                    log::warn!("Received message on API that was too big to fit in our buffers; \
                            looks like the client is broken. Stopping to process messages of the client.\n\
                            Error: {e:?}");
                    conn.invalid_read = true; // Closed mio_manager
                    break Ok(None);
                }

                // Would block
                Ok(Ret { bytes_read: 0, .. }) => break Ok(None),
                Err((_, Some(K::WouldBlock))) => break Ok(None),

                // Just keep going
                Ok(Ret { bytes_read: _, .. }) => continue,
                Err((_, Some(K::Interrupted))) => continue,

                // Other IO Error (just pass on to the caller)
                Err((E::IoError(e), _)) => {
                    log::warn!(
                        "IO error while trying to read message from API socket. \
                            The connection is broken. Stopping to process messages of the client.\n\
                            Error: {e:?}"
                    );
                    conn.invalid_read = true; // closed later by mio_manager
                    break Err(e.into());
                }
            };
        }
    }
}

trait MioConnectionContextPrivate: MioConnectionContext {
    fn steal_buffers(&mut self) -> MioConnectionBuffers {
        self.mio_connection_mut().buffers.take().unwrap()
    }

    fn return_buffers(&mut self, buffers: MioConnectionBuffers) {
        let opt = &mut self.mio_connection_mut().buffers;
        assert!(opt.is_none());
        let _ = opt.insert(buffers);
    }

    fn with_buffers_stolen<R, F: FnOnce(&mut Self, &mut MioConnectionBuffers) -> R>(
        &mut self,
        f: F,
    ) -> R {
        let mut bufs = self.steal_buffers();
        let res = f(self, &mut bufs);
        self.return_buffers(bufs);
        res
    }

    fn write_buf_mut(&mut self) -> &mut WriteBuffer {
        self.mio_connection_mut()
            .buffers
            .as_mut()
            .unwrap()
            .write_buffer
            .borrow_mut()
    }
}

impl<T> MioConnectionContextPrivate for T where T: ?Sized + MioConnectionContext {}

impl<T> ApiHandlerContext for T
where
    T: ?Sized + MioConnectionContext,
{
    fn api_handler(&self) -> &ApiHandler {
        &self.mio_connection().api_handler
    }

    fn app_server(&self) -> &AppServer {
        MioConnectionContext::app_server(self)
    }

    fn api_handler_mut(&mut self) -> &mut ApiHandler {
        &mut self.mio_connection_mut().api_handler
    }

    fn app_server_mut(&mut self) -> &mut AppServer {
        MioConnectionContext::app_server_mut(self)
    }
}
