//! Blocking version of  [`MioFdStream`].

use std::{io, net::Shutdown, os::fd::BorrowedFd};

use mio::{Events, Interest, Poll, Token};

use super::{MioFdStream, ShmStreamError};
use crate::internal::util::{
    functional::ApplyExt,
    io::{
        TryIoErrorKind,
        fd_stream::{FdPassingStream, ReadWithFdsResult},
        handle_interrupted,
    },
};

/// Event batch capacity; the facade only needs to know that a hint arrived.
const EVENTS_CAPACITY: usize = 8;

/// An owned, secure shared-memory byte stream with
#[derive(Debug)]
pub struct SyncFdStream {
    stream: MioFdStream,
    poll: Poll,
    events: Events,
}

impl SyncFdStream {
    /// Wrap a [MioFdStream], registering it with a private mio poll for blocking IO
    pub fn from_mio_fd_stream(stream: MioFdStream) -> io::Result<Self> {
        /// Private composite token: every delivered event is only a retry hint.
        const TOKEN: Token = Token(0);

        let poll = Poll::new()?;
        let mut stream = stream;
        poll.registry().register(
            &mut stream,
            TOKEN,
            Interest::READABLE.add(Interest::WRITABLE),
        )?;
        Ok(Self {
            stream,
            poll,
            events: Events::with_capacity(EVENTS_CAPACITY),
        })
    }

    /// Shut down the stream in the given direction; see [MioFdStream::shutdown].
    #[allow(dead_code)] // kept on human request (unused for now)
    pub fn shutdown(&mut self, direction: Shutdown) -> io::Result<()> {
        self.stream.shutdown(direction)
    }

    /// Wait for a retry hint after a `WouldBlock` attempt.
    fn wait(&mut self) -> Result<(), ShmStreamError> {
        let Err(err) = handle_interrupted(|| self.poll.poll(&mut self.events, None)) else {
            return Ok(());
        };

        let err = err
            .raw_os_error()
            .map(rustix::io::Errno::from_raw_os_error)
            .unwrap_or(rustix::io::Errno::IO)
            .apply(ShmStreamError::Io);

        Err(err)
    }
}

impl FdPassingStream for SyncFdStream {
    type ReadError = ShmStreamError;
    type WriteError = ShmStreamError;
    type ReadConfig = ();
    type WriteConfig = ();

    fn read_with_fds_config(
        &mut self,
        dst: &mut [u8],
        max_new_fds: usize,
        _config: (),
    ) -> Result<ReadWithFdsResult, Self::ReadError> {
        if dst.is_empty() {
            return Ok(ReadWithFdsResult::empty());
        }
        loop {
            match handle_interrupted(|| self.stream.read_with_fds(dst, max_new_fds)) {
                Err(error) if error.try_io_error_kind() == Some(io::ErrorKind::WouldBlock) => {
                    self.wait()?;
                }
                other => return other,
            }
        }
    }

    fn write_with_fds_config(
        &mut self,
        src: &[u8],
        fds: &[BorrowedFd<'_>],
        _config: (),
    ) -> Result<usize, Self::WriteError> {
        if src.is_empty() {
            return Ok(0);
        }
        loop {
            match handle_interrupted(|| self.stream.write_with_fds(src, fds)) {
                Err(error) if error.try_io_error_kind() == Some(io::ErrorKind::WouldBlock) => {
                    self.wait()?;
                }
                other => return other,
            }
        }
    }
}
