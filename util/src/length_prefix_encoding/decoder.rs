use std::{borrow::BorrowMut, cmp::min, io};

use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    io::{TryIoErrorKind, TryIoResultKindHintExt},
    result::ensure_or,
};

pub const HEADER_SIZE: usize = std::mem::size_of::<u64>();

#[derive(Error, Debug)]
pub enum SanityError {
    #[error("Offset is out of read buffer bounds")]
    OutOfBufferBounds,
    #[error("Offset is out of message buffer bounds")]
    OutOfMessageBounds,
}

#[derive(Error, Debug)]
#[error("Message too large ({msg_size} bytes) for buffer ({buf_size} bytes)")]
pub struct MessageTooLargeError {
    msg_size: usize,
    buf_size: usize,
}

impl MessageTooLargeError {
    pub fn new(msg_size: usize, buf_size: usize) -> Self {
        Self { msg_size, buf_size }
    }

    pub fn ensure(msg_size: usize, buf_size: usize) -> Result<(), Self> {
        let err = MessageTooLargeError { msg_size, buf_size };
        ensure_or(msg_size <= buf_size, err)
    }
}

#[derive(Debug)]
pub struct ReadFromIoReturn<'a> {
    pub bytes_read: usize,
    pub message: Option<&'a mut [u8]>,
}

impl<'a> ReadFromIoReturn<'a> {
    pub fn new(bytes_read: usize, message: Option<&'a mut [u8]>) -> Self {
        Self {
            bytes_read,
            message,
        }
    }
}

#[derive(Debug, Error)]
pub enum ReadFromIoError {
    #[error("Error reading from the underlying stream")]
    IoError(#[from] io::Error),
    #[error("Message size out of buffer bounds")]
    MessageTooLargeError(#[from] MessageTooLargeError),
}

impl TryIoErrorKind for ReadFromIoError {
    fn try_io_error_kind(&self) -> Option<io::ErrorKind> {
        match self {
            ReadFromIoError::IoError(ioe) => Some(ioe.kind()),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct LengthPrefixDecoder<Buf: BorrowMut<[u8]>> {
    header: [u8; HEADER_SIZE],
    buf: Buf,
    off: usize,
}

impl<Buf: BorrowMut<[u8]>> LengthPrefixDecoder<Buf> {
    pub fn new(buf: Buf) -> Self {
        let header = Default::default();
        let off = 0;
        Self { header, buf, off }
    }

    pub fn clear(&mut self) {
        self.zeroize()
    }

    pub fn from_parts(header: [u8; HEADER_SIZE], buf: Buf, off: usize) -> Self {
        Self { header, buf, off }
    }

    pub fn into_parts(self) -> ([u8; HEADER_SIZE], Buf, usize) {
        let Self { header, buf, off } = self;
        (header, buf, off)
    }

    pub fn read_all_from_stdio<R: io::Read>(
        &mut self,
        mut r: R,
    ) -> Result<&mut [u8], ReadFromIoError> {
        use io::ErrorKind as K;
        loop {
            match self.read_from_stdio(&mut r).try_io_err_kind_hint() {
                // Success (appeasing the borrow checker by calling message_mut())
                Ok(ReadFromIoReturn {
                    message: Some(_), ..
                }) => break Ok(self.message_mut().unwrap().unwrap()),

                // Unexpected EOF
                Ok(ReadFromIoReturn { bytes_read: 0, .. }) => {
                    break Err(ReadFromIoError::IoError(io::Error::new(
                        K::UnexpectedEof,
                        "",
                    )))
                }

                // Retry
                Ok(ReadFromIoReturn { message: None, .. }) => continue,
                Err((_, Some(K::Interrupted))) => continue,

                // Other error
                Err((e, _)) => break Err(e),
            }
        }
    }

    pub fn read_from_stdio<R: io::Read>(
        &mut self,
        mut r: R,
    ) -> Result<ReadFromIoReturn, ReadFromIoError> {
        Ok(match self.next_slice_to_write_to()? {
            // Read some bytes; any MessageTooLargeError in the call to self.message_mut() is
            // ignored to ensure this function changes no state upon errors; the user should rerun
            // the function and collect the MessageTooLargeError on the following invocation
            Some(buf) => {
                let bytes_read = r.read(buf)?;
                self.advance(bytes_read).unwrap();
                let message = self.message_mut().ok().flatten();
                ReadFromIoReturn {
                    bytes_read,
                    message,
                }
            }
            // Message is already fully read; full delegation to self.message_mut()
            None => ReadFromIoReturn {
                bytes_read: 0,
                message: self.message_mut()?,
            },
        })
    }

    pub fn next_slice_to_write_to(&mut self) -> Result<Option<&mut [u8]>, MessageTooLargeError> {
        fn some_if_nonempty(buf: &mut [u8]) -> Option<&mut [u8]> {
            match buf.is_empty() {
                true => None,
                false => Some(buf),
            }
        }

        macro_rules! return_if_nonempty_some {
            ($opt:expr) => {{
                // Deliberate double expansion of $opt to appease the borrow checker *sigh*
                if $opt.and_then(some_if_nonempty).is_some() {
                    return Ok($opt);
                }
            }};
        }

        return_if_nonempty_some!(Some(self.header_buffer_left_mut()));
        return_if_nonempty_some!(self.message_fragment_left_mut()?);
        Ok(None)
    }

    pub fn advance(&mut self, count: usize) -> Result<(), SanityError> {
        let off = self.off + count;
        let msg_off = off.saturating_sub(HEADER_SIZE);

        use SanityError as E;
        let alloc = self.message_buffer().len();
        let msgsz = self.message_size();
        ensure_or(msg_off <= alloc, E::OutOfBufferBounds)?;
        ensure_or(
            msgsz.map(|s| msg_off <= s).unwrap_or(true),
            E::OutOfMessageBounds,
        )?;

        self.off = off;
        Ok(())
    }

    pub fn ensure_sufficient_msg_buffer(&self) -> Result<(), MessageTooLargeError> {
        let buf_size = self.message_buffer().len();
        let msg_size = match self.get_header() {
            None => return Ok(()),
            Some(v) => v,
        };
        MessageTooLargeError::ensure(msg_size, buf_size)
    }

    pub fn header_buffer(&self) -> &[u8] {
        &self.header[..]
    }

    pub fn header_buffer_mut(&mut self) -> &mut [u8] {
        &mut self.header[..]
    }

    pub fn message_buffer(&self) -> &[u8] {
        self.buf.borrow()
    }

    pub fn message_buffer_mut(&mut self) -> &mut [u8] {
        self.buf.borrow_mut()
    }

    pub fn bytes_read(&self) -> &usize {
        &self.off
    }

    pub fn into_message_buffer(self) -> Buf {
        let Self { buf, .. } = self;
        buf
    }

    pub fn header_buffer_offset(&self) -> usize {
        min(self.off, HEADER_SIZE)
    }

    pub fn message_buffer_offset(&self) -> usize {
        self.off.saturating_sub(HEADER_SIZE)
    }

    pub fn has_header(&self) -> bool {
        self.header_buffer_offset() == HEADER_SIZE
    }

    pub fn has_message(&self) -> Result<bool, MessageTooLargeError> {
        self.ensure_sufficient_msg_buffer()?;
        let msg_size = match self.get_header() {
            None => return Ok(false),
            Some(v) => v,
        };
        Ok(self.message_buffer_avail().len() == msg_size)
    }

    pub fn header_buffer_avail(&self) -> &[u8] {
        let off = self.header_buffer_offset();
        &self.header_buffer()[..off]
    }

    pub fn header_buffer_avail_mut(&mut self) -> &mut [u8] {
        let off = self.header_buffer_offset();
        &mut self.header_buffer_mut()[..off]
    }

    pub fn header_buffer_left(&self) -> &[u8] {
        let off = self.header_buffer_offset();
        &self.header_buffer()[off..]
    }

    pub fn header_buffer_left_mut(&mut self) -> &mut [u8] {
        let off = self.header_buffer_offset();
        &mut self.header_buffer_mut()[off..]
    }

    pub fn message_buffer_avail(&self) -> &[u8] {
        let off = self.message_buffer_offset();
        &self.message_buffer()[..off]
    }

    pub fn message_buffer_avail_mut(&mut self) -> &mut [u8] {
        let off = self.message_buffer_offset();
        &mut self.message_buffer_mut()[..off]
    }

    pub fn message_buffer_left(&self) -> &[u8] {
        let off = self.message_buffer_offset();
        &self.message_buffer()[off..]
    }

    pub fn message_buffer_left_mut(&mut self) -> &mut [u8] {
        let off = self.message_buffer_offset();
        &mut self.message_buffer_mut()[off..]
    }

    pub fn get_header(&self) -> Option<usize> {
        match self.header_buffer_offset() == HEADER_SIZE {
            false => None,
            true => Some(u64::from_le_bytes(self.header) as usize),
        }
    }

    pub fn message_size(&self) -> Option<usize> {
        self.get_header()
    }

    pub fn encoded_message_bytes(&self) -> Option<usize> {
        self.message_size().map(|sz| sz + HEADER_SIZE)
    }

    pub fn message_fragment(&self) -> Result<Option<&[u8]>, MessageTooLargeError> {
        self.ensure_sufficient_msg_buffer()?;
        Ok(self.message_size().map(|sz| &self.message_buffer()[..sz]))
    }

    pub fn message_fragment_mut(&mut self) -> Result<Option<&mut [u8]>, MessageTooLargeError> {
        self.ensure_sufficient_msg_buffer()?;
        Ok(self
            .message_size()
            .map(|sz| &mut self.message_buffer_mut()[..sz]))
    }

    pub fn message_fragment_avail(&self) -> Result<Option<&[u8]>, MessageTooLargeError> {
        let off = self.message_buffer_avail().len();
        self.message_fragment()
            .map(|frag| frag.map(|frag| &frag[..off]))
    }

    pub fn message_fragment_avail_mut(
        &mut self,
    ) -> Result<Option<&mut [u8]>, MessageTooLargeError> {
        let off = self.message_buffer_avail().len();
        self.message_fragment_mut()
            .map(|frag| frag.map(|frag| &mut frag[..off]))
    }

    pub fn message_fragment_left(&self) -> Result<Option<&[u8]>, MessageTooLargeError> {
        let off = self.message_buffer_avail().len();
        self.message_fragment()
            .map(|frag| frag.map(|frag| &frag[off..]))
    }

    pub fn message_fragment_left_mut(&mut self) -> Result<Option<&mut [u8]>, MessageTooLargeError> {
        let off = self.message_buffer_avail().len();
        self.message_fragment_mut()
            .map(|frag| frag.map(|frag| &mut frag[off..]))
    }

    pub fn message(&self) -> Result<Option<&[u8]>, MessageTooLargeError> {
        let sz = self.message_size();
        self.message_fragment_avail()
            .map(|frag_opt| frag_opt.and_then(|frag| (frag.len() == sz?).then_some(frag)))
    }

    pub fn message_mut(&mut self) -> Result<Option<&mut [u8]>, MessageTooLargeError> {
        let sz = self.message_size();
        self.message_fragment_avail_mut()
            .map(|frag_opt| frag_opt.and_then(|frag| (frag.len() == sz?).then_some(frag)))
    }
}

impl<Buf: BorrowMut<[u8]>> Zeroize for LengthPrefixDecoder<Buf> {
    fn zeroize(&mut self) {
        self.header.zeroize();
        self.message_buffer_mut().zeroize();
        self.off.zeroize();
    }
}
