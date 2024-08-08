use std::{
    borrow::{Borrow, BorrowMut},
    cmp::min,
    io,
};

use thiserror::Error;
use zeroize::Zeroize;

use crate::{io::IoResultKindHintExt, result::ensure_or};

pub const HEADER_SIZE: usize = std::mem::size_of::<u64>();

#[derive(Error, Debug, Clone, Copy)]
#[error("Write position is out of buffer bounds")]
pub struct PositionOutOfBufferBounds;

#[derive(Error, Debug, Clone, Copy)]
#[error("Write position is out of message bounds")]
pub struct PositionOutOfMessageBounds;

#[derive(Error, Debug, Clone, Copy)]
#[error("Write position is out of header bounds")]
pub struct PositionOutOfHeaderBounds;

#[derive(Error, Debug, Clone, Copy)]
#[error("Message length is bigger than buffer length")]
pub struct MessageTooLarge;

#[derive(Error, Debug, Clone, Copy)]
pub enum MessageLenSanityError {
    #[error("{0:?}")]
    PositionOutOfMessageBounds(#[from] PositionOutOfMessageBounds),
    #[error("{0:?}")]
    MessageTooLarge(#[from] MessageTooLarge),
}

#[derive(Error, Debug, Clone, Copy)]
pub enum PositionSanityError {
    #[error("{0:?}")]
    PositionOutOfMessageBounds(#[from] PositionOutOfMessageBounds),
    #[error("{0:?}")]
    PositionOutOfBufferBounds(#[from] PositionOutOfBufferBounds),
}

#[derive(Error, Debug, Clone, Copy)]
pub enum SanityError {
    #[error("{0:?}")]
    PositionOutOfMessageBounds(#[from] PositionOutOfMessageBounds),
    #[error("{0:?}")]
    PositionOutOfBufferBounds(#[from] PositionOutOfBufferBounds),
    #[error("{0:?}")]
    MessageTooLarge(#[from] MessageTooLarge),
}

impl TryFrom<SanityError> for MessageLenSanityError {
    type Error = PositionOutOfBufferBounds;

    fn try_from(value: SanityError) -> Result<Self, Self::Error> {
        use {MessageLenSanityError as T, SanityError as F};
        match value {
            F::PositionOutOfMessageBounds(e) => Ok(T::PositionOutOfMessageBounds(e)),
            F::MessageTooLarge(e) => Ok(T::MessageTooLarge(e)),
            F::PositionOutOfBufferBounds(e) => Err(e),
        }
    }
}

impl From<MessageLenSanityError> for SanityError {
    fn from(value: MessageLenSanityError) -> Self {
        use {MessageLenSanityError as F, SanityError as T};
        match value {
            F::PositionOutOfMessageBounds(e) => T::PositionOutOfMessageBounds(e),
            F::MessageTooLarge(e) => T::MessageTooLarge(e),
        }
    }
}

impl From<PositionSanityError> for SanityError {
    fn from(value: PositionSanityError) -> Self {
        use {PositionSanityError as F, SanityError as T};
        match value {
            F::PositionOutOfBufferBounds(e) => T::PositionOutOfBufferBounds(e),
            F::PositionOutOfMessageBounds(e) => T::PositionOutOfMessageBounds(e),
        }
    }
}

pub struct WriteToIoReturn {
    pub bytes_written: usize,
    pub done: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct LengthPrefixEncoder<Buf: Borrow<[u8]>> {
    buf: Buf,
    header: [u8; HEADER_SIZE],
    pos: usize,
}

impl<Buf: Borrow<[u8]>> LengthPrefixEncoder<Buf> {
    pub fn from_buffer(buf: Buf) -> Self {
        let (header, pos) = ([0u8; HEADER_SIZE], 0);
        let mut r = Self { buf, header, pos };
        r.clear();
        r
    }

    pub fn from_message(msg: Buf) -> Self {
        let mut r = Self::from_buffer(msg);
        r.restart_write_with_new_message(r.buffer_bytes().len())
            .unwrap();
        r
    }

    pub fn from_short_message(msg: Buf, len: usize) -> Result<Self, MessageLenSanityError> {
        let mut r = Self::from_message(msg);
        r.set_message_len(len)?;
        Ok(r)
    }

    pub fn from_parts(buf: Buf, len: usize, pos: usize) -> Result<Self, SanityError> {
        let mut r = Self::from_buffer(buf);
        r.set_msg_len_and_position(len, pos)?;
        Ok(r)
    }

    pub fn into_buffer(self) -> Buf {
        let Self { buf, .. } = self;
        buf
    }

    pub fn into_parts(self) -> (Buf, usize, usize) {
        let len = self.message_len();
        let pos = self.writing_position();
        let buf = self.into_buffer();
        (buf, len, pos)
    }

    pub fn clear(&mut self) {
        self.set_msg_len_and_position(0, 0).unwrap();
        self.set_message_offset(0).unwrap();
    }

    pub fn write_all_to_stdio<W: io::Write>(&mut self, mut w: W) -> io::Result<()> {
        use io::ErrorKind as K;
        loop {
            match self.write_to_stdio(&mut w).io_err_kind_hint() {
                // Done
                Ok(WriteToIoReturn { done: true, .. }) => break Ok(()),

                // Retry
                Ok(WriteToIoReturn { done: false, .. }) => continue,
                Err((_, K::Interrupted)) => continue,

                Err((e, _)) => break Err(e),
            }
        }
    }

    pub fn write_to_stdio<W: io::Write>(&mut self, mut w: W) -> io::Result<WriteToIoReturn> {
        if self.exhausted() {
            return Ok(WriteToIoReturn {
                bytes_written: 0,
                done: true,
            });
        }

        let buf = self.next_slice_to_write();
        let bytes_written = w.write(buf)?;
        self.advance(bytes_written).unwrap();

        let done = self.exhausted();
        Ok(WriteToIoReturn {
            bytes_written,
            done,
        })
    }

    pub fn restart_write(&mut self) {
        self.set_writing_position(0).unwrap()
    }

    pub fn restart_write_with_new_message(
        &mut self,
        len: usize,
    ) -> Result<(), MessageLenSanityError> {
        self.set_msg_len_and_position(len, 0)
            .map_err(|e| e.try_into().unwrap())
    }

    pub fn next_slice_to_write(&self) -> &[u8] {
        let s = self.header_left();
        if !s.is_empty() {
            return s;
        }

        let s = self.message_left();
        if !s.is_empty() {
            return s;
        }

        &[]
    }

    pub fn exhausted(&self) -> bool {
        self.next_slice_to_write().is_empty()
    }

    pub fn message(&self) -> &[u8] {
        &self.buffer_bytes()[..self.message_len()]
    }

    pub fn header_written(&self) -> &[u8] {
        &self.header()[..self.header_offset()]
    }

    pub fn header_left(&self) -> &[u8] {
        &self.header()[self.header_offset()..]
    }

    pub fn message_written(&self) -> &[u8] {
        &self.message()[..self.message_offset()]
    }

    pub fn message_left(&self) -> &[u8] {
        &self.message()[self.message_offset()..]
    }

    pub fn buf(&self) -> &Buf {
        &self.buf
    }

    pub fn buffer_bytes(&self) -> &[u8] {
        self.buf().borrow()
    }

    pub fn decode_header(&self) -> u64 {
        u64::from_le_bytes(self.header)
    }

    pub fn header(&self) -> &[u8; HEADER_SIZE] {
        &self.header
    }

    pub fn message_len(&self) -> usize {
        self.decode_header() as usize
    }

    pub fn encoded_message_bytes(&self) -> usize {
        self.message_len() + HEADER_SIZE
    }

    pub fn writing_position(&self) -> usize {
        self.pos
    }

    pub fn header_offset(&self) -> usize {
        min(self.writing_position(), HEADER_SIZE)
    }

    pub fn message_offset(&self) -> usize {
        self.writing_position().saturating_sub(HEADER_SIZE)
    }

    pub fn set_header(&mut self, header: [u8; HEADER_SIZE]) -> Result<(), MessageLenSanityError> {
        self.offset_transaction(|t| {
            t.header = header;
            t.ensure_msg_in_buf_bounds()?;
            t.ensure_pos_in_msg_bounds()?;
            Ok(())
        })
    }

    pub fn encode_and_set_header(&mut self, header: u64) -> Result<(), MessageLenSanityError> {
        self.set_header(header.to_le_bytes())
    }

    pub fn set_message_len(&mut self, len: usize) -> Result<(), MessageLenSanityError> {
        self.encode_and_set_header(len as u64)
    }

    pub fn set_writing_position(&mut self, pos: usize) -> Result<(), PositionSanityError> {
        self.offset_transaction(|t| {
            t.pos = pos;
            t.ensure_pos_in_buf_bounds()?;
            t.ensure_pos_in_msg_bounds()?;
            Ok(())
        })
    }

    pub fn set_header_offset(&mut self, off: usize) -> Result<(), PositionOutOfHeaderBounds> {
        ensure_or(off <= HEADER_SIZE, PositionOutOfHeaderBounds)?;
        self.set_writing_position(off).unwrap();
        Ok(())
    }

    pub fn set_message_offset(&mut self, off: usize) -> Result<(), PositionSanityError> {
        self.set_writing_position(off + HEADER_SIZE)
    }

    pub fn advance(&mut self, off: usize) -> Result<(), PositionSanityError> {
        self.set_writing_position(self.writing_position() + off)
    }

    pub fn set_msg_len_and_position(&mut self, len: usize, pos: usize) -> Result<(), SanityError> {
        self.pos = 0;
        self.set_message_len(len)?;
        self.set_writing_position(pos)?;
        Ok(())
    }

    fn offset_transaction<E, F>(&mut self, f: F) -> Result<(), E>
    where
        F: FnOnce(&mut LengthPrefixEncoder<&[u8]>) -> Result<(), E>,
    {
        let (header, pos) = {
            let (buf, header, pos) = (self.buffer_bytes(), self.header, self.pos);
            let mut tmp = LengthPrefixEncoder { buf, header, pos };
            f(&mut tmp)?;
            Ok((tmp.header, tmp.pos))
        }?;
        (self.header, self.pos) = (header, pos);
        Ok(())
    }

    fn ensure_pos_in_buf_bounds(&self) -> Result<(), PositionOutOfBufferBounds> {
        ensure_or(
            self.message_offset() <= self.buffer_bytes().len(),
            PositionOutOfBufferBounds,
        )
    }

    fn ensure_pos_in_msg_bounds(&self) -> Result<(), PositionOutOfMessageBounds> {
        ensure_or(
            self.message_offset() <= self.message_len(),
            PositionOutOfMessageBounds,
        )
    }

    fn ensure_msg_in_buf_bounds(&self) -> Result<(), MessageTooLarge> {
        ensure_or(
            self.message_len() <= self.buffer_bytes().len(),
            MessageTooLarge,
        )
    }
}

impl<Buf: BorrowMut<[u8]>> LengthPrefixEncoder<Buf> {
    pub fn buf_mut(&mut self) -> &mut Buf {
        &mut self.buf
    }

    pub fn buffer_bytes_mut(&mut self) -> &mut [u8] {
        self.buf.borrow_mut()
    }

    pub fn message_mut(&mut self) -> &mut [u8] {
        let off = self.message_len();
        &mut self.buffer_bytes_mut()[..off]
    }

    pub fn message_written_mut(&mut self) -> &mut [u8] {
        let off = self.message_offset();
        &mut self.message_mut()[..off]
    }

    pub fn message_left_mut(&mut self) -> &mut [u8] {
        let off = self.message_offset();
        &mut self.message_mut()[off..]
    }
}

impl<Buf: BorrowMut<[u8]>> Zeroize for LengthPrefixEncoder<Buf> {
    fn zeroize(&mut self) {
        self.buffer_bytes_mut().zeroize();
        self.header.zeroize();
        self.pos.zeroize();
        self.clear();
    }
}
