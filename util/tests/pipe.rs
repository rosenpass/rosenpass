#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    any::type_name,
    cell::Cell,
    ffi::c_void,
    ops::Range,
    os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
    ptr::{null, null_mut, read_volatile, write_volatile},
    sync::{atomic::AtomicU64, Arc},
    thread,
};

struct Foo {

}

use rosenpass_util::functional::MutatingExt;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

macro_rules! dbg_print {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        //writeln!(stderr, $($arg)*).unwrap()
    }}
}

type Usize64 = u64;
static_assertions::const_assert!(Usize64::BITS >= usize::BITS);
static_assertions::const_assert!(Usize64::BITS >= u64::BITS);

fn errno() -> rustix::io::Errno {
    rustix::io::Errno::from_raw_os_error(errno::errno().0)
}

fn memfd_secret(flags: i32) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
    unsafe {
        use libc::{syscall, SYS_memfd_secret};
        syscall(SYS_memfd_secret, flags)
            .into_type::<SyscallResult>()
            .claim_fd()
    }
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SyscallResult(pub libc::c_long);

impl SyscallResult {
    pub fn raw_value(&self) -> libc::c_long {
        self.0
    }

    /// # Safety
    ///
    /// TODO…
    pub unsafe fn claim_fd(&self) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
        let fde = self.0;
        match fde {
            e if e < 0 => Err(errno()),
            fd if fd > i32::MAX.into() => panic!("File descriptor `{fd}` is out of bounds: "),
            fd => Ok(unsafe { rustix::fd::OwnedFd::from_raw_fd(fd as i32) }),
        }
    }
}

impl From<libc::c_long> for SyscallResult {
    fn from(value: libc::c_long) -> Self {
        Self(value)
    }
}

pub struct MappableFd {
    fd: OwnedFd,
    len: Cell<Option<u64>>,
}

impl MappableFd {
    pub fn memfd_secret(size: u64, flags: i32) -> rustix::io::Result<Self> {
        let me = Self::new(memfd_secret(flags)?);
        me.resize(size)?;
        Ok(me)
    }

    pub fn new(fd: OwnedFd) -> Self {
        Self {
            fd,
            len: Cell::new(None),
        }
    }

    pub fn size(&self) -> rustix::io::Result<u64> {
        if let Some(len) = self.len.get() {
            return Ok(len);
        }

        let len = self.determine_size()?;
        self.len.set(Some(len));
        Ok(len)
    }

    pub fn fd(&self) -> rustix::fd::BorrowedFd {
        self.fd.as_fd()
    }

    pub fn into_fd(self) -> rustix::fd::OwnedFd {
        self.fd
    }

    pub fn resize(&self, len: u64) -> rustix::io::Result<()> {
        rustix::fs::ftruncate(self.fd(), len)?;
        self.len.set(Some(len));
        Ok(())
    }

    pub fn determine_size(&self) -> rustix::io::Result<u64> {
        use rustix::fs::{seek, tell, SeekFrom};
        let pos = tell(self.fd())?;
        let len = seek(self.fd(), SeekFrom::End(0))?;
        seek(self.fd(), SeekFrom::Start(pos))?;
        Ok(len)
    }

    pub fn map_into_memory_raw(&self) -> rustix::io::Result<*mut c_void> {
        use rustix::mm::{mmap, MapFlags as M, ProtFlags as P};
        let len = self.size()?.try_into().unwrap();
        let ptr = unsafe {
            // TODO: Use MAP_SHARED_VALIDATE
            mmap(null_mut(), len, P::READ | P::WRITE, M::SHARED, self.fd(), 0)
        }?;
        Ok(ptr)
    }

    pub fn map_into_memory(&self) -> rustix::io::Result<MappedRegion> {
        use rustix::mm::{mmap, MapFlags as M, ProtFlags as P};
        let len = self.size()?.try_into().unwrap();
        let ptr = unsafe {
            // TODO: Use MAP_SHARED_VALIDATE
            mmap(null_mut(), len, P::READ | P::WRITE, M::SHARED, self.fd(), 0)
        }?
        .cast();
        let region = unsafe { MappedRegion::new(ptr, len) };
        Ok(region)
    }
}

pub struct MappedRegion {
    ptr: *mut u8,
    len: usize,
}

impl MappedRegion {
    pub unsafe fn new(ptr: *mut u8, len: usize) -> Self {
        Self { ptr, len }
    }

    pub fn ptr(&self) -> *mut u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn read(&self, dst: &mut [u8], off: usize) {
        dbg_print!("MappedRegion::read(off={off:?}, dst={dst:?})");

        let end = off + dst.len();
        assert!(end <= self.len());

        for (idx, dst) in dst.iter_mut().enumerate() {
            *dst = unsafe { self.ptr.add(off).add(idx).read_volatile() };
        }

        dbg_print!("    MappedRegion::read(…) -> {dst:?}");
    }

    pub fn write(&self, off: usize, src: &[u8]) {
        dbg_print!("MappedRegion::write(off={off:?}, src={src:?})");
        let end = off + src.len();
        assert!(end <= self.len());

        for (idx, src) in src.iter().enumerate() {
            unsafe { self.ptr.add(off).add(idx).write_volatile(*src) }
        }
    }

    pub fn close(&mut self) -> rustix::io::Result<()> {
        let (ptr, len) = (self.ptr, self.len);
        (self.ptr, self.len) = (null_mut(), 0);

        if ptr.is_null() {
            return Ok(());
        }

        unsafe { rustix::mm::munmap(ptr.cast(), len) }
    }
}

impl Drop for MappedRegion {
    fn drop(&mut self) {
        self.close().unwrap()
    }
}

pub trait IntoType {
    fn into_type<T>(self) -> T
    where
        Self: Into<T>,
    {
        self.into()
    }
}

impl<T> IntoType for T {}

pub trait TryIntoType {
    fn try_into_type<T>(self) -> Result<T, <Self as TryInto<T>>::Error>
    where
        Self: TryInto<T>,
    {
        dbg_print!(
            "try_into_type<{}, {}>",
            type_name::<T>(),
            type_name::<<Self as TryInto<T>>::Error>()
        );
        self.try_into()
    }
}

impl<T> TryIntoType for T {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bit {
    Zero,
    One,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    Free,
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    typ: BlockType,
    no: Bit,
    off: u64,
    len: u64,
}

impl Block {
    pub fn new(typ: BlockType, no: Bit, off: u64, len: u64) -> Self {
        Self { typ, no, off, len }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BufferLayout {
    DataFreeData,
    FreeDataFree,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BufferFillState {
    Empty,
    Partial,
    Full,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct PipeIoSched {
    buf_len: u64,
    read_off: u64,
    write_off: u64,
}

impl PipeIoSched {
    pub fn new(buf_len: u64, read_off: u64, write_off: u64) -> Self {
        Self {
            buf_len,
            read_off,
            write_off,
        }
    }

    pub fn advance_read_off(&self, adv: u64) -> Self {
        let mut r = self.clone();
        r.read_off += adv;
        r
    }

    pub fn advance_write_off(&self, adv: u64) -> Self {
        let mut r = self.clone();
        r.write_off += adv;
        r
    }

    pub fn read_off(&self) -> u64 {
        self.read_off
    }

    pub fn read_off_mod(&self) -> u64 {
        self.read_off() % self.buf_len()
    }

    pub fn write_off(&self) -> u64 {
        self.write_off
    }

    pub fn write_off_mod(&self) -> u64 {
        self.write_off() % self.buf_len()
    }

    pub fn buf_len(&self) -> u64 {
        self.buf_len
    }

    pub fn data_avail(&self) -> u64 {
        if self.write_off() < self.read_off() {
            dbg_print!("PipeIoSched::data_avail(…): INCONSISTENT STATE: write_off={} < read_off={}", self.write_off(), self.read_off());
        }
        self.write_off() - self.read_off()
    }

    pub fn space_avail(&self) -> u64 {
        if self.buf_len() < self.data_avail() {
            dbg_print!("PipeIoSched::data_avail(…): INCONSISTENT STATE: buf_len={} < data_avail={} --  write_off={} < read_off={}", self.buf_len(), self.data_avail(), self.write_off(), self.read_off());
        }
        self.buf_len() - self.data_avail()
    }

    pub fn fill_state(&self) -> BufferFillState {
        use BufferFillState as F;
        match (self.is_empty(), self.is_full()) {
            (true, false) => F::Empty,
            (false, false) => F::Partial,
            (false, true) => F::Full,
            (true, true) => panic!(
                "Contradiction! Buffer can not be both full and empty. This is a developer error."
            ),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.data_avail() == 0
    }

    pub fn is_full(&self) -> bool {
        self.space_avail() == 0
    }

    pub fn is_nonempty(&self) -> bool {
        !self.is_empty()
    }

    pub fn is_nonfull(&self) -> bool {
        !self.is_full()
    }

    pub fn block_1_off(&self) -> u64 {
        0
    }

    pub fn block_2_off(&self) -> u64 {
        std::cmp::min(self.read_off_mod(), self.write_off_mod())
    }

    pub fn block_3_off(&self) -> u64 {
        std::cmp::max(self.read_off_mod(), self.write_off_mod())
    }

    pub fn block_1_len(&self) -> u64 {
        self.block_2_off() - self.block_1_off()
    }

    pub fn block_2_len(&self) -> u64 {
        self.block_3_off() - self.block_2_off()
    }

    pub fn block_3_len(&self) -> u64 {
        self.buf_len() - self.block_3_off()
    }

    pub fn layout(&self) -> BufferLayout {
        let ord = std::cmp::Ord::cmp(&self.read_off_mod(), &self.write_off_mod());
        let fill = self.fill_state();

        use std::cmp::Ordering as O;
        use BufferFillState as F;
        match (ord, fill) {
            (O::Less, F::Partial) => BufferLayout::FreeDataFree,
            (O::Greater, F::Partial) => BufferLayout::DataFreeData,
            (O::Equal, F::Empty) => BufferLayout::FreeDataFree,
            (O::Equal, F::Full) => BufferLayout::DataFreeData,
            (ord, fill) => panic!(
                "\
                Contradictory buffer layout. \
                Ordering cmp(read_off_mod = {}, write_off_mod = {}) = {:?}, but \
                fill state is {:?}. This is a developer error.",
                self.read_off_mod(),
                self.write_off_mod(),
                ord,
                fill,
            ),
        }
    }

    pub fn block_1(&self) -> Block {
        let (typ, no) = match self.layout() {
            BufferLayout::DataFreeData => (BlockType::Data, Bit::One),
            BufferLayout::FreeDataFree => (BlockType::Free, Bit::One),
        };
        Block::new(typ, no, self.block_1_off(), self.block_1_len())
    }

    pub fn block_2(&self) -> Block {
        let (typ, no) = match self.layout() {
            BufferLayout::DataFreeData => (BlockType::Free, Bit::Zero),
            BufferLayout::FreeDataFree => (BlockType::Data, Bit::Zero),
        };
        Block::new(typ, no, self.block_2_off(), self.block_2_len())
    }

    pub fn block_3(&self) -> Block {
        let (typ, no) = match self.layout() {
            BufferLayout::DataFreeData => (BlockType::Data, Bit::Zero),
            BufferLayout::FreeDataFree => (BlockType::Free, Bit::Zero),
        };
        Block::new(typ, no, self.block_3_off(), self.block_3_len())
    }

    pub fn next_read_block(&self) -> Option<Block> {
        self.is_nonempty().then_some(())?;
        match self.layout() {
            BufferLayout::DataFreeData => Some(self.block_3()),
            BufferLayout::FreeDataFree => Some(self.block_2()),
        }
    }

    pub fn next_write_block(&self) -> Option<Block> {
        self.is_nonfull().then_some(())?;
        match self.layout() {
            BufferLayout::DataFreeData => Some(self.block_2()),
            BufferLayout::FreeDataFree => Some(self.block_3()),
        }
    }

    pub fn schedule_read(&self, dst_len: usize) -> Option<Range<u64>> {
        (dst_len > 0).then_some(())?;
        let dst_len = dst_len as u64;
        let block = self.next_read_block()?;
        let start = block.off;
        let end = start + std::cmp::min(block.len, dst_len);
        Some(Range { start, end })
    }

    pub fn schedule_write(&self, src_len: usize) -> Option<Range<u64>> {
        (src_len > 0).then_some(())?;
        let src_len = src_len as u64;
        let block = self.next_write_block()?;
        let start = block.off;
        let end = start + std::cmp::min(block.len, src_len);
        Some(Range { start, end })
    }
}

impl std::fmt::Debug for PipeIoSched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeIoSched")
            .field("buf_len()", &self.buf_len())
            .field("read_off()", &self.read_off())
            .field("read_off_mod()", &self.read_off_mod())
            .field("write_off()", &self.write_off())
            .field("write_off_mod()", &self.write_off_mod())
            .field("data_avail()", &self.data_avail())
            .field("space_avail()", &self.space_avail())
            .field("fill_state()", &self.fill_state())
            .field("is_empty()", &self.is_empty())
            .field("is_full()", &self.is_full())
            .field("block_1()", &self.block_1())
            .field("block_2()", &self.block_2())
            .field("block_3()", &self.block_3())
            .field("layout()", &self.layout())
            .field("next_read_block()", &self.next_read_block())
            .field("next_write_block()", &self.next_write_block())
            .finish()
    }
}

pub struct SimplexPipeSharedState {
    read_off: AtomicU64,
    write_off: AtomicU64,
}

impl SimplexPipeSharedState {
    pub fn new() -> Self {
        Self {
            read_off: 0.into(),
            write_off: 0.into(),
        }
    }
}

pub struct SimplexPipeReader<'a> {
    shared: &'a SimplexPipeSharedState,
    buf: MappedRegion,
}

pub struct SimplexPipeWriter<'a> {
    shared: &'a SimplexPipeSharedState,
    buf: MappedRegion,
}

impl<'a> SimplexPipeWriter<'a> {
    pub fn write_mem(&self, src: &[u8]) -> usize {
        use std::sync::atomic::Ordering as O;

        let write_off = self.shared.write_off.load(O::Relaxed);
        let read_off = self.shared.read_off.load(O::Relaxed);
        let buf_len = self.buf.len() as u64;
        let sched = PipeIoSched::new(buf_len, read_off, write_off);

        dbg_print!("SimplexPipeWriter::write_mem(self, src.len()={:?}): write_off={:?} read_off={:?}", src.len(), sched.write_off(), sched.read_off());

        let mut written = 0;
        loop {
            let src = &src[written..];
            let sched = sched.advance_write_off(written as u64);
            let write_op = match sched.schedule_write(src.len()) {
                None => break,
                Some(op) => op,
            };

            let write_len = (write_op.end - write_op.start) as usize;
            let src = &src[..write_len];

            dbg_print!("  SimplexPipeWriter::write_mem(…): self.buf.write(): write_op={write_op:?} write_len={write_len:?} src.len()={:?} write_off={:?} read_off={:?}", src.len(), sched.write_off(), sched.read_off());
            self.buf.write(write_op.start as usize, src);

            written += write_len;
        }

        if written > 0 {
            let old = sched.write_off();
            let new = old + (written as u64);
            let res = self
                .shared
                .write_off
                .compare_exchange(old, new, O::Release, O::Relaxed);
            dbg_print!("  SimplexPipeWriter::write_mem(…): self.shared.write_off.compare_exchange(): old={:?} new={:?} res={:?} data={:?}", old, new, res, &src[..written]);
            if res.is_err() {
                todo!()
            }
        }

        dbg_print!("  SimplexPipeWriter::write_mem(…) -> {:?}", written);
        written
    }
}

impl<'a> SimplexPipeReader<'a> {
    pub fn read_mem(&self, dst: &mut [u8]) -> usize {

        use std::sync::atomic::Ordering as O;

        let write_off = self.shared.write_off.load(O::Acquire);
        let read_off = self.shared.read_off.load(O::Relaxed);
        let buf_len = self.buf.len() as u64;
        let sched = PipeIoSched::new(buf_len, read_off, write_off);

        dbg_print!("SimplexPipeReader::read_mem(self, dst.len()={:?}): write_off={:?} read_off={:?}", dst.len(), sched.write_off(), sched.read_off());

        let mut readden = 0;
        loop {
            let dst = &mut dst[readden..];
            let sched = sched.advance_read_off(readden as u64);
            let read_op = match sched.schedule_read(dst.len()) {
                None => break,
                Some(op) => op,
            };

            let read_len = (read_op.end - read_op.start) as usize;
            let dst = &mut dst[..read_len];

            self.buf.read(dst, read_op.start as usize);
            dbg_print!("  SimplexPipeReader::read_mem(…): self.buf.read(): \
                read_op={read_op:?} read_len={read_len:?} dst.len()={:?} \
                write_off={:?} read_off={:?} sched={sched:?} result={dst:?}",
                dst.len(), sched.write_off(), sched.read_off());

            readden += read_len;
        }

        if readden > 0 {
            let old = sched.read_off();
            let new = old + (readden as u64);
            let res = self
                .shared
                .read_off
                .compare_exchange(old, new, O::Relaxed, O::Relaxed);
            dbg_print!("  SimplexPipeReader::read_mem(…): self.shared.read_off.compare_exchange(): old={:?} new={:?} res={:?} data={:?}", old, new, res, &dst[..readden]);
            if res.is_err() {
                todo!()
            }
        }

        dbg_print!("  SimplexPipeReader::read_mem(…) -> {:?}", readden);
        readden
    }
}

#[test]
fn pipe_test() -> anyhow::Result<()> {
    let file = MappableFd::memfd_secret(1024, 0)?;
    let reg1 = file.map_into_memory()?;
    let reg2 = file.map_into_memory()?;
    dbg_print!("Regions {:?} {:?}", reg1.ptr(), reg2.ptr());

    let mut buf = b"______________________________________".to_owned();
    reg1.read(&mut buf, 0);
    dbg_print!(
        "Region 1 read: `{:?}` `{:?}`",
        String::from_utf8_lossy(&buf),
        &buf
    );

    let mut buf = b"______________________________________".to_owned();
    reg2.read(&mut buf, 0);
    dbg_print!(
        "Region 1 read: `{:?}` `{:?}`",
        String::from_utf8_lossy(&buf),
        &buf
    );

    dbg_print!("Write to region 1");
    reg1.write(0, b"Hello World");

    let mut buf = b"______________________________________".to_owned();
    reg1.read(&mut buf, 0);
    dbg_print!(
        "Region 1 read: `{:?}` `{:?}`",
        String::from_utf8_lossy(&buf),
        &buf
    );

    let mut buf = b"______________________________________".to_owned();
    reg2.read(&mut buf, 0);
    dbg_print!(
        "Region 1 read: `{:?}` `{:?}`",
        String::from_utf8_lossy(&buf),
        &buf
    );

    let buf = MappableFd::memfd_secret(1024, 0)?;
    let shared = Arc::new(SimplexPipeSharedState::new());

    let reader = SimplexPipeReader {
        shared: &shared.clone(),
        buf: buf.map_into_memory()?,
    };

    const MSG : &[u8] = b"Hello World\0";
    const MSG_COUNT : usize = 100000;

    let t = thread::spawn(move || {
        let writer = SimplexPipeWriter {
            shared: &shared,
            buf: buf.map_into_memory().unwrap(),
        };

        for _ in 0..MSG_COUNT {
            let mut buf = MSG;
            while !buf.is_empty() {
                let n = writer.write_mem(buf);
                buf = &buf[n..];
            }
        }
    });

    let mut buf = [0u8; 1000];
    let mut buf_off = 0;
    let mut msg_no = 0usize;

    'read_data: while msg_no < MSG_COUNT {
        let mut old_off = buf_off;

        // Read the data from the shared memory buffer
        buf_off += reader.read_mem(&mut buf[buf_off..]);

        'scan_again: loop {
            // Scan the available data for the zero terminator
            let msg_len = &buf[old_off..buf_off]
                .iter()
                .copied()
                .enumerate()
                .find(|(_off, c)| *c == 0x0)
                .map(|(off, _c)| off + old_off + 1);

            // Next iteration, unless the terminator was found
            let msg_len = match *msg_len {
                Some(l) => l,
                None => continue 'read_data,
            };

            // Register the newly read message
            msg_no += 1;

            // Check that the message is correctly transferred
            let msg = &buf[0..msg_len];
            dbg_print!("CONT {:?}", &buf[..buf_off]);
            dbg_print!("RECV {msg:?}");
            assert_eq!(msg, MSG);

            // Move any extra data to the beginning of the buffer and adjust the offsets accordingly
            buf.copy_within(msg_len..buf_off, 0);
            old_off = 0;
            buf_off -= msg_len;
        }
    }

    t.join().unwrap();

    Ok(())
}
