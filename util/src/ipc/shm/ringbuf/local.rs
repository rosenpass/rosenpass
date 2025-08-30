//! Local shared memory ring buffers – mostly for testing

use std::sync::Arc;

use crate::ipc::shm::SharedMemorySegment;
use crate::ringbuf::concurrent::framework::{ConcurrentPipeReader, ConcurrentPipeWriter};

use super::{ShmPipeCore, ShmPipeVariables};

/// A process-local shared memory pipe reader
///
/// See [shm_pipe()].
pub type LocalShmPipeReader = ConcurrentPipeReader<ShmPipeCore<Arc<ShmPipeVariables>>>;

/// A process-local shared memory pipe writer
///
/// See [shm_pipe()].
pub type LocalShmPipeWriter = ConcurrentPipeWriter<ShmPipeCore<Arc<ShmPipeVariables>>>;

/// Creates a process-local shared-memory pipe.
///
/// See [ConcurrentPipeWriter]/[ConcurrentPipeReader]. The types [LocalShmPipeWriter]/[LocalShmPipeReader] are just aliases for these.
///
/// # Safety
///
/// Mind the comments in the safety section of [super::super::SharedMemorySegment]; the issues
/// described in there *exactly* affect this implementation.
pub fn shm_pipe(len: usize) -> anyhow::Result<(LocalShmPipeWriter, LocalShmPipeReader)> {
    let shared = Arc::new(ShmPipeVariables::new());
    let (seg_fd, seg_buf_1) = SharedMemorySegment::create(len)?;
    let seg_buf_2 = unsafe { SharedMemorySegment::from_fd(seg_fd, len) }?;

    let writer = ShmPipeCore::new(shared.clone(), seg_buf_1);
    let reader = ShmPipeCore::new(shared, seg_buf_2);

    Ok((
        ConcurrentPipeWriter::from_core(writer),
        ConcurrentPipeReader::from_core(reader),
    ))
}

#[test]
fn test_shm_pipe() -> anyhow::Result<()> {
    let (mut writer, mut reader) = shm_pipe(1024)?;

    const MSG: &[u8] = b"Hello World\0";
    const MSG_COUNT: usize = 100000;

    let t = std::thread::spawn(move || {
        for _ in 0..MSG_COUNT {
            let mut buf = MSG;
            while !buf.is_empty() {
                let n = writer.write(buf).unwrap();
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
        buf_off += reader.read(&mut buf[buf_off..])?;

        loop {
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
