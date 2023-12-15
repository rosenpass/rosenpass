use std::borrow::{Borrow, BorrowMut};
use std::cmp::min;

/// Concatenate two byte arrays
// TODO: Zeroize result?
#[macro_export]
macro_rules! cat {
    ($len:expr; $($toks:expr),+) => {{
        let mut buf = [0u8; $len];
        let mut off = 0;
        $({
            let tok = $toks;
            let tr = ::std::borrow::Borrow::<[u8]>::borrow(tok);
            (&mut buf[off..(off + tr.len())]).copy_from_slice(tr);
            off += tr.len();
        })+
        assert!(off == buf.len(), "Size mismatch in cat!()");
        buf
    }}
}

// TODO: consistent inout ordering
pub fn cpy<T: BorrowMut<[u8]> + ?Sized, F: Borrow<[u8]> + ?Sized>(src: &F, dst: &mut T) {
    dst.borrow_mut().copy_from_slice(src.borrow());
}

/// Copy from `src` to `dst`. If `src` and `dst` are not of equal length, copy as many bytes as possible.
pub fn cpy_min<T: BorrowMut<[u8]> + ?Sized, F: Borrow<[u8]> + ?Sized>(src: &F, dst: &mut T) {
    let src = src.borrow();
    let dst = dst.borrow_mut();
    let len = min(src.len(), dst.len());
    dst[..len].copy_from_slice(&src[..len]);
}
