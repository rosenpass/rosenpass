//! Utilities relating to volatile reads/writes on pointers

/// Read from a memory location using
/// [pointer::read_volatile] in a loop and store the
/// results in the given slice
pub trait ReadMemVolatile<T> {
    /// Read from a memory location using
    /// [pointer::read_volatile] in a loop and store the
    /// results in an array
    ///
    /// # Safety
    ///
    /// Refer to [pointer::read_volatile]
    unsafe fn read_mem_volatile(self, dst: &mut [T]);
}

impl<T> ReadMemVolatile<T> for *const T {
    unsafe fn read_mem_volatile(self, dst: &mut [T]) {
        for (idx, dst) in dst.iter_mut().enumerate() {
            *dst = unsafe { self.add(idx).read_volatile() };
        }
    }
}

impl<T> ReadMemVolatile<T> for *mut T {
    unsafe fn read_mem_volatile(self, dst: &mut [T]) {
        unsafe { self.cast_const().read_mem_volatile(dst) }
    }
}

/// Write to a memory location using
/// [pointer::write_volatile] in a loop
/// and store the resulting values in the given slice
pub trait WriteMemVolatile<T>: ReadMemVolatile<T> {
    /// Write to a memory location using
    /// [pointer::write_volatile] in a loop
    /// and store the resulting values in the given slice
    ///
    /// # Safety
    ///
    /// Refer to [pointer::write_volatile]
    unsafe fn write_mem_volatile(self, src: &[T]);
}

impl<T: Copy> WriteMemVolatile<T> for *mut T {
    unsafe fn write_mem_volatile(self, src: &[T]) {
        for (idx, src) in src.iter().enumerate() {
            unsafe { self.add(idx).write_volatile(*src) }
        }
    }
}
