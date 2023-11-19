//! Functions with destination copying data between slices and arrays.

use crate::{with_destination, To};

/// Function with destination that copies data from
/// origin into the destination.
///
/// # Panics
///
/// This function will panic if the two slices have different lengths.
pub fn copy_slice<'a, T>(origin: &'a [T]) -> impl To<[T], ()> + 'a
where
    T: Copy,
{
    with_destination(|out: &mut [T]| out.copy_from_slice(origin))
}

/// Function with destination that copies all data from
/// origin into the destination.
///
/// Destination may be longer than origin.
///
/// # Panics
///
/// This function will panic if destination is shorter than origin.
pub fn copy_slice_least_src<'a, T>(origin: &'a [T]) -> impl To<[T], ()> + 'a
where
    T: Copy,
{
    with_destination(|out: &mut [T]| copy_slice(origin).to(&mut out[..origin.len()]))
}

/// Function with destination that copies as much data as possible from origin to the
/// destination.
///
/// Copies as much data as is present in the shorter slice.
pub fn copy_slice_least<'a, T>(origin: &'a [T]) -> impl To<[T], ()> + 'a
where
    T: Copy,
{
    with_destination(|out: &mut [T]| {
        let len = std::cmp::min(origin.len(), out.len());
        copy_slice(&origin[..len]).to(&mut out[..len])
    })
}

/// Function with destination that attempts to copy data from origin into the destination.
///
/// Will return None if the slices are of different lengths.
pub fn try_copy_slice<'a, T>(origin: &'a [T]) -> impl To<[T], Option<()>> + 'a
where
    T: Copy,
{
    with_destination(|out: &mut [T]| {
        (origin.len() == out.len()).then(|| copy_slice(origin).to(out))
    })
}

/// Function with destination that tries to copy all data from
/// origin into the destination.
///
/// Destination may be longer than origin.
///
/// Will return None if the destination is shorter than origin.
pub fn try_copy_slice_least_src<'a, T>(origin: &'a [T]) -> impl To<[T], Option<()>> + 'a
where
    T: Copy,
{
    with_destination(|out: &mut [T]| {
        (origin.len() <= out.len()).then(|| copy_slice_least_src(origin).to(out))
    })
}

/// Function with destination that copies all data between two array references.
pub fn copy_array<'a, T, const N: usize>(origin: &'a [T; N]) -> impl To<[T; N], ()> + 'a
where
    T: Copy,
{
    with_destination(|out: &mut [T; N]| out.copy_from_slice(origin))
}
