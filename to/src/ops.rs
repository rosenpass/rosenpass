//! Functions that make it easy to copy data between arrays and slices using functions with
//! destinations. See the specific functions for examples and more explanations.

use crate::{with_destination, To};

/// Function with destination that copies data from
/// origin into the destination.
///
/// # Panics
///
/// This function will panic if the two slices have different lengths.
///
/// # Example
/// ```
/// use rosenpass_to::To;
/// # use crate::rosenpass_to::ops::copy_slice;
/// let to_function = copy_slice(&[0; 16]);
/// let mut dst = [255; 16];
/// to_function.to(&mut dst);
/// // After the operation `dst` will hold the same data as the original slice.
/// assert!(dst.iter().all(|b| *b == 0));
/// ```
pub fn copy_slice<T>(origin: &[T]) -> impl To<[T], ()> + '_
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
///
/// # Example
/// ```
/// use rosenpass_to::To;
/// # use crate::rosenpass_to::ops::copy_slice_least_src;
/// let to_function = copy_slice_least_src(&[0; 16]);
/// let mut dst = [255; 32];
/// to_function.to(&mut dst);
/// // After the operation the first half of `dst` will hold the same data as the original slice.
/// assert!(dst[0..16].iter().all(|b| *b == 0));
/// // The second half will have remained the same
/// assert!(dst[16..32].iter().all(|b| *b == 255));
/// ```
pub fn copy_slice_least_src<T>(origin: &[T]) -> impl To<[T], ()> + '_
where
    T: Copy,
{
    with_destination(|out: &mut [T]| copy_slice(origin).to(&mut out[..origin.len()]))
}

/// Function with destination that copies as much data as possible from origin to the
/// destination.
///
/// Copies as much data as is present in the shorter slice.
/// # Example
/// ```
/// use rosenpass_to::To;
/// # use crate::rosenpass_to::ops::copy_slice_least;
/// let to_function = copy_slice_least(&[0; 16]);
/// let mut dst = [255; 32];
/// to_function.to(&mut dst);
/// // After the operation the first half of `dst` will hold the same data as the original slice.
/// assert!(dst[0..16].iter().all(|b| *b == 0));
/// // The second half will have remained the same.
/// assert!(dst[16..32].iter().all(|b| *b == 255));
/// ```
pub fn copy_slice_least<T>(origin: &[T]) -> impl To<[T], ()> + '_
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
/// # Example
/// ```
/// use rosenpass_to::To;
/// # use crate::rosenpass_to::ops::try_copy_slice;
/// let to_function = try_copy_slice(&[0; 16]);
/// let mut dst = [255; 32];
/// let result = to_function.to(&mut dst);
/// // This will return None because the slices do not have the same length.
/// assert!(result.is_none());
///
/// let to_function = try_copy_slice(&[0; 16]);
/// let mut dst = [255; 16];
/// let result = to_function.to(&mut dst);
/// // This time it works:
/// assert!(result.is_some());
/// // After the operation `dst` will hold the same data as the original slice.
/// assert!(dst.iter().all(|b| *b == 0));
/// ```
pub fn try_copy_slice<T>(origin: &[T]) -> impl To<[T], Option<()>> + '_
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
/// # Example
/// ```rust
/// use rosenpass_to::To;
/// # use crate::rosenpass_to::ops::try_copy_slice_least_src;
/// let to_function = try_copy_slice_least_src(&[0; 16]);
/// let mut dst = [255; 15];
/// let result = to_function.to(&mut dst);
/// // This will return None because the destination is to short.
/// assert!(result.is_none());
///
/// let to_function = try_copy_slice_least_src(&[0; 16]);
/// let mut dst = [255; 32];
/// let result = to_function.to(&mut dst);
/// // This time it works:
/// assert!(result.is_some());
/// // After the operation, the first half of `dst` will hold the same data as the original slice.
/// assert!(dst[0..16].iter().all(|b| *b == 0));
/// // The second half will have remained the same.
/// assert!(dst[16..32].iter().all(|b| *b == 255));
/// ```
pub fn try_copy_slice_least_src<T>(origin: &[T]) -> impl To<[T], Option<()>> + '_
where
    T: Copy,
{
    with_destination(|out: &mut [T]| {
        (origin.len() <= out.len()).then(|| copy_slice_least_src(origin).to(out))
    })
}

/// Function with destination that copies all data between two array references.
///
/// # Example
/// ```rust
/// use rosenpass_to::ops::copy_array;
/// use rosenpass_to::To;
/// let my_arr: [u8; 32] = [0; 32];
/// let to_function = copy_array(&my_arr);
/// let mut dst = [255; 32];
/// to_function.to(&mut dst);
/// // After the operation `dst` will hold the same data as the original slice.
/// assert!(dst.iter().all(|b| *b == 0));
/// ```
pub fn copy_array<T, const N: usize>(origin: &[T; N]) -> impl To<[T; N], ()> + '_
where
    T: Copy,
{
    with_destination(|out: &mut [T; N]| out.copy_from_slice(origin))
}
