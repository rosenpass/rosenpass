//! This module provides utilities for working with zero-copy references
//! and slices.
//!
//! It offers the following primary abstractions and traits:
//!
//! - [`RefMaker`]: A helper structure for safely creating
//! [`Ref`](zerocopy::Ref) references from byte slices.
//! - [`ZerocopyEmancipateExt`]: A trait to convert `Ref<B, T>` into a borrowed
//! `Ref<&[u8], T>`.
//! - [`ZerocopyEmancipateMutExt`]: A trait to convert `Ref<B, T>` into a
//! borrowed mutable `Ref<&mut [u8], T>`.
//! - [`ZerocopySliceExt`]: Extension methods for parsing byte slices into
//! zero-copy references.
//! - [`ZerocopyMutSliceExt`]: Extension methods for parsing and zeroizing byte
//! slices into zero-copy references.

mod ref_maker;
mod zerocopy_ref_ext;
mod zerocopy_slice_ext;

pub use ref_maker::*;
pub use zerocopy_ref_ext::*;
pub use zerocopy_slice_ext::*;
