//! Module implementing the core function with destination functionality.
//!
//! Parameter naming scheme
//!
//! - `Src: impl To<Dst, Ret>` – The value of an instance of something implementing the `To` trait
//! - `Dst: ?Sized`; (e.g. [u8]) – The target to write to
//! - `Out: Sized = &mut Dst`; (e.g. &mut [u8]) – A reference to the target to write to
//! - `Coercable: ?Sized + DstCoercion<Dst>`; (e.g. `[u8]`, `[u8; 16]`) – Some value that
//! destination coercion can be applied to. Usually either `Dst` itself (e.g. `[u8]` or some sized variant of
//! `Dst` (e.g. `[u8; 64]`).
//! - `Ret: Sized`; (anything) – must be `CondenseBeside<_>` if condensing is to be applied. The ordinary return value of a function with an output
//! - `Val: Sized + BorrowMut<Dst>`; (e.g. [u8; 16]) – Some owned storage that can be borrowed as `Dst`
//! - `Condensed: Sized = CondenseBeside<Val>::Condensed`; (e.g. [u8; 16], Result<[u8; 16]>) – The combiation of Val and Ret after condensing was applied (`Beside<Val, Ret>::condense()`/`Ret::condense(v)` for all `v : Val`).

pub mod beside;
pub mod condense;
pub mod dst_coercion;
pub mod to_function;
pub mod to_trait;
pub mod with_destination;
