//! Module that contains the [To] crate which is the container used to
//! implement the core functionality of this crate.

use crate::{Beside, CondenseBeside};
use std::borrow::BorrowMut;

/// The To trait is the core of the to crate; most functions with destinations will either return
/// an object that is an instance of this trait, or they will return `-> impl To<Destination,
/// Return_value>`.
///
/// A quick way to implement a function with destination is to use the
/// [with_destination(|param: &mut Type| ...)](crate::with_destination) higher order function.
///
/// # Example
/// Below, we provide a very simple example for how the Trait can be implemented. More examples for
/// how this Trait is best implemented can be found in the overall [crate documentation](crate).
/// ```
/// use rosenpass_to::To;
///
/// // This is a simple wrapper around a String that can be written into a byte array using to.
/// struct StringToBytes {
///    inner: String
/// }
///
/// impl To<[u8], Result<(), String>> for StringToBytes {
///     fn to(self, out: &mut [u8]) -> Result<(), String> {
///         let bytes = self.inner.as_bytes();
///         if bytes.len() > out.len() {
///             return Err("out is too short".to_string());
///         }
///         for i in 0..bytes.len() {
///             out[i] = bytes[i];
///         }
///         Ok(())
///     }
/// }
///
/// let string_to_bytes = StringToBytes { inner: "my message".to_string() };
/// let mut buffer: [u8; 10] = [0; 10];
/// let result = string_to_bytes.to(&mut buffer);
/// assert_eq!(buffer, [109, 121, 32, 109, 101, 115, 115, 97, 103, 101]);
/// assert!(result.is_ok());
/// ```
pub trait To<Dst: ?Sized, Ret>: Sized {
    /// Writes self to the destination `out` and returns a value of type `Ret`.
    ///
    /// This is the core method that must be implemented by all types implementing `To`.
    fn to(self, out: &mut Dst) -> Ret;

    /// Generate a destination on the fly with a lambda.
    ///
    /// Calls the provided closure to create a value,
    /// calls [crate::to()] to evaluate the function and finally
    /// returns a [Beside] instance containing the generated destination value and the return
    /// value.
    ///
    /// # Example
    /// Below, we rewrite the example for the overall [To]-Trait and simplify it by using
    /// [self.to_this_beside]. We refer to the overall [crate documentation](crate)
    /// for more examples and general explanations.
    /// ```
    /// # use rosenpass_to::To;
    /// use rosenpass_to::Beside;
    /// # struct StringToBytes {
    /// #   inner: String
    /// # }
    ///
    /// # impl To<[u8], Result<(), String>> for StringToBytes {
    /// #    fn to(self, out: &mut [u8]) -> Result<(), String> {
    /// #        let bytes = self.inner.as_bytes();
    /// #        if bytes.len() > out.len() {
    /// #            return Err("out is to short".to_string());
    /// #        }
    /// #        for i in 0..bytes.len() {
    /// #            (*out)[i] = bytes[i];
    /// #        }
    /// #        Ok(())
    /// #    }
    /// # }
    /// // StringToBytes is taken from the overall Trait example.
    /// let string_to_bytes = StringToBytes { inner: "my message".to_string() };
    /// let Beside(dst, result) = string_to_bytes.to_this_beside(|| [0; 10]);
    /// assert_eq!(dst, [109, 121, 32, 109, 101, 115, 115, 97, 103, 101]);
    /// assert!(result.is_ok());
    /// ```
    fn to_this_beside<Val, Fun>(self, fun: Fun) -> Beside<Val, Ret>
    where
        Val: BorrowMut<Dst>,
        Fun: FnOnce() -> Val,
    {
        let mut val = fun();
        let ret = self.to(val.borrow_mut());
        Beside(val, ret)
    }

    /// Generate a destination on the fly using default.
    ///
    /// Uses [Default] to create a value, calls [crate::to()] to evaluate the function and finally
    /// returns a [Beside] instance containing the generated destination value and the return
    /// value.
    ///
    /// # Example
    /// Below, we provide a simple example for the usage of [to_value_beside](To::to_value_beside).
    /// We refer to the overall [crate documentation](crate) for more examples and general
    /// explanations.
    /// ```
    /// use rosenpass_to::Beside;
    /// use rosenpass_to::To;
    /// use rosenpass_to::ops::*;
    /// let Beside(dst, ret) = copy_array(&[42u8; 16]).to_value_beside();
    /// assert_eq!(dst, [42u8; 16]);
    /// ```
    fn to_value_beside(self) -> Beside<Dst, Ret>
    where
        Dst: Sized + Default,
    {
        self.to_this_beside(|| Dst::default())
    }

    /// Generate a destination on the fly using default and a custom storage type.
    ///
    /// Uses [Default] to create a value of the given type,
    /// calls [crate::to()] to evaluate the function and finally
    /// returns a [Beside] instance containing the generated destination value and the return
    /// value.
    ///
    /// Using collect_beside with an explicit type instead of [Self::to_value_beside] is mainly useful
    /// when the Destination is unsized.
    ///
    /// This could be the case when the destination is an `[u8]` for instance.
    ///
    /// # Example
    /// Below, we provide a simple example for the usage of [collect_beside](To::collect_beside).
    /// We refer to the overall [crate documentation](crate) for more examples and general
    /// explanations.
    /// ```
    /// use rosenpass_to::Beside;
    /// use rosenpass_to::To;
    /// use rosenpass_to::ops::*;
    ///
    /// let Beside(dst, ret) = copy_slice(&[42u8; 16]).collect_beside::<[u8; 16]>();
    /// assert_eq!(dst, [42u8; 16]);
    /// ```
    fn collect_beside<Val>(self) -> Beside<Val, Ret>
    where
        Val: Default + BorrowMut<Dst>,
    {
        self.to_this_beside(|| Val::default())
    }

    /// Generate a destination on the fly with a lambda, condensing the destination and the
    /// return value into one.
    ///
    /// This is like using [Self::to_this_beside] followed by calling [Beside::condense].
    /// # Example
    /// Below, we rewrite the example for the overall [To]-Trait and simplify it by using
    /// [Self::to_this]. We refer to the overall [crate documentation](crate)
    /// for more examples and general explanations.
    /// ```
    /// # use rosenpass_to::To;
    /// use rosenpass_to::Beside;
    /// # struct StringToBytes {
    /// #   inner: String
    /// # }
    ///
    /// # impl To<[u8], Result<(), String>> for StringToBytes {
    /// #    fn to(self, out: &mut [u8]) -> Result<(), String> {
    /// #        let bytes = self.inner.as_bytes();
    /// #        if bytes.len() > out.len() {
    /// #            return Err("out is to short".to_string());
    /// #        }
    /// #        for i in 0..bytes.len() {
    /// #            (*out)[i] = bytes[i];
    /// #        }
    /// #        Ok(())
    /// #    }
    /// # }
    /// // StringToBytes is taken from the overall Trait example.
    /// let string_to_bytes = StringToBytes { inner: "my message".to_string() };
    /// let result = string_to_bytes.to_this_beside(|| [0; 10]).condense();
    /// assert!(result.is_ok());
    /// assert_eq!(result.unwrap(), [109, 121, 32, 109, 101, 115, 115, 97, 103, 101]);
    ///
    /// ```
    fn to_this<Val, Fun>(self, fun: Fun) -> <Ret as CondenseBeside<Val>>::Condensed
    where
        Ret: CondenseBeside<Val>,
        Val: BorrowMut<Dst>,
        Fun: FnOnce() -> Val,
    {
        self.to_this_beside(fun).condense()
    }

    /// Generate a destination on the fly using default, condensing the destination and the
    /// return value into one.
    ///
    /// This is like using [Self::to_value_beside] followed by calling [Beside::condense].
    ///
    /// # Example
    /// Below, we provide a simple example for the usage of [to_value](To::to_value).
    /// We refer to the overall [crate documentation](crate) for more examples and general
    /// explanations.
    /// ```
    /// use rosenpass_to::Beside;
    /// use rosenpass_to::To;
    /// use rosenpass_to::ops::*;
    /// let dst = copy_array(&[42u8; 16]).to_value_beside().condense();
    /// assert_eq!(dst, [42u8; 16]);
    /// ```
    fn to_value(self) -> <Ret as CondenseBeside<Dst>>::Condensed
    where
        Dst: Sized + Default,
        Ret: CondenseBeside<Dst>,
    {
        self.to_value_beside().condense()
    }

    /// Generate a destination on the fly using default, condensing the destination and the
    /// return value into one.
    ///
    /// This is like using [Self::collect_beside] followed by calling [Beside::condense].
    ///
    /// # Example
    /// Below, we provide a simple example for the usage of [collect](To::collect).
    /// We refer to the overall [crate documentation](crate) for more examples and general
    /// explanations.
    /// ```
    /// use rosenpass_to::Beside;
    /// use rosenpass_to::To;
    /// use rosenpass_to::ops::*;
    ///
    /// let dst = copy_slice(&[42u8; 16]).collect_beside::<[u8; 16]>().condense();
    /// assert_eq!(dst, [42u8; 16]);
    /// ```
    fn collect<Val>(self) -> <Ret as CondenseBeside<Val>>::Condensed
    where
        Val: Default + BorrowMut<Dst>,
        Ret: CondenseBeside<Val>,
    {
        self.collect_beside::<Val>().condense()
    }
}

/// A trait that allows writing self into a destination with a specific lifetime.
pub trait ToLifetime<'a, Dst: ?Sized + 'a, Ret>: Sized {
    /// Writes self to the destination `out` and returns a value of type `Ret`.
    ///
    /// This is the core method that must be implemented by all types implementing `ToLifetime`.
    fn to(self, out: &'a mut Dst) -> Ret;

    /// Generate a destination on the fly with a lambda.
    ///
    /// Calls the provided closure to create a value,
    /// calls [crate::to()] to evaluate the function and finally
    /// returns a [Beside] instance containing the generated destination value and the return
    /// value.
    fn to_this_beside<Val, Fun>(self, fun: Fun) -> Beside<Val, Ret>
    where
        Val: BorrowMut<Dst> + 'a,
        Fun: FnOnce() -> Val,
        Dst: 'a,
    {
        let mut val = fun();
        // This cast ensures we're getting a reference with the right lifetime
        let dst_ref: &'a mut Dst = unsafe { std::mem::transmute(val.borrow_mut()) };
        let ret = self.to(dst_ref);
        Beside(val, ret)
    }

    /// Generate a destination on the fly using default.
    ///
    /// Uses [Default] to create a value, calls [crate::to()] to evaluate the function and finally
    /// returns a [Beside] instance containing the generated destination value and the return
    /// value.
    fn to_value_beside(self) -> Beside<Dst, Ret>
    where
        Dst: Sized + Default,
    {
        self.to_this_beside(|| Dst::default())
    }

    /// Generate a destination on the fly using default and a custom storage type.
    ///
    /// Uses [Default] to create a value of the given type,
    /// calls [crate::to()] to evaluate the function and finally
    /// returns a [Beside] instance containing the generated destination value and the return
    /// value.
    fn collect_beside<Val>(self) -> Beside<Val, Ret>
    where
        Val: Default + BorrowMut<Dst> + 'a,
    {
        self.to_this_beside(|| Val::default())
    }

    /// Generate a destination on the fly with a lambda, condensing the destination and the
    /// return value into one.
    ///
    /// This is like using [Self::to_this_beside] followed by calling [Beside::condense].
    fn to_this<Val, Fun>(self, fun: Fun) -> <Ret as CondenseBeside<Val>>::Condensed
    where
        Ret: CondenseBeside<Val>,
        Val: BorrowMut<Dst> + 'a,
        Fun: FnOnce() -> Val,
    {
        self.to_this_beside(fun).condense()
    }

    /// Generate a destination on the fly using default, condensing the destination and the
    /// return value into one.
    ///
    /// This is like using [Self::to_value_beside] followed by calling [Beside::condense].
    fn to_value(self) -> <Ret as CondenseBeside<Dst>>::Condensed
    where
        Dst: Sized + Default,
        Ret: CondenseBeside<Dst>,
    {
        self.to_value_beside().condense()
    }

    /// Generate a destination on the fly using default, condensing the destination and the
    /// return value into one.
    ///
    /// This is like using [Self::collect_beside] followed by calling [Beside::condense].
    fn collect<Val>(self) -> <Ret as CondenseBeside<Val>>::Condensed
    where
        Val: Default + BorrowMut<Dst> + 'a,
        Ret: CondenseBeside<Val>,
    {
        self.collect_beside::<Val>().condense()
    }
}

impl<'a, T, Dst: ?Sized + 'a, Ret> ToLifetime<'a, Dst, Ret> for T
where
    T: To<Dst, Ret>,
{
    fn to(self, out: &'a mut Dst) -> Ret {
        To::to(self, out)
    }
}
