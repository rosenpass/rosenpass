//! This module provides the [Beside] struct. In the context of functions with targets,
//! [Beside] structures the destination value and the return value unmistakably and offers useful
//! helper functions to work with them.

use crate::CondenseBeside;

/// Named tuple holding the return value and the destination from a function with destinations.
/// See the respective functions for usage examples.
#[derive(Debug, PartialEq, Eq, Default, PartialOrd, Ord, Copy, Clone)]
pub struct Beside<Val, Ret>(pub Val, pub Ret);

impl<Val, Ret> Beside<Val, Ret> {
    /// Get an immutable reference to the destination value
    ///
    /// # Example
    /// ```
    /// use rosenpass_to::Beside;
    ///
    /// let beside = Beside(1, 2);
    /// assert_eq!(beside.dest(), &1);
    /// ```
    pub fn dest(&self) -> &Val {
        &self.0
    }

    /// Get an immutable reference to the return value
    ///
    /// # Example
    /// ```
    /// use rosenpass_to::Beside;
    ///
    /// let beside = Beside(1, 2);
    /// assert_eq!(beside.ret(), &2);
    /// ```
    pub fn ret(&self) -> &Ret {
        &self.1
    }

    /// Get a mutable reference to the destination value
    ///
    /// # Example
    /// ```
    /// use rosenpass_to::Beside;
    ///
    /// let mut beside = Beside(1, 2);
    /// *beside.dest_mut() = 3;
    /// assert_eq!(beside.dest(), &3);
    /// ```
    pub fn dest_mut(&mut self) -> &mut Val {
        &mut self.0
    }

    /// Get a mutable reference to the return value
    ///
    /// # Example
    /// ```
    /// use rosenpass_to::Beside;
    ///
    /// let mut beside = Beside(1, 2);
    /// *beside.ret_mut() = 3;
    /// assert_eq!(beside.ret(), &3);
    /// ```
    pub fn ret_mut(&mut self) -> &mut Ret {
        &mut self.1
    }

    /// Perform beside condensation. See [CondenseBeside] for more details.
    ///
    /// # Example
    /// ```
    /// use rosenpass_to::Beside;
    /// use rosenpass_to::CondenseBeside;
    ///
    /// let beside = Beside(1, ());
    /// assert_eq!(beside.condense(), 1);
    /// ```
    pub fn condense(self) -> <Ret as CondenseBeside<Val>>::Condensed
    where
        Ret: CondenseBeside<Val>,
    {
        self.1.condense(self.0)
    }
}

impl<Val, Ret> From<(Val, Ret)> for Beside<Val, Ret> {
    fn from(tuple: (Val, Ret)) -> Self {
        let (val, ret) = tuple;
        Self(val, ret)
    }
}

impl<Val, Ret> From<Beside<Val, Ret>> for (Val, Ret) {
    fn from(beside: Beside<Val, Ret>) -> Self {
        let Beside(val, ret) = beside;
        (val, ret)
    }
}

#[cfg(test)]
mod tests {
    use crate::Beside;

    #[test]
    fn from_tuple() {
        let tuple = (21u8, 42u16);
        let beside: Beside<u8, u16> = Beside::from(tuple);
        assert_eq!(beside.dest(), &21u8);
        assert_eq!(beside.ret(), &42u16);
    }

    #[test]
    fn from_beside() {
        let beside: Beside<u8, u16> = Beside(21u8, 42u16);
        type U8u16 = (u8, u16);
        let tuple = U8u16::from(beside);
        assert_eq!(tuple.0, 21u8);
        assert_eq!(tuple.1, 42u16);
    }
}
