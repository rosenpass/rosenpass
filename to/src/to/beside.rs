use crate::CondenseBeside;

/// Named tuple holding the return value and the output from a function with destinations.
#[derive(Debug, PartialEq, Eq, Default, PartialOrd, Ord, Copy, Clone)]
pub struct Beside<Val, Ret>(pub Val, pub Ret);

impl<Val, Ret> Beside<Val, Ret> {
    pub fn dest(&self) -> &Val {
        &self.0
    }

    pub fn ret(&self) -> &Ret {
        &self.1
    }

    pub fn dest_mut(&mut self) -> &mut Val {
        &mut self.0
    }

    pub fn ret_mut(&mut self) -> &mut Ret {
        &mut self.1
    }

    /// Perform beside condensation. See [CondenseBeside]
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
