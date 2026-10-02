//! Numeric types for modular arithmetic

use num_traits::{
    CheckedMul, Euclid, Num, Unsigned, WrappingNeg, Zero, ops::overflowing::OverflowingAdd,
};

/// Summary-trait for numeric types that can serve as the basis for Modulus
pub trait ModuleBase: Num + Ord + Copy + Unsigned + OverflowingAdd + Zero {}
impl<T> ModuleBase for T where T: Num + Ord + Copy + Unsigned + OverflowingAdd + Zero {}

/// Represents a modulus; i.e. the range of values some number type is allowed to use.
///
/// This is based on some inner representation.
///
/// This is not just a value of the underlying representation, because it also supports the modulus
/// [Self::new_full_range()], which indicates that the full range of the underlying type is to be
/// supported.
///
/// Note that zero is not a valid modulus
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Modulus<T: ModuleBase> {
    /// Inner representation of the type
    modulus: T,
}

impl<T: ModuleBase> Modulus<T> {
    /// Create a new [Self] without any checks
    fn raw_new(modulus: T) -> Self {
        Self { modulus }
    }

    /// Create a new [Self] that indicates that the full range of the underlying type is to be used
    pub fn new_full_range() -> Self {
        Self::raw_new(T::zero())
    }

    /// Try to create a new [Self]. Will return None only if `modulus == 0`
    pub fn try_new(modulus: T) -> Option<Self> {
        match modulus == T::zero() {
            true => None,
            false => Some(Self::raw_new(modulus)),
        }
    }

    /// Like [Self::try_new] but will panic if `modulus == 0`
    ///
    /// # Panic
    ///
    /// Will panic if `modulus == 0`
    pub fn new_or_panic(modulus: T) -> Self {
        match Self::try_new(modulus) {
            None => panic!("Can not create Modulus with modulus zero!"),
            Some(me) => me,
        }
    }

    /// Check if this [Self] represents the full range of the underlying type
    pub fn is_full_range(&self) -> bool {
        self.modulus == T::zero()
    }

    /// Get the raw modulus. I.e. the value of the underlying type that can be given to
    /// a modulo operation to implement modular arithmetic.
    ///
    /// Will return None if [Self::is_full_range].
    pub fn modulus(&self) -> Option<T> {
        match self.is_full_range() {
            true => None,
            false => Some(self.modulus),
        }
    }

    /// Check if the given value is contained in the range represented by this [Self]
    pub fn contains(&self, v: T) -> bool {
        match self.is_full_range() {
            true => true,
            false => v < self.modulus,
        }
    }
    /// Double the modulus.
    ///
    /// Correctly handles the case that `v.double().is_full_range()`.
    ///
    /// # Examples
    ///
    #[cfg_attr(feature = "expose_internal_modules", doc = "```rust")]
    #[cfg_attr(not(feature = "expose_internal_modules"), doc = "```ignore")]
    /// use rosenpass::internal::util::int::modular::Modulus;
    ///
    /// fn m(v: u8) -> Modulus<u8> {
    ///   Modulus::new_or_panic(v)
    /// }
    ///
    /// assert_eq!(m(100).double(), Some(m(200)));
    /// assert_eq!(m(128).double(), Some(Modulus::new_full_range()));
    /// assert_eq!(m(129).double(), None);
    /// ```
    pub fn double(&self) -> Option<Self> {
        let s = self.modulus()?;
        match s.overflowing_add(&s) {
            (d, true) if d > T::zero() => None,
            (d, _) => Some(Self::raw_new(d)),
        }
    }

    /// Create a new [ModularArithmetic] by taking the value modulo the modulus
    pub fn new_number<U: Into<T>>(self, value: U) -> ModularArithmetic<T>
    where
        T: ModularArithmeticBase,
    {
        ModularArithmetic::modular_new(value.into(), self)
    }

    /// Apply [Self::new_number] to each of the parameters, return whatever result the closure
    /// produces
    pub fn with_converted<U, const N: usize, R, F>(&self, params: [U; N], f: F) -> R
    where
        Self: Copy,
        T: std::fmt::Debug + ModularArithmeticBase,
        U: Into<T>,
        F: FnOnce([ModularArithmetic<T>; N]) -> R,
    {
        let params = params.map(|v| self.new_number(v));
        f(params)
    }

    /// Apply [Self::new_number] to each of the parameters, converting the result to the underlying
    /// representation
    pub fn formula<U, const N: usize, F>(&self, params: [U; N], f: F) -> T
    where
        Self: Copy,
        T: std::fmt::Debug + ModularArithmeticBase,
        U: Into<T>,
        F: FnOnce([ModularArithmetic<T>; N]) -> ModularArithmetic<T>,
    {
        self.with_converted(params, f).value()
    }
}

/// Summary trait for types that can serve as the basis for [ModularArithmetic]
pub trait ModularArithmeticBase:
    ModuleBase
    + std::fmt::Debug
    + Num
    + PartialOrd
    + Ord
    + Copy
    + Unsigned
    + CheckedMul
    + Euclid
    + WrappingNeg
{
}
impl<T> ModularArithmeticBase for T where
    T: ModuleBase
        + std::fmt::Debug
        + Num
        + PartialOrd
        + Ord
        + Copy
        + Unsigned
        + CheckedMul
        + Euclid
        + WrappingNeg
{
}

/// Modular arithmetic with an arbitrary modulus
#[derive(Debug, Copy, Clone)]
pub struct ModularArithmetic<T: ModularArithmeticBase> {
    /// The modulus
    modulus: Modulus<T>,
    /// The value inside the modulus
    ///
    /// Note that `self.modulus.contains(self.value)` must always hold.
    value: T,
}

impl<T: ModularArithmeticBase> ModularArithmetic<T> {
    /// Construct a new [Self].
    ///
    /// Will return `None` unless `module.`[contains](Modulus::contains)`(value)`.
    pub fn try_new(value: T, module: Modulus<T>) -> Option<Self> {
        module.contains(value).then_some(Self {
            value,
            modulus: module,
        })
    }

    /// Construct a new [Self].
    ///
    /// # Panic
    ///
    /// Will panic unless `module.`[contains](Modulus::contains)`(value)`.
    pub fn modular_new(value: T, module: Modulus<T>) -> Self {
        let value = match module.modulus() {
            Some(m) => value.rem_euclid(&m),
            None => value,
        };

        Self {
            modulus: module,
            value,
        }
    }

    /// Return the modulus
    pub fn modulus(&self) -> &Modulus<T> {
        &self.modulus
    }

    /// The inner value
    pub fn value(&self) -> T {
        self.value
    }
}

impl<T: ModularArithmeticBase> PartialEq for ModularArithmetic<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: ModularArithmeticBase> Eq for ModularArithmetic<T> {}

impl<T: ModularArithmeticBase> PartialOrd for ModularArithmetic<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: ModularArithmeticBase> Ord for ModularArithmetic<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl<T: ModularArithmeticBase> std::ops::Neg for ModularArithmetic<T> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let ret = match self.modulus().modulus() {
            None => self.value().wrapping_neg(),
            // `modulus - 0` would be the modulus itself, which is not contained
            // in the modulus; the canonical representative of -0 is 0
            Some(modulus) => match self.value().is_zero() {
                true => T::zero(),
                false => modulus - self.value(),
            },
        };

        Self {
            value: ret,
            modulus: self.modulus,
        }
    }
}

impl<T: ModularArithmeticBase> std::ops::Sub for ModularArithmetic<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        assert_eq!(self.modulus(), rhs.modulus());

        if self < rhs {
            return -(rhs - self);
        }

        Self {
            value: self.value() - rhs.value(),
            modulus: self.modulus,
        }
    }
}

impl<T: ModularArithmeticBase> std::ops::Add for ModularArithmetic<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self - (-rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The negation of zero must be zero itself, not the modulus;
    /// both denote the same element of Z/nZ and zero is its canonical
    /// representative (only zero upholds the `value < modulus` invariant)
    #[test]
    fn neg_zero_is_zero() {
        let m = Modulus::<u8>::new_or_panic(17);
        let zero = m.new_number(0u8);
        assert_eq!(-zero, zero);
        assert_eq!((-zero).value(), 0);
    }

    /// Negation must be an involution
    #[test]
    fn neg_neg_is_identity() {
        let m = Modulus::<u8>::new_or_panic(17);
        for v in [0u8, 1, 2, 5, 8, 16] {
            let a = m.new_number(v);
            assert_eq!(-(-a), a);
        }

        let m = Modulus::<u64>::new_full_range();
        for v in [0u64, 1, 2, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            let a = m.new_number(v);
            assert_eq!(-(-a), a);
        }
    }

    /// Exhaustively verify the arithmetic properties of [ModularArithmetic]
    /// over several small moduli, including the edge modulus 1 (whose only
    /// element is zero). Deterministic; no randomness.
    #[test]
    fn exhaustive_properties_small_moduli() {
        for modulus in [1u16, 2, 3, 5, 17, 256] {
            let m = Modulus::new_or_panic(modulus);
            let zero = m.new_number(0u16);
            assert_eq!(-zero, zero, "-0 must be 0 (modulus {modulus})");
            for a in 0..modulus {
                let a = m.new_number(a);
                // Results must stay within the modulus
                assert!(m.contains((-a).value()));
                assert_eq!(-(-a), a);
                assert_eq!(a + zero, a, "0 must be the additive identity");
                for b in 0..modulus {
                    let b = m.new_number(b);
                    assert!(m.contains((a + b).value()));
                    assert!(m.contains((a - b).value()));
                    assert_eq!(a + b, b + a, "addition must be commutative");
                    assert_eq!((a + b) - b, a, "subtraction must undo addition");
                }
            }
        }
    }

    /// Spot-check the same properties for the full-range modulus (the whole
    /// range of the underlying type; exhaustive testing is infeasible there)
    #[test]
    fn full_range_properties() {
        let m = Modulus::<u64>::new_full_range();
        let zero = m.new_number(0u64);
        assert_eq!(-zero, zero);
        for a in [0u64, 1, 2, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            let a = m.new_number(a);
            assert_eq!(-(-a), a);
            assert_eq!(a + zero, a);
            for b in [0u64, 1, u64::MAX] {
                let b = m.new_number(b);
                assert_eq!(a + b, b + a);
                assert_eq!((a + b) - b, a);
            }
        }
    }
}
