//! Numeric types for modular arithmetic

use num_traits::{
    ops::overflowing::OverflowingAdd, CheckedMul, Euclid, Num, Unsigned, WrappingNeg, Zero,
};

/// Summary-trait for numeric types that can serve as the basis for ModuleBase
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
            None => panic!("Can not create Module with modulus zero!"),
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

    /// Check if the given type is contained in the range represented by this [Self]
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
    /// ```rust
    /// use rosenpass_util::int::modular::Modulus;
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
    /// Will return none unless `module.`[contains](Modulus::contains)`(value)`.
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
    /// Will punic unless `module.`[contains](Modulus::contains)`(value)`.
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
            Some(modulus) => modulus - self.value(),
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
