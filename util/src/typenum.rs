use typenum::bit::{B0, B1};
use typenum::int::{NInt, PInt, Z0};
use typenum::marker_traits as markers;
use typenum::uint::{UInt, UTerm};

/// Convenience macro to convert [`typenum`] type numbers to constant integers.
///
/// This macro takes a [`typenum`] type-level integer (like `U5`, `P3`, or `N7`)
/// and converts it into its equivalent constant integer value at compile time.
/// By default, it converts to a suitable unsigned integer type, but you can
/// specify a target type explicitly using `typenum2const!(Type as i32)`,
/// for example.
///
/// # Examples
///
/// ```rust
/// # use typenum::consts::U10;
/// # use rosenpass_util::typenum2const;
///
/// const TEN: u32 = typenum2const!(U10 as u32);
/// assert_eq!(TEN, 10);
/// ```
#[macro_export]
macro_rules! typenum2const {
    ($val:ty) => {
        typenum2const!($val as _)
    };
    ($val:ty as $type:ty) => {
        <$val as $crate::typenum::IntoConst<$type>>::VALUE
    };
}

/// A trait implemented by type-level integers to facilitate their conversion
/// into constant values.
///
/// Types from the [`typenum`] crate (like `U5`, `P3`, or `N7`) can implement
/// `IntoConst` to produce a compile-time constant integer of the specified
/// type. This trait is part of the underlying mechanism used by the
/// [`crate::typenum2const`] macro.
///
/// # Examples
///
/// ```rust
/// use rosenpass_util::typenum2const;
/// use typenum::consts::U42;
/// use rosenpass_util::typenum::IntoConst;
///
/// // Directly using IntoConst:
/// const VALUE: u64 = <U42 as IntoConst<u64>>::VALUE;
/// assert_eq!(VALUE, 42);
///
/// // Or via the macro:
/// const VALUE_MACRO: u64 = typenum2const!(U42 as u64);
/// assert_eq!(VALUE_MACRO, 42);
/// ```
pub trait IntoConst<T> {
    /// The constant value after conversion.
    const VALUE: T;
}

#[allow(dead_code)]
/// Internal struct for applying a negative sign to an unsigned type-level integer during conversion.
///
/// This is part of the implementation detail for signed conversions. It uses
/// [`AssociatedUnsigned`] to determine the underlying unsigned type and negates its value.
struct ConstApplyNegSign<T: AssociatedUnsigned, Param: IntoConst<<T as AssociatedUnsigned>::Type>>(
    *const T,
    *const Param,
);

#[allow(dead_code)]
/// Internal struct for applying a positive sign to an unsigned type-level integer during conversion.
///
/// This is used as part of converting a positive signed type-level integer to its runtime integer
/// value, ensuring that the correct unsigned representation is known via [`AssociatedUnsigned`].
struct ConstApplyPosSign<T: AssociatedUnsigned, Param: IntoConst<<T as AssociatedUnsigned>::Type>>(
    *const T,
    *const Param,
);

#[allow(dead_code)]
/// Internal struct representing a left-shift operation on a type-level integer.
///
/// Used as part of compile-time computations. `SHIFT` determines how many bits the value will be
/// shifted to the left.
struct ConstLshift<T, Param: IntoConst<T>, const SHIFT: i32>(*const T, *const Param);

#[allow(dead_code)]
/// Internal struct representing an addition operation between two type-level integers.
///
/// `ConstAdd` is another building block for compile-time arithmetic on type-level integers before
/// their conversion to runtime constants.
struct ConstAdd<T, Lhs: IntoConst<T>, Rhs: IntoConst<T>>(*const T, *const Lhs, *const Rhs);

/// Associates an unsigned type with a signed type, enabling conversions between signed and unsigned
/// representations of compile-time integers.
///
/// This trait is used internally to facilitate the conversion of signed [`typenum`] integers by
/// referencing their underlying unsigned representation.
trait AssociatedUnsigned {
    /// The associated unsigned type.
    type Type;
}

/// Internal macro implementing the [`IntoConst`] trait for a given mapping from a type-level integer
/// to a concrete integer type.
macro_rules! impl_into_const {
    ( $from:ty as $to:ty := $impl:expr) => {
        impl IntoConst<$to> for $from {
            const VALUE: $to = $impl;
        }
    };
}

/// Internal macro implementing common `IntoConst` logic for various numeric types.
///
/// It sets up `Z0`, `B0`, `B1`, `UTerm`, and also provides default implementations for
/// `ConstLshift` and `ConstAdd`.
macro_rules! impl_numeric_into_const_common {
    ($type:ty) => {
        impl_into_const! { Z0 as $type := 0 }
        impl_into_const! { B0 as $type := 0 }
        impl_into_const! { B1 as $type := 1 }
        impl_into_const! { UTerm as $type := 0 }

        impl<Param: IntoConst<$type>, const SHIFT: i32> IntoConst<$type>
            for ConstLshift<$type, Param, SHIFT>
        {
            const VALUE: $type = Param::VALUE << SHIFT;
        }

        impl<Lhs: IntoConst<$type>, Rhs: IntoConst<$type>> IntoConst<$type>
            for ConstAdd<$type, Lhs, Rhs>
        {
            const VALUE: $type =
                <Lhs as IntoConst<$type>>::VALUE + <Rhs as IntoConst<$type>>::VALUE;
        }
    };
}

/// Internal macro implementing `IntoConst` for unsigned integer types.
///
/// It sets up conversions for multiple unsigned integer target types and
/// provides the positive sign application implementation.
macro_rules! impl_numeric_into_const_unsigned {
    ($($to_list:ty),*) =>  {
        $( impl_numeric_into_const_unsigned! { @impl $to_list } )*
    };

    (@impl $type:ty) =>  {
        impl_numeric_into_const_common!{ $type }

        impl AssociatedUnsigned for $type {
            type Type = $type;
        }

        impl<Param: IntoConst<$type>> IntoConst<$type> for ConstApplyPosSign<$type, Param> {
            const VALUE : $type = Param::VALUE;
        }
    };
}

/// Internal macro implementing `IntoConst` for signed integer types.
///
/// It uses their associated unsigned types to handle positive and negative conversions correctly.
macro_rules! impl_numeric_into_const_signed {
    ($($to_list:ty : $unsigned_list:ty),*) =>  {
        $( impl_numeric_into_const_signed! { @impl $to_list : $unsigned_list} )*
    };

    (@impl $type:ty : $unsigned:ty) =>  {
        impl_numeric_into_const_common!{ $type }

        impl AssociatedUnsigned for $type {
            type Type = $unsigned;
        }

        impl<Param: IntoConst<$unsigned>> IntoConst<$type> for ConstApplyPosSign<$type, Param> {
            const VALUE : $type = Param::VALUE as $type;
        }

        impl<Param: IntoConst<$unsigned>> IntoConst<$type> for ConstApplyNegSign<$type, Param> {
            const VALUE : $type =
                if Param::VALUE == (1 as $unsigned).rotate_right(1) {
                    // Handling negative values at boundaries, such as i8::MIN
                    <$type>::MIN
                } else {
                    -(Param::VALUE as $type)
                };
        }
    };
}

impl_into_const! { B0 as bool := false }
impl_into_const! { B1 as bool := true }

impl_numeric_into_const_unsigned! { usize, u8, u16, u32, u64, u128 }
impl_numeric_into_const_signed! { isize : usize, i8 : u8, i16 : u16, i32 : u32, i64 : u64, i128 : u128 }

impl<Ret, Rest, Bit> IntoConst<Ret> for UInt<Rest, Bit>
where
    Rest: IntoConst<Ret>,
    Bit: IntoConst<Ret>,
    ConstLshift<Ret, Rest, 1>: IntoConst<Ret>,
    ConstAdd<Ret, ConstLshift<Ret, Rest, 1>, Bit>: IntoConst<Ret>,
{
    /// Converts an unsigned [`UInt`] typenum into its corresponding constant integer by
    /// decomposing it into shifts and additions on its subparts.
    const VALUE: Ret = <ConstAdd<Ret, ConstLshift<Ret, Rest, 1>, Bit> as IntoConst<Ret>>::VALUE;
}

impl<Ret, Unsigned> IntoConst<Ret> for PInt<Unsigned>
where
    Ret: AssociatedUnsigned,
    Unsigned: markers::Unsigned + markers::NonZero + IntoConst<<Ret as AssociatedUnsigned>::Type>,
    ConstApplyPosSign<Ret, Unsigned>: IntoConst<Ret>,
{
    /// Converts a positive signed [`PInt`] typenum into its corresponding constant integer.
    const VALUE: Ret = <ConstApplyPosSign<Ret, Unsigned> as IntoConst<Ret>>::VALUE;
}

impl<Ret, Unsigned> IntoConst<Ret> for NInt<Unsigned>
where
    Ret: AssociatedUnsigned,
    Unsigned: markers::Unsigned + markers::NonZero + IntoConst<<Ret as AssociatedUnsigned>::Type>,
    ConstApplyNegSign<Ret, Unsigned>: IntoConst<Ret>,
{
    /// Converts a negative signed [`NInt`] typenum into its corresponding constant integer.
    const VALUE: Ret = <ConstApplyNegSign<Ret, Unsigned> as IntoConst<Ret>>::VALUE;
}

#[allow(clippy::identity_op)]
mod test {
    use static_assertions::const_assert_eq;
    use typenum::consts::*;
    use typenum::op;

    macro_rules! test_const_conversion {
        // Type groups

        (($($typenum:ty),*) >= u7 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (u8, u16, u32, u64, u128) = $const } )*
            $( test_const_conversion! { ($typenum) as (i8, i16, i32, i64, i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= u8 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (u8, u16, u32, u64, u128) = $const } )*
            $( test_const_conversion! { ($typenum) as (    i16, i32, i64, i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= u15 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (    u16, u32, u64, u128) = $const } )*
            $( test_const_conversion! { ($typenum) as (    i16, i32, i64, i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= u16 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (    u16, u32, u64, u128) = $const } )*
            $( test_const_conversion! { ($typenum) as (         i32, i64, i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= u31 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (         u32, u64, u128) = $const } )*
            $( test_const_conversion! { ($typenum) as (         i32, i64, i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= u32 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (         u32, u64, u128) = $const } )*
            $( test_const_conversion! { ($typenum) as (              i64, i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= u63 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (              u64, u128) = $const } )*
            $( test_const_conversion! { ($typenum) as (              i64, i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= u64 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (              u64, u128) = $const } )*
            $( test_const_conversion! { ($typenum) as (                   i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= u127 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (                   u128) = $const } )*
            $( test_const_conversion! { ($typenum) as (                   i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= u128 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (                   u128) = $const } )*
            $( test_const_conversion! { ($typenum) as (                       ) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= i8 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (i8, i16, i32, i64, i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= i16 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (    i16, i32, i64, i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= i32 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (         i32, i64, i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= i64 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (              i64, i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) >= i128 = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { ($typenum) as (                   i128) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        // Basic operation

        () => {};

        (($($typenum:ty),*) as () = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) as ($type:ty) = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { @impl ($typenum) as ($type) = $const } )*
            $( test_const_conversion! { $($rest)* } )?
        };

        (($($typenum:ty),*) as ($type_head:ty, $($type_tail:ty),*) = $const:expr $(; $($rest:tt)*)?) => {
            $( test_const_conversion! { @impl ($typenum) as ($type_head) = $const } )*
            test_const_conversion! { ($($typenum),*) as ($($type_tail),*) = $const }
            $( test_const_conversion! { $($rest)* } )?
        };

        (@impl ($typenum:ty) as ($type:ty) = $const:expr $(; $($rest:tt)*)?) => {
            const_assert_eq!(typenum2const!($typenum as $type), $const);
            $( test_const_conversion!($($rest)*); )?
        };
    }

    test_const_conversion! {
        (B0, False) as (bool, bool) = false;

        (B0, U0, Z0) >= u7 = 0;
        (B1, U1, P1) >= u7 = 1;

        (U2, P2) >= u7 = 2;
        (B1, True) as (bool) = true;
        (U3, P3) >= u7 = 3;
        (U8, P8) >= u7 = 8;
        (U127, P127) >= u7 = 127;
        (U220, P220) >= u8 = 220;
        (U255, P255) >= u8 = 255;
        (U1000, P1000) >= u15 = 1000;
        (U10000, P10000) >= u15 = 10000;
        (U16384, P16384) >= u15 = 16384;
        (U32768, P32768) >= u16 = 32768;
        (U65536, P65536) >= u31 = 65536;
        (U100000, P100000) >= u31 = 100000;
        (U1000000000, P1000000000) >= u31 = 1000000000;
        (U2147483648, P2147483648) >= u32 = 2147483648;
        (U1000000000000000000, P1000000000000000000) >= u63 = 1000000000000000000;
        (U1000000000000000000, P1000000000000000000) >= u63 = 1000000000000000000;

        (U9223372036854775808) >= u64 = 9223372036854775808;
        (U10000000000000000000) >= u64 = 10000000000000000000;

        (N10000) >= i16 = -10000;
        (N1000000) >= i32 = -1000000;
        (N1000000000) >= i32 = -1000000000;
        (N1000000000000) >= i64 = -1000000000000;
    }

    const_assert_eq!(127, (!(1u8.rotate_right(1)) - 0) as _);
    const_assert_eq!(126, (!(1u8.rotate_right(1)) - 1) as _);
    const_assert_eq!(255, (!(0u8.rotate_right(1)) - 0) as _);
    const_assert_eq!(254, (!(0u8.rotate_right(1)) - 1) as _);

    test_const_conversion! {
        (op!(pow(U2, U7) - U1))   >= u7   = (!(1u8.rotate_right(1)) - 0) as _;
        (op!(pow(U2, U7) - U2))   >= u7   = (!(1u8.rotate_right(1)) - 1) as _;
        (op!(pow(U2, U15) - U1))  >= u15  = (!(1u16.rotate_right(1)) - 0) as _;
        (op!(pow(U2, U15) - U2))  >= u15  = (!(1u16.rotate_right(1)) - 1) as _;
        (op!(pow(U2, U31) - U1))  >= u31  = (!(1u32.rotate_right(1)) - 0) as _;
        (op!(pow(U2, U31) - U2))  >= u31  = (!(1u32.rotate_right(1)) - 1) as _;
        (op!(pow(U2, U63) - U1))  >= u63  = (!(1u64.rotate_right(1)) - 0) as _;
        (op!(pow(U2, U63) - U2))  >= u63  = (!(1u64.rotate_right(1)) - 1) as _;
        (op!(pow(U2, U127) - U1)) >= u127 = (!(1u128.rotate_right(1)) - 0) as _;
        (op!(pow(U2, U127) - U2)) >= u127 = (!(1u128.rotate_right(1)) - 1) as _;

        (op!(pow(U2, U8) - U1))   >= u8   = (u8::MAX - 0) as _;
        (op!(pow(U2, U8) - U2))   >= u8   = (u8::MAX - 1) as _;
        (op!(pow(U2, U16) - U1))  >= u16  = (u16::MAX - 0) as _;
        (op!(pow(U2, U16) - U2))  >= u16  = (u16::MAX - 1) as _;
        (op!(pow(U2, U32) - U1))  >= u32  = (u32::MAX - 0) as _;
        (op!(pow(U2, U32) - U2))  >= u32  = (u32::MAX - 1) as _;
        (op!(pow(U2, U64) - U1))  >= u64  = (u64::MAX - 0) as _;
        (op!(pow(U2, U64) - U2))  >= u64  = (u64::MAX - 1) as _;
        (op!(pow(U2, U128) - U1)) >= u128 = (u128::MAX - 0) as _;
        (op!(pow(U2, U128) - U2)) >= u128 = (u128::MAX - 1) as _;

        (op!(Z0 - pow(P2, P7) + Z0)) >= i8 = (i8::MIN + 0) as _;
        (op!(Z0 - pow(P2, P7) + P1)) >= i8 = (i8::MIN + 1) as _;
        (op!(Z0 - pow(P2, P15) + Z0)) >= i16 = (i16::MIN + 0) as _;
        (op!(Z0 - pow(P2, P15) + P1)) >= i16 = (i16::MIN + 1) as _;
        (op!(Z0 - pow(P2, P31) + Z0)) >= i32 = (i32::MIN + 0) as _;
        (op!(Z0 - pow(P2, P31) + P1)) >= i32 = (i32::MIN + 1) as _;
        (op!(Z0 - pow(P2, P63) + Z0)) >= i64 = (i64::MIN + 0) as _;
        (op!(Z0 - pow(P2, P63) + P1)) >= i64 = (i64::MIN + 1) as _;
        (op!(Z0 - pow(P2, P127) + Z0)) >= i128 = (i128::MIN + 0) as _;
        (op!(Z0 - pow(P2, P127) + P1)) >= i128 = (i128::MIN + 1) as _;
    }
}
