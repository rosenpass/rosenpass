# The To Crate – Patterns for dealing with destination parameters in rust functions

<!-- The code blocks in this file double as tests. -->

![crates.io](https://img.shields.io/crates/v/rosenpass-to.svg)
![Libraries.io dependency status for latest release](https://img.shields.io/librariesio/release/cargo/rosenpass-to)

The To Crate provides a pattern for declaring and dealing with destination parameters in rust functions. It improves over stock rust by providing an interface that allows the caller to choose whether to place the destination parameter first – through a `to(dest, copy(source))` function – or last – through a chained function `copy(source).to(dest)`.

The crate provides chained functions to simplify allocating the destination parameter on the fly and it provides well defined patterns for dealing with error handling and destination parameters.

For now this crate is experimental; patch releases are guaranteed not to contain any breaking changes, but minor releases may.

```rust
use rosenpass_to::ops::copy_array;
use rosenpass_to::{to, with_destination, To};
use std::ops::BitXorAssign;

// Destination functions return some value that implements the To trait.
// Unfortunately dealing with lifetimes is a bit more finicky than it would#
// be without destination parameters
fn xor_slice<'a, T>(src: &'a [T]) -> impl To<[T], ()> + 'a
where
    T: BitXorAssign + Clone,
{
    // Custom implementations of the to trait can be created, but the easiest
    with_destination(move |dst: &mut [T]| {
        assert!(src.len() == dst.len());
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d ^= s.clone();
        }
    })
}

let flip0 = b"\xff\x00\x00\x00";
let flip1 = b"\x00\xff\x00\x00";
let flip01 = b"\xff\xff\x00\x00";

// You can specify a destination by using the to method
let mut dst = [0u8; 4];
xor_slice(flip0).to(&mut dst);
xor_slice(flip1).to(&mut dst);
assert_eq!(&dst[..], &flip01[..]);

// Or using the to function
let mut dst = [0u8; 4];
to(&mut dst, xor_slice(flip0));
to(&mut dst, xor_slice(flip1));
assert_eq!(&dst[..], &flip01[..]);

// You can pass a function to generate the destination on the fly
let dst = xor_slice(flip1).to_this(|| flip0.to_vec());
assert_eq!(&dst[..], &flip01[..]);

// If xor_slice used a return value that could be created using Default::default(),
// you could just use `xor_slice(flip01).to_value()` to generate the destination
// on the fly. Since [u8] is unsized, it can only be used for references.
//
// You can however use collect to specify the storage value explicitly.
// This works for any type that implements Default::default() and BorrowMut<...> for
// the destination value.

// Collect in an array with a fixed size
let dst = xor_slice(flip01).collect::<[u8; 4]>();
assert_eq!(&dst[..], &flip01[..]);

// The builtin function copy_array supports to_value() since its
// destination parameter is a fixed size array, which can be allocated
// using default()
let dst: [u8; 4] = copy_array(flip01).to_value();
assert_eq!(&dst, flip01);
```

The to crate really starts to shine when error handling (through result) is combined with destination parameters. See the tutorial below for details.

## Motivation

Destination parameters are often used when simply returning the value is undesirable or impossible.

Using stock rust features, functions can declare destination parameters by accepting mutable references as arguments.
This pattern introduces some shortcomings; developers have to make a call on whether to place destination parameters before or after source parameters and they have to enforce consistency across their codebase or accept inconsistencies, leading to hard-to-remember interfaces.

Functions declared like this are more cumbersome to use when the destination parameter should be allocated on the fly.

```rust
use std::ops::BitXorAssign;

fn xor_slice<T>(dst: &mut [T], src: &[T])
where
    T: BitXorAssign + Clone,
{
    assert!(src.len() == dst.len());
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s.clone();
    }
}

let flip0 = b"\xff\x00\x00\x00";
let flip1 = b"\x00\xff\x00\x00";
let flip01 = b"\xff\xff\x00\x00";

// Copy a slice from src to dest; its unclear whether src or dest should come first
let mut dst = [0u8; 4];
xor_slice(&mut dst, flip0);
xor_slice(&mut dst, flip1);
assert_eq!(&dst[..], &flip01[..]);

// The other examples can not be translated to use the standard rust pattern,
// since using mutable references for destination parameters does not allow
// for specifying the destination parameter on the right side or allocating
// the destination parameter on the fly.
```

## Tutorial

### Using a function with destination

There are a couple of ways to use a function with destination:

```rust
use rosenpass_to::ops::{copy_array, copy_slice_least};
use rosenpass_to::{to, To};

let mut dst = b"           ".to_vec();

// Using the to function to have data flowing from the right to the left,
// performing something akin to a variable assignment
to(&mut dst[..], copy_slice_least(b"Hello World"));
assert_eq!(&dst[..], b"Hello World");

// Using the to method to have information flowing from the left to the right
copy_slice_least(b"This is fin").to(&mut dst[..]);
assert_eq!(&dst[..], b"This is fin");

// You can allocate the destination variable on the fly using `.to_this(...)`
let tmp =
    copy_slice_least(b"This is new---").to_this(|| b"This will be overwritten".to_owned());
assert_eq!(&tmp[..], b"This is new---verwritten");

// You can allocate the destination variable on the fly `.collect(..)` if it implements default
let tmp = copy_slice_least(b"This is ad-hoc").collect::<[u8; 16]>();
assert_eq!(&tmp[..], b"This is ad-hoc\0\0");

// Finally, if the destination variable specified by the function implements default,
// you can simply use `.to_value()` to allocate it on the fly.
let tmp = copy_array(b"Fixed").to_value();
assert_eq!(&tmp[..], b"Fixed");
```

### Builtin functions with destination

The to crate provides basic functions with destination for copying data between slices and arrays.

```rust
use rosenpass_to::ops::{
    copy_array, copy_slice, copy_slice_least, copy_slice_least_src, try_copy_slice,
    try_copy_slice_least_src,
};
use rosenpass_to::{to, To};

let mut dst = b"           ".to_vec();

// Copy a slice, source and destination must match exactly
to(&mut dst[..], copy_slice(b"Hello World"));
assert_eq!(&dst[..], b"Hello World");

// Copy a slice, destination must be at least as long as the destination
to(&mut dst[4..], copy_slice_least_src(b"!!!"));
assert_eq!(&dst[..], b"Hell!!!orld");

// Copy a slice, copying as many bytes as possible
to(
    &mut dst[6..],
    copy_slice_least(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
);
assert_eq!(&dst[..], b"Hell!!xxxxx");

// Copy a slice, will return None and abort if the sizes do not much
assert_eq!(Some(()), to(&mut dst[..], try_copy_slice(b"Hello World")));
assert_eq!(None, to(&mut dst[..], try_copy_slice(b"---")));
assert_eq!(
    None,
    to(&mut dst[..], try_copy_slice(b"---------------------"))
);
assert_eq!(&dst[..], b"Hello World");

// Copy a slice, will return None and abort if source is longer than destination
assert_eq!(
    Some(()),
    to(&mut dst[4..], try_copy_slice_least_src(b"!!!"))
);
assert_eq!(
    None,
    to(
        &mut dst[4..],
        try_copy_slice_least_src(b"-------------------------")
    )
);
assert_eq!(&dst[..], b"Hell!!!orld");

// Copy fixed size arrays all at once
let mut dst = [0u8; 5];
to(&mut dst, copy_array(b"Hello"));
assert_eq!(&dst, b"Hello");
```

### Declaring a function with destination

The easiest way to declare a function with destination is to use the with_destination function.

```rust
use rosenpass_to::ops::copy_array;
use rosenpass_to::{to, with_destination, To};

/// Copy the given slice to the start of a vector, reusing its memory if possible
fn copy_to_vec<'a, T>(src: &'a [T]) -> impl To<Vec<T>, ()> + 'a
where
    T: Clone,
{
    with_destination(move |dst: &mut Vec<T>| {
        dst.clear();
        dst.extend_from_slice(src);
    })
}

let mut buf = copy_to_vec(b"Hello World, this is a long text.").to_value();
assert_eq!(&buf[..], b"Hello World, this is a long text.");

to(&mut buf, copy_to_vec(b"Avoids allocation"));
assert_eq!(&buf[..], b"Avoids allocation");
```

This example also shows of some of the advantages of using To: The function gains a very slight allocate over using `.to_vec()` by reusing memory:

```rust
let mut buf = b"Hello World, this is a long text.".to_vec();
buf = b"This allocates".to_vec(); // This uses memory allocation
```

The same pattern can be implemented without `to`, at the cost of being slightly more verbose

```rust
/// Copy the given slice to the start of a vector, reusing its memory if possible
fn copy_to_vec<T>(dst: &mut Vec<T>, src: &[T])
where
    T: Clone,
{
    dst.clear();
    dst.extend_from_slice(src);
}

let mut buf = Vec::default();
copy_to_vec(&mut buf, b"Hello World, this is a long text.");
assert_eq!(&buf[..], b"Hello World, this is a long text.");

copy_to_vec(&mut buf, b"Avoids allocation");
assert_eq!(&buf[..], b"Avoids allocation");
```

This usability enhancement might seem minor, but when many functions take destination parameters, manually allocating all of these can really become annoying.

## Beside values: Functions with destination and return value

Return values are supported, but `from_this()`, `to_value()`, and `collect()` cannot be used together with return values (unless they implement CondenseBeside – see the next section), since that would erase the return value.

Alternative functions are returned, that return a `to::Beside` value, containing both the
destination variable and the return value.

```rust
use rosenpass_to::{to, with_destination, Beside, To};
use std::cmp::{max, min};

/// Copy an array of floats and calculate the average
pub fn copy_and_average<'a>(src: &'a [f64]) -> impl To<[f64], f64> + 'a {
    with_destination(move |dst: &mut [f64]| {
        assert!(src.len() == dst.len());
        let mut sum = 0f64;
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d = *s;
            sum = sum + *d;
        }
        sum / (src.len() as f64)
    })
}

let src = [12f64, 13f64, 14f64];

// `.to()` and `to(...)` function as normal, but return the value now
let mut dst = [0f64; 3];
let avg = copy_and_average(&src).to(&mut dst);
assert_eq!((&dst[..], avg), (&src[..], 13f64));

let mut dst = [0f64; 3];
let avg = to(&mut dst, copy_and_average(&src));
assert_eq!((&dst[..], avg), (&src[..], 13f64));

// Instead of .to_this, .to_value, or .collect variants returning a beside value have to be used

let Beside(dst, avg) = copy_and_average(&src).to_this_beside(|| [0f64; 3]);
assert_eq!((&dst[..], avg), (&src[..], 13f64));

let Beside(dst, avg) = copy_and_average(&src).collect_beside::<[f64; 3]>();
assert_eq!((&dst[..], avg), (&src[..], 13f64));

// Beside values are simple named tuples

let b = copy_and_average(&src).collect_beside::<[f64; 3]>();
assert_eq!(b, Beside(dst, avg));

// They can convert from and to tuples
let b_tup = (dst, avg);
assert_eq!(b, (dst, avg).into());
assert_eq!(b, Beside::from(b_tup));

// Simple accessors for the value and returned value are provided
assert_eq!(&dst, b.dest());
assert_eq!(&avg, b.ret());

let mut tmp = b;
*tmp.dest_mut() = [42f64; 3];
*tmp.ret_mut() = 42f64;
assert_eq!(tmp, Beside([42f64; 3], 42f64));
```

## Beside Condensation: Working with destinations and Optional or Result

When Beside values contain a `()`, `Option<()>`, or `Result<(), Error>` return value, they expose a special method called `.condense()`; this method consumes the Beside value and condenses destination and return value into one value.

```rust
use rosenpass_to::Beside;
use std::result::Result;

assert_eq!((), Beside((), ()).condense());

assert_eq!(42, Beside(42, ()).condense());
assert_eq!(None, Beside(42, None).condense());

let ok_unit = Result::<(), ()>::Ok(());
assert_eq!(Ok(42), Beside(42, ok_unit).condense());

let err_unit = Result::<(), ()>::Err(());
assert_eq!(Err(()), Beside(42, err_unit).condense());
```

When condense is implemented for a type, `.to_this(|| ...)`, `.to_value()`, and `.collect::<...>()` on the `To` trait can be used even with a return value:

```rust
use rosenpass_to::ops::try_copy_slice;
use rosenpass_to::To;

let tmp = try_copy_slice(b"Hello World").collect::<[u8; 11]>();
assert_eq!(tmp, Some(*b"Hello World"));

let tmp = try_copy_slice(b"Hello World").collect::<[u8; 2]>();
assert_eq!(tmp, None);

let tmp = try_copy_slice(b"Hello World").to_this(|| [0u8; 11].to_vec());
assert_eq!(tmp, Some(b"Hello World".to_vec()));

let tmp = try_copy_slice(b"Hello World").to_this(|| [0u8; 2].to_vec());
assert_eq!(tmp, None);
```

The same naturally also works for Results, but the example is a bit harder to motivate:

```rust
use rosenpass_to::{to, with_destination, To};
use std::result::Result;

#[derive(PartialEq, Eq, Debug, Default)]
struct InvalidFloat;

fn check_float(f: f64) -> Result<(), InvalidFloat> {
    if f.is_normal() || f == 0.0 {
        Ok(())
    } else {
        Err(InvalidFloat)
    }
}

fn checked_add<'a>(src: f64) -> impl To<f64, Result<(), InvalidFloat>> + 'a {
    with_destination(move |dst: &mut f64| {
        check_float(src)?;
        check_float(*dst)?;
        *dst += src;
        Ok(())
    })
}

let mut tmp = 0.0;
checked_add(14.0).to(&mut tmp).unwrap();
checked_add(12.0).to(&mut tmp).unwrap();
assert_eq!(tmp, 26.0);

assert_eq!(Ok(78.0), checked_add(14.0).to_this(|| 64.0));
assert_eq!(Ok(14.0), checked_add(14.0).to_value());
assert_eq!(Ok(14.0), checked_add(14.0).collect());

assert_eq!(Err(InvalidFloat), checked_add(f64::NAN).to_this(|| 64.0));
assert_eq!(Err(InvalidFloat), checked_add(f64::INFINITY).to_value());
```

## Custom condensation

Condensation is implemented through a trait called CondenseBeside ([local](CondenseBeside) | [docs.rs](https://docs.rs/to/latest/rosenpass-to/trait.CondenseBeside.html)). You can implement it for your own types.

If you can not implement this trait because its for an external type (see [orphan rule](https://doc.rust-lang.org/book/ch10-02-traits.html#implementing-a-trait-on-a-type)), this crate welcomes contributions of new Condensation rules.

```rust
use rosenpass_to::ops::copy_slice;
use rosenpass_to::{with_destination, Beside, CondenseBeside, To};

#[derive(PartialEq, Eq, Debug, Default)]
struct MyTuple<Left, Right>(Left, Right);

impl<Val, Right> CondenseBeside<Val> for MyTuple<(), Right> {
    type Condensed = MyTuple<Val, Right>;

    fn condense(self, val: Val) -> MyTuple<Val, Right> {
        let MyTuple((), right) = self;
        MyTuple(val, right)
    }
}

fn copy_slice_and_return_something<'a, T, U>(src: &'a [T], something: U) -> impl To<[T], U> + 'a
where
    T: Copy,
    U: 'a,
{
    with_destination(move |dst: &mut [T]| {
        copy_slice(src).to(dst);
        something
    })
}

let tmp = Beside(42, MyTuple((), 23)).condense();
assert_eq!(tmp, MyTuple(42, 23));

let tmp = copy_slice_and_return_something(b"23", MyTuple((), 42)).collect::<[u8; 2]>();
assert_eq!(tmp, MyTuple(*b"23", 42));
```

## Manually implementing the To trait

Using `with_destination(...)` is convenient, but since it uses closures it results in an type that can not be written down, which is why the `-> impl To<...>` pattern is used everywhere in this tutorial.

Implementing the ToTrait manual is the right choice for library use cases.

```rust
use rosenpass_to::{to, with_destination, To};

struct TryCopySliceSource<'a, T: Copy> {
    src: &'a [T],
}

impl<'a, T: Copy> To<[T], Option<()>> for TryCopySliceSource<'a, T> {
    fn to(self, dst: &mut [T]) -> Option<()> {
        (self.src.len() == dst.len()).then(|| dst.copy_from_slice(self.src))
    }
}

fn try_copy_slice<'a, T>(src: &'a [T]) -> TryCopySliceSource<'a, T>
where
    T: Copy,
{
    TryCopySliceSource { src }
}

let mut dst = try_copy_slice(b"Hello World")
    .collect::<[u8; 11]>()
    .unwrap();
assert_eq!(&dst[..], b"Hello World");
assert_eq!(None, to(&mut dst[..], try_copy_slice(b"---")));
```

## Methods with destination

Destinations can also be used with methods. This example demonstrates using destinations in an extension trait for everything that implements `Borrow<[T]>` for any `T` and a concrete `To` trait implementation.

```rust
use rosenpass_to::{to, with_destination, To};
use std::borrow::Borrow;

struct TryCopySliceSource<'a, T: Copy> {
    src: &'a [T],
}

impl<'a, T: Copy> To<[T], Option<()>> for TryCopySliceSource<'a, T> {
    fn to(self, dst: &mut [T]) -> Option<()> {
        (self.src.len() == dst.len()).then(|| dst.copy_from_slice(self.src))
    }
}

trait TryCopySliceExt<'a, T: Copy> {
    fn try_copy_slice(&'a self) -> TryCopySliceSource<'a, T>;
}

impl<'a, T: 'a + Copy, Ref: 'a + Borrow<[T]>> TryCopySliceExt<'a, T> for Ref {
    fn try_copy_slice(&'a self) -> TryCopySliceSource<'a, T> {
        TryCopySliceSource { src: self.borrow() }
    }
}

let mut dst = b"Hello World"
    .try_copy_slice()
    .collect::<[u8; 11]>()
    .unwrap();
assert_eq!(&dst[..], b"Hello World");
assert_eq!(None, to(&mut dst[..], b"---".try_copy_slice()));
```
