//! A collection of control flow utility macros

#[macro_export]
/// A simple for loop to repeat a $body a number of times
///
/// # Examples
///
/// ```
/// use rosenpass_util::repeat;
/// let mut sum = 0;
/// repeat!(10, {
///     sum += 1;
/// });
/// assert_eq!(sum, 10);
/// ```
macro_rules! repeat {
    ($times:expr, $body:expr) => {
        for _ in 0..($times) {
            $body
        }
    };
}

#[macro_export]
/// Return unless the condition $cond is true, with return value $val, if given.
///
/// # Examples
///
/// ```
/// use rosenpass_util::return_unless;
/// fn test_fn() -> i32 {
///     return_unless!(true, 1);
///     0
/// }
/// assert_eq!(test_fn(), 0);
///
/// fn test_fn2() -> i32 {
///     return_unless!(false, 1);
///     0
/// }
/// assert_eq!(test_fn2(), 1);
/// ```
macro_rules! return_unless {
    ($cond:expr) => {
        if !($cond) {
            return;
        }
    };
    ($cond:expr, $val:expr) => {
        if !($cond) {
            return $val;
        }
    };
}

#[macro_export]
/// Return if the condition $cond is true, with return value $val, if given.
///
/// # Examples
///
/// ```
/// use rosenpass_util::return_if;
/// fn test_fn() -> i32 {
///     return_if!(true, 1);
///     0
/// }
/// assert_eq!(test_fn(), 1);
///
/// fn test_fn2() -> i32 {
///     return_if!(false, 1);
///     0
/// }
/// assert_eq!(test_fn2(), 0);
/// ```
macro_rules! return_if {
    ($cond:expr) => {
        if $cond {
            return;
        }
    };
    ($cond:expr, $val:expr) => {
        if $cond {
            return $val;
        }
    };
}

#[macro_export]
/// Break unless the condition is true, from the loop with label $val, if given.
///
/// # Examples
///
/// ```
/// use rosenpass_util::break_if;
/// let mut sum = 0;
/// for i in 0..10 {
///     break_if!(i == 5);
///     sum += 1;
/// }
/// assert_eq!(sum, 5);
///
/// let mut sum = 0;
/// 'one: for _ in 0..10 {
///     for j in 0..20 {
///     break_if!(j == 5, 'one);
///     sum += 1;
///     }
/// }
/// assert_eq!(sum, 5);
/// ```
macro_rules! break_if {
    ($cond:expr) => {
        if $cond {
            break;
        }
    };
    ($cond:expr, $val:tt) => {
        if $cond {
            break $val;
        }
    };
}

#[macro_export]
/// Continue if the condition is true, in the loop with label $val, if given.
///
/// # Examples
///
/// ```
/// use rosenpass_util::continue_if;
/// let mut sum = 0;
/// for i in 0..10 {
///     continue_if!(i == 5);
///     sum += 1;
/// }
/// assert_eq!(sum, 9);
///
/// let mut sum = 0;
/// 'one: for i in 0..10 {
///     continue_if!(i == 5, 'one);
///     sum += 1;
/// }
/// assert_eq!(sum, 9);
/// ```
macro_rules! continue_if {
    ($cond:expr) => {
        if $cond {
            continue;
        }
    };
    ($cond:expr, $val:tt) => {
        if $cond {
            continue $val;
        }
    };
}
