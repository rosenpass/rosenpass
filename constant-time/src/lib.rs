use core::hint::black_box;

use rosenpass_to::{with_destination, To};

/// Xors the source into the destination
///
/// # Examples
///
/// ```
/// use rosenpass_constant_time::xor;
/// use rosenpass_to::To;
/// assert_eq!(
///     xor(b"world").to_this(|| b"hello".to_vec()),
///     b"\x1f\n\x1e\x00\x0b");
/// ```
///
/// # Panics
///
/// If source and destination are of different sizes.
#[inline]
pub fn xor(src: &[u8]) -> impl To<[u8], ()> + '_ {
    with_destination(|dst: &mut [u8]| {
        assert!(black_box(src.len()) == black_box(dst.len()));
        for (dv, sv) in dst.iter_mut().zip(src.iter()) {
            *black_box(dv) ^= black_box(*sv);
        }
    })
}

#[inline]
pub fn memcmp(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && unsafe { memsec::memeq(a.as_ptr() as *const u8, b.as_ptr() as *const u8, a.len()) }
}

#[inline]
pub fn compare(a: &[u8], b: &[u8]) -> i32 {
    assert!(a.len() == b.len());
    unsafe { memsec::memcmp(a.as_ptr(), b.as_ptr(), a.len()) }
}

/// Interpret the given slice as a little-endian unsigned integer
/// and increment that integer.
///
/// # Examples
///
/// ```
/// use rosenpass_constant_time::increment as inc;
/// use rosenpass_to::To;
///
/// fn testcase(v: &[u8], correct: &[u8]) {
///   let mut v = v.to_owned();
///   inc(&mut v);
///   assert_eq!(&v, correct);
/// }
///
/// testcase(b"", b"");
/// testcase(b"\x00", b"\x01");
/// testcase(b"\x01", b"\x02");
/// testcase(b"\xfe", b"\xff");
/// testcase(b"\xff", b"\x00");
/// testcase(b"\x00\x00", b"\x01\x00");
/// testcase(b"\x01\x00", b"\x02\x00");
/// testcase(b"\xfe\x00", b"\xff\x00");
/// testcase(b"\xff\x00", b"\x00\x01");
/// testcase(b"\x00\x00\x00\x00\x00\x00", b"\x01\x00\x00\x00\x00\x00");
/// testcase(b"\x00\xa3\x00\x77\x00\x00", b"\x01\xa3\x00\x77\x00\x00");
/// testcase(b"\xff\xa3\x00\x77\x00\x00", b"\x00\xa4\x00\x77\x00\x00");
/// testcase(b"\xff\xff\xff\x77\x00\x00", b"\x00\x00\x00\x78\x00\x00");
/// ```
#[inline]
pub fn increment(v: &mut [u8]) {
    let mut carry = 1u8;
    for val in v.iter_mut() {
        let (v, c) = black_box(*val).overflowing_add(black_box(carry));
        *black_box(val) = v;
        *black_box(&mut carry) = black_box(black_box(c) as u8);
    }
}

#[cfg(all(test, feature = "constant_time_tests"))]
mod constant_time_tests {
    use super::*;
    use rand::seq::SliceRandom;
    use rand::thread_rng;
    use std::time::Instant;

    #[test]
    /// tests whether [memcmp] actually runs in constant time
    ///
    /// This test function will run an equal amount of comparisons on two different sets of parameters:
    /// - completely equal slices
    /// - completely unequal slices.
    /// All comparisons are executed in a randomized order. The test will fail if one of the
    /// two sets is checked for equality significantly faster than the other set
    /// (absolute correlation coefficient ≥ 0.01)
    fn memcmp_runs_in_constant_time() {
        // prepare data to compare
        let n: usize = 1E6 as usize; // number of comparisons to run
        let len = 1024; // length of each slice passed as parameters to the tested comparison function
        let a1 = "a".repeat(len);
        let a2 = a1.clone();
        let b = "b".repeat(len);

        let a1 = a1.as_bytes();
        let a2 = a2.as_bytes();
        let b = b.as_bytes();

        // vector representing all timing tests
        //
        // Each element is a tuple of:
        // 0: whether the test compared two equal slices
        // 1: the duration needed for the comparison to run
        let mut tests = (0..n)
            .map(|i| (i < n / 2, std::time::Duration::ZERO))
            .collect::<Vec<_>>();
        tests.shuffle(&mut thread_rng());

        // run comparisons / call function to test
        for test in tests.iter_mut() {
            let now = Instant::now();
            if test.0 {
                memcmp(a1, a2);
            } else {
                memcmp(a1, b);
            }
            test.1 = now.elapsed();
            // println!("eq: {}, elapsed: {:.2?}", test.0, test.1);
        }

        // sort by execution time and calculate Pearson correlation coefficient
        tests.sort_by_key(|v| v.1);
        let tests = tests
            .iter()
            .map(|t| (if t.0 { 1_f64 } else { 0_f64 }, t.1.as_nanos() as f64))
            .collect::<Vec<_>>();
        // averages
        let (avg_x, avg_y): (f64, f64) = (
            tests.iter().map(|t| t.0).sum::<f64>() / n as f64,
            tests.iter().map(|t| t.1).sum::<f64>() / n as f64,
        );
        assert!((avg_x - 0.5).abs() < 1E-12);
        // standard deviations
        let sd_x = 0.5;
        let sd_y = (1_f64 / n as f64
            * tests
                .iter()
                .map(|t| {
                    let difference = t.1 - avg_y;
                    difference * difference
                })
                .sum::<f64>())
        .sqrt();
        // covariance
        let cv = 1_f64 / n as f64
            * tests
                .iter()
                .map(|t| (t.0 - avg_x) * (t.1 - avg_y))
                .sum::<f64>();
        // Pearson correlation
        let correlation = cv / (sd_x * sd_y);
        println!("correlation: {:.6?}", correlation);
        assert!(
            correlation.abs() < 0.01,
            "execution time correlates with result"
        )
    }
}
