//! memcmp

/// compares two sclices of memory content and returns whether they are equal
///
/// ## Leaks
/// If the two slices have differents lengths, the function will return immediately. This
/// effectively leaks the information whether the slices have equal length or not. This is widely
/// considered safe.
///
/// The execution time of the function grows approx. linear with the length of the input. This is
/// considered safe.
///
/// ## Examples
///
/// ```rust
/// use rosenpass_constant_time::memcmp;
/// let a = [0, 0, 0, 0];
/// let b = [0, 0, 0, 1];
/// let c = [0, 0, 0];
/// assert!(memcmp(&a, &a));
/// assert!(!memcmp(&a, &b));
/// assert!(!memcmp(&a, &c));
/// ```
#[inline]
pub fn memcmp(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && unsafe { memsec::memeq(a.as_ptr(), b.as_ptr(), a.len()) }
}

/// [tests::memcmp_runs_in_constant_time] runs a stasticial test that the equality of the two
/// input parameters does not correlate with the run time.
///
/// For discussion on how to (further) ensure the constant-time execution of this function,
/// see <https://github.com/rosenpass/rosenpass/issues/232>
#[cfg(all(test, feature = "constant_time_tests"))]
mod tests {
    use super::*;
    use core::hint::black_box;
    use rand::seq::SliceRandom;
    use rand::thread_rng;
    use std::time::Instant;

    #[test]
    /// tests whether [memcmp] actually runs in constant time
    ///
    /// This test function will run an equal amount of comparisons on two different sets of parameters:
    /// - completely equal slices
    /// - completely unequal slices.
    /// two sets is checked for equality significantly faster than the other set
    /// (absolute correlation coefficient ≥ 0.01)
    fn memcmp_runs_in_constant_time() {
        // prepare data to compare
        let n: usize = 1E6 as usize; // number of comparisons to run
        const LEN: usize = 1024; // length of each slice passed as parameters to the tested comparison function

        let a = [b'a'; LEN];
        let b = [b'b'; LEN];

        let mut tmp = [0u8; LEN];

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
            let src = match test.0 {
                true => a,
                false => b,
            };
            tmp.copy_from_slice(&src);

            let now = Instant::now();
            memcmp(black_box(&a), black_box(&tmp));
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
        #[cfg(not(coverage))]
        assert!(
            correlation.abs() < 0.01,
            "execution time correlates with result"
        )
    }
}
