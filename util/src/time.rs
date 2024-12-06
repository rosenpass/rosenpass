use std::time::Instant;

/// A timebase.
///
/// This is a simple wrapper around `std::time::Instant` that provides a
/// convenient way to get the seconds elapsed since the creation of the
/// `Timebase` instance.
///
/// # Examples
///
/// ```
/// use rosenpass_util::time::Timebase;
///
/// let timebase = Timebase::default();
/// let now = timebase.now();
/// assert!(now > 0.0);
/// ```

#[derive(Clone, Debug)]
pub struct Timebase(pub Instant);

impl Default for Timebase {
    // TODO: Implement new()?
    fn default() -> Self {
        Self(Instant::now())
    }
}

impl Timebase {
    /// Returns the seconds elapsed since the creation of the `Timebase`
    pub fn now(&self) -> f64 {
        self.0.elapsed().as_secs_f64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_timebase() {
        let timebase = Timebase::default();
        let now = timebase.now();
        assert!(now > 0.0);
    }

    #[test]
    fn test_timebase_clone() {
        let timebase = Timebase::default();
        let timebase_clone = timebase.clone();
        assert_eq!(timebase.0, timebase_clone.0);
    }

    #[test]
    fn test_timebase_sleep() {
        let timebase = Timebase::default();
        sleep(Duration::from_secs(1));
        let now = timebase.now();
        assert!(now > 1.0);
    }
}
