use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Timebase(Instant);

impl Default for Timebase {
    fn default() -> Self {
        Self(Instant::now())
    }
}

impl Timebase {
    pub fn now(&self) -> f64 {
        self.0.elapsed().as_secs_f64()
    }

    pub fn dur(&self, t: f64) -> Duration {
        Duration::from_secs_f64(t)
    }
}
