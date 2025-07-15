//! Time-keeping related utilities for the Rosenpass protocol

use super::constants::EVENT_GRACE;

/// A type for time, e.g. for backoff before re-tries
pub type Timing = f64;

/// Magic time stamp to indicate some object is ancient; "Before Common Era"
///
/// This is for instance used as a magic time stamp indicating age when some
/// cryptographic object certainly needs to be refreshed.
///
/// Using this instead of Timing::MIN or Timing::INFINITY to avoid floating
/// point math weirdness.
pub const BCE: Timing = -3600.0 * 24.0 * 356.0 * 10_000.0;

/// Magic time stamp to indicate that some process is not time-limited
///
/// Actually it's eight hours; This is intentional to avoid weirdness
/// regarding unexpectedly large numbers in system APIs as this is < i16::MAX
pub const UNENDING: Timing = 3600.0 * 8.0;

/// An even `ev` has happened relative to a point in time `now`
/// if the `ev` does not lie in the future relative to now.
///
/// An event lies in the future relative to `now` if
/// does not lie in the past or present.
///
/// An event `ev` lies in the past if `ev < now`. It lies in the
/// present if the absolute difference between `ev` and `now` is
/// smaller than [EVENT_GRACE].
///
/// Think of this as `ev <= now` for with [EVENT_GRACE] applied.
///
/// # Examples
///
/// ```
/// use rosenpass::protocol::{timing::has_happened, constants::EVENT_GRACE};
/// assert!(has_happened(EVENT_GRACE * -1.0, 0.0));
/// assert!(has_happened(0.0, 0.0));
/// assert!(has_happened(EVENT_GRACE * 0.999, 0.0));
/// assert!(!has_happened(EVENT_GRACE * 1.001, 0.0));
/// ```
pub fn has_happened(ev: Timing, now: Timing) -> bool {
    (ev - now) < EVENT_GRACE
}
