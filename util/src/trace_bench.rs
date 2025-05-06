use std::time::Instant;

use libcrux_test_utils::tracing;

lazy_static::lazy_static! {
    /// The trace value used in all Rosepass crates.
    pub static ref TRACE: RpTrace = RpTrace::default();
}

/// The trace type used to trace Rosenpass for performance measurement.
pub type RpTrace = tracing::MutexTrace<&'static str, Instant>;

/// The trace event type used to trace Rosenpass for performance measurement.
pub type RpEventType = tracing::TraceEvent<&'static str, Instant>;

// Re-export to make functionality availalable and callers don't need to also directly depend on
// [`libcrux_test_utils`].
pub use libcrux_test_utils::tracing::trace_span;
pub use tracing::Trace;
