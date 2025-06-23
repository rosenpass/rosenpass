use std::sync::OnceLock;
use std::time::Instant;

use libcrux_test_utils::tracing;

/// The trace value used in all Rosepass crates.
static TRACE: OnceLock<RpTrace> = OnceLock::new();

/// The trace type used to trace Rosenpass for performance measurement.
pub type RpTrace = tracing::MutexTrace<&'static str, Instant>;

/// The trace event type used to trace Rosenpass for performance measurement.
pub type RpEventType = tracing::TraceEvent<&'static str, Instant>;

// Re-export to make functionality available and callers don't need to also directly depend on
// [`libcrux_test_utils`].
pub use libcrux_test_utils::tracing::trace_span;
pub use tracing::Trace;

/// Returns a reference to the trace and lazily initializes it.
pub fn trace() -> &'static tracing::MutexTrace<&'static str, Instant> {
    TRACE.get_or_init(tracing::MutexTrace::default)
}
