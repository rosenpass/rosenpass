use std::{sync::LazyLock, time::Instant};

use libcrux_test_utils::tracing;

/// The trace value used in all Rosepass crates.
pub static TRACE: LazyLock<RpTrace> = LazyLock::new(|| RpTrace::default());

/// The trace type used to trace Rosenpass for performance measurement.
pub type RpTrace = tracing::MutexTrace<&'static str, Instant>;

// Re-export to make functionality availalable and callers don't need to also directly depend on
// [`libcrux_test_utils`].
pub use libcrux_test_utils::tracing::trace_span;
pub use tracing::Trace;

