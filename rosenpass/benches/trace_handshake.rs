// Standard library imports
use std::{
    collections::HashMap,
    hint::black_box,
    io::{self, Write},
    ops::DerefMut,
    time::{Duration, Instant},
};

// External crate imports
use anyhow::Result;
use libcrux_test_utils::tracing::{EventType, Trace as _};
use rosenpass::protocol::{
    CryptoServer, HandleMsgResult, MsgBuf, PeerPtr, ProtocolVersion, SPk, SSk, SymKey,
};
use rosenpass_cipher_traits::primitives::Kem;
use rosenpass_ciphers::StaticKem;
use rosenpass_secret_memory::secret_policy_try_use_memfd_secrets;
use rosenpass_util::trace_bench::{RpEventType, TRACE};

const ITERATIONS: usize = 100;

fn handle(
    tx: &mut CryptoServer,
    msgb: &mut MsgBuf,
    msgl: usize,
    rx: &mut CryptoServer,
    resb: &mut MsgBuf,
) -> Result<(Option<SymKey>, Option<SymKey>)> {
    let HandleMsgResult {
        exchanged_with: xch,
        resp,
    } = rx.handle_msg(&msgb[..msgl], &mut **resb)?;

    assert!(matches!(xch, None | Some(PeerPtr(0))));

    let xch = xch.map(|p| rx.osk(p).unwrap());

    let (rxk, txk) = resp
        .map(|resl| handle(rx, resb, resl, tx, msgb))
        .transpose()?
        .unwrap_or((None, None));

    assert!(rxk.is_none() || xch.is_none());

    Ok((txk, rxk.or(xch)))
}

fn hs(ini: &mut CryptoServer, res: &mut CryptoServer) -> Result<()> {
    let (mut inib, mut resb) = (MsgBuf::zero(), MsgBuf::zero());
    let sz = ini.initiate_handshake(PeerPtr(0), &mut *inib)?;
    let (kini, kres) = handle(ini, &mut inib, sz, res, &mut resb)?;
    assert!(kini.unwrap().secret() == kres.unwrap().secret());
    Ok(())
}

fn keygen() -> Result<(SSk, SPk)> {
    let (mut sk, mut pk) = (SSk::zero(), SPk::zero());
    StaticKem.keygen(sk.secret_mut(), pk.deref_mut())?;
    Ok((sk, pk))
}

fn make_server_pair(protocol_version: ProtocolVersion) -> Result<(CryptoServer, CryptoServer)> {
    let psk = SymKey::random();
    let ((ska, pka), (skb, pkb)) = (keygen()?, keygen()?);
    let (mut a, mut b) = (
        CryptoServer::new(ska, pka.clone()),
        CryptoServer::new(skb, pkb.clone()),
    );
    a.add_peer(Some(psk.clone()), pkb, protocol_version.clone())?;
    b.add_peer(Some(psk), pka, protocol_version)?;
    Ok((a, b))
}

fn main() {
    // Attempt to use memfd_secrets for storing sensitive key material
    secret_policy_try_use_memfd_secrets();

    // Run protocol for V02
    let (mut a_v02, mut b_v02) = make_server_pair(ProtocolVersion::V02).unwrap();
    for _ in 0..ITERATIONS {
        hs(black_box(&mut a_v02), black_box(&mut b_v02)).unwrap();
    }

    // Emit a marker event to separate V02 and V03 trace sections
    TRACE.emit_on_the_fly("start-hs-v03");

    // Run protocol for V03
    let (mut a_v03, mut b_v03) = make_server_pair(ProtocolVersion::V03).unwrap();
    for _ in 0..ITERATIONS {
        hs(black_box(&mut a_v03), black_box(&mut b_v03)).unwrap();
    }

    // Collect the trace events generated during the handshakes
    let trace: Vec<_> = TRACE.clone().report();

    // Split the trace into V02 and V03 sections based on the marker
    let (trace_v02, trace_v03) = {
        let cutoff = trace
            .iter()
            .position(|entry| entry.label == "start-hs-v03")
            .unwrap();
        // Exclude the marker itself from the V03 trace
        let (v02, v03_with_marker) = trace.split_at(cutoff);
        (v02, &v03_with_marker[1..])
    };

    // Perform statistical analysis on both trace sections and write results as JSON
    write_json_arrays(
        &mut std::io::stdout(), // Write to standard output
        vec![
            ("V02", statistical_analysis(trace_v02.to_vec())),
            ("V03", statistical_analysis(trace_v03.to_vec())),
        ],
    )
    .expect("error writing json data");
}

/// Takes a vector of trace events, bins them by label, extracts durations,
/// filters empty bins, calculates aggregate statistics (mean, std dev), and returns them.
fn statistical_analysis(trace: Vec<RpEventType>) -> Vec<(&'static str, AggregateStat<Duration>)> {
    bin_events(trace)
        .into_iter()
        .map(|(label, spans)| (label, extract_span_durations(label, spans.as_slice())))
        .filter(|(_, durations)| !durations.is_empty())
        .map(|(label, durations)| (label, AggregateStat::analyze_durations(&durations)))
        .collect()
}

/// Takes an iterator of ("protocol_version", iterator_of_stats) pairs and writes them
/// as a single flat JSON array to the provided writer.
///
/// # Arguments
/// * `w` - The writer to output JSON to (e.g., stdout, file).
/// * `item_groups` - An iterator producing tuples of (`&'static str`, `II`), where
///   `II` is itself an iterator producing (`&'static str`, `AggregateStat<Duration>`).
///   Represents the protocol_version name and the statistics items within that protocol_version.
///
/// # Type Parameters
/// * `W` - A type that implements `std::io::Write`.
/// * `II` - An iterator type yielding (`&'static str`, `AggregateStat<Duration>`).
fn write_json_arrays<W: Write, II: IntoIterator<Item = (&'static str, AggregateStat<Duration>)>>(
    w: &mut W,
    item_groups: impl IntoIterator<Item = (&'static str, II)>,
) -> io::Result<()> {
    // Flatten the groups into a single iterator of (protocol_version, label, stats)
    let iter = item_groups.into_iter().flat_map(|(version, items)| {
        items
            .into_iter()
            .map(move |(label, agg_stat)| (version, label, agg_stat))
    });
    let mut delim = ""; // Start with no delimiter

    // Start the JSON array
    write!(w, "[")?;

    // Write the flattened statistics as JSON objects, separated by commas.
    for (version, label, agg_stat) in iter {
        write!(w, "{delim}")?; // Write delimiter (empty for first item, "," for subsequent)
        agg_stat.write_json_ns(label, version, w)?; // Write the JSON object for the stat entry
        delim = ","; // Set delimiter for the next iteration
    }

    // End the JSON array
    write!(w, "]")
}

/// Used to group benchmark results in visualizations
enum RunTimeGroup {
    /// For particularly long operations.
    Long,
    /// Operations of moderate duration.
    Medium,
    /// Operations expected to complete under a millisecond.
    BelowMillisec,
    /// Very fast operations, likely under a microsecond.
    BelowMicrosec,
}

impl std::fmt::Display for RunTimeGroup {
    /// Used when writing the group information to JSON output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let txt = match self {
            RunTimeGroup::Long => "long",
            RunTimeGroup::Medium => "medium",
            RunTimeGroup::BelowMillisec => "below 1ms",
            RunTimeGroup::BelowMicrosec => "below 1us",
        };
        write!(f, "{txt}")
    }
}

/// Maps specific internal timing labels (likely from rosenpass internals)
/// to the broader SpanGroup categories.
fn run_time_group(label: &str) -> RunTimeGroup {
    match label {
        // Explicitly categorized labels based on expected performance characteristics
        "handle_init_hello" | "handle_resp_hello" | "RHI5" | "IHR5" => RunTimeGroup::Long,
        "RHR1" | "IHI2" | "ICR6" => RunTimeGroup::BelowMicrosec,
        "RHI6" | "ICI7" | "ICR7" | "RHR3" | "ICR3" | "IHR8" | "ICI4" | "RHI3" | "RHI4" | "RHR4"
        | "RHR7" | "ICI3" | "IHI3" | "IHI8" | "ICR2" | "ICR4" | "IHR4" | "IHR6" | "IHI4"
        | "RHI7" => RunTimeGroup::BelowMillisec,
        // Default protocol_version for any other labels
        _ => RunTimeGroup::Medium,
    }
}

/// Used temporarily within `extract_span_durations` to track open spans
/// and calculated durations.
#[derive(Debug, Clone)]
enum StatEntry {
    /// Represents an unmatched SpanOpen event with its timestamp.
    Start(Instant),
    /// Represents a completed span with its calculated duration.
    Duration(Duration),
}

/// Takes a flat list of events and organizes them into a HashMap where keys
/// are event labels and values are vectors of events with that label.
fn bin_events(events: Vec<RpEventType>) -> HashMap<&'static str, Vec<RpEventType>> {
    let mut spans = HashMap::<_, Vec<_>>::new();
    for event in events {
        // Get the vector for the event's label, or create a new one
        let spans_for_label = spans.entry(event.label).or_default();
        // Add the event to the vector
        spans_for_label.push(event);
    }
    spans
}

/// Processes a list of events (assumed to be for the same label), matching
/// `SpanOpen` and `SpanClose` events to calculate the duration of each span.
/// It handles potentially interleaved spans correctly.
fn extract_span_durations(label: &str, events: &[RpEventType]) -> Vec<Duration> {
    let mut processing_list: Vec<StatEntry> = vec![]; // List to track open spans and final durations

    for entry in events {
        match &entry.ty {
            EventType::SpanOpen => {
                // Record the start time of a new span
                processing_list.push(StatEntry::Start(entry.at));
            }
            EventType::SpanClose => {
                // Find the most recent unmatched 'Start' entry
                let start_index = processing_list
                    .iter()
                    .rposition(|span| matches!(span, StatEntry::Start(_))); // Find last Start

                match start_index {
                    Some(index) => {
                        // Retrieve the start time
                        let start_time = match processing_list[index] {
                            StatEntry::Start(t) => t,
                            _ => unreachable!(), // Should always be Start based on rposition logic
                        };
                        // Calculate duration and replace the 'Start' entry with 'Duration'
                        processing_list[index] = StatEntry::Duration(entry.at - start_time);
                    }
                    None => {
                        // This should not happen with well-formed traces
                        eprintln!(
                            "Warning: Found SpanClose without a matching SpanOpen for label '{}': {:?}",
                            label, entry
                        );
                    }
                }
            }
            EventType::OnTheFly => {
                // Ignore OnTheFly events for duration calculation
            }
        }
    }

    // Collect all calculated durations, reporting any unmatched starts
    processing_list
        .into_iter()
        .filter_map(|span| match span {
            StatEntry::Start(at) => {
                // Report error if a span was opened but never closed
                eprintln!(
                    "Warning: Unmatched SpanOpen at {:?} for label '{}'",
                    at, label
                );
                None // Discard unmatched starts
            }
            StatEntry::Duration(dur) => Some(dur), // Keep calculated durations
        })
        .collect()
}

/// Stores the mean, standard deviation, relative standard deviation (sd/mean),
/// and the number of samples used for calculation.
#[derive(Debug)]
struct AggregateStat<T> {
    /// Average duration.
    mean_duration: T,
    /// Standard deviation of durations.
    sd_duration: T,
    /// Standard deviation as a percentage of the mean.
    sd_by_mean: String,
    /// Number of duration measurements.
    sample_size: usize,
}

impl AggregateStat<Duration> {
    /// Calculates mean, variance, and standard deviation for a slice of Durations.
    fn analyze_durations(durations: &[Duration]) -> Self {
        let sample_size = durations.len();
        assert!(sample_size > 0, "Cannot analyze empty duration slice");

        // Calculate the sum of durations
        let sum: Duration = durations.iter().sum();
        // Calculate the mean duration
        let mean = sum / (sample_size as u32);

        // Calculate mean in nanoseconds, adding 1 to avoid potential division by zero later
        // (though highly unlikely with realistic durations)
        let mean_ns = mean.as_nanos().saturating_add(1);

        // Calculate variance (sum of squared differences from the mean) / N
        let variance = durations
            .iter()
            .map(Duration::as_nanos)
            .map(|d_ns| d_ns.abs_diff(mean_ns).pow(2)) // (duration_ns - mean_ns)^2
            .sum::<u128>() // Sum of squares
            / (sample_size as u128); // Divide by sample size

        // Calculate standard deviation (sqrt of variance)
        let sd_ns = (variance as f64).sqrt() as u128;
        let sd = Duration::from_nanos(sd_ns as u64); // Convert back to Duration

        // Calculate relative standard deviation (sd / mean) as a percentage string
        let sd_rel_permille = (10000 * sd_ns).checked_div(mean_ns).unwrap_or(0); // Calculate sd/mean * 10000
        let sd_rel_formatted = format!("{}.{:02}%", sd_rel_permille / 100, sd_rel_permille % 100);

        AggregateStat {
            mean_duration: mean,
            sd_duration: sd,
            sd_by_mean: sd_rel_formatted,
            sample_size,
        }
    }

    /// Writes the statistics as a JSON object to the provided writer.
    /// Includes metadata like label, protocol_version, OS, architecture, and run time group.
    ///
    /// # Arguments
    /// * `label` - The specific benchmark/span label.
    /// * `protocol_version` - Version of the protocol that is benchmarked.
    /// * `w` - The output writer (must implement `std::io::Write`).
    fn write_json_ns(
        &self,
        label: &str,
        protocol_version: &str,
        w: &mut impl io::Write,
    ) -> io::Result<()> {
        // Format the JSON string using measured values and environment constants
        writeln!(
            w,
            r#"{{"name":"{name}", "unit":"ns/iter", "value":"{value}", "range":"± {range}", "protocol version":"{protocol_version}", "sample size":"{sample_size}", "operating system":"{os}", "architecture":"{arch}", "run time":"{run_time}"}}"#,
            name = label,                          // Benchmark name
            value = self.mean_duration.as_nanos(), // Mean duration in nanoseconds
            range = self.sd_duration.as_nanos(),   // Standard deviation in nanoseconds
            sample_size = self.sample_size,        // Number of samples
            os = std::env::consts::OS,             // Operating system
            arch = std::env::consts::ARCH,         // CPU architecture
            run_time = run_time_group(label),      // Run time group category (long, medium, etc.)
            protocol_version = protocol_version // Overall protocol_version (e.g., protocol version)
        )
    }
}
