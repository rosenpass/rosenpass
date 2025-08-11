use std::{
    collections::HashMap,
    hint::black_box,
    ops::DerefMut,
    time::{Duration, Instant},
};

use anyhow::Result;

use libcrux_test_utils::tracing::{EventType, Trace as _};

use rosenpass_cipher_traits::primitives::Kem;
use rosenpass_ciphers::StaticKem;
use rosenpass_secret_memory::secret_policy_try_use_memfd_secrets;
use rosenpass_util::trace_bench::RpEvent;

use rosenpass::protocol::basic_types::{MsgBuf, SPk, SSk, SymKey};
use rosenpass::protocol::osk_domain_separator::OskDomainSeparator;
use rosenpass::protocol::{CryptoServer, HandleMsgResult, PeerPtr, ProtocolVersion};
use serde::ser::SerializeStruct;

const ITERATIONS: usize = 100;

/// Performs a full protocol run by processing a message and recursing into handling that message,
/// until no further response is produced. Returns the keys produce by the two parties.
///
/// Ensures that each party produces one of the two keys.
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

/// Performs the full handshake by calling `handle` with the correct values, based on just two
/// `CryptoServer`s.
///
/// Ensures that both parties compute the same keys.
fn hs(ini: &mut CryptoServer, res: &mut CryptoServer) -> Result<()> {
    let (mut inib, mut resb) = (MsgBuf::zero(), MsgBuf::zero());
    let sz = ini.initiate_handshake(PeerPtr(0), &mut *inib)?;
    let (kini, kres) = handle(ini, &mut inib, sz, res, &mut resb)?;
    assert!(kini.unwrap().secret() == kres.unwrap().secret());
    Ok(())
}

/// Generates a new key pair.
fn keygen() -> Result<(SSk, SPk)> {
    let (mut sk, mut pk) = (SSk::zero(), SPk::zero());
    StaticKem.keygen(sk.secret_mut(), pk.deref_mut())?;
    Ok((sk, pk))
}

/// Creates two instanves of `CryptoServer`, generating key pairs for each.
fn make_server_pair(protocol_version: ProtocolVersion) -> Result<(CryptoServer, CryptoServer)> {
    let psk = SymKey::random();
    let ((ska, pka), (skb, pkb)) = (keygen()?, keygen()?);
    let (mut a, mut b) = (
        CryptoServer::new(ska, pka.clone()),
        CryptoServer::new(skb, pkb.clone()),
    );
    a.add_peer(
        Some(psk.clone()),
        pkb,
        protocol_version.clone(),
        OskDomainSeparator::default(),
    )?;
    b.add_peer(
        Some(psk),
        pka,
        protocol_version,
        OskDomainSeparator::default(),
    )?;
    Ok((a, b))
}

fn main() {
    let trace = rosenpass_util::trace_bench::trace();

    // Attempt to use memfd_secrets for storing sensitive key material
    secret_policy_try_use_memfd_secrets();

    // Run protocol for V02
    let (mut a_v02, mut b_v02) = make_server_pair(ProtocolVersion::V02).unwrap();
    for _ in 0..ITERATIONS {
        hs(black_box(&mut a_v02), black_box(&mut b_v02)).unwrap();
    }

    // Emit a marker event to separate V02 and V03 trace sections
    trace.emit_on_the_fly("start-hs-v03");

    // Run protocol for V03
    let (mut a_v03, mut b_v03) = make_server_pair(ProtocolVersion::V03).unwrap();
    for _ in 0..ITERATIONS {
        hs(black_box(&mut a_v03), black_box(&mut b_v03)).unwrap();
    }

    // Collect the trace events generated during the handshakes
    let trace: Vec<_> = trace.clone().report();

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

    // Perform statistical analysis on both trace sections
    let analysis_v02 = statistical_analysis(trace_v02);
    let analysis_v03 = statistical_analysis(trace_v03);

    // Transform analysis results to JSON-encodable data type
    let stats_v02 = analysis_v02
        .iter()
        .map(|(label, agg_stat)| JsonAggregateStat {
            protocol_version: "V02",
            label,
            agg_stat,
        });
    let stats_v03 = analysis_v03
        .iter()
        .map(|(label, agg_stat)| JsonAggregateStat {
            protocol_version: "V03",
            label,
            agg_stat: &agg_stat,
        });

    // Write results as JSON
    let stats_all: Vec<_> = stats_v02.chain(stats_v03).collect();
    let stats_json = serde_json::to_string_pretty(&stats_all).expect("error encoding to json");
    println!("{stats_json}");
}

/// Performs a simple statistical analysis:
/// - bins trace events by label
/// - extracts durations of spamns
/// - filters out empty bins
/// - calculates aggregate statistics (mean, std dev)
fn statistical_analysis(trace: &[RpEvent]) -> Vec<(&'static str, AggregateStat<Duration>)> {
    bin_events(trace)
        .into_iter()
        .map(|(label, spans)| (label, extract_span_durations(label, spans.as_slice())))
        .filter(|(_, durations)| !durations.is_empty())
        .map(|(label, durations)| (label, AggregateStat::analyze_durations(&durations)))
        .collect()
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
fn bin_events(events: &[RpEvent]) -> HashMap<&'static str, Vec<RpEvent>> {
    let mut spans = HashMap::<_, Vec<_>>::new();
    for event in events {
        // Get the vector for the event's label, or create a new one
        let spans_for_label = spans.entry(event.label).or_default();
        // Add the event to the vector
        spans_for_label.push(event.clone());
    }
    spans
}

/// Processes a list of events (assumed to be for the same label), matching
/// `SpanOpen` and `SpanClose` events to calculate the duration of each span.
/// It handles potentially interleaved spans correctly.
fn extract_span_durations(label: &str, events: &[RpEvent]) -> Vec<Duration> {
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
#[allow(dead_code)]
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
}

struct JsonAggregateStat<'a, T> {
    agg_stat: &'a AggregateStat<T>,
    label: &'a str,
    protocol_version: &'a str,
}

impl<'a> serde::Serialize for JsonAggregateStat<'a, Duration> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut stat = serializer.serialize_struct("AggregateStat", 9)?;
        stat.serialize_field("name", self.label)?;
        stat.serialize_field("unit", "ns/iter")?;
        stat.serialize_field("value", &self.agg_stat.mean_duration.as_nanos().to_string())?;
        stat.serialize_field(
            "range",
            &format!("± {}", self.agg_stat.sd_duration.as_nanos()),
        )?;
        stat.serialize_field("protocol version", self.protocol_version)?;
        stat.serialize_field("sample size", &self.agg_stat.sample_size)?;
        stat.serialize_field("operating system", std::env::consts::OS)?;
        stat.serialize_field("architecture", std::env::consts::ARCH)?;
        stat.serialize_field("run time", &run_time_group(self.label).to_string())?;

        stat.end()
    }
}
