use anyhow::Result;
use rosenpass::protocol::{
    CryptoServer, HandleMsgResult, MsgBuf, PeerPtr, ProtocolVersion, SPk, SSk, SymKey,
};
use std::{collections::HashMap, ops::DerefMut, time::Duration};

use rosenpass_cipher_traits::primitives::Kem;
use rosenpass_ciphers::StaticKem;

use std::hint::black_box;

use rosenpass_secret_memory::secret_policy_try_use_memfd_secrets;

use libcrux_test_utils::tracing::{EventType, Trace as _};

use rosenpass_bench_util::RpEventType;

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
    secret_policy_try_use_memfd_secrets();
    let (mut a, mut b) = make_server_pair(ProtocolVersion::V02).unwrap();
    hs(black_box(&mut a), black_box(&mut b)).unwrap();

    rosenpass_bench_util::TRACE.emit_on_the_fly("start-hs-v03");
    secret_policy_try_use_memfd_secrets();
    let (mut a, mut b) = make_server_pair(ProtocolVersion::V03).unwrap();
    hs(black_box(&mut a), black_box(&mut b)).unwrap();

    let trace: Vec<_> = rosenpass_bench_util::TRACE.clone().report();

    let cutoff = trace
        .iter()
        .position(|entry| entry.label == "start-hs-v03")
        .unwrap();

    let (trace_v02, trace_v03) = trace.split_at(cutoff);

    let result_v02: HashMap<_, _> = bin_events(trace_v02.to_vec())
        .into_iter()
        .map(|(label, spans)| (label, extract_span_durations(label, spans.as_slice())))
        .filter(|(_, spans)| !spans.is_empty())
        .map(|(label, durations)| (label, AggregateStat::analyze_durations(&durations)))
        .collect();

    let result_v03: HashMap<_, _> = bin_events(trace_v03.to_vec())
        .into_iter()
        .map(|(label, spans)| (label, extract_span_durations(label, spans.as_slice())))
        .filter(|(_, spans)| !spans.is_empty())
        .map(|(label, durations)| (label, AggregateStat::analyze_durations(&durations)))
        .collect();

    let mut json_data = String::with_capacity(2048);

    write_json_array::<AggregateStat<Duration>, _>(&mut json_data, result_v02, |w, label, item| {
        item.write_json_ns(label, "proto_run_V02", w)
    })
    .expect("error writing json");

    println!("{json_data}");
    json_data.truncate(0);

    write_json_array::<AggregateStat<Duration>, _>(&mut json_data, result_v03, |w, label, item| {
        item.write_json_ns(label, "proto_run_V03", w)
    })
    .expect("error writing json");

    println!("{json_data}");
}

#[derive(Debug, Clone)]
enum StatEntry {
    Start(std::time::Instant),
    Duration(std::time::Duration),
}

fn bin_events(events: Vec<RpEventType>) -> HashMap<&'static str, Vec<RpEventType>> {
    let mut spans = HashMap::<_, Vec<_>>::new();

    for event in events {
        let spans_for_label = spans.entry(event.label).or_default();
        spans_for_label.push(event)
    }

    spans
}

fn extract_span_durations(label: &str, events: &[RpEventType]) -> Vec<std::time::Duration> {
    let mut out = vec![];

    for entry in events {
        match &entry.ty {
            EventType::SpanOpen => out.push(StatEntry::Start(entry.at)),
            EventType::SpanClose => {
                let (last_start, StatEntry::Start(start)) = out
                    .iter()
                    .enumerate()
                    .find(|(_, span)| matches!(span, StatEntry::Start(_)))
                    .unwrap()
                else {
                    unreachable!("found a close for something that doesn't have an open: {entry:?}")
                };

                out[last_start] = StatEntry::Duration(entry.at - *start);
            }
            EventType::OnTheFly => {}
        }
    }

    out.into_iter()
        .filter_map(|span| match span {
            StatEntry::Start(at) => {
                println!("unmatched open span at {at:?} for label {label}");
                None
            }
            StatEntry::Duration(dur) => Some(dur),
        })
        .collect()
}

#[derive(Debug)]
struct AggregateStat<T> {
    mean_duration: T,
    sd_duration: T,
    sd_by_mean: String,
    sample_size: usize,
}

impl AggregateStat<Duration> {
    fn analyze_durations(durations: &[Duration]) -> Self {
        let sample_size = durations.len();
        assert!(sample_size > 0);

        let sum = durations.iter().sum::<Duration>();
        let mean = sum / (sample_size as u32);

        // We don't really care about being a nanosecond off, but this way we don't need to care about
        // div0 bugs
        let mean_ns = mean.as_nanos() + 1;

        let variance = durations
            .iter()
            .map(Duration::as_nanos)
            .map(|d| (d.abs_diff(mean_ns)).pow(2))
            .sum::<u128>()
            / durations.len() as u128;

        let sd_ns = (variance as f64).sqrt() as u128;
        let sd = Duration::from_nanos(sd_ns as u64);

        let sd_rel = (10000 * sd_ns) / mean_ns;
        let sd_rel = format!("{}.{:02}%", sd_rel / 100, sd_rel % 100);

        AggregateStat {
            mean_duration: mean,
            sd_duration: sd,
            sd_by_mean: sd_rel,
            sample_size,
        }
    }

    fn write_json_ns(
        &self,
        label: &str,
        category: &str,
        w: &mut impl std::fmt::Write,
    ) -> std::fmt::Result {
        write!(
            w,
            r#"{{ "name": "{name}", "unit": "ns/iter", "value": "{value}", "range": "+- {range}", "category": "{category}" }}"#,
            name = label,
            value = self.mean_duration.as_nanos(),
            range = self.sd_duration.as_nanos(),
        )
    }
}

fn write_json_array<T, W: std::fmt::Write>(
    w: &mut W,
    items: impl IntoIterator<Item = (&'static str, T)>,
    write_item: impl Fn(&mut W, &str, &T),
) -> std::fmt::Result {
    let mut iter = items.into_iter();
    if let Some((first_label, first)) = iter.next() {
        write!(w, "[")?;
        write_item(w, first_label, &first)?;
    } else {
        return write!(w, "[]");
    }

    for (label, item) in iter {
        write!(w, ",")?;
        write_item(w, label, &item)?;
    }

    write!(w, "]")
}
