/// This file contains a correct simulation of a two-party key exchange using Poll
use std::{
    borrow::{Borrow, BorrowMut},
    collections::VecDeque,
    ops::DerefMut,
};

use rosenpass_cipher_traits::primitives::Kem;
use rosenpass_ciphers::StaticKem;
use rosenpass_util::result::OkExt;

use rosenpass::protocol::{
    testutils::time_travel_forward, CryptoServer, HostIdentification, MsgBuf, PeerPtr, PollResult,
    ProtocolVersion, SPk, SSk, SymKey, Timing, UNENDING,
};

// TODO: Most of the utility functions in here should probably be moved to
// rosenpass::protocol::testutils;

#[test]
fn test_successful_exchange_with_poll_v02() -> anyhow::Result<()> {
    test_successful_exchange_with_poll(ProtocolVersion::V02)
}

#[test]
fn test_successful_exchange_with_poll_v03() -> anyhow::Result<()> {
    test_successful_exchange_with_poll(ProtocolVersion::V03)
}

fn test_successful_exchange_with_poll(protocol_version: ProtocolVersion) -> anyhow::Result<()> {
    // Set security policy for storing secrets; choose the one that is faster for testing
    rosenpass_secret_memory::policy::secret_policy_use_only_malloc_secrets();

    let mut sim = RosenpassSimulator::new(protocol_version)?;
    sim.poll_loop(150)?; // Poll 75 times
    let transcript = sim.transcript;

    let _completions: Vec<_> = transcript
        .iter()
        .filter(|elm| matches!(elm, (_, TranscriptEvent::CompletedExchange(_))))
        .collect();

    #[cfg(not(coverage))]
    assert!(
        !_completions.is_empty(),
        "\
        Should have performed a successful key exchanged!\n\
          Transcript: {transcript:?}\n\
          Completions: {_completions:?}\
        "
    );
    #[cfg(not(coverage))]
    assert!(
        _completions[0].0 < 20.0,
        "\
        First key exchange should happen in under twenty seconds!\n\
          Transcript: {transcript:?}\n\
          Completions: {_completions:?}\
        "
    );

    #[cfg(not(coverage))]
    assert!(
        _completions.len() >= 3,
        "\
        Should have at least two renegotiations!\n\
          Transcript: {transcript:?}\n\
          Completions: {_completions:?}\
        "
    );
    #[cfg(not(coverage))]
    assert!(
        (110.0..175.0).contains(&_completions[1].0),
        "\
        First renegotiation should happen in between two and three minutes!\n\
          Transcript: {transcript:?}\n\
          Completions: {_completions:?}\
        "
    );
    #[cfg(not(coverage))]
    assert!((110.0..175.0).contains(&(_completions[2].0 - _completions[1].0)), "\
        First renegotiation should happen in between two and three minutes after the first renegotiation!\n\
          Transcript: {transcript:?}\n\
          Completions: {_completions:?}\
        ");

    Ok(())
}

#[test]
fn test_successful_exchange_under_packet_loss_v02() -> anyhow::Result<()> {
    test_successful_exchange_under_packet_loss(ProtocolVersion::V02)
}

#[test]
fn test_successful_exchange_under_packet_loss_v03() -> anyhow::Result<()> {
    test_successful_exchange_under_packet_loss(ProtocolVersion::V03)
}

fn test_successful_exchange_under_packet_loss(
    protocol_version: ProtocolVersion,
) -> anyhow::Result<()> {
    // Set security policy for storing secrets; choose the one that is faster for testing
    rosenpass_secret_memory::policy::secret_policy_use_only_malloc_secrets();

    // Create the simulator
    let mut sim = RosenpassSimulator::new(protocol_version)?;

    // Make sure the servers are set to under load condition
    sim.srv_a.under_load = true;
    sim.srv_b.under_load = false; // See Issue #539 -- https://github.com/rosenpass/rosenpass/issues/539

    // Perform the key exchanges
    let mut pkg_counter = 0usize;
    for _ in 0..300 {
        let ev = sim.poll()?;
        if let TranscriptEvent::ServerEvent {
            source,
            event: ServerEvent::Transmit(_, _),
        } = ev
        {
            // Drop every fifth package
            if pkg_counter % 10 == 0 {
                source.drop_outgoing_packet(&mut sim);
            }

            pkg_counter += 1;
        }
    }

    let transcript = sim.transcript;
    let _completions: Vec<_> = transcript
        .iter()
        .filter(|elm| matches!(elm, (_, TranscriptEvent::CompletedExchange(_))))
        .collect();

    #[cfg(not(coverage))]
    assert!(
        !_completions.is_empty(),
        "\
        Should have performed a successful key exchanged!\n\
          Transcript: {transcript:?}\n\
          Completions: {_completions:?}\
        "
    );
    #[cfg(not(coverage))]
    assert!(
        _completions[0].0 < 10.0,
        "\
          First key exchange should happen in under twenty seconds!\n\
          Transcript: {transcript:?}\n\
          Completions: {_completions:?}\
        "
    );

    #[cfg(not(coverage))]
    assert!(
        _completions.len() >= 3,
        "\
        Should have at least two renegotiations!\n\
          Transcript: {transcript:?}\n\
          Completions: {_completions:?}\
        "
    );
    #[cfg(not(coverage))]
    assert!(
        (110.0..175.0).contains(&_completions[1].0),
        "\
        First renegotiation should happen in between two and three minutes!\n\
          Transcript: {transcript:?}\n\
          Completions: {_completions:?}\
        "
    );
    #[cfg(not(coverage))]
    assert!((110.0..175.0).contains(&(_completions[2].0 - _completions[1].0)), "\
        First renegotiation should happen in between two and three minutes after the first renegotiation!\n\
          Transcript: {transcript:?}\n\
          Completions: {_completions:?}\
        ");

    Ok(())
}

type MessageType = u8;

/// Lets record the events that are produced by Rosenpass
#[derive(Debug)]
#[allow(unused)]
enum TranscriptEvent {
    Wait(Timing),
    ServerEvent {
        source: ServerPtr,
        event: ServerEvent,
    },
    CompletedExchange(SymKey),
}

#[derive(Debug)]
#[allow(unused)]
enum ServerEvent {
    DeleteKey,
    SendInitiationRequested,
    SendRetransmissionRequested,
    Exchanged(SymKey),
    DiscardInvalidMessage(anyhow::Error),
    Transmit(MessageType, SendMsgReason),
    Receive(Option<MessageType>),
    DroppedPackage,
}

#[derive(Debug, Clone, Copy)]
enum SendMsgReason {
    Initiation,
    Response,
    Retransmission,
}

impl TranscriptEvent {
    fn hibernate() -> Self {
        Self::Wait(UNENDING)
    }

    fn begin_poll() -> Self {
        Self::hibernate()
    }

    fn transmit(source: ServerPtr, buf: &[u8], reason: SendMsgReason) -> Self {
        assert!(!buf.is_empty());
        let msg_type = buf[0];
        ServerEvent::Transmit(msg_type, reason).into_transcript_event(source)
    }

    fn receive(source: ServerPtr, buf: &[u8]) -> Self {
        let msg_type = (!buf.is_empty()).then(|| buf[0]);
        ServerEvent::Receive(msg_type).into_transcript_event(source)
    }

    pub fn try_fold_with<F: FnOnce() -> anyhow::Result<TranscriptEvent>>(
        self,
        f: F,
    ) -> anyhow::Result<TranscriptEvent> {
        let wait_time_a = match self {
            Self::Wait(wait_time_a) => wait_time_a,
            els => return (els).ok(),
        };

        let wait_time_b = match f()? {
            Self::Wait(wait_time_b) => wait_time_b,
            els => return els.ok(),
        };

        let min_wt = if wait_time_a <= wait_time_b {
            wait_time_a
        } else {
            wait_time_b
        };
        Self::Wait(min_wt).ok()
    }
}

impl ServerEvent {
    fn into_transcript_event(self, source: ServerPtr) -> TranscriptEvent {
        let event = self;
        TranscriptEvent::ServerEvent { source, event }
    }
}

#[derive(Debug)]
struct RosenpassSimulator {
    transcript: Vec<(Timing, TranscriptEvent)>,
    srv_a: SimulatorServer,
    srv_b: SimulatorServer,
    poll_focus: ServerPtr,
}

#[derive(Debug)]
enum UpcomingPollResult {
    IssueEvent(TranscriptEvent),
    SendMessage(Vec<u8>, TranscriptEvent),
}

#[derive(Debug)]
struct SimulatorServer {
    /// We sometimes return multiple multiple events in one call,
    /// but [ServerPtr::poll] should return just one event per call
    upcoming_poll_results: VecDeque<UpcomingPollResult>,
    srv: CryptoServer,
    rx_queue: VecDeque<Vec<u8>>,
    other_peer: PeerPtr,
    under_load: bool,
}

impl RosenpassSimulator {
    /// Set up the simulator
    fn new(protocol_version: ProtocolVersion) -> anyhow::Result<Self> {
        // Set up the first server
        let (mut peer_a_sk, mut peer_a_pk) = (SSk::zero(), SPk::zero());
        StaticKem.keygen(peer_a_sk.secret_mut(), peer_a_pk.deref_mut())?;
        let mut srv_a = CryptoServer::new(peer_a_sk, peer_a_pk.clone());

        // …and the second server.
        let (mut peer_b_sk, mut peer_b_pk) = (SSk::zero(), SPk::zero());
        StaticKem.keygen(peer_b_sk.secret_mut(), peer_b_pk.deref_mut())?;
        let mut srv_b = CryptoServer::new(peer_b_sk, peer_b_pk.clone());

        // Generate a PSK and introduce the Peers to each other.
        let psk = SymKey::random();
        let peer_a = srv_a.add_peer(Some(psk.clone()), peer_b_pk, protocol_version.clone())?;
        let peer_b = srv_b.add_peer(Some(psk), peer_a_pk, protocol_version.clone())?;

        // Set up the individual server data structures
        let srv_a = SimulatorServer::new(srv_a, peer_b);
        let srv_b = SimulatorServer::new(srv_b, peer_a);

        // Initialize transcript and polling state
        let transcript = Vec::new();
        let poll_focus = ServerPtr::A;

        // Construct the simulator itself
        Self {
            transcript,
            poll_focus,
            srv_a,
            srv_b,
        }
        .ok()
    }

    /// Call [poll] a fixed number of times
    fn poll_loop(&mut self, times: u64) -> anyhow::Result<()> {
        for _ in 0..times {
            self.poll()?;
        }
        Ok(())
    }

    /// Every call to poll produces one [TranscriptEvent]
    /// and implicitly adds it to [Self::transcript]
    fn poll(&mut self) -> anyhow::Result<&TranscriptEvent> {
        let ev = TranscriptEvent::begin_poll()
            .try_fold_with(|| self.poll_focus.poll(self))?
            .try_fold_with(|| {
                self.poll_focus = self.poll_focus.other();
                self.poll_focus.poll(self)
            })?;

        // Generate up a time stamp
        let now = self.srv_a.srv.timebase.now();

        // Push the event onto the transcript
        self.transcript.push((now, ev));
        // We can unwrap; we just pushed the event ourselves
        let ev = self.transcript.last().unwrap().1.borrow();

        // Time travel instead of waiting
        if let TranscriptEvent::Wait(secs) = ev {
            time_travel_forward(&mut self.srv_a.srv, *secs);
            time_travel_forward(&mut self.srv_b.srv, *secs);
        }

        ev.ok()
    }
}

impl SimulatorServer {
    fn new(srv: CryptoServer, other_peer: PeerPtr) -> Self {
        let upcoming_poll_results = VecDeque::new();
        let rx_queue = VecDeque::new();
        let under_load = false;
        Self {
            upcoming_poll_results,
            srv,
            rx_queue,
            other_peer,
            under_load,
        }
    }
}

/// Straightforward way of accessing either of the two servers
/// with associated data
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ServerPtr {
    A,
    B,
}

impl std::fmt::Display for ServerPtr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

impl HostIdentification for ServerPtr {
    fn encode(&self) -> &[u8] {
        match *self {
            Self::A => b"ServerPtr::A",
            Self::B => b"ServerPtr::B",
        }
    }
}

impl ServerPtr {
    fn poll(self, sim: &mut RosenpassSimulator) -> anyhow::Result<TranscriptEvent> {
        TranscriptEvent::begin_poll()
            .try_fold_with(|| self.flush_upcoming_events(sim).ok())?
            .try_fold_with(|| self.poll_for_timed_events(sim))?
            .try_fold_with(|| self.process_incoming_messages(sim))
    }

    /// Returns and applies the first upcoming event
    fn flush_upcoming_events(self, sim: &mut RosenpassSimulator) -> TranscriptEvent {
        use UpcomingPollResult as R;
        match self.get_mut(sim).upcoming_poll_results.pop_front() {
            None => TranscriptEvent::hibernate(),
            Some(R::IssueEvent(ev)) => ev,
            Some(R::SendMessage(msg, ev)) => {
                self.transmit(sim, msg);
                ev
            }
        }
    }

    fn poll_for_timed_events(
        self,
        sim: &mut RosenpassSimulator,
    ) -> anyhow::Result<TranscriptEvent> {
        use PollResult as P;
        use ServerEvent as SE;
        use TranscriptEvent as TE;

        let other_peer = self.peer(sim);

        // Check if there are events to process from poll()
        loop {
            match self.srv_mut(sim).poll()? {
                // Poll just told us to immediately call poll again
                P::Sleep(0.0) => continue,

                // No event to handle immediately. We can now check to see if there are some
                // messages to be handled
                P::Sleep(wait_time) => {
                    return TE::Wait(wait_time).ok();
                }

                // Not deleting any keys in practice here, since we just push events to the
                // transcript
                P::DeleteKey(_) => {
                    return SE::DeleteKey.into_transcript_event(self).ok();
                }

                P::SendInitiation(_) => {
                    self.enqueue_upcoming_poll_event(
                        sim,
                        SE::SendInitiationRequested.into_transcript_event(self),
                    );

                    let mut buf = MsgBuf::zero();
                    let len = self
                        .srv_mut(sim)
                        .initiate_handshake(other_peer, &mut buf[..])?;
                    self.enqueue_upcoming_poll_transmission(
                        sim,
                        buf[..len].to_vec(),
                        SendMsgReason::Initiation,
                    );

                    return self.flush_upcoming_events(sim).ok(); // Just added them
                }

                P::SendRetransmission(_) => {
                    self.enqueue_upcoming_poll_event(
                        sim,
                        SE::SendRetransmissionRequested.into_transcript_event(self),
                    );

                    let mut buf = MsgBuf::zero();
                    let len = self
                        .srv_mut(sim)
                        .retransmit_handshake(other_peer, &mut buf[..])?;
                    self.enqueue_upcoming_poll_transmission(
                        sim,
                        buf[..len].to_vec(),
                        SendMsgReason::Retransmission,
                    );

                    return self.flush_upcoming_events(sim).ok(); // Just added them
                }
            };
        }
    }

    fn process_incoming_messages(
        self,
        sim: &mut RosenpassSimulator,
    ) -> anyhow::Result<TranscriptEvent> {
        use ServerEvent as SE;
        use TranscriptEvent as TE;

        // Check for a message or exit
        let rx_msg = match self.recv(sim) {
            None => return TE::hibernate().ok(),
            // Actually received a message
            Some(rx_msg) => rx_msg,
        };

        // Add info that a message was received into the transcript
        self.enqueue_upcoming_poll_event(sim, TE::receive(self, rx_msg.borrow()));

        // Let the crypto server handle the message now
        let mut tx_buf = MsgBuf::zero();
        let handle_msg_result = if self.get(sim).under_load {
            self.srv_mut(sim)
                .handle_msg_under_load(rx_msg.borrow(), tx_buf.borrow_mut(), &self)
        } else {
            self.srv_mut(sim)
                .handle_msg(rx_msg.borrow(), tx_buf.borrow_mut())
        };

        // Handle bad messages
        let handle_msg_result = match handle_msg_result {
            Ok(res) => res,
            Err(e) => {
                self.enqueue_upcoming_poll_event(
                    sim,
                    SE::DiscardInvalidMessage(e).into_transcript_event(self),
                );
                return self.flush_upcoming_events(sim).ok(); // Just added them
            }
        };

        // Successful key exchange; emit the appropriate event
        if handle_msg_result.exchanged_with.is_some() {
            self.enqueue_on_exchanged_events(sim)?;
        }

        // Handle message responses
        if let Some(len) = handle_msg_result.resp {
            let resp = &tx_buf[..len];
            self.enqueue_upcoming_poll_transmission(sim, resp.to_vec(), SendMsgReason::Response);
        };

        // Return the first of the events we just enqueued
        self.flush_upcoming_events(sim).ok()
    }

    fn enqueue_on_exchanged_events(self, sim: &mut RosenpassSimulator) -> anyhow::Result<()> {
        use ServerEvent as SE;
        use TranscriptEvent as TE;

        // Retrieve the key exchanged; this function will panic if the OSK is missing
        let osk = self.osk(sim).unwrap();

        // Issue the `Exchanged`
        self.enqueue_upcoming_poll_event(
            sim,
            SE::Exchanged(osk.clone()).into_transcript_event(self),
        );

        // Retrieve the other osk
        let other_osk = match self.other().try_osk(sim) {
            Some(other_osk) => other_osk,
            None => return Ok(()),
        };

        // Issue the successful exchange event if the OSKs are equal;
        // be careful to use constant time comparison for things like this!
        if rosenpass_constant_time::memcmp(osk.secret(), other_osk.secret()) {
            self.enqueue_upcoming_poll_event(sim, TE::CompletedExchange(osk));
        }

        Ok(())
    }

    fn enqueue_upcoming_poll_event(self, sim: &mut RosenpassSimulator, ev: TranscriptEvent) {
        let upcoming = UpcomingPollResult::IssueEvent(ev);
        self.get_mut(sim).upcoming_poll_results.push_back(upcoming);
    }

    fn enqueue_upcoming_poll_transmission(
        self,
        sim: &mut RosenpassSimulator,
        msg: Vec<u8>,
        reason: SendMsgReason,
    ) {
        let ev = TranscriptEvent::transmit(self, msg.borrow(), reason);
        let upcoming = UpcomingPollResult::SendMessage(msg, ev);
        self.get_mut(sim).upcoming_poll_results.push_back(upcoming);
    }

    fn try_osk(self, sim: &RosenpassSimulator) -> Option<SymKey> {
        let peer = self.peer(sim);
        let has_osk = peer.session().get(self.srv(sim)).is_some();

        has_osk.then(|| {
            // We already checked whether the OSK is present; there should be no other errors
            self.osk(sim).unwrap()
        })
    }

    fn osk(self, sim: &RosenpassSimulator) -> anyhow::Result<SymKey> {
        self.srv(sim).osk(self.peer(sim))
    }

    fn drop_outgoing_packet(self, sim: &mut RosenpassSimulator) -> Option<Vec<u8>> {
        let pkg = self.tx_queue_mut(sim).pop_front();
        self.enqueue_upcoming_poll_event(
            sim,
            ServerEvent::DroppedPackage.into_transcript_event(self),
        );
        pkg
    }

    fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    fn get(self, sim: &RosenpassSimulator) -> &SimulatorServer {
        match self {
            ServerPtr::A => sim.srv_a.borrow(),
            ServerPtr::B => sim.srv_b.borrow(),
        }
    }

    fn get_mut(self, sim: &mut RosenpassSimulator) -> &mut SimulatorServer {
        match self {
            ServerPtr::A => sim.srv_a.borrow_mut(),
            ServerPtr::B => sim.srv_b.borrow_mut(),
        }
    }

    fn srv(self, sim: &RosenpassSimulator) -> &CryptoServer {
        self.get(sim).srv.borrow()
    }

    fn srv_mut(self, sim: &mut RosenpassSimulator) -> &mut CryptoServer {
        self.get_mut(sim).srv.borrow_mut()
    }

    fn peer(self, sim: &RosenpassSimulator) -> PeerPtr {
        self.get(sim).other_peer
    }

    fn recv(self, sim: &mut RosenpassSimulator) -> Option<Vec<u8>> {
        self.rx_queue_mut(sim).pop_front()
    }

    fn transmit(self, sim: &mut RosenpassSimulator, msg: Vec<u8>) {
        self.tx_queue_mut(sim).push_back(msg);
    }

    fn rx_queue_mut(self, sim: &mut RosenpassSimulator) -> &mut VecDeque<Vec<u8>> {
        self.get_mut(sim).rx_queue.borrow_mut()
    }

    fn tx_queue_mut(self, sim: &mut RosenpassSimulator) -> &mut VecDeque<Vec<u8>> {
        self.other().rx_queue_mut(sim)
    }
}
