//! Constants and configuration values used in the rosenpass core protocol

use crate::msgs::MAC_SIZE;

use super::timing::Timing;

/// Time after which the responder attempts to rekey the session
///
/// From the wireguard paper: rekey every two minutes,
/// discard the key if no rekey is achieved within three
pub const REKEY_AFTER_TIME_RESPONDER: Timing = 120.0;
/// Time after which the initiator attempts to rekey the session.
///
/// This happens ten seconds after [REKEY_AFTER_TIME_RESPONDER], so
/// parties would usually switch roles after every handshake.
///
/// From the wireguard paper: rekey every two minutes,
/// discard the key if no rekey is achieved within three
pub const REKEY_AFTER_TIME_INITIATOR: Timing = 130.0;
/// Time after which either party rejects the current key.
///
/// At this point a new key should have been negotiated.
/// Rejection happens 50-60 seconds after key renegotiation
/// to allow for a graceful handover.
///
/// From the wireguard paper: rekey every two minutes,
/// discard the key if no rekey is achieved within three
pub const REJECT_AFTER_TIME: Timing = 180.0;

/// The length of the `cookie_secret` in the [whitepaper](https://rosenpass.eu/whitepaper.pdf)
pub const COOKIE_SECRET_LEN: usize = MAC_SIZE;
/// The life time of the `cookie_secret` in the [whitepaper](https://rosenpass.eu/whitepaper.pdf)
pub const COOKIE_SECRET_EPOCH: Timing = 120.0;

/// Length of a cookie value (see info about the cookie mechanism in the [whitepaper](https://rosenpass.eu/whitepaper.pdf))
pub const COOKIE_VALUE_LEN: usize = MAC_SIZE;
/// Time after which to delete a cookie, as the initiator, for a certain peer (see info about the cookie mechanism in the [whitepaper](https://rosenpass.eu/whitepaper.pdf))
pub const PEER_COOKIE_VALUE_EPOCH: Timing = 120.0;

/// Seconds until the biscuit key is changed; we issue biscuits
/// using one biscuit key for one epoch and store the biscuit for
/// decryption for a second epoch
///
/// The biscuit mechanism is used to make sure the responder is stateless in our protocol.
pub const BISCUIT_EPOCH: Timing = 300.0;

/// The initiator opportunistically retransmits their messages; it applies an increasing delay
/// between each retreansmission. This is the factor by which the delay grows after each
/// retransmission.
pub const RETRANSMIT_DELAY_GROWTH: Timing = 2.0;
/// The initiator opportunistically retransmits their messages; it applies an increasing delay
/// between each retreansmission. This is the initial delay between retransmissions.
pub const RETRANSMIT_DELAY_BEGIN: Timing = 0.5;
/// The initiator opportunistically retransmits their messages; it applies an increasing delay
/// between each retreansmission. This is the maximum delay between retransmissions.
pub const RETRANSMIT_DELAY_END: Timing = 10.0;
/// The initiator opportunistically retransmits their messages; it applies an increasing delay
/// between each retreansmission. This is the jitter (randomness) applied to the retransmission
/// delay.
pub const RETRANSMIT_DELAY_JITTER: Timing = 0.5;

/// This is the maximum delay that can separate two events for us to consider the events to have
/// happened at the same time.
pub const EVENT_GRACE: Timing = 0.0025;
