use rosenpass_util::zerocopy::ZerocopyMutSliceExt;
use zerocopy::{AsBytes, ByteSliceMut, FromBytes, FromZeroes, Ref};

use super::{Message, RawMsgType, RequestMsgType, ResponseMsgType};

/// Size required to fit any message in binary form
pub const MAX_REQUEST_LEN: usize = 2500; // TODO fix this
pub const MAX_RESPONSE_LEN: usize = 2500; // TODO fix this
pub const MAX_REQUEST_FDS: usize = 2;

#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct Envelope<M: AsBytes + FromBytes> {
    /// Which message this is
    pub msg_type: RawMsgType,
    /// The actual Paylod
    pub payload: M,
}

pub type RequestEnvelope<M> = Envelope<M>;
pub type ResponseEnvelope<M> = Envelope<M>;

#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct PingRequestPayload {
    /// Randomly generated connection id
    pub echo: [u8; 256],
}

pub type PingRequest = RequestEnvelope<PingRequestPayload>;

impl PingRequest {
    pub fn new(echo: [u8; 256]) -> Self {
        Self::from_payload(PingRequestPayload { echo })
    }
}

impl Message for PingRequest {
    type Payload = PingRequestPayload;
    type MessageClass = RequestMsgType;
    const MESSAGE_TYPE: Self::MessageClass = RequestMsgType::Ping;

    fn from_payload(payload: Self::Payload) -> Self {
        Self {
            msg_type: Self::MESSAGE_TYPE.into(),
            payload,
        }
    }

    fn setup<B: ByteSliceMut>(buf: B) -> anyhow::Result<Ref<B, Self>> {
        let mut r: Ref<B, Self> = buf.zk_zeroized()?;
        r.init();
        Ok(r)
    }

    fn init(&mut self) {
        self.msg_type = Self::MESSAGE_TYPE.into();
    }
}

#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct PingResponsePayload {
    /// Randomly generated connection id
    pub echo: [u8; 256],
}

pub type PingResponse = ResponseEnvelope<PingResponsePayload>;

impl PingResponse {
    pub fn new(echo: [u8; 256]) -> Self {
        Self::from_payload(PingResponsePayload { echo })
    }
}

impl Message for PingResponse {
    type Payload = PingResponsePayload;
    type MessageClass = ResponseMsgType;
    const MESSAGE_TYPE: Self::MessageClass = ResponseMsgType::Ping;

    fn from_payload(payload: Self::Payload) -> Self {
        Self {
            msg_type: Self::MESSAGE_TYPE.into(),
            payload,
        }
    }

    fn setup<B: ByteSliceMut>(buf: B) -> anyhow::Result<Ref<B, Self>> {
        let mut r: Ref<B, Self> = buf.zk_zeroized()?;
        r.init();
        Ok(r)
    }

    fn init(&mut self) {
        self.msg_type = Self::MESSAGE_TYPE.into();
    }
}

#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct SupplyKeypairRequestPayload {}

pub type SupplyKeypairRequest = RequestEnvelope<SupplyKeypairRequestPayload>;

impl Default for SupplyKeypairRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl SupplyKeypairRequest {
    pub fn new() -> Self {
        Self::from_payload(SupplyKeypairRequestPayload {})
    }
}

impl Message for SupplyKeypairRequest {
    type Payload = SupplyKeypairRequestPayload;
    type MessageClass = RequestMsgType;
    const MESSAGE_TYPE: Self::MessageClass = RequestMsgType::SupplyKeypair;

    fn from_payload(payload: Self::Payload) -> Self {
        Self {
            msg_type: Self::MESSAGE_TYPE.into(),
            payload,
        }
    }

    fn setup<B: ByteSliceMut>(buf: B) -> anyhow::Result<Ref<B, Self>> {
        let mut r: Ref<B, Self> = buf.zk_zeroized()?;
        r.init();
        Ok(r)
    }

    fn init(&mut self) {
        self.msg_type = Self::MESSAGE_TYPE.into();
    }
}

pub mod supply_keypair_response_status {
    pub const OK: u128 = 0;
    pub const KEYPAIR_ALREADY_SUPPLIED: u128 = 1;
    pub const INTERNAL_ERROR: u128 = 2;
    pub const INVALID_REQUEST: u128 = 3;
    pub const IO_ERROR: u128 = 4;
}

#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct SupplyKeypairResponsePayload {
    pub status: u128,
}

pub type SupplyKeypairResponse = ResponseEnvelope<SupplyKeypairResponsePayload>;

impl SupplyKeypairResponse {
    pub fn new(status: u128) -> Self {
        Self::from_payload(SupplyKeypairResponsePayload { status })
    }
}

impl Message for SupplyKeypairResponse {
    type Payload = SupplyKeypairResponsePayload;
    type MessageClass = ResponseMsgType;
    const MESSAGE_TYPE: Self::MessageClass = ResponseMsgType::SupplyKeypair;

    fn from_payload(payload: Self::Payload) -> Self {
        Self {
            msg_type: Self::MESSAGE_TYPE.into(),
            payload,
        }
    }

    fn setup<B: ByteSliceMut>(buf: B) -> anyhow::Result<Ref<B, Self>> {
        let mut r: Ref<B, Self> = buf.zk_zeroized()?;
        r.init();
        Ok(r)
    }

    fn init(&mut self) {
        self.msg_type = Self::MESSAGE_TYPE.into();
    }
}
