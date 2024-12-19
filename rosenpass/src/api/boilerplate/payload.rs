use rosenpass_util::zerocopy::ZerocopyMutSliceExt;
use zerocopy::{AsBytes, ByteSliceMut, FromBytes, FromZeroes, Ref};

use super::{Message, RawMsgType, RequestMsgType, ResponseMsgType};

/// Size required to fit any request message in binary form
pub const MAX_REQUEST_LEN: usize = 2500; // TODO fix this
/// Size required to fit any response message in binary form
pub const MAX_RESPONSE_LEN: usize = 2500; // TODO fix this
/// Maximum number of file descriptors that can be sent in a request.
pub const MAX_REQUEST_FDS: usize = 2;

/// Message envelope for API messages
#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct Envelope<M: AsBytes + FromBytes> {
    /// Which message this is
    pub msg_type: RawMsgType,
    /// The actual Paylod
    pub payload: M,
}

/// Message envelope for API requests
pub type RequestEnvelope<M> = Envelope<M>;
/// Message envelope for API responses
pub type ResponseEnvelope<M> = Envelope<M>;

#[allow(missing_docs)]
#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct PingRequestPayload {
    /// Randomly generated connection id
    pub echo: [u8; 256],
}

#[allow(missing_docs)]
pub type PingRequest = RequestEnvelope<PingRequestPayload>;

impl PingRequest {
    #[allow(missing_docs)]
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

#[allow(missing_docs)]
#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct PingResponsePayload {
    /// Randomly generated connection id
    pub echo: [u8; 256],
}

#[allow(missing_docs)]
pub type PingResponse = ResponseEnvelope<PingResponsePayload>;

impl PingResponse {
    #[allow(missing_docs)]
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

#[allow(missing_docs)]
#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct SupplyKeypairRequestPayload {}

#[allow(missing_docs)]
pub type SupplyKeypairRequest = RequestEnvelope<SupplyKeypairRequestPayload>;

impl Default for SupplyKeypairRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl SupplyKeypairRequest {
    #[allow(missing_docs)]
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

#[allow(missing_docs)]
pub mod supply_keypair_response_status {
    #[allow(missing_docs)]
    pub const OK: u128 = 0;
    #[allow(missing_docs)]
    pub const KEYPAIR_ALREADY_SUPPLIED: u128 = 1;
    /// TODO: This is not actually part of the API. Remove.
    #[allow(missing_docs)]
    pub const INTERNAL_ERROR: u128 = 2;
    #[allow(missing_docs)]
    pub const INVALID_REQUEST: u128 = 3;
    /// TODO: Deprectaed, remove
    #[allow(missing_docs)]
    pub const IO_ERROR: u128 = 4;
}

#[allow(missing_docs)]
#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct SupplyKeypairResponsePayload {
    #[allow(missing_docs)]
    pub status: u128,
}

#[allow(missing_docs)]
pub type SupplyKeypairResponse = ResponseEnvelope<SupplyKeypairResponsePayload>;

impl SupplyKeypairResponse {
    #[allow(missing_docs)]
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

#[allow(missing_docs)]
#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct AddListenSocketRequestPayload {}

#[allow(missing_docs)]
pub type AddListenSocketRequest = RequestEnvelope<AddListenSocketRequestPayload>;

impl Default for AddListenSocketRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl AddListenSocketRequest {
    #[allow(missing_docs)]
    pub fn new() -> Self {
        Self::from_payload(AddListenSocketRequestPayload {})
    }
}

impl Message for AddListenSocketRequest {
    type Payload = AddListenSocketRequestPayload;
    type MessageClass = RequestMsgType;
    const MESSAGE_TYPE: Self::MessageClass = RequestMsgType::AddListenSocket;

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

#[allow(missing_docs)]
pub mod add_listen_socket_response_status {
    #[allow(missing_docs)]
    pub const OK: u128 = 0;
    #[allow(missing_docs)]
    pub const INVALID_REQUEST: u128 = 1;
    #[allow(missing_docs)]
    pub const INTERNAL_ERROR: u128 = 2;
}

#[allow(missing_docs)]
#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct AddListenSocketResponsePayload {
    pub status: u128,
}

#[allow(missing_docs)]
pub type AddListenSocketResponse = ResponseEnvelope<AddListenSocketResponsePayload>;

impl AddListenSocketResponse {
    #[allow(missing_docs)]
    pub fn new(status: u128) -> Self {
        Self::from_payload(AddListenSocketResponsePayload { status })
    }
}

impl Message for AddListenSocketResponse {
    type Payload = AddListenSocketResponsePayload;
    type MessageClass = ResponseMsgType;
    const MESSAGE_TYPE: Self::MessageClass = ResponseMsgType::AddListenSocket;

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

#[allow(missing_docs)]
#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct AddPskBrokerRequestPayload {}

#[allow(missing_docs)]
pub type AddPskBrokerRequest = RequestEnvelope<AddPskBrokerRequestPayload>;

impl Default for AddPskBrokerRequest {
    #[allow(missing_docs)]
    fn default() -> Self {
        Self::new()
    }
}

impl AddPskBrokerRequest {
    #[allow(missing_docs)]
    pub fn new() -> Self {
        Self::from_payload(AddPskBrokerRequestPayload {})
    }
}

impl Message for AddPskBrokerRequest {
    type Payload = AddPskBrokerRequestPayload;
    type MessageClass = RequestMsgType;
    const MESSAGE_TYPE: Self::MessageClass = RequestMsgType::AddPskBroker;

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

#[allow(missing_docs)]
pub mod add_psk_broker_response_status {
    #[allow(missing_docs)]
    pub const OK: u128 = 0;
    #[allow(missing_docs)]
    pub const INVALID_REQUEST: u128 = 1;
    #[allow(missing_docs)]
    pub const INTERNAL_ERROR: u128 = 2;
}

#[allow(missing_docs)]
#[repr(packed)]
#[derive(Debug, Copy, Clone, Hash, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct AddPskBrokerResponsePayload {
    pub status: u128,
}

#[allow(missing_docs)]
pub type AddPskBrokerResponse = ResponseEnvelope<AddPskBrokerResponsePayload>;

impl AddPskBrokerResponse {
    #[allow(missing_docs)]
    pub fn new(status: u128) -> Self {
        Self::from_payload(AddPskBrokerResponsePayload { status })
    }
}

impl Message for AddPskBrokerResponse {
    type Payload = AddPskBrokerResponsePayload;
    type MessageClass = ResponseMsgType;
    const MESSAGE_TYPE: Self::MessageClass = ResponseMsgType::AddPskBroker;

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
