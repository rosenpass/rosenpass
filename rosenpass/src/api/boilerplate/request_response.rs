use rosenpass_util::zerocopy::{
    RefMaker, ZerocopyEmancipateExt, ZerocopyEmancipateMutExt, ZerocopySliceExt,
};
use zerocopy::{ByteSlice, ByteSliceMut, Ref};

use super::{Message, PingRequest, PingResponse};
use super::{RequestRef, ResponseRef, ZerocopyResponseMakerSetupMessageExt};

/// Extension trait for [Message]s that are requests messages
pub trait RequestMsg: Sized + Message {
    /// The response message belonging to this request message
    type ResponseMsg: ResponseMsg;

    /// Construct a response make for this particular message
    fn zk_response_maker<B: ByteSlice>(buf: B) -> RefMaker<B, Self::ResponseMsg> {
        buf.zk_ref_maker()
    }

    /// Setup a response maker (through [Message::setup]) for this request message type
    fn setup_response<B: ByteSliceMut>(buf: B) -> anyhow::Result<Ref<B, Self::ResponseMsg>> {
        Self::zk_response_maker(buf).setup_msg()
    }

    /// Setup a response maker from a buffer prefix (through [Message::setup]) for this request message type
    fn setup_response_from_prefix<B: ByteSliceMut>(
        buf: B,
    ) -> anyhow::Result<Ref<B, Self::ResponseMsg>> {
        Self::zk_response_maker(buf).from_prefix()?.setup_msg()
    }

    /// Setup a response maker from a buffer suffix (through [Message::setup]) for this request message type
    fn setup_response_from_suffix<B: ByteSliceMut>(
        buf: B,
    ) -> anyhow::Result<Ref<B, Self::ResponseMsg>> {
        Self::zk_response_maker(buf).from_prefix()?.setup_msg()
    }
}

/// Extension trait for [Message]s that are response messages
pub trait ResponseMsg: Message {
    type RequestMsg: RequestMsg;
}

impl RequestMsg for PingRequest {
    type ResponseMsg = PingResponse;
}

impl ResponseMsg for PingResponse {
    type RequestMsg = PingRequest;
}

impl RequestMsg for super::SupplyKeypairRequest {
    type ResponseMsg = super::SupplyKeypairResponse;
}

impl ResponseMsg for super::SupplyKeypairResponse {
    type RequestMsg = super::SupplyKeypairRequest;
}

impl RequestMsg for super::AddListenSocketRequest {
    type ResponseMsg = super::AddListenSocketResponse;
}

impl ResponseMsg for super::AddListenSocketResponse {
    type RequestMsg = super::AddListenSocketRequest;
}

impl RequestMsg for super::AddPskBrokerRequest {
    type ResponseMsg = super::AddPskBrokerResponse;
}

impl ResponseMsg for super::AddPskBrokerResponse {
    type RequestMsg = super::AddPskBrokerRequest;
}

/// Request and response for the [crate::api::RequestMsgType::Ping] message type
pub type PingPair<B1, B2> = (Ref<B1, PingRequest>, Ref<B2, PingResponse>);
/// Request and response for the [crate::api::RequestMsgType::SupplyKeypair] message type
pub type SupplyKeypairPair<B1, B2> = (
    Ref<B1, super::SupplyKeypairRequest>,
    Ref<B2, super::SupplyKeypairResponse>,
);
/// Request and response for the [crate::api::RequestMsgType::AddListenSocket] message type
pub type AddListenSocketPair<B1, B2> = (
    Ref<B1, super::AddListenSocketRequest>,
    Ref<B2, super::AddListenSocketResponse>,
);
/// Request and response for the [crate::api::RequestMsgType::AddPskBroker] message type
pub type AddPskBrokerPair<B1, B2> = (
    Ref<B1, super::AddPskBrokerRequest>,
    Ref<B2, super::AddPskBrokerResponse>,
);

/// A pair of references to messages; request and response each.
pub enum RequestResponsePair<B1, B2> {
    Ping(PingPair<B1, B2>),
    SupplyKeypair(SupplyKeypairPair<B1, B2>),
    AddListenSocket(AddListenSocketPair<B1, B2>),
    AddPskBroker(AddPskBrokerPair<B1, B2>),
}

impl<B1, B2> From<PingPair<B1, B2>> for RequestResponsePair<B1, B2> {
    fn from(v: PingPair<B1, B2>) -> Self {
        RequestResponsePair::Ping(v)
    }
}

impl<B1, B2> From<SupplyKeypairPair<B1, B2>> for RequestResponsePair<B1, B2> {
    fn from(v: SupplyKeypairPair<B1, B2>) -> Self {
        RequestResponsePair::SupplyKeypair(v)
    }
}

impl<B1, B2> From<AddListenSocketPair<B1, B2>> for RequestResponsePair<B1, B2> {
    fn from(v: AddListenSocketPair<B1, B2>) -> Self {
        RequestResponsePair::AddListenSocket(v)
    }
}

impl<B1, B2> From<AddPskBrokerPair<B1, B2>> for RequestResponsePair<B1, B2> {
    fn from(v: AddPskBrokerPair<B1, B2>) -> Self {
        RequestResponsePair::AddPskBroker(v)
    }
}

impl<B1, B2> RequestResponsePair<B1, B2>
where
    B1: ByteSlice,
    B2: ByteSlice,
{
    /// Returns a tuple to both the request and the response message
    pub fn both(&self) -> (RequestRef<&[u8]>, ResponseRef<&[u8]>) {
        match self {
            Self::Ping((req, res)) => {
                let req = RequestRef::Ping(req.emancipate());
                let res = ResponseRef::Ping(res.emancipate());
                (req, res)
            }
            Self::SupplyKeypair((req, res)) => {
                let req = RequestRef::SupplyKeypair(req.emancipate());
                let res = ResponseRef::SupplyKeypair(res.emancipate());
                (req, res)
            }
            Self::AddListenSocket((req, res)) => {
                let req = RequestRef::AddListenSocket(req.emancipate());
                let res = ResponseRef::AddListenSocket(res.emancipate());
                (req, res)
            }
            Self::AddPskBroker((req, res)) => {
                let req = RequestRef::AddPskBroker(req.emancipate());
                let res = ResponseRef::AddPskBroker(res.emancipate());
                (req, res)
            }
        }
    }

    /// Returns the request message
    pub fn request(&self) -> RequestRef<&[u8]> {
        self.both().0
    }

    /// Returns the response message
    pub fn response(&self) -> ResponseRef<&[u8]> {
        self.both().1
    }
}

impl<B1, B2> RequestResponsePair<B1, B2>
where
    B1: ByteSliceMut,
    B2: ByteSliceMut,
{
    /// Returns a mutable tuple to both the request and the response message
    pub fn both_mut(&mut self) -> (RequestRef<&mut [u8]>, ResponseRef<&mut [u8]>) {
        match self {
            Self::Ping((req, res)) => {
                let req = RequestRef::Ping(req.emancipate_mut());
                let res = ResponseRef::Ping(res.emancipate_mut());
                (req, res)
            }
            Self::SupplyKeypair((req, res)) => {
                let req = RequestRef::SupplyKeypair(req.emancipate_mut());
                let res = ResponseRef::SupplyKeypair(res.emancipate_mut());
                (req, res)
            }
            Self::AddListenSocket((req, res)) => {
                let req = RequestRef::AddListenSocket(req.emancipate_mut());
                let res = ResponseRef::AddListenSocket(res.emancipate_mut());
                (req, res)
            }
            Self::AddPskBroker((req, res)) => {
                let req = RequestRef::AddPskBroker(req.emancipate_mut());
                let res = ResponseRef::AddPskBroker(res.emancipate_mut());
                (req, res)
            }
        }
    }

    /// Returns the request message, mutably
    pub fn request_mut(&mut self) -> RequestRef<&mut [u8]> {
        self.both_mut().0
    }

    /// Returns the response message, mutably
    pub fn response_mut(&mut self) -> ResponseRef<&mut [u8]> {
        self.both_mut().1
    }
}
