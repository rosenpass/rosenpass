use hex_literal::hex;
use rosenpass_util::zerocopy::RefMaker;
use zerocopy::ByteSlice;

use crate::RosenpassError::{self, InvalidApiMessageType};

pub type RawMsgType = u128;

// hash domain hash of: Rosenpass IPC API -> Rosenpass Protocol Server -> Ping Request
pub const PING_REQUEST: RawMsgType =
    RawMsgType::from_le_bytes(hex!("2397 3ecc c441 704d    0b02 ea31 45d3 4999"));
// hash domain hash of: Rosenpass IPC API -> Rosenpass Protocol Server -> Ping Response
pub const PING_RESPONSE: RawMsgType =
    RawMsgType::from_le_bytes(hex!("4ec7 f6f0 2bbc ba64    48f1 da14 c7cf 0260"));

pub trait MessageAttributes {
    fn message_size(&self) -> usize;
}

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum RequestMsgType {
    Ping,
}

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum ResponseMsgType {
    Ping,
}

impl MessageAttributes for RequestMsgType {
    fn message_size(&self) -> usize {
        match self {
            Self::Ping => std::mem::size_of::<super::PingRequest>(),
        }
    }
}

impl MessageAttributes for ResponseMsgType {
    fn message_size(&self) -> usize {
        match self {
            Self::Ping => std::mem::size_of::<super::PingResponse>(),
        }
    }
}

impl TryFrom<RawMsgType> for RequestMsgType {
    type Error = RosenpassError;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        use RequestMsgType as E;
        Ok(match value {
            self::PING_REQUEST => E::Ping,
            _ => return Err(InvalidApiMessageType(value)),
        })
    }
}

impl From<RequestMsgType> for RawMsgType {
    fn from(val: RequestMsgType) -> Self {
        use RequestMsgType as E;
        match val {
            E::Ping => self::PING_REQUEST,
        }
    }
}

impl TryFrom<RawMsgType> for ResponseMsgType {
    type Error = RosenpassError;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        use ResponseMsgType as E;
        Ok(match value {
            self::PING_RESPONSE => E::Ping,
            _ => return Err(InvalidApiMessageType(value)),
        })
    }
}

impl From<ResponseMsgType> for RawMsgType {
    fn from(val: ResponseMsgType) -> Self {
        use ResponseMsgType as E;
        match val {
            E::Ping => self::PING_RESPONSE,
        }
    }
}

pub trait RawMsgTypeExt {
    fn into_request_msg_type(self) -> Result<RequestMsgType, RosenpassError>;
    fn into_response_msg_type(self) -> Result<ResponseMsgType, RosenpassError>;
}

impl RawMsgTypeExt for RawMsgType {
    fn into_request_msg_type(self) -> Result<RequestMsgType, RosenpassError> {
        self.try_into()
    }

    fn into_response_msg_type(self) -> Result<ResponseMsgType, RosenpassError> {
        self.try_into()
    }
}

pub trait RefMakerRawMsgTypeExt {
    fn parse_request_msg_type(self) -> anyhow::Result<RequestMsgType>;
    fn parse_response_msg_type(self) -> anyhow::Result<ResponseMsgType>;
}

impl<B: ByteSlice> RefMakerRawMsgTypeExt for RefMaker<B, RawMsgType> {
    fn parse_request_msg_type(self) -> anyhow::Result<RequestMsgType> {
        Ok(self.parse()?.read().try_into()?)
    }

    fn parse_response_msg_type(self) -> anyhow::Result<ResponseMsgType> {
        Ok(self.parse()?.read().try_into()?)
    }
}
