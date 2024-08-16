// TODO: This is copied verbatim from ResponseRef…not pretty
use anyhow::ensure;

use zerocopy::{ByteSlice, ByteSliceMut, Ref};

use super::{ByteSliceRefExt, MessageAttributes, PingResponse, ResponseMsgType};

struct ResponseRefMaker<B> {
    buf: B,
    msg_type: ResponseMsgType,
}

impl<B: ByteSlice> ResponseRef<B> {
    pub fn parse(buf: B) -> anyhow::Result<Self> {
        ResponseRefMaker::new(buf)?.parse()
    }

    pub fn parse_from_prefix(buf: B) -> anyhow::Result<Self> {
        ResponseRefMaker::new(buf)?.from_prefix()?.parse()
    }

    pub fn parse_from_suffix(buf: B) -> anyhow::Result<Self> {
        ResponseRefMaker::new(buf)?.from_suffix()?.parse()
    }

    pub fn message_type(&self) -> ResponseMsgType {
        match self {
            Self::Ping(_) => ResponseMsgType::Ping,
            Self::SupplyKeypair(_) => ResponseMsgType::SupplyKeypair,
            Self::AddListenSocket(_) => ResponseMsgType::AddListenSocket,
        }
    }
}

impl<B> From<Ref<B, PingResponse>> for ResponseRef<B> {
    fn from(v: Ref<B, PingResponse>) -> Self {
        Self::Ping(v)
    }
}

impl<B> From<Ref<B, super::SupplyKeypairResponse>> for ResponseRef<B> {
    fn from(v: Ref<B, super::SupplyKeypairResponse>) -> Self {
        Self::SupplyKeypair(v)
    }
}

impl<B> From<Ref<B, super::AddListenSocketResponse>> for ResponseRef<B> {
    fn from(v: Ref<B, super::AddListenSocketResponse>) -> Self {
        Self::AddListenSocket(v)
    }
}

impl<B: ByteSlice> ResponseRefMaker<B> {
    fn new(buf: B) -> anyhow::Result<Self> {
        let msg_type = buf.deref().response_msg_type_from_prefix()?;
        Ok(Self { buf, msg_type })
    }

    fn target_size(&self) -> usize {
        self.msg_type.message_size()
    }

    fn parse(self) -> anyhow::Result<ResponseRef<B>> {
        Ok(match self.msg_type {
            ResponseMsgType::Ping => ResponseRef::Ping(self.buf.ping_response()?),
            ResponseMsgType::SupplyKeypair => {
                ResponseRef::SupplyKeypair(self.buf.supply_keypair_response()?)
            }
            ResponseMsgType::AddListenSocket => {
                ResponseRef::AddListenSocket(self.buf.add_listen_socket_response()?)
            }
        })
    }

    #[allow(clippy::wrong_self_convention)]
    fn from_prefix(self) -> anyhow::Result<Self> {
        self.ensure_fit()?;
        let point = self.target_size();
        let Self { buf, msg_type } = self;
        let (buf, _) = buf.split_at(point);
        Ok(Self { buf, msg_type })
    }

    #[allow(clippy::wrong_self_convention)]
    fn from_suffix(self) -> anyhow::Result<Self> {
        self.ensure_fit()?;
        let point = self.buf.len() - self.target_size();
        let Self { buf, msg_type } = self;
        let (buf, _) = buf.split_at(point);
        Ok(Self { buf, msg_type })
    }

    pub fn ensure_fit(&self) -> anyhow::Result<()> {
        let have = self.buf.len();
        let need = self.target_size();
        ensure!(
            need <= have,
            "Buffer is undersized at {have} bytes (need {need} bytes)!"
        );
        Ok(())
    }
}

pub enum ResponseRef<B> {
    Ping(Ref<B, PingResponse>),
    SupplyKeypair(Ref<B, super::SupplyKeypairResponse>),
    AddListenSocket(Ref<B, super::AddListenSocketResponse>),
}

impl<B> ResponseRef<B>
where
    B: ByteSlice,
{
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Ping(r) => r.bytes(),
            Self::SupplyKeypair(r) => r.bytes(),
            Self::AddListenSocket(r) => r.bytes(),
        }
    }
}

impl<B> ResponseRef<B>
where
    B: ByteSliceMut,
{
    pub fn bytes_mut(&mut self) -> &[u8] {
        match self {
            Self::Ping(r) => r.bytes_mut(),
            Self::SupplyKeypair(r) => r.bytes_mut(),
            Self::AddListenSocket(r) => r.bytes_mut(),
        }
    }
}
