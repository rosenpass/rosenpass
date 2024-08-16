use anyhow::ensure;

use zerocopy::{ByteSlice, ByteSliceMut, Ref};

use super::{ByteSliceRefExt, MessageAttributes, PingRequest, RequestMsgType};

struct RequestRefMaker<B> {
    buf: B,
    msg_type: RequestMsgType,
}

impl<B: ByteSlice> RequestRef<B> {
    pub fn parse(buf: B) -> anyhow::Result<Self> {
        RequestRefMaker::new(buf)?.parse()
    }

    pub fn parse_from_prefix(buf: B) -> anyhow::Result<Self> {
        RequestRefMaker::new(buf)?.from_prefix()?.parse()
    }

    pub fn parse_from_suffix(buf: B) -> anyhow::Result<Self> {
        RequestRefMaker::new(buf)?.from_suffix()?.parse()
    }

    pub fn message_type(&self) -> RequestMsgType {
        match self {
            Self::Ping(_) => RequestMsgType::Ping,
            Self::SupplyKeypair(_) => RequestMsgType::SupplyKeypair,
            Self::AddListenSocket(_) => RequestMsgType::AddListenSocket,
        }
    }
}

impl<B> From<Ref<B, PingRequest>> for RequestRef<B> {
    fn from(v: Ref<B, PingRequest>) -> Self {
        Self::Ping(v)
    }
}

impl<B> From<Ref<B, super::SupplyKeypairRequest>> for RequestRef<B> {
    fn from(v: Ref<B, super::SupplyKeypairRequest>) -> Self {
        Self::SupplyKeypair(v)
    }
}

impl<B> From<Ref<B, super::AddListenSocketRequest>> for RequestRef<B> {
    fn from(v: Ref<B, super::AddListenSocketRequest>) -> Self {
        Self::AddListenSocket(v)
    }
}

impl<B: ByteSlice> RequestRefMaker<B> {
    fn new(buf: B) -> anyhow::Result<Self> {
        let msg_type = buf.deref().request_msg_type_from_prefix()?;
        Ok(Self { buf, msg_type })
    }

    fn target_size(&self) -> usize {
        self.msg_type.message_size()
    }

    fn parse(self) -> anyhow::Result<RequestRef<B>> {
        Ok(match self.msg_type {
            RequestMsgType::Ping => RequestRef::Ping(self.buf.ping_request()?),
            RequestMsgType::SupplyKeypair => {
                RequestRef::SupplyKeypair(self.buf.supply_keypair_request()?)
            }
            RequestMsgType::AddListenSocket => {
                RequestRef::AddListenSocket(self.buf.add_listen_socket_request()?)
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

pub enum RequestRef<B> {
    Ping(Ref<B, PingRequest>),
    SupplyKeypair(Ref<B, super::SupplyKeypairRequest>),
    AddListenSocket(Ref<B, super::AddListenSocketRequest>),
}

impl<B> RequestRef<B>
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

impl<B> RequestRef<B>
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
