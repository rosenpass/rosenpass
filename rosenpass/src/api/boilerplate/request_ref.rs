use anyhow::{anyhow, ensure};

use zerocopy::{ByteSlice, ByteSliceMut, Ref, SplitByteSlice};

use super::{ByteSliceRefExt, MessageAttributes, PingRequest, RequestMsgType};

/// Helper for producing API message request references, [RequestRef].
///
/// This is to [RequestRef] as [rosenpass_util::zerocopy::RefMaker] is to
/// [zerocopy::Ref].
struct RequestRefMaker<B> {
    buf: B,
    msg_type: RequestMsgType,
}

impl<B: SplitByteSlice> RequestRef<B> {
    /// Produce a [RequestRef] from a raw message buffer,
    /// reading the type from the buffer
    ///
    /// # Examples
    ///
    /// ```
    /// use zerocopy::IntoBytes;
    ///
    /// use rosenpass::api::{PingRequest, RequestMsgType, RequestRef};
    ///
    /// let msg = PingRequest::new([0u8; 256]);
    ///
    /// // TODO: HEISENBUG: This is necessary for some reason to make the rest of the example work
    /// let typ = msg.msg_type;
    /// assert_eq!(typ, rosenpass::api::PING_REQUEST);
    ///
    /// let buf = msg.as_bytes();
    /// let msg_ref = RequestRef::parse(buf)?;
    /// assert!(matches!(msg_ref, RequestRef::Ping(_)));
    ///
    /// assert_eq!(msg_ref.message_type(), RequestMsgType::Ping);
    ///
    /// assert!(std::ptr::eq(buf, msg_ref.bytes()));
    ///
    /// Ok::<(), anyhow::Error>(())
    /// ```
    pub fn parse(buf: B) -> anyhow::Result<Self> {
        RequestRefMaker::new(buf)?.parse()
    }

    /// Produce a [ResponseRef] from the prefix of a raw message buffer,
    /// reading the type from the buffer.
    pub fn parse_from_prefix(buf: B) -> anyhow::Result<Self> {
        RequestRefMaker::new(buf)?.from_prefix()?.parse()
    }

    /// Produce a [ResponseRef] from the suffix of a raw message buffer,
    /// reading the type from the buffer.
    pub fn parse_from_suffix(buf: B) -> anyhow::Result<Self> {
        RequestRefMaker::new(buf)?.from_suffix()?.parse()
    }

    /// Get the message type [Self] contains
    ///
    /// # Examples
    ///
    /// See [Self::parse]
    pub fn message_type(&self) -> RequestMsgType {
        match self {
            Self::Ping(_) => RequestMsgType::Ping,
            Self::SupplyKeypair(_) => RequestMsgType::SupplyKeypair,
            Self::AddListenSocket(_) => RequestMsgType::AddListenSocket,
            Self::AddPskBroker(_) => RequestMsgType::AddPskBroker,
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

impl<B> From<Ref<B, super::AddPskBrokerRequest>> for RequestRef<B> {
    fn from(v: Ref<B, super::AddPskBrokerRequest>) -> Self {
        Self::AddPskBroker(v)
    }
}

impl<B: SplitByteSlice> RequestRefMaker<B> {
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
            RequestMsgType::AddPskBroker => {
                RequestRef::AddPskBroker(self.buf.add_psk_broker_request()?)
            }
        })
    }

    #[allow(clippy::wrong_self_convention)]
    fn from_prefix(self) -> anyhow::Result<Self> {
        self.ensure_fit()?;
        let point = self.target_size();
        let Self { buf, msg_type } = self;
        let (buf, _) = buf
            .split_at(point)
            .map_err(|_| anyhow!("RequestRefMaker::from_prefix: can not split buffer"))?;
        Ok(Self { buf, msg_type })
    }

    #[allow(clippy::wrong_self_convention)]
    fn from_suffix(self) -> anyhow::Result<Self> {
        self.ensure_fit()?;
        let point = self.buf.len() - self.target_size();
        let Self { buf, msg_type } = self;
        let (_, buf) = buf
            .split_at(point)
            .map_err(|_| anyhow!("split_at failed after ensure_fit; this should be unreachable"))?;
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

/// Reference to a API message response, typed as an enum.
pub enum RequestRef<B> {
    Ping(Ref<B, PingRequest>),
    SupplyKeypair(Ref<B, super::SupplyKeypairRequest>),
    AddListenSocket(Ref<B, super::AddListenSocketRequest>),
    AddPskBroker(Ref<B, super::AddPskBrokerRequest>),
}

impl<B> RequestRef<B>
where
    B: ByteSlice,
{
    /// Access the byte data of this reference
    ///
    /// # Examples
    ///
    /// See [Self::parse].
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Ping(r) => Ref::bytes(r),
            Self::SupplyKeypair(r) => Ref::bytes(r),
            Self::AddListenSocket(r) => Ref::bytes(r),
            Self::AddPskBroker(r) => Ref::bytes(r),
        }
    }
}

impl<B> RequestRef<B>
where
    B: ByteSliceMut,
{
    /// Access the byte data of this reference; mutably
    pub fn bytes_mut(&mut self) -> &[u8] {
        match self {
            Self::Ping(r) => Ref::bytes_mut(r),
            Self::SupplyKeypair(r) => Ref::bytes_mut(r),
            Self::AddListenSocket(r) => Ref::bytes_mut(r),
            Self::AddPskBroker(r) => Ref::bytes_mut(r),
        }
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::IntoBytes;

    use super::*;

    #[test]
    fn parse_from_suffix_returns_suffix_request() -> anyhow::Result<()> {
        let prefix = PingRequest::new([1; 256]);
        let suffix = PingRequest::new([2; 256]);
        let mut buf = Vec::new();
        buf.extend_from_slice(prefix.as_bytes());
        buf.extend_from_slice(suffix.as_bytes());

        let msg_ref = RequestRef::parse_from_suffix(buf.as_slice())?;

        assert!(matches!(msg_ref, RequestRef::Ping(_)));
        assert_eq!(msg_ref.bytes(), suffix.as_bytes());
        Ok(())
    }
}
