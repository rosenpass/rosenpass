use std::borrow::BorrowMut;

use rosenpass_secret_memory::{Public, Secret};

use crate::api::msgs::{self, Envelope, SetPskRequest, SetPskResponse};
use crate::WireGuardBroker;

use super::config::{NetworkBrokerConfigBuilder, NetworkBrokerConfigErr};

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum BrokerServerError {
    #[error("No such request type: {}", .0)]
    NoSuchRequestType(u8),
    #[error("Invalid message received.")]
    InvalidMessage,
    #[error("Network Broker Config error: {0}")]
    BrokerError(NetworkBrokerConfigErr),
}

impl From<msgs::InvalidMessageTypeError> for BrokerServerError {
    fn from(value: msgs::InvalidMessageTypeError) -> Self {
        let msgs::InvalidMessageTypeError = value; // Assert that this is a unit type
        BrokerServerError::InvalidMessage
    }
}

pub struct BrokerServer<Err, Inner>
where
    Inner: WireGuardBroker<Error = Err>,
    msgs::SetPskError: From<Err>,
{
    inner: Inner,
}

impl<Err, Inner> BrokerServer<Err, Inner>
where
    Inner: WireGuardBroker<Error = Err>,
    msgs::SetPskError: From<Err>,
{
    pub fn new(inner: Inner) -> Self {
        Self { inner }
    }

    pub fn handle_message(
        &mut self,
        req: &[u8],
        res: &mut [u8; msgs::RESPONSE_MSG_BUFFER_SIZE],
    ) -> Result<usize, BrokerServerError> {
        use BrokerServerError::*;

        let typ = req.get(0).ok_or(InvalidMessage)?;
        let typ = msgs::MsgType::try_from(*typ)?;
        let msgs::MsgType::SetPsk = typ; // Assert type

        let req = zerocopy::Ref::<&[u8], Envelope<SetPskRequest>>::new(req)
            .ok_or(BrokerServerError::InvalidMessage)?;
        let mut res = zerocopy::Ref::<&mut [u8], Envelope<SetPskResponse>>::new(res)
            .ok_or(BrokerServerError::InvalidMessage)?;

        res.payload.return_code = msgs::MsgType::SetPsk as u8;
        self.handle_set_psk(&req.payload, &mut res.payload)?;
        Ok(res.bytes().len())
    }

    fn handle_set_psk(
        &mut self,
        req: &SetPskRequest,
        res: &mut SetPskResponse,
    ) -> Result<(), BrokerServerError> {
        // Using unwrap here since lenses can not return fixed-size arrays
        // TODO: Slices should give access to fixed size arrays
        let peer_id = Public::from_slice(&req.peer_id);
        let psk = Secret::from_slice(&req.psk);

        let interface = req
            .iface()
            .map_err(|_e| BrokerServerError::InvalidMessage)?;

        let config = NetworkBrokerConfigBuilder::default()
            .peer_id(&peer_id)
            .psk(&psk)
            .iface(interface)
            .build()
            .unwrap();
        let r: Result<(), Err> = self.inner.borrow_mut().set_psk(config.into());
        let r: msgs::SetPskResult = r.map_err(|e| e.into());
        let r: msgs::SetPskResponseReturnCode = r.into();
        res.return_code = r as u8;

        Ok(())
    }
}
