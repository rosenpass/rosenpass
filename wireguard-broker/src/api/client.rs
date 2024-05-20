use std::{borrow::BorrowMut, fmt::Debug};

use crate::{
    api::{
        config::NetworkBrokerConfig,
        msgs::{self, REQUEST_MSG_BUFFER_SIZE},
    },
    SerializedBrokerConfig, WireGuardBroker,
};

use super::{
    config::NetworkBrokerConfigErr,
    msgs::{Envelope, SetPskResponse},
};

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum BrokerClientPollResponseError<RecvError> {
    #[error(transparent)]
    IoError(RecvError),
    #[error("Invalid message.")]
    InvalidMessage,
}

impl<RecvError> From<msgs::InvalidMessageTypeError> for BrokerClientPollResponseError<RecvError> {
    fn from(value: msgs::InvalidMessageTypeError) -> Self {
        let msgs::InvalidMessageTypeError = value; // Assert that this is a unit type
        BrokerClientPollResponseError::<RecvError>::InvalidMessage
    }
}

fn io_poller<RecvError>(e: RecvError) -> BrokerClientPollResponseError<RecvError> {
    BrokerClientPollResponseError::<RecvError>::IoError(e)
}

fn invalid_msg_poller<RecvError>() -> BrokerClientPollResponseError<RecvError> {
    BrokerClientPollResponseError::<RecvError>::InvalidMessage
}

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum BrokerClientSetPskError<SendError> {
    #[error("Error with encoding/decoding message")]
    MsgError,
    #[error("Network Broker Config error: {0}")]
    BrokerError(NetworkBrokerConfigErr),
    #[error(transparent)]
    IoError(SendError),
    #[error("Interface name out of bounds")]
    IfaceOutOfBounds,
}

pub trait BrokerClientIo {
    type SendError;
    type RecvError;

    fn send_msg(&mut self, buf: &[u8]) -> Result<(), Self::SendError>;
    fn recv_msg(&mut self) -> Result<Option<&[u8]>, Self::RecvError>;
}

#[derive(Debug)]
pub struct BrokerClient<Io>
where
    Io: BrokerClientIo + Debug,
{
    io: Io,
}

impl<Io> BrokerClient<Io>
where
    Io: BrokerClientIo + Debug,
{
    pub fn new(io: Io) -> Self {
        Self { io }
    }

    pub fn io(&self) -> &Io {
        &self.io
    }

    pub fn io_mut(&mut self) -> &mut Io {
        &mut self.io
    }

    pub fn poll_response(
        &mut self,
    ) -> Result<Option<msgs::SetPskResult>, BrokerClientPollResponseError<Io::RecvError>> {
        let res: &[u8] = match self.io.borrow_mut().recv_msg().map_err(io_poller)? {
            Some(r) => r,
            None => return Ok(None),
        };

        let typ = res.get(0).ok_or(invalid_msg_poller())?;
        let typ = msgs::MsgType::try_from(*typ)?;
        let msgs::MsgType::SetPsk = typ; // Assert type

        let res = zerocopy::Ref::<&[u8], Envelope<SetPskResponse>>::new(res)
            .ok_or(invalid_msg_poller())?;
        let res: &msgs::SetPskResponse = &res.payload;
        let res: msgs::SetPskResponseReturnCode = res
            .return_code
            .try_into()
            .map_err(|_| invalid_msg_poller())?;
        let res: msgs::SetPskResult = res.into();

        Ok(Some(res))
    }
}

impl<Io> WireGuardBroker for BrokerClient<Io>
where
    Io: BrokerClientIo + Debug,
{
    type Error = BrokerClientSetPskError<Io::SendError>;

    fn set_psk(&mut self, config: SerializedBrokerConfig) -> Result<(), Self::Error> {
        let config: Result<NetworkBrokerConfig, NetworkBrokerConfigErr> = config.try_into();
        let config = config.map_err(|e| BrokerClientSetPskError::BrokerError(e))?;

        use BrokerClientSetPskError::*;
        const BUF_SIZE: usize = REQUEST_MSG_BUFFER_SIZE;

        // Allocate message
        let mut req = [0u8; BUF_SIZE];

        // Construct message view
        let mut req = zerocopy::Ref::<&mut [u8], Envelope<msgs::SetPskRequest>>::new(&mut req)
            .ok_or(MsgError)?;

        // Populate envelope
        req.msg_type = msgs::MsgType::SetPsk as u8;
        {
            // Derived payload
            let req = &mut req.payload;

            // Populate payload
            req.peer_id.copy_from_slice(&config.peer_id.value);
            req.psk.copy_from_slice(config.psk.secret());
            req.set_iface(config.iface.as_ref())
                .ok_or(IfaceOutOfBounds)?;
        }

        // Send message
        self.io
            .borrow_mut()
            .send_msg(req.bytes())
            .map_err(IoError)?;

        Ok(())
    }
}
