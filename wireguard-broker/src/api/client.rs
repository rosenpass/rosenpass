use std::{borrow::BorrowMut, marker::PhantomData};

use rosenpass_lenses::LenseView;

use crate::{
    api::msgs::{self, EnvelopeExt, SetPskRequestExt, SetPskResponseExt},
    WireGuardBroker,
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

fn io_pollerr<RecvError>(e: RecvError) -> BrokerClientPollResponseError<RecvError> {
    BrokerClientPollResponseError::<RecvError>::IoError(e)
}

fn invalid_msg_pollerr<RecvError>() -> BrokerClientPollResponseError<RecvError> {
    BrokerClientPollResponseError::<RecvError>::InvalidMessage
}

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum BrokerClientSetPskError<SendError> {
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
pub struct BrokerClient<'a, Io, IoRef>
where
    Io: BrokerClientIo,
    IoRef: 'a + BorrowMut<Io>,
{
    io: IoRef,
    _phantom_io: PhantomData<&'a mut Io>,
}

impl<'a, Io, IoRef> BrokerClient<'a, Io, IoRef>
where
    Io: BrokerClientIo,
    IoRef: 'a + BorrowMut<Io>,
{
    pub fn new(io: IoRef) -> Self {
        Self {
            io,
            _phantom_io: PhantomData,
        }
    }

    pub fn io(&self) -> &IoRef {
        &self.io
    }

    pub fn io_mut(&mut self) -> &mut IoRef {
        &mut self.io
    }

    pub fn poll_response(
        &mut self,
    ) -> Result<Option<msgs::SetPskResult>, BrokerClientPollResponseError<Io::RecvError>> {
        let res: &[u8] = match self.io.borrow_mut().recv_msg().map_err(io_pollerr)? {
            Some(r) => r,
            None => return Ok(None),
        };

        let typ = res.get(0).ok_or(invalid_msg_pollerr())?;
        let typ = msgs::MsgType::try_from(*typ)?;
        let msgs::MsgType::SetPsk = typ; // Assert type

        let res: msgs::Envelope<_, msgs::SetPskResponse<&[u8]>> = res
            .envelope_truncating()
            .map_err(|_| invalid_msg_pollerr())?;
        let res: msgs::SetPskResponse<&[u8]> = res
            .payload()
            .set_psk_response()
            .map_err(|_| invalid_msg_pollerr())?;
        let res: msgs::SetPskResponseReturnCode = res.return_code()[0]
            .try_into()
            .map_err(|_| invalid_msg_pollerr())?;
        let res: msgs::SetPskResult = res.into();

        Ok(Some(res))
    }
}

impl<'a, Io, IoRef> WireGuardBroker for BrokerClient<'a, Io, IoRef>
where
    Io: BrokerClientIo,
    IoRef: 'a + BorrowMut<Io>,
{
    type Error = BrokerClientSetPskError<Io::SendError>;

    fn set_psk(
        &mut self,
        iface: &str,
        peer_id: [u8; 32],
        psk: [u8; 32],
    ) -> Result<(), Self::Error> {
        use BrokerClientSetPskError::*;
        const BUF_SIZE: usize = <msgs::Envelope<(), msgs::SetPskRequest<()>> as LenseView>::LEN;

        // Allocate message
        let mut req = [0u8; BUF_SIZE];

        // Construct message view
        let mut req: msgs::Envelope<_, msgs::SetPskRequest<&mut [u8]>> =
            (&mut req as &mut [u8]).envelope_truncating().unwrap();

        // Populate envelope
        req.msg_type_mut()
            .copy_from_slice(&[msgs::MsgType::SetPsk as u8]);
        {
            // Derived payload
            let mut req: msgs::SetPskRequest<&mut [u8]> =
                req.payload_mut().set_psk_request().unwrap();

            // Populate payload
            req.peer_id_mut().copy_from_slice(&peer_id);
            req.psk_mut().copy_from_slice(&psk);
            req.set_iface(iface).ok_or(IfaceOutOfBounds)?;
        }

        // Send message
        self.io
            .borrow_mut()
            .send_msg(req.all_bytes())
            .map_err(IoError)?;

        Ok(())
    }
}
