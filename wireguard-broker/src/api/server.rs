use std::borrow::BorrowMut;
use std::marker::PhantomData;
use std::result::Result;

use rosenpass_lenses::LenseError;

use crate::api::msgs::{self, EnvelopeExt, SetPskRequestExt, SetPskResponseExt};
use crate::WireGuardBroker;

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum BrokerServerError {
    #[error("No such request type: {}", .0)]
    NoSuchRequestType(u8),
    #[error("Invalid message received.")]
    InvalidMessage,
}

impl From<LenseError> for BrokerServerError {
    fn from(value: LenseError) -> Self {
        use BrokerServerError as Be;
        use LenseError as Le;
        match value {
            Le::BufferSizeMismatch => Be::InvalidMessage,
        }
    }
}

impl From<msgs::InvalidMessageTypeError> for BrokerServerError {
    fn from(value: msgs::InvalidMessageTypeError) -> Self {
        let msgs::InvalidMessageTypeError = value; // Assert that this is a unit type
        BrokerServerError::InvalidMessage
    }
}

pub struct BrokerServer<'a, Err, Inner, Ref>
where
    msgs::SetPskError: From<Err>,
    Inner: WireGuardBroker<Error = Err>,
    Ref: BorrowMut<Inner> + 'a,
{
    inner: Ref,
    _phantom: PhantomData<&'a mut Inner>,
}

impl<'a, Err, Inner, Ref> BrokerServer<'a, Err, Inner, Ref>
where
    msgs::SetPskError: From<Err>,
    Inner: WireGuardBroker<Error = Err>,
    Ref: 'a + BorrowMut<Inner>,
{
    pub fn new(inner: Ref) -> Self {
        Self {
            inner,
            _phantom: PhantomData,
        }
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

        let req: msgs::Envelope<_, msgs::SetPskRequest<&[u8]>> = req.envelope_truncating()?;
        let mut res: msgs::Envelope<_, msgs::SetPskResponse<&mut [u8]>> =
            (res as &mut [u8]).envelope_truncating()?;
        (&mut res).msg_type_mut()[0] = msgs::MsgType::SetPsk as u8;
        self.handle_set_psk(
            req.payload().set_psk_request()?,
            res.payload_mut().set_psk_response()?,
        )?;
        Ok(res.all_bytes().len())
    }

    fn handle_set_psk(
        &mut self,
        req: msgs::SetPskRequest<&[u8]>,
        mut res: msgs::SetPskResponse<&mut [u8]>,
    ) -> Result<(), BrokerServerError> {
        // Using unwrap here since lenses can not return fixed-size arrays
        // TODO: Slices should give access to fixed size arrays
        let r: Result<(), Err> = self.inner.borrow_mut().set_psk(
            req.iface()
                .map_err(|_e| BrokerServerError::InvalidMessage)?,
            req.peer_id().try_into().unwrap(),
            req.psk().try_into().unwrap(),
        );
        let r: msgs::SetPskResult = r.map_err(|e| e.into());
        let r: msgs::SetPskResponseReturnCode = r.into();
        res.return_code_mut()[0] = r as u8;

        Ok(())
    }
}
