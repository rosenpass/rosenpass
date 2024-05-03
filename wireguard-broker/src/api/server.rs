use std::borrow::BorrowMut;
use std::marker::PhantomData;
use std::result::Result;

use crate::api::msgs::{self, Envelope, SetPskRequest, SetPskResponse};
use crate::WireGuardBroker;

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum BrokerServerError {
    #[error("No such request type: {}", .0)]
    NoSuchRequestType(u8),
    #[error("Invalid message received.")]
    InvalidMessage,
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
        let r: Result<(), Err> = self.inner.borrow_mut().set_psk(
            req.iface()
                .map_err(|_e| BrokerServerError::InvalidMessage)?,
            req.peer_id.try_into().unwrap(),
            req.psk.try_into().unwrap(),
        );
        let r: msgs::SetPskResult = r.map_err(|e| e.into());
        let r: msgs::SetPskResponseReturnCode = r.into();
        res.return_code = r as u8;

        Ok(())
    }
}
