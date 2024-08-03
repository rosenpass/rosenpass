use rosenpass_to::{ops::copy_slice, To};

use crate::protocol::CryptoServer;

use super::Server as ApiServer;

#[derive(Debug)]
pub struct CryptoServerApiState {
    _dummy: (),
}

impl CryptoServerApiState {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self { _dummy: () }
    }

    pub fn acquire_backend<'a>(
        &'a mut self,
        crypto: &'a mut Option<CryptoServer>,
    ) -> CryptoServerApiHandler<'a> {
        let state = self;
        CryptoServerApiHandler { state, crypto }
    }
}

pub struct CryptoServerApiHandler<'a> {
    #[allow(unused)] // TODO: Remove
    crypto: &'a mut Option<CryptoServer>,
    #[allow(unused)] // TODO: Remove
    state: &'a mut CryptoServerApiState,
}

impl<'a> ApiServer for CryptoServerApiHandler<'a> {
    fn ping(
        &mut self,
        req: &super::PingRequest,
        res: &mut super::PingResponse,
    ) -> anyhow::Result<()> {
        let (req, res) = (&req.payload, &mut res.payload);
        copy_slice(&req.echo).to(&mut res.echo);
        Ok(())
    }
}
