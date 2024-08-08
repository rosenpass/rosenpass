use rosenpass_to::{ops::copy_slice, To};

use crate::app_server::AppServer;

use super::Server as ApiServer;

#[derive(Debug)]
pub struct ApiHandler {
    _dummy: (),
}

impl ApiHandler {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self { _dummy: () }
    }
}

pub trait ApiHandlerContext {
    fn api_handler(&self) -> &ApiHandler;
    fn app_server(&self) -> &AppServer;
    fn api_handler_mut(&mut self) -> &mut ApiHandler;
    fn app_server_mut(&mut self) -> &mut AppServer;
}

impl<T> ApiServer for T
where
    T: ?Sized + ApiHandlerContext,
{
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
