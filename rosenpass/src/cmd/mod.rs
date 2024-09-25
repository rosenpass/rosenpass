use crate::app_server::AppServerTest;
use crate::event_loop::BrokerInterface;

pub mod exchange;
pub mod exchangeconfig;
pub mod genconfig;
pub mod genkeys;
pub mod keygen;
pub mod man;
pub mod validate;

pub trait Command {
    fn run(
        self,
        broker_interface: Option<BrokerInterface>,
        test_helpers: Option<AppServerTest>,
    ) -> anyhow::Result<()>;
}
