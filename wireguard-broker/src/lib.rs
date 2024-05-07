#[cfg(feature = "enable_broker")]
use std::result::Result;

#[cfg(feature = "enable_broker")]
pub trait WireGuardBroker {
    type Error;

    fn set_psk(
        &mut self,
        interface: &str,
        peer_id: [u8; 32],
        psk: [u8; 32],
    ) -> Result<(), Self::Error>;
}

#[cfg(feature = "enable_broker")]
pub mod api;
#[cfg(feature = "enable_broker")]
pub mod netlink;
