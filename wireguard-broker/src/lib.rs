use std::result::Result;

pub trait WireGuardBroker {
    type Error;

    fn set_psk(
        &mut self,
        interface: &str,
        peer_id: [u8; 32],
        psk: [u8; 32],
    ) -> Result<(), Self::Error>;
}

pub mod api;
