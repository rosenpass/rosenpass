use std::io;

use mio::net::{UnixListener, UnixStream};

use rosenpass_util::{io::nonblocking_handle_io_errors, mio::interest::RW as MIO_RW};

use crate::{app_server::MioTokenDispenser, protocol::CryptoServer};

use super::MioConnection;

#[derive(Default, Debug)]
pub struct MioManager {
    listeners: Vec<UnixListener>,
    connections: Vec<MioConnection>,
}

impl MioManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_listener(
        &mut self,
        mut listener: UnixListener,
        registry: &mio::Registry,
        token_dispenser: &mut MioTokenDispenser,
    ) -> io::Result<()> {
        registry.register(&mut listener, token_dispenser.dispense(), MIO_RW)?;
        self.listeners.push(listener);
        Ok(())
    }

    pub fn add_connection(
        &mut self,
        connection: UnixStream,
        registry: &mio::Registry,
        token_dispenser: &mut MioTokenDispenser,
    ) -> io::Result<()> {
        let connection = MioConnection::new(connection, registry, token_dispenser)?;
        self.connections.push(connection);
        Ok(())
    }

    pub fn poll(
        &mut self,
        crypto: &mut Option<CryptoServer>,
        registry: &mio::Registry,
        token_dispenser: &mut MioTokenDispenser,
    ) -> anyhow::Result<()> {
        self.accept_connections(registry, token_dispenser)?;
        self.poll_connections(crypto)?;
        Ok(())
    }

    fn accept_connections(
        &mut self,
        registry: &mio::Registry,
        token_dispenser: &mut MioTokenDispenser,
    ) -> io::Result<()> {
        for idx in 0..self.listeners.len() {
            self.accept_from(idx, registry, token_dispenser)?;
        }
        Ok(())
    }

    fn accept_from(
        &mut self,
        idx: usize,
        registry: &mio::Registry,
        token_dispenser: &mut MioTokenDispenser,
    ) -> io::Result<()> {
        // Accept connection until the socket would block or returns another error
        loop {
            match nonblocking_handle_io_errors(|| self.listeners[idx].accept())? {
                None => break,
                Some((conn, _addr)) => {
                    self.add_connection(conn, registry, token_dispenser)?;
                }
            };
        }

        Ok(())
    }

    fn poll_connections(&mut self, crypto: &mut Option<CryptoServer>) -> anyhow::Result<()> {
        for conn in self.connections.iter_mut() {
            conn.poll(crypto)?
        }
        Ok(())
    }
}
