use std::{
    borrow::{Borrow, BorrowMut},
    io,
};

use mio::net::{UnixListener, UnixStream};

use rosenpass_util::{io::nonblocking_handle_io_errors, mio::interest::RW as MIO_RW};

use crate::app_server::AppServer;

use super::{MioConnection, MioConnectionContext};

#[derive(Default, Debug)]
pub struct MioManager {
    listeners: Vec<UnixListener>,
    connections: Vec<MioConnection>,
}

impl MioManager {
    pub fn new() -> Self {
        Self::default()
    }
}

struct MioConnectionFocus<'a, T: ?Sized + MioManagerContext> {
    ctx: &'a mut T,
    conn_idx: usize,
}

impl<'a, T: ?Sized + MioManagerContext> MioConnectionFocus<'a, T> {
    fn new(ctx: &'a mut T, conn_idx: usize) -> Self {
        Self { ctx, conn_idx }
    }
}

pub trait MioManagerContext {
    fn mio_manager(&self) -> &MioManager;
    fn mio_manager_mut(&mut self) -> &mut MioManager;
    fn app_server(&self) -> &AppServer;
    fn app_server_mut(&mut self) -> &mut AppServer;

    fn add_listener(&mut self, mut listener: UnixListener) -> io::Result<()> {
        let srv = self.app_server_mut();
        srv.mio_poll.registry().register(
            &mut listener,
            srv.mio_token_dispenser.dispense(),
            MIO_RW,
        )?;
        self.mio_manager_mut().listeners.push(listener);
        Ok(())
    }

    fn add_connection(&mut self, connection: UnixStream) -> io::Result<()> {
        let connection = MioConnection::new(self.app_server_mut(), connection)?;
        self.mio_manager_mut().connections.push(connection);
        Ok(())
    }

    fn poll(&mut self) -> anyhow::Result<()> {
        self.accept_connections()?;
        self.poll_connections()?;
        Ok(())
    }

    fn accept_connections(&mut self) -> io::Result<()> {
        for idx in 0..self.mio_manager_mut().listeners.len() {
            self.accept_from(idx)?;
        }
        Ok(())
    }

    fn accept_from(&mut self, idx: usize) -> io::Result<()> {
        // Accept connection until the socket would block or returns another error
        // TODO: This currently only adds connections--we eventually need the ability to remove
        // them as well, see the note in connection.rs
        loop {
            match nonblocking_handle_io_errors(|| self.mio_manager().listeners[idx].accept())? {
                None => break,
                Some((conn, _addr)) => {
                    self.add_connection(conn)?;
                }
            };
        }

        Ok(())
    }

    fn poll_connections(&mut self) -> anyhow::Result<()> {
        for idx in 0..self.mio_manager().connections.len() {
            let mut foc: MioConnectionFocus<Self> = MioConnectionFocus::new(self, idx);
            foc.poll()?;
        }
        Ok(())
    }
}

impl<T: ?Sized + MioManagerContext> MioConnectionContext for MioConnectionFocus<'_, T> {
    fn mio_connection(&self) -> &MioConnection {
        self.ctx.mio_manager().connections[self.conn_idx].borrow()
    }

    fn app_server(&self) -> &AppServer {
        self.ctx.app_server()
    }

    fn mio_connection_mut(&mut self) -> &mut MioConnection {
        self.ctx.mio_manager_mut().connections[self.conn_idx].borrow_mut()
    }

    fn app_server_mut(&mut self) -> &mut AppServer {
        self.ctx.app_server_mut()
    }
}
