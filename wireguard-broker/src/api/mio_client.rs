use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};

use anyhow::{bail, ensure};

use crate::WireGuardBroker;

use super::client::{
    BrokerClient, BrokerClientIo, BrokerClientPollResponseError, BrokerClientSetPskError,
};
use super::msgs;

#[derive(Debug)]
pub struct MioBrokerClient {
    inner: BrokerClient<'static, MioBrokerClientIo, MioBrokerClientIo>,
}

#[derive(Debug)]
struct MioBrokerClientIo {
    socket: mio::net::UnixStream,
    send_buf: VecDeque<u8>,
    receiving_size: bool,
    recv_buf: Vec<u8>,
    recv_off: usize,
}

impl MioBrokerClient {
    pub fn new(socket: mio::net::UnixStream) -> Self {
        let io = MioBrokerClientIo {
            socket,
            send_buf: VecDeque::new(),
            receiving_size: false,
            recv_buf: Vec::new(),
            recv_off: 0,
        };
        let inner = BrokerClient::new(io);
        Self { inner }
    }

    pub fn poll(&mut self) -> anyhow::Result<Option<msgs::SetPskResult>> {
        self.inner.io_mut().flush()?;

        // This sucks
        match self.inner.poll_response() {
            Ok(res) => {
                return Ok(res);
            }
            Err(BrokerClientPollResponseError::IoError(e)) => {
                return Err(e);
            }
            Err(BrokerClientPollResponseError::InvalidMessage) => {
                bail!("Invalid message");
            }
        };
    }
}

impl WireGuardBroker for MioBrokerClient {
    type Error = anyhow::Error;

    fn set_psk(&mut self, iface: &str, peer_id: [u8; 32], psk: [u8; 32]) -> anyhow::Result<()> {
        use BrokerClientSetPskError::*;
        let e = self.inner.set_psk(iface, peer_id, psk);
        match e {
            Ok(()) => Ok(()),
            Err(IoError(e)) => Err(e),
            Err(IfaceOutOfBounds) => bail!("Interface name size is out of bounds."),
            Err(MsgError) => bail!("Error with encoding/decoding message."),
        }
    }
}

impl BrokerClientIo for MioBrokerClientIo {
    type SendError = anyhow::Error;
    type RecvError = anyhow::Error;

    fn send_msg(&mut self, buf: &[u8]) -> Result<(), Self::SendError> {
        self.flush()?;
        self.send_or_buffer(&(buf.len() as u64).to_le_bytes())?;
        self.send_or_buffer(&buf)?;
        self.flush()?;

        Ok(())
    }

    fn recv_msg(&mut self) -> Result<Option<&[u8]>, Self::RecvError> {
        // Stale message in receive buffer. Reset!
        if self.recv_off == self.recv_buf.len() {
            self.receiving_size = true;
            self.recv_off = 0;
            self.recv_buf.resize(8, 0);
        }

        // Try filling the receive buffer
        self.recv_off += raw_recv(&self.socket, &mut self.recv_buf[self.recv_off..])?;
        if self.recv_off < self.recv_buf.len() {
            return Ok(None);
        }

        // Received size, now start receiving
        if self.receiving_size {
            // Received the size
            // Parse the received length
            let len: &[u8; 8] = self.recv_buf[..].try_into().unwrap();
            let len: usize = u64::from_le_bytes(*len) as usize;

            ensure!(
                len <= msgs::RESPONSE_MSG_BUFFER_SIZE,
                "Oversized buffer ({len}) in psk buffer response."
            );

            // Prepare the message buffer for receiving an actual message of the given size
            self.receiving_size = false;
            self.recv_off = 0;
            self.recv_buf.resize(len, 0);

            // Try to receive the message
            return self.recv_msg();
        }

        // Received an actual message
        return Ok(Some(&self.recv_buf[..]));
    }
}

impl MioBrokerClientIo {
    fn flush(&mut self) -> anyhow::Result<()> {
        let (fst, snd) = self.send_buf.as_slices();

        let (written, res) = match raw_send(&self.socket, fst) {
            Ok(w1) if w1 >= fst.len() => match raw_send(&self.socket, snd) {
                Ok(w2) => (w1 + w2, Ok(())),
                Err(e) => (w1, Err(e)),
            },
            Ok(w1) => (w1, Ok(())),
            Err(e) => (0, Err(e)),
        };

        self.send_buf.drain(..written);

        (&self.socket).try_io(|| (&self.socket).flush())?;

        res
    }

    fn send_or_buffer(&mut self, buf: &[u8]) -> anyhow::Result<()> {
        let mut off = 0;

        if self.send_buf.is_empty() {
            off += raw_send(&self.socket, buf)?;
        }

        self.send_buf.extend((&buf[off..]).iter());

        Ok(())
    }
}

fn raw_send(mut socket: &mio::net::UnixStream, data: &[u8]) -> anyhow::Result<usize> {
    let mut off = 0;

    socket.try_io(|| {
        loop {
            if off == data.len() {
                return Ok(());
            }
            match socket.write(&data[off..]) {
                Ok(n) => {
                    off += n;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {
                    // pass – retry
                }
                Err(e) if off > 0 || e.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    })?;

    return Ok(off);
}

fn raw_recv(mut socket: &mio::net::UnixStream, out: &mut [u8]) -> anyhow::Result<usize> {
    let mut off = 0;

    socket.try_io(|| {
        loop {
            if off == out.len() {
                return Ok(());
            }
            match socket.read(&mut out[off..]) {
                Ok(n) => {
                    off += n;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {
                    // pass – retry
                }
                Err(e) if off > 0 || e.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    })?;

    return Ok(off);
}
