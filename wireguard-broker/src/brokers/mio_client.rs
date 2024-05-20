use anyhow::{bail, ensure};
use mio::Interest;
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};

use crate::{SerializedBrokerConfig, WireGuardBroker, WireguardBrokerMio};

use crate::api::client::{
    BrokerClient, BrokerClientIo, BrokerClientPollResponseError, BrokerClientSetPskError,
};
use crate::api::msgs::{self, RESPONSE_MSG_BUFFER_SIZE};

#[derive(Debug)]
pub struct MioBrokerClient {
    inner: BrokerClient<MioBrokerClientIo>,
}

const LEN_SIZE: usize = 8;
const RECV_BUF_SIZE: usize = RESPONSE_MSG_BUFFER_SIZE;

#[derive(Debug)]
struct MioBrokerClientIo {
    socket: mio::net::UnixStream,
    send_buf: VecDeque<u8>,
    recv_state: RxState,
    expected_state: RxState,
    recv_buf: [u8; RECV_BUF_SIZE],
}

#[derive(Debug, Clone, Copy)]
enum RxState {
    //Recieving size with buffer offset
    RxSize(usize),
    RxBuffer(usize),
}

impl MioBrokerClient {
    pub fn new(socket: mio::net::UnixStream) -> Self {
        let io = MioBrokerClientIo {
            socket,
            send_buf: VecDeque::new(),
            recv_state: RxState::RxSize(0),
            recv_buf: [0u8; RECV_BUF_SIZE],
            expected_state: RxState::RxSize(LEN_SIZE),
        };
        let inner = BrokerClient::new(io);
        Self { inner }
    }

    fn poll(&mut self) -> anyhow::Result<Option<msgs::SetPskResult>> {
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

    fn set_psk<'a>(&mut self, config: SerializedBrokerConfig<'a>) -> anyhow::Result<()> {
        use BrokerClientSetPskError::*;
        let e = self.inner.set_psk(config);
        match e {
            Ok(()) => Ok(()),
            Err(IoError(e)) => Err(e),
            Err(IfaceOutOfBounds) => bail!("Interface name size is out of bounds."),
            Err(MsgError) => bail!("Error with encoding/decoding message."),
            Err(BrokerError(e)) => bail!("Broker error: {:?}", e),
        }
    }
}

impl WireguardBrokerMio for MioBrokerClient {
    type MioError = anyhow::Error;

    fn register(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
    ) -> Result<(), Self::MioError> {
        registry.register(
            &mut self.inner.io_mut().socket,
            token,
            Interest::READABLE | Interest::WRITABLE,
        )?;
        Ok(())
    }

    fn process_poll(&mut self) -> Result<(), Self::MioError> {
        self.poll()?;
        Ok(())
    }

    fn unregister(&mut self, registry: &mio::Registry) -> Result<(), Self::MioError> {
        registry.deregister(&mut self.inner.io_mut().socket)?;
        Ok(())
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
        loop {
            match (self.recv_state, self.expected_state) {
                //Stale Buffer state or recieved everything
                (RxState::RxSize(x), RxState::RxSize(y))
                | (RxState::RxBuffer(x), RxState::RxBuffer(y))
                    if x == y =>
                {
                    match self.recv_state {
                        RxState::RxSize(s) => {
                            let len: &[u8; LEN_SIZE] = self.recv_buf[0..s].try_into().unwrap();
                            let len: usize = u64::from_le_bytes(*len) as usize;

                            ensure!(
                                len <= msgs::RESPONSE_MSG_BUFFER_SIZE,
                                "Oversized buffer ({len}) in psk buffer response."
                            );

                            self.recv_state = RxState::RxBuffer(0);
                            self.expected_state = RxState::RxBuffer(len);
                            continue;
                        }
                        RxState::RxBuffer(s) => {
                            self.recv_state = RxState::RxSize(0);
                            self.expected_state = RxState::RxSize(LEN_SIZE);
                            return Ok(Some(&self.recv_buf[0..s]));
                        }
                    }
                }

                //Recieve if x < y
                (RxState::RxSize(x), RxState::RxSize(y))
                | (RxState::RxBuffer(x), RxState::RxBuffer(y))
                    if x < y =>
                {
                    let bytes = raw_recv(&self.socket, &mut self.recv_buf[x..y])?;

                    if x + bytes == y {
                        return Ok(Some(&self.recv_buf[0..y]));
                    }
                    //We didn't recieve everything so let's assume something went wrong
                    self.recv_state = RxState::RxSize(0);
                    self.expected_state = RxState::RxSize(LEN_SIZE);
                    bail!("Invalid state");
                }
                _ => {
                    //Reset states
                    self.recv_state = RxState::RxSize(0);
                    self.expected_state = RxState::RxSize(LEN_SIZE);
                    bail!("Invalid state");
                }
            };
        }
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
