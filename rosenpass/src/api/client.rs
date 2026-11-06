//! Synchronous API client, supporting every API endpoint including the
//! upgrade to the shared-memory transport.

use std::{
    os::{
        fd::{AsFd, BorrowedFd},
        unix::net::UnixStream,
    },
    path::Path,
};

use anyhow::bail;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::{
    AddListenSocketRequest, AddListenSocketResponse, AddPskBrokerRequest, AddPskBrokerResponse,
    PingRequest, PingResponse, SupplyKeypairRequest, SupplyKeypairResponse,
    UpgradeTransportRequest, UpgradeTransportResponse, add_listen_socket_response_status,
    add_psk_broker_response_status, supply_keypair_response_status,
    upgrade_transport_response_status,
};
use crate::internal::util::{
    io::fd_stream::FdStreamWriter,
    ipc::shm::stream::{SyncFdStream, upgrade_unix_socket::UpgradableSocket},
    length_prefix_encoding::{decoder::LengthPrefixDecoder, encoder::LengthPrefixEncoder},
};

/// A connection to the Rosenpass API
#[derive(Debug)]
pub struct ApiClient {
    io: Socket,
}

type Socket = UpgradableSocket<UnixStream, SyncFdStream>;

impl ApiClient {
    /// Connect to the API socket at `path`
    pub fn connect(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let io = Socket::new(UnixStream::connect(path)?);
        Ok(Self { io })
    }

    /// Send one request, with `fds` attached, and receive its response
    pub fn call<Req, Res>(&mut self, request: Req, fds: &[BorrowedFd]) -> anyhow::Result<Res>
    where
        Req: IntoBytes + Immutable,
        Res: FromBytes + IntoBytes,
    {
        LengthPrefixEncoder::from_message(request.as_bytes())
            .write_all_to_stdio(FdStreamWriter::new(&mut self.io, fds))?;

        let mut response = Res::new_zeroed();
        let response_len = LengthPrefixDecoder::new(response.as_mut_bytes())
            .read_all_from_stdio(&mut self.io)?
            .len();
        if response_len != size_of::<Res>() {
            bail!("API response has invalid length {response_len}");
        }
        Ok(response)
    }

    /// Ping endpoint; returns the echoed bytes
    pub fn ping(&mut self, echo: [u8; 256]) -> anyhow::Result<[u8; 256]> {
        let response: PingResponse = self.call(PingRequest::new(echo), &[])?;
        Ok(response.payload.echo)
    }

    /// SupplyKeypair endpoint
    pub fn supply_keypair(
        &mut self,
        secret_key: impl AsFd,
        public_key: impl AsFd,
    ) -> anyhow::Result<()> {
        use supply_keypair_response_status as status;
        let fds = [secret_key.as_fd(), public_key.as_fd()];
        let response: SupplyKeypairResponse = self.call(SupplyKeypairRequest::new(), &fds)?;
        match response.payload.status {
            status::OK => Ok(()),
            status::KEYPAIR_ALREADY_SUPPLIED => bail!("Server already has a keypair"),
            status::INVALID_REQUEST => bail!("Server rejected the keypair as invalid"),
            status::INTERNAL_ERROR => bail!("Server failed internally while loading the keypair"),
            status::IO_ERROR => bail!("Server failed to read the keypair"),
            other => bail!("SupplyKeypair failed with unknown status {other}"),
        }
    }

    /// AddListenSocket endpoint
    pub fn add_listen_socket(&mut self, socket: impl AsFd) -> anyhow::Result<()> {
        use add_listen_socket_response_status as status;
        let response: AddListenSocketResponse =
            self.call(AddListenSocketRequest::new(), &[socket.as_fd()])?;
        match response.payload.status {
            status::OK => Ok(()),
            status::INVALID_REQUEST => bail!("Server rejected the listen socket as invalid"),
            status::INTERNAL_ERROR => {
                bail!("Server failed internally while adding the listen socket")
            }
            other => bail!("AddListenSocket failed with unknown status {other}"),
        }
    }

    /// AddPskBroker endpoint
    pub fn add_psk_broker(&mut self, socket: impl AsFd) -> anyhow::Result<()> {
        use add_psk_broker_response_status as status;
        let response: AddPskBrokerResponse =
            self.call(AddPskBrokerRequest::new(), &[socket.as_fd()])?;
        match response.payload.status {
            status::OK => Ok(()),
            status::INVALID_REQUEST => bail!("Server rejected the PSK broker socket as invalid"),
            status::INTERNAL_ERROR => bail!("Server failed internally while adding the PSK broker"),
            other => bail!("AddPskBroker failed with unknown status {other}"),
        }
    }

    /// UpgradeTransport endpoint; switches this connection to the
    /// shared-memory transport. If the server refuses, the connection keeps
    /// using the current transport.
    pub fn upgrade_transport(&mut self, buffer_size: usize) -> anyhow::Result<()> {
        use upgrade_transport_response_status as status;
        let request = self.io.prepare_upgrade_request(buffer_size)?;
        let fds = [request.buffer_fd.as_fd(), request.srv_send_nsock_fd.as_fd()];
        let response: UpgradeTransportResponse = self.call(UpgradeTransportRequest::new(), &fds)?;
        match response.payload.status {
            status::OK => self.io.finalize_upgrade(),
            status::INVALID_REQUEST => bail!("Server rejected the transport upgrade as invalid"),
            status::INTERNAL_ERROR => {
                bail!("Server failed internally during the transport upgrade")
            }
            other => bail!("UpgradeTransport failed with unknown status {other}"),
        }
    }
}
