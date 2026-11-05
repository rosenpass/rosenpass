use std::{
    borrow::{Borrow, BorrowMut},
    collections::VecDeque,
    os::fd::{AsFd, AsRawFd, OwnedFd},
};

use mio::{event::Source, unix::SourceFd};

use crate::internal::util::{
    functional::ApplyExt,
    io::fd_stream::{FdPassingStream, FdStreamReader, FdStreamWriter, ReadWithFdsResult},
    ipc::shm::stream::{
        MioFdStream, ShmStreamError, SyncFdStream,
        mio::ShmStreamCreationError,
        upgrade_unix_socket::{
            UpgradePendingClient, UpgradePendingServer, UpgradeToShmStream,
            UpgradeToShmStreamRequest,
        },
    },
    rustix::GetSocketConnectedness,
};

#[derive(Debug, derive_more::Constructor)]
struct BeforeUpgrade<BeforeUpgradeStream> {
    socket: BeforeUpgradeStream,
}

#[derive(Debug, derive_more::Constructor)]
struct DuringUpgradeClient<BeforeUpgradeStream> {
    socket: BeforeUpgradeStream,
    pending: UpgradePendingClient,
}

#[derive(Debug, derive_more::Constructor)]
struct DuringUpgradeServer<BeforeUpgradeStream> {
    socket: BeforeUpgradeStream,
    pending: UpgradePendingServer,
}

#[derive(Debug, derive_more::Constructor)]
struct AfterUpgrade<AfterUpgradeStream> {
    stream: AfterUpgradeStream,
}

#[derive(
    Debug,
    derive_more::IsVariant,
    derive_more::TryUnwrap,
    strum::EnumDiscriminants,
    derive_more::From,
)]
#[try_unwrap(owned, ref, ref_mut)]
enum UpgradeState<BeforeUpgradeStream, AfterUpgradeStream> {
    BeforeUpgrade(BeforeUpgrade<BeforeUpgradeStream>),
    DuringUpgradeClient(DuringUpgradeClient<BeforeUpgradeStream>),
    DuringUpgradeServer(DuringUpgradeServer<BeforeUpgradeStream>),
    AfterUpgrade(AfterUpgrade<AfterUpgradeStream>),
}

/// A Unix stream socket that can be upgraded in place to the shared-memory stream
#[derive(Debug)]
pub struct UpgradableSocket<BeforeUpgradeStream, AfterUpgradeStream> {
    state: Option<UpgradeState<BeforeUpgradeStream, AfterUpgradeStream>>, // The option is just there so we can take the value briefly
}

impl UpgradableSocket<std::os::unix::net::UnixStream, SyncFdStream> {
    /// Wrap a not yet upgraded socket
    pub fn new(sock: std::os::unix::net::UnixStream) -> Self {
        Self::new_impl(sock)
    }

    /// Switch to the shared-memory stream once the server accepted the pending upgrade
    pub fn finalize_upgrade(&mut self) -> anyhow::Result<()> {
        self.ensure_upgrade_supported()?;
        let after = self
            .finalize_upgrade_impl()?
            .apply(SyncFdStream::from_mio_fd_stream)?;
        self.state = Some(AfterUpgrade::new(after).into());
        Ok(())
    }

    /// Shut down the socket or, once upgraded, the stream in the given direction
    #[allow(dead_code)] // kept on human request (unused for now)
    pub fn shutdown(&mut self, direction: std::net::Shutdown) -> std::io::Result<()> {
        match self.upgraded_stream_mut() {
            Ok(stream) => stream.shutdown(direction),
            Err(sock) => sock.shutdown(direction),
        }
    }
}

impl UpgradableSocket<mio::net::UnixStream, MioFdStream> {
    /// Wrap a not yet upgraded socket
    pub fn new(sock: mio::net::UnixStream) -> Self {
        Self::new_impl(sock)
    }

    /// Finalize the pending upgrade and register the notification socket with `registry`
    pub fn finalize_upgrade_and_update_mio_registry(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> anyhow::Result<()> {
        self.ensure_upgrade_supported()?;
        self.ensure_upgrading()?;
        let notification_fd = self
            .second_notification_socket_during_update_mut()
            .unwrap()
            .as_raw_fd();
        SourceFd(&notification_fd).register(registry, token, interests)?;
        let outcome = self.finalize_upgrade_without_updating_mio_registry();
        if outcome.is_err() {
            let _ = SourceFd(&notification_fd).deregister(registry);
        }
        outcome
    }

    /// Finalize the pending upgrade without touching any mio registration
    pub fn finalize_upgrade_without_updating_mio_registry(&mut self) -> anyhow::Result<()> {
        self.ensure_upgrade_supported()?;
        let after = self.finalize_upgrade_impl()?;
        self.state = Some(AfterUpgrade::new(after).into());
        Ok(())
    }

    /// Shut down the socket or, once upgraded, the stream in the given direction
    #[allow(dead_code)] // kept on human request (unused for now)
    pub fn shutdown(&mut self, direction: std::net::Shutdown) -> std::io::Result<()> {
        match self.upgraded_stream_mut() {
            Ok(stream) => stream.shutdown(direction),
            Err(sock) => sock.shutdown(direction),
        }
    }
}

impl<BeforeUpgradeStream, AfterUpgradeStream>
    UpgradableSocket<BeforeUpgradeStream, AfterUpgradeStream>
where
    BeforeUpgradeStream: std::fmt::Debug + Into<OwnedFd>,
    AfterUpgradeStream: std::fmt::Debug,
{
    fn new_impl(sock: BeforeUpgradeStream) -> Self {
        let state = Some(BeforeUpgrade::new(sock).into());
        Self { state }
    }

    /// Client: start an upgrade and return the request to send to the server
    pub fn prepare_upgrade_request(
        &mut self,
        buffer_size: usize,
    ) -> anyhow::Result<UpgradeToShmStreamRequest> {
        self.ensure_upgrade_supported()?;
        self.ensure_not_upgraded()?;

        let (pending, req) = UpgradeToShmStream::prepare_upgrade_request(buffer_size)?;

        let sock = self.take_pre_upgrade_stream().unwrap();
        self.state = Some(DuringUpgradeClient::new(sock, pending).into());

        Ok(req)
    }

    /// Server: accept an upgrade request; finalize once the response was sent
    pub fn handle_upgrade_request(
        &mut self,
        request: UpgradeToShmStreamRequest,
    ) -> anyhow::Result<()> {
        self.ensure_upgrade_supported()?;
        self.ensure_not_upgraded()?;
        let pending = UpgradeToShmStream::handle_upgrade_request(request)?;
        let sock = self.take_pre_upgrade_stream().unwrap();
        self.state = Some(DuringUpgradeServer::new(sock, pending).into());
        Ok(())
    }

    /// A client-side upgrade was prepared and is waiting to be finalized.
    #[allow(dead_code)] // kept on human request (unused for now)
    pub fn client_upgrade_in_process(&self) -> bool {
        matches!(self.state, Some(UpgradeState::DuringUpgradeClient(_)))
    }

    /// A server-side upgrade was admitted and is waiting to be finalized.
    pub fn server_upgrade_in_process(&self) -> bool {
        matches!(self.state, Some(UpgradeState::DuringUpgradeServer(_)))
    }

    /// An upgrade, client- or server-side, is in process.
    #[allow(dead_code)] // kept on human request (unused for now)
    pub fn upgrade_in_process(&self) -> bool {
        self.client_upgrade_in_process() || self.server_upgrade_in_process()
    }

    fn finalize_upgrade_impl(&mut self) -> anyhow::Result<MioFdStream>
    where
        BeforeUpgradeStream: AsFd,
    {
        self.ensure_upgrade_supported()?;
        self.ensure_not_upgraded()?;
        self.ensure_upgrading()?;

        use UpgradeState as S;
        // Checked before taking the state so a peer that did not seal or
        // closed its ends leaves the socket usable
        if let Some(S::DuringUpgradeClient(s)) = &self.state {
            s.pending.validate_seals()?;
        }
        let socket = self.pre_upgrade_stream().unwrap().as_fd();
        let notification_socket = self.second_notification_socket_during_update().unwrap();
        for fd in [socket, notification_socket.as_fd()] {
            if !fd.is_connected()? {
                return Err(ShmStreamCreationError::UnconnectedSocket.into());
            }
        }

        match self.state.take().unwrap() {
            S::BeforeUpgrade(_) => unreachable!(),
            S::AfterUpgrade(_) => unreachable!(),
            S::DuringUpgradeClient(s) => s.pending.finalize_upgrade(s.socket.into()),
            S::DuringUpgradeServer(s) => s.pending.finalize_upgrade(s.socket.into()),
        }
    }

    fn ensure_upgrade_supported(&self) -> anyhow::Result<()> {
        cfg_select! {
            target_os = "linux" => Ok(()),
            _ => {
                rustix::io::Errno::NOSYS
                    .apply(anyhow::Error::new)
                    .context("shared-memory transport upgrade is not supported on this platform")
                    .apply(Err)
            },
        }
    }

    fn ensure_not_upgraded(&self) -> anyhow::Result<()> {
        if self.pre_upgrade_stream().is_err() {
            anyhow::bail!("Already upgraded");
        }

        Ok(())
    }

    fn ensure_upgrading(&self) -> anyhow::Result<()> {
        if self.second_notification_socket_during_update().is_none() {
            anyhow::bail!("Not updating");
        }

        Ok(())
    }

    fn take_upgraded_stream(&mut self) -> Result<AfterUpgradeStream, BeforeUpgradeStream> {
        use UpgradeState as S;
        match self.state.take().unwrap() {
            S::BeforeUpgrade(s) => Err(s.socket),
            S::DuringUpgradeClient(s) => Err(s.socket),
            S::DuringUpgradeServer(s) => Err(s.socket),
            S::AfterUpgrade(s) => Ok(s.stream),
        }
    }

    fn upgraded_stream(&self) -> Result<&AfterUpgradeStream, &BeforeUpgradeStream> {
        use UpgradeState as S;
        match self.state.as_ref().unwrap() {
            S::BeforeUpgrade(s) => Err(s.socket.borrow()),
            S::DuringUpgradeClient(s) => Err(s.socket.borrow()),
            S::DuringUpgradeServer(s) => Err(s.socket.borrow()),
            S::AfterUpgrade(s) => Ok(s.stream.borrow()),
        }
    }

    fn upgraded_stream_mut(&mut self) -> Result<&mut AfterUpgradeStream, &mut BeforeUpgradeStream> {
        use UpgradeState as S;
        match self.state.as_mut().unwrap() {
            S::BeforeUpgrade(s) => Err(s.socket.borrow_mut()),
            S::DuringUpgradeClient(s) => Err(s.socket.borrow_mut()),
            S::DuringUpgradeServer(s) => Err(s.socket.borrow_mut()),
            S::AfterUpgrade(s) => Ok(s.stream.borrow_mut()),
        }
    }

    fn take_pre_upgrade_stream(&mut self) -> Result<BeforeUpgradeStream, AfterUpgradeStream> {
        self.take_upgraded_stream().map_or_else(Ok, Err)
    }

    fn pre_upgrade_stream(&self) -> Result<&BeforeUpgradeStream, &AfterUpgradeStream> {
        self.upgraded_stream().map_or_else(Ok, Err)
    }

    fn second_notification_socket_during_update(&self) -> Option<&OwnedFd> {
        use UpgradeState as S;
        match self.state.as_ref().unwrap() {
            S::BeforeUpgrade(_) => None,
            S::DuringUpgradeClient(s) => Some(s.pending.client_recv_nsock_fd.borrow()),
            S::DuringUpgradeServer(s) => Some(s.pending.server_send_nsock_fd.borrow()),
            S::AfterUpgrade(_) => None,
        }
    }

    fn second_notification_socket_during_update_mut(&mut self) -> Option<&mut OwnedFd> {
        use UpgradeState as S;
        match self.state.as_mut().unwrap() {
            S::BeforeUpgrade(_) => None,
            S::DuringUpgradeClient(s) => Some(s.pending.client_recv_nsock_fd.borrow_mut()),
            S::DuringUpgradeServer(s) => Some(s.pending.server_send_nsock_fd.borrow_mut()),
            S::AfterUpgrade(_) => None,
        }
    }
}

impl<BeforeUpgradeStream, AfterUpgradeStream> FdPassingStream
    for UpgradableSocket<BeforeUpgradeStream, AfterUpgradeStream>
where
    BeforeUpgradeStream: FdPassingStream<ReadError = rustix::io::Errno, WriteError = rustix::io::Errno>
        + std::fmt::Debug
        + Into<OwnedFd>,
    AfterUpgradeStream:
        FdPassingStream<ReadError = ShmStreamError, WriteError = ShmStreamError> + std::fmt::Debug,
{
    type ReadError = ShmStreamError;
    type WriteError = ShmStreamError;
    type ReadConfig = ();
    type WriteConfig = ();

    fn read_with_fds_config(
        &mut self,
        dst: &mut [u8],
        max_new_fds: usize,
        _config: (),
    ) -> Result<ReadWithFdsResult, Self::ReadError> {
        match self.upgraded_stream_mut() {
            Ok(stream) => stream.read_with_fds(dst, max_new_fds),
            Err(sock) => sock.read_with_fds(dst, max_new_fds).map_err(|e| e.into()),
        }
    }

    fn write_with_fds_config(
        &mut self,
        src: &[u8],
        fds: &[std::os::fd::BorrowedFd<'_>],
        _config: (),
    ) -> Result<usize, Self::WriteError> {
        match self.upgraded_stream_mut() {
            Ok(stream) => stream.write_with_fds(src, fds),
            Err(sock) => sock.write_with_fds(src, fds).map_err(|e| e.into()),
        }
    }
}

impl<BeforeUpgradeStream, AfterUpgradeStream> std::io::Write
    for UpgradableSocket<BeforeUpgradeStream, AfterUpgradeStream>
where
    BeforeUpgradeStream: FdPassingStream<ReadError = rustix::io::Errno, WriteError = rustix::io::Errno>
        + std::fmt::Debug
        + Into<OwnedFd>,
    AfterUpgradeStream:
        FdPassingStream<ReadError = ShmStreamError, WriteError = ShmStreamError> + std::fmt::Debug,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        FdStreamWriter::new(self, &[]).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<BeforeUpgradeStream, AfterUpgradeStream> std::io::Read
    for UpgradableSocket<BeforeUpgradeStream, AfterUpgradeStream>
where
    BeforeUpgradeStream: FdPassingStream<ReadError = rustix::io::Errno, WriteError = rustix::io::Errno>
        + std::fmt::Debug
        + Into<OwnedFd>,
    AfterUpgradeStream:
        FdPassingStream<ReadError = ShmStreamError, WriteError = ShmStreamError> + std::fmt::Debug,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        FdStreamReader::new(self, &mut VecDeque::new(), 0).read(buf)
    }
}

impl mio::event::Source for UpgradableSocket<mio::net::UnixStream, MioFdStream> {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        match self.upgraded_stream_mut() {
            Ok(stream) => stream.register(registry, token, interests),
            Err(sock) => sock.register(registry, token, interests),
        }
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        match self.upgraded_stream_mut() {
            Ok(stream) => stream.reregister(registry, token, interests),
            Err(sock) => sock.reregister(registry, token, interests),
        }
    }

    fn deregister(&mut self, registry: &mio::Registry) -> std::io::Result<()> {
        match self.upgraded_stream_mut() {
            Ok(stream) => stream.deregister(registry),
            Err(sock) => sock.deregister(registry),
        }
    }
}
