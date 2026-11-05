use std::os::fd::OwnedFd;

use rustix::net::{AddressFamily, SocketFlags, SocketType};

use super::super::mio::{MioFdStream, RingLayout, validate_buffer_geometry};

use crate::internal::util::{
    functional::ApplyExt,
    int::u64uint::U64USize,
    ipc::shm::SharedMemorySegment,
    result::OkExt,
    rustix::{
        DescriptorFlagsExt, FileSealsExt, GetSocketConnectedness, GetUnixSocketType, SealFlags,
        TryStatExt, TryStatFsExt, clone_fd_cloexec,
    },
    secret_memory::{fd::SecretMemfdConfig, mmap::MappingConfig},
};

/// The upgrade-specific objects transmitted client → server: the SCM_RIGHTS
/// payload carried alongside the `UpgradeTransportRequest` envelope.
/// Defines the wire order — buffer, then server-sender notification — in
/// exactly one place.
///
/// Role semantics: the client keeps the receiver end of the notification
/// pair and transmits the sender end inside this request.
#[derive(Debug, derive_more::Constructor)]
pub struct UpgradeToShmStreamRequest {
    /// Backing descriptor of the shared-memory buffer (wire position 0).
    pub buffer_fd: OwnedFd,
    /// Server-sender end of the notification pair (wire position 1); the
    /// client keeps the receiver end.
    pub srv_send_nsock_fd: OwnedFd,
}

impl UpgradeToShmStreamRequest {
    fn into_tuple(self) -> (OwnedFd, OwnedFd) {
        (self.buffer_fd, self.srv_send_nsock_fd)
    }
}

/// Entry namespace for the shared-memory transport upgrade protocol machine.
#[derive(Debug)]
pub enum UpgradeToShmStream {}

/// Client-side upgrade state between sending the request and receiving the answer
#[derive(Debug, derive_more::Constructor)]
pub struct UpgradePendingClient {
    /// The client's mapping of the shared buffer
    pub segment: SharedMemorySegment,
    /// Backing descriptor of the shared buffer, kept to check the server's seals
    pub buffer_fd: OwnedFd,
    /// Receiver end of the notification pair
    pub client_recv_nsock_fd: OwnedFd,
}

/// Server-side upgrade state between accepting the request and sending the answer
#[derive(Debug, derive_more::Constructor)]
pub struct UpgradePendingServer {
    /// The server's mapping of the shared buffer
    pub segment: SharedMemorySegment,
    /// Sender end of the notification pair, received from the client
    pub server_send_nsock_fd: OwnedFd,
}

impl UpgradeToShmStream {
    /// Client: allocate and map a shared buffer of `buffer_size` bytes and build the request
    pub fn prepare_upgrade_request(
        buffer_size: usize,
    ) -> anyhow::Result<(UpgradePendingClient, UpgradeToShmStreamRequest)> {
        validate_buffer_geometry(buffer_size)?;

        // Allocate the shm file descriptor
        let mappable = SecretMemfdConfig::new()
            .used_in_shared_memory()
            .create()?
            .adjust_config(|cfg| {
                cfg.without_future_write_seal()
                    .resize_on_mmap(buffer_size as u64)
            });

        // Map the segment into memory
        let segment = mappable
            .mmap()?
            .apply(|seg| unsafe { SharedMemorySegment::from_mapped_segment(seg) });

        // Discard the mappable
        let buffer_fd = mappable.into_fd().unwrap();

        // SAFETY: this is a fresh, unshared buffer with no mapped references yet.
        unsafe {
            segment.mapped_segment().populate_pages()?;
        }

        // Create the extra notification socket pair we need
        let (client_recv_nsock_fd, srv_send_nsock_fd) = notification_socket_pair()?;

        // Create the upgrade request
        let req = {
            let buffer_fd = clone_fd_cloexec(&buffer_fd)?;
            srv_send_nsock_fd.set_cloexec()?;
            UpgradeToShmStreamRequest::new(buffer_fd, srv_send_nsock_fd)
        };

        // Create the state machine
        let state = UpgradePendingClient::new(segment, buffer_fd, client_recv_nsock_fd);

        Ok((state, req))
    }

    /// Server: validate and map the client's shared buffer and seal it against future writes
    pub fn handle_upgrade_request(
        request: UpgradeToShmStreamRequest,
    ) -> anyhow::Result<UpgradePendingServer> {
        let (buffer_fd, srv_send_nsock_fd) = request.into_tuple();

        // Validate the notification socket before the request is accepted
        srv_send_nsock_fd.demand_unix_stream_socket()?;
        if !srv_send_nsock_fd.is_connected()? {
            anyhow::bail!("Notification socket is not connected");
        }

        // Validate the buffer size
        let buf_len = buffer_fd.size()?.apply(U64USize::try_new)?.u64();
        validate_buffer_geometry(buf_len as usize)?;

        // Wrap FD into a Mappable
        let mappable = MappingConfig::new()
            .set_shared()
            .expected_size(buf_len)
            .mappable(&buffer_fd);

        // Allocated the Mappable
        let segment = mappable
            .mmap()?
            .apply(|seg| unsafe { SharedMemorySegment::from_mapped_segment(seg) });

        // Seal FD against future writes
        mappable.seal_future_write()?;

        // SAFETY: no local readers or Rust references into this mapping exist yet.
        // Mapping validity inherits the allocator's old-host secretmem limitation
        // (no resize protection for secretmem FDs on hosts that permit
        // truncation), rather than an upgrade-specific resize guard.
        unsafe { segment.mapped_segment().populate_pages()? };

        UpgradePendingServer::new(segment, srv_send_nsock_fd).ok()
    }
}

impl UpgradePendingClient {
    /// Finish the client upgrade after the server accepted, taking ownership
    /// of the original socket. The caller must check [Self::validate_seals] first.
    pub fn finalize_upgrade(self, unix_socket: OwnedFd) -> anyhow::Result<MioFdStream> {
        unix_socket.set_cloexec()?;
        MioFdStream::new(
            self.segment,
            RingLayout::LowSendHighReceive,
            unix_socket,
            self.client_recv_nsock_fd,
        )?
        .ok()
    }

    /// Check that the server sealed the buffer with F_SEAL_FUTURE_WRITE, so no
    /// further writable mappings can be created; memfd_secret(2) buffers are
    /// exempt.
    ///
    /// FreeBSD lacks F_SEAL_FUTURE_WRITE, so nothing is required there: the
    /// buffer is only sealed against resizing (when either side maps it), and
    /// anyone holding the descriptor can still write(2) to it or map it
    /// writable.
    pub fn validate_seals(&self) -> anyhow::Result<()> {
        const WANTED: SealFlags = cfg_select! {
            target_os = "linux" => SealFlags::FUTURE_WRITE,
            _ => SealFlags::empty(),
        };
        if self.buffer_fd.is_memfd_secret()? {
            return Ok(());
        }

        if !self.buffer_fd.has_all_of_these_seals(WANTED)? {
            anyhow::bail!("Required backing seals unavailable")
        }

        Ok(())
    }
}

impl UpgradePendingServer {
    /// Finish the server upgrade, taking ownership of the original socket.
    /// As on the client, the imported original socket becomes CLOEXEC here;
    /// completion configures both endpoints nonblocking, validates them once,
    /// and leaves the stream unregistered until the caller registers it.
    /// Stream construction failures are reported as [ShmStreamCreationError](crate::internal::util::ipc::shm::stream::mio::ShmStreamCreationError)
    /// inside the returned [anyhow::Error].
    pub fn finalize_upgrade(self, unix_socket: OwnedFd) -> anyhow::Result<MioFdStream> {
        unix_socket.set_cloexec()?;
        MioFdStream::new(
            self.segment,
            RingLayout::LowReceiveHighSend,
            self.server_send_nsock_fd,
            unix_socket,
        )?
        .ok()
    }
}

fn notification_socket_pair() -> anyhow::Result<(OwnedFd, OwnedFd)> {
    let flags = cfg_select! {
        // Apple lacks SOCK_NONBLOCK/SOCK_CLOEXEC; the upgrade is refused there
        // before this runs (see UpgradableSocket::ensure_upgrade_supported).
        target_vendor = "apple" => SocketFlags::empty(),
        _ => SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
    };
    rustix::net::socketpair(AddressFamily::UNIX, SocketType::STREAM, flags, None)?.ok()
}
