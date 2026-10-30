//! part of the experimental PSK broker feature
//!
//! - TODO: where should this code reside?

#[cfg(feature = "experiment_api")]
use {
    crate::internal::util::rustix::claim_fd,
    crate::internal::wireguard_broker::WireguardBrokerMio,
    crate::internal::wireguard_broker::brokers::mio_client::MioBrokerClient,
    command_fds::{CommandFdExt, FdMapping},
    log::{error, info},
    mio::net::UnixStream,
    rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair},
    std::process::Command,
    std::thread,
};

use super::BrokerInterface;
/// Return the WireGuard PSK broker interface configured.
///
/// Returns `None` if the `experiment_api` feature is disabled.
#[cfg(not(feature = "experiment_api"))]
pub fn get_broker_interface(&self) -> Option<BrokerInterface> {
    None
}

/// Create the WireGuard PSK broker to be used by
/// [crate::app_server::AppServer].
///
/// If the `experiment_api`
/// feature flag is set, then this communicates with a PSK broker
/// running in a different process as configured via
/// the `psk_broker_path`, `psk_broker_fd`, and `psk_broker_spawn`
/// fields.
///
/// If the `experiment_api`
/// feature flag is not set, then this returns a [NativeUnixBroker],
/// sending pre-shared keys directly to WireGuard from within this
/// process.
#[cfg(feature = "experiment_api")]
pub fn create_broker(
    broker_interface: Option<BrokerInterface>,
) -> Result<
    Box<dyn WireguardBrokerMio<MioError = anyhow::Error, Error = anyhow::Error> + Send>,
    anyhow::Error,
> {
    if let Some(interface) = broker_interface {
        let socket = get_broker_socket(interface)?;
        Ok(Box::new(MioBrokerClient::new(socket)))
    } else {
        use crate::internal::wireguard_broker::brokers::native_unix::NativeUnixBroker;

        Ok(Box::new(NativeUnixBroker::new()))
    }
}

/// Create the WireGuard PSK broker to be used by
/// [crate::app_server::AppServer].
///
/// If the `experiment_api`
/// feature flag is set, then this communicates with a PSK broker
/// running in a different process as configured via
/// the `psk_broker_path`, `psk_broker_fd`, and `psk_broker_spawn`
/// fields.
///
/// If the `experiment_api`
/// feature flag is not set, then this returns a [NativeUnixBroker],
/// sending pre-shared keys directly to WireGuard from within this
/// process.
#[cfg(not(feature = "experiment_api"))]
fn create_broker(
    _broker_interface: Option<BrokerInterface>,
) -> Result<Box<NativeUnixBroker>, anyhow::Error> {
    Ok(Box::new(NativeUnixBroker::new()))
}

/// Used by [CliCommand::create_broker] if the `experiment_api` is configured
/// to set up the connection with the PSK broker process as configured
/// via the `psk_broker_path`, `psk_broker_fd`, and `psk_broker_spawn`
/// fields.
#[cfg(feature = "experiment_api")]
pub fn get_broker_socket(broker_interface: BrokerInterface) -> Result<UnixStream, anyhow::Error> {
    // Connect to the psk broker unix socket if one was specified
    // OR OTHERWISE spawn the psk broker and use socketpair(2) to connect with them
    match broker_interface {
        BrokerInterface::Socket(broker_path) => Ok(UnixStream::connect(broker_path)?),
        BrokerInterface::FileDescriptor(broker_fd) => {
            // mio::net::UnixStream doesn't implement From<OwnedFd>, so we have to go through std
            let sock = std::os::unix::net::UnixStream::from(claim_fd(broker_fd)?);
            sock.set_nonblocking(true)?;
            Ok(UnixStream::from_std(sock))
        }
        BrokerInterface::SocketPair => {
            // Form a socketpair for communicating to the broker
            let (ours, theirs) = socketpair(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::empty(),
                None,
            )?;

            // Setup our end of the socketpair
            let ours = std::os::unix::net::UnixStream::from(ours);
            ours.set_nonblocking(true)?;

            // Start the PSK broker
            let mut child = Command::new("rosenpass-wireguard-broker-socket-handler")
                .args(["--stream-fd", "3"])
                .fd_mappings(vec![FdMapping {
                    parent_fd: theirs,
                    child_fd: 3,
                }])?
                .spawn()?;

            // Handle the PSK broker crashing
            thread::spawn(move || {
                let status = child.wait();

                if let Ok(status) = status {
                    if status.success() {
                        // Maybe they are doing double forking?
                        info!("PSK broker exited.");
                    } else {
                        error!("PSK broker exited with an error ({status:?})");
                    }
                } else {
                    error!("Wait on PSK broker process failed ({status:?})");
                }
            });

            Ok(UnixStream::from_std(ours))
        }
    }
}
