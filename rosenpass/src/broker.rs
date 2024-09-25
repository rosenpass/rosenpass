use crate::cli::Cli;
use crate::event_loop::BrokerInterface;
use rosenpass_wireguard_broker::brokers::native_unix::NativeUnixBroker;

#[cfg(feature = "experiment_api")]
/// returns the broker interface set by CLI args
/// returns `None` if the `experiment_api` feature isn't enabled
pub fn get_broker_interface(cli: &Cli) -> Option<BrokerInterface> {
    if let Some(path_ref) = cli.psk_broker_path.as_ref() {
        Some(BrokerInterface::Socket(path_ref.to_path_buf()))
    } else if let Some(fd) = cli.psk_broker_fd {
        Some(BrokerInterface::FileDescriptor(fd))
    } else if cli.psk_broker_spawn {
        Some(BrokerInterface::SocketPair)
    } else {
        None
    }
}

#[cfg(not(feature = "experiment_api"))]
/// returns the broker interface set by CLI args
/// returns `None` if the `experiment_api` feature isn't enabled
pub fn get_broker_interface(cli: &Cli) -> Option<BrokerInterface> {
    None
}

#[cfg(feature = "experiment_api")]
use {
    command_fds::{CommandFdExt, FdMapping},
    log::{error, info},
    mio::net::UnixStream,
    rosenpass_util::fd::claim_fd,
    rosenpass_wireguard_broker::brokers::mio_client::MioBrokerClient,
    rosenpass_wireguard_broker::WireguardBrokerMio,
    rustix::fd::AsRawFd,
    rustix::net::{socketpair, AddressFamily, SocketFlags, SocketType},
    std::os::unix::net,
    std::process::Command,
    std::thread,
};

#[cfg(feature = "experiment_api")]
fn create_broker(
    broker_interface: Option<BrokerInterface>,
) -> Result<
    Box<dyn WireguardBrokerMio<MioError = anyhow::Error, Error = anyhow::Error>>,
    anyhow::Error,
> {
    if let Some(interface) = broker_interface {
        let socket = get_broker_socket(interface)?;
        Ok(Box::new(MioBrokerClient::new(socket)))
    } else {
        Ok(Box::new(NativeUnixBroker::new()))
    }
}

#[cfg(not(feature = "experiment_api"))]
fn create_broker(
    _broker_interface: Option<BrokerInterface>,
) -> Result<Box<NativeUnixBroker>, anyhow::Error> {
    Ok(Box::new(NativeUnixBroker::new()))
}

#[cfg(feature = "experiment_api")]
fn get_broker_socket(broker_interface: BrokerInterface) -> Result<UnixStream, anyhow::Error> {
    // Connect to the psk broker unix socket if one was specified
    // OR OTHERWISE spawn the psk broker and use socketpair(2) to connect with them
    match broker_interface {
        BrokerInterface::Socket(broker_path) => Ok(UnixStream::connect(broker_path)?),
        BrokerInterface::FileDescriptor(broker_fd) => {
            // mio::net::UnixStream doesn't implement From<OwnedFd>, so we have to go through std
            let sock = net::UnixStream::from(claim_fd(broker_fd)?);
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
            let ours = net::UnixStream::from(ours);
            ours.set_nonblocking(true)?;

            // Start the PSK broker
            let mut child = Command::new("rosenpass-wireguard-broker-socket-handler")
                .args(["--stream-fd", "3"])
                .fd_mappings(vec![FdMapping {
                    parent_fd: theirs.as_raw_fd(),
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
