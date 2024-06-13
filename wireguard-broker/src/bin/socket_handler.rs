use std::process::Stdio;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tokio::task;

use anyhow::{bail, ensure, Result};
use clap::{ArgGroup, Parser};

use rosenpass_util::fd::claim_fd;
use rosenpass_wireguard_broker::api::msgs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[clap(group(
            ArgGroup::new("socket")
                .required(true)
                .args(&["listen_path", "listen_fd", "stream_fd"]),
        ))]
struct Args {
    /// Where in the file-system to create the unix socket this broker will be listening for
    /// connections on
    #[arg(long)]
    listen_path: Option<String>,

    /// When this broker is called from another process, the other process can open and bind the
    /// unix socket to use themselves, passing it to this process. In Rust this can be achieved
    /// using the [command-fds](https://docs.rs/command-fds/latest/command_fds/) crate.
    #[arg(long)]
    listen_fd: Option<i32>,

    /// When this broker is called from another process, the other process can connect the unix socket
    /// themselves, for instance using the `socketpair(2)` system call.
    #[arg(long)]
    stream_fd: Option<i32>,

    /// The underlying broker, accepting commands through stdin and sending results through stdout.
    #[arg(
        last = true,
        allow_hyphen_values = true,
        default_value = "rosenpass-wireguard-broker-privileged"
    )]
    command: Vec<String>,
}

struct BrokerRequest {
    reply_to: oneshot::Sender<BrokerResponse>,
    request: Vec<u8>,
}

struct BrokerResponse {
    response: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    let (proc_tx, proc_rx) = mpsc::channel(100);

    // Start the inner broker handler
    task::spawn(async move {
        if let Err(e) = direct_broker_process(proc_rx, args.command).await {
            log::error!("Error in broker command handler: {e}");
            panic!("Can not proceed without underlying broker process");
        }
    });

    // Listen for incoming requests
    if let Some(path) = args.listen_path {
        let sock = UnixListener::bind(path)?;
        listen_for_clients(proc_tx, sock).await
    } else if let Some(fd) = args.listen_fd {
        let sock = std::os::unix::net::UnixListener::from(claim_fd(fd)?);
        sock.set_nonblocking(true)?;
        listen_for_clients(proc_tx, UnixListener::from_std(sock)?).await
    } else if let Some(fd) = args.stream_fd {
        let stream = std::os::unix::net::UnixStream::from(claim_fd(fd)?);
        stream.set_nonblocking(true)?;
        on_accept(proc_tx, UnixStream::from_std(stream)?).await
    } else {
        unreachable!();
    }
}

async fn direct_broker_process(
    mut queue: mpsc::Receiver<BrokerRequest>,
    cmd: Vec<String>,
) -> Result<()> {
    let proc = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut stdin = proc.stdin.unwrap();
    let mut stdout = proc.stdout.unwrap();

    loop {
        let BrokerRequest { reply_to, request } = queue.recv().await.unwrap();

        stdin
            .write_all(&(request.len() as u64).to_le_bytes())
            .await?;
        stdin.write_all(&request[..]).await?;

        // Read the response length
        let mut len = [0u8; 8];
        stdout.read_exact(&mut len).await?;

        // Parse the response length
        let len = u64::from_le_bytes(len) as usize;
        ensure!(
            len <= msgs::RESPONSE_MSG_BUFFER_SIZE,
            "Oversized buffer ({len}) in broker stdout."
        );

        // Read the message itself
        let mut res_buf = request; // Avoid allocating memory if we don't have to
        res_buf.resize(len as usize, 0);
        stdout.read_exact(&mut res_buf[..len]).await?;

        // Return to the unix socket connection worker
        reply_to
            .send(BrokerResponse { response: res_buf })
            .or_else(|_| bail!("Unable to send respnse to unix socket worker."))?;
    }
}

async fn listen_for_clients(queue: mpsc::Sender<BrokerRequest>, sock: UnixListener) -> Result<()> {
    loop {
        let (stream, _addr) = sock.accept().await?;
        let queue = queue.clone();
        task::spawn(async move {
            if let Err(e) = on_accept(queue, stream).await {
                log::error!("Error during connection processing: {e}");
            }
        });
    }

    // NOTE: If loop can ever terminate we need to join the spawned tasks
}

async fn on_accept(queue: mpsc::Sender<BrokerRequest>, mut stream: UnixStream) -> Result<()> {
    let mut req_buf = Vec::new();

    loop {
        stream.readable().await?;

        // Read the message length
        let mut len = [0u8; 8];
        stream.read_exact(&mut len).await?;

        // Parse the message length
        let len = u64::from_le_bytes(len) as usize;
        ensure!(
            len <= msgs::REQUEST_MSG_BUFFER_SIZE,
            "Oversized buffer ({len}) in unix socket input."
        );

        // Read the message itself
        req_buf.resize(len as usize, 0);
        stream.read_exact(&mut req_buf[..len]).await?;

        // Handle the message
        let (reply_tx, reply_rx) = oneshot::channel();
        queue
            .send(BrokerRequest {
                reply_to: reply_tx,
                request: req_buf,
            })
            .await?;

        // Wait for the reply
        let BrokerResponse { response } = reply_rx.await.unwrap();

        // Write reply back to unix socket
        stream
            .write_all(&(response.len() as u64).to_le_bytes())
            .await?;
        stream.write_all(&response[..]).await?;
        stream.flush().await?;

        // Reuse the same memory for the next message
        req_buf = response;
    }
}
