fn main() {
    #[cfg(target_os = "linux")]
    linux::main().unwrap();

    #[cfg(not(target_os = "linux"))]
    panic!("This binary is only supported on Linux");
}

#[cfg(target_os = "linux")]
pub mod linux {
    use std::io::{stdin, stdout, Read, Write};

    use rosenpass_wireguard_broker::api::msgs;
    use rosenpass_wireguard_broker::api::server::BrokerServer;
    use rosenpass_wireguard_broker::brokers::netlink as wg;

    #[derive(thiserror::Error, Debug)]
    pub enum BrokerAppError {
        #[error(transparent)]
        IoError(#[from] std::io::Error),
        #[error(transparent)]
        WgConnectError(#[from] wg::ConnectError),
        #[error(transparent)]
        WgSetPskError(#[from] wg::SetPskError),
        #[error("Oversized message {}; something about the request is fatally wrong", .0)]
        OversizedMessage(u64),
    }

    pub fn main() -> Result<(), BrokerAppError> {
        let mut broker = BrokerServer::new(wg::NetlinkWireGuardBroker::new()?);

        let mut stdin = stdin().lock();
        let mut stdout = stdout().lock();
        loop {
            // Read the message length
            let mut len = [0u8; 8];
            stdin.read_exact(&mut len)?;

            // Parse the message length
            let len = u64::from_le_bytes(len);
            if (len as usize) > msgs::REQUEST_MSG_BUFFER_SIZE {
                return Err(BrokerAppError::OversizedMessage(len));
            }

            // Read the message itself
            let mut req_buf = [0u8; msgs::REQUEST_MSG_BUFFER_SIZE];
            let req_buf = &mut req_buf[..(len as usize)];
            stdin.read_exact(req_buf)?;

            // Process the message
            let mut res_buf = [0u8; msgs::RESPONSE_MSG_BUFFER_SIZE];
            let res = match broker.handle_message(req_buf, &mut res_buf) {
                Ok(len) => &res_buf[..len],
                Err(e) => {
                    eprintln!("Error processing message for wireguard PSK broker: {e:?}");
                    continue;
                }
            };

            // Write the response
            stdout.write_all(&(res.len() as u64).to_le_bytes())?;
            stdout.write_all(&res)?;
            stdout.flush()?;
        }
    }
}
