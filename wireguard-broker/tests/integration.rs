#[cfg(feature = "enable_broker")]
#[cfg(test)]
mod integration_tests {

    use rand::Rng;
    use rosenpass_wireguard_broker::api::mio_client::MioBrokerClient;
    use rosenpass_wireguard_broker::api::msgs::{
        SetPskError, REQUEST_MSG_BUFFER_SIZE, RESPONSE_MSG_BUFFER_SIZE,
    };
    use rosenpass_wireguard_broker::api::server::{BrokerServer, BrokerServerError};
    use rosenpass_wireguard_broker::WireGuardBroker;
    use std::io::Read;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct MockServerBrokerInner {
        psk: Option<[u8; 32]>,
        peer_id: Option<[u8; 32]>,
        interface: Option<String>,
    }

    struct MockServerBroker {
        inner: Arc<Mutex<MockServerBrokerInner>>,
    }

    impl MockServerBroker {
        fn new(inner: Arc<Mutex<MockServerBrokerInner>>) -> Self {
            Self { inner }
        }
    }

    impl WireGuardBroker for MockServerBroker {
        type Error = SetPskError;

        fn set_psk(
            &mut self,
            interface: &str,
            peer_id: [u8; 32],
            psk: [u8; 32],
        ) -> Result<(), Self::Error> {
            loop {
                let mut lock = self.inner.try_lock();

                if let Ok(ref mut mutex) = lock {
                    **mutex = MockServerBrokerInner {
                        psk: Some(psk),
                        peer_id: Some(peer_id),
                        interface: Some(interface.to_string()),
                    };
                    break;
                }
            }
            Ok(())
        }
    }

    #[test]
    fn test_psk_exchanges() {
        const TEST_RUNS: usize = 100;

        let server_broker_inner = Arc::new(Mutex::new(MockServerBrokerInner::default()));
        // Create a mock BrokerServer
        let server_broker = MockServerBroker::new(server_broker_inner.clone());

        let mut server = BrokerServer::<SetPskError, MockServerBroker>::new(server_broker);

        let (client_socket, mut server_socket) = mio::net::UnixStream::pair().unwrap();

        // Spawn a new thread to connect to the unix socket
        let handle = std::thread::spawn(move || {
            for _ in 0..TEST_RUNS {
                // Wait for 8 bytes of length to come in
                let mut length_buffer = [0; 8];

                while let Err(_err) = server_socket.read_exact(&mut length_buffer) {}

                let length = u64::from_le_bytes(length_buffer) as usize;

                // Read the amount of length bytes into a buffer
                let mut data_buffer = [0; REQUEST_MSG_BUFFER_SIZE];
                while let Err(_err) = server_socket.read_exact(&mut data_buffer[0..length]) {}

                let mut response = [0; RESPONSE_MSG_BUFFER_SIZE];
                server.handle_message(&data_buffer[0..length], &mut response)?;
            }
            Ok::<(), BrokerServerError>(())
        });

        // Create a MioBrokerClient and send a psk
        let mut client = MioBrokerClient::new(client_socket);

        for _ in 0..TEST_RUNS {
            //Create psk of random 32 bytes
            let mut psk: [u8; 32] = [0; 32];
            rand::thread_rng().fill(&mut psk);
            let mut peer_id: [u8; 32] = [0; 32];
            rand::thread_rng().fill(&mut peer_id);
            let interface = "test";
            client.set_psk(&interface, peer_id, psk).unwrap();

            //Sleep for a while to allow the server to process the message
            std::thread::sleep(std::time::Duration::from_millis(
                rand::thread_rng().gen_range(100..500),
            ));

            loop {
                let mut lock = server_broker_inner.try_lock();

                if let Ok(ref mut inner) = lock {
                    // Check if the psk is received by the server
                    let received_psk = inner.psk;
                    assert_eq!(received_psk, Some(psk));

                    let recieved_peer_id = inner.peer_id;
                    assert_eq!(recieved_peer_id, Some(peer_id));

                    let target_interface = &inner.interface;
                    assert_eq!(target_interface.as_deref(), Some(interface));

                    break;
                }
            }
        }
        handle.join().unwrap().unwrap();
    }
}
