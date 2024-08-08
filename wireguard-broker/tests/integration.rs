#[cfg(feature = "enable_broker_api")]
#[cfg(test)]
mod integration_tests {

    use rand::Rng;
    use rosenpass_secret_memory::{Public, Secret};
    use rosenpass_wireguard_broker::api::msgs::{
        SetPskError, REQUEST_MSG_BUFFER_SIZE, RESPONSE_MSG_BUFFER_SIZE,
    };
    use rosenpass_wireguard_broker::api::server::{BrokerServer, BrokerServerError};
    use rosenpass_wireguard_broker::brokers::mio_client::MioBrokerClient;
    use rosenpass_wireguard_broker::WG_KEY_LEN;
    use rosenpass_wireguard_broker::WG_PEER_LEN;
    use rosenpass_wireguard_broker::{SerializedBrokerConfig, WireGuardBroker};
    use std::io::Read;
    use std::sync::{Arc, Mutex};

    #[derive(Default, Debug)]
    struct MockServerBrokerInner {
        psk: Option<Secret<WG_KEY_LEN>>,
        peer_id: Option<Public<WG_PEER_LEN>>,
        interface: Option<String>,
    }

    #[derive(Debug)]
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

        #[allow(clippy::clone_on_copy)]
        fn set_psk(&mut self, config: SerializedBrokerConfig) -> Result<(), Self::Error> {
            loop {
                let mut lock = self.inner.try_lock();

                if let Ok(ref mut mutex) = lock {
                    **mutex = MockServerBrokerInner {
                        psk: Some(config.psk.clone()),
                        peer_id: Some(config.peer_id.clone()),
                        interface: Some(std::str::from_utf8(config.interface).unwrap().to_string()),
                    };
                    break;
                }
            }
            Ok(())
        }
    }

    procspawn::enable_test_support!();

    #[test]
    fn test_psk_exchanges() {
        const TEST_RUNS: usize = 100;

        use rosenpass_secret_memory::test_spawn_process_provided_policies;

        test_spawn_process_provided_policies!({
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
                let psk = Secret::random();
                let peer_id = Public::random();
                let interface = "test";
                let config = SerializedBrokerConfig {
                    psk: &psk,
                    peer_id: &peer_id,
                    interface: interface.as_bytes(),
                    additional_params: &[],
                };
                client.set_psk(config).unwrap();

                //Sleep for a while to allow the server to process the message
                std::thread::sleep(std::time::Duration::from_millis(
                    rand::thread_rng().gen_range(100..500),
                ));

                let psk = psk.secret().to_owned();

                loop {
                    let mut lock = server_broker_inner.try_lock();

                    if let Ok(ref mut inner) = lock {
                        // Check if the psk is received by the server
                        let received_psk = &inner.psk;
                        assert_eq!(
                            received_psk.as_ref().map(|psk| psk.secret().to_owned()),
                            Some(psk)
                        );

                        let recieved_peer_id = inner.peer_id;
                        assert_eq!(recieved_peer_id, Some(peer_id));

                        let target_interface = &inner.interface;
                        assert_eq!(target_interface.as_deref(), Some(interface));

                        break;
                    }
                }
            }
            handle.join().unwrap().unwrap();
        });
    }
}
