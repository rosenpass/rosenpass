use crate::app_server::AppServerTest;
use crate::app_server::{AppServer, BrokerPeer};
use crate::broker::create_broker;
use crate::config;
use crate::protocol::{SPk, SSk, SymKey};
use rosenpass_util::file::LoadValue;
use rosenpass_util::file::LoadValueB64;
use rosenpass_wireguard_broker::brokers::native_unix::NativeUnixBrokerConfigBaseBuilder;
use rosenpass_wireguard_broker::brokers::native_unix::NativeUnixBrokerConfigBaseBuilderError;
use std::path::PathBuf;

pub enum BrokerInterface {
    Socket(PathBuf),
    FileDescriptor(i32),
    SocketPair,
}

pub fn event_loop(
    config: config::Rosenpass,
    broker_interface: Option<BrokerInterface>,
    test_helpers: Option<AppServerTest>,
) -> anyhow::Result<()> {
    const MAX_PSK_SIZE: usize = 1000;

    // load own keys
    let keypair = config
        .keypair
        .as_ref()
        .map(|kp| -> anyhow::Result<_> {
            let sk = SSk::load(&kp.secret_key)?;
            let pk = SPk::load(&kp.public_key)?;
            Ok((sk, pk))
        })
        .transpose()?;

    // start an application server
    let mut srv = std::boxed::Box::<AppServer>::new(AppServer::new(
        keypair,
        config.listen.clone(),
        config.verbosity,
        test_helpers,
    )?);

    config.apply_to_app_server(&mut srv)?;

    let broker = create_broker(broker_interface)?;
    let broker_store_ptr = srv.register_broker(broker)?;

    fn cfg_err_map(e: NativeUnixBrokerConfigBaseBuilderError) -> anyhow::Error {
        anyhow::Error::msg(format!("NativeUnixBrokerConfigBaseBuilderError: {:?}", e))
    }

    for cfg_peer in config.peers {
        let broker_peer = if let Some(wg) = &cfg_peer.wg {
            let peer_cfg = NativeUnixBrokerConfigBaseBuilder::default()
                .peer_id_b64(&wg.peer)?
                .interface(wg.device.clone())
                .extra_params_ser(&wg.extra_params)?
                .build()
                .map_err(cfg_err_map)?;

            let broker_peer = BrokerPeer::new(broker_store_ptr.clone(), Box::new(peer_cfg));

            Some(broker_peer)
        } else {
            None
        };

        srv.add_peer(
            // psk, pk, outfile, outwg, tx_addr
            cfg_peer
                .pre_shared_key
                .map(SymKey::load_b64::<MAX_PSK_SIZE, _>)
                .transpose()?,
            SPk::load(&cfg_peer.public_key)?,
            cfg_peer.key_out,
            broker_peer,
            cfg_peer.endpoint.clone(),
        )?;
    }

    srv.event_loop()
}
