use std::{
    collections::HashSet,
    fs,
    io::Write,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure};
use serde::{Deserialize, Serialize};

use crate::util::fopen_w;

#[derive(Debug, Serialize, Deserialize)]
pub struct Rosenpass {
    pub public_key: PathBuf,

    pub secret_key: PathBuf,

    pub listen: Vec<SocketAddr>,

    #[serde(default)]
    pub verbosity: Verbosity,
    pub peers: Vec<RosenpassPeer>,

    #[serde(skip)]
    pub config_file_path: PathBuf,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verbosity {
    Quiet,
    Verbose,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosenpassPeer {
    pub public_key: PathBuf,
    pub endpoint: Option<String>,
    pub pre_shared_key: Option<PathBuf>,

    #[serde(default)]
    pub key_out: Option<PathBuf>,

    // TODO make sure failure does not crash but is logged
    #[serde(default)]
    pub exchange_command: Vec<String>,

    // TODO make this field only available on binary builds, not on library builds
    #[serde(flatten)]
    pub wg: Option<WireGuard>,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuard {
    pub device: String,
    pub peer: String,
    pub extra_params: Vec<String>,
}

impl Rosenpass {
    /// Load a config file from a file path
    ///
    /// no validation is conducted
    pub fn load<P: AsRef<Path>>(p: P) -> anyhow::Result<Self> {
        let mut config: Self = toml::from_str(&fs::read_to_string(&p)?)?;

        config.config_file_path = p.as_ref().to_owned();
        Ok(config)
    }

    /// Write a config to a file
    pub fn store<P: AsRef<Path>>(&self, p: P) -> anyhow::Result<()> {
        let serialized_config =
            toml::to_string_pretty(&self).expect("unable to serialize the default config");
        fs::write(p, serialized_config)?;
        Ok(())
    }

    /// Commit the configuration to where it came from, overwriting the original file
    pub fn commit(&self) -> anyhow::Result<()> {
        let mut f = fopen_w(&self.config_file_path)?;
        f.write_all(toml::to_string_pretty(&self)?.as_bytes())?;

        self.store(&self.config_file_path)
    }

    /// Validate a configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        // check the public-key file exists
        ensure!(
            self.public_key.is_file(),
            "public-key file {:?} does not exist",
            self.public_key
        );

        // check the secret-key file exists
        ensure!(
            self.secret_key.is_file(),
            "secret-key file {:?} does not exist",
            self.secret_key
        );

        for (i, peer) in self.peers.iter().enumerate() {
            // check peer's public-key file exists
            ensure!(
                peer.public_key.is_file(),
                "peer {i} public-key file {:?} does not exist",
                peer.public_key
            );

            // check endpoint is usable
            if let Some(addr) = peer.endpoint.as_ref() {
                ensure!(
                    addr.to_socket_addrs().is_ok(),
                    "peer {i} endpoint {} can not be parsed to a socket address",
                    addr
                );
            }

            // TODO warn if neither out_key nor exchange_command is defined
        }

        Ok(())
    }

    /// Creates a new configuration
    pub fn new<P1: AsRef<Path>, P2: AsRef<Path>>(public_key: P1, secret_key: P2) -> Self {
        Self {
            public_key: PathBuf::from(public_key.as_ref()),
            secret_key: PathBuf::from(secret_key.as_ref()),
            listen: vec![],
            verbosity: Verbosity::Quiet,
            peers: vec![],
            config_file_path: PathBuf::new(),
        }
    }

    /// Add IPv4 __and__ IPv6 IF_ANY address to the listen interfaces
    pub fn add_if_any(&mut self, port: u16) {
        let ipv4_any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port));
        let ipv6_any = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            port,
            0,
            0,
        ));
        self.listen.push(ipv4_any);
        self.listen.push(ipv6_any);
    }

    /// from chaotic args
    /// Quest: the grammar is undecideable, what do we do here?
    pub fn parse_args(args: Vec<String>) -> anyhow::Result<Self> {
        let mut config = Self::new("", "");

        #[derive(Debug, Hash, PartialEq, Eq)]
        enum State {
            Own,
            OwnPublicKey,
            OwnSecretKey,
            OwnListen,
            Peer,
            PeerPsk,
            PeerPublicKey,
            PeerEndpoint,
            PeerOutfile,
            PeerWireguardDev,
            PeerWireguardPeer,
            PeerWireguardExtraArgs,
        }

        let mut already_set = HashSet::new();

        // TODO idea: use config.peers.len() to give index of peer with conflicting argument
        use State::*;
        let mut state = Own;
        let mut current_peer = None;
        let p_exists = "a peer should exist by now";
        let wg_exists = "a peer wireguard should exist by now";
        for arg in args {
            state = match (state, arg.as_str(), &mut current_peer) {
                (Own, "public-key", None) => OwnPublicKey,
                (Own, "secret-key", None) => OwnSecretKey,
                (Own, "listen", None) => OwnListen,
                (Own, "verbose", None) => {
                    config.verbosity = Verbosity::Verbose;
                    Own
                }
                (Own, "peer", None) => {
                    ensure!(
                        already_set.contains(&OwnPublicKey),
                        "public-key file must be set"
                    );
                    ensure!(
                        already_set.contains(&OwnSecretKey),
                        "secret-key file must be set"
                    );

                    already_set.clear();
                    current_peer = Some(RosenpassPeer::default());

                    Peer
                }
                (OwnPublicKey, pk, None) => {
                    ensure!(
                        already_set.insert(OwnPublicKey),
                        "public-key was already set"
                    );
                    config.public_key = pk.into();
                    Own
                }
                (OwnSecretKey, sk, None) => {
                    ensure!(
                        already_set.insert(OwnSecretKey),
                        "secret-key was already set"
                    );
                    config.secret_key = sk.into();
                    Own
                }
                (OwnListen, l, None) => {
                    already_set.insert(OwnListen); // multiple listen directives are allowed
                    for socket_addr in l.to_socket_addrs()? {
                        config.listen.push(socket_addr);
                    }

                    Own
                }
                (Peer | PeerWireguardExtraArgs, "peer", maybe_peer @ Some(_)) => {
                    // TODO check current peer
                    // commit current peer, create a new one
                    config.peers.push(maybe_peer.take().expect(p_exists));

                    already_set.clear();
                    current_peer = Some(RosenpassPeer::default());

                    Peer
                }
                (Peer, "public-key", Some(_)) => PeerPublicKey,
                (Peer, "endpoint", Some(_)) => PeerEndpoint,
                (Peer, "preshared-key", Some(_)) => PeerPsk,
                (Peer, "outfile", Some(_)) => PeerOutfile,
                (Peer, "wireguard", Some(_)) => PeerWireguardDev,
                (PeerPublicKey, pk, Some(peer)) => {
                    ensure!(
                        already_set.insert(PeerPublicKey),
                        "public-key was already set"
                    );
                    peer.public_key = pk.into();
                    Peer
                }
                (PeerEndpoint, e, Some(peer)) => {
                    ensure!(already_set.insert(PeerEndpoint), "endpoint was already set");
                    peer.endpoint = Some(e.to_owned());
                    Peer
                }
                (PeerPsk, psk, Some(peer)) => {
                    ensure!(already_set.insert(PeerEndpoint), "peer psk was already set");
                    peer.pre_shared_key = Some(psk.into());
                    Peer
                }
                (PeerOutfile, of, Some(peer)) => {
                    ensure!(
                        already_set.insert(PeerOutfile),
                        "peer outfile was already set"
                    );
                    peer.key_out = Some(of.into());
                    Peer
                }
                (PeerWireguardDev, dev, Some(peer)) => {
                    ensure!(
                        already_set.insert(PeerWireguardDev),
                        "peer wireguard-dev was already set"
                    );
                    assert!(peer.wg.is_none());
                    peer.wg = Some(WireGuard {
                        device: dev.to_string(),
                        ..Default::default()
                    });

                    PeerWireguardPeer
                }
                (PeerWireguardPeer, p, Some(peer)) => {
                    ensure!(
                        already_set.insert(PeerWireguardPeer),
                        "peer wireguard-peer was already set"
                    );
                    peer.wg.as_mut().expect(wg_exists).peer = p.to_string();
                    PeerWireguardExtraArgs
                }
                (PeerWireguardExtraArgs, arg, Some(peer)) => {
                    peer.wg
                        .as_mut()
                        .expect(wg_exists)
                        .extra_params
                        .push(arg.to_string());
                    PeerWireguardExtraArgs
                }

                // error cases
                (Own, x, None) => {
                    bail!("unrecognised argument {x}");
                }
                (Own | OwnPublicKey | OwnSecretKey | OwnListen, _, Some(_)) => {
                    panic!("current_peer is not None while in Own* state, this must never happen")
                }

                (State::Peer, arg, Some(_)) => {
                    bail!("unrecongnised argument {arg}");
                }
                (
                    Peer
                    | PeerEndpoint
                    | PeerOutfile
                    | PeerPublicKey
                    | PeerPsk
                    | PeerWireguardDev
                    | PeerWireguardPeer
                    | PeerWireguardExtraArgs,
                    _,
                    None,
                ) => {
                    panic!("got peer options but no peer was created")
                }
            };
        }

        if let Some(p) = current_peer {
            // TODO ensure peer is propagated with sufficient information
            config.peers.push(p);
        }

        Ok(config)
    }
}

impl Rosenpass {
    /// Generate an example configuration
    pub fn example_config() -> Self {
        let peer = RosenpassPeer {
            public_key: "rp-peer-public-key".into(),
            endpoint: Some("my-peer.test:9999".into()),
            exchange_command: [
                "wg",
                "set",
                "wg0",
                "peer",
                "<PEER_ID>",
                "preshared-key",
                "/dev/stdin",
            ]
            .into_iter()
            .map(|x| x.to_string())
            .collect(),
            key_out: Some("rp-key-out".into()),
            pre_shared_key: None,
            wg: None,
        };

        Self {
            public_key: "rp-public-key".into(),
            secret_key: "rp-secret-key".into(),
            peers: vec![peer],
            ..Self::new("", "")
        }
    }
}

impl Default for Verbosity {
    fn default() -> Self {
        Self::Quiet
    }
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;

    use super::*;

    fn split_str(s: &str) -> Vec<String> {
        s.split(" ").map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_simple_cli_parse() {
        let args = split_str(
            "public-key /my/public-key secret-key /my/secret-key verbose \
                listen 0.0.0.0:9999 peer public-key /peer/public-key endpoint \
                peer.test:9999 outfile /peer/rp-out",
        );

        let config = Rosenpass::parse_args(args).unwrap();

        assert_eq!(config.public_key, PathBuf::from("/my/public-key"));
        assert_eq!(config.secret_key, PathBuf::from("/my/secret-key"));
        assert_eq!(config.verbosity, Verbosity::Verbose);
        assert_eq!(
            &config.listen,
            &vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9999)]
        );
        assert_eq!(
            config.peers,
            vec![RosenpassPeer {
                public_key: PathBuf::from("/peer/public-key"),
                endpoint: Some("peer.test:9999".into()),
                pre_shared_key: None,
                key_out: Some(PathBuf::from("/peer/rp-out")),
                ..Default::default()
            }]
        )
    }

    #[test]
    fn test_cli_parse_multiple_peers() {
        let args = split_str(
            "public-key /my/public-key secret-key /my/secret-key verbose \
                peer public-key /peer-a/public-key endpoint \
                peer.test:9999 outfile /peer-a/rp-out \
                peer public-key /peer-b/public-key outfile /peer-b/rp-out",
        );

        let config = Rosenpass::parse_args(args).unwrap();

        assert_eq!(config.public_key, PathBuf::from("/my/public-key"));
        assert_eq!(config.secret_key, PathBuf::from("/my/secret-key"));
        assert_eq!(config.verbosity, Verbosity::Verbose);
        assert!(&config.listen.is_empty());
        assert_eq!(
            config.peers,
            vec![
                RosenpassPeer {
                    public_key: PathBuf::from("/peer-a/public-key"),
                    endpoint: Some("peer.test:9999".into()),
                    pre_shared_key: None,
                    key_out: Some(PathBuf::from("/peer-a/rp-out")),
                    ..Default::default()
                },
                RosenpassPeer {
                    public_key: PathBuf::from("/peer-b/public-key"),
                    endpoint: None,
                    pre_shared_key: None,
                    key_out: Some(PathBuf::from("/peer-b/rp-out")),
                    ..Default::default()
                }
            ]
        )
    }
}
