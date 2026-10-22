//! Configuration readable from a config file.
//!
//! Rosenpass supports reading its configuration from a TOML file. This module contains a struct
//! [`Rosenpass`] which holds such a configuration.
//!
//! ## TODO
//! - TODO: support `~` in <https://github.com/rosenpass/rosenpass/issues/237>
//! - TODO: provide tooling to create config file from shell <https://github.com/rosenpass/rosenpass/issues/247>

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::{collections::HashSet, fs, io::Write};

use anyhow::{Context, bail, ensure};

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};

use crate::internal::util::file::{LoadValue, Visibility, fopen_w};

use crate::protocol::basic_types::{PublicSymKey, SPk, SSk};
use crate::protocol::osk_domain_separator::OskDomainSeparator;

use crate::app_server::AppServer;

#[cfg(feature = "experiment_api")]
fn empty_api_config() -> crate::api::config::ApiConfig {
    crate::api::config::ApiConfig {
        listen_path: Vec::new(),
        listen_fd: Vec::new(),
        stream_fd: Vec::new(),
    }
}

/// Configuration for the Rosenpass key exchange
///
/// i.e. configuration for the `rosenpass exchange` and `rosenpass exchange-config` commands
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rosenpass {
    // TODO: Raise error if secret key or public key alone is set during deserialization
    // SEE: https://github.com/serde-rs/serde/issues/2793
    #[serde(flatten)]
    pub keypair: Option<Keypair>,

    /// Location of the API listen sockets
    #[cfg(feature = "experiment_api")]
    #[serde(default = "empty_api_config")]
    pub api: crate::api::config::ApiConfig,

    /// list of [`SocketAddr`] to listen on
    ///
    /// Examples:
    ///
    /// - `0.0.0.0:123` – Listen on any interface using IPv4, port 123
    /// - `[::1]:1234` – Listen on IPv6 localhost, port 1234
    /// - `[::]:4476` – Listen on any IPv4 or IPv6 interface, port 4476
    pub listen: Vec<SocketAddr>,

    /// log verbosity
    ///
    /// This is subject to change. See [`Verbosity`] for details.
    #[serde(default)]
    pub verbosity: Verbosity,

    /// list of peers
    ///
    /// See the [`RosenpassPeer`] type for more information and examples.
    pub peers: Vec<RosenpassPeer>,

    /// path to the file which provided this configuration
    ///
    /// This item is of course not read from the TOML but is added by the algorithm that parses
    /// the config file.
    #[serde(skip)]
    pub config_file_path: PathBuf,
}

/// Public key and secret key locations.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Keypair {
    /// path to the public key file
    pub public_key: PathBuf,

    /// path to the secret key file
    pub secret_key: PathBuf,
}

impl Keypair {
    /// Construct a keypair from its fields
    pub fn new<Pk: AsRef<Path>, Sk: AsRef<Path>>(public_key: Pk, secret_key: Sk) -> Self {
        let public_key = public_key.as_ref().to_path_buf();
        let secret_key = secret_key.as_ref().to_path_buf();
        Self {
            public_key,
            secret_key,
        }
    }
}

/// Level of verbosity for [crate::app_server::AppServer]
///
/// The value of the field [crate::app_server::AppServer::verbosity]. See the field documentation
/// for details.
///
/// - TODO: replace this type with [`log::LevelFilter`], also see <https://github.com/rosenpass/rosenpass/pull/246>
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Copy, Clone)]
#[serde(deny_unknown_fields)]
pub enum Verbosity {
    Quiet,
    Verbose,
}

/// The protocol version to be used by a peer.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Copy, Clone, Default)]
#[serde(deny_unknown_fields)]
pub enum ProtocolVersion {
    #[default]
    V02,
    V03,
}

/// Configuration data for a single Rosenpass peer
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosenpassPeer {
    /// path to the public key of the peer
    pub public_key: PathBuf,

    /// The hostname and port to connect to
    ///
    /// Can be a
    ///
    /// - hostname and port, e.g. `localhost:8876` or `rosenpass.eu:1427`
    /// - IPv4 address and port, e.g. `1.2.3.4:7764`
    /// - IPv6 address and port, e.g. `[fe80::24]:7890`
    pub endpoint: Option<String>,

    /// path to the pre-shared key shared with the peer
    ///
    /// NOTE: this item can be skipped in the config if you do not use a pre-shared key with the peer
    pub pre_shared_key: Option<PathBuf>,

    /// If this field is set to a path, the Rosenpass will write the exchanged symmetric keys
    /// to the given file and write a notification to standard out to let the calling application
    /// know that a new key was exchanged
    #[serde(default)]
    pub key_out: Option<PathBuf>,

    /// Information for supplying exchanged keys directly to WireGuard
    #[serde(flatten, deserialize_with = "WireGuard::deserialize_optional")]
    pub wg: Option<WireGuard>,

    #[serde(default)]
    /// The protocol version to use for the exchange
    pub protocol_version: ProtocolVersion,

    /// Allows using a custom domain separator
    #[serde(flatten)]
    pub osk_domain_separator: RosenpassPeerOskDomainSeparator,
}

/// Configuration for [crate::protocol::osk_domain_separator::OskDomainSeparator]
///
/// Refer to its documentation for more information and examples of how to use this.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosenpassPeerOskDomainSeparator {
    /// If Rosenpass is used for purposes other then securing WireGuard,
    /// a custom domain separator and domain separator must be specified.
    ///
    /// Use `osk_organization` to indicate the organization who specifies the use case
    /// and `osk_label` for a specific purpose within that organization.
    ///
    /// ```toml
    /// [[peer]]
    /// public_key = "my_public_key"
    /// ...
    /// osk_organization = "myorg.com"
    /// osk_label = ["My Custom Messenger app"]
    /// ```
    pub osk_organization: Option<String>,
    // If Rosenpass is used for purposes other then securing WireGuard,
    /// a custom domain separator and domain separator must be specified.
    ///
    /// Use `osk_organization` to indicate the organization who specifies the use case
    /// and `osk_label` for a specific purpose within that organization.
    ///
    /// ```toml
    /// [[peer]]
    /// public_key = "my_public_key"
    /// ...
    /// osk_namespace = "myorg.com"
    /// osk_label = ["My Custom Messenger app"]
    /// ```
    pub osk_label: Option<Vec<String>>,
}

impl RosenpassPeerOskDomainSeparator {
    pub fn org_and_label(&self) -> anyhow::Result<Option<(&String, &Vec<String>)>> {
        match (&self.osk_organization, &self.osk_label) {
            (None, None) => Ok(None),
            (Some(org), Some(label)) => Ok(Some((org, label))),
            (Some(_), None) => bail!(
                "Specified osk_organization but not osk_label in config file. You need to specify both, or none."
            ),
            (None, Some(_)) => bail!(
                "Specified osk_label but not osk_organization in config file. You need to specify both, or none."
            ),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let _org_and_label: Option<(_, _)> = self.org_and_label()?;
        Ok(())
    }
}

impl TryFrom<RosenpassPeerOskDomainSeparator> for OskDomainSeparator {
    type Error = anyhow::Error;

    fn try_from(val: RosenpassPeerOskDomainSeparator) -> anyhow::Result<Self> {
        match val.org_and_label()? {
            None => Ok(OskDomainSeparator::default()),
            Some((org, label)) => Ok(OskDomainSeparator::custom_utf8(org, label)),
        }
    }
}

/// Information for supplying exchanged keys directly to WireGuard
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuard {
    /// Name of the WireGuard interface to supply with pre-shared keys generated by the Rosenpass
    /// key exchange
    pub device: String,

    /// WireGuard public key of the peer to supply with pre-shared keys
    pub peer: String,

    /// our WireGuard public key – required since protocol version 3
    #[serde(default)]
    pub our_wg_pubkey: Option<String>,

    /// Extra parameters passed to the `wg` command
    #[serde(default)]
    pub extra_params: Vec<String>,
}

impl WireGuard {
    /// deserializes the entirety of the WireGuard protocol extension config
    /// for one [`RosenpassPeer`]
    ///
    /// - If any of the WireGuard extension's config keys are present, this
    /// returns `Some(WireGuard)`. All of the extension's config keys must
    /// be absent to return `None`.
    /// - The deserializer ensures that `device` and `peer` are set if any of
    /// the other WireGuard extensions config keys are present.
    ///
    /// TODO: write tests for this deserialization
    fn deserialize_optional<'de, D>(deserializer: D) -> Result<Option<Self>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        // A flattened Option<WireGuard> silently discards missing required fields.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            device: Option<String>,
            peer: Option<String>,
            our_wg_pubkey: Option<String>,
            extra_params: Option<Vec<String>>,
        }

        let fields = Fields::deserialize(deserializer)?;

        match (
            fields.device,
            fields.peer,
            fields.our_wg_pubkey,
            fields.extra_params,
        ) {
            // if all fields are are None, the WireGuard extension is actually not used
            (None, None, None, None) => Ok(None),

            // if any field is Some(_), the WireGuard extension seems to be in use
            (device, peer, our_wg_pubkey, extra_params) => Ok(Some(Self {
                // `device` and `peer` are required if the WireGuard extension is used
                device: device.ok_or_else(|| D::Error::missing_field("device"))?,
                peer: peer.ok_or_else(|| D::Error::missing_field("peer"))?,
                // `our_wg_pubkey` is optional because it is only required since protocol version 3.
                // `crate::config::Rosenpass::validate` will catch incosistencies depending on protocol version.
                our_wg_pubkey,
                // extra_params is optional and will just default to an empty list
                extra_params: extra_params.unwrap_or_default(),
            })),
        }
    }
}

/// decode a base64-encoded WireGuard public key (32 bytes) into a [`PublicSymKey`]
pub fn decode_wg_pubkey_b64(b64_encoded_key: &str) -> anyhow::Result<PublicSymKey> {
    let mut pubkey: PublicSymKey = [0u8; _];

    let decoded_len = Base64::decode(b64_encoded_key, &mut pubkey)
        .context("can not decode base64-encoded WireGuard public key")?
        .len();

    ensure!(
        decoded_len == pubkey.len(),
        "invalid WireGuard public key length: expected {} bytes, got {decoded_len} bytes",
        pubkey.len()
    );

    Ok(pubkey)
}
#[cfg(test)]
mod test_decode_wg_pubkey_b64 {
    use super::{Base64, Encoding, decode_wg_pubkey_b64};

    // valid WireGuard public key: 32 decoded bytes public X25519 key
    const VALID: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    // invalid WireGuard public keys
    const TOO_SHORT: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTg==";
    const TOO_LONG: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmoA";
    // TODO: add more tests

    #[test]
    fn test_decode_wg_pubkey_b64() {
        let decoded = decode_wg_pubkey_b64(VALID).unwrap();
        let mut reencoded: [u8; _] = [0; 44];
        Base64::encode(&decoded, &mut reencoded).unwrap();
        let reencoded = String::from_utf8(reencoded.to_vec()).unwrap();
        assert_eq!(reencoded.as_str(), VALID);
    }

    #[test]
    #[should_panic = "can not decode base64-encoded WireGuard public key"]
    fn test_decode_wg_pubkey_b64_rejects_too_long() {
        decode_wg_pubkey_b64(TOO_LONG).unwrap();
    }

    #[test]
    #[should_panic = "invalid WireGuard public key length: expected 32 bytes, got 31 bytes"]
    fn test_decode_wg_pubkey_b64_rejects_too_short() {
        decode_wg_pubkey_b64(TOO_SHORT).unwrap();
    }
}

impl Default for Rosenpass {
    /// Generate an empty configuration
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../tests/config_Rosenpass_new.rs")]
    #[doc = "```"]
    fn default() -> Self {
        Self::empty()
    }
}

impl Rosenpass {
    /// load configuration from a TOML file
    ///
    /// NOTE: no validation is conducted, e.g. the paths specified in the configuration are not
    /// checked whether they even exist.
    ///
    /// ## TODO
    ///
    /// - consider using a different algorithm to determine home directory – the below one may
    ///   behave unexpectedly on Windows
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../tests/config_Rosenpass_store.rs")]
    #[doc = "```"]
    pub fn load<P: AsRef<Path>>(p: P) -> anyhow::Result<Self> {
        // read file and deserialize
        let mut config: Self = toml::from_str(&fs::read_to_string(&p)?)?;

        // resolve `~` (see https://github.com/rosenpass/rosenpass/issues/237)
        use util::resolve_path_with_tilde;
        if let Some(ref mut keypair) = config.keypair {
            resolve_path_with_tilde(&mut keypair.public_key);
            resolve_path_with_tilde(&mut keypair.secret_key);
        }
        for peer in config.peers.iter_mut() {
            resolve_path_with_tilde(&mut peer.public_key);
            if let Some(psk) = &mut peer.pre_shared_key {
                resolve_path_with_tilde(psk);
            }
            if let Some(ko) = &mut peer.key_out {
                resolve_path_with_tilde(ko);
            }
        }

        // add path to "self"
        p.as_ref().clone_into(&mut config.config_file_path);

        // return
        Ok(config)
    }

    /// Encode a configuration object as toml and write it to a file
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../tests/config_Rosenpass_store.rs")]
    #[doc = "```"]
    pub fn store<P: AsRef<Path>>(&self, p: P) -> anyhow::Result<()> {
        let serialized_config =
            toml::to_string_pretty(&self).expect("unable to serialize the default config");
        fs::write(p, serialized_config)?;
        Ok(())
    }

    /// Commit the configuration to where it came from, overwriting the original file
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../tests/config_Rosenpass_store.rs")]
    #[doc = "```"]
    pub fn commit(&self) -> anyhow::Result<()> {
        let mut f = fopen_w(&self.config_file_path, Visibility::Public)?;
        f.write_all(toml::to_string_pretty(&self)?.as_bytes())?;

        self.store(&self.config_file_path)
    }

    /// Apply the configuration in this object to the given [crate::app_server::AppServer]
    pub fn apply_to_app_server(&self, _srv: &mut AppServer) -> anyhow::Result<()> {
        #[cfg(feature = "experiment_api")]
        self.api.apply_to_app_server(_srv)?;
        Ok(())
    }

    /// Check that the configuration is sound, ensuring
    /// for instance that the referenced files exist
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../tests/config_Rosenpass_validate.rs")]
    #[doc = "```"]
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(ref keypair) = self.keypair {
            // check the public key file exists
            ensure!(
                keypair.public_key.is_file(),
                "could not find public-key file {:?}: no such file. Consider running `rosenpass gen-keys` to generate a new keypair.",
                keypair.public_key
            );

            // check the public-key file is a valid key
            ensure!(
                SPk::load(&keypair.public_key).is_ok(),
                "could not load public-key file {:?}: invalid key",
                keypair.public_key
            );

            // check the secret-key file exists
            ensure!(
                keypair.secret_key.is_file(),
                "could not find secret-key file {:?}: no such file. Consider running `rosenpass gen-keys` to generate a new keypair.",
                keypair.secret_key
            );

            // check the secret-key file is a valid key
            ensure!(
                SSk::load(&keypair.secret_key).is_ok(),
                "could not load secret-key file {:?}: invalid key",
                keypair.secret_key
            );
        }

        for (i, peer) in self.peers.iter().enumerate() {
            // check peer's public-key file exists
            ensure!(
                peer.public_key.is_file(),
                "peer {i} public-key file {:?} does not exist",
                peer.public_key
            );

            // check peer's public-key file is a valid key
            ensure!(
                SPk::load(&peer.public_key).is_ok(),
                "peer {i} public-key file {:?} is invalid",
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

            // check if `key_out` or `device` and `peer` are defined
            // TODO: this check is a bit messy, first introduced in b9e873e53475a7024a9608af7ceec6d53773153d
            if peer.key_out.is_none() {
                if let Some(wg) = &peer.wg {
                    if wg.device.is_empty() || wg.peer.is_empty() {
                        bail!("peer {i} has neither `key_out` nor valid wireguard config defined");
                    }
                } else {
                    bail!("peer {i} has neither `key_out` nor valid wireguard config defined");
                }
            }

            // check the WireGuard key binding configuration
            if let Some(wg) = &peer.wg {
                if peer.protocol_version == ProtocolVersion::V03 {
                    ensure!(
                        wg.our_wg_pubkey.is_some(),
                        "peer {i} uses protocol version V03 and has a wireguard config, but no \
                         `our_wg_pubkey` is set"
                    );
                }
                if let Some(our_wg_pubkey) = &wg.our_wg_pubkey {
                    ensure!(
                        decode_wg_pubkey_b64(our_wg_pubkey).is_ok(),
                        "peer {i} has an invalid `our_wg_pubkey` (expected a base64-encoded 32-byte key)"
                    );
                }
            }

            if let Err(e) = peer.osk_domain_separator.validate() {
                bail!("Invalid OSK domain separation configuration for peer {i}: {e}");
            }
        }

        Ok(())
    }

    /// Check that the configuration is useful given the feature set Rosenpass was compiled with
    /// and the configuration values.
    ///
    /// This was introduced when we introduced a unix-socket API feature allowing the server
    /// keypair to be supplied via the API; in this process we also made [Self::keypair] optional.
    /// With respect to this particular feature, this function ensures that [Self::keypair] is set
    /// when Rosenpass is compiles without the `experiment_api` flag. When `experiment_api` is
    /// used, the function ensures that [Self::keypair] is only `None`, if the Rosenpass API is
    /// enabled in the configuration.
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../tests/config_Rosenpass_validate.rs")]
    #[doc = "```"]
    pub fn check_usefullness(&self) -> anyhow::Result<()> {
        #[cfg(not(feature = "experiment_api"))]
        ensure!(self.keypair.is_some(), "Server keypair missing.");

        #[cfg(feature = "experiment_api")]
        ensure!(
            self.keypair.is_some() || self.api.has_api_sources(),
            "{}{}",
            "Specify a server keypair or some API connections to configure the keypair with.",
            "Without a keypair, rosenpass can not operate."
        );

        Ok(())
    }

    /// Produce an empty confuguration
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../tests/config_Rosenpass_new.rs")]
    #[doc = "```"]
    pub fn empty() -> Self {
        Self::new(None)
    }

    /// Produce configuration from the keypair
    ///
    /// Shorthand for calling [Self::new] with Some([Keypair]::new(sk, pk)).
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../tests/config_Rosenpass_new.rs")]
    #[doc = "```"]
    pub fn from_sk_pk<Sk: AsRef<Path>, Pk: AsRef<Path>>(sk: Sk, pk: Pk) -> Self {
        Self::new(Some(Keypair::new(pk, sk)))
    }

    /// Initialize a minimal configuration with the [Self::keypair] field supplied
    /// as a parameter
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../tests/config_Rosenpass_new.rs")]
    #[doc = "```"]
    pub fn new(keypair: Option<Keypair>) -> Self {
        Self {
            keypair,
            listen: vec![],
            #[cfg(feature = "experiment_api")]
            api: crate::api::config::ApiConfig::default(),
            verbosity: Verbosity::Quiet,
            peers: vec![],
            config_file_path: PathBuf::new(),
        }
    }

    /// Add IPv4 __and__ IPv6 IF_ANY address to the listen interfaces
    ///
    /// I.e. listen on any interface.
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../tests/config_Rosenpass_add_if_any.rs")]
    #[doc = "```"]
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

    /// Parser for the old, IP style grammar.
    ///
    /// See out manual page rosenpass-exchange(1) on details about the grammar.
    ///
    /// This function parses the grammar and turns it into an instance of the configuration
    /// struct.
    ///
    /// TODO: the grammar is undecidable, what do we do here?
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../tests/config_Rosenpass_parse_args_simple.rs")]
    #[doc = "```"]
    pub fn parse_args(args: Vec<String>) -> anyhow::Result<Self> {
        let mut config = Self::new(Some(Keypair::new("", "")));

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
                (Own, "private-key", None) => {
                    log::warn!(
                        "the private-key argument is deprecated, please use secret-key instead"
                    );
                    OwnSecretKey
                }
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
                    config.keypair.as_mut().unwrap().public_key = pk.into();
                    Own
                }
                (OwnSecretKey, sk, None) => {
                    ensure!(
                        already_set.insert(OwnSecretKey),
                        "secret-key was already set"
                    );
                    config.keypair.as_mut().unwrap().secret_key = sk.into();
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

impl Default for Verbosity {
    /// Self::Quiet
    fn default() -> Self {
        Self::Quiet
    }
}

/// Example configuration generated by the command `rosenpass gen-config <TOML-FILE>`.
pub static EXAMPLE_CONFIG: &str = r###"public_key = "/path/to/rp-public-key"
secret_key = "/path/to/rp-secret-key"
listen = [] # socket address to listen on (e.g. "[::]:10002")
verbosity = "Verbose" # options: "Quiet", "Verbose"

[[peers]]
# Commented out fields are optional
public_key = "/path/to/rp-peer-public-key"
endpoint = "127.0.0.1:9998"
# pre_shared_key = "/path/to/preshared-key"

# Choose to store the key in a file via `key_out` or pass it to WireGuard.
# You can also choose to do both.

# ========== outfile option ==========
# You can save the key from the handshake to a file.
key_out = "/path/to/rp-key-out.txt" # path to store the key

# ========== options for the WireGuard extension ==========
# Using the WireGuard extension is optional.
# See the whitepaper section 3.2 for more information.
# https://rosenpass.eu/docs/whitepaper

# device = "wg0" # WireGuard interface
# peer = "RULdRAtUw7SFfVfGD..." # WireGuard public key
# our_wg_pubkey = "LDn3YQZ3+4V..." # our WireGuard public key, required since protocol version 3
# extra_params = [] # passed to WireGuard `wg set`
"###;

#[cfg(test)]
mod test {

    use super::*;
    use std::borrow::Borrow;

    fn toml_des<S: Borrow<str>>(s: S) -> Result<toml::Table, toml::de::Error> {
        toml::from_str(s.borrow())
    }

    fn toml_ser<S: Serialize>(s: S) -> Result<toml::Table, toml::ser::Error> {
        toml::Table::try_from(s)
    }

    fn assert_toml<L: Serialize, R: Borrow<str>>(l: L, r: R, info: &str) -> anyhow::Result<()> {
        fn lines_prepend(prefix: &str, s: &str) -> anyhow::Result<String> {
            use std::fmt::Write;

            let mut buf = String::new();
            for line in s.lines() {
                writeln!(&mut buf, "{prefix}{line}")?;
            }
            Ok(buf)
        }

        let l = toml_ser(l)?;
        let r = toml_des(r.borrow())?;
        ensure!(
            l == r,
            "{}{}TOML value mismatch.\n  Have:\n{}\n  Expected:\n{}",
            info,
            if info.is_empty() { "" } else { ": " },
            lines_prepend("    ", &toml::to_string_pretty(&l)?)?,
            lines_prepend("    ", &toml::to_string_pretty(&r)?)?
        );
        Ok(())
    }

    fn assert_toml_round<'de, L: Serialize + Deserialize<'de>, R: Borrow<str>>(
        l: L,
        r: R,
    ) -> anyhow::Result<()> {
        let l = toml_ser(l)?;
        assert_toml(&l, r.borrow(), "Straight deserialization")?;

        let l: L = l.try_into().unwrap();
        let l = toml_ser(l).unwrap();
        assert_toml(l, r.borrow(), "Roundtrip deserialization")?;

        Ok(())
    }

    fn split_str(s: &str) -> Vec<String> {
        s.split(' ').map(|s| s.to_string()).collect()
    }

    #[test]
    fn toml_serialization() -> anyhow::Result<()> {
        #[cfg(feature = "experiment_api")]
        assert_toml_round(
            Rosenpass::empty(),
            r#"
            listen = []
            verbosity = "Quiet"
            peers = []

            [api]
            listen_path = []
            listen_fd = []
            stream_fd = []
        "#,
        )?;

        #[cfg(not(feature = "experiment_api"))]
        assert_toml_round(
            Rosenpass::empty(),
            r#"
            listen = []
            verbosity = "Quiet"
            peers = []
        "#,
        )?;

        #[cfg(feature = "experiment_api")]
        assert_toml_round(
            Rosenpass::from_sk_pk("/my/sk", "/my/pk"),
            r#"
            public_key = "/my/pk"
            secret_key = "/my/sk"
            listen = []
            verbosity = "Quiet"
            peers = []

            [api]
            listen_path = []
            listen_fd = []
            stream_fd = []
        "#,
        )?;

        #[cfg(not(feature = "experiment_api"))]
        assert_toml_round(
            Rosenpass::from_sk_pk("/my/sk", "/my/pk"),
            r#"
            public_key = "/my/pk"
            secret_key = "/my/sk"
            listen = []
            verbosity = "Quiet"
            peers = []
        "#,
        )?;

        Ok(())
    }

    #[test]
    fn test_protocol_version() {
        let mut rosenpass = Rosenpass::empty();
        let mut peer_v_02 = RosenpassPeer::default();
        peer_v_02.protocol_version = ProtocolVersion::V02;
        rosenpass.peers.push(peer_v_02);
        let mut peer_v_03 = RosenpassPeer::default();
        peer_v_03.protocol_version = ProtocolVersion::V03;
        rosenpass.peers.push(peer_v_03);
        #[cfg(feature = "experiment_api")]
        {
            rosenpass.api.listen_fd = vec![];
            rosenpass.api.listen_path = vec![];
            rosenpass.api.stream_fd = vec![];
        }
        #[cfg(feature = "experiment_api")]
        let expected_toml = r#"listen = []
          verbosity = "Quiet"
          
          [api]
          listen_fd = []
          listen_path = []
          stream_fd = []

          [[peers]]
          protocol_version = "V02"
          public_key = ""

          [[peers]]
          protocol_version = "V03"
          public_key = ""
          "#;
        #[cfg(not(feature = "experiment_api"))]
        let expected_toml = r#"listen = []
          verbosity = "Quiet"

          [[peers]]
          protocol_version = "V02"
          public_key = ""

          [[peers]]
          protocol_version = "V03"
          public_key = ""
          "#;
        assert_toml_round(rosenpass, expected_toml).unwrap()
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

        assert_eq!(
            config.keypair,
            Some(Keypair::new("/my/public-key", "/my/secret-key"))
        );
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

pub mod util {
    use std::path::{Path, PathBuf};
    /// takes a path that can potentially start with a `~` and resolves that `~` to the user's home directory
    ///
    /// ## Example
    /// ```
    /// use rosenpass::oldconfig::util::resolve_path_with_tilde;
    /// let home = home::home_dir().unwrap();
    /// let mut path = std::path::PathBuf::from("~/foo.toml");
    /// resolve_path_with_tilde(&mut path);
    /// assert!(path == home.join("foo.toml"));
    /// ```
    pub fn resolve_path_with_tilde(path: &mut PathBuf) {
        if let Some(first_segment) = path.iter().next() {
            if !path.has_root() && first_segment == "~" {
                let home_dir = home::home_dir().unwrap_or_else(|| {
                    log::error!("config file contains \"~\" but can not determine home diretory");
                    std::process::exit(1);
                });
                let orig_path = path.clone();
                path.clear();
                path.push(home_dir);
                for segment in orig_path.iter().skip(1) {
                    path.push(segment);
                }
            }
        }
    }
    /// takes a path that can be relative to a working directory or might start with a `~` and resolves it
    ///
    /// Note: `working_diretory` may not start with a tilde.
    ///
    /// ```
    /// use rosenpass::oldconfig::util::resolve_relative_path_with_tilde;
    /// let path = std::path::PathBuf::from("foo.toml");
    /// let working_directory = std::path::PathBuf::from("some_dir");
    /// let resolved_path = resolve_relative_path_with_tilde(&path, &working_directory);
    /// assert!(resolved_path == working_directory.join(path));
    /// ```
    pub fn resolve_relative_path_with_tilde(
        path: &Path,
        working_directory: &Path,
    ) -> PathBuf {
        let mut path = path.to_owned();
        resolve_path_with_tilde(&mut path);
        if !path.is_relative() {
            path
        } else {
            working_directory.join(path)
        }
    }

    pub trait ResolvePathWithTilde<WDT> {
        fn resolve_relative_with_tilde(&self, working_directory: WDT) -> PathBuf;
    }
    impl ResolvePathWithTilde<&Path> for PathBuf {
        fn resolve_relative_with_tilde(&self, working_directory: &Path) -> PathBuf {
            resolve_relative_path_with_tilde(self, working_directory)
        }
    }
    impl ResolvePathWithTilde<PathBuf> for PathBuf {
        fn resolve_relative_with_tilde(&self, working_directory: PathBuf) -> PathBuf {
            resolve_relative_path_with_tilde(self, &working_directory)
        }
    }
    impl ResolvePathWithTilde<&Path> for &Path {
        fn resolve_relative_with_tilde(&self, working_directory: &Path) -> PathBuf {
            resolve_relative_path_with_tilde(self, working_directory)
        }
    }
    impl ResolvePathWithTilde<PathBuf> for &Path {
        fn resolve_relative_with_tilde(&self, working_directory: PathBuf) -> PathBuf {
            resolve_relative_path_with_tilde(self, &working_directory)
        }
    }

    #[cfg(test)]
    mod test {
        use std::str::FromStr;

        use super::*;
        #[test]
        fn test_resolve_path_with_tilde() {
            let test = |path_str: &str, resolved: PathBuf| {
                let mut path = PathBuf::from(path_str);
                resolve_path_with_tilde(&mut path);
                assert!(
                    path == resolved,
                    "Path {:?} has been resolved to {:?} but should have been resolved to {:?}.",
                    path_str,
                    path,
                    resolved
                );
            };
            // do not use `std::env::set_var` here because it is unsound in multi-threaded
            // programs and tests are run multi-threaded by default
            let home_dir = home::home_dir().expect("can not determine home directory");

            // should resolve
            test("~/foo.toml", home_dir.join("foo.toml"));
            test("~//foo", home_dir.join("foo"));
            test("~/../other_user/foo", home_dir.join("../other_user/foo"));

            // should _not_ resolve
            test("~foo/bar", PathBuf::from("~foo/bar"));
            test(".~/foo", PathBuf::from(".~/foo"));
            test("/~/foo.toml", PathBuf::from("/~/foo.toml"));
            test(r"~\foo", PathBuf::from(r"~\foo"));
            test(r"C:\~\foo.toml", PathBuf::from(r"C:\~\foo.toml"));
        }
        #[test]
        fn test_resolve_relative_path_with_tilde() {
            let home_dir = home::home_dir().expect("can not determine home directory");
            let working_dir = PathBuf::from("/foo/bar");
            assert_ne!(
                home_dir, working_dir,
                "home dir and working dir are unexpectedly the same"
            );
            let test = |path_str: &str, resolved: PathBuf| {
                let result =
                    resolve_relative_path_with_tilde(&PathBuf::from(path_str), &working_dir);
                assert_eq!(
                    result, resolved,
                    "Path {:?} has been resolved to {:?} but should have been resolved to {:?}.",
                    path_str, result, resolved
                )
            };

            // should resolve
            test("~/foo.toml", home_dir.join("foo.toml"));
            test("foo.toml", working_dir.join("foo.toml"));
            test("a/b.toml", working_dir.join("a").join("b.toml"));

            // should _not_ resolve
            // TODO
        }
    }
}
