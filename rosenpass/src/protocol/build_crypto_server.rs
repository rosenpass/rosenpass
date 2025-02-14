use rosenpass_util::{
    build::Build,
    mem::{DiscardResultExt, SwapWithDefaultExt},
    result::ensure_or,
};
use thiserror::Error;
use crate::config::ProtocolVersion;
use super::{CryptoServer, PeerPtr, SPk, SSk, SymKey};

#[derive(Debug, Clone)]
/// A pair of matching public/secret keys used to launch the crypto server.
///
/// # Examples
///
/// Decomposing a key pair into its individual components, then recreating it:
///
/// ```rust
/// use rosenpass::protocol::Keypair;
///
/// // We have to define the security policy before using Secrets.
/// use rosenpass_secret_memory::secret_policy_use_only_malloc_secrets;
/// secret_policy_use_only_malloc_secrets();
///
/// let random_pair = Keypair::random();
/// let random_copy = random_pair.clone();
/// let (sk_copy, pk_copy) = random_copy.into_parts();
///
/// // Re-assemble the key pair from the original secret/public key
/// // Note that it doesn't have to be the exact same keys;
/// // you could just as easily use a completely different pair here
/// let reconstructed_pair = Keypair::from_parts((sk_copy, pk_copy));
///
/// assert_eq!(random_pair.sk.secret(), reconstructed_pair.sk.secret());
/// assert_eq!(random_pair.pk, reconstructed_pair.pk);
/// ```
pub struct Keypair {
    /// Secret key matching the crypto server's public key.
    pub sk: SSk,
    /// Public key identifying the crypto server instance.
    pub pk: SPk,
}

// TODO: We need a named tuple derive
impl Keypair {
    /// Creates a new key pair from the given secret/public key components.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rosenpass::protocol::{Keypair, SSk, SPk};
    ///
    /// // We have to define the security policy before using Secrets.
    /// use rosenpass_secret_memory::secret_policy_use_only_malloc_secrets;
    /// secret_policy_use_only_malloc_secrets();
    ///
    /// let random_sk = SSk::random();
    /// let random_pk = SPk::random();
    /// let random_pair = Keypair::new(random_sk.clone(), random_pk.clone());
    ///
    /// assert_eq!(random_sk.secret(), random_pair.sk.secret());
    /// assert_eq!(random_pk, random_pair.pk);
    /// ```
    pub fn new(sk: SSk, pk: SPk) -> Self {
        Self { sk, pk }
    }

    /// Creates a new "empty" key pair. All bytes are initialized to zero.
    ///
    /// See [SSk:zero()][crate::protocol::SSk::zero] and [SPk:zero()][crate::protocol::SPk::zero], respectively.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rosenpass::protocol::{Keypair, SSk, SPk};
    ///
    /// // We have to define the security policy before using Secrets.
    /// use rosenpass_secret_memory::secret_policy_use_only_malloc_secrets;
    /// secret_policy_use_only_malloc_secrets();
    ///
    /// let zero_sk = SSk::zero();
    /// let zero_pk = SPk::zero();
    /// let zero_pair = Keypair::zero();
    ///
    /// assert_eq!(zero_sk.secret(), zero_pair.sk.secret());
    /// assert_eq!(zero_pk, zero_pair.pk);
    /// ```
    pub fn zero() -> Self {
        Self::new(SSk::zero(), SPk::zero())
    }

    /// Creates a new (securely-)random key pair. The mechanism is described in [rosenpass_secret_memory::Secret].
    ///
    /// See [SSk:random()][crate::protocol::SSk::random] and [SPk:random()][crate::protocol::SPk::random], respectively.
    pub fn random() -> Self {
        Self::new(SSk::random(), SPk::random())
    }

    /// Creates a new key pair from the given public/secret key components.
    pub fn from_parts(parts: (SSk, SPk)) -> Self {
        Self::new(parts.0, parts.1)
    }

    /// Deconstructs the key pair, yielding the individual public/secret key components.
    pub fn into_parts(self) -> (SSk, SPk) {
        (self.sk, self.pk)
    }
}

#[derive(Error, Debug)]
#[error("PSK already set in BuildCryptoServer")]
/// Error indicating that the PSK is already set.
/// Unused in the current version of the protocol.
pub struct PskAlreadySet;

#[derive(Error, Debug)]
#[error("Keypair already set in BuildCryptoServer")]
/// Error type indicating that the public/secret key pair has already been set.
pub struct KeypairAlreadySet;

#[derive(Error, Debug)]
#[error("Can not construct CryptoServer: Missing keypair")]
/// Error type indicating that no public/secret key pair has been provided.
pub struct MissingKeypair;

#[derive(Debug, Default)]
/// Builder for setting up a [CryptoServer] (with deferred initialization).
///
/// There are multiple ways of creating a crypto server:
///
/// 1. Provide the key pair at initialization time (using [CryptoServer::new][crate::protocol::CryptoServer::new])
/// 2. Provide the key pair at a later time (using [BuildCryptoServer::empty])
///
/// With BuildCryptoServer, you can gradually configure parameters as they become available.
/// This may be useful when they depend on runtime conditions or have to be fetched asynchronously.
/// It's possible to use the builder multiple times; it then serves as a "blueprint" for new
/// instances, several of which may be spawned with the same base configuration (or variations thereof).
///
/// Note that the server won't actually launch without a key pair (expect a [MissingKeypair] error).
/// The setup will be much simplified if one is provided, at the cost of some flexibility.
/// It's however possible to defer this step in case your application requires it.
///
/// For additional details or examples, see [AppServer::crypto_site][crate::app_server::AppServer::crypto_site] and [ConstructionSite][rosenpass_util::build::ConstructionSite].
///
/// # Example
///
/// ```rust
/// use rosenpass_util::build::Build;
/// use rosenpass::protocol::{BuildCryptoServer, Keypair, PeerParams, SPk, SymKey};
/// use rosenpass::config::ProtocolVersion;
///
/// // We have to define the security policy before using Secrets.
/// use rosenpass_secret_memory::secret_policy_use_only_malloc_secrets;
/// secret_policy_use_only_malloc_secrets();
///
/// let keypair = Keypair::random();
/// let peer1 = PeerParams { psk: Some(SymKey::random()), pk: SPk::random(), protocol_version: ProtocolVersion::V02 };
/// let peer2 = PeerParams { psk: None, pk: SPk::random(), protocol_version: ProtocolVersion::V02 };
///
/// let mut builder = BuildCryptoServer::new(Some(keypair.clone()), vec![peer1]);
/// builder.add_peer(peer2.psk.clone(), peer2.pk, ProtocolVersion::V02);
///
/// let server = builder.build().expect("build failed");
/// assert_eq!(server.peers.len(), 2);
/// assert_eq!(server.sskm.secret(), keypair.sk.secret());
/// assert_eq!(server.spkm, keypair.pk);
/// ```
pub struct BuildCryptoServer {
    /// The key pair (secret/public key) identifying the crypto server instance.
    pub keypair: Option<Keypair>,
    /// A list of network peers that should be registered when launching the server.
    pub peers: Vec<PeerParams>,
}

impl Build<CryptoServer> for BuildCryptoServer {
    type Error = anyhow::Error;

    /// Creates a crypto server, adding all peers that have previously been registered.
    ///
    /// You must provide a key pair at the time of instantiation.
    /// If the list of peers is outdated, building the server will fail.
    ///
    /// In this case, make sure to remove or re-add any peers that may have changed.
    fn build(self) -> Result<CryptoServer, Self::Error> {
        let Some(Keypair { sk, pk }) = self.keypair else {
            return Err(MissingKeypair)?;
        };

        let mut srv = CryptoServer::new(sk, pk);

        for (idx, PeerParams { psk, pk , protocol_version}) in self.peers.into_iter().enumerate() {
            let PeerPtr(idx2) = srv.add_peer(psk, pk, protocol_version.into())?;
            assert!(idx == idx2, "Peer id changed during CryptoServer construction from {idx} to {idx2}. This is a developer error.")
        }

        Ok(srv)
    }
}

#[derive(Debug)]
/// Cryptographic key(s) identifying the connected [peer][crate::protocol::Peer] ("client")
/// for a given session that is being managed by the crypto server.
///
/// Each peer must be identified by a [public key (SPk)][crate::protocol::SPk].
/// Optionally, a [symmetric key (SymKey)][crate::protocol::SymKey]
/// can be provided when setting up the connection.
/// For more information on the intended usage and security considerations, see [Peer::psk][crate::protocol::Peer::psk] and [Peer::spkt][crate::protocol::Peer::spkt].
pub struct PeerParams {
    /// Pre-shared (symmetric) encryption keys that should be used with this peer.
    pub psk: Option<SymKey>,
    /// Public key identifying the peer.
    pub pk: SPk,
    /// The used protocol version.
    pub protocol_version: ProtocolVersion,
}

impl BuildCryptoServer {
    /// Creates a new builder instance using the given key pair and peer list.
    pub fn new(keypair: Option<Keypair>, peers: Vec<PeerParams>) -> Self {
        Self { keypair, peers }
    }

    /// Creates an "incomplete" builder instance, without assigning a key pair.
    pub fn empty() -> Self {
        Self::new(None, Vec::new())
    }

    /// Creates a builder instance from the given key pair and peer list components.
    pub fn from_parts(parts: (Option<Keypair>, Vec<PeerParams>)) -> Self {
        Self {
            keypair: parts.0,
            peers: parts.1,
        }
    }

    /// Deconstructs the current builder instance, taking ownership of its key pair and peer list.
    ///
    /// Replaces all parameters with their default values, which allows extracting them
    /// while leaving the builder in a reusable state.
    pub fn take_parts(&mut self) -> (Option<Keypair>, Vec<PeerParams>) {
        (self.keypair.take(), self.peers.swap_with_default())
    }

    /// Deconstructs the builder instance, yielding the assigned key pair and peer list.
    pub fn into_parts(mut self) -> (Option<Keypair>, Vec<PeerParams>) {
        self.take_parts()
    }

    /// Creates a new builder instance, assigning the given keypair to it.
    ///
    /// Note that only one key pair can be assigned (expect [KeypairAlreadySet] on failure).
    ///
    /// # Examples
    ///
    /// ## Adding key pairs to an existing builder
    ///
    /// ```rust
    /// // We have to define the security policy before using Secrets.
    /// use rosenpass_secret_memory::secret_policy_use_only_malloc_secrets;
    /// secret_policy_use_only_malloc_secrets();
    ///
    /// use rosenpass_util::build::Build;
    /// use rosenpass::protocol::{BuildCryptoServer, Keypair};
    ///
    /// // Deferred initialization: Create builder first, add the key pair later
    /// let mut builder = BuildCryptoServer::empty();
    /// // Do something with the builder ...
    ///
    /// // Quite some time may have passed (network/disk IO, runtime events, ...)
    /// // Now we've got a key pair that should be added to the configuration
    /// let keypair = Keypair::random();
    /// builder.with_keypair(keypair.clone()).expect("build with key pair failed");
    ///
    /// // New server instances can now make use of the assigned key pair
    /// let server = builder.build().expect("build failed");
    /// assert_eq!(server.sskm.secret(), keypair.sk.secret());
    /// assert_eq!(server.spkm, keypair.pk);
    /// ```
    ///
    /// ## Basic error handling: Re-assigning key pairs
    ///
    /// ```rust
    /// // We have to define the security policy before using Secrets.
    /// use rosenpass_secret_memory::secret_policy_use_only_malloc_secrets;
    /// secret_policy_use_only_malloc_secrets();
    ///
    /// use rosenpass_util::build::Build;
    /// use rosenpass::protocol::{BuildCryptoServer, Keypair, KeypairAlreadySet};
    ///
    /// // In this case, we'll create a functional builder from its various components
    /// // These could be salvaged from another builder, or obtained from disk/network (etc.)
    /// let keypair = Keypair::random();
    /// let mut builder = BuildCryptoServer::from_parts((Some(keypair.clone()), Vec::new()));
    ///
    /// // The builder has already been assigned a key pair, so this won't work
    /// let err = builder.with_keypair(keypair).expect_err("should fail to reassign key pair");
    /// assert!(matches!(err, KeypairAlreadySet));
    /// ```
    pub fn with_keypair(&mut self, keypair: Keypair) -> Result<&mut Self, KeypairAlreadySet> {
        ensure_or(self.keypair.is_none(), KeypairAlreadySet)?;
        self.keypair.insert(keypair).discard_result();
        Ok(self)
    }

    /// Creates a new builder instance, adding a new entry to the list of registered peers.
    ///
    /// # Example
    ///
    /// Adding peers to an existing builder:
    ///
    /// ```rust
    /// use rosenpass::config::ProtocolVersion;
    /// // We have to define the security policy before using Secrets.
    /// use rosenpass_secret_memory::secret_policy_use_only_malloc_secrets;
    /// secret_policy_use_only_malloc_secrets();
    ///
    /// use rosenpass_util::build::Build;
    /// use rosenpass::protocol::{BuildCryptoServer, Keypair, SymKey, SPk};
    ///
    /// // Deferred initialization: Create builder first, add some peers later
    /// let keypair_option = Some(Keypair::random());
    /// let mut builder = BuildCryptoServer::new(keypair_option, Vec::new());
    /// assert!(builder.peers.is_empty());
    ///
    /// // Do something with the builder ...
    ///
    /// // Quite some time may have passed (network/disk IO, runtime events, ...)
    /// // Now we've found a peer that should be added to the configuration
    /// let pre_shared_key = SymKey::random();
    /// let public_key = SPk::random();
    /// builder.with_added_peer(Some(pre_shared_key.clone()), public_key.clone(), ProtocolVersion::V02);
    ///
    /// // New server instances will then start with the peer being registered already
    /// let server = builder.build().expect("build failed");
    /// assert_eq!(server.peers.len(), 1);
    /// let peer = &server.peers[0];
    /// let peer_psk = Some(peer.psk.clone()).expect("PSK is None");
    /// assert_eq!(peer.spkt, public_key);
    /// assert_eq!(peer_psk.secret(), pre_shared_key.secret());
    /// ```
    pub fn with_added_peer(&mut self, psk: Option<SymKey>, pk: SPk, protocol_version: ProtocolVersion) -> &mut Self {
        // TODO: Check here already whether peer was already added
        self.peers.push(PeerParams { psk, pk, protocol_version });
        self
    }

    /// Add a new entry to the list of registered peers, with or without a pre-shared key.
    pub fn add_peer(&mut self, psk: Option<SymKey>, pk: SPk, protocol_version: ProtocolVersion) -> PeerPtr {
        let id = PeerPtr(self.peers.len());
        self.with_added_peer(psk, pk, protocol_version);
        id
    }

    /// Creates a new builder, taking ownership of another instance's key pair and peer list.
    /// Allows duplicating the current set of launch parameters, which can then be used to
    /// start multiple servers with the exact same configuration (or variants using it as a base).
    ///
    /// # Example
    ///
    ///  Extracting the server configuration from a builder:
    ///
    /// ```rust
    /// // We have to define the security policy before using Secrets.
    /// use rosenpass::config::ProtocolVersion;
    /// use rosenpass::hash_domains::protocol;
    /// use rosenpass_secret_memory::secret_policy_use_only_malloc_secrets;
    /// secret_policy_use_only_malloc_secrets();
    ///
    /// use rosenpass_util::build::Build;
    /// use rosenpass::protocol::{BuildCryptoServer, Keypair, SymKey, SPk};
    ///
    /// let keypair = Keypair::random();
    /// let peer_pk = SPk::random();
    /// let mut builder = BuildCryptoServer::new(Some(keypair.clone()), vec![]);
    /// builder.add_peer(None, peer_pk, ProtocolVersion::V02);
    ///
    /// // Extract configuration parameters from the decomissioned builder
    /// let (keypair_option, peers) = builder.take_parts();
    /// let extracted_keypair = keypair_option.unwrap();
    /// assert_eq!(extracted_keypair.sk.secret(), keypair.sk.secret());
    /// assert_eq!(extracted_keypair.pk, keypair.pk);
    /// assert_eq!(peers.len(), 1);
    ///
    /// // Now we can create a new builder with the same configuration
    /// let parts = (Some(extracted_keypair), peers);
    /// let mut reassembled_builder = BuildCryptoServer::from_parts(parts);
    /// let new_builder = reassembled_builder.emancipate();
    ///
    /// // Do something with the new builder ...
    ///
    /// // ... and now, deconstruct this one as well - still using the same parts
    /// let (keypair_option, peers) = new_builder.into_parts();
    /// let extracted_keypair = keypair_option.unwrap();
    /// assert_eq!(extracted_keypair.sk.secret(), keypair.sk.secret());
    /// assert_eq!(extracted_keypair.pk, keypair.pk);
    /// assert_eq!(peers.len(), 1);
    /// ```
    pub fn emancipate(&mut self) -> Self {
        Self::from_parts(self.take_parts())
    }
}
