//! Management of domain separators for the OSK (output key) in the rosenpass protocol
//!
//! The domain separator is there to ensure that keys are bound to the purpose they are used for.
//!
//! See the whitepaper section on protocol extensions for more details on how this is used.
//!
//! # See also
//!
//! - [crate::protocol::Peer]
//! - [crate::protocol::CryptoServer::add_peer]
//! - [crate::protocol::CryptoServer::osk]
//!
//! # Examples
//!
//! There are some basic examples of using custom domain separators in the examples of
//! [super::CryptoServer::poll]. Look for the test function `test_osk_label_mismatch()`
//! in particular.

use rosenpass_ciphers::subtle::keyed_hash::KeyedHash;
use rosenpass_util::result::OkExt;

use crate::hash_domains;

use super::basic_types::PublicSymKey;

/// The OSK (output shared key) domain separator to use for a specific peer
///
#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Default)]
pub enum OskDomainSeparator {
    /// By default we use the domain separator that indicates that the resulting keys
    /// are used by WireGuard to establish a connection
    #[default]
    ExtensionWireguardPsk,
    /// Used for user-defined domain separators
    Custom {
        /// A globally unique string identifying the vendor or group who defines this domain
        /// separator (we use our domain ourselves – "rosenpass.eu")
        namespace: Vec<u8>,
        /// Any custom labels within that namespace. Could be descriptive prose.
        labels: Vec<Vec<u8>>,
    },
}

impl OskDomainSeparator {
    /// Construct [OskDomainSeparator::ExtensionWireguardPsk]
    pub fn for_wireguard_psk() -> Self {
        Self::ExtensionWireguardPsk
    }

    /// Construct [OskDomainSeparator::Custom] from strings
    pub fn custom_utf8<I, T>(namespace: &str, label: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let namespace = namespace.as_bytes().to_owned();
        let labels = label
            .into_iter()
            .map(|e| e.as_ref().as_bytes().to_owned())
            .collect::<Vec<_>>();
        Self::Custom { namespace, labels }
    }

    /// Variant of [Self::custom_utf8] that takes just one label (instead of a sequence)
    pub fn custom_utf8_single_label(namespace: &str, label: &str) -> Self {
        Self::custom_utf8(namespace, std::iter::once(label))
    }

    /// The domain separator is not just an encoded string, it instead uses
    /// [rosenpass_ciphers::hash_domain::HashDomain], starting from [hash_domains::cke_user].
    ///
    /// This means, that the domain separator is really a sequence of multiple different domain
    /// separators, each of which is allowed to be quite long. This is very useful as it allows
    /// users to avoid specifying complex, prosaic domain separators. To ensure that this does not
    /// force us create extra overhead when the protocol is executed, this sequence of strings is
    /// compressed into a single, fixed-length hash of all the inputs. This hash could be created
    /// at program startup and cached.
    ///
    /// This function generates this fixed-length hash.
    pub fn compress_with(&self, hash_choice: KeyedHash) -> anyhow::Result<PublicSymKey> {
        use OskDomainSeparator as O;
        match &self {
            O::ExtensionWireguardPsk => hash_domains::ext_wireguard_psk_osk(hash_choice),
            O::Custom { namespace, labels } => hash_domains::cke_user(hash_choice)?
                .mix(namespace)?
                .mix_many(labels)?
                .into_value()
                .ok(),
        }
    }
}
