use crate::cfg;
use crate::protocol;
use anyhow::bail;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
/// Configuration data for a single Rosenpass peer
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
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
    #[serde(flatten)]
    pub wg: Option<cfg::WireGuard>,

    #[serde(default)]
    /// The protocol version to use for the exchange
    pub protocol_version: cfg::ProtocolVersion,

    /// Allows using a custom domain separator
    #[serde(flatten)]
    pub osk_domain_separator: cfg::OskDomainSeparator,
}

/// Configuration for [crate::protocol::OskDomainSeparator]
///
/// Refer to its documentation for more information and examples of how to use this.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OskDomainSeparator {
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

impl OskDomainSeparator {
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

impl TryFrom<OskDomainSeparator> for protocol::OskDomainSeparator {
    type Error = anyhow::Error;

    fn try_from(val: OskDomainSeparator) -> anyhow::Result<Self> {
        match val.org_and_label()? {
            None => Ok(protocol::OskDomainSeparator::default()),
            Some((org, label)) => Ok(protocol::OskDomainSeparator::custom_utf8(org, label)),
        }
    }
}
