use crate::protocol::osk_domain_separator::OskDomainSeparator;
use serde::{Deserialize, Serialize};
use anyhow::bail;

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
