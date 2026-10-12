//! This module only contains [`EphemeralKemChoice`] – see its documentation.

/// choice of the  ephemeral key encapsulation mechanism to use in the Rosenpass protocol
///
/// See the ephemeral keypairs `eski`/`epki` in the whitepaper.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EphemeralKemChoice {
    /// Kyber512 (NIST competition, round 3)
    ///
    /// This was the original choice in early Rosenpass version when ML-KEM had not been standardized back then.
    #[default]
    Kyber512Round3,

    /// ML-KEM-512 (FIPS 203)
    MlKem512,
}

impl EphemeralKemChoice {
    /// identifier used in the protocol's hash domain separation strings
    ///
    /// also see implementation of [`crate::hash_domains::protocol`]
    pub const fn protocol_string_kem_id(&self) -> &'static str {
        match self {
            EphemeralKemChoice::Kyber512Round3 => "Kyber512",
            EphemeralKemChoice::MlKem512 => "ML-KEM-512",
        }
    }

    /// Select the ephemeral KEM based on the `use_ml_kem` configuration switch
    /// (see [`crate::config::Rosenpass::use_ml_kem`])
    pub const fn from_config_value(use_ml_kem: bool) -> Self {
        if use_ml_kem {
            Self::MlKem512
        } else {
            Self::Kyber512Round3
        }
    }
}
