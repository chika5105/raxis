// raxis-policy::error — PolicyError type.
//
// All failure modes during policy loading and validation are typed here.
// The kernel maps these to BOOT_ERR_POLICY_INVALID (exit code 10).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    /// TOML parsing failed.
    #[error("policy.toml parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// Filesystem I/O error reading policy.toml or policy.sig.
    #[error("policy file I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The policy artifact is structurally valid TOML but fails a semantic rule
    /// (e.g. a required section is absent, a field value is out of range, or an
    /// operator entry is missing a required field).
    ///
    /// This maps to BOOT_ERR_POLICY_INVALID at the kernel startup layer.
    #[error("malformed policy artifact: {0}")]
    MalformedArtifact(String),

    /// Ed25519 signature on the policy artifact is invalid or the signing key
    /// fingerprint does not match any registered operator.
    #[error("policy artifact signature invalid: {0}")]
    SignatureInvalid(String),

    /// Hex decode error (fingerprint, signature, pubkey bytes).
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// An operator entry references an unknown capability class.
    #[error("unknown capability class '{0}' in operator entry")]
    UnknownCapabilityClass(String),

    /// A gate entry references an unknown gate type.
    #[error("unknown gate type '{0}' in [[gates]] entry")]
    UnknownGateType(String),

    /// The policy epoch in the artifact is not monotonically greater than the
    /// current epoch. Only relevant during epoch advance, not cold boot.
    #[error("policy epoch {new} is not greater than current epoch {current}")]
    EpochNotMonotonic { current: u64, new: u64 },
}
