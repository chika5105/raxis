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

    /// An embedded operator certificate failed structural validation
    /// or self-signature verification, AND `force_misconfig_bypass`
    /// was not set on the entry. The kernel refuses to install a
    /// silently-broken cert: every misconfig is either fixed at
    /// source, or explicitly bypassed and audited.
    ///
    /// `errors` is the full list of structural / signature failures
    /// produced by `raxis-crypto::cert::validate_cert_structurally`
    /// and `verify_cert_self_signature`, so a single load attempt
    /// surfaces ALL problems in one pass (no whack-a-mole).
    #[error(
        "operator certificate for fingerprint {fingerprint:?} ({display_name:?}) \
         failed validation; bypass with force_misconfig_bypass = true on the entry \
         (audited at boot). Errors:\n{errors}"
    )]
    CertValidation {
        fingerprint: String,
        display_name: String,
        errors: String,
    },

    /// The pubkey on the OperatorEntry does not match the pubkey
    /// embedded in its cert. This is NEVER bypassable: the cert and
    /// the entry must agree on the operator identity, otherwise the
    /// audit chain becomes meaningless.
    #[error(
        "operator entry {fingerprint:?} declares pubkey_hex={entry_pubkey_hex:?} \
         but its embedded cert has pubkey_hex={cert_pubkey_hex:?}; the two MUST \
         match so the cert binds the same identity the policy registers"
    )]
    CertPubkeyMismatch {
        fingerprint: String,
        entry_pubkey_hex: String,
        cert_pubkey_hex: String,
    },

    /// The operator's pubkey hashes to a fingerprint that does not
    /// match the one declared on the entry. NEVER bypassable.
    #[error(
        "operator entry {fingerprint:?} declares pubkey_hex={entry_pubkey_hex:?} \
         but SHA-256[:16] of those bytes is {computed_fingerprint:?}; \
         the fingerprint MUST match (kernel-store.md §2.5.4)"
    )]
    FingerprintMismatch {
        fingerprint: String,
        entry_pubkey_hex: String,
        computed_fingerprint: String,
    },
}
