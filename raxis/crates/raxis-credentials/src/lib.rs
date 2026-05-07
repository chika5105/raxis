//! `raxis-credentials` — V2 `CredentialBackend` extensibility seam.
//!
//! Normative reference: `specs/v2/extensibility-traits.md §4`.
//!
//! # What this crate is
//!
//! The trait every credential store implements. The reference deployment
//! reads plaintext files under `<data_dir>/credentials/<name>.env` and
//! `<data_dir>/providers/<name>.toml` (chmod 0600, kernel-OS-user); that
//! impl lives in `raxis-credentials-file`. Future deployments can plug
//! HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or a PKCS#11
//! HSM behind the same trait without changing a single call site in the
//! kernel, the gateway, or the credential proxies.
//!
//! # What this crate is NOT
//!
//! - Not the credential proxy. The proxy types (Postgres, k8s, AWS,
//!   Azure, GCP, Redis, MongoDB, MySQL, MSSQL, SMTP) live in
//!   `raxis-credential-proxy` (or per-protocol sub-crates). They consume
//!   `Arc<dyn CredentialBackend>` to resolve the *value* and never see
//!   the underlying file/Vault/HSM detail.
//! - Not the gateway's provider-credentials reader. That logic moves
//!   into `raxis-credentials-file` so both the gateway and the proxies
//!   share one resolver — `extensibility-traits.md §4.4` "Files to
//!   change".
//!
//! # Why a separate crate (and not `crates/raxis-credentials-substrate`)
//!
//! Same pattern as `raxis-isolation` (trait crate) /
//! `raxis-isolation-apple-vz` + `raxis-isolation-firecracker` (concrete
//! substrates). The trait crate has zero platform-specific dependencies
//! so test fakes (in `raxis-test-support`) and concrete impls can both
//! depend on it without dragging the platform-specific deps into every
//! transitive consumer.
//!
//! # Conformance contract (verified in `tests/conformance.rs`)
//!
//! Per `extensibility-traits.md §4.5`:
//!
//! 1. `resolve(name)` returns `Err(CredentialNotFound)` for any name
//!    not previously created.
//! 2. `rotate(name, v1)` then `resolve(name)` returns `v1`.
//! 3. `rotate` is atomic — concurrent `resolve`s during rotation
//!    observe either the pre-state or the post-state, never a torn
//!    read.
//! 4. Every `resolve` emits exactly one `CredentialAccessed` audit
//!    event.
//! 5. `CredentialValue` zeroes its memory on `Drop` (via `secrecy` +
//!    `zeroize`).

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;

use raxis_audit_tools::{AuditEventKind, AuditSink};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod audit;

pub use audit::AuditingBackend;

// ---------------------------------------------------------------------------
// Newtypes
// ---------------------------------------------------------------------------

/// The policy-declared name of a credential. Always a short ASCII
/// identifier (e.g. `"postgres-staging"`,
/// `"providers.anthropic-prod"`). The trait stores it as a plain
/// `String` rather than a more constrained type so that future variants
/// (`vault://kv/data/secret-name`, `aws-sm://arn:...`) can ride on the
/// same wire shape — concrete backends are free to require a more
/// restrictive form via `resolve` and reject everything else with
/// `CredentialError::NotFound`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialName(String);

impl CredentialName {
    /// Wrap an existing string. The kernel-side admission pipeline
    /// validates the name against `[[permitted_credentials]]` BEFORE
    /// reaching the backend, so there's no shape validation here.
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }

    /// The underlying name string. Logged in `CredentialAccessed`
    /// and shown to the operator CLI; never the value.
    pub fn as_str(&self) -> &str { &self.0 }
}

impl std::fmt::Display for CredentialName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for CredentialName {
    fn from(s: &str) -> Self { Self(s.to_owned()) }
}

impl From<String> for CredentialName {
    fn from(s: String) -> Self { Self(s) }
}

/// The bytes of a credential. Wrapped in [`secrecy::SecretBox`] so
/// `Debug`/`Display` redact, and zeroed on `Drop` (via the underlying
/// `zeroize` integration). Concrete backends construct this from
/// whatever bytes the store returned.
///
/// # Why a newtype rather than `Secret<Vec<u8>>` directly
///
/// Two reasons:
///
///   1. The whole-crate `pub use` ergonomics: callers see one
///      `CredentialValue` type rather than juggling `secrecy`'s
///      `Secret<Vec<u8>>` plus its `ExposeSecret` trait import on
///      every call site.
///   2. We can attach methods specific to credential semantics —
///      `as_bytes` returns a borrowed slice scoped to the secret,
///      `into_bytes` consumes the wrapper with an explicit "I am
///      about to send these bytes downstream" affordance.
pub struct CredentialValue {
    inner: secrecy::SecretBox<Vec<u8>>,
}

impl CredentialValue {
    /// Wrap a freshly-read byte vector. The concrete backend MUST
    /// have constructed `bytes` itself — passing through
    /// caller-supplied bytes weakens the zeroize discipline because
    /// the caller may keep its own copy of the same `Vec<u8>` alive.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            inner: secrecy::SecretBox::new(Box::new(bytes)),
        }
    }

    /// Borrow the credential bytes for the duration of the closure.
    /// The closure is the only place the value is reachable; the
    /// borrow's lifetime keeps the bytes from being moved out into
    /// a longer-lived `Vec<u8>` that escapes the zeroize boundary.
    ///
    /// # Discipline
    ///
    /// The closure should NOT clone the bytes into a heap buffer
    /// outside the closure. Code that needs the bytes long-term
    /// must call [`Self::into_bytes`] explicitly so the move is
    /// auditable in code review.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        use secrecy::ExposeSecret;
        f(self.inner.expose_secret().as_slice())
    }

    /// Consume the wrapper and return the raw bytes. Intentionally
    /// awkward: callers MUST commit to the move (the wrapper's
    /// zeroize-on-drop is gone after this). Use this in the smallest
    /// possible scope and pass the bytes into the next zeroize-aware
    /// boundary (e.g. the credential proxy's auth-injection step,
    /// which writes the bytes to a wire socket and then drops them).
    pub fn into_bytes(self) -> Vec<u8> {
        use secrecy::ExposeSecret;
        // Clone before drop. `SecretBox::expose_secret` returns
        // `&Vec<u8>`; we copy that into a fresh owned `Vec` and then
        // let the original `SecretBox` zero its inner copy on drop.
        let bytes = self.inner.expose_secret().clone();
        bytes
    }

    /// Borrow the value as a UTF-8 string IF it parses as such.
    /// Returns `None` when the credential is binary (e.g. an HSM
    /// key blob). Logging is forbidden — the redaction is on the
    /// wrapper itself.
    pub fn as_utf8(&self) -> Option<String> {
        use secrecy::ExposeSecret;
        std::str::from_utf8(self.inner.expose_secret().as_slice())
            .map(str::to_owned)
            .ok()
    }
}

impl std::fmt::Debug for CredentialValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialValue(<redacted>)")
    }
}

/// Operator pubkey fingerprint authorising a credential rotation.
/// 32-char lowercase hex (matches `policy.toml [meta].signed_by` and
/// `[[operators.entries]].pubkey_fingerprint`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperatorId(pub String);

impl std::fmt::Display for OperatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who is asking the backend for a credential. Rendered into the
/// `consumer_kind` and `consumer_id` fields of the
/// `CredentialAccessed` audit event so forensic tooling can trace
/// every access back to the kernel subsystem responsible.
#[derive(Debug, Clone, Copy)]
pub struct ConsumerIdentity<'a> {
    /// Stable short identifier of the consumer subsystem. Pin this
    /// in code review; downstream tooling matches on it.
    /// Recognised values:
    /// - `"gateway"` — the kernel's `raxis-gateway` supervisor
    ///   resolves provider credentials at boot + on epoch advance.
    /// - `"credential_proxy"` — a per-session credential proxy
    ///   resolves the upstream credential at session activation.
    /// - `"isolation_kernel_signer"` — the AVF/Firecracker substrate
    ///   resolves the VM-image signing key at boot.
    /// - `"operator_cli"` — `raxis credential rotate` /
    ///   `raxis credential show` (the latter is intentionally
    ///   absent today — operators read filenames, not bytes).
    pub kind: &'a str,
    /// Free-form disambiguator within `kind`. For `gateway` the
    /// provider_id; for `credential_proxy` the
    /// `<session_id>:<proxy_type>:<proxy_port>`; for `operator_cli`
    /// the operator pubkey fingerprint.
    pub id: &'a str,
}

impl<'a> ConsumerIdentity<'a> {
    /// Build a consumer identity. Both arguments are short ASCII
    /// strings; nothing here validates them — the audit event
    /// records them verbatim and the operator CLI is responsible
    /// for matching what it sees against its own taxonomy.
    pub fn new(kind: &'a str, id: &'a str) -> Self { Self { kind, id } }
}

/// Lifetime hint for a resolved credential. The kernel uses this
/// to schedule re-resolution before re-injection into a
/// long-running VM (e.g. Vault leases that expire mid-session).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lease {
    /// File-backed and HSM-backed credentials have no expiry.
    Forever,
    /// Vault-style lease — re-resolve before this TTL elapses.
    /// Caller stores the issuance time and refreshes when
    /// `now - issued > ttl - safety_margin`.
    TtlSeconds(u32),
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure modes from a `CredentialBackend` operation. Stable wire
/// strings (via `error_code`) so the operator CLI can pattern-match
/// on them across backend implementations.
#[derive(Debug, Error)]
pub enum CredentialError {
    /// No credential of that name exists in the backend.
    #[error("credential not found: {0}")]
    NotFound(CredentialName),

    /// The caller's identity does not authorise this access. Most
    /// concrete backends never return this — the kernel's admission
    /// pipeline gates access — but Vault / AWS-SM may return it
    /// when the kernel's own auth token is expired or scoped wrong.
    #[error("permission denied resolving credential {name}: {reason}")]
    PermissionDenied {
        /// Credential whose access was denied.
        name: CredentialName,
        /// Backend-specific human-readable detail (e.g. token
        /// scope mismatch). Logged but never returned to the agent.
        reason: String,
    },

    /// The store is reachable but the value is malformed (parse
    /// error, mode/uid mismatch, version mismatch).
    #[error("credential {name} is malformed: {reason}")]
    Malformed {
        /// Credential whose stored representation failed validation.
        name: CredentialName,
        /// Human-readable parse / validation detail.
        reason: String,
    },

    /// The backend store itself is unreachable (Vault sealed,
    /// network partition, HSM offline, file-system error). Callers
    /// MUST treat this as transient on the boot path (retry once
    /// after a short delay) and fatal on the per-request path
    /// (return `CredentialResolutionFailed` to the agent).
    #[error("credential backend unavailable: {reason}")]
    BackendUnavailable {
        /// Human-readable detail (e.g. "Vault sealed", "i/o error").
        reason: String,
    },

    /// `rotate` is not supported by this backend (HSM, where the
    /// rotation must happen out-of-band on the device's own
    /// management plane).
    #[error("credential rotation requires out-of-band ceremony on this backend")]
    RotationRequiresOutOfBand,

    /// Audit emission failed — surface as fatal to the kernel boot
    /// path. Per `R-7`, an unrecoverable audit-write failure halts
    /// the kernel.
    #[error("credential audit emission failed: {reason}")]
    AuditEmissionFailed {
        /// The wrapped audit-writer error (file system, mutex,
        /// schema mismatch).
        reason: String,
    },
}

impl CredentialError {
    /// Stable short-string for the operator CLI's error envelope.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::NotFound(_)                       => "FAIL_CRED_NOT_FOUND",
            Self::PermissionDenied { .. }           => "FAIL_CRED_PERMISSION_DENIED",
            Self::Malformed { .. }                  => "FAIL_CRED_MALFORMED",
            Self::BackendUnavailable { .. }         => "FAIL_CRED_BACKEND_UNAVAILABLE",
            Self::RotationRequiresOutOfBand         => "FAIL_CRED_ROTATION_OOB",
            Self::AuditEmissionFailed { .. }        => "FAIL_CRED_AUDIT_EMIT",
        }
    }
}

// ---------------------------------------------------------------------------
// CredentialBackend trait
// ---------------------------------------------------------------------------

/// Pluggable seam for credential storage and resolution.
///
/// `R-2 Mediated I/O` requires intelligence to never see credential
/// material directly. This trait does not weaken that — every impl
/// returns the value into the kernel's address space, never into a
/// VM-readable surface. The credential proxy and the gateway are the
/// only two consumers (per the two-credential-system architecture in
/// `paradigm.md §5.1`).
///
/// Implementations:
/// - [`raxis-credentials-file::FileCredentialBackend`] — plaintext
///   files under `<data_dir>/` (V2 default).
/// - Future: `VaultCredentialBackend`, `AwsSecretsManagerBackend`,
///   `AzureKeyVaultBackend`, `Pkcs11HsmBackend`.
///
/// # Audit discipline
///
/// Every `resolve` MUST emit exactly one `CredentialAccessed` event,
/// every successful `rotate` MUST emit one `CredentialRotated` event.
/// Concrete impls do NOT have to repeat the audit step on every
/// implementation — they can wrap themselves in [`AuditingBackend`]
/// at construction time, which performs the emission generically.
/// `extensibility-traits.md §4.5` rule 4.
///
/// # Concurrency
///
/// `resolve` and `rotate` take `&self` so the kernel can hold
/// `Arc<dyn CredentialBackend>` in `HandlerContext` and call into
/// the backend from any tokio task without serialisation. Concrete
/// impls are responsible for their own internal synchronisation
/// (file backend uses fcntl locks during rotate; Vault backend uses
/// the underlying client's connection pool).
pub trait CredentialBackend: Send + Sync + 'static {
    /// Resolve a credential by its policy-declared name. The caller
    /// must already have authorisation to read it (the kernel's
    /// admission pipeline checked the policy declaration).
    fn resolve(
        &self,
        name: &CredentialName,
        consumer: ConsumerIdentity<'_>,
    ) -> Result<CredentialValue, CredentialError>;

    /// Rotate a credential. Called only by `raxis credential rotate`,
    /// which itself is a privileged operator op gated by `INV-CERT-01`.
    /// File backend: writes the new value, fsyncs, atomic-renames.
    /// Vault backend: KV v2 versioned write.
    /// HSM backend: returns `CredentialError::RotationRequiresOutOfBand`.
    fn rotate(
        &self,
        name: &CredentialName,
        new: CredentialValue,
        actor: OperatorId,
    ) -> Result<(), CredentialError>;

    /// Probe whether a credential exists without reading its value.
    /// Used by `raxis doctor` and policy-load-time validation.
    /// Implementations SHOULD validate access controls at the same
    /// time so a misconfigured permission surfaces as `false` here
    /// rather than at first resolution.
    fn exists(&self, name: &CredentialName) -> bool;

    /// Lifetime hint: when does the value's lease expire? File
    /// backend returns [`Lease::Forever`]. Vault backend returns the
    /// lease TTL.
    fn lease(&self, name: &CredentialName) -> Lease;

    /// Stable short-string identifying this backend implementation.
    /// Recorded in `CredentialAccessed.backend_kind` for forensic
    /// audit. Pin one value per impl crate (`"file"`, `"vault"`,
    /// `"aws_secrets_manager"`, etc.).
    fn backend_kind(&self) -> &'static str;
}

/// Kind discriminator persisted in `policy.toml [credential_backend]`
/// and read by `kernel/src/main.rs` at boot to pick the concrete
/// `Arc<dyn CredentialBackend>`. The `File` variant is the V2
/// default. Future variants slot in alphabetically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialBackendKind {
    /// Plaintext files under `<data_dir>/credentials/<name>.env` and
    /// `<data_dir>/providers/<name>.toml`. The V2 default.
    File,
    /// HashiCorp Vault KV v2 store. Future.
    Vault,
    /// AWS Secrets Manager. Future.
    AwsSecretsManager,
    /// Azure Key Vault. Future.
    AzureKeyVault,
    /// PKCS#11 hardware security module. Future.
    Pkcs11Hsm,
}

impl Default for CredentialBackendKind {
    fn default() -> Self { Self::File }
}

impl CredentialBackendKind {
    /// Stable short-string used in audit events and operator CLI
    /// errors. Pinned by tests so a future rename does not silently
    /// drift the wire shape.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::File              => "file",
            Self::Vault             => "vault",
            Self::AwsSecretsManager => "aws_secrets_manager",
            Self::AzureKeyVault     => "azure_key_vault",
            Self::Pkcs11Hsm         => "pkcs11",
        }
    }
}

// ---------------------------------------------------------------------------
// Audit-emission convenience helpers used by concrete impls
// ---------------------------------------------------------------------------

/// Emit a `CredentialAccessed` event through the supplied audit sink.
/// Concrete impls call this from inside `resolve` (with `success` set
/// per the resolution outcome). Returns `CredentialError::AuditEmissionFailed`
/// on sink-write failure so the kernel treats a missed audit as fatal.
///
/// This helper is the recommended path; alternatively, wrap the
/// concrete backend in [`AuditingBackend`] at construction time and
/// implement `resolve` on the inner backend without manual audit.
pub fn emit_credential_accessed(
    audit: &Arc<dyn AuditSink>,
    name: &CredentialName,
    consumer: ConsumerIdentity<'_>,
    backend_kind: &'static str,
    success: bool,
) -> Result<(), CredentialError> {
    audit
        .emit(
            AuditEventKind::CredentialAccessed {
                name:          name.as_str().to_owned(),
                consumer_kind: consumer.kind.to_owned(),
                consumer_id:   consumer.id.to_owned(),
                backend_kind:  backend_kind.to_owned(),
                success,
            },
            None,
            None,
            None,
        )
        .map(|_| ())
        .map_err(|e| CredentialError::AuditEmissionFailed { reason: e.to_string() })
}

/// Emit a `CredentialRotated` event through the supplied audit sink.
/// Called from concrete `rotate` impls AFTER the underlying store
/// has acknowledged the write. `INV-CRED-AUDIT-02`.
pub fn emit_credential_rotated(
    audit: &Arc<dyn AuditSink>,
    name: &CredentialName,
    actor: &OperatorId,
    backend_kind: &'static str,
) -> Result<(), CredentialError> {
    audit
        .emit(
            AuditEventKind::CredentialRotated {
                name:              name.as_str().to_owned(),
                actor_fingerprint: actor.0.clone(),
                backend_kind:      backend_kind.to_owned(),
            },
            None,
            None,
            None,
        )
        .map(|_| ())
        .map_err(|e| CredentialError::AuditEmissionFailed { reason: e.to_string() })
}

// ---------------------------------------------------------------------------
// Smoke tests for the value/name newtypes (no backend involvement).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_value_with_bytes_yields_the_raw_bytes() {
        let v = CredentialValue::from_bytes(b"shhh-its-a-secret".to_vec());
        let observed = v.with_bytes(<[u8]>::to_vec);
        assert_eq!(observed, b"shhh-its-a-secret");
    }

    #[test]
    fn credential_value_debug_redacts_the_bytes() {
        let v = CredentialValue::from_bytes(b"this-is-the-actual-secret".to_vec());
        let s = format!("{v:?}");
        assert!(
            !s.contains("actual-secret"),
            "Debug format must redact: got {s}"
        );
        assert!(s.contains("redacted"), "Debug format should say redacted: got {s}");
    }

    #[test]
    fn credential_value_into_bytes_yields_the_raw_bytes() {
        let v = CredentialValue::from_bytes(b"abc".to_vec());
        assert_eq!(v.into_bytes(), b"abc");
    }

    #[test]
    fn credential_value_as_utf8_returns_string_when_valid() {
        let v = CredentialValue::from_bytes(b"hello".to_vec());
        assert_eq!(v.as_utf8().as_deref(), Some("hello"));
    }

    #[test]
    fn credential_value_as_utf8_returns_none_for_binary() {
        let v = CredentialValue::from_bytes(vec![0xFF, 0xFE, 0xFD]);
        assert!(v.as_utf8().is_none());
    }

    #[test]
    fn credential_name_round_trips_through_str_and_string() {
        let a = CredentialName::from("foo");
        let b = CredentialName::from("foo".to_string());
        assert_eq!(a, b);
        assert_eq!(a.as_str(), "foo");
        assert_eq!(format!("{a}"), "foo");
    }

    #[test]
    fn credential_backend_kind_str_pin() {
        assert_eq!(CredentialBackendKind::File.as_str(), "file");
        assert_eq!(CredentialBackendKind::Vault.as_str(), "vault");
        assert_eq!(CredentialBackendKind::AwsSecretsManager.as_str(), "aws_secrets_manager");
        assert_eq!(CredentialBackendKind::AzureKeyVault.as_str(), "azure_key_vault");
        assert_eq!(CredentialBackendKind::Pkcs11Hsm.as_str(), "pkcs11");
    }

    #[test]
    fn credential_backend_kind_default_is_file() {
        assert_eq!(CredentialBackendKind::default(), CredentialBackendKind::File);
    }

    #[test]
    fn credential_error_codes_are_stable() {
        assert_eq!(
            CredentialError::NotFound("x".into()).error_code(),
            "FAIL_CRED_NOT_FOUND",
        );
        assert_eq!(
            CredentialError::PermissionDenied {
                name: "x".into(),
                reason: "y".into(),
            }
            .error_code(),
            "FAIL_CRED_PERMISSION_DENIED",
        );
        assert_eq!(
            CredentialError::Malformed { name: "x".into(), reason: "y".into() }.error_code(),
            "FAIL_CRED_MALFORMED",
        );
        assert_eq!(
            CredentialError::BackendUnavailable { reason: "y".into() }.error_code(),
            "FAIL_CRED_BACKEND_UNAVAILABLE",
        );
        assert_eq!(
            CredentialError::RotationRequiresOutOfBand.error_code(),
            "FAIL_CRED_ROTATION_OOB",
        );
        assert_eq!(
            CredentialError::AuditEmissionFailed { reason: "y".into() }.error_code(),
            "FAIL_CRED_AUDIT_EMIT",
        );
    }
}
