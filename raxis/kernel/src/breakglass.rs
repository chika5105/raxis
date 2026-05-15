//! `kernel/src/breakglass.rs` — V1 Tier 4 emergency operator
//! override.
//!
//! Normative reference: `specs/v1/kernel-core.md §2.3
//! src/breakglass.rs`.
//!
//! ## Role
//!
//! Break-glass activation suspends gate evaluation
//! ([`crate::gates::evaluate_claims`] returns
//! [`crate::gates::GateEvalResult::BreakglassPass`] without
//! consulting claims/witnesses/policy) for a TTL-bounded window.
//! It is an explicitly dangerous capability, surrounded by
//! ceremony, logging, and strict audit:
//!
//! - **Two-operator activation.** `activate` requires two distinct
//!   operator signatures over the activation record canonical
//!   bytes. Both signers MUST be present in the bundled
//!   `[[operators]]` registry (the same set that authorises CLI
//!   operations).
//! - **Single-operator deactivation.** Either signer (or any
//!   operator with admin rights) can deactivate before TTL.
//! - **Hard TTL.** `expires_at <= activated_at + max_duration`.
//!   Default `max_duration = 4 h`. Activations whose TTL has
//!   passed are silently treated as inactive on the next
//!   [`check_active`] call and pruned.
//! - **Audit chain.** Every state change emits an audit event:
//!   `BreakglassActivated`, `BreakglassDeactivated`, and (per
//!   bypassed action) `BreakglassAction`.
//!
//! ## Persistence
//!
//! V1 stores the activation record in
//! `<data_dir>/breakglass/active.toml` (atomic write: tempfile +
//! fsync + rename). One record at a time — the TOML file is
//! either present (active) or absent (inactive). The store SQL
//! schema is reserved for V2 when concurrent activation history
//! becomes useful.
//!
//! ## Trust boundary
//!
//! - Activation records are signed by operator keys. The kernel
//!   verifies signatures against the policy bundle's
//!   `[[operators]]` registry (loaded by `raxis-policy`).
//! - The kernel never accepts an activation without a fully-valid
//!   pair of signatures. A planner cannot signal break-glass
//!   directly; the operator CLI is the only ingress.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use parking_lot::RwLock;
use raxis_audit_tools::{AuditEventKind, AuditSink, AuditWriterError};
use raxis_policy::{OperatorEntry, PolicyBundle};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Default break-glass TTL when the operator's `expires_at` is
/// omitted. Spec-default: 4 hours. The kernel hard-caps any
/// operator-supplied TTL to this value.
pub const DEFAULT_BREAKGLASS_MAX_DURATION_SECS: i64 = 4 * 60 * 60;

/// Maximum length of the operator-supplied justification, in
/// bytes. Above this, [`activate`] returns
/// [`BreakglassError::JustificationTooLong`].
pub const MAX_JUSTIFICATION_BYTES: usize = 256;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Submitted activation record. Two operator signatures over the
/// canonical hash bytes (see [`canonical_signing_bytes`]) are
/// required; both signer pubkeys MUST be in the policy bundle's
/// `[[operators]]` registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakglassActivation {
    /// Server-assigned UUID-v4. Pre-`activate`, callers leave this
    /// at `Uuid::nil()`; the kernel mints a fresh value before
    /// persisting.
    #[serde(default)]
    pub activation_id: Uuid,
    /// Free-form one-line operator justification. Length-checked
    /// (≤ 256 bytes); CRLF sanitised to spaces before persisting
    /// or auditing.
    pub justification: String,
    /// Pubkey fingerprints (32-hex) of the two signing operators,
    /// in canonical sort order.
    pub activated_by: Vec<String>,
    /// Wallclock at admission (RFC-3339 UTC). Pre-`activate`,
    /// callers leave this at the proposed start time; the kernel
    /// overwrites it with `Utc::now()` before persisting.
    pub activated_at: DateTime<Utc>,
    /// Wallclock at TTL expiry (RFC-3339 UTC). MUST satisfy
    /// `expires_at <= activated_at + max_duration`.
    pub expires_at: DateTime<Utc>,
    /// First operator's Ed25519 signature (64 bytes).
    pub signature_1: Vec<u8>,
    /// Second operator's Ed25519 signature (64 bytes).
    pub signature_2: Vec<u8>,
}

/// Output of [`check_active`]. Closed enum so callers exhaustively
/// match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakglassStatus {
    /// An unexpired activation is in effect.
    Active {
        /// Activation_id; threaded through to `BreakglassAction`
        /// events so every bypass references the activation.
        activation_id: Uuid,
        /// Wallclock at TTL expiry; UI surfaces use this to render
        /// a countdown.
        expires_at: DateTime<Utc>,
    },
    /// No activation in effect (either never activated, expired
    /// past TTL, or deactivated).
    Inactive,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised by the break-glass module.
#[derive(Debug, thiserror::Error)]
pub enum BreakglassError {
    /// Filesystem error reading or writing the activation file.
    #[error("breakglass io error at {path:?}: {source}")]
    Io {
        /// Path attempted.
        path: PathBuf,
        /// IO source.
        #[source]
        source: std::io::Error,
    },
    /// The activation file existed but failed to parse.
    #[error("breakglass file at {path:?} is corrupt: {reason}")]
    Corrupt {
        /// Path attempted.
        path: PathBuf,
        /// Reason text.
        reason: String,
    },
    /// Operator pubkey-fingerprint not present in the policy
    /// bundle's `[[operators]]` registry.
    #[error("breakglass: signer {fp} not in policy [[operators]]")]
    UnknownSigner {
        /// 32-hex pubkey fingerprint.
        fp: String,
    },
    /// Both signatures came from the same operator identity.
    #[error("breakglass: same-operator double-signing rejected (fingerprint = {fp})")]
    SameOperator {
        /// 32-hex pubkey fingerprint of the duplicate signer.
        fp: String,
    },
    /// Signature verification failed against the canonical bytes.
    #[error("breakglass: invalid signature from {fp}")]
    InvalidSignature {
        /// 32-hex pubkey fingerprint of the rejected signer.
        fp: String,
    },
    /// `expires_at` violates the configured `max_duration` cap.
    #[error("breakglass: TTL {ttl_secs}s exceeds max_duration {max_secs}s")]
    TtlExceedsMaxDuration {
        /// Operator-supplied TTL.
        ttl_secs: i64,
        /// Configured cap (default 4h).
        max_secs: i64,
    },
    /// `expires_at <= activated_at` — a TTL must extend into the
    /// future.
    #[error("breakglass: expires_at must be > activated_at")]
    TtlNonPositive,
    /// Justification is empty or exceeds the byte cap.
    #[error("breakglass: justification length {len} bytes (must be 1..{max})")]
    JustificationTooLong {
        /// Submitted length.
        len: usize,
        /// Allowed cap.
        max: usize,
    },
    /// Activation already exists (and has not expired). Operators
    /// must `deactivate` before opening a fresh ceremony.
    #[error("breakglass: activation {activation_id} already in effect")]
    AlreadyActive {
        /// The in-effect activation's UUID.
        activation_id: Uuid,
    },
    /// `deactivate` referenced an activation_id that doesn't match
    /// the in-effect record (or no record exists).
    #[error("breakglass: no active record matches activation_id {activation_id}")]
    NoMatchingRecord {
        /// The submitted UUID.
        activation_id: Uuid,
    },
    /// Audit chain refused the event. The kernel treats audit-
    /// write failures as fatal (kernel-store.md §2.5.2), so this
    /// variant is propagated up; the operator-facing CLI surfaces
    /// it as a hard error and refuses to acknowledge the
    /// activation.
    #[error("breakglass: audit emit failed: {0}")]
    Audit(#[from] AuditWriterError),
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// On-disk envelope written into `<data_dir>/breakglass/active.toml`.
/// Single-record per file — V1 simplification per the module-level
/// comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OnDisk {
    activation: BreakglassActivation,
}

fn load_record(path: &Path) -> Result<Option<BreakglassActivation>, BreakglassError> {
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(path).map_err(|e| BreakglassError::Io {
        path: path.to_owned(),
        source: e,
    })?;
    let envelope: OnDisk = toml::from_str(&body).map_err(|e| BreakglassError::Corrupt {
        path: path.to_owned(),
        reason: e.to_string(),
    })?;
    Ok(Some(envelope.activation))
}

fn write_record(path: &Path, rec: &BreakglassActivation) -> Result<(), BreakglassError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BreakglassError::Io {
            path: path.to_owned(),
            source: e,
        })?;
    }
    let body = toml::to_string_pretty(&OnDisk {
        activation: rec.clone(),
    })
    .map_err(|e| BreakglassError::Corrupt {
        path: path.to_owned(),
        reason: e.to_string(),
    })?;
    let tmp = path.with_extension("toml.tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).map_err(|e| BreakglassError::Io {
            path: tmp.clone(),
            source: e,
        })?;
        f.write_all(body.as_bytes())
            .map_err(|e| BreakglassError::Io {
                path: tmp.clone(),
                source: e,
            })?;
        f.sync_all().map_err(|e| BreakglassError::Io {
            path: tmp.clone(),
            source: e,
        })?;
    }
    std::fs::rename(&tmp, path).map_err(|e| BreakglassError::Io {
        path: path.to_owned(),
        source: e,
    })?;
    Ok(())
}

fn remove_record(path: &Path) -> Result<(), BreakglassError> {
    if !path.exists() {
        return Ok(());
    }
    std::fs::remove_file(path).map_err(|e| BreakglassError::Io {
        path: path.to_owned(),
        source: e,
    })
}

/// Default activation file path under `<data_dir>`.
pub fn default_record_path(data_dir: &Path) -> PathBuf {
    data_dir.join("breakglass").join("active.toml")
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Per-kernel break-glass state. Construct once at boot
/// ([`crate::ipc::context::HandlerContext::with_breakglass`]) and
/// share via `Arc<BreakglassState>`. Cheap to clone.
pub struct BreakglassState {
    /// Cached, hot-path-readable view of the in-effect record.
    /// `None` ⇒ inactive (file absent or TTL passed).
    inner: RwLock<Option<BreakglassActivation>>,
    /// Persisted record path; `<data_dir>/breakglass/active.toml`
    /// in production.
    record_path: PathBuf,
    /// Hard TTL cap; defaults to 4 h.
    max_duration: ChronoDuration,
}

impl BreakglassState {
    /// Open (and re-load) the breakglass state from `<data_dir>`.
    /// Missing or expired records ⇒ `Inactive` until activation.
    pub fn open(record_path: PathBuf) -> Result<Self, BreakglassError> {
        let initial = load_record(&record_path)?;
        let initial = match initial {
            Some(rec) if rec.expires_at > Utc::now() => Some(rec),
            Some(_) => {
                let _ = remove_record(&record_path);
                None
            }
            None => None,
        };
        Ok(Self {
            inner: RwLock::new(initial),
            record_path,
            max_duration: ChronoDuration::seconds(DEFAULT_BREAKGLASS_MAX_DURATION_SECS),
        })
    }

    /// Construct a memory-only state (no on-disk persistence). Used
    /// by tests + the kernel's `disabled()` default when no
    /// `<data_dir>` is wired yet.
    pub fn disabled() -> Self {
        Self {
            inner: RwLock::new(None),
            record_path: PathBuf::new(),
            max_duration: ChronoDuration::seconds(DEFAULT_BREAKGLASS_MAX_DURATION_SECS),
        }
    }

    /// Override the hard TTL cap. Operators wire this from
    /// `[breakglass].max_duration` in policy.toml when V2 lands;
    /// V1 just keeps the default 4 h.
    pub fn with_max_duration(mut self, d: ChronoDuration) -> Self {
        self.max_duration = d;
        self
    }

    /// Snapshot the current status. Hot path — held by every
    /// `evaluate_claims` invocation.
    pub fn check(&self) -> BreakglassStatus {
        let snap = {
            let g = self.inner.read();
            g.clone()
        };
        match snap {
            Some(rec) if rec.expires_at > Utc::now() => BreakglassStatus::Active {
                activation_id: rec.activation_id,
                expires_at: rec.expires_at,
            },
            Some(_) => {
                // Expired — drop the in-memory copy and the on-disk
                // file so subsequent calls don't repeatedly see the
                // stale record.
                let mut g = self.inner.write();
                *g = None;
                drop(g);
                if !self.record_path.as_os_str().is_empty() {
                    let _ = remove_record(&self.record_path);
                }
                BreakglassStatus::Inactive
            }
            None => BreakglassStatus::Inactive,
        }
    }

    /// Snapshot the in-effect record (without TTL pruning). For
    /// `raxis status` and audit replay tooling.
    pub fn current(&self) -> Option<BreakglassActivation> {
        self.inner.read().clone()
    }

    /// Configured hard TTL cap.
    pub fn max_duration(&self) -> ChronoDuration {
        self.max_duration
    }
}

// ---------------------------------------------------------------------------
// Public API: activate / deactivate / log_action
// ---------------------------------------------------------------------------

/// Verify and persist a break-glass activation. Returns the
/// admitted activation_id (UUID-v4). On error, the on-disk file
/// is unchanged.
///
/// Steps:
///
/// 1. Justify length-check.
/// 2. Resolve signer pubkey-fingerprints to operator entries.
///    (`UnknownSigner` if missing, `SameOperator` if the two
///    fingerprints collide.)
/// 3. Verify both signatures over [`canonical_signing_bytes`].
/// 4. Cap `expires_at` to `now + max_duration`; reject negative
///    TTLs.
/// 5. Mint a fresh UUID-v4 activation_id; sort the
///    `activated_by` list canonically; write to disk; cache in
///    memory.
/// 6. Emit `AuditEventKind::BreakglassActivated`.
pub fn activate(
    mut activation: BreakglassActivation,
    policy: &PolicyBundle,
    state: &BreakglassState,
    audit: &Arc<dyn AuditSink>,
) -> Result<Uuid, BreakglassError> {
    // 1. Length-check.
    let justification = sanitise_justification(&activation.justification);
    let len = justification.as_bytes().len();
    if len == 0 || len > MAX_JUSTIFICATION_BYTES {
        return Err(BreakglassError::JustificationTooLong {
            len,
            max: MAX_JUSTIFICATION_BYTES,
        });
    }
    // 2. Resolve signers.
    if activation.activated_by.len() != 2 {
        return Err(BreakglassError::UnknownSigner {
            fp: format!("expected 2 signers, got {}", activation.activated_by.len()),
        });
    }
    let signer_1 = lookup_operator(&activation.activated_by[0], policy.operators())?;
    let signer_2 = lookup_operator(&activation.activated_by[1], policy.operators())?;
    if signer_1.pubkey_fingerprint == signer_2.pubkey_fingerprint {
        return Err(BreakglassError::SameOperator {
            fp: signer_1.pubkey_fingerprint.clone(),
        });
    }
    // 3. Verify signatures.
    let canonical = canonical_signing_bytes(&activation, &justification);
    verify_sig(
        &signer_1.pubkey_hex,
        &activation.signature_1,
        &canonical,
        &signer_1.pubkey_fingerprint,
    )?;
    verify_sig(
        &signer_2.pubkey_hex,
        &activation.signature_2,
        &canonical,
        &signer_2.pubkey_fingerprint,
    )?;
    // 4. TTL.
    let now = Utc::now();
    if activation.expires_at <= now {
        return Err(BreakglassError::TtlNonPositive);
    }
    let ttl = activation.expires_at - now;
    if ttl > state.max_duration {
        return Err(BreakglassError::TtlExceedsMaxDuration {
            ttl_secs: ttl.num_seconds(),
            max_secs: state.max_duration.num_seconds(),
        });
    }
    // 5. Persist.
    {
        let g = state.inner.read();
        if let Some(existing) = g.as_ref() {
            if existing.expires_at > now {
                return Err(BreakglassError::AlreadyActive {
                    activation_id: existing.activation_id,
                });
            }
        }
    }
    activation.activation_id = Uuid::new_v4();
    activation.activated_at = now;
    activation.justification = justification.clone();
    activation.activated_by.sort();
    if !state.record_path.as_os_str().is_empty() {
        write_record(&state.record_path, &activation)?;
    }
    {
        let mut g = state.inner.write();
        *g = Some(activation.clone());
    }
    // 6. Audit.
    audit.emit(
        AuditEventKind::BreakglassActivated {
            activation_id: activation.activation_id.to_string(),
            activated_by: activation.activated_by.clone(),
            activated_at: activation.activated_at.to_rfc3339(),
            expires_at: activation.expires_at.to_rfc3339(),
            justification: activation.justification.clone(),
        },
        None,
        None,
        None,
    )?;
    Ok(activation.activation_id)
}

/// Deactivate the current break-glass activation. One operator
/// signature is sufficient; the operator MUST be in the policy
/// bundle's `[[operators]]` registry. Audit emits
/// `BreakglassDeactivated`.
pub fn deactivate(
    operator_fingerprint: &str,
    operator_signature: &[u8],
    activation_id: Uuid,
    policy: &PolicyBundle,
    state: &BreakglassState,
    audit: &Arc<dyn AuditSink>,
) -> Result<(), BreakglassError> {
    let signer = lookup_operator(operator_fingerprint, policy.operators())?;
    let current = match state.current() {
        Some(rec) if rec.activation_id == activation_id => rec,
        _ => return Err(BreakglassError::NoMatchingRecord { activation_id }),
    };
    let canonical = deactivate_signing_bytes(activation_id, &signer.pubkey_fingerprint);
    verify_sig(
        &signer.pubkey_hex,
        operator_signature,
        &canonical,
        &signer.pubkey_fingerprint,
    )?;
    if !state.record_path.as_os_str().is_empty() {
        remove_record(&state.record_path)?;
    }
    {
        let mut g = state.inner.write();
        *g = None;
    }
    let now = Utc::now();
    audit.emit(
        AuditEventKind::BreakglassDeactivated {
            activation_id: current.activation_id.to_string(),
            deactivated_by: signer.pubkey_fingerprint.clone(),
            deactivated_at: now.to_rfc3339(),
        },
        None,
        None,
        None,
    )?;
    Ok(())
}

/// Append `BreakglassAction` to the audit chain. Called by every
/// handler that detects `BreakglassStatus::Active` before
/// proceeding with a bypassed action.
pub fn log_action(
    activation_id: Uuid,
    session_id: Option<&str>,
    action_description: &str,
    audit: &Arc<dyn AuditSink>,
) -> Result<(), BreakglassError> {
    let now = Utc::now();
    let desc = sanitise_justification(action_description);
    audit.emit(
        AuditEventKind::BreakglassAction {
            activation_id: activation_id.to_string(),
            session_id: session_id.unwrap_or("-").to_owned(),
            action_description: desc,
            action_at: now.to_rfc3339(),
        },
        session_id,
        None,
        None,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Signature helpers
// ---------------------------------------------------------------------------

/// Canonical bytes signed by both operators on activation. The
/// payload is a length-prefixed concatenation of the static fields
/// — version + activation kind + sorted-fingerprint pair +
/// expires_at-secs + justification bytes. **No JSON, no TOML**:
/// JSON adds whitespace/key-order ambiguity, TOML adds even more.
/// A flat tagged binary keeps the canonical form simple to compute
/// in any signing CLI.
pub fn canonical_signing_bytes(act: &BreakglassActivation, justification: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(192);
    buf.extend_from_slice(b"raxis.breakglass.v1\0");
    let mut fps = act.activated_by.clone();
    fps.sort();
    for fp in &fps {
        push_lp(&mut buf, fp.as_bytes());
    }
    let exp_secs = act.expires_at.timestamp();
    buf.extend_from_slice(&exp_secs.to_be_bytes());
    push_lp(&mut buf, justification.as_bytes());
    buf
}

/// Canonical bytes signed by the single deactivating operator.
/// Tagged with the activation_id so an operator's signature on
/// activation_id A cannot be replayed on activation_id B.
pub fn deactivate_signing_bytes(activation_id: Uuid, signer_fp: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(b"raxis.breakglass.deactivate.v1\0");
    buf.extend_from_slice(activation_id.as_bytes());
    push_lp(&mut buf, signer_fp.as_bytes());
    buf
}

fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn lookup_operator<'a>(
    fp: &str,
    operators: &'a [OperatorEntry],
) -> Result<&'a OperatorEntry, BreakglassError> {
    operators
        .iter()
        .find(|o| o.pubkey_fingerprint.eq_ignore_ascii_case(fp))
        .ok_or_else(|| BreakglassError::UnknownSigner { fp: fp.to_owned() })
}

fn verify_sig(
    pubkey_hex: &str,
    signature: &[u8],
    payload: &[u8],
    fp: &str,
) -> Result<(), BreakglassError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if signature.len() != 64 {
        return Err(BreakglassError::InvalidSignature { fp: fp.to_owned() });
    }
    let pk_bytes = match hex::decode(pubkey_hex) {
        Ok(b) => b,
        Err(_) => return Err(BreakglassError::InvalidSignature { fp: fp.to_owned() }),
    };
    if pk_bytes.len() != 32 {
        return Err(BreakglassError::InvalidSignature { fp: fp.to_owned() });
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| BreakglassError::InvalidSignature { fp: fp.to_owned() })?;
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature);
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(payload, &sig)
        .map_err(|_| BreakglassError::InvalidSignature { fp: fp.to_owned() })
}

fn sanitise_justification(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch == '\r' || ch == '\n' {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn rand_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("rng");
        SigningKey::from_bytes(&bytes)
    }

    fn empty_state() -> BreakglassState {
        BreakglassState::disabled()
    }

    #[test]
    fn canonical_bytes_are_stable_under_fingerprint_reorder() {
        let mut act = BreakglassActivation {
            activation_id: Uuid::nil(),
            justification: "test".into(),
            activated_by: vec!["bbb".into(), "aaa".into()],
            activated_at: Utc::now(),
            expires_at: Utc::now() + ChronoDuration::seconds(100),
            signature_1: vec![],
            signature_2: vec![],
        };
        let a = canonical_signing_bytes(&act, "test");
        act.activated_by.swap(0, 1);
        let b = canonical_signing_bytes(&act, "test");
        assert_eq!(a, b, "canonical bytes ignore activated_by ordering");
    }

    #[test]
    fn check_returns_inactive_when_no_record() {
        let s = empty_state();
        assert_eq!(s.check(), BreakglassStatus::Inactive);
    }

    #[test]
    fn record_path_default_under_data_dir() {
        let p = default_record_path(std::path::Path::new("/var/lib/raxis"));
        assert_eq!(
            p,
            std::path::PathBuf::from("/var/lib/raxis/breakglass/active.toml"),
        );
    }

    #[test]
    fn justification_sanitise_replaces_crlf() {
        // Input: 5 chars "hello" + \r\n + "world" + \n + "!" + \r
        //         = 15 chars total. Each \r and \n becomes a single space.
        let s = sanitise_justification("hello\r\nworld\n!\r");
        assert_eq!(s, "hello  world ! ");
    }

    #[test]
    fn open_purges_expired_record_on_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("active.toml");
        let now = Utc::now();
        let rec = BreakglassActivation {
            activation_id: Uuid::new_v4(),
            justification: "expired".into(),
            activated_by: vec!["aaa".into(), "bbb".into()],
            activated_at: now - ChronoDuration::seconds(100),
            expires_at: now - ChronoDuration::seconds(10),
            signature_1: vec![0u8; 64],
            signature_2: vec![0u8; 64],
        };
        write_record(&path, &rec).unwrap();
        assert!(path.exists());
        let s = BreakglassState::open(path.clone()).unwrap();
        assert_eq!(s.check(), BreakglassStatus::Inactive);
        assert!(!path.exists(), "expired record removed on open");
    }

    #[test]
    fn signing_payload_distinguishes_activation_from_deactivation() {
        let act = BreakglassActivation {
            activation_id: Uuid::nil(),
            justification: "j".into(),
            activated_by: vec!["a".into(), "b".into()],
            activated_at: Utc::now(),
            expires_at: Utc::now() + ChronoDuration::seconds(100),
            signature_1: vec![],
            signature_2: vec![],
        };
        let act_bytes = canonical_signing_bytes(&act, "j");
        let dea_bytes = deactivate_signing_bytes(Uuid::new_v4(), "a");
        // Different prefixes ⇒ disjoint signing domains.
        assert!(!act_bytes.starts_with(&dea_bytes));
        assert!(!dea_bytes.starts_with(&act_bytes));
    }

    #[test]
    fn verify_sig_fails_on_wrong_payload() {
        let sk = rand_key();
        let vk_bytes = sk.verifying_key().to_bytes();
        let pk_hex = hex::encode(vk_bytes);
        let payload = b"hello";
        let sig = sk.sign(payload).to_bytes();
        // Same payload + correct sig ⇒ ok.
        verify_sig(&pk_hex, &sig, payload, "fp").unwrap();
        // Mutated payload ⇒ rejected.
        let res = verify_sig(&pk_hex, &sig, b"world", "fp");
        assert!(matches!(res, Err(BreakglassError::InvalidSignature { .. })));
    }

    // -------------------------------------------------------------------
    // Real-fixture integration tests — drive `activate` /
    // `deactivate` / `log_action` through real Ed25519 signing keys,
    // a real `PolicyBundle` (with two `OperatorEntry` rows), a real
    // on-disk `BreakglassState` (atomic write/fsync/rename), and a
    // real `FakeAuditSink` (the same sink shape `kernel-store.md
    // §2.5.2` mandates for production wiring).
    // -------------------------------------------------------------------

    use raxis_audit_tools::AuditSink;
    use raxis_crypto::cert::sign_cert;
    use raxis_policy::{OperatorEntry, PolicyBundle};
    use raxis_test_support::audit_sink::FakeAuditSink;
    use raxis_types::operator_cert::{CertKind, OperatorCert};
    use sha2::{Digest, Sha256};

    /// Mint a deterministic operator entry for the given seed.
    /// Returns `(SigningKey, OperatorEntry)` so the test driver can
    /// sign canonical payloads and look up the matching pubkey
    /// fingerprint via `policy.operators()`.
    fn make_operator(seed: u8, name: &str) -> (SigningKey, OperatorEntry) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk_bytes = sk.verifying_key().to_bytes();
        let pubkey_hex = hex::encode(pk_bytes);
        let mut h = Sha256::new();
        h.update(pk_bytes);
        let fp = hex::encode(&h.finalize()[..16]);
        let mut cert = OperatorCert {
            kind: CertKind::Standard,
            display_name: name.to_owned(),
            pubkey_hex: pubkey_hex.clone(),
            // `not_before` / `not_after` are unrelated to the
            // break-glass TTL; they govern the operator-cert
            // four-zone gate. Use a very wide window so the cert
            // is unambiguously in `Active`.
            not_before: 1_700_000_000,
            not_after: 4_000_000_000,
            warn_before_expiry_days: 30,
            grace_period_days: 7,
            permitted_ops: vec!["RotateEpoch".to_owned()],
            contact_info: None,
            self_sig_hex: String::new(),
        };
        cert.self_sig_hex = sign_cert(&cert, &sk);
        let entry = OperatorEntry {
            pubkey_fingerprint: fp,
            display_name: name.to_owned(),
            pubkey_hex,
            permitted_ops: vec!["RotateEpoch".to_owned()],
            cert,
            force_misconfig_bypass: false,
        };
        (sk, entry)
    }

    /// Build a `PolicyBundle` carrying the two supplied operator
    /// entries. Mirrors the helper used by other kernel-side
    /// fixtures (`store::genesis::tests::bundle_with_cert`).
    fn bundle_with(op_a: &OperatorEntry, op_b: &OperatorEntry) -> PolicyBundle {
        PolicyBundle::for_tests_with_operators(vec![op_a.clone(), op_b.clone()])
    }

    fn sign_activation(
        sk: &SigningKey,
        act: &BreakglassActivation,
        justification: &str,
    ) -> Vec<u8> {
        let canonical = canonical_signing_bytes(act, justification);
        sk.sign(&canonical).to_bytes().to_vec()
    }

    /// Build a paired `(Arc<FakeAuditSink>, Arc<dyn AuditSink>)`.
    /// The first handle is for assertions
    /// (`fake.event_kinds()`); the second is the trait-object
    /// reference the kernel API consumes. Sharing the same `Arc`
    /// underneath means `event_kinds()` sees every event the
    /// kernel emitted.
    fn paired_audit_sink() -> (Arc<FakeAuditSink>, Arc<dyn AuditSink>) {
        let fake: Arc<FakeAuditSink> = Arc::new(FakeAuditSink::new());
        let trait_obj: Arc<dyn AuditSink> = Arc::clone(&fake) as Arc<dyn AuditSink>;
        (fake, trait_obj)
    }

    /// End-to-end happy path: two real operators co-sign an
    /// activation; the kernel verifies, persists to disk, caches
    /// in memory, and emits exactly one `BreakglassActivated`
    /// event. A subsequent `log_action` emits a `BreakglassAction`
    /// event keyed by the activation_id; `deactivate` emits a
    /// `BreakglassDeactivated` event and removes the on-disk
    /// record.
    #[test]
    fn integration_two_operator_activation_then_action_then_deactivate() {
        let (sk_a, op_a) = make_operator(0xA1, "alice");
        let (sk_b, op_b) = make_operator(0xB2, "bob");
        let policy = bundle_with(&op_a, &op_b);
        let (fake, audit) = paired_audit_sink();

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("active.toml");
        let state = BreakglassState::open(path.clone()).unwrap();
        assert_eq!(state.check(), BreakglassStatus::Inactive);

        // Build the activation: two distinct fingerprints, valid
        // TTL inside the 4-h cap, justification under 256 B.
        let now = Utc::now();
        let expires = now + ChronoDuration::minutes(30);
        let mut act = BreakglassActivation {
            activation_id: Uuid::nil(),
            justification: "incident #INC-12345 — pager woke me up".into(),
            activated_by: vec![
                op_a.pubkey_fingerprint.clone(),
                op_b.pubkey_fingerprint.clone(),
            ],
            activated_at: now,
            expires_at: expires,
            signature_1: vec![],
            signature_2: vec![],
        };
        // The canonical bytes do NOT include the signatures
        // themselves, so signing each operator independently over
        // the same canonical buffer is correct.
        let just_owned = act.justification.clone();
        act.signature_1 = sign_activation(&sk_a, &act, &just_owned);
        act.signature_2 = sign_activation(&sk_b, &act, &just_owned);

        let activation_id = activate(act, &policy, &state, &audit).unwrap();

        // Memory cache + on-disk file both populated.
        assert!(matches!(state.check(), BreakglassStatus::Active { .. }));
        assert!(path.exists(), "activation persisted to disk");

        // Audit chain saw exactly one BreakglassActivated.
        assert_eq!(fake.event_kinds(), vec!["BreakglassActivated"]);

        // Log a bypassed action — emits BreakglassAction.
        log_action(
            activation_id,
            Some("session-abc"),
            "intent.editfilesintent.task=t-1",
            &audit,
        )
        .unwrap();
        assert_eq!(
            fake.event_kinds(),
            vec!["BreakglassActivated", "BreakglassAction"],
        );

        // Deactivate via op_a's signature over the
        // deactivate-domain canonical bytes.
        let deactivate_canonical =
            deactivate_signing_bytes(activation_id, &op_a.pubkey_fingerprint);
        let deact_sig = sk_a.sign(&deactivate_canonical).to_bytes().to_vec();
        deactivate(
            &op_a.pubkey_fingerprint,
            &deact_sig,
            activation_id,
            &policy,
            &state,
            &audit,
        )
        .unwrap();

        // Inactive again, on-disk record removed.
        assert_eq!(state.check(), BreakglassStatus::Inactive);
        assert!(!path.exists(), "deactivate removed on-disk record");

        assert_eq!(
            fake.event_kinds(),
            vec![
                "BreakglassActivated",
                "BreakglassAction",
                "BreakglassDeactivated",
            ],
        );
    }

    /// A signature minted against the deactivate-domain canonical
    /// bytes MUST NOT verify when fed into the activate path
    /// (`canonical_signing_bytes` carries a different domain
    /// prefix). This is the cross-domain-replay invariant called
    /// out in the module-level docs (signatures bound to a
    /// specific domain prefix).
    #[test]
    fn integration_cross_domain_signature_replay_rejected() {
        let (sk_a, op_a) = make_operator(0xA1, "alice");
        let (_sk_b, op_b) = make_operator(0xB2, "bob");
        let policy = bundle_with(&op_a, &op_b);
        let (fake, audit) = paired_audit_sink();
        let tmp = tempfile::tempdir().unwrap();
        let state = BreakglassState::open(tmp.path().join("active.toml")).unwrap();

        // Build a real activation; replace `signature_1` with a
        // signature minted against the *deactivate* domain (a
        // signature the operator might legitimately mint for an
        // unrelated deactivate ceremony — must not be accepted
        // here).
        let now = Utc::now();
        let mut act = BreakglassActivation {
            activation_id: Uuid::nil(),
            justification: "j".into(),
            activated_by: vec![
                op_a.pubkey_fingerprint.clone(),
                op_b.pubkey_fingerprint.clone(),
            ],
            activated_at: now,
            expires_at: now + ChronoDuration::minutes(10),
            signature_1: vec![],
            signature_2: vec![64; 64],
        };
        let cross = deactivate_signing_bytes(Uuid::new_v4(), &op_a.pubkey_fingerprint);
        act.signature_1 = sk_a.sign(&cross).to_bytes().to_vec();

        let res = activate(act, &policy, &state, &audit);
        assert!(matches!(res, Err(BreakglassError::InvalidSignature { .. })));
        // No partial state: nothing on disk and the sink saw no
        // `BreakglassActivated` event.
        assert_eq!(state.check(), BreakglassStatus::Inactive);
        assert!(fake.event_kinds().is_empty());
    }

    /// Same-operator double-signing is rejected even when both
    /// signatures verify mathematically. The two-operator
    /// invariant is policy-level, not crypto-level.
    #[test]
    fn integration_same_operator_double_sign_rejected() {
        let (sk_a, op_a) = make_operator(0xA1, "alice");
        let (_sk_b, op_b) = make_operator(0xB2, "bob");
        let policy = bundle_with(&op_a, &op_b);
        let (_fake, audit) = paired_audit_sink();
        let tmp = tempfile::tempdir().unwrap();
        let state = BreakglassState::open(tmp.path().join("active.toml")).unwrap();

        let now = Utc::now();
        let mut act = BreakglassActivation {
            activation_id: Uuid::nil(),
            justification: "j".into(),
            activated_by: vec![
                op_a.pubkey_fingerprint.clone(),
                op_a.pubkey_fingerprint.clone(),
            ],
            activated_at: now,
            expires_at: now + ChronoDuration::minutes(10),
            signature_1: vec![],
            signature_2: vec![],
        };
        let just_owned = act.justification.clone();
        // Both "signatures" minted by the same operator. We
        // expect rejection BEFORE crypto check by the
        // SameOperator branch.
        act.signature_1 = sign_activation(&sk_a, &act, &just_owned);
        act.signature_2 = sign_activation(&sk_a, &act, &just_owned);

        let res = activate(act, &policy, &state, &audit);
        assert!(matches!(res, Err(BreakglassError::SameOperator { .. })));
    }

    /// TTL above the 4-h cap is rejected.
    #[test]
    fn integration_ttl_exceeds_cap_rejected() {
        let (sk_a, op_a) = make_operator(0xA1, "alice");
        let (sk_b, op_b) = make_operator(0xB2, "bob");
        let policy = bundle_with(&op_a, &op_b);
        let (_fake, audit) = paired_audit_sink();
        let tmp = tempfile::tempdir().unwrap();
        let state = BreakglassState::open(tmp.path().join("active.toml")).unwrap();

        let now = Utc::now();
        let mut act = BreakglassActivation {
            activation_id: Uuid::nil(),
            justification: "j".into(),
            activated_by: vec![
                op_a.pubkey_fingerprint.clone(),
                op_b.pubkey_fingerprint.clone(),
            ],
            activated_at: now,
            // 5 hours — above the 4-h cap.
            expires_at: now + ChronoDuration::hours(5),
            signature_1: vec![],
            signature_2: vec![],
        };
        let just_owned = act.justification.clone();
        act.signature_1 = sign_activation(&sk_a, &act, &just_owned);
        act.signature_2 = sign_activation(&sk_b, &act, &just_owned);
        let res = activate(act, &policy, &state, &audit);
        assert!(matches!(
            res,
            Err(BreakglassError::TtlExceedsMaxDuration { .. })
        ));
    }

    /// `deactivate` with an `activation_id` that does NOT match
    /// the in-effect record returns `NoMatchingRecord`, even when
    /// the operator signature verifies.
    #[test]
    fn integration_deactivate_with_wrong_activation_id_rejected() {
        let (sk_a, op_a) = make_operator(0xA1, "alice");
        let (sk_b, op_b) = make_operator(0xB2, "bob");
        let policy = bundle_with(&op_a, &op_b);
        let (_fake, audit) = paired_audit_sink();
        let tmp = tempfile::tempdir().unwrap();
        let state = BreakglassState::open(tmp.path().join("active.toml")).unwrap();

        let now = Utc::now();
        let mut act = BreakglassActivation {
            activation_id: Uuid::nil(),
            justification: "real".into(),
            activated_by: vec![
                op_a.pubkey_fingerprint.clone(),
                op_b.pubkey_fingerprint.clone(),
            ],
            activated_at: now,
            expires_at: now + ChronoDuration::minutes(30),
            signature_1: vec![],
            signature_2: vec![],
        };
        let just = act.justification.clone();
        act.signature_1 = sign_activation(&sk_a, &act, &just);
        act.signature_2 = sign_activation(&sk_b, &act, &just);
        let _real_id = activate(act, &policy, &state, &audit).unwrap();

        let bogus_id = Uuid::new_v4();
        let canonical = deactivate_signing_bytes(bogus_id, &op_a.pubkey_fingerprint);
        let sig = sk_a.sign(&canonical).to_bytes().to_vec();
        let res = deactivate(
            &op_a.pubkey_fingerprint,
            &sig,
            bogus_id,
            &policy,
            &state,
            &audit,
        );
        assert!(matches!(res, Err(BreakglassError::NoMatchingRecord { .. })));
        // State unchanged.
        assert!(matches!(state.check(), BreakglassStatus::Active { .. }));
    }
}
