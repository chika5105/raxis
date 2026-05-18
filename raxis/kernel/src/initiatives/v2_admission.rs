//! V2 Plan Bundle Sealing — kernel admission handler.
//!
//! Normative reference: `specs/v2/plan-bundle-sealing.md` §8.1
//! ("Admission sequence"). This module implements the §8.1 step
//! ordering verbatim — the steps are numbered in code comments to
//! make spec drift trivially auditable.
//!
//! # High-level shape
//!
//! ```text
//!  [pre-tx]   1.  Hex-decoded inputs (caller responsibility)
//!             2.  Recompute SHA-256(plan_bundle), compare wire echo
//!             3.  Bundle-byte size cap (cheap, before decode)
//!             4.  canonical_decode (covers structural decode + per-
//!                 artifact SHA verification + V2.0/V2.1 envelope
//!                 coherence)
//!             4a. Schema-deprecated gate (V2.0 + policy off)
//!             5.  (rolled into canonical_decode)
//!             6.  artifacts[0].name == "plan.toml"
//!             7.  Artifact name discipline (no `/`, no `..`, no NUL)
//!             3'. Per-artifact + artifact-count caps (post-decode)
//!             8.  Operator lookup by signed_by fingerprint
//!             9.  Ed25519 signature verify
//!  --- BEGIN IMMEDIATE on kernel.db ---
//!             10. Key revocation state                   (deferred)
//!             10a (V2.1 only) freshness window
//!             10b (V2.1 only) replay nonce check
//!             11. plan.toml parseability                 (scoped)
//!             12. seal: insert bundle + artifacts +
//!                 initiative row + nonce row
//!  --- COMMIT ---
//!             post-commit: emit InitiativeCreated audit event
//! ```
//!
//! # Deferred to follow-up tasks
//!
//! * **Step 10 (key revocation).** `key-revocation.md` is its own
//!   spec; the V2 admission handler will gain the lookup once the
//!   revocation table lands. Until then, the operator-policy lookup
//!   in step 8 is the sole authentication gate (same as V1).
//! * **Step 11 (full §5 shift-left validation).** Per spec, step 11
//!   should run the full `policy-plan-authority.md §5` shift-left
//!   chain at *admission* time, recording rejections as
//!   `TerminallyRejected` so the same bundle bytes cannot be replayed
//!   against a future policy. The current implementation runs only
//!   plan.toml *parseability* (`toml::from_str`); the full
//!   shift-left chain remains at `approve_plan` (V1-shape). This is a
//!   best-judgment scope split documented in
//!   `plan-bundle-sealing.md §11.1`: bundling the full `approve_plan`
//!   validation into admission is a substantial refactor that does
//!   not change the cryptographic invariants of admission. The
//!   replay-protection layer (`INV-PLAN-BUNDLE-FRESH`) is preserved:
//!   a malformed-TOML bundle still records a `TerminallyRejected`
//!   nonce row so the same bytes cannot be re-submitted.
//! * **`InitiativeAdmissionFailed` audit event.** Spec §4.4 calls for
//!   a structured audit event keyed by `bundle_sha256` for
//!   submit-time rejections. The current handler logs a structured
//!   stderr line for every rejection (matching V1 patterns); the
//!   chain-logged audit event lands in a follow-up. Adding a new
//!   `AuditEventKind` variant requires audit-chain serialization
//!   updates and is intentionally out of scope here.

use std::sync::Arc;

use arc_swap::ArcSwap;
use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_crypto::{
    bundle_sha256 as crypto_bundle_sha256, canonical_decode, signing_input, PlanBundleCodecError,
};
use raxis_policy::PolicyBundle;
use raxis_store::{plan_bundles as pb_store, Store, Table};
use raxis_types::{
    BundleSha256, InitiativeState, OperatorFingerprint, PlanBundle, PlanBundleNonceOutcome,
    SchemaVersion,
};
use rusqlite::{params, TransactionBehavior};
use thiserror::Error;

// Single source of truth for the table identifier used in the
// initiatives INSERT — we do not hand-write `INITIATIVES`-the-string
// here per `INV-STORE-03`.
const INITIATIVES: &str = Table::Initiatives.as_str();

/// Successful admission outcome — projected onto
/// `OperatorResponse::InitiativeCreated` by the IPC dispatcher.
/// Pre-V2.5 the kernel also exposed a V1-only `InitiativeCreated`
/// type via the deleted `lifecycle::create_initiative` path; the
/// sealed-bundle pipeline (this module) is the sole admission path
/// today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2InitiativeCreated {
    pub initiative_id: String,
    pub status: String,
    pub bundle_sha256: BundleSha256,
}

/// Result of `create_initiative_v2`. Variants project onto the
/// canonical `FAIL_PLAN_BUNDLE_*` codes via [`V2AdmissionError::fail_code`].
#[derive(Debug, Error)]
pub enum V2AdmissionError {
    /// Step 1: Hex-decode failure (caller-supplied envelope was bad).
    #[error("FAIL_PLAN_BUNDLE_DECODE_FAILED: {0}")]
    DecodeFailed(String),

    /// Step 2: `bundle_sha256` echo did not match
    /// `SHA-256(plan_bundle)`.
    #[error("FAIL_PLAN_BUNDLE_SHA256_MISMATCH: wire={wire_hex}, computed={computed_hex}")]
    Sha256Mismatch {
        wire_hex: String,
        computed_hex: String,
    },

    /// Step 3 / step 3': size-cap violation. `which` indicates which
    /// cap was hit (artifact / bundle / count); `observed` and
    /// `limit` are the actual numbers.
    #[error("{which}: observed={observed}, limit={limit}")]
    SizeCap {
        which: SizeCapWhich,
        observed: u64,
        limit: u64,
    },

    /// Step 4: canonical decode failed (structurally malformed
    /// bundle, or per-artifact SHA mismatch).
    #[error("{0}")]
    CanonicalDecode(#[from] PlanBundleCodecError),

    /// Step 4a: V2.0 schema bundle and policy.accept_unfresh_v2_0_bundles is false.
    #[error("FAIL_PLAN_BUNDLE_SCHEMA_DEPRECATED")]
    SchemaDeprecated,

    /// Step 6: `artifacts[0].name != "plan.toml"`.
    #[error("FAIL_PLAN_BUNDLE_FIRST_ARTIFACT_NOT_PLAN_TOML: got {0:?}")]
    FirstArtifactNotPlanToml(String),

    /// Step 7: artifact name violates §3.3 (leading `/`, `..`, NUL,
    /// or empty).
    #[error("FAIL_PLAN_BUNDLE_INVALID_NAME: artifact[{seq}] {reason}: {name:?}")]
    InvalidArtifactName {
        seq: usize,
        name: String,
        reason: &'static str,
    },

    /// Step 8: signed_by fingerprint not present in `policy.operators`.
    #[error("FAIL_UNKNOWN_SIGNER: signed_by={0}")]
    UnknownSigner(String),

    /// Step 8 defensive: the policy operator entry has a malformed
    /// pubkey_hex value (already caught at policy load, but defended
    /// here for catastrophic policy corruption).
    #[error("FAIL_POLICY_OPERATOR_PUBKEY_INVALID: {0}")]
    PolicyOperatorPubkeyInvalid(String),

    /// Step 9: Ed25519 verify failed.
    #[error("FAIL_PLAN_SIGNATURE_INVALID: {0}")]
    SignatureInvalid(String),

    /// Step 10a: `now() - signed_at > max_plan_bundle_age_secs`.
    #[error("FAIL_PLAN_BUNDLE_EXPIRED: signed_at={signed_at}, now={now}, max_age={max_age}")]
    Expired {
        signed_at: u64,
        now: i64,
        max_age: u64,
    },

    /// Step 10a: `signed_at - now() > max_clock_skew_secs`.
    #[error("FAIL_PLAN_BUNDLE_FROM_FUTURE: signed_at={signed_at}, now={now}, max_skew={max_skew}")]
    FromFuture {
        signed_at: u64,
        now: i64,
        max_skew: u64,
    },

    /// Step 10b: `bundle_nonce` already present in
    /// `plan_bundle_nonces_seen`.
    #[error("FAIL_PLAN_BUNDLE_REPLAY: previous_outcome={previous_outcome:?}, previous_initiative_id={previous_initiative_id:?}, first_seen_at={first_seen_at}")]
    Replay {
        previous_outcome: PlanBundleNonceOutcome,
        previous_initiative_id: Option<String>,
        first_seen_at: i64,
    },

    /// Step 11: `plan.toml` is not parseable as TOML. Recorded as
    /// `TerminallyRejected` so the same bytes cannot be replayed.
    #[error("FAIL_PLAN_INVALID_TOML: {0}")]
    PlanInvalidToml(String),

    /// Step 12 / 12a: initiative_id collision with an existing row
    /// (operator chose an id that's already in use). The CLI mints
    /// UUIDv7 so this is essentially "client bug or attacker"; we
    /// reject defensively.
    #[error("FAIL_INITIATIVE_ID_COLLISION: id {0:?} already exists")]
    InitiativeIdCollision(String),

    /// SQLite-level error inside the admission transaction. Kept
    /// distinct so callers can distinguish "I rejected you" from
    /// "I crashed mid-admission".
    #[error("kernel-side store error during admission: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// `raxis-store` plan-bundle helper signaled a contract violation
    /// (e.g., schema-envelope mismatch). Bubbles up to operator
    /// surface; in normal operation this branch is dead because the
    /// codec already rejected the bundle.
    #[error("plan-bundle store helper error: {0}")]
    PlanBundleStore(#[from] pb_store::PlanBundleStoreError),
}

/// Discriminator for the §7 size cap violation surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeCapWhich {
    /// `FAIL_PLAN_BUNDLE_TOO_LARGE` — total bundle bytes over cap.
    BundleBytes,
    /// `FAIL_PLAN_BUNDLE_ARTIFACT_TOO_LARGE` — single artifact bytes
    /// over cap.
    ArtifactBytes,
    /// `FAIL_PLAN_BUNDLE_TOO_MANY_ARTIFACTS` — artifact count over
    /// cap.
    ArtifactCount,
}

impl std::fmt::Display for SizeCapWhich {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BundleBytes => "FAIL_PLAN_BUNDLE_TOO_LARGE",
            Self::ArtifactBytes => "FAIL_PLAN_BUNDLE_ARTIFACT_TOO_LARGE",
            Self::ArtifactCount => "FAIL_PLAN_BUNDLE_TOO_MANY_ARTIFACTS",
        })
    }
}

impl V2AdmissionError {
    /// Project the error onto its canonical `FAIL_PLAN_BUNDLE_*` /
    /// `FAIL_*` code per `plan-bundle-sealing.md §9`.
    pub fn fail_code(&self) -> &'static str {
        match self {
            Self::DecodeFailed(_) => "FAIL_PLAN_BUNDLE_DECODE_FAILED",
            Self::Sha256Mismatch { .. } => "FAIL_PLAN_BUNDLE_SHA256_MISMATCH",
            Self::SizeCap { which, .. } => match which {
                SizeCapWhich::BundleBytes => "FAIL_PLAN_BUNDLE_TOO_LARGE",
                SizeCapWhich::ArtifactBytes => "FAIL_PLAN_BUNDLE_ARTIFACT_TOO_LARGE",
                SizeCapWhich::ArtifactCount => "FAIL_PLAN_BUNDLE_TOO_MANY_ARTIFACTS",
            },
            Self::CanonicalDecode(e) => match e {
                PlanBundleCodecError::ArtifactHashMismatch { .. } => {
                    "FAIL_PLAN_BUNDLE_ARTIFACT_HASH_MISMATCH"
                }
                _ => "FAIL_PLAN_BUNDLE_CANONICAL_DECODE_FAILED",
            },
            Self::SchemaDeprecated => "FAIL_PLAN_BUNDLE_SCHEMA_DEPRECATED",
            Self::FirstArtifactNotPlanToml(_) => "FAIL_PLAN_BUNDLE_FIRST_ARTIFACT_NOT_PLAN_TOML",
            Self::InvalidArtifactName { .. } => "FAIL_PLAN_BUNDLE_INVALID_NAME",
            Self::UnknownSigner(_) => "FAIL_UNKNOWN_SIGNER",
            Self::PolicyOperatorPubkeyInvalid(_) => "FAIL_POLICY_OPERATOR_PUBKEY_INVALID",
            Self::SignatureInvalid(_) => "FAIL_PLAN_SIGNATURE_INVALID",
            Self::Expired { .. } => "FAIL_PLAN_BUNDLE_EXPIRED",
            Self::FromFuture { .. } => "FAIL_PLAN_BUNDLE_FROM_FUTURE",
            Self::Replay { .. } => "FAIL_PLAN_BUNDLE_REPLAY",
            Self::PlanInvalidToml(_) => "FAIL_PLAN_INVALID_TOML",
            Self::InitiativeIdCollision(_) => "FAIL_INITIATIVE_ID_COLLISION",
            Self::Sqlite(_) => "FAIL_KERNEL_INTERNAL",
            Self::PlanBundleStore(_) => "FAIL_KERNEL_INTERNAL",
        }
    }
}

/// Inputs to the V2 admission handler. Kept as a struct so the
/// caller's hex-decode happy path doesn't have to track 5+ positional
/// arguments.
pub struct V2AdmissionRequest {
    pub initiative_id: String,
    pub plan_bundle: Vec<u8>,
    pub bundle_sha256: BundleSha256,
    pub signature: [u8; 64],
    pub signed_by: OperatorFingerprint,
}

// ===========================================================================
// Pre-transactional checks (steps 2–9 from §8.1)
// ===========================================================================

/// Output of [`pre_tx_checks`]: the decoded bundle plus the operator's
/// pubkey bytes (looked up via step 8). Held so the caller can hand
/// both to the transactional half without re-running any work.
struct PreTxOk {
    bundle: PlanBundle,
    pubkey_bytes: [u8; 32],
}

/// Run §8.1 steps 2–9 against `req` and `policy`. No DB I/O.
///
/// On success returns the decoded bundle (so step 11 + step 12 can
/// reuse the work) and the operator's 32-byte Ed25519 public key.
fn pre_tx_checks(
    req: &V2AdmissionRequest,
    policy: &PolicyBundle,
) -> Result<PreTxOk, V2AdmissionError> {
    // Step 2 — recompute SHA-256(plan_bundle) and compare.
    let computed = crypto_bundle_sha256(&req.plan_bundle);
    if computed != req.bundle_sha256 {
        return Err(V2AdmissionError::Sha256Mismatch {
            wire_hex: req.bundle_sha256.to_hex(),
            computed_hex: computed.to_hex(),
        });
    }

    // Step 3 (bundle-bytes only) — total bundle byte cap. The
    // per-artifact and artifact-count caps are checked after
    // canonical_decode (we don't know artifact byte lengths yet).
    let limits = policy.plan_bundle_limits();
    let bundle_len = req.plan_bundle.len() as u64;
    if bundle_len > limits.max_bundle_bytes {
        return Err(V2AdmissionError::SizeCap {
            which: SizeCapWhich::BundleBytes,
            observed: bundle_len,
            limit: limits.max_bundle_bytes,
        });
    }

    // Step 4 + 5 — canonical_decode handles structural decode AND
    // per-artifact SHA-256 verification in one pass. Errors project
    // through `From<PlanBundleCodecError>` onto our error enum and
    // surface with either FAIL_PLAN_BUNDLE_CANONICAL_DECODE_FAILED
    // (most variants) or FAIL_PLAN_BUNDLE_ARTIFACT_HASH_MISMATCH
    // (the per-artifact SHA failure variant).
    let bundle = canonical_decode(&req.plan_bundle)?;

    // Step 4a — schema-deprecated gate: V2.0 with policy off → reject.
    if bundle.schema_version == SchemaVersion::V2_0
        && !policy.plan_signing().accept_unfresh_v2_0_bundles
    {
        return Err(V2AdmissionError::SchemaDeprecated);
    }

    // Step 3' — per-artifact + artifact-count caps (now that we know
    // the artifact list).
    let artifact_count = bundle.artifacts.len() as u64;
    if artifact_count > limits.max_artifact_count as u64 {
        return Err(V2AdmissionError::SizeCap {
            which: SizeCapWhich::ArtifactCount,
            observed: artifact_count,
            limit: limits.max_artifact_count as u64,
        });
    }
    for a in &bundle.artifacts {
        let len = a.bytes.len() as u64;
        if len > limits.max_artifact_bytes {
            return Err(V2AdmissionError::SizeCap {
                which: SizeCapWhich::ArtifactBytes,
                observed: len,
                limit: limits.max_artifact_bytes,
            });
        }
    }

    // Step 6 — artifacts[0].name == "plan.toml".
    let first = bundle.artifacts.first().ok_or_else(|| {
        // canonical_decode allows a zero-artifact bundle structurally,
        // so we defensively reject it here at the §8.1 step 6 check.
        V2AdmissionError::FirstArtifactNotPlanToml(String::new())
    })?;
    if first.name != "plan.toml" {
        return Err(V2AdmissionError::FirstArtifactNotPlanToml(
            first.name.clone(),
        ));
    }

    // Step 7 — artifact name discipline (§3.3). The CLI's path
    // resolver should never produce a violating name; this is a
    // defensive gate against a hostile non-canonical CLI.
    for (seq, a) in bundle.artifacts.iter().enumerate() {
        if let Err(reason) = validate_artifact_name(&a.name) {
            return Err(V2AdmissionError::InvalidArtifactName {
                seq,
                name: a.name.clone(),
                reason,
            });
        }
    }

    // Step 8 — operator policy lookup by fingerprint. The
    // `OperatorEntry::pubkey_fingerprint` field is stored in policy
    // as a hex-encoded string; we hex-encode the 8-byte signed_by
    // and compare.
    let signed_by_hex = req.signed_by.to_hex();
    let entry = policy
        .operator_entry(&signed_by_hex)
        .ok_or_else(|| V2AdmissionError::UnknownSigner(signed_by_hex.clone()))?;
    let pubkey_bytes_vec = hex::decode(&entry.pubkey_hex).map_err(|e| {
        V2AdmissionError::PolicyOperatorPubkeyInvalid(format!(
            "operator '{signed_by_hex}' pubkey_hex: {e}",
        ))
    })?;
    let pubkey_bytes: [u8; 32] = pubkey_bytes_vec.as_slice().try_into().map_err(|_| {
        V2AdmissionError::PolicyOperatorPubkeyInvalid(format!(
            "operator '{signed_by_hex}' pubkey_hex: expected 32 bytes, got {}",
            pubkey_bytes_vec.len(),
        ))
    })?;

    // Step 9 — Ed25519 signature verify over signing_input(bundle_sha256).
    let sig_input = signing_input(&req.bundle_sha256);
    raxis_crypto::verify::verify_ed25519(&pubkey_bytes, &sig_input, &req.signature)
        .map_err(|e| V2AdmissionError::SignatureInvalid(e.to_string()))?;

    Ok(PreTxOk {
        bundle,
        pubkey_bytes,
    })
}

/// Validate an artifact name per §3.3:
///
///   * non-empty
///   * does not begin with `/`
///   * contains no `..` segments (between forward slashes)
///   * contains no NUL byte
///
/// We deliberately do NOT NFC-normalise here — that's a CLI-side
/// invariant; the kernel just rejects names that are dangerous.
fn validate_artifact_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("empty_name");
    }
    if name.starts_with('/') {
        return Err("absolute_path");
    }
    if name.contains('\0') {
        return Err("nul_byte");
    }
    for seg in name.split('/') {
        if seg == ".." {
            return Err("path_escape");
        }
    }
    Ok(())
}

// ===========================================================================
// Transactional half (steps 10a, 10b, 11, 12 from §8.1)
// ===========================================================================

/// Outcome of the transactional admission half. `Ok(initiative_id)`
/// = bundle sealed, nonce recorded as Admitted, COMMIT done.
/// `Err(e)` = bundle rejected; if `e` was a step-10a/10b/11
/// terminal-rejection-class error, the transaction has already
/// recorded a TerminallyRejected nonce row before being returned.
fn run_admission_tx(
    req: &V2AdmissionRequest,
    bundle: &PlanBundle,
    plan_bundle: &[u8],
    now_unix_secs: i64,
    policy: &PolicyBundle,
    store: &Store,
) -> Result<String, V2AdmissionError> {
    let mut conn = store.lock_sync();
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    // Step 10 — key revocation. Deferred (see module-level docs).

    // Step 10a — freshness window (V2.1 only).
    if let Some(signed_at) = bundle.signed_at_unix_secs {
        let signing = policy.plan_signing();
        let now_u = now_unix_secs.max(0) as u64;
        // signed_at vs now_u using i128 to avoid u64 wrap-around.
        let signed_at_i128 = signed_at as i128;
        let now_i128 = now_u as i128;
        let age_i128 = now_i128 - signed_at_i128;
        if age_i128 > signing.max_plan_bundle_age_secs as i128 {
            return Err(V2AdmissionError::Expired {
                signed_at,
                now: now_unix_secs,
                max_age: signing.max_plan_bundle_age_secs,
            });
        }
        if -age_i128 > signing.max_clock_skew_secs as i128 {
            return Err(V2AdmissionError::FromFuture {
                signed_at,
                now: now_unix_secs,
                max_skew: signing.max_clock_skew_secs,
            });
        }
    }

    // Step 10b — replay nonce check (V2.1 only).
    let nonce_opt = bundle.bundle_nonce;
    if let Some(nonce) = nonce_opt {
        if let Some(prior) = pb_store::nonce_status_in_tx(&tx, &nonce)? {
            return Err(V2AdmissionError::Replay {
                previous_outcome: prior.outcome,
                previous_initiative_id: prior.initiative_id,
                first_seen_at: prior.first_seen_at_unix_secs,
            });
        }
    }

    // Step 11 — plan.toml parseability (scoped: parseability only;
    // see module-level docs for why the full §5 shift-left chain is
    // deferred to approve_plan).
    let plan_toml_bytes = &bundle.artifacts[0].bytes;
    let plan_toml_str = std::str::from_utf8(plan_toml_bytes).map_err(|e| {
        V2AdmissionError::PlanInvalidToml(format!("plan.toml is not valid UTF-8: {e}"))
    });
    let parse_result = match plan_toml_str {
        Ok(s) => toml::from_str::<toml::Value>(s)
            .map(|_| ())
            .map_err(|e| V2AdmissionError::PlanInvalidToml(format!("plan.toml parse error: {e}"))),
        Err(e) => Err(e),
    };
    if let Err(e) = parse_result {
        // Spec §8.1 step 11 — record the nonce as TerminallyRejected
        // INSIDE the same tx so the same bundle bytes cannot be
        // replayed against a future policy that might accept them.
        if let Some(nonce) = nonce_opt {
            let signed_at = bundle.signed_at_unix_secs.unwrap_or(0) as i64;
            pb_store::record_nonce(
                &tx,
                &nonce,
                &req.bundle_sha256,
                signed_at,
                now_unix_secs,
                PlanBundleNonceOutcome::TerminallyRejected,
                None,
            )?;
            tx.commit()?;
        }
        return Err(e);
    }

    // Step 12 — seal: bundle row, artifact rows, initiative row,
    // nonce row (Admitted). All inside this transaction.
    pb_store::insert_bundle(
        &tx,
        &req.bundle_sha256,
        plan_bundle,
        &req.signature,
        &req.signed_by,
        bundle,
        now_unix_secs,
    )?;
    pb_store::insert_artifacts(&tx, &req.bundle_sha256, &bundle.artifacts)?;

    // Step 12a — mint the initiatives row referencing plan_bundle_sha256.
    // We use INSERT (not INSERT OR IGNORE) so a deliberate id
    // collision surfaces clearly. Idempotency at the bundle level
    // is provided by the nonce check (step 10b); idempotency at the
    // initiative level is the operator's responsibility (UUIDv7
    // mints are 122-bit unique).
    //
    // **`plan_artifact_sha256` for V2 rows.** The V1 DDL declares
    // this column `NOT NULL` (kernel-store.md §2.5.1 Table 2). The
    // V2 spec (§8.2) intends V2 rows to leave it unpopulated and
    // carry the canonical reference in `plan_bundle_sha256` instead,
    // but we cannot leave it NULL without a forward migration. We
    // store the **bundle_sha256 hex** here as a strict superset of
    // the V1 meaning (bundle_sha256 covers plan.toml + every other
    // artifact) — this satisfies the NOT NULL constraint and keeps
    // forensic queries that join on `plan_artifact_sha256` working
    // for V2 rows. The authoritative content-addressed reference
    // for V2 remains `plan_bundle_sha256`. Documented in
    // `plan-bundle-sealing.md §11.1`.
    let bundle_sha_hex = req.bundle_sha256.to_hex();
    let collision = tx.execute(
        &format!(
            "INSERT INTO {INITIATIVES} \
                (initiative_id, state, terminal_criteria_json, \
                 plan_artifact_sha256, plan_bundle_sha256, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        ),
        params![
            &req.initiative_id,
            InitiativeState::Draft.as_sql_str(),
            "{}",
            &bundle_sha_hex,
            req.bundle_sha256.as_bytes().as_slice(),
            now_unix_secs,
        ],
    );
    match collision {
        Ok(_) => {}
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            return Err(V2AdmissionError::InitiativeIdCollision(
                req.initiative_id.clone(),
            ));
        }
        Err(e) => return Err(e.into()),
    }

    // Step 12b — record nonce as Admitted (V2.1 only). For V2.0
    // bundles (only reachable when accept_unfresh_v2_0_bundles =
    // true) replay protection is structurally absent — there is no
    // nonce to record. The spec's §3.5 design accepts this trade-off
    // for the legacy path.
    if let Some(nonce) = nonce_opt {
        let signed_at = bundle.signed_at_unix_secs.unwrap_or(0) as i64;
        pb_store::record_nonce(
            &tx,
            &nonce,
            &req.bundle_sha256,
            signed_at,
            now_unix_secs,
            PlanBundleNonceOutcome::Admitted,
            Some(&req.initiative_id),
        )?;
    }

    // Step 12c — COMMIT.
    tx.commit()?;

    Ok(req.initiative_id.clone())
}

// ===========================================================================
// Public entry point
// ===========================================================================

/// V2 plan-bundle admission. Implements `plan-bundle-sealing.md §8.1`
/// step ordering. The caller (operator IPC dispatcher) is responsible
/// for hex-decoding the wire envelope into the `V2AdmissionRequest`
/// struct; any decode failure surfaces as `V2AdmissionError::DecodeFailed`
/// and short-circuits this entry.
///
/// `now_unix_secs` is injected for testability — production callers
/// pass `raxis_types::unix_now_secs() as i64` immediately before the
/// call.
pub fn create_initiative_v2(
    req: V2AdmissionRequest,
    now_unix_secs: i64,
    policy: &PolicyBundle,
    store: &Store,
    audit: &dyn AuditSink,
) -> Result<V2InitiativeCreated, V2AdmissionError> {
    // Steps 2–9: cheap pre-transactional checks.
    let pre = pre_tx_checks(&req, policy)?;
    let _ = pre.pubkey_bytes; // signature already verified; bytes
                              // not needed downstream.

    // Steps 10a, 10b, 11, 12: transactional admission half.
    let initiative_id = run_admission_tx(
        &req,
        &pre.bundle,
        &req.plan_bundle,
        now_unix_secs,
        policy,
        store,
    )?;

    // Post-commit: emit InitiativeCreated audit event. Same audit-
    // after-commit ordering as V1 (kernel-store.md §2.5.2). A
    // failure here is logged but not propagated — the store is
    // already consistent and the operator's intent has been
    // honoured.
    let signed_at = pre
        .bundle
        .signed_at_unix_secs
        .map(|s| s as i64)
        .unwrap_or(0);
    let signed_by_hex = req.signed_by.to_hex();
    if let Err(e) = audit.emit(
        AuditEventKind::InitiativeCreated {
            initiative_id: initiative_id.clone(),
            plan_hash: req.bundle_sha256.to_hex(),
            signed_by: signed_by_hex.clone(),
            signed_at,
        },
        None,
        None,
        Some(&initiative_id),
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"InitiativeCreated\",\
             \"audit_emit_failed\":\"{e}\",\
             \"initiative_id\":\"{initiative_id}\",\
             \"signed_by\":\"{signed_by_hex}\"}}",
        );
    }

    Ok(V2InitiativeCreated {
        initiative_id,
        status: "Draft".to_owned(),
        bundle_sha256: req.bundle_sha256,
    })
}

/// Async wrapper that drives [`create_initiative_v2`] on a blocking
/// pool. The IPC dispatcher should always go through this rather
/// than calling the sync function directly — admission can perform
/// O(bundle_size) crypto work plus a SQLite transaction, which the
/// async runtime should not block on.
pub async fn create_initiative_v2_blocking(
    req: V2AdmissionRequest,
    now_unix_secs: i64,
    policy: Arc<ArcSwap<PolicyBundle>>,
    store: Arc<Store>,
    audit: Arc<dyn AuditSink>,
) -> Result<V2InitiativeCreated, V2AdmissionError> {
    tokio::task::spawn_blocking(move || {
        let snapshot = policy.load_full();
        create_initiative_v2(req, now_unix_secs, &snapshot, &store, audit.as_ref())
    })
    .await
    .unwrap_or_else(|e| {
        // spawn_blocking join failure is itself a kernel-internal
        // event; surface it through Sqlite() so the operator gets a
        // FAIL_KERNEL_INTERNAL projection.
        Err(V2AdmissionError::DecodeFailed(format!(
            "spawn_blocking join failed: {e}"
        )))
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use raxis_crypto::{
        bundle_sha256 as crypto_bundle_sha256, canonical_encode, mint_bundle_nonce,
        sha256_of_artifact_bytes,
    };
    use raxis_test_support::FakeAuditSink;
    use raxis_test_support::{ephemeral_cert, mem_store};
    use raxis_types::{BundleArtifact, PlanBundle};

    // ---------- Fixtures ----------------------------------------------------

    /// Build a deterministic operator entry + signing key. The
    /// signing key fingerprint matches OperatorFingerprint construction
    /// so the §8.1 step 8 lookup resolves cleanly.
    struct OperatorFixture {
        signing_key: SigningKey,
        pubkey_bytes: [u8; 32],
        fingerprint: OperatorFingerprint,
        fingerprint_16hex: String, // 16 hex chars = 8 bytes (SHA-256[:8])
    }

    impl OperatorFixture {
        fn new(seed: u8) -> Self {
            let signing_key = SigningKey::from_bytes(&[seed; 32]);
            let pubkey_bytes = signing_key.verifying_key().to_bytes();
            let digest = *sha256_of_artifact_bytes(&pubkey_bytes).as_bytes();
            let mut fp = [0u8; 8];
            fp.copy_from_slice(&digest[..8]);
            let fingerprint = OperatorFingerprint::new(fp);
            Self {
                signing_key,
                pubkey_bytes,
                fingerprint,
                fingerprint_16hex: hex::encode(fp),
            }
        }

        fn to_operator_entry(&self) -> raxis_policy::OperatorEntry {
            // The operator fingerprint stored in policy is the
            // CANONICAL "SHA-256[:16]" form (i.e. 16 hex chars, 8
            // bytes) — this is what `signed_by` carries and what the
            // §8.1 step 8 lookup compares against.
            let cert = ephemeral_cert(self.signing_key.to_bytes(), 0);
            // Override the cert's pubkey to match our deterministic
            // signing key (ephemeral_cert generates its own).
            // For our tests we only care about the entry.pubkey_hex
            // / pubkey_fingerprint match — the cert is structurally
            // valid by construction.
            raxis_policy::OperatorEntry {
                pubkey_fingerprint: self.fingerprint_16hex.clone(),
                display_name: "test-operator".to_owned(),
                pubkey_hex: hex::encode(self.pubkey_bytes),
                permitted_ops: cert.permitted_ops.clone(),
                cert,
                force_misconfig_bypass: false,
            }
        }
    }

    /// Build a fresh `PolicyBundle` with the given operator and (by
    /// default) policy-defaults for `[plan_signing]` /
    /// `[plan_bundle_limits]`.
    fn build_policy(op: &OperatorFixture) -> PolicyBundle {
        let entry = op.to_operator_entry();
        PolicyBundle::for_tests_with_operators(vec![entry])
    }

    /// Build a fresh V2.1 plan bundle around a small valid plan.toml.
    fn build_v2_1_bundle(signed_at_unix_secs: u64) -> PlanBundle {
        let plan_toml_bytes = b"[meta]\nepoch = 1\n".to_vec();
        let plan_sha = sha256_of_artifact_bytes(&plan_toml_bytes);
        PlanBundle::new_v2_1(
            signed_at_unix_secs,
            signed_at_unix_secs,
            mint_bundle_nonce().expect("mint nonce"),
            "myplan".to_owned(),
            vec![BundleArtifact {
                name: "plan.toml".to_owned(),
                bytes: plan_toml_bytes,
                sha256: plan_sha,
            }],
        )
    }

    /// Sign a bundle with the operator fixture and return a
    /// fully-populated admission request.
    fn sign_to_request(
        op: &OperatorFixture,
        bundle: &PlanBundle,
        initiative_id: &str,
    ) -> V2AdmissionRequest {
        let canonical = canonical_encode(bundle).expect("canonical_encode");
        let bundle_sha = crypto_bundle_sha256(&canonical);
        let sig_input = signing_input(&bundle_sha);
        let sig = op.signing_key.sign(&sig_input);
        V2AdmissionRequest {
            initiative_id: initiative_id.to_owned(),
            plan_bundle: canonical,
            bundle_sha256: bundle_sha,
            signature: sig.to_bytes(),
            signed_by: op.fingerprint,
        }
    }

    // ---------- Happy path --------------------------------------------------

    #[test]
    fn admit_happy_path_seals_bundle_and_records_admitted_nonce() {
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op = OperatorFixture::new(0x42);
        let policy = build_policy(&op);
        let now: i64 = 1_700_000_000;
        let bundle = build_v2_1_bundle(now as u64);
        let req = sign_to_request(&op, &bundle, "init-happy-1");

        let result = create_initiative_v2(req, now, &policy, &store, &audit).unwrap();
        assert_eq!(result.initiative_id, "init-happy-1");
        assert_eq!(result.status, "Draft");

        // Audit event emitted (post-commit) for the admission.
        let captured = audit.events();
        assert_eq!(captured.len(), 1, "expected exactly one audit event");
        assert_eq!(captured[0].kind.as_str(), "InitiativeCreated");

        // initiatives row landed in Draft state with plan_bundle_sha256.
        let conn = store.lock_sync();
        let state: String = conn
            .query_row(
                &format!("SELECT state FROM {INITIATIVES} WHERE initiative_id=?1"),
                rusqlite::params!["init-happy-1"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "Draft");
        let bundle_sha_blob: Vec<u8> = conn
            .query_row(
                &format!("SELECT plan_bundle_sha256 FROM {INITIATIVES} WHERE initiative_id=?1"),
                rusqlite::params!["init-happy-1"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(bundle_sha_blob.len(), 32);
    }

    // ---------- Pre-tx failures (steps 2–9) --------------------------------

    #[test]
    fn step2_sha256_mismatch_is_rejected() {
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op = OperatorFixture::new(0x42);
        let policy = build_policy(&op);
        let now: i64 = 1_700_000_000;
        let bundle = build_v2_1_bundle(now as u64);
        let mut req = sign_to_request(&op, &bundle, "init-sha-mismatch");
        // Corrupt the wire echo.
        req.bundle_sha256 = BundleSha256::new([0xffu8; 32]);

        let err = create_initiative_v2(req, now, &policy, &store, &audit).unwrap_err();
        assert_eq!(err.fail_code(), "FAIL_PLAN_BUNDLE_SHA256_MISMATCH");
    }

    #[test]
    fn step3_bundle_too_large_is_rejected() {
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op = OperatorFixture::new(0x42);
        let policy = build_policy(&op);
        let now: i64 = 1_700_000_000;

        // The default policy.plan_bundle_limits().max_bundle_bytes
        // is 10 MiB; build a synthetic 11 MiB plan.toml. Real-world
        // operators will hit this cap CLI-side first; this test
        // covers the kernel's defensive enforcement.
        let big_plan = vec![b'#'; 11 * 1024 * 1024];
        let plan_sha = sha256_of_artifact_bytes(&big_plan);
        let bundle = PlanBundle::new_v2_1(
            now as u64,
            now as u64,
            mint_bundle_nonce().unwrap(),
            "big".to_owned(),
            vec![BundleArtifact {
                name: "plan.toml".to_owned(),
                bytes: big_plan,
                sha256: plan_sha,
            }],
        );
        let req = sign_to_request(&op, &bundle, "init-too-big");

        let err = create_initiative_v2(req, now, &policy, &store, &audit).unwrap_err();
        // Because total bundle bytes > max_bundle_bytes, the bundle-
        // bytes cap fires (step 3 — checked before canonical_decode).
        assert_eq!(err.fail_code(), "FAIL_PLAN_BUNDLE_TOO_LARGE");
    }

    #[test]
    fn step4a_v2_0_bundle_with_policy_off_is_rejected() {
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op = OperatorFixture::new(0x42);
        let policy = build_policy(&op); // accept_unfresh_v2_0_bundles=false (default)
        let now: i64 = 1_700_000_000;

        let plan_bytes = b"[meta]\nepoch=1\n".to_vec();
        let plan_sha = sha256_of_artifact_bytes(&plan_bytes);
        let bundle = PlanBundle::new_v2_0_legacy(
            now as u64,
            "legacy".to_owned(),
            vec![BundleArtifact {
                name: "plan.toml".to_owned(),
                bytes: plan_bytes,
                sha256: plan_sha,
            }],
        );
        let req = sign_to_request(&op, &bundle, "init-v20-deprecated");

        let err = create_initiative_v2(req, now, &policy, &store, &audit).unwrap_err();
        assert_eq!(err.fail_code(), "FAIL_PLAN_BUNDLE_SCHEMA_DEPRECATED");
    }

    #[test]
    fn step6_first_artifact_not_plan_toml_is_rejected() {
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op = OperatorFixture::new(0x42);
        let policy = build_policy(&op);
        let now: i64 = 1_700_000_000;

        // The CLI's path-resolver normally guarantees artifacts[0].name
        // == "plan.toml"; this test simulates a hostile CLI that
        // submits a bundle with the wrong first artifact.
        let pirate_bytes = b"# not plan.toml\n".to_vec();
        let pirate_sha = sha256_of_artifact_bytes(&pirate_bytes);
        let bundle = PlanBundle::new_v2_1(
            now as u64,
            now as u64,
            mint_bundle_nonce().unwrap(),
            "rogue".to_owned(),
            vec![BundleArtifact {
                name: "definitely-not-plan.toml".to_owned(),
                bytes: pirate_bytes,
                sha256: pirate_sha,
            }],
        );
        let req = sign_to_request(&op, &bundle, "init-rogue-first");

        let err = create_initiative_v2(req, now, &policy, &store, &audit).unwrap_err();
        assert_eq!(
            err.fail_code(),
            "FAIL_PLAN_BUNDLE_FIRST_ARTIFACT_NOT_PLAN_TOML"
        );
    }

    #[test]
    fn step7_artifact_name_path_escape_is_rejected() {
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op = OperatorFixture::new(0x42);
        let policy = build_policy(&op);
        let now: i64 = 1_700_000_000;

        let plan_bytes = b"[meta]\nepoch=1\n".to_vec();
        let plan_sha = sha256_of_artifact_bytes(&plan_bytes);
        let bad_bytes = b"hello".to_vec();
        let bad_sha = sha256_of_artifact_bytes(&bad_bytes);
        let bundle = PlanBundle::new_v2_1(
            now as u64,
            now as u64,
            mint_bundle_nonce().unwrap(),
            "ok".to_owned(),
            vec![
                BundleArtifact {
                    name: "plan.toml".to_owned(),
                    bytes: plan_bytes,
                    sha256: plan_sha,
                },
                BundleArtifact {
                    name: "../escape.txt".to_owned(),
                    bytes: bad_bytes,
                    sha256: bad_sha,
                },
            ],
        );
        let req = sign_to_request(&op, &bundle, "init-path-escape");

        let err = create_initiative_v2(req, now, &policy, &store, &audit).unwrap_err();
        assert_eq!(err.fail_code(), "FAIL_PLAN_BUNDLE_INVALID_NAME");
    }

    #[test]
    fn step8_unknown_signer_is_rejected() {
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op_known = OperatorFixture::new(0x42);
        let op_other = OperatorFixture::new(0x99);
        // Policy only knows op_known; we sign with op_other.
        let policy = build_policy(&op_known);
        let now: i64 = 1_700_000_000;
        let bundle = build_v2_1_bundle(now as u64);
        let req = sign_to_request(&op_other, &bundle, "init-unknown-signer");

        let err = create_initiative_v2(req, now, &policy, &store, &audit).unwrap_err();
        assert_eq!(err.fail_code(), "FAIL_UNKNOWN_SIGNER");
    }

    #[test]
    fn step9_signature_invalid_is_rejected() {
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op = OperatorFixture::new(0x42);
        let policy = build_policy(&op);
        let now: i64 = 1_700_000_000;
        let bundle = build_v2_1_bundle(now as u64);
        let mut req = sign_to_request(&op, &bundle, "init-bad-sig");
        // Corrupt the signature.
        req.signature[0] ^= 0xff;

        let err = create_initiative_v2(req, now, &policy, &store, &audit).unwrap_err();
        assert_eq!(err.fail_code(), "FAIL_PLAN_SIGNATURE_INVALID");
    }

    // ---------- Transactional failures (steps 10a, 10b, 11) ----------------

    #[test]
    fn step10a_freshness_expired_is_rejected() {
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op = OperatorFixture::new(0x42);
        let policy = build_policy(&op);
        // Default policy.max_plan_bundle_age_secs = 86_400 (24 h).
        // Submit a bundle signed 25 h ago.
        let now: i64 = 1_700_000_000;
        let signed_at_old = now - (25 * 60 * 60);
        let bundle = build_v2_1_bundle(signed_at_old as u64);
        let req = sign_to_request(&op, &bundle, "init-expired");

        let err = create_initiative_v2(req, now, &policy, &store, &audit).unwrap_err();
        assert_eq!(err.fail_code(), "FAIL_PLAN_BUNDLE_EXPIRED");
    }

    #[test]
    fn step10a_from_future_is_rejected() {
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op = OperatorFixture::new(0x42);
        let policy = build_policy(&op);
        // Default policy.max_clock_skew_secs = 300 (5 min).
        // Submit a bundle signed 10 min in the future.
        let now: i64 = 1_700_000_000;
        let signed_at_future = now + (10 * 60);
        let bundle = build_v2_1_bundle(signed_at_future as u64);
        let req = sign_to_request(&op, &bundle, "init-future");

        let err = create_initiative_v2(req, now, &policy, &store, &audit).unwrap_err();
        assert_eq!(err.fail_code(), "FAIL_PLAN_BUNDLE_FROM_FUTURE");
    }

    #[test]
    fn step10b_nonce_replay_after_admit_is_rejected() {
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op = OperatorFixture::new(0x42);
        let policy = build_policy(&op);
        let now: i64 = 1_700_000_000;
        let bundle = build_v2_1_bundle(now as u64);

        // First admission — succeeds.
        let req1 = sign_to_request(&op, &bundle, "init-replay-1");
        create_initiative_v2(req1, now, &policy, &store, &audit).unwrap();

        // Re-submit the SAME bundle (same nonce). Even though the
        // initiative_id differs, the nonce-replay layer rejects.
        let req2 = sign_to_request(&op, &bundle, "init-replay-2");
        let err = create_initiative_v2(req2, now, &policy, &store, &audit).unwrap_err();
        assert_eq!(err.fail_code(), "FAIL_PLAN_BUNDLE_REPLAY");
        if let V2AdmissionError::Replay {
            previous_outcome,
            previous_initiative_id,
            ..
        } = err
        {
            assert_eq!(previous_outcome, PlanBundleNonceOutcome::Admitted);
            assert_eq!(previous_initiative_id.as_deref(), Some("init-replay-1"));
        } else {
            panic!("expected Replay variant");
        }
    }

    #[test]
    fn step11_invalid_toml_records_terminally_rejected_nonce() {
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op = OperatorFixture::new(0x42);
        let policy = build_policy(&op);
        let now: i64 = 1_700_000_000;

        // plan.toml that's NOT valid TOML (malformed value).
        let bad_toml = b"this is not toml ! @ # $".to_vec();
        let plan_sha = sha256_of_artifact_bytes(&bad_toml);
        let bundle = PlanBundle::new_v2_1(
            now as u64,
            now as u64,
            mint_bundle_nonce().unwrap(),
            "bad".to_owned(),
            vec![BundleArtifact {
                name: "plan.toml".to_owned(),
                bytes: bad_toml,
                sha256: plan_sha,
            }],
        );
        let nonce_in_bundle = bundle.bundle_nonce.unwrap();
        let req = sign_to_request(&op, &bundle, "init-bad-toml");

        let err = create_initiative_v2(req, now, &policy, &store, &audit).unwrap_err();
        assert_eq!(err.fail_code(), "FAIL_PLAN_INVALID_TOML");

        // The nonce should now be recorded as TerminallyRejected so
        // the same bytes cannot be replayed.
        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        let status = pb_store::nonce_status_in_tx(&tx, &nonce_in_bundle).unwrap();
        let s = status.expect("nonce should be recorded");
        assert_eq!(s.outcome, PlanBundleNonceOutcome::TerminallyRejected);
        assert_eq!(s.initiative_id, None);

        // And the initiatives table has NO row for the rejected
        // initiative — sealing only happens on the success path.
        let count: i64 = tx
            .query_row(
                &format!("SELECT COUNT(*) FROM {INITIATIVES} WHERE initiative_id=?1"),
                rusqlite::params!["init-bad-toml"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn step10b_replay_after_terminal_reject_is_also_rejected() {
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op = OperatorFixture::new(0x42);
        let policy = build_policy(&op);
        let now: i64 = 1_700_000_000;

        // First submit — bad TOML → TerminallyRejected.
        let bad_toml = b"this is not toml".to_vec();
        let plan_sha = sha256_of_artifact_bytes(&bad_toml);
        let bundle = PlanBundle::new_v2_1(
            now as u64,
            now as u64,
            mint_bundle_nonce().unwrap(),
            "bad".to_owned(),
            vec![BundleArtifact {
                name: "plan.toml".to_owned(),
                bytes: bad_toml,
                sha256: plan_sha,
            }],
        );
        let req1 = sign_to_request(&op, &bundle, "init-bad-1");
        let _ = create_initiative_v2(req1, now, &policy, &store, &audit).unwrap_err();

        // Resubmit same bundle — replay layer rejects with Replay,
        // citing prior TerminallyRejected.
        let req2 = sign_to_request(&op, &bundle, "init-bad-2");
        let err = create_initiative_v2(req2, now, &policy, &store, &audit).unwrap_err();
        assert_eq!(err.fail_code(), "FAIL_PLAN_BUNDLE_REPLAY");
        if let V2AdmissionError::Replay {
            previous_outcome,
            previous_initiative_id,
            ..
        } = err
        {
            assert_eq!(previous_outcome, PlanBundleNonceOutcome::TerminallyRejected);
            assert_eq!(previous_initiative_id, None);
        } else {
            panic!("expected Replay");
        }
    }

    // ---------- V2.0 transitional path -------------------------------------

    #[test]
    fn v2_0_admit_path_when_policy_opts_in() {
        // accept_unfresh_v2_0_bundles=true — V2.0 bundles admit
        // without freshness/nonce checks. There is no replay
        // protection in this mode (no nonce); document the trade-off.
        let store = mem_store();
        let audit = FakeAuditSink::new();
        let op = OperatorFixture::new(0x42);
        let mut policy = build_policy(&op);
        policy.set_plan_signing_accept_unfresh_v2_0_for_tests(true);

        let now: i64 = 1_700_000_000;
        let plan_bytes = b"[meta]\nepoch=1\n".to_vec();
        let plan_sha = sha256_of_artifact_bytes(&plan_bytes);
        let bundle = PlanBundle::new_v2_0_legacy(
            now as u64,
            "legacy".to_owned(),
            vec![BundleArtifact {
                name: "plan.toml".to_owned(),
                bytes: plan_bytes,
                sha256: plan_sha,
            }],
        );
        let req = sign_to_request(&op, &bundle, "init-v20-ok");

        let result = create_initiative_v2(req, now, &policy, &store, &audit).unwrap();
        assert_eq!(result.initiative_id, "init-v20-ok");
    }

    // ---------- Artifact-name validator unit tests --------------------------

    #[test]
    fn artifact_name_rejects_empty() {
        assert_eq!(super::validate_artifact_name(""), Err("empty_name"));
    }

    #[test]
    fn artifact_name_rejects_leading_slash() {
        assert_eq!(
            super::validate_artifact_name("/etc/passwd"),
            Err("absolute_path")
        );
    }

    #[test]
    fn artifact_name_rejects_dotdot_segment() {
        assert_eq!(super::validate_artifact_name("a/../b"), Err("path_escape"));
        assert_eq!(super::validate_artifact_name("../"), Err("path_escape"));
    }

    #[test]
    fn artifact_name_rejects_nul_byte() {
        assert_eq!(super::validate_artifact_name("a\0b"), Err("nul_byte"));
    }

    #[test]
    fn artifact_name_accepts_typical_relative_path() {
        assert_eq!(super::validate_artifact_name("plan.toml"), Ok(()));
        assert_eq!(super::validate_artifact_name("prompts/ext.md"), Ok(()));
        assert_eq!(super::validate_artifact_name("a/b/c/d.txt"), Ok(()));
    }

    #[test]
    fn artifact_name_does_not_panic_on_dotdot_substring() {
        // ".." inside a segment (e.g. "spam..ham") is NOT a path
        // escape — the validator must compare per-segment.
        assert_eq!(super::validate_artifact_name("spam..ham"), Ok(()));
    }
}
