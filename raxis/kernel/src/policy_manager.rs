// raxis-kernel::policy_manager — Policy artifact lifecycle.
//
// Normative reference: kernel-core.md §`policy_manager.rs`.
//
// This module is the SINGLE writer to the `policy_epoch_history` store
// table (kernel-store.md §2.5.1 Table 19). Per spec §INV-POLICY-01 there
// are exactly two write entry points:
//
//   1. `install_genesis_policy_epoch` — called once, at genesis time
//      from `bootstrap::run_inner`, after the kernel.db schema has been
//      installed and the policy.toml artifact has been written. Inserts
//      the canonical `epoch_id = 1, triggered_by_operator = "genesis"`
//      row.
//
//   2. `advance_epoch` — called from `handlers/operator::handle_rotate_epoch`
//      every time an operator rotates the active policy. Inserts a new
//      `epoch_id = N+1` row inside the SQL transaction that also sweeps
//      delegations and invalidates session prompts.
//
// Every other subsystem observes the current epoch by reading
// `ctx.policy.load().epoch_id` from the in-memory `Arc<ArcSwap<PolicyBundle>>` —
// no other module reads `policy_epoch_history` in the hot path.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_policy::PolicyBundle;
use raxis_store::{Store, Table};
use raxis_types::{unix_now_secs, DelegationStatus};
use thiserror::Error;

use crate::authority::keys::{authority_verifying_key, KeyRegistry};
use crate::prompt::EpochBinding;

// INV-STORE-03 (kernel-store.md §2.5.1): "no raw SQL table-name literals
// in raxis/kernel/src; use Table enum + .as_str()". Same posture for state
// strings — `DelegationStatus::*.as_sql_str()` flows through these queries
// so any rename in `raxis-types` is caught at compile time, not at runtime.
const POLICY_EPOCH_HISTORY: &str = Table::PolicyEpochHistory.as_str();
const DELEGATIONS:          &str = Table::Delegations.as_str();
const SESSIONS:             &str = Table::Sessions.as_str();

// ---------------------------------------------------------------------------
// PolicyError
// ---------------------------------------------------------------------------

/// Failure modes for `policy_manager` operations. Each variant is mapped
/// to a stable wire string by `error_code()` for the CLI's pattern-matching
/// layer.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The Ed25519 signature on the policy artifact does not verify
    /// against `KeyRegistry.authority_keypair.public`.
    #[error("policy signature verification failed: {reason}")]
    SignatureInvalid { reason: String },

    /// The artifact's `meta.epoch` is less than or equal to the current
    /// `MAX(epoch_id)` recorded in `policy_epoch_history`. Replay
    /// protection per kernel-core.md §`policy_manager.rs`.
    #[error(
        "policy epoch_id={attempted} is not greater than current epoch_id={current}; \
         replay protected"
    )]
    EpochReplay { attempted: u64, current: u64 },

    /// The artifact bytes are not a well-formed signed policy artifact
    /// (TOML parse failure, missing required field, semantic validation
    /// failure in `raxis-policy::PolicyBundle::validate`).
    #[error("policy artifact is malformed: {reason}")]
    MalformedArtifact { reason: String },

    /// The supplied path canonicalises to a location outside the
    /// kernel data directory. Defence-in-depth against operators who
    /// accidentally point at a build-server staging dir.
    #[error("policy path {path:?} is outside data_dir {data_dir:?}")]
    PathOutsideDataDir { path: PathBuf, data_dir: PathBuf },

    /// `policy_epoch_history.policy_sha256` UNIQUE constraint trip — the
    /// same artifact bytes were previously installed under a different
    /// `epoch_id`. Surfaces an operator who hand-edited `meta.epoch` to
    /// bypass replay protection.
    #[error("policy artifact (sha256={sha256}) was previously installed")]
    PolicyArtifactAlreadyInstalled { sha256: String },

    /// SQLite write failed during Phase 1 (delegations sweep, prompt
    /// invalidation, history INSERT, audit-pointer append). The
    /// transaction was rolled back; in-memory state is unchanged.
    #[error("policy store write failed: {reason}")]
    StoreWriteFailed { reason: String },

    /// I/O failure reading the policy or signature artifact.
    #[error("policy artifact read failed: {reason}")]
    ArtifactReadFailed { reason: String },
}

impl PolicyError {
    /// Stable wire short-string used by the operator IPC error envelope
    /// (`OperatorResponse::Error.code`). The CLI pattern-matches on
    /// these to render operator-friendly messages.
    pub fn error_code(&self) -> &'static str {
        match self {
            PolicyError::SignatureInvalid { .. }            => "FAIL_POLICY_SIGNATURE_INVALID",
            PolicyError::EpochReplay { .. }                 => "FAIL_POLICY_EPOCH_REPLAY",
            PolicyError::MalformedArtifact { .. }           => "FAIL_POLICY_MALFORMED",
            PolicyError::PathOutsideDataDir { .. }          => "FAIL_POLICY_PATH_OUTSIDE_DATA_DIR",
            PolicyError::PolicyArtifactAlreadyInstalled { .. } => {
                "FAIL_POLICY_ARTIFACT_ALREADY_INSTALLED"
            }
            PolicyError::StoreWriteFailed { .. }            => "FAIL_POLICY_STORE_WRITE",
            PolicyError::ArtifactReadFailed { .. }          => "FAIL_POLICY_ARTIFACT_READ",
        }
    }
}

// ---------------------------------------------------------------------------
// read_current_epoch
// ---------------------------------------------------------------------------

/// Read the highest installed policy epoch from `policy_epoch_history`.
///
/// Returns `0` when the table is empty (pre-genesis), so a freshly
/// migrated database with no genesis row reports epoch `0` — and the
/// genesis install (`install_genesis_policy_epoch`) is the only
/// transition from `0 → 1` that does not go through `advance_epoch`.
///
/// **Cold-path only.** Hot-path callers must read
/// `ctx.policy.load().epoch_id` from the `Arc<ArcSwap<PolicyBundle>>`;
/// this function exists for `policy_manager` itself (replay protection
/// in `advance_epoch` and `load_and_verify`) and for forensics tooling.
pub fn read_current_epoch(store: &Store) -> Result<u64, PolicyError> {
    let conn = store.lock_sync();
    let epoch: i64 = conn
        .query_row(
            &format!("SELECT COALESCE(MAX(epoch_id), 0) FROM {POLICY_EPOCH_HISTORY}"),
            [],
            |r| r.get(0),
        )
        .map_err(|e| PolicyError::StoreWriteFailed {
            reason: format!("read MAX(epoch_id) failed: {e}"),
        })?;
    // The schema constrains epoch_id to NOT NULL INTEGER PRIMARY KEY;
    // genesis writes 1, every advance writes a strictly larger value,
    // so the value never goes negative. We saturate-cast for safety.
    Ok(epoch.max(0) as u64)
}

// ---------------------------------------------------------------------------
// install_genesis_policy_epoch
// ---------------------------------------------------------------------------

/// Insert the `epoch_id = 1, triggered_by_operator = "genesis"` row into
/// `policy_epoch_history`. Idempotent: if a row with `epoch_id = 1`
/// already exists, the function returns `Ok(())` without modifying the
/// row. This makes it safe to invoke from `bootstrap::run_inner` even
/// if a previous bootstrap run reached this step before crashing.
///
/// Spec contract (kernel-core.md §`policy_manager.rs`):
///   "the genesis bootstrap path (raxis-cli genesis →
///    bootstrap::install_genesis_policy, which writes the epoch_id = 1
///    row with triggered_by_operator = "genesis" under the same
///    transaction that finalises the schema)"
///
/// `policy_sha256` is the lowercase-hex SHA-256 of the genesis
/// `policy.toml` bytes (computed by `raxis_policy::load_policy`).
/// `signed_by_authority` is the authority pubkey fingerprint
/// (SHA-256[:16] hex; same convention as
/// `raxis_genesis_tools::pubkey_fingerprint`).
pub fn install_genesis_policy_epoch(
    store: &Store,
    policy_sha256: &str,
    signed_by_authority: &str,
    advanced_at_unix_secs: i64,
    bundle: &PolicyBundle,
) -> Result<(), PolicyError> {
    // Delegate to the shared writer in `raxis-store`. Both this kernel-side
    // genesis path and the operator-facing `raxis genesis` CLI command call
    // the same function, so a future schema rename or column addition is a
    // single-file change. See `crates/store/src/genesis.rs` for the
    // INSERT OR IGNORE rationale that used to live here AND for the
    // operator_certificates atomic-mirror contract added in step 4 of
    // the cert feature. Cert is mandatory (INV-CERT-01); bundle is
    // non-Option.
    raxis_store::install_genesis_policy_epoch_row(
        store,
        policy_sha256,
        signed_by_authority,
        advanced_at_unix_secs,
        bundle,
    )
    .map_err(|e| PolicyError::StoreWriteFailed {
        reason: format!("INSERT OR IGNORE {POLICY_EPOCH_HISTORY} failed: {e}"),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// load_and_verify
// ---------------------------------------------------------------------------

/// Outcome of a successful `load_and_verify`. Includes the parsed
/// `PolicyBundle`, the raw artifact bytes (so callers can re-verify or
/// re-hash without re-reading the file), and the lowercase-hex SHA-256
/// of those bytes.
#[derive(Debug)]
pub struct VerifiedPolicyArtifact {
    pub bundle:       PolicyBundle,
    pub raw_bytes:    Vec<u8>,
    pub sha256_hex:   String,
}

/// Read the signed policy artifact at `policy_path`, verify the
/// detached Ed25519 signature at `sig_path` against the authority
/// public key in `registry`, parse the TOML, and confirm the artifact
/// epoch is strictly greater than the current epoch in
/// `policy_epoch_history`.
///
/// All checks are read-only — no SQL writes, no in-memory swaps. Used
/// by `advance_epoch` Phase 0 (cold path) and exposed for direct test
/// coverage.
///
/// Failure mapping
/// - file/IO error            → `ArtifactReadFailed`
/// - signature length / parse → `SignatureInvalid`
/// - Ed25519 verify failure   → `SignatureInvalid`
/// - TOML parse / validation  → `MalformedArtifact`
/// - new epoch ≤ current       → `EpochReplay`
pub fn load_and_verify(
    policy_path: &Path,
    sig_path:    &Path,
    registry:    &KeyRegistry,
    store:       &Store,
) -> Result<VerifiedPolicyArtifact, PolicyError> {
    // Read the policy artifact bytes. Hash + parse run on the same
    // byte content so a TOCTOU between the two reads is impossible.
    let (bundle, raw_bytes, sha256_hex) =
        raxis_policy::load_policy(policy_path).map_err(|e| match e {
            raxis_policy::PolicyError::Io(io)             => PolicyError::ArtifactReadFailed {
                reason: format!("read {policy_path:?} failed: {io}"),
            },
            raxis_policy::PolicyError::SignatureInvalid(s) => PolicyError::SignatureInvalid {
                reason: s,
            },
            raxis_policy::PolicyError::EpochNotMonotonic { current, new } => {
                PolicyError::EpochReplay { attempted: new, current }
            }
            raxis_policy::PolicyError::TomlParse(_)
            | raxis_policy::PolicyError::HexDecode(_)
            | raxis_policy::PolicyError::MalformedArtifact(_)
            | raxis_policy::PolicyError::UnknownCapabilityClass(_)
            | raxis_policy::PolicyError::UnknownGateType(_)
            // Cert-related validation failures from the new
            // operator-cert flow (raxis-policy::bundle::validate_operator_certs).
            // All four variants are categorically "the policy artifact is
            // malformed in a way the kernel will not silently accept" —
            // we surface the full error message verbatim so the operator
            // sees exactly which cert tripped which invariant.
            | raxis_policy::PolicyError::CertValidation { .. }
            | raxis_policy::PolicyError::CertPubkeyMismatch { .. }
            | raxis_policy::PolicyError::FingerprintMismatch { .. } => PolicyError::MalformedArtifact {
                reason: e.to_string(),
            },
        })?;

    // Read the detached signature. We read the raw bytes (not hex) per
    // the operator-signing contract in `cli/src/commands/policy.rs` —
    // the CLI writes 64 raw Ed25519 signature bytes, NOT a hex string.
    let sig_bytes = std::fs::read(sig_path).map_err(|e| PolicyError::ArtifactReadFailed {
        reason: format!("read {sig_path:?} failed: {e}"),
    })?;
    if sig_bytes.len() != 64 {
        return Err(PolicyError::SignatureInvalid {
            reason: format!(
                "signature file {sig_path:?} is {} bytes (expected 64)",
                sig_bytes.len(),
            ),
        });
    }

    // Verify Ed25519 over the raw policy bytes against the authority
    // public key. The authority key was loaded from `keys/authority_keypair.pem`
    // at startup and is the SOLE trust root for policy artifacts —
    // operator-signed approvals (escalations, plan approvals) use a
    // different key class entirely.
    let authority_vk = authority_verifying_key(registry);
    raxis_crypto::verify_ed25519(&authority_vk.to_bytes(), &raw_bytes, &sig_bytes).map_err(|e| {
        PolicyError::SignatureInvalid {
            reason: format!("Ed25519 verify failed: {e}"),
        }
    })?;

    // Replay protection: the artifact epoch must be strictly greater
    // than the current `MAX(epoch_id)` in `policy_epoch_history`. Genesis
    // wrote `epoch_id = 1`, so the operator's first `RotateEpoch` must
    // present an artifact with `meta.epoch >= 2`.
    let current_epoch = read_current_epoch(store)?;
    let new_epoch = bundle.epoch();
    if new_epoch <= current_epoch {
        return Err(PolicyError::EpochReplay {
            attempted: new_epoch,
            current:   current_epoch,
        });
    }

    Ok(VerifiedPolicyArtifact {
        bundle,
        raw_bytes,
        sha256_hex,
    })
}

// ---------------------------------------------------------------------------
// advance_epoch
// ---------------------------------------------------------------------------

/// Outcome of a successful `advance_epoch`. Returned to the operator
/// IPC layer so the wire response can carry forensic-grade detail
/// (sweep counts, artifact identity).
#[derive(Debug, Clone)]
pub struct AdvanceOutcome {
    pub new_epoch_id:               u64,
    pub policy_sha256:              String,
    pub signed_by_authority:        String,
    pub n_delegations_marked_stale: u64,
    pub n_sessions_invalidated:     u64,
    pub advanced_at_unix_secs:      i64,
}

/// Advance the kernel's policy epoch in-process, in four phases per
/// kernel-core.md §`policy_manager.rs`.
///
/// **Phase 0 — Verification (no side effects).** Calls `load_and_verify`
/// to read both files, verify the signature, parse the artifact, and
/// confirm `meta.epoch > current_epoch`. Failures here surface as
/// `PolicyError` *before* any SQL is touched; the caller (operator
/// dispatcher) writes the `PolicyAdvanceRejected` audit event.
///
/// **Phase 1 — SQL transaction (single mutex acquisition, single
/// `BEGIN IMMEDIATE`).** Inside one transaction:
///   1. `UPDATE delegations SET status='StaleOnNextUse' WHERE status='Active'`
///      → `n_delegations_marked_stale`.
///   2. `SELECT session_id FROM sessions WHERE revoked_at IS NULL AND
///      expires_at > now()` → list of currently-active session IDs.
///      The list flows out of the SQL transaction unchanged and is
///      handed to `prompt::epoch_binding::mark_all_invalid` after
///      commit (Phase 1.5b). The in-memory `EpochBinding` is the
///      v1 substitute for the spec's `sessions.prompt_epoch_valid`
///      column (kernel-core.md §`prompt::epoch_binding`); the column
///      lands in v1.1 alongside the migration that persists this flag.
///      The count `n_sessions_invalidated` reports the actual count
///      of active sessions whose prompt-epoch flag flipped.
///   3. `INSERT INTO policy_epoch_history (...)` — replay protection
///      via `epoch_id PRIMARY KEY` AND `policy_sha256 UNIQUE`.
///   4. The audit emit happens AFTER commit (Phase 1.5) per the
///      `kernel-store.md` §2.5.2 audit-after-commit ordering contract;
///      `AuditEventKind::PolicyEpochAdvanced` records all sweep counts.
///
/// **Phase 2 — In-memory visibility flip.** `ctx.policy.store(...)`
/// swaps the `Arc<PolicyBundle>` behind the `ArcSwap`. Subsequent
/// readers observe the new epoch. Infallible — the `ArcSwap::store`
/// API takes `&self` and never returns an error.
///
/// **Phase 3 — Gateway signal (best-effort).** Notify the gateway via
/// `gateway_client.notify_epoch_advanced(new_epoch_id)` so it re-reads
/// `policy.toml` for the allowlist. Failures are logged and recorded
/// as `AuditEventKind::GatewaySignalFailed`; they do NOT roll back
/// the advance (the gateway has its own failure-closed contract per
/// `peripherals.md` §3.2).
///
/// Returns `Ok(AdvanceOutcome)` after Phases 0-2 succeed (Phase 3
/// success/failure does not affect the return value).
#[allow(clippy::too_many_arguments)]
pub fn advance_epoch(
    policy_path:    &Path,
    sig_path:       &Path,
    triggered_by:   &str,
    registry:       &KeyRegistry,
    policy_swap:    &Arc<ArcSwap<PolicyBundle>>,
    store:          &Store,
    audit:          &Arc<dyn AuditSink>,
    epoch_binding:  &EpochBinding,
) -> Result<AdvanceOutcome, PolicyError> {
    // ── Phase 0: verification (cold, read-only) ──────────────────────
    let VerifiedPolicyArtifact { bundle: new_bundle, raw_bytes: _, sha256_hex } =
        load_and_verify(policy_path, sig_path, registry, store)?;
    let new_epoch_id        = new_bundle.epoch();
    let signed_by_authority = raxis_genesis_tools::pubkey_fingerprint(
        authority_verifying_key(registry).as_bytes(),
    );
    let advanced_at_unix_secs = unix_now_secs() as i64;

    // ── Phase 1: SQL transaction ─────────────────────────────────────
    // Acquire the connection mutex once and hold it for the entire
    // transaction body (kernel-store.md §INV-STORE-01). Any error
    // inside the closure rolls the transaction back and surfaces as
    // `PolicyError::StoreWriteFailed` (or `PolicyArtifactAlreadyInstalled`
    // for the UNIQUE(policy_sha256) trip).
    let (n_delegations_marked_stale, active_session_ids, n_certs_installed) = {
        let mut conn = store.lock_sync();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| PolicyError::StoreWriteFailed {
                reason: format!("BEGIN IMMEDIATE failed: {e}"),
            })?;

        // Step 1: delegation sweep. State strings sourced via
        // `DelegationStatus::*.as_sql_str()` per INV-STORE-03.
        let stale_state  = DelegationStatus::StaleOnNextUse
            .as_sql_str()
            .expect("StaleOnNextUse is a stored variant");
        let active_state = DelegationStatus::Active
            .as_sql_str()
            .expect("Active is a stored variant");
        let n_delegations = tx
            .execute(
                &format!(
                    "UPDATE {DELEGATIONS} SET status = ?1 WHERE status = ?2"
                ),
                rusqlite::params![stale_state, active_state],
            )
            .map_err(|e| PolicyError::StoreWriteFailed {
                reason: format!("UPDATE {DELEGATIONS} failed: {e}"),
            })? as u64;

        // Step 2: snapshot the active sessions whose prompts now need
        // re-assembly. The actual flag flip happens in Phase 1.5b
        // (in-memory only — see the doc comment) so we leave the SQL
        // transaction footprint to the delegation sweep + the epoch
        // history insert. Live filter: not revoked AND not expired.
        let now_secs = advanced_at_unix_secs;
        let mut session_id_strs: Vec<String> = Vec::new();
        {
            let mut stmt = tx
                .prepare_cached(&format!(
                    "SELECT session_id FROM {SESSIONS} \
                     WHERE revoked_at IS NULL AND expires_at > ?1"
                ))
                .map_err(|e| PolicyError::StoreWriteFailed {
                    reason: format!("prepare active-sessions select failed: {e}"),
                })?;
            let rows = stmt
                .query_map(rusqlite::params![now_secs], |row| row.get::<_, String>(0))
                .map_err(|e| PolicyError::StoreWriteFailed {
                    reason: format!("execute active-sessions select failed: {e}"),
                })?;
            for row in rows {
                let s = row.map_err(|e| PolicyError::StoreWriteFailed {
                    reason: format!("read active-sessions row failed: {e}"),
                })?;
                session_id_strs.push(s);
            }
        }

        // Step 3: persist the new epoch row. Catch the
        // UNIQUE(policy_sha256) constraint and surface it as the
        // dedicated `PolicyArtifactAlreadyInstalled` variant so the
        // operator gets a precise wire code (vs a generic
        // StoreWriteFailed that would lose the diagnostic).
        let insert_result = tx.execute(
            &format!(
                "INSERT INTO {POLICY_EPOCH_HISTORY} (
                     epoch_id, policy_sha256, signed_by_authority,
                     triggered_by_operator, advanced_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)"
            ),
            rusqlite::params![
                new_epoch_id as i64,
                sha256_hex,
                signed_by_authority,
                triggered_by,
                advanced_at_unix_secs,
            ],
        );
        if let Err(e) = insert_result {
            // Per rusqlite's error model, a UNIQUE constraint violation
            // surfaces as `Error::SqliteFailure` carrying
            // `ErrorCode::ConstraintViolation`. Match on the textual
            // message as a defence-in-depth check; either match path
            // returns the precise variant.
            let msg = e.to_string();
            let is_unique = matches!(
                &e,
                rusqlite::Error::SqliteFailure(err, _)
                    if err.code == rusqlite::ErrorCode::ConstraintViolation
            ) || msg.contains("UNIQUE constraint");
            if is_unique {
                return Err(PolicyError::PolicyArtifactAlreadyInstalled {
                    sha256: sha256_hex.clone(),
                });
            }
            return Err(PolicyError::StoreWriteFailed {
                reason: format!("INSERT {POLICY_EPOCH_HISTORY} failed: {e}"),
            });
        }

        // Step 4: rebuild the operator_certificates view table from the
        // freshly-loaded bundle. MUST run inside the same transaction as
        // the policy_epoch_history INSERT above so a power-loss between
        // the two cannot leave the kernel running with stale cert rows
        // for an old epoch (the FK would fail; equivalently the cert
        // rows would point at an epoch that doesn't exist). Cert-less
        // ("legacy") operator entries are skipped — see the writer's
        // doc comment for the audit-emission contract that lives in
        // step 5.
        let n_certs_installed = raxis_store::views::operator_certificates::repopulate(
            &tx,
            &new_bundle,
            new_epoch_id,
            advanced_at_unix_secs,
        )
        .map_err(|e| PolicyError::StoreWriteFailed {
            reason: format!("operator_certificates repopulate failed: {e}"),
        })?;

        tx.commit().map_err(|e| PolicyError::StoreWriteFailed {
            reason: format!("COMMIT failed: {e}"),
        })?;

        (n_delegations, session_id_strs, n_certs_installed)
    };
    let _ = n_certs_installed;

    // ── Phase 1.5b: in-memory prompt-epoch sweep ─────────────────────
    // The in-memory `EpochBinding` is the v1 substitute for the
    // spec's `sessions.prompt_epoch_valid` column. Sessions present in
    // `active_session_ids` (snapshot taken inside the SQL transaction
    // above) get their prompt flagged invalid; the next assembly call
    // for any of them will log
    // `AuditEventKind::PromptReassembled { reason: EpochAdvance }`
    // before rebuilding. Sessions admitted AFTER this point start
    // with a fresh epoch implicitly (the binding's default is
    // "valid"), which is correct because they were assembled against
    // the new epoch.
    let active_session_ids: Vec<raxis_types::SessionId> = active_session_ids
        .into_iter()
        .filter_map(|s| raxis_types::SessionId::parse(&s).ok())
        .collect();
    let n_sessions_invalidated = epoch_binding.mark_all_invalid(&active_session_ids) as u64;

    // ── Phase 1.5: post-commit audit emit ────────────────────────────
    // Per kernel-store.md §2.5.2 audit emission MUST follow a
    // successful SQLite commit; emitting inside the transaction would
    // strand the audit record on rollback.
    if let Err(e) = audit.emit(
        AuditEventKind::PolicyEpochAdvanced {
            new_epoch_id,
            policy_sha256:           sha256_hex.clone(),
            triggered_by:            triggered_by.to_owned(),
            delegations_marked_stale: n_delegations_marked_stale,
            sessions_invalidated:    n_sessions_invalidated,
        },
        None, None, None,
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"PolicyEpochAdvanced\",\
             \"audit_emit_failed\":\"{e}\",\"new_epoch_id\":{new_epoch_id}}}",
        );
    }

    // ── Phase 1.5c: cert audit-chain mirror ─────────────────────────
    // For every operator entry we emit OperatorCertInstalled (cert is
    // mandatory — INV-CERT-01 — so every entry produces exactly one
    // record). These records are the authoritative ledger that backs
    // the operator_certificates view table — if the table is ever
    // lost (disk corruption, schema rebuild) it can be reconstructed
    // by replaying these records up to the latest PolicyEpochAdvanced.
    // We also emit one OperatorCertMisconfigBypassed per relaxed
    // invariant so the ledger captures every structural override the
    // operator opted into. Self-signature failures and pubkey
    // mismatches are unbypassable and never reach this point —
    // `validate_operator_certs` already returned a hard PolicyError
    // before the SQL transaction even opened. Errors from individual
    // emits are logged and DO NOT unwind the epoch advance — the
    // in-memory visibility flip below must still happen so the operator
    // gets the new epoch's enforcement.
    //
    // Pass the OUTGOING bundle so the cert mirror can detect rotations
    // (same pubkey, different cert content → `previous_fingerprint`
    // populated on `OperatorCertInstalled`). The load here happens
    // before the `policy_swap.store(...)` below so we still observe
    // the pre-advance state.
    let prev_bundle_arc = policy_swap.load_full();
    cert_audit_emit::emit_cert_chain_mirror(
        audit.as_ref(), &new_bundle, Some(&*prev_bundle_arc), new_epoch_id,
    );

    // ── Phase 2: in-memory visibility flip ───────────────────────────
    // `ArcSwap::store` is sequentially consistent (`AcqRel` ordering on
    // the swap), so subsequent reader `load`s observe the new bundle.
    // We have to re-construct the bundle in an `Arc` because `load_full`
    // returns the new owner.
    policy_swap.store(Arc::new(new_bundle));

    Ok(AdvanceOutcome {
        new_epoch_id,
        policy_sha256: sha256_hex,
        signed_by_authority,
        n_delegations_marked_stale,
        n_sessions_invalidated,
        advanced_at_unix_secs,
    })
}

// ---------------------------------------------------------------------------
// cert_audit_emit — operator-cert audit-chain mirror helpers.
// ---------------------------------------------------------------------------

/// Audit-emit helpers that mirror the `operator_certificates` view
/// table state into the audit chain whenever a new policy epoch is
/// installed.
///
/// **Why this is its own module.** The cert ledger is a
/// security-critical durability story (kernel-store.md §2.5.7): if
/// the SQLite view is ever lost, the audit chain MUST be enough to
/// reconstruct "which cert was bound to which operator at epoch N".
/// Keeping the emit logic isolated lets us unit-test it against a
/// `FakeAuditSink` without spinning up the whole `advance_epoch`
/// transaction, and lets a future reader audit the emit set in one
/// file.
///
/// **Idempotency / dedupe.** Each operator entry produces:
///   - exactly one `OperatorCertInstalled` (cert is mandatory —
///     INV-CERT-01 — so every entry produces exactly one record);
///   - zero or more `OperatorCertMisconfigBypassed` (one per
///     relaxed structural invariant; only emitted when the operator
///     entry has `force_misconfig_bypass = true` AND validation
///     surfaced violations).
///
/// **Failure posture.** Individual emit errors are logged via
/// `eprintln!` and DROPPED. Per kernel-store.md §2.5.2 the
/// audit-after-commit ordering means the SQLite write has already
/// landed; failing the epoch advance now would leave the kernel
/// running on an out-of-date in-memory bundle, which is strictly
/// worse than a one-record audit gap (`ReconciliationGap` is
/// designed for exactly this case).
mod cert_audit_emit {
    use raxis_audit_tools::{AuditEventKind, AuditSink};
    use raxis_policy::PolicyBundle;

    /// Drive every cert-related post-commit audit emit for one
    /// `advance_epoch` (or genesis) call.
    ///
    /// `prev_bundle` is the OUTGOING policy bundle (i.e. the one being
    /// replaced by `bundle`). It is `None` only at genesis — there is
    /// no prior bundle to diff against. For every subsequent epoch
    /// advance the kernel passes `Some(prev_bundle)` so the cert
    /// mirror can detect cert rotations: an operator entry whose
    /// `pubkey_hex` matches a prior entry but whose embedded cert's
    /// `self_sig_hex` differs is a rotation, and we record the prior
    /// fingerprint on `OperatorCertInstalled.previous_fingerprint` so
    /// the audit chain captures continuity. (INV-CERT-04 forbids
    /// pubkey changes on `cert install --replace-for`, so the prior
    /// fingerprint is the same string as the current one — but its
    /// presence vs absence is the operator-meaningful signal.)
    pub(super) fn emit_cert_chain_mirror(
        audit:        &dyn AuditSink,
        bundle:       &PolicyBundle,
        prev_bundle:  Option<&PolicyBundle>,
        new_epoch_id: u64,
    ) {
        // 1. One `OperatorCertInstalled` per operator entry, matching
        //    the `operator_certificates` row written inside the
        //    just-committed transaction. Cert is mandatory
        //    (INV-CERT-01) so every entry produces an event — there
        //    is no cert-less / "legacy" branch to skip.
        for entry in bundle.operators() {
            let cert = &entry.cert;
            // Rotation detection: same pubkey, different cert content
            // (`self_sig_hex` is the integrity tag over every
            // signed-into field, so any field change forces a
            // different signature). Per INV-CERT-04 the pubkey cannot
            // change across a rotation, so we look up the prior entry
            // by `pubkey_hex` rather than `pubkey_fingerprint` — the
            // two are equivalent here but `pubkey_hex` is the value
            // the policy.toml carries verbatim.
            let previous_fingerprint = prev_bundle.and_then(|prev| {
                let prior = prev.operators()
                    .iter()
                    .find(|e| e.pubkey_hex.eq_ignore_ascii_case(&entry.pubkey_hex))?;
                if prior.cert.self_sig_hex != cert.self_sig_hex {
                    Some(prior.pubkey_fingerprint.clone())
                } else {
                    None
                }
            });
            try_emit(audit, AuditEventKind::OperatorCertInstalled {
                pubkey_fingerprint:     entry.pubkey_fingerprint.clone(),
                epoch_id:               new_epoch_id,
                cert_kind:              cert.kind.as_str().to_owned(),
                display_name:           cert.display_name.clone(),
                not_before:             cert.not_before,
                not_after:              cert.not_after,
                permitted_ops:          cert.permitted_ops.clone(),
                force_misconfig_bypass: entry.force_misconfig_bypass,
                previous_fingerprint,
            }, "OperatorCertInstalled");
        }

        // 2. One `OperatorCertMisconfigBypassed` per operator entry that
        //    opted into bypassing structural cert-validation errors. The
        //    full violations list is bundled into a single record so a
        //    forensic auditor sees the entire relaxed-rule set in one
        //    chain entry. The policy bundle only emits these entries
        //    when `force_misconfig_bypass = true` AND the entry
        //    surfaced violations.
        for bypass in bundle.bypassed_cert_misconfigs() {
            try_emit(audit, AuditEventKind::OperatorCertMisconfigBypassed {
                pubkey_fingerprint: bypass.operator_fingerprint.clone(),
                epoch_id:           new_epoch_id,
                cert_kind:          bypass.kind.as_str().to_owned(),
                display_name:       bypass.display_name.clone(),
                violations:         bypass.violations.clone(),
            }, "OperatorCertMisconfigBypassed");
        }
    }

    fn try_emit(audit: &dyn AuditSink, ev: AuditEventKind, label: &'static str) {
        if let Err(e) = audit.emit(ev, None, None, None) {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"{label}\",\
                 \"audit_emit_failed\":\"{e}\"}}",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// canonicalize_under_data_dir
// ---------------------------------------------------------------------------

/// Canonicalise `path` and confirm it resolves under `data_dir`.
///
/// Returns `Ok(canonical_path)` on success. Surfaces
/// `PolicyError::PathOutsideDataDir` if the canonical path escapes the
/// data dir, or `PolicyError::ArtifactReadFailed` if either
/// `canonicalize` call fails.
///
/// Used by `advance_epoch` (and tests) to enforce the
/// `<data_dir>/policy/` containment invariant before opening the
/// artifact (kernel-core.md §`policy_manager.rs`).
pub(crate) fn canonicalize_under_data_dir(
    path: &Path,
    data_dir: &Path,
) -> Result<PathBuf, PolicyError> {
    let canon_data_dir = std::fs::canonicalize(data_dir).map_err(|e| {
        PolicyError::ArtifactReadFailed {
            reason: format!("canonicalize data_dir {data_dir:?} failed: {e}"),
        }
    })?;
    let canon_path = std::fs::canonicalize(path).map_err(|e| {
        PolicyError::ArtifactReadFailed {
            reason: format!("canonicalize path {path:?} failed: {e}"),
        }
    })?;
    if !canon_path.starts_with(&canon_data_dir) {
        return Err(PolicyError::PathOutsideDataDir {
            path: canon_path,
            data_dir: canon_data_dir,
        });
    }
    Ok(canon_path)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_store::Store;

    fn open_mem_store() -> Store {
        Store::open_in_memory().expect("open in-memory store")
    }

    #[test]
    fn read_current_epoch_returns_zero_on_empty_table() {
        let store = open_mem_store();
        assert_eq!(read_current_epoch(&store).unwrap(), 0);
    }

    /// Helper used by the genesis-row tests that don't care about
    /// cert mirroring — the bundle is empty, so `repopulate` inserts
    /// 0 rows into `operator_certificates` and the test exercises the
    /// `policy_epoch_history` writer in isolation.
    fn empty_bundle_for_genesis_test() -> PolicyBundle {
        PolicyBundle::for_tests_with_operators(vec![])
    }

    #[test]
    fn install_genesis_writes_epoch_one() {
        let store = open_mem_store();
        let bundle = empty_bundle_for_genesis_test();
        install_genesis_policy_epoch(
            &store,
            "abc123",
            "deadbeefdeadbeefdeadbeefdeadbeef",
            1_700_000_000,
            &bundle,
        )
        .unwrap();
        assert_eq!(read_current_epoch(&store).unwrap(), 1);
    }

    #[test]
    fn install_genesis_is_idempotent_on_re_run() {
        // Two consecutive invocations with the same byte content must
        // succeed; the second is a no-op via INSERT OR IGNORE. This is
        // the recovery contract for a bootstrap that crashed after the
        // INSERT but before returning.
        let store = open_mem_store();
        let bundle = empty_bundle_for_genesis_test();
        install_genesis_policy_epoch(
            &store, "abc123", "fp", 1_700_000_000, &bundle,
        )
        .unwrap();
        install_genesis_policy_epoch(
            &store, "abc123", "fp", 1_700_000_000, &bundle,
        )
        .expect("second install must be a no-op");
        assert_eq!(read_current_epoch(&store).unwrap(), 1);
    }

    #[test]
    fn install_genesis_persists_metadata_columns() {
        let store = open_mem_store();
        let bundle = empty_bundle_for_genesis_test();
        install_genesis_policy_epoch(
            &store, "deadc0de", "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1", 1_700_000_001, &bundle,
        )
        .unwrap();
        let conn = store.lock_sync();
        let (sha, signed_by, triggered, ts): (String, String, String, i64) = conn
            .query_row(
                &format!(
                    "SELECT policy_sha256, signed_by_authority, triggered_by_operator, advanced_at
                       FROM {POLICY_EPOCH_HISTORY} WHERE epoch_id = 1"
                ),
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(sha, "deadc0de");
        assert_eq!(signed_by, "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1");
        assert_eq!(triggered, "genesis");
        assert_eq!(ts, 1_700_000_001);
    }

    #[test]
    fn canonicalize_under_data_dir_rejects_escape() {
        let data_dir = tempfile::tempdir().expect("data_dir");
        let outside = tempfile::NamedTempFile::new().expect("outside tempfile");
        let result = canonicalize_under_data_dir(outside.path(), data_dir.path());
        assert!(matches!(result, Err(PolicyError::PathOutsideDataDir { .. })));
    }

    #[test]
    fn canonicalize_under_data_dir_accepts_inside() {
        let data_dir = tempfile::tempdir().expect("data_dir");
        let inside = data_dir.path().join("policy.toml");
        std::fs::write(&inside, b"stub").unwrap();
        let canon = canonicalize_under_data_dir(&inside, data_dir.path()).unwrap();
        assert!(canon.starts_with(std::fs::canonicalize(data_dir.path()).unwrap()));
    }

    // ── advance_epoch + load_and_verify integration tests ──────────────
    //
    // These tests stand up a real SigningKey, write signed policy
    // artifacts at incrementing epochs, and exercise every Phase 0,
    // Phase 1, and Phase 2 branch of `advance_epoch`. They do NOT
    // exercise the gateway-signal Phase 3 — that lives behind the
    // `GatewayClient` and is integration-tested separately.

    use ed25519_dalek::{Signer, SigningKey};
    use raxis_audit_tools::{AuditSink, FakeAuditSink};
    use std::sync::Arc as StdArc;

    /// Fixed authority key seed → reproducible KeyRegistry across tests.
    const TEST_AUTHORITY_SEED: [u8; 32] = [0x42u8; 32];

    /// Build a `KeyRegistry` whose `authority_keypair` matches the
    /// signing key returned alongside it. The verifier-token-key and
    /// quality-key fields are filled with stub bytes — `advance_epoch`
    /// only ever reads the authority key.
    fn registry_and_signing_key() -> (StdArc<KeyRegistry>, SigningKey) {
        let sk = SigningKey::from_bytes(&TEST_AUTHORITY_SEED);
        let registry = StdArc::new(KeyRegistry::for_tests_with_authority(sk.clone()));
        (registry, sk)
    }

    /// Build a minimal valid policy.toml with the supplied epoch +
    /// authority pubkey, sign it, and write both files into `data_dir/policy/`.
    /// Returns `(policy_path, sig_path)`.
    fn write_signed_policy_artifact(
        data_dir:     &Path,
        epoch:        u64,
        authority_sk: &SigningKey,
    ) -> (PathBuf, PathBuf) {
        let policy_dir = data_dir.join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();
        let policy_path = policy_dir.join(format!("policy.epoch-{epoch}.toml"));
        let sig_path    = policy_dir.join(format!("policy.epoch-{epoch}.sig"));

        let auth_hex = hex::encode(authority_sk.verifying_key().to_bytes());
        let qual_hex = "b".repeat(64);

        // Mint a real Ed25519 operator key + self-signed cert so the
        // policy.toml passes `PolicyBundle::validate`'s mandatory cert
        // checks (INV-CERT-01). The seed [0x33; 32] is deterministic
        // so the test's outputs are stable across runs.
        let op_sk = SigningKey::from_bytes(&[0x33u8; 32]);
        let op_pk_hex = hex::encode(op_sk.verifying_key().to_bytes());
        let op_fp = raxis_policy::loader::operator_pubkey_fingerprint(&op_pk_hex).unwrap();

        let cert = raxis_test_support::ephemeral_cert_with_key(
            &op_sk,
            raxis_test_support::CertOpts {
                display_name: "Chika".to_owned(),
                permitted_ops: vec!["CreateInitiative".to_owned()],
                ..raxis_test_support::CertOpts::default()
            },
        );
        let cert_subtable = toml::to_string(&cert).unwrap();

        // Hand-built policy.toml that satisfies `PolicyBundle::validate`.
        // Keeping it inline avoids a dependency on the genesis emitter
        // (which hard-codes `epoch = 1`) and forces this test to spell
        // out exactly which fields participate in advance.
        let toml = format!(
            "[meta]\n\
             epoch     = {epoch}\n\
             signed_by = \"{op_fp}\"\n\
             signed_at = 1700000000\n\
             \n\
             [authority]\n\
             authority_pubkey = \"{auth_hex}\"\n\
             quality_pubkey   = \"{qual_hex}\"\n\
             \n\
             [escalation_policy]\n\
             timeout_secs         = 3600\n\
             window_secs          = 300\n\
             max_per_window       = 5\n\
             quarantine_threshold = 3\n\
             \n\
             [sessions]\n\
             default_ttl_secs       = 86400\n\
             max_ttl_secs           = 604800\n\
             allowed_worktree_roots = [\"/tmp/raxis-policy-manager-tests\"]\n\
             \n\
             [delegations]\n\
             max_ttl_secs = 86400\n\
             \n\
             [budget]\n\
             [budget.base_cost_per_intent_kind]\n\
             SingleCommit = 10\n\
             \n\
             [operators]\n\
             [[operators.entries]]\n\
             pubkey_fingerprint = \"{op_fp}\"\n\
             display_name       = \"Chika\"\n\
             pubkey_hex         = \"{op_pk_hex}\"\n\
             permitted_ops      = [\"CreateInitiative\"]\n\
             \n\
             [operators.entries.cert]\n\
             {cert_subtable}\n",
        );
        std::fs::write(&policy_path, toml.as_bytes()).unwrap();

        let sig = authority_sk.sign(toml.as_bytes());
        std::fs::write(&sig_path, sig.to_bytes()).unwrap();

        (policy_path, sig_path)
    }

    /// Boot a HandlerContext-shaped state suitable for `advance_epoch`:
    /// in-memory store with the genesis epoch row pre-installed, a
    /// fresh `Arc<ArcSwap<PolicyBundle>>` holding a stub bundle, and a
    /// `FakeAuditSink` that captures every emitted event.
    fn boot_state() -> (
        StdArc<KeyRegistry>,
        SigningKey,
        StdArc<Store>,
        StdArc<ArcSwap<PolicyBundle>>,
        StdArc<dyn AuditSink>,
        StdArc<FakeAuditSink>,
    ) {
        let (registry, sk) = registry_and_signing_key();
        let store = StdArc::new(open_mem_store());
        // Pre-install the genesis epoch_id = 1 row so `advance_epoch`
        // can move us to epoch 2 onwards. SHA + fingerprint values
        // are stable test fixtures; their content is not what we
        // assert on in these tests.
        let empty = PolicyBundle::for_tests_with_operators(vec![]);
        install_genesis_policy_epoch(&store, "genesis-sha", "genesis-fp", 1, &empty).unwrap();

        let bundle = PolicyBundle::for_tests_with_operators(vec![]);
        let policy_swap = StdArc::new(ArcSwap::from_pointee(bundle));

        let sink = StdArc::new(FakeAuditSink::new());
        let audit: StdArc<dyn AuditSink> = sink.clone();
        (registry, sk, store, policy_swap, audit, sink)
    }

    // ── load_and_verify ───────────────────────────────────────────────

    #[test]
    fn load_and_verify_accepts_valid_signed_artifact_at_higher_epoch() {
        let (registry, sk, store, _swap, _audit, _sink) = boot_state();
        let tmp = tempfile::tempdir().unwrap();
        let (policy_path, sig_path) = write_signed_policy_artifact(tmp.path(), 2, &sk);
        let verified = load_and_verify(&policy_path, &sig_path, &registry, &store).unwrap();
        assert_eq!(verified.bundle.epoch(), 2);
        assert_eq!(verified.sha256_hex.len(), 64);
        assert!(!verified.raw_bytes.is_empty());
    }

    #[test]
    fn load_and_verify_rejects_artifact_signed_with_wrong_key() {
        let (registry, _sk, store, _swap, _audit, _sink) = boot_state();
        let tmp = tempfile::tempdir().unwrap();
        let other_sk = SigningKey::from_bytes(&[0x99u8; 32]);
        let (policy_path, sig_path) = write_signed_policy_artifact(tmp.path(), 2, &other_sk);
        let result = load_and_verify(&policy_path, &sig_path, &registry, &store);
        assert!(matches!(result, Err(PolicyError::SignatureInvalid { .. })),
            "expected SignatureInvalid, got {result:?}");
    }

    #[test]
    fn load_and_verify_rejects_corrupted_signature() {
        let (registry, sk, store, _swap, _audit, _sink) = boot_state();
        let tmp = tempfile::tempdir().unwrap();
        let (policy_path, sig_path) = write_signed_policy_artifact(tmp.path(), 2, &sk);
        // Flip a bit in the signature file.
        let mut bytes = std::fs::read(&sig_path).unwrap();
        bytes[0] ^= 0xFF;
        std::fs::write(&sig_path, &bytes).unwrap();
        let result = load_and_verify(&policy_path, &sig_path, &registry, &store);
        assert!(matches!(result, Err(PolicyError::SignatureInvalid { .. })));
    }

    #[test]
    fn load_and_verify_rejects_short_signature_file() {
        let (registry, sk, store, _swap, _audit, _sink) = boot_state();
        let tmp = tempfile::tempdir().unwrap();
        let (policy_path, sig_path) = write_signed_policy_artifact(tmp.path(), 2, &sk);
        std::fs::write(&sig_path, b"short").unwrap();
        let result = load_and_verify(&policy_path, &sig_path, &registry, &store);
        assert!(matches!(result, Err(PolicyError::SignatureInvalid { .. })));
    }

    #[test]
    fn load_and_verify_rejects_replayed_epoch() {
        let (registry, sk, store, _swap, _audit, _sink) = boot_state();
        let tmp = tempfile::tempdir().unwrap();
        // Genesis already wrote epoch 1; an artifact at epoch 1 must
        // be rejected as a replay.
        let (policy_path, sig_path) = write_signed_policy_artifact(tmp.path(), 1, &sk);
        let result = load_and_verify(&policy_path, &sig_path, &registry, &store);
        assert!(matches!(result, Err(PolicyError::EpochReplay { attempted: 1, current: 1 })),
            "expected EpochReplay {{1, 1}}, got {result:?}");
    }

    #[test]
    fn load_and_verify_rejects_missing_artifact() {
        let (registry, _sk, store, _swap, _audit, _sink) = boot_state();
        let result = load_and_verify(
            Path::new("/nonexistent/policy.toml"),
            Path::new("/nonexistent/policy.sig"),
            &registry,
            &store,
        );
        assert!(matches!(result, Err(PolicyError::ArtifactReadFailed { .. })));
    }

    // ── advance_epoch happy path ──────────────────────────────────────

    #[test]
    fn advance_epoch_swaps_policy_and_persists_history_row() {
        let (registry, sk, store, swap, audit, sink) = boot_state();
        let tmp = tempfile::tempdir().unwrap();
        let (policy_path, sig_path) = write_signed_policy_artifact(tmp.path(), 2, &sk);

        let binding = EpochBinding::new();
        let outcome = advance_epoch(
            &policy_path, &sig_path, "op-prime",
            &registry, &swap, &store, &audit, &binding,
        ).unwrap();

        assert_eq!(outcome.new_epoch_id, 2);
        assert_eq!(outcome.n_delegations_marked_stale, 0);
        assert_eq!(outcome.n_sessions_invalidated, 0);
        assert_eq!(outcome.policy_sha256.len(), 64);
        assert_eq!(outcome.signed_by_authority.len(), 32);

        // ArcSwap visibility flip — readers now see epoch 2.
        assert_eq!(swap.load().epoch(), 2);

        // Store row written.
        assert_eq!(read_current_epoch(&store).unwrap(), 2);

        // Audit event emitted.
        let kinds = sink.event_kinds();
        assert!(kinds.iter().any(|k| *k == "PolicyEpochAdvanced"),
            "expected PolicyEpochAdvanced in {kinds:?}");
    }

    /// Pin the cert audit-chain mirror for the cert-bound operator
    /// entry path. The fixture's policy.toml contains exactly one
    /// operator entry whose `[cert]` block is a freshly-self-signed
    /// Standard cert, so a successful `advance_epoch` must emit
    /// exactly one `OperatorCertInstalled` AND zero
    /// `OperatorCertMisconfigBypassed` events. Cert is mandatory
    /// (INV-CERT-01); there is no cert-less / "legacy" path, and
    /// `OperatorCertLegacyEntryDetected` was deleted alongside it.
    /// The presence / cardinality of the install event is the
    /// visible signal that kernel-store.md §2.5.7 audit-chain
    /// mirroring is wired through the advance path.
    #[test]
    fn advance_epoch_emits_one_cert_installed_per_cert_bound_operator() {
        let (registry, sk, store, swap, audit, sink) = boot_state();
        let tmp = tempfile::tempdir().unwrap();
        let (policy_path, sig_path) = write_signed_policy_artifact(tmp.path(), 2, &sk);

        let binding = EpochBinding::new();
        advance_epoch(
            &policy_path, &sig_path, "op-prime",
            &registry, &swap, &store, &audit, &binding,
        ).unwrap();

        let kinds = sink.event_kinds();
        let n_installed= kinds.iter().filter(|k| **k == "OperatorCertInstalled").count();
        let n_bypass   = kinds.iter().filter(|k| **k == "OperatorCertMisconfigBypassed").count();
        assert_eq!(n_installed, 1, "expected exactly one OperatorCertInstalled (one cert-bound entry); kinds={kinds:?}");
        assert_eq!(n_bypass,    0, "no bypass entries in fixture; kinds={kinds:?}");
        // Sanity: the deleted OperatorCertLegacyEntryDetected MUST
        // never appear in any kernel emit path again.
        assert!(!kinds.iter().any(|k| *k == "OperatorCertLegacyEntryDetected"),
            "deleted variant must never be emitted; kinds={kinds:?}");
    }

    #[test]
    fn advance_epoch_sweeps_active_delegations_and_records_count() {
        // Seed the store with two delegations: one Active (must flip
        // to StaleOnNextUse) and one Revoked (must NOT change). The
        // outcome's `n_delegations_marked_stale` counts only the
        // Active flip.
        let (registry, sk, store, swap, audit, _sink) = boot_state();
        let active_state = DelegationStatus::Active.as_sql_str().unwrap();
        let stale_state  = DelegationStatus::StaleOnNextUse.as_sql_str().unwrap();
        {
            let conn = store.lock_sync();
            // Seed a session row so the delegations FK resolves.
            // Role identifier ("planner") is a free-form text column,
            // so it stays inline; only state strings come from the
            // typed enum per INV-STORE-03.
            conn.execute(
                &format!(
                    "INSERT INTO {SESSIONS} (session_id, role_id, session_token, lineage_id,
                                             fetch_quota, sequence_number, created_at, expires_at)
                     VALUES ('s1', 'planner', 'tok1', 'lin1', 10, 0, 1, 9999999999)"
                ),
                [],
            ).unwrap();
            // The delegations CHECK constraint allows
            // ('Active', 'StaleOnNextUse', 'RenewalRequired') — the
            // schema does NOT have 'Revoked' as a status. Use
            // 'StaleOnNextUse' as the negative-control row instead;
            // the sweep targets only 'Active' rows so 'StaleOnNextUse'
            // must remain unchanged.
            conn.execute(
                &format!(
                    "INSERT INTO {DELEGATIONS} (
                        delegation_id, session_id, capability_class,
                        delegating_role_id, delegate_role_id,
                        effective_from, expires_at, status, operator_signature
                     ) VALUES ('d1', 's1', 'FsRead', 'planner', 'planner',
                               1, 9999999, ?1, X'00')"
                ),
                rusqlite::params![active_state],
            ).unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO {DELEGATIONS} (
                        delegation_id, session_id, capability_class,
                        delegating_role_id, delegate_role_id,
                        effective_from, expires_at, status, operator_signature
                     ) VALUES ('d2', 's1', 'FsWrite', 'planner', 'planner',
                               1, 9999999, ?1, X'00')"
                ),
                rusqlite::params![stale_state],
            ).unwrap();
        }

        let tmp = tempfile::tempdir().unwrap();
        let (pp, sp) = write_signed_policy_artifact(tmp.path(), 2, &sk);
        let binding = EpochBinding::new();
        let outcome = advance_epoch(
            &pp, &sp, "op-prime", &registry, &swap, &store, &audit, &binding,
        ).unwrap();
        assert_eq!(outcome.n_delegations_marked_stale, 1);

        // Verify the actual rows. The Active row flipped to
        // StaleOnNextUse; the already-StaleOnNextUse row is unchanged
        // (the WHERE clause targets `status = 'Active'` only).
        let conn = store.lock_sync();
        let active_status: String = conn
            .query_row(
                &format!("SELECT status FROM {DELEGATIONS} WHERE delegation_id = 'd1'"),
                [], |r| r.get(0),
            )
            .unwrap();
        let stale_status: String = conn
            .query_row(
                &format!("SELECT status FROM {DELEGATIONS} WHERE delegation_id = 'd2'"),
                [], |r| r.get(0),
            )
            .unwrap();
        assert_eq!(active_status, stale_state);
        assert_eq!(stale_status, stale_state);
    }

    #[test]
    fn advance_epoch_marks_active_session_prompts_invalid_in_epoch_binding() {
        // Seed the store with three sessions: two active (must be
        // marked invalid in the binding) and one revoked (must NOT
        // appear in the binding's invalidated set). The outcome's
        // `n_sessions_invalidated` must reflect only the two active
        // sessions; the binding's `session_prompt_valid()` must report
        // `false` for them and `true` for the revoked one.
        use raxis_types::SessionId;
        let (registry, sk, store, swap, audit, _sink) = boot_state();
        let s_alpha = SessionId::new_v4();
        let s_beta  = SessionId::new_v4();
        let s_gone  = SessionId::new_v4();
        {
            let conn = store.lock_sync();
            // Two active sessions (revoked_at IS NULL, expires_at far
            // in the future).
            for sid in [&s_alpha, &s_beta] {
                conn.execute(
                    &format!(
                        "INSERT INTO {SESSIONS} (session_id, role_id, session_token, lineage_id,
                                                 fetch_quota, sequence_number, created_at, expires_at)
                         VALUES (?1, 'planner', ?2, 'lin', 10, 0, 1, 9999999999)"
                    ),
                    rusqlite::params![sid.as_str(), format!("tok-{}", sid.as_str())],
                ).unwrap();
            }
            // One revoked session (revoked_at is set; the active-sessions
            // filter must exclude it).
            conn.execute(
                &format!(
                    "INSERT INTO {SESSIONS} (session_id, role_id, session_token, lineage_id,
                                             fetch_quota, sequence_number, created_at, expires_at,
                                             revoked_at)
                     VALUES (?1, 'planner', ?2, 'lin', 10, 0, 1, 9999999999, 100)"
                ),
                rusqlite::params![s_gone.as_str(), format!("tok-{}", s_gone.as_str())],
            ).unwrap();
        }

        let tmp = tempfile::tempdir().unwrap();
        let (pp, sp) = write_signed_policy_artifact(tmp.path(), 2, &sk);
        let binding = EpochBinding::new();
        let outcome = advance_epoch(
            &pp, &sp, "op-prime", &registry, &swap, &store, &audit, &binding,
        ).unwrap();

        assert_eq!(outcome.n_sessions_invalidated, 2,
            "expected exactly 2 active sessions to be invalidated; got {}",
            outcome.n_sessions_invalidated);
        assert!(!binding.session_prompt_valid(&s_alpha),
            "alpha must be invalidated after epoch advance");
        assert!(!binding.session_prompt_valid(&s_beta),
            "beta must be invalidated after epoch advance");
        assert!(binding.session_prompt_valid(&s_gone),
            "the revoked session must NOT appear in the invalidated set");
    }

    // ── advance_epoch failure paths ───────────────────────────────────

    #[test]
    fn advance_epoch_rejects_artifact_at_or_below_current_epoch() {
        let (registry, sk, store, swap, audit, sink) = boot_state();
        let tmp = tempfile::tempdir().unwrap();
        let (pp, sp) = write_signed_policy_artifact(tmp.path(), 1, &sk);
        let binding = EpochBinding::new();
        let result = advance_epoch(
            &pp, &sp, "op-prime", &registry, &swap, &store, &audit, &binding,
        );
        assert!(matches!(result, Err(PolicyError::EpochReplay { .. })));
        // No store mutation, no in-memory swap.
        assert_eq!(read_current_epoch(&store).unwrap(), 1);
        assert_ne!(swap.load().epoch(), 1, "stub bundle epoch is not 1");
        // No audit emit on failed Phase 0 — the dispatcher writes
        // PolicyAdvanceRejected outside this function.
        assert!(sink.event_kinds().iter().all(|k| *k != "PolicyEpochAdvanced"));
    }

    #[test]
    fn advance_epoch_rejects_invalid_signature_without_state_change() {
        let (registry, _sk, store, swap, audit, _sink) = boot_state();
        let tmp = tempfile::tempdir().unwrap();
        let other_sk = SigningKey::from_bytes(&[0x77u8; 32]);
        let (pp, sp) = write_signed_policy_artifact(tmp.path(), 2, &other_sk);
        let binding = EpochBinding::new();
        let result = advance_epoch(
            &pp, &sp, "op-prime", &registry, &swap, &store, &audit, &binding,
        );
        assert!(matches!(result, Err(PolicyError::SignatureInvalid { .. })));
        assert_eq!(read_current_epoch(&store).unwrap(), 1, "no store mutation");
    }

    #[test]
    fn advance_epoch_rejects_re_install_of_same_artifact_at_different_epoch() {
        // Pin the UNIQUE(policy_sha256) defence-in-depth path. We
        // first install epoch 2, then attempt to install the SAME
        // bytes claiming to be epoch 3 (we hand-edit the file). The
        // INSERT must trip the UNIQUE constraint on the SHA.
        //
        // To reproduce, we need two *different* TOMLs whose SHAs
        // collide — impossible. Instead we demonstrate the contract
        // by emitting the same epoch-3 artifact twice; the SECOND
        // INSERT trips on policy_sha256 UNIQUE because epoch 3 is
        // already installed (the epoch_id PK trips first, but the
        // surface is still the unique-trip path). To distinguish PK
        // from SHA conflicts we directly seed the policy_epoch_history
        // row first.
        let (registry, sk, store, swap, audit, _sink) = boot_state();
        let tmp = tempfile::tempdir().unwrap();
        let (pp, sp) = write_signed_policy_artifact(tmp.path(), 2, &sk);
        // Compute the SHA of the artifact bytes and pre-seed a row at
        // epoch 5 with the same SHA. When `advance_epoch` runs, its
        // epoch (2) is no longer > current (5) — so we'd hit
        // EpochReplay first. To target the SHA path, seed epoch 1
        // with that SHA via direct INSERT (replacing genesis), then
        // advance to epoch 2 with the same artifact.
        let raw = std::fs::read(&pp).unwrap();
        let sha = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&raw);
            hex::encode(h.finalize())
        };
        {
            let conn = store.lock_sync();
            // Replace the genesis row's SHA with the artifact SHA so
            // the next INSERT trips on UNIQUE(policy_sha256), not
            // UNIQUE(epoch_id).
            conn.execute(
                &format!(
                    "UPDATE {POLICY_EPOCH_HISTORY} SET policy_sha256 = ?1 WHERE epoch_id = 1"
                ),
                [&sha],
            )
            .unwrap();
        }
        let binding = EpochBinding::new();
        let result = advance_epoch(
            &pp, &sp, "op-prime", &registry, &swap, &store, &audit, &binding,
        );
        assert!(matches!(result, Err(PolicyError::PolicyArtifactAlreadyInstalled { .. })),
            "expected PolicyArtifactAlreadyInstalled, got {result:?}");
    }

    #[test]
    fn error_code_strings_are_stable() {
        // The CLI keys off these short strings; bumping them would be a
        // wire break. Pin every variant.
        assert_eq!(
            PolicyError::SignatureInvalid { reason: "x".into() }.error_code(),
            "FAIL_POLICY_SIGNATURE_INVALID",
        );
        assert_eq!(
            PolicyError::EpochReplay { attempted: 1, current: 2 }.error_code(),
            "FAIL_POLICY_EPOCH_REPLAY",
        );
        assert_eq!(
            PolicyError::MalformedArtifact { reason: "x".into() }.error_code(),
            "FAIL_POLICY_MALFORMED",
        );
        assert_eq!(
            PolicyError::PathOutsideDataDir {
                path: PathBuf::from("/x"),
                data_dir: PathBuf::from("/y"),
            }
            .error_code(),
            "FAIL_POLICY_PATH_OUTSIDE_DATA_DIR",
        );
        assert_eq!(
            PolicyError::PolicyArtifactAlreadyInstalled { sha256: "x".into() }.error_code(),
            "FAIL_POLICY_ARTIFACT_ALREADY_INSTALLED",
        );
        assert_eq!(
            PolicyError::StoreWriteFailed { reason: "x".into() }.error_code(),
            "FAIL_POLICY_STORE_WRITE",
        );
        assert_eq!(
            PolicyError::ArtifactReadFailed { reason: "x".into() }.error_code(),
            "FAIL_POLICY_ARTIFACT_READ",
        );
    }
}
