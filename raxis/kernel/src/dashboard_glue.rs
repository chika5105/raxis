//! Kernel-side `PolicyAdvancer` impl for `PUT /api/policy/toml`.
//! Lives inside the kernel binary (rather than `raxis-dashboard-kernel`)
//! because it depends on `policy_manager::advance_epoch` —
//! which is internal to the kernel. The trait that bridges
//! the dashboard surface to this impl is defined in
//! `raxis-dashboard-kernel::PolicyAdvancer`.
//! Spec contract:
//!   * The dashboard accepts the new policy.toml + a detached
//!     Ed25519 signature over those bytes (the operator signs
//!     offline with the air-gapped authority key — the
//!     dashboard NEVER holds the authority private key).
//!   * The kernel-side advancer atomically stages the new
//!     bytes onto `policy.toml` / `policy.toml.sig`, runs the
//!     same `advance_epoch` pipeline as the CLI's `raxis policy
//!     reload`, and emits a dashboard-distinct
//!     `PolicyUpdatedViaDashboard` audit event in addition to
//!     the canonical `PolicyEpochAdvanced`.
//!   * On any failure (signature invalid, replay, malformed
//!     TOML, IO trouble) the staged files are rolled back
//!     to the previous bytes so the on-disk state stays
//!     consistent with the kernel's in-memory `PolicyBundle`.

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_dashboard_kernel::{AdvanceError, AdvanceResult, PolicyAdvancer};
use raxis_policy::PolicyBundle;
use raxis_store::Store;

use crate::authority::keys::KeyRegistry;
use crate::policy_manager::{self, PolicyError};
use crate::prompt::epoch_binding::EpochBinding;

/// Kernel-resident `PolicyAdvancer`. Holds Arcs for everything
/// `policy_manager::advance_epoch` needs plus the canonical
/// on-disk paths.
pub struct KernelPolicyAdvancer {
    /// Kernel state shared with the IPC handlers.
    pub registry: Arc<KeyRegistry>,
    pub store: Arc<Store>,
    pub audit: Arc<dyn AuditSink>,
    pub policy: Arc<ArcSwap<PolicyBundle>>,
    pub epoch_binding: Arc<EpochBinding>,
    pub artifact_store: Option<Arc<raxis_artifact_store::ArtifactStore>>,
    /// Canonical on-disk policy.toml path. Writes go via temp +
    /// rename so a partial write never leaves the canonical
    /// path inconsistent with the in-memory bundle.
    pub policy_path: PathBuf,
    /// Canonical detached-signature path
    /// (`<policy_path>.sig` by convention).
    pub sig_path: PathBuf,
}

impl KernelPolicyAdvancer {
    /// Build the advancer. The kernel main loop calls this
    /// once at boot and threads the resulting `Arc<dyn
    /// PolicyAdvancer>` into `KernelDashboardData`.
    pub fn new(
        registry: Arc<KeyRegistry>,
        store: Arc<Store>,
        audit: Arc<dyn AuditSink>,
        policy: Arc<ArcSwap<PolicyBundle>>,
        epoch_binding: Arc<EpochBinding>,
        artifact_store: Option<Arc<raxis_artifact_store::ArtifactStore>>,
        policy_path: PathBuf,
    ) -> Self {
        let sig_path = sig_path_for(&policy_path);
        Self {
            registry,
            store,
            audit,
            policy,
            epoch_binding,
            artifact_store,
            policy_path,
            sig_path,
        }
    }
}

impl PolicyAdvancer for KernelPolicyAdvancer {
    fn advance(
        &self,
        toml_bytes: &[u8],
        sig_bytes: &[u8],
        operator_fingerprint: &str,
    ) -> Result<AdvanceResult, AdvanceError> {
        // Phase A — read the previous on-disk content so we can
        // roll back a failed `advance_epoch`. If either file is
        // missing (fresh install, edge case) we treat the
        // missing side as "no previous content" and roll back
        // by deleting the staged bytes.
        let prev_toml = read_existing(&self.policy_path);
        let prev_sig = read_existing(&self.sig_path);
        // Phase B — stage the new bytes onto the canonical
        // paths atomically (write to .tmp, then rename).
        atomic_write(&self.policy_path, toml_bytes).map_err(|e| {
            AdvanceError::Internal(format!("stage policy.toml at {:?}: {e}", self.policy_path))
        })?;
        if let Err(e) = atomic_write(&self.sig_path, sig_bytes) {
            // The .toml landed but the .sig did not — restore
            // the previous .toml so the caller doesn't see a
            // half-written artifact.
            restore(&self.policy_path, prev_toml.as_deref());
            return Err(AdvanceError::Internal(format!(
                "stage policy.toml.sig at {:?}: {e}",
                self.sig_path
            )));
        }
        // Phase C — capture the previous epoch BEFORE the swap
        // so we can return it to the operator UI.
        let previous_epoch = self.policy.load_full().epoch();
        // Phase D — drive `advance_epoch`. On any failure,
        // restore the previous on-disk bytes and surface a
        // typed AdvanceError.
        let outcome = match policy_manager::advance_epoch(
            &self.policy_path,
            &self.sig_path,
            operator_fingerprint,
            &self.registry,
            &self.policy,
            &self.store,
            &self.audit,
            &self.epoch_binding,
            self.artifact_store.as_deref(),
        ) {
            Ok(o) => o,
            Err(e) => {
                restore(&self.policy_path, prev_toml.as_deref());
                restore(&self.sig_path, prev_sig.as_deref());
                // Operator-safe error mapping. The Validation
                // bucket carries the validator's short message;
                // the Internal bucket hides IO trouble that
                // could leak host-internal paths.
                return Err(map_policy_error(e));
            }
        };
        // Phase E — emit the dashboard-distinct audit event.
        // Failure is logged; we DO NOT roll back the swap (the
        // canonical PolicyEpochAdvanced row already landed in
        // the chain inside advance_epoch).
        if let Err(e) = self.audit.emit(
            AuditEventKind::PolicyUpdatedViaDashboard {
                operator_fingerprint: operator_fingerprint.to_owned(),
                previous_epoch,
                new_epoch: outcome.new_epoch_id,
                policy_sha256: outcome.policy_sha256.clone(),
            },
            None,
            None,
            None,
        ) {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"PolicyUpdatedViaDashboardEmitFailed\",\
                 \"reason\":\"{e}\"}}"
            );
        }
        Ok(AdvanceResult {
            previous_epoch,
            new_epoch: outcome.new_epoch_id,
            policy_sha256: outcome.policy_sha256,
            signed_by_authority: outcome.signed_by_authority,
            n_delegations_marked_stale: outcome.n_delegations_marked_stale,
            n_sessions_invalidated: outcome.n_sessions_invalidated,
            advanced_at: outcome.advanced_at_unix_secs.max(0) as u64,
        })
    }
}

/// Convention: `<policy_path>.sig`. Mirrors the CLI default
/// (`raxis policy sign`).
pub fn sig_path_for(policy_path: &std::path::Path) -> PathBuf {
    let mut sig = policy_path.as_os_str().to_owned();
    sig.push(".sig");
    PathBuf::from(sig)
}

/// Read existing bytes; absent file ⇒ `None` (treated as a
/// fresh install for rollback purposes).
fn read_existing(path: &std::path::Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

/// Write `bytes` to `path` atomically: write to `<path>.tmp`
/// then rename. The temp file is in the same directory so the
/// rename stays on the same filesystem (atomic per POSIX).
fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("policy path {path:?} has no parent"),
        )
    })?;
    std::fs::create_dir_all(parent)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".dashboard.tmp");
    let tmp_path = std::path::PathBuf::from(tmp);
    std::fs::write(&tmp_path, bytes)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Restore the previous bytes (or remove the staged file when
/// no previous bytes existed). Best-effort; rollback failures
/// are logged via stderr (the operator sees the wrapping
/// AdvanceError so they know to re-check on-disk state).
fn restore(path: &std::path::Path, prev: Option<&[u8]>) {
    let res = match prev {
        Some(bytes) => atomic_write(path, bytes),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        },
    };
    if let Err(e) = res {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"PolicyAdvanceRollbackFailed\",\
             \"path\":\"{}\",\"reason\":\"{e}\"}}",
            path.display(),
        );
    }
}

/// Map a `PolicyError` to the dashboard's `AdvanceError`
/// surface. Validation-class errors carry their own
/// operator-safe `Display` text; store-write trouble is
/// suppressed onto Internal so on-disk paths don't leak.
fn map_policy_error(e: PolicyError) -> AdvanceError {
    match e {
        PolicyError::SignatureInvalid { .. }
        | PolicyError::EpochReplay { .. }
        | PolicyError::MalformedArtifact { .. }
        | PolicyError::PathOutsideDataDir { .. }
        | PolicyError::ArtifactReadFailed { .. }
        | PolicyError::PolicyArtifactAlreadyInstalled { .. } => {
            AdvanceError::Validation(e.to_string())
        }
        PolicyError::StoreWriteFailed { .. } => AdvanceError::Internal(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Arc as StdArc;

    use raxis_test_support::FakeAuditSink;

    #[test]
    fn sig_path_appends_sig() {
        let p = PathBuf::from("/foo/bar/policy.toml");
        let s = sig_path_for(&p);
        assert_eq!(s, PathBuf::from("/foo/bar/policy.toml.sig"));
    }

    #[test]
    fn atomic_write_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("nested/dir/policy.toml");
        atomic_write(&p, b"hello").unwrap();
        let read = std::fs::read(&p).unwrap();
        assert_eq!(read, b"hello");
    }

    #[test]
    fn restore_removes_when_no_previous() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("file.toml");
        std::fs::write(&p, b"new").unwrap();
        restore(&p, None);
        assert!(!p.exists());
    }

    #[test]
    fn restore_writes_previous_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("file.toml");
        std::fs::write(&p, b"new").unwrap();
        restore(&p, Some(b"old"));
        let read = std::fs::read(&p).unwrap();
        assert_eq!(read, b"old");
    }

    // --- Real-pipeline tests -------------------------------------------
    // The helpers below exercise the full advancer pipeline (Phase A
    // stage → Phase D advance_epoch → Phase E audit emit) against
    // a real on-disk store + audit chain. The `policy_manager`
    // module already covers `advance_epoch` directly; these tests
    // pin the dashboard-side glue (file rollback, audit emission,
    // error mapping).

    /// Reuse the same test fixtures as `policy_manager::tests`. We
    /// import the `super::policy_manager::tests` helpers via path
    /// because they are private — instead we build minimal
    /// equivalents inline here. (The manifest of fields a valid
    /// policy.toml needs is captured by
    /// `raxis_policy::PolicyBundle::validate`, so any drift is
    /// caught at compile/run-time the same way the
    /// `policy_manager::tests::write_signed_policy_artifact`
    /// does.)
    const TEST_AUTHORITY_SEED: [u8; 32] = [0x42u8; 32];

    fn registry_and_authority() -> (StdArc<KeyRegistry>, SigningKey) {
        let sk = SigningKey::from_bytes(&TEST_AUTHORITY_SEED);
        let registry = StdArc::new(KeyRegistry::for_tests_with_authority(sk.clone()));
        (registry, sk)
    }

    fn write_signed_policy(
        data_dir: &std::path::Path,
        epoch: u64,
        authority_sk: &SigningKey,
    ) -> Vec<u8> {
        let auth_hex = hex::encode(authority_sk.verifying_key().to_bytes());
        let qual_hex = "b".repeat(64);
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
        let toml_str = format!(
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
             allowed_worktree_roots = [\"/tmp/raxis-dashboard-glue\"]\n\
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
        let _ = data_dir;
        toml_str.into_bytes()
    }

    /// Boot a complete advancer setup: real Store with genesis row,
    /// real ArcSwap<PolicyBundle>, real authority key, real
    /// EpochBinding, FakeAuditSink so the test can introspect the
    /// emitted events.
    fn boot_advancer(
        policy_path: PathBuf,
    ) -> (
        KernelPolicyAdvancer,
        StdArc<FakeAuditSink>,
        StdArc<arc_swap::ArcSwap<raxis_policy::PolicyBundle>>,
        StdArc<raxis_store::Store>,
        SigningKey,
    ) {
        let (registry, authority_sk) = registry_and_authority();
        let store = StdArc::new(raxis_store::Store::open_in_memory().expect("open mem store"));
        let empty = raxis_policy::PolicyBundle::for_tests_with_operators(vec![]);
        crate::policy_manager::install_genesis_policy_epoch(
            &store,
            "genesis-sha",
            "genesis-fp",
            1,
            &empty,
        )
        .unwrap();
        let policy: StdArc<arc_swap::ArcSwap<raxis_policy::PolicyBundle>> =
            StdArc::new(arc_swap::ArcSwap::from_pointee(empty));
        let sink = StdArc::new(FakeAuditSink::new());
        let audit: StdArc<dyn AuditSink> = sink.clone();
        let epoch_binding = StdArc::new(crate::prompt::EpochBinding::new());

        let advancer = KernelPolicyAdvancer::new(
            registry,
            StdArc::clone(&store),
            audit,
            StdArc::clone(&policy),
            epoch_binding,
            None,
            policy_path,
        );
        (advancer, sink, policy, store, authority_sk)
    }

    #[test]
    fn advance_round_trips_and_emits_dashboard_audit() {
        let tmp = tempfile::tempdir().unwrap();
        let policy_path = tmp.path().join("policy.toml");
        // Pre-populate a "previous" policy.toml + sig so the
        // rollback path has prior bytes to restore from on
        // failure (the happy path here doesn't restore).
        std::fs::write(&policy_path, b"# previous\n").unwrap();
        std::fs::write(sig_path_for(&policy_path), [0u8; 64]).unwrap();
        let (advancer, sink, swap, _store, authority_sk) = boot_advancer(policy_path.clone());
        let toml_bytes = write_signed_policy(tmp.path(), 2, &authority_sk);
        let sig_bytes = authority_sk.sign(&toml_bytes).to_bytes().to_vec();

        let outcome = advancer
            .advance(&toml_bytes, &sig_bytes, "op-dashboard")
            .expect("advance");

        // The in-memory swap was seeded with `for_tests_with_operators(vec![])`
        // which carries `epoch = 0`; production seeds the swap with the
        // genesis bundle (epoch = 1). The advancer captures
        // `previous_epoch` straight off the swap, so the test
        // observes the test-fixture's pre-swap epoch (0), not the
        // SQL row (1). The advance still succeeds because Phase 0
        // verifies against the SQL row.
        assert_eq!(outcome.previous_epoch, 0);
        assert_eq!(outcome.new_epoch, 2);
        assert_eq!(outcome.policy_sha256.len(), 64);
        // The in-memory swap reflects the new bundle.
        assert_eq!(swap.load().epoch(), 2);
        // Both audit events landed: the canonical
        // PolicyEpochAdvanced from advance_epoch + the dashboard's
        // PolicyUpdatedViaDashboard.
        let kinds = sink.event_kinds();
        assert!(
            kinds.contains(&"PolicyEpochAdvanced"),
            "expected PolicyEpochAdvanced; got {kinds:?}"
        );
        assert!(
            kinds.contains(&"PolicyUpdatedViaDashboard"),
            "expected PolicyUpdatedViaDashboard; got {kinds:?}"
        );
        // The on-disk policy.toml + sig now hold the new bytes.
        assert_eq!(std::fs::read(&policy_path).unwrap(), toml_bytes);
        assert_eq!(
            std::fs::read(sig_path_for(&policy_path)).unwrap(),
            sig_bytes
        );
    }

    #[test]
    fn advance_with_bad_signature_rolls_back_disk_and_returns_validation() {
        let tmp = tempfile::tempdir().unwrap();
        let policy_path = tmp.path().join("policy.toml");
        let prev_toml = b"# previous policy\n";
        let prev_sig = [0u8; 64];
        std::fs::write(&policy_path, prev_toml).unwrap();
        std::fs::write(sig_path_for(&policy_path), prev_sig).unwrap();
        let (advancer, sink, swap, _store, authority_sk) = boot_advancer(policy_path.clone());
        let toml_bytes = write_signed_policy(tmp.path(), 2, &authority_sk);
        // Sign with a DIFFERENT key so verify fails.
        let bad_sk = SigningKey::from_bytes(&[0x99u8; 32]);
        let bad_sig = bad_sk.sign(&toml_bytes).to_bytes().to_vec();

        let result = advancer.advance(&toml_bytes, &bad_sig, "op-dashboard");
        assert!(matches!(result, Err(AdvanceError::Validation(_))));
        // Epoch unchanged.
        assert_eq!(swap.load().epoch(), 0); // Not 1, because the swap was seeded with for_tests epoch=0
                                            // No PolicyUpdatedViaDashboard event.
        let kinds = sink.event_kinds();
        assert!(!kinds.contains(&"PolicyUpdatedViaDashboard"));
        // On-disk files restored to their previous content.
        assert_eq!(std::fs::read(&policy_path).unwrap(), prev_toml);
        assert_eq!(
            std::fs::read(sig_path_for(&policy_path)).unwrap(),
            &prev_sig[..]
        );
    }

    #[test]
    fn advance_with_replay_epoch_rolls_back_and_returns_validation() {
        let tmp = tempfile::tempdir().unwrap();
        let policy_path = tmp.path().join("policy.toml");
        let prev_toml = b"# previous\n";
        let prev_sig = [0u8; 64];
        std::fs::write(&policy_path, prev_toml).unwrap();
        std::fs::write(sig_path_for(&policy_path), prev_sig).unwrap();
        let (advancer, sink, _swap, _store, authority_sk) = boot_advancer(policy_path.clone());
        // Sign a policy at epoch 1 — replay protection should reject
        // because the genesis row already pinned epoch 1.
        let toml_bytes = write_signed_policy(tmp.path(), 1, &authority_sk);
        let sig_bytes = authority_sk.sign(&toml_bytes).to_bytes().to_vec();

        let result = advancer.advance(&toml_bytes, &sig_bytes, "op-dashboard");
        assert!(matches!(result, Err(AdvanceError::Validation(_))));
        let kinds = sink.event_kinds();
        assert!(!kinds.contains(&"PolicyUpdatedViaDashboard"));
        assert_eq!(std::fs::read(&policy_path).unwrap(), prev_toml);
    }
}
