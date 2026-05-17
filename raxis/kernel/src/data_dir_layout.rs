// raxis-kernel::data_dir_layout — Canonical data-dir subdirectory
// list + boot-time bootstrap helper.
//
// Normative reference:
//   * `specs/invariants.md` `INV-DATA-DIR-WITNESS-SUBDIR-BOOTSTRAPPED-01`
//   * `specs/invariants.md` `INV-DATA-DIR-LAYOUT-COMPLETE-ON-BOOT-01`
//
// **Why this module exists.** Every per-handler subdirectory the kernel
// can ever write to MUST exist on disk before the first IPC frame is
// dispatched. Until iter66, individual handler call sites trusted that
// genesis (`bootstrap.rs`) or a sibling crate's lazy `Foo::open(data_dir)`
// constructor had already created their directory. The witness blob
// writer (`write_blob_to_disk`) was the surface that proved the trust
// was misplaced: a fresh-genesis kernel that never created
// `<data_dir>/witness/` panicked the first `IntegrationMerge` gate
// evaluation with `No such file or directory (os error 2)` — leaving
// the gate permanently `GatesPending` and cascading into a runaway
// orchestrator respawn loop visible only at the ceiling-exceeded
// harness panic five layers downstream.
//
// **What this module enforces.** [`DATA_DIR_SUBDIRS`] is the canonical,
// alphabetically-sorted list of every per-handler subdirectory the
// kernel daemon either (a) creates eagerly at boot anyway, or (b) MUST
// have on disk for a write surface to function safely. Adding a new
// per-handler subdirectory writer to the kernel REQUIRES adding the
// directory name to this list — pinned by
// `kernel/tests/data_dir_bootstrap.rs::canonical_layout_complete_on_boot`.
//
// **What this module deliberately omits.** Some directories are NOT
// part of the canonical layout because the kernel either never writes
// to them (`escalations/` — escalation rows live in SQLite, see
// `kernel/tests/extended_e2e_concurrent_lifecycle.rs::
// assert_no_forged_approvals_on_disk`) or only writes to them under a
// per-session sub-key the kernel must mint at runtime
// (`guests/<session_id>/console.log` — created by
// `session_spawn_orchestrator` at first session spawn). Those surfaces
// stay out of this list deliberately; the test that walks
// `DATA_DIR_SUBDIRS` MUST NOT trip them.

use std::path::Path;

/// Canonical list of per-handler subdirectories the kernel daemon
/// MUST ensure exist before accepting any IPC intent.
///
/// Alphabetically sorted for `raxis doctor` / operator-`ls` parity.
/// The list is the source of truth for both:
///   * boot-time bootstrap ([`ensure_data_dir_layout`]),
///   * doctor's `EXPECTED_MODES` (which adds the per-dir mode bits),
///   * the regression-net test in `kernel/tests/data_dir_bootstrap.rs`.
pub const DATA_DIR_SUBDIRS: &[&str] = &[
    // Content-addressed immutable artifact store
    // (`crates/artifact-store`). Created eagerly at boot today, but
    // listing it here keeps the list authoritative.
    "artifacts",
    // Append-only audit chain (`audit/segment-NNN.jsonl`).
    "audit",
    // Authority + quality + verifier_token keys (mode 0o700).
    "keys",
    // Per-task LLM-turn capture
    // (`raxis-dashboard-kernel::TaskLlmCapture`).
    "llm-turns",
    // Operator notification inbox (`notifications/inbox.jsonl`)
    // + sidecar bookkeeping.
    "notifications",
    // Pre-populated OCI image cache for the offline image resolver
    // (`raxis-image-cache::PrePopulatedResolver`).
    "oci-cache",
    // Active signed policy artifact + per-epoch history.
    "policy",
    // Per-provider credential files (mode 0o700).
    "providers",
    // Host-side main-repo clone root used by
    // `worktree_provisioning::orchestrator_provision_main`. The kernel
    // creates the `main/` subdir explicitly at boot — the bare
    // `repositories/` parent is required so a fresh genesis can be
    // `ls`'d cleanly.
    "repositories",
    // Heartbeat (`heartbeat.json`), embedded gateway state, and
    // operator-runtime working dirs.
    "runtime",
    // Per-session lifecycle / post-mortem capture
    // (`raxis-dashboard-kernel::SessionCapture`). Records survive
    // session termination so the dashboard Post-mortem tab can
    // read them after the VM is gone — see
    // `INV-DASHBOARD-SESSION-CAPTURE-PERSIST-AFTER-TERMINATION-01`.
    "session-capture",
    // Three UDS endpoints (operator / planner / gateway).
    "sockets",
    // Per-session SSE / activity-stream capture
    // (`raxis-dashboard-kernel::SessionStreamCapture`).
    "streams",
    // Host-side worktree-staging staging root
    // (`raxis-worktree-staging`). Paired with `worktrees/`.
    "transfer",
    // Witness-blob filesystem store, content-addressed by SHA-256.
    // Read + written by `kernel::witness_index`. **iter66 root cause
    // — see module-level comment.**
    "witness",
    // Content-addressed worktree snapshot blob store. SQL index in
    // `worktree_snapshots`; blobs live at
    // `worktree-snapshots/blobs/<sha256>`. Read + written by
    // `kernel::worktree_snapshot`. iter68 — specs/v3/worktree-snapshots.md.
    "worktree-snapshots",
    // Per-session worktree clones produced by
    // `worktree_provisioning::{executor_clone_from_orchestrator,
    // reviewer_clone_at_evaluation_sha}`.
    "worktrees",
];

/// Idempotently create every directory listed in
/// [`DATA_DIR_SUBDIRS`] under `data_dir`.
///
/// The function is `create_dir_all`-based, so it is safe against
/// concurrent callers and against pre-existing directories (genesis
/// already mkdir'd most of these). It returns the list of (name,
/// outcome) pairs so the caller can log per-dir creation events;
/// callers that don't need that detail can ignore the return value.
///
/// **What this is NOT.** This helper does not chmod, does not write
/// any files inside the new directories, and does not compete with
/// genesis bootstrap for permission-mode authority. genesis is the
/// owner of mode 0o700 on `keys/` and `providers/` (kernel-store.md
/// §2.5.1 + peripherals.md §3.2); the per-dir chmods stay there. This
/// helper is purely an "exists before write" gate.
///
/// **Order with respect to genesis.** Designed to be safe to call
/// AFTER genesis has run (the eager-genesis case) AND on a fresh
/// non-genesis data dir that an operator dropped a pre-built
/// `policy.toml` + key registry into (the upgrade case). Either way,
/// every entry in `DATA_DIR_SUBDIRS` is on disk when this function
/// returns Ok.
pub fn ensure_data_dir_layout(data_dir: &Path) -> std::io::Result<()> {
    for name in DATA_DIR_SUBDIRS {
        let path = data_dir.join(name);
        std::fs::create_dir_all(&path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn data_dir_subdirs_is_alphabetically_sorted() {
        let mut sorted = DATA_DIR_SUBDIRS.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            sorted.as_slice(),
            DATA_DIR_SUBDIRS,
            "DATA_DIR_SUBDIRS must stay alphabetically sorted so \
             reviewers + operators can scan the list at a glance",
        );
    }

    #[test]
    fn data_dir_subdirs_contains_witness() {
        // INV-DATA-DIR-WITNESS-SUBDIR-BOOTSTRAPPED-01 — pinning the
        // exact directory name the iter66 root cause turned on.
        assert!(
            DATA_DIR_SUBDIRS.contains(&"witness"),
            "witness/ must be in the canonical layout list — see \
             INV-DATA-DIR-WITNESS-SUBDIR-BOOTSTRAPPED-01",
        );
    }

    #[test]
    fn ensure_creates_every_listed_subdir_on_a_fresh_data_dir() {
        let tmp = TempDir::new().unwrap();
        ensure_data_dir_layout(tmp.path()).expect("first run must succeed");
        for name in DATA_DIR_SUBDIRS {
            let p = tmp.path().join(name);
            assert!(
                p.is_dir(),
                "ensure_data_dir_layout did not create {} (path: {})",
                name,
                p.display(),
            );
        }
    }

    #[test]
    fn ensure_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        ensure_data_dir_layout(tmp.path()).expect("first call");
        ensure_data_dir_layout(tmp.path()).expect("second call must be a no-op");
        ensure_data_dir_layout(tmp.path()).expect("third call must be a no-op");
        for name in DATA_DIR_SUBDIRS {
            assert!(tmp.path().join(name).is_dir());
        }
    }

    #[test]
    fn ensure_tolerates_pre_existing_directories() {
        let tmp = TempDir::new().unwrap();
        // Pre-create one of the listed subdirs the way `bootstrap.rs`
        // does at genesis time.
        std::fs::create_dir_all(tmp.path().join("audit")).unwrap();
        ensure_data_dir_layout(tmp.path())
            .expect("ensure must accept a pre-existing subdir without error");
        for name in DATA_DIR_SUBDIRS {
            assert!(tmp.path().join(name).is_dir());
        }
    }
}
