// V2.5 `integration-merge.md §11.4` (INV-MERGE-WORKTREE-RETAIN) —
// kernel-side worktree garbage collector.
//
// Scope. The kernel evicts a session's host-side worktree directory
// (`<data_dir>/worktrees/<session_uuid>/`) when one of these conditions
// is observed:
//
//   * the session has been revoked / completed AND
//   * no in-flight `IntegrationMerge` for any task in the same
//     initiative still has `git_apply_pending = 1`.
//
// The second predicate is the §11.4 retention rule: while
// `git_apply_pending = 1` for an initiative, the originating
// Orchestrator's worktree is the input to `commit_merge_to_target_ref`
// during `recovery::reconcile_git_apply_pending` after a kernel
// crash. Removing it would convert a Case-A recovery into a Case-C
// `GitStateInconsistent` violation.
//
// What this module provides.
// ---------------------------
// One synchronous entry point — [`gc_session_worktree`] — that:
//
//   1. Acquires the SQLite mutex once and reads
//      (worktree_root, pending_initiative_id) atomically.
//   2. If a pending initiative is found, returns a
//      [`WorktreeGcDecision::RetainedPendingMerge`] WITHOUT touching
//      disk. The caller (a periodic scrubber, a `SessionRevoked`
//      handler, or a recovery sweep) is responsible for re-trying
//      after the recovery procedure clears the flag.
//   3. Otherwise calls `worktree_staging::destroy` on the recorded
//      `worktree_root` and returns
//      [`WorktreeGcDecision::Removed`].
//
// Why a separate module instead of folding into `worktree-staging`.
// `raxis-worktree-staging` is a pure-data crate with no SQLite dep
// (per its crate-level docs); putting the §11.4 guard there would
// force every consumer to drag in `raxis-store` even when they only
// want to mint a worktree. The kernel binary already depends on
// both, so the orchestration belongs here.
//
// Why no audit emission here.
// The §11.4 spec does not define an `AuditEventKind` for "worktree
// retention deferred"; the structured-log line plus the typed return
// value are sufficient for the dashboard to surface the deferral.
// Adding a new audit variant would be a wire-shape change to the
// chain; we intentionally avoid that.

use std::path::{Path, PathBuf};

use raxis_store::Store;

use crate::worktree_snapshot::{snapshot_worktree, SnapshotInput, SnapshotTrigger};

/// Outcome of a single [`gc_session_worktree`] call.
///
/// `Removed` and `NoWorktree` both indicate the GC has nothing more
/// to do for this session; `RetainedPendingMerge` means the caller
/// MUST retry after the next `reconcile_git_apply_pending` sweep
/// (or after the in-flight Phase 3 commits, whichever comes first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorktreeGcDecision {
    /// `worktree_staging::destroy` succeeded; the directory is gone.
    Removed { path: PathBuf },
    /// The session row had `worktree_root IS NULL` — the session was
    /// reserved but never received a staged worktree (or a previous
    /// GC pass already removed it). No-op.
    NoWorktree,
    /// `git_apply_pending = 1` still holds for an initiative
    /// referencing this session. Per INV-MERGE-WORKTREE-RETAIN
    /// (`integration-merge.md §11.4`), the GC MUST leave the
    /// worktree on disk so a crash-recovery Case A re-fetch has
    /// the objects it needs.
    RetainedPendingMerge {
        path: PathBuf,
        blocking_initiative_id: String,
    },
}

/// Errors the GC orchestrator can surface.
#[derive(Debug, thiserror::Error)]
pub enum WorktreeGcError {
    /// SQLite read failed (FK / IO / lock contention). The GC is a
    /// best-effort scrubber; the caller logs and moves on.
    #[error("worktree-gc store read failed: {0}")]
    Store(#[from] rusqlite::Error),
    /// `worktree_staging::destroy` could not delete the directory
    /// (permission denied, EBUSY on a still-mounted virtiofs share,
    /// ...). The worktree is still on disk; a retry on the next
    /// sweep is appropriate.
    #[error("worktree destroy failed: {0}")]
    Destroy(#[from] raxis_worktree_staging::StagingError),
    /// `INV-WORKTREE-SNAPSHOT-PRE-GC-01` — the pre-GC snapshot
    /// could not be written; the GC MUST NOT remove the tree.
    /// The caller (the periodic scrubber) retries on the next
    /// sweep; the worktree stays on disk until either the
    /// snapshot succeeds or operator intervention removes the
    /// tree manually.
    #[error("pre-GC snapshot failed; refusing to remove worktree (INV-WORKTREE-SNAPSHOT-PRE-GC-01): {0}")]
    PreGcSnapshot(#[from] crate::worktree_snapshot::SnapshotError),
}

/// Run the §11.4 retention check and, if cleared, evict the
/// session's host-side worktree.
///
/// This function is **idempotent**: a second call after `Removed`
/// returns `NoWorktree` (the row's `worktree_root` is unchanged but
/// the directory is already gone, and `worktree_staging::destroy`
/// is itself idempotent on the disk side).
///
/// Holds the store mutex only for the read. The disk I/O happens
/// AFTER the mutex is dropped so a slow `remove_dir_all` does not
/// block other store consumers (admission, audit emit).
pub fn gc_session_worktree(
    store: &Store,
    data_dir: &Path,
    session_id: &str,
) -> Result<WorktreeGcDecision, WorktreeGcError> {
    use raxis_store::views::sessions::{pending_initiative_for_session, worktree_root_for_session};

    let (worktree_root_opt, pending_initiative, snapshot_targets): (
        Option<String>,
        Option<String>,
        Vec<SessionTaskSnapshotTarget>,
    ) = {
        let conn = store.lock_sync();
        let wr = worktree_root_for_session(&conn, session_id)?;
        let pi = pending_initiative_for_session(&conn, session_id)?;
        let targets = if wr.is_some() && pi.is_none() {
            // Only enumerate snapshot targets when we are actually
            // going to destroy the tree. Retained-merge or orphan-
            // session paths skip the SQL walk to keep the GC sweep
            // cheap.
            list_snapshot_targets_for_session(&conn, session_id)?
        } else {
            Vec::new()
        };
        (wr, pi, targets)
    };

    let path = match worktree_root_opt {
        Some(p) => PathBuf::from(p),
        None => return Ok(WorktreeGcDecision::NoWorktree),
    };

    if let Some(blocking_initiative_id) = pending_initiative {
        eprintln!(
            "{{\"level\":\"info\",\"step\":\"worktree_gc\",\
             \"action\":\"retained_pending_merge\",\
             \"session_id\":\"{session_id}\",\
             \"initiative_id\":\"{blocking_initiative_id}\",\
             \"worktree_root\":\"{}\",\
             \"reason\":\"INV-MERGE-WORKTREE-RETAIN\"}}",
            path.display(),
        );
        return Ok(WorktreeGcDecision::RetainedPendingMerge {
            path,
            blocking_initiative_id,
        });
    }

    // ── iter68: INV-WORKTREE-SNAPSHOT-PRE-GC-01 — hard-required ────────────
    //
    // Before the tree leaves disk forever, write a content-addressed
    // snapshot for every task bound to this session so the dashboard
    // (and a post-mortem audit-chain replay) can render the worktree
    // state at the moment of GC. A snapshot-write failure here MUST
    // refuse to destroy — the next sweep retries; the operator can
    // intervene manually if a persistent disk fault keeps the
    // snapshot path from succeeding.
    //
    // Sessions with zero bound tasks (orphans created by aborted
    // session-spawn handshakes) skip the snapshot since the
    // `worktree_snapshots.task_id` FK can never be satisfied. The
    // structured-log line records the skip so an operator can
    // distinguish "no tasks → no snapshot" from "snapshot crashed".
    if snapshot_targets.is_empty() {
        eprintln!(
            "{{\"level\":\"info\",\"step\":\"worktree_gc\",\
             \"action\":\"pre_gc_snapshot_skipped_no_tasks\",\
             \"session_id\":\"{session_id}\",\
             \"worktree_root\":\"{}\"}}",
            path.display(),
        );
    } else {
        for target in &snapshot_targets {
            // `worktree_root_for_session` returned `Some(_)` —
            // so the tree IS on disk at `path`. If git plumbing
            // fails (corrupted ODB, missing HEAD, base_sha not in
            // the tree) the snapshot writer surfaces a
            // `GitPlumbing` error and we abort GC. The retention
            // log line below carries enough context for the
            // operator to fix the underlying tree and retry.
            let base_sha = match target.base_sha.clone() {
                Some(b) => b,
                None => {
                    // Task admitted before iter68 — no base_sha to
                    // anchor the diff. Skip the snapshot for this
                    // task (legacy data; the INV does not retro-
                    // actively bind pre-iter68 tasks) but keep
                    // going for the rest.
                    eprintln!(
                        "{{\"level\":\"warn\",\"step\":\"worktree_gc\",\
                         \"action\":\"pre_gc_snapshot_skipped_no_base_sha\",\
                         \"session_id\":\"{session_id}\",\
                         \"task_id\":\"{}\"}}",
                        target.task_id,
                    );
                    continue;
                }
            };
            snapshot_worktree(
                store,
                data_dir,
                SnapshotInput {
                    task_id: target.task_id.clone(),
                    session_id: Some(session_id.to_owned()),
                    initiative_id: target.initiative_id.clone(),
                    trigger: SnapshotTrigger::PreGc,
                    worktree_root: path.clone(),
                    base_sha,
                },
            )?;
        }
        eprintln!(
            "{{\"level\":\"info\",\"step\":\"worktree_gc\",\
             \"action\":\"pre_gc_snapshot_completed\",\
             \"session_id\":\"{session_id}\",\
             \"task_count\":{},\
             \"worktree_root\":\"{}\"}}",
            snapshot_targets.len(),
            path.display(),
        );
    }

    raxis_worktree_staging::destroy(&path)?;
    eprintln!(
        "{{\"level\":\"info\",\"step\":\"worktree_gc\",\
         \"action\":\"removed\",\
         \"session_id\":\"{session_id}\",\
         \"worktree_root\":\"{}\"}}",
        path.display(),
    );
    Ok(WorktreeGcDecision::Removed { path })
}

/// Per-task snapshot input materialised from
/// `(tasks WHERE session_id = ?)` at GC-decision time. Held by
/// value (not borrow) so the SQL lock is released before the
/// snapshot writer runs.
#[derive(Debug, Clone)]
struct SessionTaskSnapshotTarget {
    task_id: String,
    base_sha: Option<String>,
    initiative_id: Option<String>,
}

fn list_snapshot_targets_for_session(
    conn: &rusqlite::Connection,
    session_id: &str,
) -> Result<Vec<SessionTaskSnapshotTarget>, rusqlite::Error> {
    let tasks = raxis_store::Table::Tasks.as_str();
    let mut stmt = conn.prepare(&format!(
        "SELECT task_id, base_sha, initiative_id FROM {tasks} WHERE session_id = ?1"
    ))?;
    let rows = stmt
        .query_map(rusqlite::params![session_id], |row| {
            Ok(SessionTaskSnapshotTarget {
                task_id: row.get(0)?,
                base_sha: row.get(1)?,
                initiative_id: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Tests — production `gc_session_worktree` ⟷ on-disk SQLite ⟷
// real `<tempdir>/worktrees/<uuid>/` directory tree.
//
// The fixture uses `DiskStore` (a TempDir-backed `Store`) and a
// hand-rolled worktree directory so we can assert both the SQL
// guard AND the disk-side destruction in one round trip.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    use raxis_store::Table;
    use raxis_test_support::DiskStore;

    const INITIATIVES: &str = Table::Initiatives.as_str();
    const TASKS: &str = Table::Tasks.as_str();
    const SESSIONS: &str = Table::Sessions.as_str();

    /// Materialise a worktree-shaped directory at
    /// `<data_dir>/worktrees/<session_uuid>/` so `destroy` has
    /// something to remove. Returns the absolute path.
    fn stage_worktree_on_disk(data_dir: &Path, session_uuid: &str) -> PathBuf {
        let path = data_dir
            .join(raxis_worktree_staging::WORKTREES_DIR)
            .join(session_uuid);
        fs::create_dir_all(path.join(".raxis").join("bundles")).unwrap();
        fs::write(path.join(".raxis").join("system_prompt.txt"), b"test\n").unwrap();
        path
    }

    fn seed_initiative(store: &raxis_store::Store, initiative_id: &str, pending: i64) {
        let g = store.lock_sync();
        g.execute(
            &format!(
                "INSERT INTO {INITIATIVES} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at, git_apply_pending) \
                 VALUES (?1, 'Executing', '{{}}', 'deadbeef', 100, ?2)"
            ),
            rusqlite::params![initiative_id, pending],
        )
        .unwrap();
    }

    fn seed_session(store: &raxis_store::Store, session_id: &str, worktree_root: Option<&Path>) {
        let g = store.lock_sync();
        g.execute(
            &format!(
                "INSERT INTO {SESSIONS} \
                    (session_id, role_id, session_token, lineage_id, fetch_quota, \
                     worktree_root, created_at, expires_at) \
                 VALUES (?1, 'orch', ?2, ?1, 0, ?3, 100, 9999999999)"
            ),
            rusqlite::params![
                session_id,
                format!("tok-{session_id}"),
                worktree_root.map(|p| p.display().to_string()),
            ],
        )
        .unwrap();
    }

    fn seed_task(store: &raxis_store::Store, task_id: &str, initiative_id: &str, session_id: &str) {
        let g = store.lock_sync();
        g.execute(
            &format!(
                "INSERT INTO {TASKS} \
                    (task_id, initiative_id, lane_id, state, actor, \
                     policy_epoch, admitted_at, transitioned_at, session_id) \
                 VALUES (?1, ?2, 'lane-1', 'Running', 'orch', 1, 100, 100, ?3)"
            ),
            rusqlite::params![task_id, initiative_id, session_id],
        )
        .unwrap();
    }

    #[test]
    fn removes_worktree_when_no_pending_merge() {
        let disk = DiskStore::new();
        let session_id = "sess-clear";
        let wt = stage_worktree_on_disk(disk.data_dir(), session_id);
        assert!(wt.exists(), "fixture must create the worktree");

        seed_initiative(disk.store(), "init-clear", 0);
        seed_session(disk.store(), session_id, Some(&wt));
        seed_task(disk.store(), "t-clear", "init-clear", session_id);

        let decision = gc_session_worktree(disk.store(), disk.data_dir(), session_id).unwrap();
        match decision {
            WorktreeGcDecision::Removed { path } => assert_eq!(path, wt),
            other => panic!("expected Removed, got {other:?}"),
        }
        assert!(
            !wt.exists(),
            "INV-MERGE-WORKTREE-RETAIN cleared ⇒ GC must evict the worktree"
        );
    }

    #[test]
    fn retains_worktree_when_initiative_has_git_apply_pending() {
        let disk = DiskStore::new();
        let session_id = "sess-pending";
        let wt = stage_worktree_on_disk(disk.data_dir(), session_id);

        seed_initiative(disk.store(), "init-pending", 1);
        seed_session(disk.store(), session_id, Some(&wt));
        seed_task(disk.store(), "t-pending", "init-pending", session_id);

        let decision = gc_session_worktree(disk.store(), disk.data_dir(), session_id).unwrap();
        match decision {
            WorktreeGcDecision::RetainedPendingMerge {
                path,
                blocking_initiative_id,
            } => {
                assert_eq!(path, wt);
                assert_eq!(blocking_initiative_id, "init-pending");
            }
            other => panic!("expected RetainedPendingMerge, got {other:?}"),
        }
        assert!(
            wt.exists(),
            "INV-MERGE-WORKTREE-RETAIN: GC MUST NOT delete worktree while \
             pending merge would need it for Case-A recovery"
        );
    }

    #[test]
    fn no_worktree_when_session_unknown() {
        let disk = DiskStore::new();
        let decision =
            gc_session_worktree(disk.store(), disk.data_dir(), "ghost-session").unwrap();
        assert_eq!(decision, WorktreeGcDecision::NoWorktree);
    }

    #[test]
    fn no_worktree_when_column_null() {
        let disk = DiskStore::new();
        seed_session(disk.store(), "sess-orphan", None);
        let decision =
            gc_session_worktree(disk.store(), disk.data_dir(), "sess-orphan").unwrap();
        assert_eq!(decision, WorktreeGcDecision::NoWorktree);
    }

    #[test]
    fn idempotent_after_removal() {
        let disk = DiskStore::new();
        let session_id = "sess-idem";
        let wt = stage_worktree_on_disk(disk.data_dir(), session_id);
        seed_initiative(disk.store(), "init-idem", 0);
        seed_session(disk.store(), session_id, Some(&wt));
        seed_task(disk.store(), "t-idem", "init-idem", session_id);

        let d1 = gc_session_worktree(disk.store(), disk.data_dir(), session_id).unwrap();
        assert!(matches!(d1, WorktreeGcDecision::Removed { .. }));
        // Disk is gone, but the row still has worktree_root set —
        // destroy() is itself a no-op on a missing path, so we
        // should still see Removed (or NoWorktree if we cleared
        // the column on Phase 3, which we don't).
        let d2 = gc_session_worktree(disk.store(), disk.data_dir(), session_id).unwrap();
        assert!(
            matches!(d2, WorktreeGcDecision::Removed { .. }),
            "idempotency: a second sweep after Removed must succeed"
        );
        assert!(!wt.exists());
    }

    #[test]
    fn unblocks_after_pending_flag_clears() {
        let disk = DiskStore::new();
        let session_id = "sess-unblock";
        let wt = stage_worktree_on_disk(disk.data_dir(), session_id);
        seed_initiative(disk.store(), "init-unblock", 1);
        seed_session(disk.store(), session_id, Some(&wt));
        seed_task(disk.store(), "t-unblock", "init-unblock", session_id);

        // First sweep: blocked.
        let d1 = gc_session_worktree(disk.store(), disk.data_dir(), session_id).unwrap();
        assert!(matches!(
            d1,
            WorktreeGcDecision::RetainedPendingMerge { .. }
        ));
        assert!(wt.exists());

        // Phase 3 (or recovery Case B/A) clears the flag.
        {
            let g = disk.store().lock_sync();
            raxis_store::views::initiatives::clear_git_apply_pending(&g, "init-unblock").unwrap();
        }

        // Second sweep: unblocked.
        let d2 = gc_session_worktree(disk.store(), disk.data_dir(), session_id).unwrap();
        assert!(matches!(d2, WorktreeGcDecision::Removed { .. }));
        assert!(!wt.exists());
    }

    // ── iter68 — INV-WORKTREE-SNAPSHOT-PRE-GC-01 witness tests ────────────
    //
    // These pin the contract that gc_session_worktree refuses to
    // destroy a tree until snapshots have been written for every
    // bound task that has a `base_sha`. The legacy tests above
    // exercise the no-base_sha skip branch; these pin the
    // happy-path snapshot emission + the snapshot-failure abort.

    /// Initialise a tiny one-commit git repo at `worktree_path` and
    /// return the resulting HEAD sha. Used by the pre-GC snapshot
    /// tests so `git rev-parse HEAD` / `git diff` / `git log`
    /// inside `worktree_snapshot::snapshot_worktree` succeed.
    fn init_git_repo_with_one_commit(worktree_path: &Path) -> String {
        let run = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(worktree_path)
                .output()
                .expect("git available");
            assert!(
                out.status.success(),
                "git {args:?} failed: stderr={}",
                String::from_utf8_lossy(&out.stderr),
            );
            String::from_utf8(out.stdout).unwrap()
        };
        run(&["init", "-q"]);
        run(&["config", "user.email", "test@raxis.local"]);
        run(&["config", "user.name", "Raxis Test"]);
        fs::write(worktree_path.join("hello.txt"), b"hello\n").unwrap();
        run(&["add", "hello.txt"]);
        run(&["commit", "-q", "-m", "init"]);
        run(&["rev-parse", "HEAD"]).trim().to_owned()
    }

    fn seed_task_with_base_sha(
        store: &raxis_store::Store,
        task_id: &str,
        initiative_id: &str,
        session_id: &str,
        base_sha: &str,
    ) {
        let g = store.lock_sync();
        g.execute(
            &format!(
                "INSERT INTO {TASKS} \
                    (task_id, initiative_id, lane_id, state, actor, \
                     policy_epoch, admitted_at, transitioned_at, session_id, base_sha) \
                 VALUES (?1, ?2, 'lane-1', 'Running', 'orch', 1, 100, 100, ?3, ?4)"
            ),
            rusqlite::params![task_id, initiative_id, session_id, base_sha],
        )
        .unwrap();
    }

    #[test]
    fn inv_worktree_snapshot_pre_gc_writes_snapshot_before_destroy() {
        let disk = DiskStore::new();
        let session_id = "sess-pregc";
        let wt = stage_worktree_on_disk(disk.data_dir(), session_id);
        let head_sha = init_git_repo_with_one_commit(&wt);
        seed_initiative(disk.store(), "init-pregc", 0);
        seed_session(disk.store(), session_id, Some(&wt));
        seed_task_with_base_sha(
            disk.store(),
            "t-pregc",
            "init-pregc",
            session_id,
            &head_sha,
        );

        let decision = gc_session_worktree(disk.store(), disk.data_dir(), session_id).unwrap();
        assert!(matches!(decision, WorktreeGcDecision::Removed { .. }));
        assert!(!wt.exists(), "tree removed after snapshot succeeded");

        // INV-WORKTREE-SNAPSHOT-PRE-GC-01: a snapshot row must
        // exist for the task with trigger='PreGc' before destroy.
        let snaps = crate::worktree_snapshot::list_for_task(disk.store(), "t-pregc").unwrap();
        assert_eq!(snaps.len(), 1, "exactly one pre-GC snapshot");
        assert_eq!(
            snaps[0].trigger,
            crate::worktree_snapshot::SnapshotTrigger::PreGc
        );
        assert_eq!(snaps[0].head_sha, head_sha);
        assert_eq!(snaps[0].task_id, "t-pregc");
        assert_eq!(snaps[0].session_id.as_deref(), Some(session_id));
    }

    #[test]
    fn inv_worktree_snapshot_pre_gc_skips_when_no_base_sha() {
        // Legacy tasks (admitted before iter68) carry no base_sha.
        // The GC MUST still proceed — we cannot snapshot what we
        // cannot diff — but the structured-log line records the
        // skip so the operator sees the data-quality gap.
        let disk = DiskStore::new();
        let session_id = "sess-legacy";
        let wt = stage_worktree_on_disk(disk.data_dir(), session_id);
        let _head = init_git_repo_with_one_commit(&wt);
        seed_initiative(disk.store(), "init-legacy", 0);
        seed_session(disk.store(), session_id, Some(&wt));
        seed_task(disk.store(), "t-legacy", "init-legacy", session_id);

        let decision = gc_session_worktree(disk.store(), disk.data_dir(), session_id).unwrap();
        assert!(matches!(decision, WorktreeGcDecision::Removed { .. }));
        assert!(!wt.exists());

        // No snapshots persisted — the task had no base_sha to
        // anchor a diff against.
        let snaps = crate::worktree_snapshot::list_for_task(disk.store(), "t-legacy").unwrap();
        assert!(
            snaps.is_empty(),
            "legacy task with NULL base_sha must skip the pre-GC snapshot row"
        );
    }

    #[test]
    fn inv_worktree_snapshot_pre_gc_skipped_for_orphan_session() {
        // Sessions with zero bound tasks (rare; aborted spawn
        // handshakes) skip the snapshot loop entirely and proceed
        // to destroy.
        let disk = DiskStore::new();
        let session_id = "sess-orphan-pregc";
        let wt = stage_worktree_on_disk(disk.data_dir(), session_id);
        seed_session(disk.store(), session_id, Some(&wt));

        let decision = gc_session_worktree(disk.store(), disk.data_dir(), session_id).unwrap();
        assert!(matches!(decision, WorktreeGcDecision::Removed { .. }));
        assert!(!wt.exists());
    }
}
