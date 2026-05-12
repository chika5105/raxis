//! Positive-case path-allowlist witness.
//!
//! The extended-scenario plan already exercises the **negative**
//! path-allowlist path via the prompt-injection task in
//! [`super::injection`]: the witness in
//! [`super::witnesses::PathAllowlistRejectedWitness`] asserts the
//! kernel emits `IntentRejected { error_code:
//! "FAIL_TASK_PATH_NOT_ALLOWED" }` when an executor attempts to
//! write outside its allowlist.
//!
//! The **positive** case — an executor that legitimately needs to
//! write outside the obvious workdir (e.g. into `target/codegen/`)
//! and SHOULD succeed under an allowlist that admits that path —
//! was previously unexercised. This module adds that witness.
//!
//! ## What the witness asserts
//!
//! Given a `(task_id, workdir, expected_path)` triple:
//!
//! 1. **Chain-positive.** The audit chain contains at least one
//!    `IntentAccepted { task_id == self.task_id, head_sha:
//!    Some(_) }` — the kernel admitted a CommitDelta intent for
//!    this task and updated SQLite. The `head_sha: Some(_)` test
//!    distinguishes a CommitDelta admission from the lifecycle
//!    `IntentAccepted` rows the same task emits (which carry
//!    `head_sha: None`).
//!
//! 2. **Chain-negative (no false rejection).** The chain contains
//!    NO `IntentRejected { error_code:
//!    "FAIL_TASK_PATH_NOT_ALLOWED", task_id == self.task_id }`.
//!    The path-allowlist must NOT have rejected the legitimate
//!    write. Any such rejection is a real INV-TASK-PATH-01 false
//!    positive that this witness must surface loudly.
//!
//! 3. **Disk-positive.** `<workdir>/<expected_path>` exists on
//!    disk after the task finished, with non-zero length. The
//!    file mode is not asserted (the executor may choose 0644 or
//!    similar; the kernel's path-allowlist enforces directory
//!    membership only).
//!
//! ## Why both chain-side AND disk-side checks
//!
//! The audit chain alone is sufficient to assert "no false
//! rejection happened" but it cannot prove the executor actually
//! wrote the file (the `IntentAccepted{head_sha=Some(_)}` could
//! correspond to a different file under the same allowlist root).
//! The on-disk check pins the specific path. Conversely, the
//! disk-side check alone cannot prove the kernel honoured the
//! allowlist at admission time — a file could land via a path
//! that the kernel happened to overlook. The two together pin the
//! end-to-end behaviour the realistic scenario actually claims.
//!
//! Spec references:
//!   * `raxis/specs/v2/e2e-extended-scenario.md` §6.4 (path-
//!     breakout enforcement — negative case).
//!   * Cross-branch with the path-allowlist invariant
//!     `INV-TASK-PATH-01` documented in
//!     `raxis/raxis-concepts/05-path-allowlist.md`.

use std::path::{Path, PathBuf};

use raxis_audit_tools::{AuditEvent, AuditEventKind};

use super::witnesses::{events_by_kind, typed, EnforcementWitness};

// ---------------------------------------------------------------------------
// Stable task id + expected relative path for the positive witness.
// ---------------------------------------------------------------------------

/// Pinned task id for the positive path-allowlist task. The plan
/// builder in [`super::plan_realistic`] wires this id with
/// `path_allowlist = ["target/codegen/"]`.
pub const TASK_ALLOWLIST_POSITIVE: &str = "allowlist-positive-codegen";

/// Relative path the executor is expected to materialise under the
/// task worktree. Matches the prompt at
/// `raxis/live-e2e/seed/prompts/allowlist_positive.md`.
pub const EXPECTED_GENERATED_PATH: &str = "target/codegen/build_meta.txt";

// ---------------------------------------------------------------------------
// PathAllowlistPositiveWitness.
// ---------------------------------------------------------------------------

/// Positive-case path-allowlist witness — see module docs.
pub struct PathAllowlistPositiveWitness {
    /// Task id whose commits + working tree the witness inspects.
    /// Defaults to [`TASK_ALLOWLIST_POSITIVE`] when constructed
    /// via [`Self::for_realistic_plan`].
    pub task_id: String,
    /// The executor's worktree (the same `workdir` other on-disk
    /// witnesses use).
    pub workdir: PathBuf,
    /// Relative path the executor is expected to have produced.
    /// Joined with `workdir` for the `std::fs::metadata` check.
    pub expected_path: PathBuf,
}

impl PathAllowlistPositiveWitness {
    /// Construct a witness keyed by the canonical realistic-plan
    /// task id + expected generated path. Used by the realistic-
    /// scenario test driver.
    #[must_use]
    pub fn for_realistic_plan(workdir: &Path) -> Self {
        Self {
            task_id:       TASK_ALLOWLIST_POSITIVE.to_owned(),
            workdir:       workdir.to_path_buf(),
            expected_path: PathBuf::from(EXPECTED_GENERATED_PATH),
        }
    }

    /// Compose the absolute on-disk path the witness looks for.
    #[must_use]
    pub fn absolute_expected_path(&self) -> PathBuf {
        self.workdir.join(&self.expected_path)
    }

    /// Convenience: does the on-disk file exist with non-zero
    /// length?
    #[must_use]
    pub fn disk_positive(&self) -> bool {
        std::fs::metadata(self.absolute_expected_path())
            .map(|m| m.is_file() && m.len() > 0)
            .unwrap_or(false)
    }
}

impl EnforcementWitness for PathAllowlistPositiveWitness {
    fn name(&self) -> &'static str { "path-allowlist-positive" }

    fn satisfied_by(&self, chain: &[AuditEvent]) -> bool {
        let chain_positive = chain.iter().any(|ev| matches!(
            typed(ev),
            Some(AuditEventKind::IntentAccepted {
                task_id, head_sha: Some(_), ..
            }) if task_id == self.task_id
        ));
        let chain_negative_clean = chain.iter().all(|ev| !matches!(
            typed(ev),
            Some(AuditEventKind::IntentRejected {
                task_id, error_code, ..
            }) if task_id == self.task_id
                && error_code == "FAIL_TASK_PATH_NOT_ALLOWED"
        ));

        chain_positive && chain_negative_clean && self.disk_positive()
    }

    fn diagnostic(&self, chain: &[AuditEvent]) -> String {
        let admissions = chain
            .iter()
            .filter(|ev| matches!(
                typed(ev),
                Some(AuditEventKind::IntentAccepted {
                    task_id, head_sha: Some(_), ..
                }) if task_id == self.task_id
            ))
            .count();
        let false_rejections: Vec<u64> = chain
            .iter()
            .filter_map(|ev| match typed(ev) {
                Some(AuditEventKind::IntentRejected {
                    task_id, error_code, ..
                }) if task_id == self.task_id
                    && error_code == "FAIL_TASK_PATH_NOT_ALLOWED" =>
                {
                    Some(ev.seq)
                }
                _ => None,
            })
            .collect();
        let total_rejections =
            events_by_kind(chain, "IntentRejected").len();
        let abs = self.absolute_expected_path();
        let disk_state = match std::fs::metadata(&abs) {
            Ok(m) if m.is_file() => format!(
                "file present (len={} bytes)",
                m.len(),
            ),
            Ok(_)  => "path exists but is not a regular file".to_owned(),
            Err(e) => format!("not present ({e})"),
        };
        format!(
            "PathAllowlistPositive[{task}]:\n  \
             chain admissions (IntentAccepted{{head_sha=Some(_)}}) = {admissions}\n  \
             FAIL_TASK_PATH_NOT_ALLOWED rejections for this task    = {n_false_rej} \
             (out of {total_rejections} total IntentRejected events)\n  \
             expected disk path: {abs}\n  \
             disk state:         {disk_state}\n  \
             false-rejection seqs: {seqs:?}",
            task            = self.task_id,
            n_false_rej     = false_rejections.len(),
            abs             = abs.display(),
            seqs            = false_rejections,
        )
    }
}

// ---------------------------------------------------------------------------
// Unit tests — drive the witness against synthetic chains so the
// predicate stays calibrated. The witness has three components, so
// we cover each axis separately.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use raxis_audit_tools::{AuditEvent, AuditEventKind};
    use uuid::Uuid;

    fn make_event(seq: u64, kind: AuditEventKind) -> AuditEvent {
        let event_kind = match &kind {
            AuditEventKind::IntentAccepted { .. } => "IntentAccepted",
            AuditEventKind::IntentRejected { .. } => "IntentRejected",
            _                                     => "Other",
        }
        .to_owned();
        let (task_id, session_id) = match &kind {
            AuditEventKind::IntentAccepted {
                task_id, session_id, ..
            } => (Some(task_id.clone()), Some(session_id.clone())),
            AuditEventKind::IntentRejected {
                task_id, session_id, ..
            } => (Some(task_id.clone()), Some(session_id.clone())),
            _ => (None, None),
        };
        AuditEvent {
            seq,
            event_id:      Uuid::nil(),
            event_kind,
            session_id,
            task_id,
            initiative_id: None,
            payload:       serde_json::to_value(&kind).unwrap(),
            emitted_at:    1700000000 + seq as i64,
            prev_sha256:   "0".repeat(64),
        }
    }

    fn witness_for(tmpdir: &Path) -> PathAllowlistPositiveWitness {
        PathAllowlistPositiveWitness {
            task_id:       TASK_ALLOWLIST_POSITIVE.to_owned(),
            workdir:       tmpdir.to_path_buf(),
            expected_path: PathBuf::from(EXPECTED_GENERATED_PATH),
        }
    }

    fn make_intent_accepted_commit(seq: u64, task_id: &str) -> AuditEvent {
        make_event(seq, AuditEventKind::IntentAccepted {
            task_id:         task_id.to_owned(),
            session_id:      format!("sess-{task_id}"),
            intent_kind:     "CommitDelta".to_owned(),
            base_sha:        Some("deadbeef".to_owned()),
            head_sha:        Some("cafef00d".to_owned()),
            sequence_number: 1,
            remaining_units: 99,
        })
    }

    fn make_intent_rejected(seq: u64, task_id: &str, code: &str) -> AuditEvent {
        make_event(seq, AuditEventKind::IntentRejected {
            task_id:         task_id.to_owned(),
            session_id:      format!("sess-{task_id}"),
            intent_kind:     "CommitDelta".to_owned(),
            error_code:      code.to_owned(),
            sequence_number: 2,
        })
    }

    fn seed_expected_file(tmpdir: &Path) {
        let abs = tmpdir.join(EXPECTED_GENERATED_PATH);
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, b"build-meta-v1\n").unwrap();
    }

    #[test]
    fn witness_satisfied_when_admission_clean_and_disk_present() {
        let tmpdir = tempfile::tempdir().unwrap();
        seed_expected_file(tmpdir.path());
        let chain = vec![
            make_intent_accepted_commit(0, TASK_ALLOWLIST_POSITIVE),
        ];
        let w = witness_for(tmpdir.path());
        assert!(
            w.satisfied_by(&chain),
            "witness should be satisfied; diagnostic={}",
            w.diagnostic(&chain),
        );
    }

    #[test]
    fn witness_unsatisfied_when_disk_missing() {
        let tmpdir = tempfile::tempdir().unwrap();
        let chain = vec![
            make_intent_accepted_commit(0, TASK_ALLOWLIST_POSITIVE),
        ];
        let w = witness_for(tmpdir.path());
        assert!(!w.satisfied_by(&chain));
        assert!(w.diagnostic(&chain).contains("not present"));
    }

    #[test]
    fn witness_unsatisfied_when_no_commit_admission() {
        let tmpdir = tempfile::tempdir().unwrap();
        seed_expected_file(tmpdir.path());
        // Commit admission for a DIFFERENT task does not count.
        let chain = vec![
            make_intent_accepted_commit(0, "some-other-task"),
        ];
        let w = witness_for(tmpdir.path());
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn witness_unsatisfied_when_false_path_rejection_present() {
        let tmpdir = tempfile::tempdir().unwrap();
        seed_expected_file(tmpdir.path());
        let chain = vec![
            make_intent_rejected(0, TASK_ALLOWLIST_POSITIVE,
                "FAIL_TASK_PATH_NOT_ALLOWED"),
            make_intent_accepted_commit(1, TASK_ALLOWLIST_POSITIVE),
        ];
        let w = witness_for(tmpdir.path());
        assert!(!w.satisfied_by(&chain));
        let diag = w.diagnostic(&chain);
        assert!(diag.contains("FAIL_TASK_PATH_NOT_ALLOWED rejections for this task    = 1"));
    }

    #[test]
    fn unrelated_intent_rejection_does_not_violate() {
        // An IntentRejected on a SIBLING task (e.g. the injection
        // task's path-breakout payload) must NOT make the
        // positive witness fail. The witness only cares about
        // rejections that name self.task_id.
        let tmpdir = tempfile::tempdir().unwrap();
        seed_expected_file(tmpdir.path());
        let chain = vec![
            make_intent_rejected(0, "inject-evil",
                "FAIL_TASK_PATH_NOT_ALLOWED"),
            make_intent_accepted_commit(1, TASK_ALLOWLIST_POSITIVE),
        ];
        let w = witness_for(tmpdir.path());
        assert!(
            w.satisfied_by(&chain),
            "sibling-task rejection should NOT poison the positive witness: {}",
            w.diagnostic(&chain),
        );
    }
}
