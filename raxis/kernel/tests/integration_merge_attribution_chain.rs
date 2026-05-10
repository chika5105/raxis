//! Real-runtime integration test for V2 Step 30 — Audit Attribution
//! for Operator-Assisted Commits.
//!
//! Composes the components s30 added against real, on-disk objects
//! (no fakes for the I/O surfaces under test):
//!
//!   * `raxis_audit_tools::AuditWriter` — actual file-backed JSONL
//!     segment with chained SHA-256 prev hashes, written + read back
//!     verbatim.
//!   * `raxis_audit_tools::FileAuditSink` — production sink trait
//!     impl wrapping `AuditWriter`. Same `Arc<dyn AuditSink>`
//!     coercion the kernel's `HandlerContext` performs at boot.
//!   * `raxis_audit_tools::AuditEventKind::IntegrationMergeCompleted`
//!     — the real audit variant carrying the s30 attribution
//!     fields.
//!
//! Why this test does NOT call the kernel-internal verifier:
//!   `raxis-kernel` is a bin-only crate; integration tests cannot
//!   reach `handlers::integration_merge_attribution::
//!   verify_merge_conflict_resolution` directly. That function is
//!   exhaustively covered by unit tests in the same module against
//!   a real in-memory `Store`. This test pins the *audit chain
//!   contract* — that the Step 30 attribution fields land on disk
//!   in the shape an external auditor will read tomorrow.

use std::sync::Arc;

use raxis_audit_tools::{
    sink::{AuditSink, FileAuditSink},
    AuditEvent, AuditEventKind, AuditWriter,
};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Construct a real on-disk `FileAuditSink`. Returns the sink behind
/// `Arc<dyn AuditSink>` (the same trait object the kernel injects)
/// AND the segment path so the test can read the JSONL bytes back.
fn fresh_audit_sink(dir: &TempDir) -> (Arc<dyn AuditSink>, std::path::PathBuf) {
    let segment = dir.path().join("audit-0000.jsonl");
    let writer  = AuditWriter::open(&segment, 0, None).expect("open audit segment");
    let sink    = Arc::new(FileAuditSink::new(writer));
    (sink, segment)
}

/// Read the JSONL audit segment back as a vector of decoded
/// `AuditEvent`s. Fails the calling test on parse error so
/// regressions in the on-disk wire shape produce loud failures
/// rather than silent empty vectors.
fn read_audit_segment(path: &std::path::Path) -> Vec<AuditEvent> {
    let bytes = std::fs::read(path).expect("read audit segment");
    let text  = std::str::from_utf8(&bytes).expect("audit segment is UTF-8");
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str::<AuditEvent>(l)
                 .unwrap_or_else(|e| panic!("decode audit line: {e}\nline: {l}")))
        .collect()
}

/// Helper: SHA-256 of the n-th line including trailing '\n', matching
/// the audit chain hashing convention in `writer.rs`.
fn sha256_of_line(path: &std::path::Path, n: usize) -> String {
    use sha2::Digest;
    let bytes = std::fs::read(path).unwrap();
    let line  = bytes
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .nth(n)
        .expect("line in segment");
    let mut h = sha2::Sha256::new();
    h.update(line);
    h.update(b"\n");
    hex::encode(h.finalize())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Step 30 attribution: an operator-assisted merge writes one
/// `IntegrationMergeCompleted` line carrying `operator_assisted:
/// true` and `escalation_id` to the JSONL segment, in the shape an
/// external auditor will read.
#[test]
fn merge_conflict_attribution_lands_on_audit_chain() {
    let dir          = TempDir::new().unwrap();
    let (sink, path) = fresh_audit_sink(&dir);

    // Same call shape `run_phase_c` uses post-commit when
    // `IntentRequest.resolved_via_escalation = Some(esc_id)` and
    // Check 6b passed.
    let event: AuditEvent = sink.emit(
        AuditEventKind::IntegrationMergeCompleted {
            initiative_id:     "init-9".into(),
            session_id:        "11111111-1111-1111-1111-111111111111".into(),
            commit_sha:        "deadbeefcafebabedeadbeefcafebabedeadbeef".into(),
            previous_sha:      "f3d21a09f3d21a09f3d21a09f3d21a09f3d21a09".into(),
            operator_assisted: true,
            escalation_id:     Some(
                "22222222-2222-2222-2222-222222222222".to_owned()),
        },
        Some("11111111-1111-1111-1111-111111111111"),
        Some("task-9"),
        Some("init-9"),
    ).expect("emit must succeed");

    assert_eq!(event.event_kind,                 "IntegrationMergeCompleted");
    assert_eq!(event.session_id.as_deref(),
        Some("11111111-1111-1111-1111-111111111111"));
    assert_eq!(event.initiative_id.as_deref(),   Some("init-9"));
    assert_eq!(event.task_id.as_deref(),         Some("task-9"));

    let chain = read_audit_segment(&path);
    assert_eq!(chain.len(), 1, "exactly one event must hit the segment");
    let line = &chain[0];
    assert_eq!(line.event_kind, "IntegrationMergeCompleted");
    let payload = line.payload.as_object().expect("payload is a JSON object");
    assert_eq!(payload["operator_assisted"], serde_json::json!(true),
        "Step 30 attribution: operator_assisted MUST be true on the wire");
    assert_eq!(payload["escalation_id"],
        serde_json::Value::String(
            "22222222-2222-2222-2222-222222222222".to_owned()),
        "Step 30 attribution: escalation_id MUST link back to the \
         consumed MergeConflict row");
    assert_eq!(payload["commit_sha"],
        serde_json::Value::String(
            "deadbeefcafebabedeadbeefcafebabedeadbeef".to_owned()),
        "commit_sha is the SHA the operator authored — verifiable \
         against `git log --author` independently");
    assert_eq!(payload["previous_sha"],
        serde_json::Value::String(
            "f3d21a09f3d21a09f3d21a09f3d21a09f3d21a09".to_owned()));
    assert_eq!(line.prev_sha256, AuditWriter::GENESIS_PREV_SHA256,
        "first segment line points at the genesis prev hash");
}

/// A standard (non-operator-assisted) merge emits the same audit
/// variant with `operator_assisted: false`. Critically, the JSON
/// projection elides `escalation_id` (skip-on-None) so a legacy
/// audit reader that has not learned the Step 30 fields can still
/// decode the line.
#[test]
fn standard_merge_emits_attribution_event_without_escalation_link() {
    let dir          = TempDir::new().unwrap();
    let (sink, path) = fresh_audit_sink(&dir);

    let _ = sink.emit(
        AuditEventKind::IntegrationMergeCompleted {
            initiative_id:     "init-9".into(),
            session_id:        "sess-orch".into(),
            commit_sha:        "abc1234abc1234abc1234abc1234abc1234abc1".into(),
            previous_sha:      "f3d21a09f3d21a09f3d21a09f3d21a09f3d21a09".into(),
            operator_assisted: false,
            escalation_id:     None,
        },
        Some("sess-orch"),
        None,
        Some("init-9"),
    ).expect("emit");

    let chain = read_audit_segment(&path);
    let payload = chain[0].payload.as_object().unwrap();
    assert_eq!(payload["operator_assisted"], serde_json::json!(false));
    assert!(!payload.contains_key("escalation_id"),
        "escalation_id MUST be elided from JSON when None — legacy \
         audit segment readers depend on this forward-compat shape");
}

/// Chain integrity: when two merges land on the same initiative
/// (one operator-assisted, one not), the second event's
/// `prev_sha256` chains correctly to the first event's hash. This
/// is the standard audit-chain invariant; we exercise it on
/// `IntegrationMergeCompleted` specifically because Step 30 added
/// the variant.
#[test]
fn two_consecutive_merges_chain_through_prev_sha256() {
    let dir          = TempDir::new().unwrap();
    let (sink, path) = fresh_audit_sink(&dir);

    let _ = sink.emit(
        AuditEventKind::IntegrationMergeCompleted {
            initiative_id:     "init-c".into(),
            session_id:        "sess-orch".into(),
            commit_sha:        "1111111111111111111111111111111111111111".into(),
            previous_sha:      "0000000000000000000000000000000000000000".into(),
            operator_assisted: false,
            escalation_id:     None,
        },
        Some("sess-orch"), None, Some("init-c"),
    ).unwrap();

    let _ = sink.emit(
        AuditEventKind::IntegrationMergeCompleted {
            initiative_id:     "init-c".into(),
            session_id:        "sess-orch".into(),
            commit_sha:        "2222222222222222222222222222222222222222".into(),
            previous_sha:      "1111111111111111111111111111111111111111".into(),
            operator_assisted: true,
            escalation_id:     Some("esc-77".into()),
        },
        Some("sess-orch"), None, Some("init-c"),
    ).unwrap();

    let chain = read_audit_segment(&path);
    assert_eq!(chain.len(), 2, "two events expected on the segment");
    assert_eq!(chain[0].seq, 0);
    assert_eq!(chain[1].seq, 1);
    assert_eq!(chain[0].prev_sha256, AuditWriter::GENESIS_PREV_SHA256,
        "first event chains to genesis");
    let first_line_sha = sha256_of_line(&path, 0);
    assert_eq!(chain[1].prev_sha256, first_line_sha,
        "audit chain MUST link consecutive entries by SHA-256 of line bytes");

    let p0 = chain[0].payload.as_object().unwrap();
    let p1 = chain[1].payload.as_object().unwrap();
    assert_eq!(p0["operator_assisted"], serde_json::json!(false));
    assert_eq!(p1["operator_assisted"], serde_json::json!(true));
    assert!(!p0.contains_key("escalation_id"),
        "first event omits escalation_id (None — skip on serde)");
    assert_eq!(p1["escalation_id"], serde_json::json!("esc-77"));
}

/// V2 `v2_extended_gaps.md §1.2` — when the host-side fast-forward
/// of the operator-configured `target_ref` fails (Phase 2), the
/// kernel writes a `MergeFastForwardFailed` line to the audit chain
/// AND keeps writing the standard `IntegrationMergeCompleted` line
/// for Phase 1 (the SQLite intent commit succeeded). The two lines
/// chain through `prev_sha256` so an external auditor reconstructing
/// the timeline sees: Phase 1 done → Phase 2 alarm → operator
/// recovery follow-up.
///
/// Pinning the on-disk shape here protects the operator dashboard,
/// alert routing, and recovery runbooks — all of which pivot on the
/// `category` discriminator string.
#[test]
fn merge_fast_forward_failed_lands_on_audit_chain_with_category_discriminator() {
    let dir          = TempDir::new().unwrap();
    let (sink, path) = fresh_audit_sink(&dir);

    // First, the durable signal that Phase 2 failed.
    let ff_event: AuditEvent = sink.emit(
        AuditEventKind::MergeFastForwardFailed {
            initiative_id: "init-ff".into(),
            commit_sha:    "abc1234abc1234abc1234abc1234abc1234abc1".into(),
            target_ref:    "refs/heads/main".into(),
            category:      "target_ref_advanced_concurrently".into(),
            reason:        "ref txn rejected: expected aaa…, got bbb…".into(),
        },
        Some("sess-orch"),
        Some("task-merge"),
        Some("init-ff"),
    ).expect("emit MergeFastForwardFailed");

    assert_eq!(ff_event.event_kind, "MergeFastForwardFailed");

    // Second, the standard IntegrationMergeCompleted line for the
    // Phase-1 intent. The two MUST chain.
    let _ = sink.emit(
        AuditEventKind::IntegrationMergeCompleted {
            initiative_id:     "init-ff".into(),
            session_id:        "sess-orch".into(),
            commit_sha:        "abc1234abc1234abc1234abc1234abc1234abc1".into(),
            previous_sha:      "f3d21a09f3d21a09f3d21a09f3d21a09f3d21a09".into(),
            operator_assisted: false,
            escalation_id:     None,
        },
        Some("sess-orch"),
        Some("task-merge"),
        Some("init-ff"),
    ).expect("emit IntegrationMergeCompleted");

    let chain = read_audit_segment(&path);
    assert_eq!(chain.len(), 2,
        "Phase-2 failure + Phase-1 completion both land on the segment");

    assert_eq!(chain[0].event_kind, "MergeFastForwardFailed");
    let p0 = chain[0].payload.as_object().expect("payload object");
    assert_eq!(p0["initiative_id"], serde_json::json!("init-ff"));
    assert_eq!(p0["target_ref"],    serde_json::json!("refs/heads/main"));
    assert_eq!(
        p0["category"],
        serde_json::json!("target_ref_advanced_concurrently"),
        "category MUST land verbatim — dashboards and alert routing \
         pivot on this discriminator string",
    );
    assert!(p0["reason"].as_str().unwrap().contains("ref txn rejected"),
        "reason MUST round-trip the underlying gix error verbatim");

    assert_eq!(chain[1].event_kind, "IntegrationMergeCompleted");
    assert_eq!(chain[0].prev_sha256, AuditWriter::GENESIS_PREV_SHA256,
        "first event chains to genesis");
    let first_line_sha = sha256_of_line(&path, 0);
    assert_eq!(chain[1].prev_sha256, first_line_sha,
        "MergeFastForwardFailed → IntegrationMergeCompleted MUST chain");
}
