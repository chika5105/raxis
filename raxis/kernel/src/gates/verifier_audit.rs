// raxis-kernel::gates::verifier_audit — iter62 D8 audit-emission
// helpers for the `VerifierVm*` event family.
//
// Why this module exists
// ──────────────────────
// `gates::verifier_runner::spawn_verifier` is the canonical seam
// where the kernel observes a verifier's lifecycle: spawn-time
// digest verification, child spawn / exit, witness admission,
// timeout, artefact rejection. Emitting the structured
// `AuditEventKind::Verifier*` events from a single helper module
// (rather than scattering `sink.emit(...)` calls across
// `spawn_verifier`, `handlers::witness`, and the watcher tokio
// task) keeps the lockstep between this surface and the variants
// added in `crates/audit/src/event.rs` honest.
//
// Trust contract
// ──────────────
// Each helper takes a `&dyn AuditSink` and an `AuditEventCommonFields`
// builder so the caller controls the per-event metadata (operator
// fingerprint, policy epoch, …) without this module duplicating
// the kernel's audit-record envelope shape. Errors are reported via
// `tracing::warn!`; we never panic on an audit-sink failure (the
// kernel's audit chain is already responsible for surfacing chain
// gaps and a panic here would surface as a verifier hang rather
// than a clean failure).
//
// Wiring discipline
// ─────────────────
// Each variant is emitted at exactly one call site:
//
//   * `emit_vm_spawned`     — at the bottom of `spawn_verifier`
//                             once the child handle is in flight
//                             (Step 5 in `spawn_verifier`'s
//                             numbered-step comment).
//   * `emit_vm_exited`      — inside the `tokio::spawn`-d watcher
//                             task in `spawn_verifier` (Step 5).
//   * `emit_witness_received` — at the top of
//                               `handlers::witness::handle` once
//                               admission succeeds (parent-owned;
//                               parent wires this in at merge time).
//   * `emit_image_digest_mismatch` — wherever the kernel-canonical
//                                    image-digest gate runs (the
//                                    spawn preflight; pulled into
//                                    `spawn_verifier` once the
//                                    canonical-images digest envs
//                                    are populated).
//   * `emit_timeout`        — inside the `tokio::spawn`-d watcher
//                             task's timeout arm.
//   * `emit_artifact_rejected` — at the witness-handler artefact
//                                admission gate (parent-owned).
//
// `INV-VERIFIER-AUDIT-PAIRED-WRITE-01` (D11) makes this contract
// normative: every `VerifierVmSpawned` MUST be paired with exactly
// one `VerifierVmExited` AND exactly one `VerifierWitnessReceived`
// (or the relevant short-circuit). The kernel's audit-chain
// invariant test (`crates/audit::tests::paired_writes`) keys off
// these helpers' emit-site count.

use raxis_audit_tools::{AuditEventKind, AuditSink};

/// Stable wire string for the `signal_class` field of
/// `VerifierVmExited`. Pinned by
/// `iter62_verifier_signal_class_strings_are_pinned`.
pub const SIGNAL_CLASS_EXIT: &str = "exit";
/// Verifier was killed by a Unix signal (no exit_code observable).
pub const SIGNAL_CLASS_SIGNAL: &str = "signal";
/// Verifier was killed because its kernel-side wall-clock fired.
pub const SIGNAL_CLASS_TIMEOUT: &str = "timeout";
/// Verifier was force-killed by the operator or kernel supervisor.
pub const SIGNAL_CLASS_KILLED: &str = "killed";

/// Stable wire strings for the `reason` field of
/// `VerifierArtifactRejected`.
pub const ARTIFACT_REJECT_SIZE_CAP: &str = "size_cap";
pub const ARTIFACT_REJECT_PATH_ESCAPE: &str = "path_escape";
pub const ARTIFACT_REJECT_SHA_MISMATCH: &str = "sha_mismatch";

/// Common envelope inputs every `Verifier*` audit event needs.
/// Bundled here so call sites construct one struct per event-pair
/// instead of threading 7 positional args through each helper.
#[derive(Debug, Clone)]
pub struct VerifierAuditContext {
    /// Stable per-VM identifier the kernel mints at spawn (UUIDv4).
    pub verifier_run_id: String,
    /// Task whose verifier this is.
    pub task_id: String,
    /// Owning initiative.
    pub initiative_id: String,
    /// Operator-visible image alias the kernel resolved at spawn.
    pub image_alias: String,
    /// Lowercase-hex SHA-256 of the spawned image (kernel-canonical
    /// digest).
    pub oci_digest: String,
    /// Verifier-supplied shell command line (or `<builtin>` for the
    /// kernel-canonical built-in pipeline; see
    /// `crates/verifier/src/lib.rs::VerifierBuiltin`).
    pub command: String,
    /// Operator-supplied disposition for the verifier's witness
    /// (`fail_initiative`, `warn_only`, `retry_task`).
    pub on_failure: String,
}

/// Emit `VerifierVmSpawned`. Call-site: `spawn_verifier` after the
/// child handle is in flight.
pub fn emit_vm_spawned(sink: &dyn AuditSink, ctx: &VerifierAuditContext) {
    let kind = AuditEventKind::VerifierVmSpawned {
        verifier_run_id: ctx.verifier_run_id.clone(),
        task_id: ctx.task_id.clone(),
        initiative_id: ctx.initiative_id.clone(),
        image_alias: ctx.image_alias.clone(),
        oci_digest: ctx.oci_digest.clone(),
        command: ctx.command.clone(),
        on_failure: ctx.on_failure.clone(),
    };
    record(sink, kind, Some(&ctx.task_id), Some(&ctx.initiative_id));
}

/// Emit `VerifierVmExited`. Call-site: `spawn_verifier`'s watcher
/// task on normal child wait completion.
///
/// `task_id` / `initiative_id` are the same correlation keys the
/// matching `VerifierVmSpawned` carried; threaded through here so
/// the audit-record envelope stays joinable (`task_id` is a
/// top-level column on the JSONL line, not just a payload field).
pub fn emit_vm_exited(
    sink: &dyn AuditSink,
    verifier_run_id: &str,
    signal_class: &str,
    exit_code: Option<i32>,
    wall_ms: u64,
    task_id: Option<&str>,
    initiative_id: Option<&str>,
) {
    let kind = AuditEventKind::VerifierVmExited {
        verifier_run_id: verifier_run_id.to_owned(),
        signal_class: signal_class.to_owned(),
        exit_code,
        wall_ms,
    };
    record(sink, kind, task_id, initiative_id);
}

/// Emit `VerifierWitnessReceived`. Call-site: parent-owned
/// `handlers::witness::handle` once the witness is admitted.
pub fn emit_witness_received(
    sink: &dyn AuditSink,
    verifier_run_id: &str,
    verdict: &str,
    artifact_sha256: Option<&str>,
    artifact_bytes: Option<u64>,
    task_id: Option<&str>,
    initiative_id: Option<&str>,
) {
    let kind = AuditEventKind::VerifierWitnessReceived {
        verifier_run_id: verifier_run_id.to_owned(),
        verdict: verdict.to_owned(),
        artifact_sha256: artifact_sha256.map(str::to_owned),
        artifact_bytes,
    };
    record(sink, kind, task_id, initiative_id);
}

/// Emit `VerifierImageDigestMismatch`. Call-site: spawn preflight,
/// when `verify_canonical_image_via_manifest` (or the V1 pin path)
/// surfaces `DigestMismatch` for one of the two iter62 verifier
/// images.
pub fn emit_image_digest_mismatch(
    sink: &dyn AuditSink,
    image_alias: &str,
    expected: &str,
    actual: &str,
    path: &str,
    task_id: Option<&str>,
    initiative_id: Option<&str>,
) {
    let kind = AuditEventKind::VerifierImageDigestMismatch {
        image_alias: image_alias.to_owned(),
        expected: expected.to_owned(),
        actual: actual.to_owned(),
        path: path.to_owned(),
    };
    record(sink, kind, task_id, initiative_id);
}

/// Emit `VerifierTimeout`. Call-site: `spawn_verifier`'s watcher
/// task on the timeout arm of the `tokio::select!`.
pub fn emit_timeout(
    sink: &dyn AuditSink,
    verifier_run_id: &str,
    timeout_seconds: u64,
    partial_stdout_bytes: u64,
    task_id: Option<&str>,
    initiative_id: Option<&str>,
) {
    let kind = AuditEventKind::VerifierTimeout {
        verifier_run_id: verifier_run_id.to_owned(),
        timeout_seconds,
        partial_stdout_bytes,
    };
    record(sink, kind, task_id, initiative_id);
}

/// Emit `VerifierArtifactRejected`. Call-site: parent-owned
/// `handlers::witness::handle` artefact admission gate (size cap,
/// path-escape, sha mismatch).
pub fn emit_artifact_rejected(
    sink: &dyn AuditSink,
    verifier_run_id: &str,
    reason: &str,
    task_id: Option<&str>,
    initiative_id: Option<&str>,
) {
    let kind = AuditEventKind::VerifierArtifactRejected {
        verifier_run_id: verifier_run_id.to_owned(),
        reason: reason.to_owned(),
    };
    record(sink, kind, task_id, initiative_id);
}

/// Internal: shared envelope wrap-and-emit. Logs sink failures via
/// stderr (the kernel's audit chain has its own gap-detection
/// invariants that surface at chain-replay time; a duplicated log
/// here would only add noise).
fn record(
    sink: &dyn AuditSink,
    kind: AuditEventKind,
    task_id: Option<&str>,
    initiative_id: Option<&str>,
) {
    if let Err(e) = sink.emit(kind, None, task_id, initiative_id) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"VerifierAuditEmitFailed\",\
             \"reason\":\"{e}\"}}",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::{AuditEvent, AuditWriterError};
    use std::sync::Mutex;
    use uuid::Uuid;

    /// Minimal test-only sink that captures every emitted event in
    /// memory. Tests assert against `kind.as_str()` to pin the wire
    /// string per `INV-VERIFIER-AUDIT-PAIRED-WRITE-01`. Uses the
    /// public `AuditSink` shape directly; production code paths use
    /// `raxis_test_support::FakeAuditSink` (dev-dep-only) for the
    /// same purpose.
    type CapturedEvent = (String, Option<String>, Option<String>);

    #[derive(Default)]
    struct CapturingSink {
        events: Mutex<Vec<CapturedEvent>>,
    }

    impl AuditSink for CapturingSink {
        fn emit(
            &self,
            kind: AuditEventKind,
            session_id: Option<&str>,
            task_id: Option<&str>,
            initiative_id: Option<&str>,
        ) -> Result<AuditEvent, AuditWriterError> {
            let event_kind = kind.as_str().to_owned();
            self.events.lock().unwrap().push((
                event_kind.clone(),
                task_id.map(str::to_owned),
                initiative_id.map(str::to_owned),
            ));
            // Return a synthetic AuditEvent — the test only cares
            // about the captured (kind, task_id, initiative_id) tuple.
            Ok(AuditEvent {
                seq: 0,
                event_id: Uuid::nil(),
                event_kind,
                session_id: session_id.map(str::to_owned),
                task_id: task_id.map(str::to_owned),
                initiative_id: initiative_id.map(str::to_owned),
                payload: serde_json::json!({}),
                emitted_at: 0,
                prev_sha256: "0".repeat(64),
            })
        }
    }

    fn fixture_ctx() -> VerifierAuditContext {
        VerifierAuditContext {
            verifier_run_id: "vrun-1".to_owned(),
            task_id: "task-7".to_owned(),
            initiative_id: "ini-3".to_owned(),
            image_alias: "raxis-verifier-symbol-index".to_owned(),
            oci_digest: "deadbeef".to_owned(),
            command: "<builtin>".to_owned(),
            on_failure: "warn_only".to_owned(),
        }
    }

    #[test]
    fn iter62_verifier_signal_class_strings_are_pinned() {
        // Pin the wire literals so the dashboard SSE consumer's
        // groupings stay stable.
        assert_eq!(SIGNAL_CLASS_EXIT, "exit");
        assert_eq!(SIGNAL_CLASS_SIGNAL, "signal");
        assert_eq!(SIGNAL_CLASS_TIMEOUT, "timeout");
        assert_eq!(SIGNAL_CLASS_KILLED, "killed");
    }

    #[test]
    fn iter62_verifier_artifact_reject_reason_strings_are_pinned() {
        assert_eq!(ARTIFACT_REJECT_SIZE_CAP, "size_cap");
        assert_eq!(ARTIFACT_REJECT_PATH_ESCAPE, "path_escape");
        assert_eq!(ARTIFACT_REJECT_SHA_MISMATCH, "sha_mismatch");
    }

    #[test]
    fn iter62_emit_vm_spawned_pushes_correctly_shaped_event() {
        let sink = CapturingSink::default();
        emit_vm_spawned(&sink, &fixture_ctx());
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1, "exactly one event per emit call");
        assert_eq!(events[0].0, "VerifierVmSpawned");
        assert_eq!(events[0].1.as_deref(), Some("task-7"));
        assert_eq!(events[0].2.as_deref(), Some("ini-3"));
    }

    #[test]
    fn iter62_emit_vm_exited_carries_correlation_keys() {
        let sink = CapturingSink::default();
        emit_vm_exited(
            &sink,
            "vrun-1",
            SIGNAL_CLASS_EXIT,
            Some(0),
            184,
            Some("task-7"),
            Some("ini-3"),
        );
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "VerifierVmExited");
        assert_eq!(events[0].1.as_deref(), Some("task-7"));
        assert_eq!(events[0].2.as_deref(), Some("ini-3"));
    }

    #[test]
    fn iter62_emit_witness_received_carries_optional_artifact_metadata() {
        let sink = CapturingSink::default();
        emit_witness_received(
            &sink,
            "vrun-1",
            "Pass",
            Some("cafebabe"),
            Some(2048),
            Some("task-7"),
            Some("ini-3"),
        );
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "VerifierWitnessReceived");
    }

    #[test]
    fn iter62_emit_image_digest_mismatch_routes_through_audit_kind() {
        let sink = CapturingSink::default();
        emit_image_digest_mismatch(
            &sink,
            "raxis-verifier-symbol-index",
            "abc",
            "def",
            "/var/lib/raxis/images/raxis-verifier-symbol-index-0.1.0.img",
            None,
            None,
        );
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "VerifierImageDigestMismatch");
    }

    #[test]
    fn iter62_emit_timeout_carries_partial_stdout_bytes() {
        let sink = CapturingSink::default();
        emit_timeout(&sink, "vrun-1", 30, 4096, Some("task-7"), Some("ini-3"));
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "VerifierTimeout");
    }

    #[test]
    fn iter62_emit_artifact_rejected_carries_stable_reason_string() {
        let sink = CapturingSink::default();
        emit_artifact_rejected(
            &sink,
            "vrun-1",
            ARTIFACT_REJECT_SIZE_CAP,
            Some("task-7"),
            Some("ini-3"),
        );
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "VerifierArtifactRejected");
    }

    /// `INV-VERIFIER-AUDIT-PAIRED-WRITE-01` (D11): a healthy
    /// verifier lifecycle emits exactly THREE events — Spawned,
    /// Exited, WitnessReceived. Pin the cardinality so a future
    /// emit-site doubling (e.g. retry-loop spawn) surfaces in this
    /// test rather than at audit-chain-replay time.
    #[test]
    fn iter62_paired_write_happy_path_emits_three_events() {
        let sink = CapturingSink::default();
        let ctx = fixture_ctx();
        emit_vm_spawned(&sink, &ctx);
        emit_vm_exited(
            &sink,
            &ctx.verifier_run_id,
            SIGNAL_CLASS_EXIT,
            Some(0),
            100,
            Some(&ctx.task_id),
            Some(&ctx.initiative_id),
        );
        emit_witness_received(
            &sink,
            &ctx.verifier_run_id,
            "Pass",
            None,
            None,
            Some(&ctx.task_id),
            Some(&ctx.initiative_id),
        );
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 3);
        let kinds: Vec<&str> = events.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "VerifierVmSpawned",
                "VerifierVmExited",
                "VerifierWitnessReceived",
            ]
        );
    }

    /// `INV-VERIFIER-AUDIT-PAIRED-WRITE-01` short-circuit case:
    /// timeout produces Spawned + Timeout (no Exit/Witness) — the
    /// witness short-circuit shape per the doc-comment.
    #[test]
    fn iter62_paired_write_timeout_short_circuit_emits_spawned_plus_timeout() {
        let sink = CapturingSink::default();
        let ctx = fixture_ctx();
        emit_vm_spawned(&sink, &ctx);
        emit_timeout(
            &sink,
            &ctx.verifier_run_id,
            30,
            1024,
            Some(&ctx.task_id),
            Some(&ctx.initiative_id),
        );
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, "VerifierVmSpawned");
        assert_eq!(events[1].0, "VerifierTimeout");
    }
}
