// raxis-kernel::notifications::handler::file — File channel handler.
//
// Normative reference: cli-readonly.md §5.6.5 (File).
//
// Appends a JSON line to the operator-supplied `target` path:
//   - `O_APPEND | O_CREAT`, mode 0644.
//   - Write one JSON line:
//       { notified_at, event_kind, event_seq, payload, human_summary }
//   - `fsync` (best-effort).
//
// Failure mapping → `DeliveryError`:
//   - I/O error opening or writing the target → `Io(e)`
//   - empty target → `TargetInvalid`
//     (validate already rejects this, but defence-in-depth at runtime)

use std::path::PathBuf;

use raxis_audit_tools::AuditEvent;
use raxis_policy::{NotificationChannel, NotificationChannelKind};
use serde::Serialize;
use tokio::io::AsyncWriteExt;

use super::super::{summary, DeliveryError};

/// One JSONL line written by the File handler.
#[derive(Debug, Serialize)]
struct FileRecord<'a> {
    notified_at: i64,
    event_kind: &'a str,
    event_seq: u64,
    payload: &'a serde_json::Value,
    human_summary: String,
}

/// Append one notification record to `channel.target`. On disk
/// failure, returns `DeliveryError::Io(_)` for the dispatcher to
/// translate into `NotificationDeliveryFailed { reason: "io" }`.
pub async fn deliver(
    channel: &NotificationChannel,
    event: &AuditEvent,
) -> Result<(), DeliveryError> {
    let target = resolve_target(channel)?;

    let record = FileRecord {
        notified_at: raxis_types::unix_now_secs(),
        event_kind: &event.event_kind,
        event_seq: event.seq,
        payload: &event.payload,
        human_summary: summary::render(event),
    };
    let mut line = serde_json::to_vec(&record).map_err(|e| {
        // serde_json on a serializable input fails only on a writer
        // I/O error; surface as Io for consistency.
        DeliveryError::Io(std::io::Error::other(e))
    })?;
    line.push(b'\n');

    // O_APPEND | O_CREAT, mode 0644 (unix only — on non-unix the bit
    // is ignored). `OpenOptions::append(true)` does not require any
    // mode bit; we set the umask-compliant mode by passing it to the
    // platform-specific `mode()` extension (gated behind `#[cfg(unix)]`).
    let mut opts = tokio::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        opts.mode(0o644);
    }
    let mut file = opts.open(&target).await.map_err(DeliveryError::Io)?;

    file.write_all(&line).await.map_err(DeliveryError::Io)?;
    // fsync is best-effort — failure already produces an Io error
    // from the OS.
    let _ = file.sync_data().await;
    Ok(())
}

/// Resolve `channel.target` to an absolute path. File channels with
/// empty targets are rejected at validate time but double-checked here.
fn resolve_target(channel: &NotificationChannel) -> Result<PathBuf, DeliveryError> {
    match channel.kind {
        NotificationChannelKind::File => {
            if channel.target.is_empty() {
                Err(DeliveryError::TargetInvalid)
            } else {
                Ok(PathBuf::from(&channel.target))
            }
        }
        _ => Err(DeliveryError::TargetInvalid),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::AuditEvent;
    use raxis_policy::NotificationChannel;
    use serde_json::json;
    use std::path::Path;
    use uuid::Uuid;

    fn make_event(kind: &str, seq: u64, payload: serde_json::Value) -> AuditEvent {
        AuditEvent {
            seq,
            event_id: Uuid::new_v4(),
            event_kind: kind.to_owned(),
            session_id: None,
            task_id: None,
            initiative_id: None,
            payload,
            emitted_at: 1_700_000_000,
            prev_sha256: "0".repeat(64),
        }
    }

    fn make_file_channel(tmp: &tempfile::TempDir, name: &str) -> (NotificationChannel, PathBuf) {
        let p = tmp.path().join(name);
        let ch = NotificationChannel {
            id: "audit-mirror".into(),
            kind: NotificationChannelKind::File,
            target: p.to_string_lossy().into_owned(),
            max_in_flight: 8,
        };
        (ch, p)
    }

    /// Read the JSONL file at `path` into a Vec<JSON> for assertions.
    fn read_jsonl(path: &Path) -> Vec<serde_json::Value> {
        let bytes = std::fs::read(path).unwrap_or_default();
        std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    // ── File channel writes to supplied target ────────────────────────

    #[tokio::test]
    async fn file_channel_writes_to_target() {
        let tmp = tempfile::tempdir().unwrap();
        let (chan, p) = make_file_channel(&tmp, "audit.jsonl");
        let event = make_event(
            "EscalationApproved",
            7,
            json!({
                "escalation_id": "esc-7",
                "approved_by":   "op",
            }),
        );

        deliver(&chan, &event).await.expect("write must succeed");

        let records = read_jsonl(&p);
        assert_eq!(
            records.len(),
            1,
            "exactly one line written; got {records:?}"
        );
        let r = &records[0];
        assert_eq!(r["event_kind"], "EscalationApproved");
        assert_eq!(r["event_seq"], 7);
        assert_eq!(r["payload"]["escalation_id"], "esc-7");
        assert!(r["human_summary"].as_str().unwrap().contains("APPROVED"));
        assert!(r["notified_at"].is_i64());
    }

    // ── Multiple events append in order ───────────────────────────────

    #[tokio::test]
    async fn multiple_events_append_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let (chan, p) = make_file_channel(&tmp, "seq.jsonl");
        for i in 0..3u64 {
            let e = make_event(
                "EscalationSubmitted",
                i,
                json!({
                    "escalation_id": format!("esc-{i}"),
                    "task_id":       "t",
                    "class":         "CapabilityUpgrade",
                    "lineage_id":    "lin",
                }),
            );
            deliver(&chan, &e).await.unwrap();
        }
        let records = read_jsonl(&p);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["event_seq"], 0);
        assert_eq!(records[1]["event_seq"], 1);
        assert_eq!(records[2]["event_seq"], 2);
    }

    // ── File channel with empty target fails at runtime ──────────────

    #[tokio::test]
    async fn file_channel_with_empty_target_returns_target_invalid() {
        // Validate already rejects this; the runtime double-check
        // protects against test fixtures or hand-built bundles.
        let chan = NotificationChannel {
            id: "broken".into(),
            kind: NotificationChannelKind::File,
            target: String::new(),
            max_in_flight: 8,
        };
        let e = make_event("KernelStarted", 1, json!({}));
        let result = deliver(&chan, &e).await;
        assert!(matches!(result, Err(DeliveryError::TargetInvalid)));
    }

    // ── I/O failure on unwritable target maps to Io ──────────────────

    #[tokio::test]
    async fn io_error_on_unwritable_target_maps_to_io_variant() {
        let chan = NotificationChannel {
            id: "broken".into(),
            kind: NotificationChannelKind::File,
            target: "/nonexistent/dir/that/does/not/exist/x.jsonl".into(),
            max_in_flight: 8,
        };
        let e = make_event("KernelStarted", 1, json!({}));
        let result = deliver(&chan, &e).await;
        match result {
            Err(DeliveryError::Io(_)) => {}
            other => panic!("expected Io, got {other:?}"),
        }
    }

    // ── DeliveryError::category is stable wire ───────────────────────

    #[test]
    fn delivery_error_category_strings_are_stable() {
        assert_eq!(
            DeliveryError::Io(std::io::Error::other("x")).category(),
            "io",
        );
        assert_eq!(DeliveryError::TargetInvalid.category(), "target_invalid");
        assert_eq!(DeliveryError::Network("x".into()).category(), "network");
        assert_eq!(
            DeliveryError::UpstreamRejected("x".into()).category(),
            "upstream_rejected",
        );
        assert_eq!(
            DeliveryError::CredentialUnavailable("x".into()).category(),
            "credential_unavailable",
        );
    }

    // ── Record shape contract pin ────────────────────────────────────

    #[tokio::test]
    async fn record_shape_carries_required_fields() {
        // Pin the JSONL field set so any rename here is caught by a
        // failing test rather than silently breaking `raxis inbox`.
        let tmp = tempfile::tempdir().unwrap();
        let (chan, p) = make_file_channel(&tmp, "shape.jsonl");
        let e = make_event(
            "PolicyEpochAdvanced",
            99,
            json!({
                "new_epoch_id":             5,
                "policy_sha256":            "a".repeat(64),
                "triggered_by":             "op",
                "delegations_marked_stale": 0,
                "sessions_invalidated":     0,
            }),
        );
        deliver(&chan, &e).await.unwrap();
        let r = &read_jsonl(&p)[0];
        for required in &[
            "notified_at",
            "event_kind",
            "event_seq",
            "payload",
            "human_summary",
        ] {
            assert!(
                r.get(required).is_some(),
                "JSONL record MUST carry `{required}`; got: {r}"
            );
        }
    }
}
