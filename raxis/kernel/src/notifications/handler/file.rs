// raxis-kernel::notifications::handler::file — Shell + File channel handler.
//
// Normative reference: cli-readonly.md §5.6.4 (Shell), §5.6.5 (File).
//
// Both channel kinds are operationally identical:
//   - Resolve `target` to an absolute path. For `Shell` channels with
//     an empty target (the synthesised implicit channel), resolve to
//     `<data_dir>/notifications/inbox.jsonl`.
//   - `O_APPEND | O_CREAT`, mode 0644.
//   - Write one JSON line:
//       { notified_at, event_kind, event_seq, payload, human_summary }
//   - `fsync` (best-effort).
//
// Failure mapping → `DeliveryError`:
//   - I/O error opening or writing the target → `Io(e)`
//   - empty target on a `File` channel → `TargetInvalid`
//     (validate already rejects this, but defence-in-depth at runtime)

use std::path::{Path, PathBuf};

use raxis_audit_tools::AuditEvent;
use raxis_policy::{NotificationChannel, NotificationChannelKind, PolicyBundle};
use serde::Serialize;
use tokio::io::AsyncWriteExt;

use super::super::{summary, DeliveryError};

/// One JSONL line written by the Shell / File handler. The shape is
/// pinned by `cli-readonly.md` §5.6.4 — bumping any field here is a
/// wire-break for `raxis inbox` (read by tests in this file).
#[derive(Debug, Serialize)]
struct ShellRecord<'a> {
    notified_at:   i64,
    event_kind:    &'a str,
    event_seq:     u64,
    payload:       &'a serde_json::Value,
    human_summary: String,
}

/// Append one notification record to `channel.target` (resolved
/// against `data_dir` for the implicit Shell channel). On disk
/// failure, returns `DeliveryError::Io(_)` for the dispatcher to
/// translate into `NotificationDeliveryFailed { reason: "io" }`.
pub async fn deliver(
    channel:  &NotificationChannel,
    event:    &AuditEvent,
    data_dir: &Path,
) -> Result<(), DeliveryError> {
    let target = resolve_target(channel, data_dir)?;

    // Ensure the parent directory exists. The implicit Shell channel
    // points at <data_dir>/notifications/ which the kernel creates at
    // bootstrap; operator-supplied File channels may point anywhere
    // and we are deliberately conservative — the operator is
    // responsible for the parent directory existing AND being
    // writable. We `create_dir_all` only for the implicit Shell
    // channel because spec §5.6.4 documents that the kernel owns
    // <data_dir>/notifications/.
    if matches!(channel.kind, NotificationChannelKind::Shell) {
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(DeliveryError::Io)?;
        }
    }

    let record = ShellRecord {
        notified_at:   raxis_types::unix_now_secs() as i64,
        event_kind:    &event.event_kind,
        event_seq:     event.seq,
        payload:       &event.payload,
        human_summary: summary::render(event),
    };
    let mut line = serde_json::to_vec(&record).map_err(|e| {
        // serde_json on a serializable input fails only on a writer
        // I/O error; surface as Io for consistency.
        DeliveryError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
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
        // `tokio::fs::OpenOptions::mode` is a direct method on
        // unix targets — no `OpenOptionsExt` import required.
        opts.mode(0o644);
    }
    let mut file = opts.open(&target).await.map_err(DeliveryError::Io)?;

    file.write_all(&line).await.map_err(DeliveryError::Io)?;
    // fsync is best-effort per spec §5.6.4 — failure already produces
    // an Io error from the OS, so we don't separately classify "wrote
    // but didn't sync".
    let _ = file.sync_data().await;
    Ok(())
}

/// Resolve `channel.target` to an absolute path. The implicit Shell
/// channel's empty target resolves to
/// `<data_dir>/notifications/inbox.jsonl` (cli-readonly.md §5.6.4).
/// File channels with empty targets are rejected at validate time but
/// double-checked here.
fn resolve_target(channel: &NotificationChannel, data_dir: &Path) -> Result<PathBuf, DeliveryError> {
    match channel.kind {
        NotificationChannelKind::Shell => {
            if channel.target.is_empty() {
                Ok(PolicyBundle::shell_inbox_path_for(data_dir))
            } else {
                Ok(PathBuf::from(&channel.target))
            }
        }
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

    fn implicit_shell() -> NotificationChannel {
        NotificationChannel {
            id: "shell".into(),
            kind: NotificationChannelKind::Shell,
            target: String::new(),
        }
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

    // ── Implicit Shell channel writes to canonical inbox path ─────────

    #[tokio::test]
    async fn implicit_shell_writes_to_canonical_inbox_path() {
        let tmp = tempfile::tempdir().unwrap();
        let event = make_event("EscalationApproved", 7, json!({
            "escalation_id": "esc-7",
            "approved_by":   "op",
        }));

        deliver(&implicit_shell(), &event, tmp.path())
            .await
            .expect("write must succeed");

        let inbox = PolicyBundle::shell_inbox_path_for(tmp.path());
        let records = read_jsonl(&inbox);
        assert_eq!(records.len(), 1, "exactly one line written; got {records:?}");
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
        for i in 0..3u64 {
            let e = make_event("EscalationSubmitted", i, json!({
                "escalation_id": format!("esc-{i}"),
                "task_id":       "t",
                "class":         "CapabilityUpgrade",
                "lineage_id":    "lin",
            }));
            deliver(&implicit_shell(), &e, tmp.path()).await.unwrap();
        }
        let records = read_jsonl(&PolicyBundle::shell_inbox_path_for(tmp.path()));
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["event_seq"], 0);
        assert_eq!(records[1]["event_seq"], 1);
        assert_eq!(records[2]["event_seq"], 2);
    }

    // ── Explicit Shell target overrides the implicit path ─────────────

    #[tokio::test]
    async fn explicit_shell_target_writes_to_supplied_path() {
        let tmp = tempfile::tempdir().unwrap();
        let custom = tmp.path().join("custom.jsonl");
        let chan = NotificationChannel {
            id: "shell".into(),
            kind: NotificationChannelKind::Shell,
            target: custom.to_string_lossy().into_owned(),
        };
        let e = make_event("EscalationApproved", 1, json!({
            "escalation_id": "esc-x",
            "approved_by":   "op",
        }));
        deliver(&chan, &e, tmp.path()).await.unwrap();

        let records = read_jsonl(&custom);
        assert_eq!(records.len(), 1);
        assert!(!PolicyBundle::shell_inbox_path_for(tmp.path()).exists(),
            "implicit-target file MUST NOT have been written");
    }

    // ── File channel honours its target ────────────────────────────────

    #[tokio::test]
    async fn file_channel_writes_to_target() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("audit.jsonl");
        let chan = NotificationChannel {
            id: "audit-mirror".into(),
            kind: NotificationChannelKind::File,
            target: p.to_string_lossy().into_owned(),
        };
        let e = make_event("EscalationDenied", 1, json!({
            "escalation_id": "esc-d",
            "denied_by":     "op",
            "reason":        "scope mismatch",
        }));
        deliver(&chan, &e, tmp.path()).await.unwrap();

        let records = read_jsonl(&p);
        assert_eq!(records.len(), 1);
        assert!(records[0]["human_summary"].as_str().unwrap().contains("scope mismatch"));
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
        };
        let e = make_event("KernelStarted", 1, json!({}));
        let result = deliver(&chan, &e, std::path::Path::new("/tmp")).await;
        assert!(matches!(result, Err(DeliveryError::TargetInvalid)));
    }

    // ── I/O failure on unwritable target maps to Io ──────────────────

    #[tokio::test]
    async fn io_error_on_unwritable_target_maps_to_io_variant() {
        // Point at a path whose parent doesn't exist AND is on a kind
        // that doesn't auto-create-parents (File). Open MUST fail
        // and surface Io.
        let chan = NotificationChannel {
            id: "broken".into(),
            kind: NotificationChannelKind::File,
            target: "/nonexistent/dir/that/does/not/exist/x.jsonl".into(),
        };
        let e = make_event("KernelStarted", 1, json!({}));
        let result = deliver(&chan, &e, std::path::Path::new("/tmp")).await;
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
        assert_eq!(DeliveryError::UnimplementedV1.category(), "unimplemented_v1");
    }

    // ── Record shape contract pin ────────────────────────────────────

    #[tokio::test]
    async fn record_shape_carries_required_fields() {
        // Pin the JSONL field set so any rename here is caught by a
        // failing test rather than silently breaking `raxis inbox`.
        let tmp = tempfile::tempdir().unwrap();
        let e = make_event("PolicyEpochAdvanced", 99, json!({
            "new_epoch_id":             5,
            "policy_sha256":            "a".repeat(64),
            "triggered_by":             "op",
            "delegations_marked_stale": 0,
            "sessions_invalidated":     0,
        }));
        deliver(&implicit_shell(), &e, tmp.path()).await.unwrap();
        let r = &read_jsonl(&PolicyBundle::shell_inbox_path_for(tmp.path()))[0];
        for required in &["notified_at", "event_kind", "event_seq", "payload", "human_summary"] {
            assert!(r.get(required).is_some(),
                "JSONL record MUST carry `{required}` per cli-readonly.md §5.6.4; got: {r}");
        }
    }
}
