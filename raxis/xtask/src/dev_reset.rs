// xtask/src/dev_reset.rs — operator-side reset commands for dev/test data.
//
// Usage:
//   cargo xtask dev-reset notifications [--data-dir <PATH>] [--dry-run]
//
// What it does
// ────────────
//   * Opens `<data_dir>/kernel.db` read-write and runs
//     `DELETE FROM notifications` so the next kernel boot starts
//     with an empty inbox. Honours `--dry-run` to print the row
//     count without mutating anything.
//   * Removes `<data_dir>/notifications/inbox.jsonl` if it exists.
//   * Reports the counts so the operator can confirm the wipe.
//
// What it does NOT do
// ───────────────────
//   * **NEVER** touches the audit chain (`<data_dir>/audit/`).
//     The audit chain is the forensic record; the notifications
//     table is the operator-attention projection. Per
//     `INV-NOTIF-SCOPE-01`, the audit chain stays untouched even
//     when the projection is wiped.
//   * **NEVER** deletes the SQLite database file itself; only the
//     rows in `notifications`.
//
// Why this command exists
// ───────────────────────
// Phase 1 of `dashboard-hardening.md §2` shipped the
// `notification_priority` filter, which scopes the inbox to events
// that demand operator attention. Pre-filter SQLite rows from
// previous dev runs (operator mark-read, view-diff, view-file,
// chain-reverify, …) remain in the database and clutter the
// dashboard until cleared. This command is the dev-mode "Option A"
// reset path described in the worker brief.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};

/// Default data dir if the operator does not pass `--data-dir`.
/// Mirrors the kernel's `bootstrap::default_data_dir()` discipline:
/// `$XDG_DATA_HOME/raxis` on Linux, `~/Library/Application
/// Support/raxis` on macOS, falling back to `~/.raxis` for
/// portability.
fn default_data_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("RAXIS_DATA_DIR") {
        return Some(PathBuf::from(d));
    }
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    #[cfg(target_os = "macos")]
    {
        Some(home.join("Library/Application Support/raxis"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            return Some(PathBuf::from(xdg).join("raxis"));
        }
        Some(home.join(".local/share/raxis"))
    }
}

/// `cargo xtask dev-reset <subcommand>` entry point.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let mut iter = args.iter();
    let sub = iter.next().ok_or_else(|| {
        anyhow!(
            "missing dev-reset subcommand; available: notifications\n\
             usage: cargo xtask dev-reset notifications \
             [--data-dir <PATH>] [--dry-run]"
        )
    })?;
    let tail: Vec<String> = iter.cloned().collect();
    match sub.as_str() {
        "notifications" => run_notifications(&tail),
        other => bail!(
            "unknown dev-reset subcommand: {other:?}; available: notifications"
        ),
    }
}

/// `cargo xtask dev-reset notifications [--data-dir <PATH>] [--dry-run]`.
///
/// Truncates the `notifications` SQLite table and removes the
/// inbox JSONL file. Audit chain is untouched.
fn run_notifications(args: &[String]) -> anyhow::Result<()> {
    let mut data_dir: Option<PathBuf> = None;
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow!("--data-dir requires a path argument"))?;
                data_dir = Some(PathBuf::from(val));
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            other => bail!(
                "unknown flag for `dev-reset notifications`: {other:?}\n\
                 usage: cargo xtask dev-reset notifications \
                 [--data-dir <PATH>] [--dry-run]"
            ),
        }
    }

    let data_dir = data_dir
        .or_else(default_data_dir)
        .ok_or_else(|| anyhow!(
            "could not resolve a default data dir (no $HOME / $XDG_DATA_HOME); \
             pass --data-dir <PATH> explicitly"
        ))?;

    let db_path = data_dir.join("kernel.db");
    let inbox_path = data_dir.join("notifications").join("inbox.jsonl");

    println!(
        "{{\"event\":\"dev_reset_notifications_start\",\
         \"data_dir\":{:?},\"dry_run\":{dry_run}}}",
        data_dir.display().to_string(),
    );

    if !data_dir.exists() {
        bail!(
            "data dir does not exist: {} — pass --data-dir to a kernel \
             data directory",
            data_dir.display()
        );
    }

    let row_count = if db_path.exists() {
        truncate_notifications_table(&db_path, dry_run)
            .with_context(|| format!("truncating notifications table at {}",
                db_path.display()))?
    } else {
        eprintln!(
            "{{\"event\":\"dev_reset_notifications_db_absent\",\
             \"db_path\":{:?}}}",
            db_path.display().to_string(),
        );
        0
    };

    let inbox_removed = if inbox_path.exists() {
        if dry_run {
            true
        } else {
            std::fs::remove_file(&inbox_path).with_context(|| {
                format!("removing inbox.jsonl at {}", inbox_path.display())
            })?;
            true
        }
    } else {
        false
    };

    // INV-NOTIF-SCOPE-01: audit chain stays untouched. We surface
    // the audit-dir presence as a forensic-only log line so the
    // operator can confirm the chain is intact post-reset.
    let audit_dir = data_dir.join("audit");
    println!(
        "{{\"event\":\"dev_reset_notifications_done\",\
         \"rows_deleted\":{row_count},\
         \"inbox_jsonl_removed\":{inbox_removed},\
         \"audit_chain_untouched\":true,\
         \"audit_dir\":{:?},\
         \"audit_dir_present\":{}}}",
        audit_dir.display().to_string(),
        audit_dir.exists(),
    );

    if dry_run {
        println!(
            "(dry-run — no rows actually deleted, no files removed; \
             rerun without --dry-run to apply.)"
        );
    } else {
        println!(
            "Deleted {row_count} notification row(s); inbox.jsonl removed: {inbox_removed}. \
             Audit chain at {} is untouched.",
            audit_dir.display(),
        );
    }
    Ok(())
}

/// Open kernel.db, count current notifications rows, and
/// `DELETE FROM notifications` (unless `dry_run`). Returns the
/// number of rows that were (or would have been) removed.
fn truncate_notifications_table(db_path: &Path, dry_run: bool) -> anyhow::Result<u64> {
    // Open with the same flags the kernel uses for write access:
    // RW (no auto-create — the file MUST exist).
    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )
    .with_context(|| format!("opening sqlite at {}", db_path.display()))?;

    // The `notifications` table may be missing if the operator wiped
    // the DB but kept the data dir; treat that as "0 rows" rather
    // than a hard error.
    let table_exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='notifications'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !table_exists {
        eprintln!(
            "{{\"event\":\"dev_reset_notifications_table_absent\"}}",
        );
        return Ok(0);
    }

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM notifications", [], |r| r.get(0))
        .context("counting notifications rows")?;
    let count_u64 = count.max(0) as u64;

    if dry_run {
        return Ok(count_u64);
    }

    // Atomic — wraps the DELETE in BEGIN IMMEDIATE so a concurrent
    // kernel writer is held off (the rusqlite handle uses busy-
    // timeout-1s by default, which is plenty for a one-row table).
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let n = conn
        .execute("DELETE FROM notifications", [])
        .context("DELETE FROM notifications")?;
    conn.execute_batch("COMMIT")?;

    Ok(n as u64)
}

// ---------------------------------------------------------------------------
// Tests — happy path + audit-chain-untouched assertion.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use tempfile::TempDir;

    /// Build a synthetic data dir with a `notifications` SQLite
    /// table, three rows, an inbox.jsonl, and an audit/ dir
    /// containing a chain segment file. The reset MUST drop the
    /// SQLite rows and the inbox file but leave the audit segment
    /// file BYTE-IDENTICAL.
    fn synth_data_dir() -> (TempDir, PathBuf, PathBuf, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let db_path = data_dir.join("kernel.db");
        let inbox_dir = data_dir.join("notifications");
        let inbox_path = inbox_dir.join("inbox.jsonl");
        let audit_dir = data_dir.join("audit");
        let audit_segment = audit_dir.join("0000000000000001.jsonl");

        std::fs::create_dir_all(&inbox_dir).unwrap();
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::write(
            &inbox_path,
            "{\"notification_id\":\"n-1\",\"event_kind\":\"OperatorNotificationMarkedRead\"}\n",
        )
        .unwrap();
        std::fs::write(
            &audit_segment,
            "{\"seq\":1,\"event_kind\":\"OperatorNotificationMarkedRead\"}\n",
        )
        .unwrap();

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE notifications (\
                notification_id TEXT NOT NULL PRIMARY KEY,\
                event_kind      TEXT NOT NULL,\
                summary         TEXT NOT NULL,\
                payload_json    TEXT NOT NULL,\
                read            INTEGER NOT NULL DEFAULT 0,\
                source_event_id TEXT NOT NULL,\
                created_at      INTEGER NOT NULL\
            );",
        )
        .unwrap();
        for (id, kind) in [
            ("n-1", "OperatorNotificationMarkedRead"),
            ("n-2", "OperatorWorktreeAccessed"),
            ("n-3", "EscalationApproved"),
        ] {
            conn.execute(
                "INSERT INTO notifications \
                 (notification_id, event_kind, summary, payload_json, read, \
                  source_event_id, created_at) \
                 VALUES (?1, ?2, ?2, '{}', 0, 'evt', 0)",
                params![id, kind],
            )
            .unwrap();
        }
        (tmp, db_path, inbox_path, audit_segment)
    }

    #[test]
    fn run_notifications_truncates_table_and_removes_inbox() {
        let (tmp, db_path, inbox_path, audit_segment) = synth_data_dir();
        let audit_bytes_before = std::fs::read(&audit_segment).unwrap();

        let args = vec![
            "--data-dir".to_string(),
            tmp.path().to_string_lossy().into_owned(),
        ];
        run_notifications(&args).unwrap();

        // Notifications gone.
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notifications", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "all rows must be deleted");

        // Inbox file gone.
        assert!(
            !inbox_path.exists(),
            "inbox.jsonl must be removed; still found at {}",
            inbox_path.display()
        );

        // Audit chain BYTE-IDENTICAL — INV-NOTIF-SCOPE-01.
        let audit_bytes_after = std::fs::read(&audit_segment).unwrap();
        assert_eq!(
            audit_bytes_before, audit_bytes_after,
            "audit chain MUST be untouched by dev-reset notifications \
             (INV-NOTIF-SCOPE-01)"
        );
    }

    #[test]
    fn dry_run_leaves_state_unchanged() {
        let (tmp, db_path, inbox_path, _audit_segment) = synth_data_dir();
        let args = vec![
            "--data-dir".to_string(),
            tmp.path().to_string_lossy().into_owned(),
            "--dry-run".to_string(),
        ];
        run_notifications(&args).unwrap();

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notifications", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 3, "dry-run must NOT delete any rows");
        assert!(
            inbox_path.exists(),
            "dry-run must NOT remove inbox.jsonl"
        );
    }

    #[test]
    fn missing_data_dir_errors_clearly() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/raxis-this-data-dir-does-not-exist-xyzzy".into(),
        ];
        let err = run_notifications(&args).expect_err("must error");
        let msg = format!("{err:?}");
        assert!(msg.contains("data dir does not exist"), "got: {msg}");
    }

    #[test]
    fn audit_dir_only_is_a_no_op_apart_from_log_line() {
        // Operator runs reset against a data dir that has no
        // `kernel.db` and no `notifications/`. Should succeed with
        // 0 rows reported, audit chain dir is reported as
        // untouched.
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let audit_segment = audit_dir.join("0000000000000001.jsonl");
        std::fs::write(&audit_segment, "{\"seq\":1}\n").unwrap();
        let bytes_before = std::fs::read(&audit_segment).unwrap();

        let args = vec![
            "--data-dir".into(),
            tmp.path().to_string_lossy().into_owned(),
        ];
        run_notifications(&args).unwrap();

        let bytes_after = std::fs::read(&audit_segment).unwrap();
        assert_eq!(bytes_before, bytes_after);
    }
}
