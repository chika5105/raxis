//! `raxis-cli::reveal` — the audit-writing helper for the read-only
//! CLI's `--reveal-paths` surface (and any future redaction-bypass
//! flag).
//!
//! # Why this is the only write the read-only CLI is allowed
//!
//! `cli-readonly.md` §5.7.3 pins the contract: the CLI is read-only
//! by design EXCEPT for the `PathReadAccessed` audit event, which is
//! itself the record of the read. Every other code path opens
//! `kernel.db` with `OpenFlags::SQLITE_OPEN_READ_ONLY` and never
//! touches the `<data_dir>/audit/` directory. This module is the one
//! place where the CLI appends to `segment-NNN.jsonl`, so the
//! invariant has exactly one enforcement site.
//!
//! # Audit-on-reveal contract
//!
//! [`reveal_path_fields`] must be the only entry point that returns
//! the unredacted [`PlanPathFields`] to the inspect renderer. It:
//!
//! 1. Looks the fields up via [`raxis_store::views::plan_fields::reveal_for_task`].
//! 2. Resolves the audit chain head (`last_chain_state`) so the
//!    appended record carries the correct `prev_sha256` and a fresh
//!    `seq`.
//! 3. Appends one `PathReadAccessed { actor, table, column, task_id,
//!    command }` event with the `task_id` foreign-key set so
//!    `raxis log --task <id>` surfaces every reveal.
//! 4. Returns the unredacted fields to the caller.
//!
//! Any failure between steps (1) and (4) — DB read, audit chain
//! resume, append — is surfaced as a `CliError`, never swallowed:
//! the CLI must NEVER reveal paths without leaving a trace.
//!
//! # Actor identity
//!
//! [`resolve_actor_identity`] derives the operator string used in
//! the audit event:
//!
//! - When `--operator-key` is supplied, we load the private key,
//!   compute the SHA-256[:16] fingerprint of its public half via
//!   [`raxis_policy::loader::operator_pubkey_fingerprint`], and use
//!   that 32-hex-char fingerprint. This matches the `signed_by`
//!   field in `policy.toml [meta]`, so an auditor can cross-reference
//!   reveal events with the operator entry that authorised them.
//! - Otherwise we fall back to `cli:<unix-user>` (best-effort, from
//!   `$USER` then `$LOGNAME`, defaulting to `cli:unknown`). The
//!   underlying audit chain hashes the line either way; the actor
//!   field is informational.

use std::path::PathBuf;

use raxis_audit_tools::{
    last_chain_state, AuditEventKind, AuditWriter, AUDIT_DIR_NAME,
};
use raxis_store::views::plan_fields::{reveal_for_task, PlanFieldsError, PlanPathFields};
use raxis_store::open_ro;

use crate::errors::CliError;
use crate::GlobalFlags;

/// Logical "table" name for the path-scope reveal — matches
/// cli-readonly.md §5.4.2 example wording.
pub const REVEAL_TABLE_NAME: &str = "task_plan_fields";

/// Logical "column" used when the reveal returns the entire path
/// bundle as a unit (rather than a single field). The spec leaves
/// the column granularity up to the implementation; the inspect
/// command reveals all four §2.5.8 fields together so we audit it
/// as one record per command invocation.
pub const REVEAL_COLUMN_ALL: &str = "all";

/// Resolve every §2.5.8 path-scope field for the given task AND
/// append exactly one `PathReadAccessed` audit record before
/// returning. See module docs for the full contract.
///
/// `command` is the short name of the CLI subcommand that triggered
/// the reveal — e.g. `"inspect"`. Stored verbatim in the audit
/// payload's `command` field so multiple reveal-capable commands can
/// be told apart by log readers.
pub fn reveal_path_fields(
    flags:   &GlobalFlags,
    task_id: &str,
    command: &str,
) -> Result<PlanPathFields, CliError> {
    // Step 1 — Look the data up. This MUST come before the audit
    // append: a `TaskNotFound` from the view layer means the
    // operator passed a nonexistent task_id and we should NOT
    // pollute the audit chain with a "reveal" of nothing.
    let conn = open_ro(flags.data_dir()).map_err(|e| {
        CliError::Policy(format!("kernel.db open failed: {e}"))
    })?;
    let fields = reveal_for_task(&conn, task_id).map_err(map_reveal_error)?;

    // Step 2 + 3 — Append the audit event. Failure here is fatal:
    // we MUST NOT return the fields if we couldn't record the read
    // (cli-readonly.md §5.7.2 — "audit-event-on-read is the
    // INV-08 enforcement mechanism").
    let actor = resolve_actor_identity(flags)?;
    append_path_read_accessed(flags, &actor, task_id, command)?;

    Ok(fields)
}

/// Append one `PathReadAccessed` event to `<data_dir>/audit/segment-000.jsonl`.
///
/// Resumes the chain from disk via `last_chain_state` so the new
/// record's `seq` and `prev_sha256` are continuous with whatever the
/// kernel last wrote. Public so future read-only commands that need
/// to audit other column reveals (e.g. `delegations.scope_json`) can
/// call it directly without going through the plan-fields path.
pub fn append_path_read_accessed(
    flags:   &GlobalFlags,
    actor:   &str,
    task_id: &str,
    command: &str,
) -> Result<(), CliError> {
    let segment_path = audit_segment_path(flags);

    let resume = last_chain_state(&segment_path).map_err(|e| {
        CliError::Policy(format!(
            "audit chain at {} could not be resumed for reveal: {e}",
            segment_path.display(),
        ))
    })?;
    let (next_seq, prev_sha) = match resume {
        Some(info) => (info.next_seq, Some(info.prev_sha256)),
        None       => (0, None),
    };

    let mut writer = AuditWriter::open(&segment_path, next_seq, prev_sha).map_err(|e| {
        CliError::Policy(format!(
            "audit segment {} could not be opened for append: {e}",
            segment_path.display(),
        ))
    })?;
    writer
        .append(
            AuditEventKind::PathReadAccessed {
                actor:   actor.to_owned(),
                table:   REVEAL_TABLE_NAME.to_owned(),
                column:  REVEAL_COLUMN_ALL.to_owned(),
                task_id: task_id.to_owned(),
                command: command.to_owned(),
            },
            None,           // session_id — CLI runs out-of-session
            Some(task_id),  // foreign key for `raxis log --task`
            None,           // initiative_id derivable from task_id via store query
        )
        .map_err(|e| {
            CliError::Policy(format!("audit append for PathReadAccessed failed: {e}"))
        })?;
    Ok(())
}

/// Translate a `PlanFieldsError` into a `CliError` with the same
/// shape `inspect.rs` already uses for view-layer failures (so the
/// error messages stay consistent across read-only commands).
fn map_reveal_error(e: PlanFieldsError) -> CliError {
    match e {
        PlanFieldsError::TaskNotFound { task_id } => CliError::KernelError {
            code:   "TASK_NOT_FOUND".to_owned(),
            detail: format!("no task with id {task_id:?}"),
        },
        PlanFieldsError::PlanArtifactMissing { task_id, initiative_id } => {
            CliError::Policy(format!(
                "task {task_id:?} (initiative {initiative_id:?}) has no signed plan artifact \
                 in kernel.db; cannot reveal paths"
            ))
        }
        PlanFieldsError::PlanInvalid { initiative_id, reason } => {
            CliError::Policy(format!(
                "plan TOML for initiative {initiative_id:?} is unparseable: {reason}"
            ))
        }
        PlanFieldsError::TaskNotInPlan { initiative_id, task_id } => {
            CliError::Policy(format!(
                "plan for initiative {initiative_id:?} has no [[tasks]] entry for \
                 task_id={task_id:?} — kernel may have admitted a task outside the signed plan"
            ))
        }
        PlanFieldsError::Sqlite(e) => CliError::Policy(format!("plan_fields sqlite error: {e}")),
    }
}

/// `<data_dir>/audit/segment-000.jsonl`. Co-located with the
/// constant `AUDIT_DIR_NAME` from `raxis-audit-tools` so a future
/// rename in the kernel writer reaches both.
fn audit_segment_path(flags: &GlobalFlags) -> PathBuf {
    flags.data_dir().join(AUDIT_DIR_NAME).join("segment-000.jsonl")
}

/// Build the `actor` string for the `PathReadAccessed` payload. See
/// the module-level "Actor identity" comment for the rationale.
pub fn resolve_actor_identity(flags: &GlobalFlags) -> Result<String, CliError> {
    if let Some(key_path) = flags.operator_key_path.as_ref() {
        let sk = crate::signing::load_operator_key(key_path)?;
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let fp = raxis_policy::loader::operator_pubkey_fingerprint(&pk_hex)
            .map_err(|e| CliError::Policy(format!("operator fingerprint compute failed: {e}")))?;
        return Ok(fp);
    }
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_owned());
    Ok(format!("cli:{user}"))
}

// ────────────────────────────────────────────────────────────────────
// Tests — pin the audit-on-reveal invariant end-to-end. The CLI's
// outer `inspect.rs` test suite covers the rendering layer; these
// tests cover (a) the audit append happens, (b) the chain stays
// intact across reveal calls, (c) the actor string flows through.
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::{verify_chain_full, ChainReader};
    use raxis_store::Store;
    use std::fs;
    use tempfile::TempDir;

    /// Build a kernel.db with one initiative + task + a signed plan
    /// artifact, AND a fresh audit segment seeded with one
    /// kernel-style record so we exercise the chain-resume path.
    /// Returns the tempdir + the (init, task) ids.
    fn fresh_data_dir_with_plan(plan_toml: &str) -> (TempDir, String, String) {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        // kernel.db
        let db = data_dir.join("kernel.db");
        let initiative_id = "init-1".to_owned();
        let task_id       = "t-1".to_owned();
        {
            let store = Store::open(&db).unwrap();
            let guard = store.lock_sync();
            guard.execute(
                "INSERT INTO initiatives \
                 (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                 VALUES (?1, 'Executing', '{}', 'sha-1', 1)",
                rusqlite::params![&initiative_id],
            ).unwrap();
            guard.execute(
                "INSERT INTO tasks \
                 (task_id, initiative_id, lane_id, state, actor, \
                  policy_epoch, admitted_at, transitioned_at) \
                 VALUES (?1, ?2, 'default', 'Running', 'op', 1, 1, 1)",
                rusqlite::params![&task_id, &initiative_id],
            ).unwrap();
            guard.execute(
                "INSERT INTO signed_plan_artifacts \
                 (initiative_id, plan_bytes, plan_sig, stored_at) \
                 VALUES (?1, ?2, x'00', 1)",
                rusqlite::params![&initiative_id, plan_toml.as_bytes()],
            ).unwrap();
        }
        // audit/segment-000.jsonl with one seed record so the
        // resume path is exercised (not just the genesis-from-empty
        // branch).
        let audit_dir = data_dir.join(AUDIT_DIR_NAME);
        fs::create_dir_all(&audit_dir).unwrap();
        let seg = audit_dir.join("segment-000.jsonl");
        let mut seed = AuditWriter::open(&seg, 0, None).unwrap();
        seed.append(
            AuditEventKind::KernelStarted {
                data_dir:       data_dir.display().to_string(),
                policy_epoch:   1,
                schema_version: 1,
            },
            None, None, None,
        ).unwrap();
        drop(seed);
        (tmp, initiative_id, task_id)
    }

    fn flags_for(data_dir: &std::path::Path) -> GlobalFlags {
        GlobalFlags {
            data_dir:          data_dir.to_path_buf(),
            socket_path:       None,
            operator_key_path: None,
        }
    }

    #[test]
    fn reveal_returns_path_fields_and_appends_one_audit_event() {
        let plan = r#"
            [[tasks]]
            task_id        = "t-1"
            path_allowlist = ["src/**", "README.md"]
        "#;
        let (tmp, _init, task) = fresh_data_dir_with_plan(plan);
        let flags = flags_for(tmp.path());

        let fields = reveal_path_fields(&flags, &task, "inspect").unwrap();
        assert_eq!(fields.path_allowlist, vec!["src/**", "README.md"]);

        // Audit chain now has 2 records: KernelStarted + PathReadAccessed.
        let stats = verify_chain_full(&tmp.path().join(AUDIT_DIR_NAME))
            .expect("chain must be intact after reveal");
        assert_eq!(stats.total_records, 2);
        assert_eq!(stats.last_seq, 1);

        // Inspect the appended record's projection: kind, task_id,
        // payload fields. Pin the wire shape so log readers don't
        // accidentally drift on field names.
        let recs: Vec<_> = ChainReader::open(&tmp.path().join(AUDIT_DIR_NAME))
            .unwrap()
            .records()
            .collect::<Result<_, _>>()
            .unwrap();
        let last = recs.last().unwrap();
        assert_eq!(last.event_kind, "PathReadAccessed");
        assert_eq!(last.task_id.as_deref(), Some("t-1"));
        let payload = last.parsed_value.as_ref().unwrap().get("payload").unwrap();
        assert_eq!(payload["kind"],    serde_json::json!("PathReadAccessed"));
        assert_eq!(payload["table"],   serde_json::json!("task_plan_fields"));
        assert_eq!(payload["column"],  serde_json::json!("all"));
        assert_eq!(payload["command"], serde_json::json!("inspect"));
        assert_eq!(payload["task_id"], serde_json::json!("t-1"));
        let actor = payload["actor"].as_str().unwrap();
        assert!(
            actor.starts_with("cli:"),
            "no --operator-key given → actor must fall back to cli:<user>; got {actor:?}"
        );
    }

    #[test]
    fn reveal_does_not_append_when_task_not_found() {
        // Step 1 of `reveal_path_fields` MUST fail BEFORE step 2;
        // a missing task is operator error, not a real read, so it
        // must not pollute the audit chain.
        let plan = "[[tasks]]\ntask_id = \"t-1\"\n";
        let (tmp, _init, _task) = fresh_data_dir_with_plan(plan);
        let flags = flags_for(tmp.path());

        let err = reveal_path_fields(&flags, "ghost-task", "inspect").unwrap_err();
        match err {
            CliError::KernelError { code, .. } => assert_eq!(code, "TASK_NOT_FOUND"),
            other => panic!("expected TASK_NOT_FOUND; got {other:?}"),
        }

        let stats = verify_chain_full(&tmp.path().join(AUDIT_DIR_NAME)).unwrap();
        // Still just the seed KernelStarted; reveal must not have
        // appended a record for a nonexistent task.
        assert_eq!(stats.total_records, 1);
    }

    #[test]
    fn reveal_chains_correctly_across_repeated_calls() {
        // Two consecutive reveals must produce two consecutive
        // audit records with intact prev_sha256 linkage. This pins
        // that the chain-resume helper inside `append_path_read_accessed`
        // re-reads the LAST line each time rather than re-anchoring
        // to the seed record.
        let plan = r#"
            [[tasks]]
            task_id        = "t-1"
            path_allowlist = ["src/**"]
        "#;
        let (tmp, _init, task) = fresh_data_dir_with_plan(plan);
        let flags = flags_for(tmp.path());

        for _ in 0..3 {
            let _ = reveal_path_fields(&flags, &task, "inspect").unwrap();
        }

        let stats = verify_chain_full(&tmp.path().join(AUDIT_DIR_NAME)).unwrap();
        // 1 seed + 3 reveals = 4 records, last_seq = 3.
        assert_eq!(stats.total_records, 4);
        assert_eq!(stats.last_seq, 3);
    }

    #[test]
    fn resolve_actor_identity_returns_cli_user_when_no_key_supplied() {
        let tmp   = TempDir::new().unwrap();
        let flags = flags_for(tmp.path());
        let actor = resolve_actor_identity(&flags).unwrap();
        assert!(
            actor.starts_with("cli:"),
            "actor without --operator-key must be cli:<user>; got {actor:?}"
        );
    }
}
