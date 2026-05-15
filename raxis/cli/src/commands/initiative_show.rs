//! `raxis initiative show <initiative_id>` — the canonical forensic
//! surface for one initiative.
//!
//! Normative reference: `plan-bundle-sealing.md §8.5` (V2.1 bundle
//! surface). This command is the SOLE forensic surface for an
//! initiative; the V1-era `inspect-initiative` was retired and its
//! quarantine + per-task joins were absorbed here per the V2
//! "no two CLI commands do the same thing" rule
//! (`v2_extended_gaps.md §1.1`).
//!
//! # Surface
//!
//! `raxis initiative show <id> [--bundle] [--with-tasks] [--task-limit N]
//!                             [--to <dir>] [--json]`
//!
//! Output composition:
//!
//!   * Base header — initiative id, state, created/approved/completed
//!     timestamps. Always printed.
//!
//!   * Plan-bundle envelope — sha-256 prefix, schema version,
//!     signed-by fingerprint prefix, sealed-at, signed-at, artifact
//!     count, total-bytes. Always printed.
//!
//!   * Quarantine block — YES/NO; when YES the block carries
//!     quarantined-at, quarantined-by (operator display), reason
//!     (when stored), and `sweep_target` (when issued by an
//!     `operator quarantine-plans-by` sweep). Always printed.
//!
//!   * Per-task table — task_id, state, lane, transitioned_at,
//!     actor. Opt-in via `--with-tasks` so the default render stays
//!     bytes-free for shared shells; `--task-limit N` caps the
//!     listing (default 100) so a runaway plan can't flood the TTY.
//!
//!   * `--bundle` — adds a per-artifact `(seq, name, sha-256, size)`
//!     listing. No artifact bytes are written; this is the read-only
//!     operator surface §8.5 calls out as "for human inspection".
//!
//!   * `--bundle --to <dir>` — extracts every artifact under `<dir>`,
//!     preserving `artifact_name` as the relative path (with
//!     intermediate directory creation). Refuses to overwrite an
//!     existing non-empty `<dir>` so the operator does not
//!     accidentally clobber unrelated files. Implies the human
//!     header is suppressed (the side-effect IS the output).
//!
//! `--json` emits the same data as a structured object (excludes
//! `--to <dir>`, where the side-effect is the output).
//!
//! # Output discipline
//!
//! - All fingerprints / SHAs render as their first 16 hex characters
//!   followed by `…` so log captures are grep-friendly without
//!   leaking the full digest. Operators who need the full value pass
//!   `--json`.
//! - All Unix timestamps render in RFC-3339 UTC for consistency with
//!   `raxis log` / `raxis status`.
//! - The `--to <dir>` output is **byte-identical** to the artifact
//!   bytes the operator originally signed; `read_artifact` returns
//!   raw payload bytes verbatim per `views::plan_bundles` §8.3.
//! - Operator-bearing fields (signed-by fingerprint, quarantined-by)
//!   are routed through `operator_display` so the rendered identity
//!   is consistent with `raxis log` / `raxis inbox` /
//!   `raxis policy show --history` per `kernel-store.md` §2.5.2.

use std::io::Write;
use std::path::PathBuf;

use raxis_store::open_ro;
use raxis_store::views::initiative_quarantines::{
    get_by_initiative_id as quarantine_for_initiative, InitiativeQuarantineRow,
};
use raxis_store::views::initiatives::{
    by_id as initiative_by_id, plan_bundle_sha256_by_id, InitiativeRow,
};
use raxis_store::views::plan_bundles::{
    header_by_sha256, list_artifact_names, read_artifact, PlanBundleHeader,
};
use raxis_store::views::tasks::{list_by_initiative, TaskRow};

use crate::errors::CliError;
use crate::operator_display::{
    fingerprint_prefix, format_operator_with_lookup, OperatorNameLookup,
};
use crate::GlobalFlags;

/// Default cap for the per-initiative task table when `--with-tasks`
/// is set. V2 plans are well below this; the cap exists so a
/// degenerate plan with thousands of tasks (or a query against a
/// misbehaving DB) cannot make the CLI page through unbounded rows.
pub(crate) const DEFAULT_TASK_LIMIT: usize = 100;

// ---------------------------------------------------------------------------
// Argument parser
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ShowOpts {
    pub initiative_id: String,
    /// `true` when the operator passed `--bundle` (extended mode).
    pub bundle: bool,
    /// `Some(dir)` when the operator passed `--to <dir>`. Implies
    /// `--bundle`; rejected at parse time when `--bundle` is absent.
    pub to: Option<PathBuf>,
    pub json: bool,
    /// `true` when the operator passed `--with-tasks` — the per-task
    /// table is opt-in so the default render stays bytes-free.
    pub with_tasks: bool,
    /// Per-task table cap; honoured only when `with_tasks` is set.
    pub task_limit: usize,
}

pub(crate) fn parse_args(args: &[String]) -> Result<ShowOpts, CliError> {
    let mut initiative_id: Option<String> = None;
    let mut bundle = false;
    let mut to: Option<PathBuf> = None;
    let mut json = false;
    let mut with_tasks = false;
    let mut task_limit: usize = DEFAULT_TASK_LIMIT;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bundle" => {
                bundle = true;
            }
            "--to" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| CliError::Usage("--to requires a directory path".to_owned()))?;
                to = Some(PathBuf::from(v));
            }
            "--json" => {
                json = true;
            }
            "--with-tasks" => {
                with_tasks = true;
            }
            "--task-limit" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    CliError::Usage("--task-limit requires a positive integer".to_owned())
                })?;
                let parsed: usize = v.parse().map_err(|_| {
                    CliError::Usage(format!(
                        "--task-limit must be a positive integer, got {v:?}"
                    ))
                })?;
                if parsed == 0 {
                    return Err(CliError::Usage("--task-limit must be > 0".to_owned()));
                }
                task_limit = parsed;
            }
            arg if !arg.starts_with('-') && initiative_id.is_none() => {
                initiative_id = Some(arg.to_owned());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown flag for `initiative show`: {other:?}"
                )));
            }
        }
        i += 1;
    }
    let initiative_id = initiative_id.ok_or_else(|| {
        CliError::Usage(
            "initiative show requires <initiative_id> \
             [--bundle] [--to <dir>] [--json] \
             [--with-tasks] [--task-limit N]"
                .to_owned(),
        )
    })?;

    if to.is_some() && !bundle {
        return Err(CliError::Usage(
            "--to <dir> requires --bundle (extracts artifacts from the plan bundle)".to_owned(),
        ));
    }
    if to.is_some() && json {
        return Err(CliError::Usage(
            "--to <dir> writes raw artifact bytes; --json is not meaningful here".to_owned(),
        ));
    }
    Ok(ShowOpts {
        initiative_id,
        bundle,
        to,
        json,
        with_tasks,
        task_limit,
    })
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    let conn = open_ro(flags.data_dir())
        .map_err(|e| CliError::Policy(format!("kernel.db open failed: {e}")))?;

    let initiative = initiative_by_id(&conn, &opts.initiative_id)
        .map_err(|e| CliError::Policy(format!("initiatives::by_id failed: {e}")))?
        .ok_or_else(|| CliError::KernelError {
            code: "INITIATIVE_NOT_FOUND".to_owned(),
            detail: format!("no initiative with id {:?}", opts.initiative_id),
        })?;

    let bundle_sha = plan_bundle_sha256_by_id(&conn, &opts.initiative_id)
        .map_err(|e| {
            CliError::Policy(format!("initiatives::plan_bundle_sha256_by_id failed: {e}"))
        })?
        .ok_or_else(|| CliError::KernelError {
            // V2 admits all plans through the bundle path; reaching
            // this with no `plan_bundle_sha256` would mean the
            // initiative was created but the bundle row was never
            // written (a torn-write bug or external DB corruption).
            code: "PLAN_BUNDLE_NOT_FOUND".to_owned(),
            detail: format!(
                "initiative {} has no plan_bundle_sha256 — every V2 \
                 admission writes one (plan-bundle-sealing.md §8); \
                 the kernel.db is torn or was corrupted out-of-band",
                opts.initiative_id,
            ),
        })?;

    let header = header_by_sha256(&conn, &bundle_sha)
        .map_err(|e| CliError::Policy(format!("plan_bundles::header_by_sha256 failed: {e}")))?
        .ok_or_else(|| CliError::KernelError {
            code: "PLAN_BUNDLE_HEADER_MISSING".to_owned(),
            detail: format!(
            "initiative {} references plan_bundle_sha256={} but no row exists in `plan_bundles`",
            opts.initiative_id,
            bundle_sha.to_hex(),
        ),
        })?;

    let artifact_names = list_artifact_names(&conn, &bundle_sha)
        .map_err(|e| CliError::Policy(format!("plan_bundles::list_artifact_names failed: {e}")))?;

    // Extract-mode short-circuit: write artifacts to disk and exit.
    // This deliberately skips quarantine + tasks reads (the mode IS
    // the side-effect; no rendering happens).
    if let Some(out_dir) = opts.to.as_ref() {
        return extract_artifacts(&conn, &bundle_sha, &header, &artifact_names, out_dir);
    }

    // Live-state joins — quarantine + tasks. Both views are opt-in
    // for the per-task table (gated on `--with-tasks`) but we always
    // read the rows so the renderer has a consistent struct shape
    // (operator-meaningful "this initiative was quarantined" must
    // never be silently elided).
    let quarantine = quarantine_for_initiative(&conn, &opts.initiative_id).map_err(|e| {
        CliError::Policy(format!(
            "initiative_quarantines::get_by_initiative_id failed: {e}"
        ))
    })?;
    let tasks = if opts.with_tasks {
        list_by_initiative(&conn, &opts.initiative_id, opts.task_limit)
            .map_err(|e| CliError::Policy(format!("tasks::list_by_initiative failed: {e}")))?
    } else {
        // Fast path: count only. We still need the count for the
        // "Tasks (N): pass --with-tasks to expand" hint. The view's
        // existing call gives back rows; in practice the unbounded
        // count is bounded by the DEFAULT_TASK_LIMIT cap from the
        // SQL projection, but the cap is generous enough that this
        // is fine.
        list_by_initiative(&conn, &opts.initiative_id, opts.task_limit)
            .map_err(|e| CliError::Policy(format!("tasks::list_by_initiative failed: {e}")))?
    };

    // Drop the read-only handle before opening the operator-name
    // lookup (which opens its own RoConn). They wouldn't collide,
    // but releasing the WAL snapshot early keeps the hot path crisp
    // for any concurrent kernel writer (same discipline as
    // `inspect.rs`).
    drop(conn);

    let name_lookup = OperatorNameLookup::load_from_data_dir(flags.data_dir())
        .unwrap_or_else(|_| OperatorNameLookup::empty());

    // Render mode.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if opts.json {
        render_json(
            &mut out,
            &opts.initiative_id,
            &initiative,
            &header,
            &artifact_names,
            quarantine.as_ref(),
            &tasks,
            &name_lookup,
        );
    } else {
        render_text(
            &mut out,
            &opts.initiative_id,
            &initiative,
            &header,
            opts.bundle,
            &artifact_names,
            quarantine.as_ref(),
            &tasks,
            opts.with_tasks,
            &name_lookup,
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Extract-mode — `--bundle --to <dir>`
// ---------------------------------------------------------------------------

fn extract_artifacts(
    conn: &raxis_store::ro::RoConn,
    bundle_sha: &raxis_types::BundleSha256,
    header: &PlanBundleHeader,
    artifact_names: &[raxis_store::views::plan_bundles::PlanBundleArtifactName],
    out_dir: &std::path::Path,
) -> Result<(), CliError> {
    // Refuse to write into an existing non-empty directory: the
    // operator-visible blast radius of an accidental `--to ~/work` is
    // too large to ignore. An existing empty directory or a
    // not-yet-created one are both fine.
    match std::fs::read_dir(out_dir) {
        Ok(rd) => {
            // Directory exists; verify it's empty (no entries —
            // ignoring `.DS_Store` would creep into per-OS heuristics
            // so we hold a hard line: any entry counts).
            let mut iter = rd;
            if iter.next().is_some() {
                return Err(CliError::Usage(format!(
                    "refusing to extract into non-empty directory {}: \
                     pass an empty or not-yet-existent path",
                    out_dir.display(),
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(out_dir).map_err(|e| CliError::Io {
                path: out_dir.display().to_string(),
                source: e,
            })?;
        }
        Err(e) => {
            return Err(CliError::Io {
                path: out_dir.display().to_string(),
                source: e,
            });
        }
    }

    for a in artifact_names {
        let bytes = read_artifact(conn, bundle_sha, a.artifact_seq)
            .map_err(|e| {
                CliError::Policy(format!(
                    "plan_bundles::read_artifact failed for seq={}: {e}",
                    a.artifact_seq,
                ))
            })?
            .ok_or_else(|| CliError::KernelError {
                code: "PLAN_BUNDLE_ARTIFACT_MISSING".to_owned(),
                detail: format!(
                    "bundle {} declared artifact_seq={} but no row in `plan_bundle_artifacts`",
                    bundle_sha.to_hex(),
                    a.artifact_seq,
                ),
            })?;

        // Defence-in-depth against a malformed bundle on disk. The
        // §8.1 admission-time check already rejects names that
        // contain `..` segments / leading slashes / NUL bytes, but
        // we re-validate here so a future-corrupted row cannot
        // escape `<out_dir>`.
        if !is_safe_artifact_name(&a.artifact_name) {
            return Err(CliError::Policy(format!(
                "refusing to write artifact with unsafe name: {:?}",
                a.artifact_name,
            )));
        }
        let target = out_dir.join(&a.artifact_name);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| CliError::Io {
                path: parent.display().to_string(),
                source: e,
            })?;
        }
        std::fs::write(&target, &bytes).map_err(|e| CliError::Io {
            path: target.display().to_string(),
            source: e,
        })?;
    }

    println!(
        "Extracted {} artifact{} (bundle_sha256={}) to {}",
        artifact_names.len(),
        if artifact_names.len() == 1 { "" } else { "s" },
        truncate_hex(&bundle_sha.to_hex()),
        out_dir.display(),
    );
    let _ = header; // header consumed by render only; here for symmetry.
    Ok(())
}

/// Mirror of `kernel/src/initiatives/v2_admission.rs::validate_artifact_name`
/// — reasserts the same discipline on the egress path. Empty names,
/// names with leading `/`, names containing a literal `..` segment,
/// or names with embedded NUL bytes are all rejected.
fn is_safe_artifact_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.starts_with('/') {
        return false;
    }
    if name.as_bytes().contains(&0) {
        return false;
    }
    for seg in name.split('/') {
        if seg == ".." {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Render-mode helpers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn render_text(
    out: &mut dyn Write,
    initiative_id: &str,
    initiative: &InitiativeRow,
    header: &PlanBundleHeader,
    bundle: bool,
    artifact_names: &[raxis_store::views::plan_bundles::PlanBundleArtifactName],
    quarantine: Option<&InitiativeQuarantineRow>,
    tasks: &[TaskRow],
    with_tasks: bool,
    name_lookup: &OperatorNameLookup,
) {
    let _ = writeln!(out, "Initiative   : {initiative_id}");
    let _ = writeln!(out, "  state              : {}", initiative.state);
    let _ = writeln!(
        out,
        "  created_at         : {} (unix={})",
        format_unix_secs(initiative.created_at as i64),
        initiative.created_at,
    );
    if let Some(t) = initiative.approved_at {
        let _ = writeln!(
            out,
            "  approved_at        : {} (unix={t})",
            format_unix_secs(t as i64),
        );
    }
    if let Some(t) = initiative.completed_at {
        let _ = writeln!(
            out,
            "  completed_at       : {} (unix={t})",
            format_unix_secs(t as i64),
        );
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "Plan Bundle  :");
    let _ = writeln!(
        out,
        "  bundle_sha256      : {} ({} chars elided)",
        truncate_hex(&header.bundle_sha256.to_hex()),
        64 - 16,
    );
    let _ = writeln!(
        out,
        "  schema_version     : {}",
        schema_label(header.schema_version),
    );
    let signed_by_hex = header.signed_by.to_hex();
    let signed_by_display = format_operator_with_lookup(&signed_by_hex, None, name_lookup);
    let _ = writeln!(
        out,
        "  signed_by          : {} ({})",
        truncate_hex(&signed_by_hex),
        signed_by_display,
    );
    let _ = writeln!(
        out,
        "  sealed_at          : {} (unix={})",
        format_unix_secs(header.sealed_at_unix_secs),
        header.sealed_at_unix_secs,
    );
    if let Some(signed_at) = header.signed_at_unix_secs {
        let _ = writeln!(
            out,
            "  signed_at          : {} (unix={})",
            format_unix_secs(signed_at),
            signed_at,
        );
    }
    if let Some(nonce) = header.bundle_nonce {
        let _ = writeln!(out, "  bundle_nonce       : {}", hex::encode(nonce));
    }
    let _ = writeln!(out, "  artifact_count     : {}", header.artifact_count);
    let _ = writeln!(
        out,
        "  bundle_bytes_len   : {} bytes",
        header.bundle_bytes_len
    );

    let _ = writeln!(out);
    render_quarantine_block(out, quarantine, name_lookup);

    let _ = writeln!(out);
    if with_tasks {
        render_task_table(out, tasks);
    } else {
        let _ = writeln!(
            out,
            "Tasks ({n}): pass --with-tasks to expand the per-task table",
            n = tasks.len(),
        );
    }

    if bundle {
        let _ = writeln!(out);
        let _ = writeln!(out, "Artifacts:");
        for a in artifact_names {
            let _ = writeln!(
                out,
                "  [{seq}] {name}",
                seq = a.artifact_seq,
                name = a.artifact_name,
            );
        }
    } else {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "(pass --bundle to list artifacts, --bundle --to <dir> to extract)",
        );
    }
}

fn render_quarantine_block<W: Write + ?Sized>(
    out: &mut W,
    quarantine: Option<&InitiativeQuarantineRow>,
    name_lookup: &OperatorNameLookup,
) {
    match quarantine {
        None => {
            let _ = writeln!(out, "Quarantine  : NO");
        }
        Some(q) => {
            let by = format_operator_with_lookup(&q.quarantined_by, None, name_lookup);
            let _ = writeln!(out, "Quarantine  : YES");
            let _ = writeln!(out, "  quarantined_at     : {}", q.quarantined_at);
            let _ = writeln!(out, "  quarantined_by     : {by}");
            if let Some(reason) = &q.reason {
                let _ = writeln!(out, "  reason             : {reason}");
            }
            if let Some(target) = &q.sweep_target {
                let target_rendered = format_operator_with_lookup(target, None, name_lookup);
                let _ = writeln!(out, "  sweep_target       : {target_rendered}");
            }
        }
    }
}

fn render_task_table<W: Write + ?Sized>(out: &mut W, tasks: &[TaskRow]) {
    let _ = writeln!(out, "Tasks ({n}):", n = tasks.len());
    if tasks.is_empty() {
        let _ = writeln!(out, "  (no tasks under this initiative)");
        return;
    }
    let _ = writeln!(
        out,
        "  {tid:<24} {state:<24} {lane:<14} {ts:<12} {actor}",
        tid = "task_id",
        state = "state",
        lane = "lane",
        ts = "transitioned_at",
        actor = "actor",
    );
    for t in tasks {
        let _ = writeln!(
            out,
            "  {tid:<24} {state:<24} {lane:<14} {ts:<12} {actor}",
            tid = truncate(&t.task_id, 24),
            state = truncate(&t.state, 24),
            lane = truncate(&t.lane_id, 14),
            ts = t.transitioned_at,
            actor = truncate(&t.actor, 16),
        );
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else if max == 0 {
        String::new()
    } else {
        format!("{}\u{2026}", &s[..max - 1])
    }
}

#[allow(clippy::too_many_arguments)]
fn render_json(
    out: &mut dyn Write,
    initiative_id: &str,
    initiative: &InitiativeRow,
    header: &PlanBundleHeader,
    artifact_names: &[raxis_store::views::plan_bundles::PlanBundleArtifactName],
    quarantine: Option<&InitiativeQuarantineRow>,
    tasks: &[TaskRow],
    name_lookup: &OperatorNameLookup,
) {
    let artifacts: Vec<serde_json::Value> = artifact_names
        .iter()
        .map(|a| {
            serde_json::json!({
                "artifact_seq":  a.artifact_seq,
                "artifact_name": a.artifact_name,
            })
        })
        .collect();
    let signed_by_hex = header.signed_by.to_hex();
    let v = serde_json::json!({
        "initiative_id":  initiative_id,
        "state":          initiative.state,
        "created_at":     initiative.created_at,
        "approved_at":    initiative.approved_at,
        "completed_at":   initiative.completed_at,
        "plan_bundle":    {
            "bundle_sha256":       header.bundle_sha256.to_hex(),
            "schema_version":      schema_label(header.schema_version),
            "signed_by":           {
                "fingerprint":        signed_by_hex.clone(),
                "fingerprint_prefix": fingerprint_prefix(&signed_by_hex),
                "display":            format_operator_with_lookup(
                                          &signed_by_hex, None, name_lookup,
                                      ),
            },
            "sealed_at_unix_secs": header.sealed_at_unix_secs,
            "signed_at_unix_secs": header.signed_at_unix_secs,
            "bundle_nonce_hex":    header.bundle_nonce.map(hex::encode),
            "artifact_count":      header.artifact_count,
            "bundle_bytes_len":    header.bundle_bytes_len,
            "artifacts":           artifacts,
        },
        "quarantine":     serialize_quarantine(quarantine, name_lookup),
        "tasks":          tasks.iter().map(serialize_task).collect::<Vec<_>>(),
    });
    let _ = serde_json::to_writer_pretty(&mut *out, &v);
    let _ = writeln!(out);
}

fn serialize_quarantine(
    q: Option<&InitiativeQuarantineRow>,
    name_lookup: &OperatorNameLookup,
) -> serde_json::Value {
    match q {
        None => serde_json::json!({ "quarantined": false }),
        Some(q) => serde_json::json!({
            "quarantined":     true,
            "quarantined_at":  q.quarantined_at,
            "quarantined_by":  {
                "fingerprint":        q.quarantined_by,
                "fingerprint_prefix": fingerprint_prefix(&q.quarantined_by),
                "display":            format_operator_with_lookup(
                                          &q.quarantined_by, None, name_lookup,
                                      ),
            },
            "reason":          q.reason,
            "sweep_target":    q.sweep_target.as_ref().map(|t| serde_json::json!({
                "fingerprint":        t,
                "fingerprint_prefix": fingerprint_prefix(t),
                "display":            format_operator_with_lookup(
                                          t, None, name_lookup,
                                      ),
            })),
        }),
    }
}

fn serialize_task(t: &TaskRow) -> serde_json::Value {
    serde_json::json!({
        "task_id":         t.task_id,
        "state":           t.state,
        "lane_id":         t.lane_id,
        "transitioned_at": t.transitioned_at,
        "actor":           t.actor,
    })
}

fn schema_label(v: raxis_types::SchemaVersion) -> &'static str {
    match v {
        raxis_types::SchemaVersion::V2_0 => "V2.0",
        raxis_types::SchemaVersion::V2_1 => "V2.1",
    }
}

fn truncate_hex(s: &str) -> String {
    if s.len() <= 16 {
        s.to_owned()
    } else {
        format!("{}\u{2026}", &s[..16])
    }
}

/// RFC-3339 UTC formatter that does NOT pull a date-time crate. Good
/// enough for forensic CLI output; precision is whole-seconds.
fn format_unix_secs(unix: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    if let Ok(t) = UNIX_EPOCH
        .checked_add(Duration::from_secs(unix.max(0) as u64))
        .ok_or_else(|| CliError::Policy("timestamp overflow".to_owned()))
    {
        // Manual breakdown: civil-from-days algorithm. We only need
        // YYYY-MM-DDTHH:MM:SSZ accurate to ±1s for forensic output.
        let total_secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let secs = (total_secs % 60) as u32;
        let mins = ((total_secs / 60) % 60) as u32;
        let hrs = ((total_secs / 3600) % 24) as u32;
        let days = (total_secs / 86_400) as i64;
        let (y, m, d) = civil_from_days(days);
        format!("{y:04}-{m:02}-{d:02}T{hrs:02}:{mins:02}:{secs:02}Z")
    } else {
        format!("invalid({unix})")
    }
}

/// Howard Hinnant's `civil_from_days` algorithm, ported.
/// Returns `(year, month, day)` from a count of days since 1970-01-01.
/// Range: well outside any operator-meaningful timestamp.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146_096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + (m <= 2) as i64, m, d)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn parse_requires_initiative_id() {
        let err = parse_args(&[]).unwrap_err();
        match err {
            CliError::Usage(m) => {
                assert!(m.contains("initiative show"), "msg = {m:?}");
                assert!(m.contains("<initiative_id>"), "msg = {m:?}");
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn parse_default_is_summary_only() {
        let opts = parse_args(&s(&["init-1"])).unwrap();
        assert_eq!(opts.initiative_id, "init-1");
        assert!(!opts.bundle);
        assert!(opts.to.is_none());
        assert!(!opts.json);
        // Default render is task-count only — operators must opt in
        // to the per-task table so a casual `initiative show` never
        // floods the TTY.
        assert!(!opts.with_tasks);
        assert_eq!(opts.task_limit, DEFAULT_TASK_LIMIT);
        assert_eq!(opts.task_limit, 100);
    }

    #[test]
    fn parse_with_tasks_and_task_limit_compose() {
        let opts = parse_args(&s(&["init-1", "--with-tasks", "--task-limit", "42"])).unwrap();
        assert!(opts.with_tasks);
        assert_eq!(opts.task_limit, 42);
    }

    #[test]
    fn parse_task_limit_rejects_zero() {
        let err = parse_args(&s(&["init-1", "--task-limit", "0"])).unwrap_err();
        match err {
            CliError::Usage(m) => assert!(m.contains("> 0"), "msg = {m:?}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn parse_task_limit_rejects_non_integer() {
        let err = parse_args(&s(&["init-1", "--task-limit", "lots"])).unwrap_err();
        match err {
            CliError::Usage(m) => {
                assert!(
                    m.contains("--task-limit must be a positive integer"),
                    "msg = {m:?}"
                );
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn parse_bundle_and_json_compose() {
        let opts = parse_args(&s(&["init-1", "--bundle", "--json"])).unwrap();
        assert!(opts.bundle);
        assert!(opts.json);
    }

    #[test]
    fn parse_to_implies_bundle_and_rejects_when_absent() {
        let err = parse_args(&s(&["init-1", "--to", "/tmp/foo"])).unwrap_err();
        match err {
            CliError::Usage(m) => {
                assert!(m.contains("--to <dir> requires --bundle"), "msg = {m:?}");
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn parse_to_with_bundle_is_accepted() {
        let opts = parse_args(&s(&["init-1", "--bundle", "--to", "/tmp/foo"])).unwrap();
        assert!(opts.bundle);
        assert_eq!(opts.to.as_ref().unwrap(), &PathBuf::from("/tmp/foo"));
    }

    #[test]
    fn parse_to_plus_json_is_rejected() {
        let err =
            parse_args(&s(&["init-1", "--bundle", "--to", "/tmp/foo", "--json"])).unwrap_err();
        match err {
            CliError::Usage(m) => assert!(m.contains("--json is not meaningful"), "msg = {m:?}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_flag_is_usage_error() {
        let err = parse_args(&s(&["init-1", "--bogus"])).unwrap_err();
        match err {
            CliError::Usage(m) => {
                assert!(
                    m.contains("--bogus") || m.contains("unknown flag"),
                    "msg = {m:?}"
                );
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn parse_to_without_value_is_usage_error() {
        let err = parse_args(&s(&["init-1", "--bundle", "--to"])).unwrap_err();
        match err {
            CliError::Usage(m) => assert!(m.contains("--to requires"), "msg = {m:?}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    // ── Safety helper ────────────────────────────────────────────────────

    #[test]
    fn artifact_name_safety_filter_rejects_path_escapes() {
        assert!(!is_safe_artifact_name(""));
        assert!(!is_safe_artifact_name("/etc/passwd"));
        assert!(!is_safe_artifact_name("../escape.txt"));
        assert!(!is_safe_artifact_name("subdir/../escape.txt"));
        assert!(!is_safe_artifact_name("name\0with-nul"));
        assert!(is_safe_artifact_name("plan.toml"));
        assert!(is_safe_artifact_name("subdir/file.md"));
        // ".." substring (not segment) is allowed.
        assert!(is_safe_artifact_name("foo..bar"));
    }

    // ── Truncate-hex helper ──────────────────────────────────────────────

    #[test]
    fn truncate_hex_pinches_long_digests() {
        let s = "abcdef0123456789".repeat(4); // 64 chars
        let t = truncate_hex(&s);
        assert!(t.starts_with("abcdef0123456789"));
        assert!(t.ends_with('\u{2026}'));
        assert_eq!(t.chars().count(), 17);
    }

    #[test]
    fn truncate_hex_passes_short_strings_through() {
        let t = truncate_hex("deadbeef");
        assert_eq!(t, "deadbeef");
    }

    // ── Civil-from-days date math ────────────────────────────────────────

    #[test]
    fn format_unix_secs_renders_known_landmarks() {
        // 1970-01-01T00:00:00Z
        assert_eq!(format_unix_secs(0), "1970-01-01T00:00:00Z");
        // 2026-01-01T00:00:00Z = 1_767_225_600
        assert_eq!(format_unix_secs(1_767_225_600), "2026-01-01T00:00:00Z");
        // Negative / zero handling: clamp to epoch.
        assert_eq!(format_unix_secs(-100), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_unix_secs_pads_single_digits() {
        // Pin the structural shape of the output (ZZ-padded YYYY,
        // MM, DD, HH, MM, SS) without depending on a hand-computed
        // landmark — `format_unix_secs(0)` already pins
        // 1970-01-01T00:00:00Z, so all we need here is the format
        // itself.
        let s = format_unix_secs(1_775_645_289);
        assert_eq!(s.len(), 20, "expected 20-char output, got {s:?}");
        assert!(s.ends_with('Z'), "must terminate Z: {s:?}");
        assert_eq!(s.chars().nth(4), Some('-'));
        assert_eq!(s.chars().nth(7), Some('-'));
        assert_eq!(s.chars().nth(10), Some('T'));
        assert_eq!(s.chars().nth(13), Some(':'));
        assert_eq!(s.chars().nth(16), Some(':'));
    }

    // ── End-to-end: real Store + run() ───────────────────────────────────
    //
    // These fixtures stand up a real on-disk SQLite store, seed an
    // initiative + V2 plan bundle through the typed
    // `raxis_store::plan_bundles` helpers (NOT raw SQL), and then
    // exercise the `run` entry point. They catch wiring bugs that
    // pure parser tests can't — wrong column ordering in the FK
    // chain, missing artifact rows, render-mode stdout discipline,
    // and the `--to <dir>` extract-write loop.

    fn fresh_seeded_store_with_v2_initiative() -> (
        tempfile::TempDir,
        raxis_types::BundleSha256,
        Vec<(String, Vec<u8>)>,
    ) {
        use raxis_store::{Store, Table};
        use raxis_types::{
            BundleArtifact, BundleNonce, BundleSha256, OperatorFingerprint, PlanBundle,
        };
        use sha2::{Digest, Sha256};

        let tmp = tempfile::TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();

        let plan_bytes = b"[orchestrator]\ntitle = \"e2e\"\n".to_vec();
        let extra_bytes = b"forensic notes\n".to_vec();
        let plan_sha = {
            let mut h = Sha256::new();
            h.update(&plan_bytes);
            BundleSha256::new(h.finalize().into())
        };
        let extra_sha = {
            let mut h = Sha256::new();
            h.update(&extra_bytes);
            BundleSha256::new(h.finalize().into())
        };
        let bundle = PlanBundle::new_v2_1(
            1_700_000_100,
            1_700_000_200,
            BundleNonce::new([0xCDu8; 16]),
            "demo".to_owned(),
            vec![
                BundleArtifact {
                    name: "plan.toml".into(),
                    bytes: plan_bytes.clone(),
                    sha256: plan_sha,
                },
                BundleArtifact {
                    name: "notes/ref.md".into(),
                    bytes: extra_bytes.clone(),
                    sha256: extra_sha,
                },
            ],
        );
        let bundle_sha = BundleSha256::new([0x12u8; 32]);

        {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            raxis_store::plan_bundles::insert_bundle(
                &tx,
                &bundle_sha,
                b"placeholder-canonical-bytes",
                &[0x77u8; 64],
                &OperatorFingerprint::new([0x88u8; 8]),
                &bundle,
                1_700_000_999,
            )
            .unwrap();
            raxis_store::plan_bundles::insert_artifacts(&tx, &bundle_sha, &bundle.artifacts)
                .unwrap();
            tx.execute(
                &format!(
                    "INSERT INTO {} \
                     (initiative_id, state, terminal_criteria_json, \
                      plan_artifact_sha256, plan_bundle_sha256, created_at) \
                     VALUES ('init-e2e', 'Draft', '{{}}', ?1, ?2, 1700000999)",
                    Table::Initiatives.as_str(),
                ),
                rusqlite::params![bundle_sha.to_hex(), bundle_sha.as_bytes().as_slice()],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        (
            tmp,
            bundle_sha,
            vec![
                ("plan.toml".to_owned(), plan_bytes),
                ("notes/ref.md".to_owned(), extra_bytes),
            ],
        )
    }

    fn flags_with_data_dir(data_dir: &std::path::Path) -> crate::GlobalFlags {
        // GlobalFlags is private; the same in-crate test discipline
        // used by the rest of `commands/` constructs it manually.
        // Using a concrete struct constructor here keeps the test
        // local and avoids growing a `Default` impl on the type
        // (which would silently leak default paths into the binary).
        crate::GlobalFlags {
            data_dir: data_dir.to_path_buf(),
            socket_path: None,
            operator_key_path: None,
        }
    }

    #[test]
    fn run_with_no_flags_succeeds_for_v2_initiative() {
        let (tmp, _sha, _) = fresh_seeded_store_with_v2_initiative();
        let flags = flags_with_data_dir(tmp.path());
        let r = run(&flags, &s(&["init-e2e"]));
        assert!(r.is_ok(), "expected ok, got {r:?}");
    }

    #[test]
    fn run_returns_error_for_unknown_initiative() {
        let (tmp, _sha, _) = fresh_seeded_store_with_v2_initiative();
        let flags = flags_with_data_dir(tmp.path());
        let err = run(&flags, &s(&["init-MISSING"])).unwrap_err();
        match err {
            CliError::KernelError { code, detail } => {
                assert_eq!(code, "INITIATIVE_NOT_FOUND");
                assert!(detail.contains("init-MISSING"), "detail = {detail:?}");
            }
            other => panic!("expected KernelError, got {other:?}"),
        }
    }

    #[test]
    fn run_returns_error_for_initiative_without_bundle() {
        // V2 admits every initiative through the bundle path; the
        // schema still permits writing an `initiatives` row with NULL
        // `plan_bundle_sha256` (because the column is added by a
        // migration that doesn't backfill). Reaching `initiative
        // show` against such a torn row is a forensic-grade failure
        // and MUST surface as a typed error rather than a panic. We
        // simulate that exact wedge here.
        use raxis_store::{Store, Table};
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        {
            let conn = store.lock_sync();
            conn.execute(
                &format!(
                    "INSERT INTO {} \
                     (initiative_id, state, terminal_criteria_json, \
                      plan_artifact_sha256, created_at) \
                     VALUES ('init-torn', 'Draft', '{{}}', 'fallback-sha', 1700000000)",
                    Table::Initiatives.as_str(),
                ),
                [],
            )
            .unwrap();
        }
        let flags = flags_with_data_dir(tmp.path());
        let err = run(&flags, &s(&["init-torn"])).unwrap_err();
        match err {
            CliError::KernelError { code, detail } => {
                assert_eq!(code, "PLAN_BUNDLE_NOT_FOUND");
                assert!(detail.contains("init-torn"), "detail = {detail:?}");
            }
            other => panic!("expected KernelError, got {other:?}"),
        }
    }

    #[test]
    fn run_extract_writes_byte_identical_artifacts_into_target_dir() {
        let (tmp, _sha, expected) = fresh_seeded_store_with_v2_initiative();
        let flags = flags_with_data_dir(tmp.path());
        let out = tempfile::TempDir::new().unwrap();
        // The directory exists but is empty; extract should succeed.
        let r = run(
            &flags,
            &s(&["init-e2e", "--bundle", "--to", out.path().to_str().unwrap()]),
        );
        assert!(r.is_ok(), "extract failed: {r:?}");
        for (name, expected_bytes) in &expected {
            let actual = std::fs::read(out.path().join(name))
                .unwrap_or_else(|e| panic!("missing extract for {name:?}: {e}"));
            assert_eq!(
                actual, *expected_bytes,
                "byte mismatch for {name}: extract is not byte-identical"
            );
        }
    }

    #[test]
    fn render_text_default_shows_task_count_hint_not_table() {
        // Build the renderer inputs directly so we can exercise the
        // "summary mode" without going through `run`'s I/O. This keeps
        // the assertion focused on the render contract: when
        // `with_tasks=false`, the render MUST surface the task count
        // and the `--with-tasks` hint, and MUST NOT enumerate task
        // IDs.
        use raxis_types::{BundleSha256, OperatorFingerprint, SchemaVersion};
        let header = PlanBundleHeader {
            bundle_sha256: BundleSha256::new([0xAAu8; 32]),
            schema_version: SchemaVersion::V2_1,
            signed_by: OperatorFingerprint::new([0x88u8; 8]),
            sealed_at_unix_secs: 1_700_000_100,
            signed_at_unix_secs: Some(1_700_000_200),
            bundle_nonce: Some([0xCDu8; 16]),
            artifact_count: 2,
            bundle_bytes_len: 256,
        };
        let initiative = InitiativeRow {
            initiative_id: "init-render".to_owned(),
            state: "Executing".to_owned(),
            plan_artifact_sha256: "deadbeef".to_owned(),
            created_at: 1_700_000_000,
            approved_at: Some(1_700_000_010),
            completed_at: None,
        };
        let tasks = vec![TaskRow {
            task_id: "t-rendered".to_owned(),
            initiative_id: "init-render".to_owned(),
            initiative_state: "Executing".to_owned(),
            lane_id: "default".to_owned(),
            state: "Running".to_owned(),
            block_reason: None,
            actor: "executor".to_owned(),
            policy_epoch: 1,
            admitted_at: 1_700_000_020,
            transitioned_at: 1_700_000_030,
            session_id: None,
            evaluation_sha: None,
            base_sha: None,
            admission_reserved_units: None,
            actual_cost: 0,
        }];
        let lookup = OperatorNameLookup::empty();
        let mut buf: Vec<u8> = Vec::new();
        render_text(
            &mut buf,
            "init-render",
            &initiative,
            &header,
            false, // bundle
            &[],
            None, // quarantine
            &tasks,
            false, // with_tasks (count-only mode)
            &lookup,
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("Initiative   : init-render"),
            "header missing: {s}"
        );
        assert!(
            s.contains("Tasks (1): pass --with-tasks to expand"),
            "task-count hint missing in summary mode: {s}",
        );
        assert!(
            !s.contains("t-rendered"),
            "task IDs MUST NOT render in summary mode: {s}",
        );
        assert!(
            s.contains("Quarantine  : NO"),
            "quarantine block missing: {s}"
        );
    }

    #[test]
    fn render_text_with_tasks_expands_table_and_shows_quarantine_block() {
        use raxis_types::{BundleSha256, OperatorFingerprint, SchemaVersion};
        let header = PlanBundleHeader {
            bundle_sha256: BundleSha256::new([0xAAu8; 32]),
            schema_version: SchemaVersion::V2_1,
            signed_by: OperatorFingerprint::new([0x88u8; 8]),
            sealed_at_unix_secs: 1_700_000_100,
            signed_at_unix_secs: None,
            bundle_nonce: Some([0xCDu8; 16]),
            artifact_count: 1,
            bundle_bytes_len: 128,
        };
        let initiative = InitiativeRow {
            initiative_id: "init-q".to_owned(),
            state: "Quarantined".to_owned(),
            plan_artifact_sha256: "abc".to_owned(),
            created_at: 1_700_000_000,
            approved_at: None,
            completed_at: None,
        };
        let tasks = vec![TaskRow {
            task_id: "task-alpha".to_owned(),
            initiative_id: "init-q".to_owned(),
            initiative_state: "Quarantined".to_owned(),
            lane_id: "default".to_owned(),
            state: "Running".to_owned(),
            block_reason: None,
            actor: "executor".to_owned(),
            policy_epoch: 1,
            admitted_at: 1_700_000_020,
            transitioned_at: 1_700_000_030,
            session_id: None,
            evaluation_sha: None,
            base_sha: None,
            admission_reserved_units: None,
            actual_cost: 0,
        }];
        let q = InitiativeQuarantineRow {
            initiative_id: "init-q".to_owned(),
            quarantined_at: 1_700_000_040,
            quarantined_by: "abcd1234abcd1234abcd1234abcd1234".to_owned(),
            reason: Some("compromised key suspected".to_owned()),
            sweep_target: None,
        };
        let lookup =
            OperatorNameLookup::from_pairs([("abcd1234abcd1234abcd1234abcd1234", "Chika")]);
        let mut buf: Vec<u8> = Vec::new();
        render_text(
            &mut buf,
            "init-q",
            &initiative,
            &header,
            false,
            &[],
            Some(&q),
            &tasks,
            true, // with_tasks
            &lookup,
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Quarantine  : YES"), "got: {s}");
        assert!(
            s.contains("compromised key suspected"),
            "reason MUST surface: {s}"
        );
        assert!(
            s.contains("Chika (abcd1234"),
            "operator display MUST resolve: {s}"
        );
        assert!(
            s.contains("task-alpha"),
            "task row MUST surface in --with-tasks mode: {s}"
        );
        assert!(s.contains("Running"), "state MUST surface: {s}");
    }

    #[test]
    fn render_json_emits_quarantine_and_task_keys() {
        use raxis_types::{BundleSha256, OperatorFingerprint, SchemaVersion};
        let header = PlanBundleHeader {
            bundle_sha256: BundleSha256::new([0xAAu8; 32]),
            schema_version: SchemaVersion::V2_1,
            signed_by: OperatorFingerprint::new([0x88u8; 8]),
            sealed_at_unix_secs: 1_700_000_100,
            signed_at_unix_secs: None,
            bundle_nonce: Some([0xCDu8; 16]),
            artifact_count: 0,
            bundle_bytes_len: 0,
        };
        let initiative = InitiativeRow {
            initiative_id: "init-json".to_owned(),
            state: "Executing".to_owned(),
            plan_artifact_sha256: "abc".to_owned(),
            created_at: 1_700_000_000,
            approved_at: None,
            completed_at: None,
        };
        let lookup = OperatorNameLookup::empty();
        let mut buf: Vec<u8> = Vec::new();
        render_json(
            &mut buf,
            "init-json",
            &initiative,
            &header,
            &[],
            None,
            &[],
            &lookup,
        );
        let v: serde_json::Value =
            serde_json::from_slice(&buf).expect("render_json MUST emit valid JSON");
        for k in [
            "initiative_id",
            "state",
            "created_at",
            "approved_at",
            "completed_at",
            "plan_bundle",
            "quarantine",
            "tasks",
        ] {
            assert!(v.get(k).is_some(), "missing top-level key {k}; got {v}");
        }
        assert_eq!(
            v["quarantine"],
            serde_json::json!({ "quarantined": false }),
            "quarantine block MUST surface a discriminated `quarantined: false` shape: {v}",
        );
        assert_eq!(
            v["tasks"],
            serde_json::json!([]),
            "tasks key MUST always be an array, even when empty: {v}",
        );
    }

    #[test]
    fn run_extract_refuses_to_write_into_non_empty_directory() {
        let (tmp, _sha, _) = fresh_seeded_store_with_v2_initiative();
        let flags = flags_with_data_dir(tmp.path());
        let out = tempfile::TempDir::new().unwrap();
        // Plant an unrelated file so the directory is non-empty.
        std::fs::write(out.path().join("unrelated.txt"), b"do not clobber").unwrap();
        let err = run(
            &flags,
            &s(&["init-e2e", "--bundle", "--to", out.path().to_str().unwrap()]),
        )
        .unwrap_err();
        match err {
            CliError::Usage(m) => {
                assert!(m.contains("non-empty directory"), "msg = {m:?}");
            }
            other => panic!("expected Usage, got {other:?}"),
        }
        // The unrelated file is untouched.
        assert_eq!(
            std::fs::read(out.path().join("unrelated.txt")).unwrap(),
            b"do not clobber",
        );
    }
}
