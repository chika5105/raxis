//! `raxis policy diff` — semantic diff between two policy bundles.
//!
//! Normative reference: cli-readonly.md §5.5.12.
//!
//! # What this command answers
//!
//! "What changes if I rotate from <left>.toml to <right>.toml?" by
//! loading both through `raxis_policy::load_policy` (so we diff the
//! *validated* shape, not raw TOML bytes) and surfacing every
//! per-section delta the operator needs to reason about a rotation:
//!
//!   * epoch / sha256 / signed_by              — bundle identity
//!   * lanes  (added / removed / changed)
//!   * operators (added / removed; permitted_ops set deltas)
//!   * gates  (added / removed; per-field deltas)
//!   * egress_domains  (set diff)
//!   * gateway          (binary_path / timeout / respawn deltas)
//!   * providers        (added / removed; per-field deltas)
//!   * notification channels + default routes
//!
//! # Why semantic diff and not `diff -u <left> <right>`
//!
//! Three reasons:
//!
//!   1. **Trustworthy comparison.** A textual diff would surface
//!      whitespace-only changes and TOML key reordering as
//!      "changes" the operator does not actually need to consider.
//!   2. **Validation gating.** The CLI must refuse to compare a
//!      bundle the kernel cannot load — the operator should fix the
//!      bundle, not approve a diff against an invalid file.
//!   3. **Stable output for tooling.** The JSON form of this diff
//!      is the contract a CI bot can subscribe to ("alert me on any
//!      gateway.binary_path change") without re-implementing TOML
//!      parsing.
//!
//! # Exit code
//!
//! `0` on every successful render, regardless of whether there are
//! deltas (use the report itself, or `--exit-code` (v1.x) for
//! script integration). Failure to load either bundle is `Policy(...)`.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

use raxis_policy::{
    load_policy, GateEntry, GatewaySection, LaneEntry, NotificationChannel, OperatorEntry,
    PolicyBundle, ProviderEntry,
};

use crate::errors::CliError;
use crate::GlobalFlags;

// ────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────

pub fn run(_flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    let (left, _, left_sha) = load_policy(&opts.left)
        .map_err(|e| CliError::Policy(format!("load left {:?}: {e}", opts.left)))?;
    let (right, _, right_sha) = load_policy(&opts.right)
        .map_err(|e| CliError::Policy(format!("load right {:?}: {e}", opts.right)))?;

    let report = diff_bundles(&left, &right, &left_sha, &right_sha);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if opts.json {
        render_json(&mut out, &opts, &report);
    } else {
        render_human(&mut out, &opts, &report);
    }
    let _ = out.flush();
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct PolicyDiffOpts {
    left: PathBuf,
    right: PathBuf,
    json: bool,
}

fn parse_args(args: &[String]) -> Result<PolicyDiffOpts, CliError> {
    let mut positionals: Vec<PathBuf> = Vec::new();
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other if !other.starts_with('-') => {
                positionals.push(PathBuf::from(other));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown policy diff flag: {other:?} \
                     (try <left.toml> <right.toml> [--json])"
                )));
            }
        }
        i += 1;
    }
    if positionals.len() != 2 {
        return Err(CliError::Usage(
            "policy diff requires exactly two positional paths \
             <left.toml> <right.toml>"
                .to_owned(),
        ));
    }
    let mut it = positionals.into_iter();
    Ok(PolicyDiffOpts {
        left: it.next().unwrap(),
        right: it.next().unwrap(),
        json,
    })
}

fn print_help() {
    println!(
        "raxis policy diff — compare two validated policy bundles\n\
         \n\
         USAGE:\n\
         \traxis policy diff <left.toml> <right.toml> [--json]\n\
         \n\
         FLAGS:\n\
         \t--json   Emit one JSON object instead of human text.\n\
         "
    );
}

// ────────────────────────────────────────────────────────────────────
// Diff model
// ────────────────────────────────────────────────────────────────────

/// One line of the diff output. We use "added" / "removed" /
/// "changed" rather than `+` / `-` / `~` because a future colourised
/// renderer can map them to glyphs without parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DiffEntry {
    section: &'static str,
    kind: DiffKind,
    label: String,
    detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffKind {
    Added,
    Removed,
    Changed,
}

impl DiffKind {
    fn token(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Changed => "changed",
        }
    }
}

#[derive(Debug, Default, Clone)]
struct DiffReport {
    entries: Vec<DiffEntry>,
}

impl DiffReport {
    fn push(
        &mut self,
        section: &'static str,
        kind: DiffKind,
        label: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.entries.push(DiffEntry {
            section,
            kind,
            label: label.into(),
            detail: detail.into(),
        });
    }
}

// ────────────────────────────────────────────────────────────────────
// Top-level diff orchestrator
// ────────────────────────────────────────────────────────────────────

fn diff_bundles(
    left: &PolicyBundle,
    right: &PolicyBundle,
    left_sha: &str,
    right_sha: &str,
) -> DiffReport {
    let mut r = DiffReport::default();

    if left.epoch() != right.epoch() {
        r.push(
            "identity",
            DiffKind::Changed,
            "epoch",
            format!("{} → {}", left.epoch(), right.epoch()),
        );
    }
    if left_sha != right_sha {
        r.push(
            "identity",
            DiffKind::Changed,
            "policy_sha256",
            format!(
                "{}… → {}…",
                &left_sha[..16.min(left_sha.len())],
                &right_sha[..16.min(right_sha.len())]
            ),
        );
    }
    if left.signed_by() != right.signed_by() {
        r.push(
            "identity",
            DiffKind::Changed,
            "signed_by",
            format!("{} → {}", left.signed_by(), right.signed_by()),
        );
    }

    diff_lanes(&mut r, left.lanes(), right.lanes());
    diff_operators(&mut r, left.operators(), right.operators());
    diff_gates(&mut r, left.gates(), right.gates());
    diff_egress(&mut r, left.egress_domains(), right.egress_domains());
    diff_gateway(&mut r, left.gateway(), right.gateway());
    diff_providers(&mut r, left.providers(), right.providers());
    diff_notifications(
        &mut r,
        left.notification_channels(),
        right.notification_channels(),
        left.default_notification_channels(),
        right.default_notification_channels(),
    );

    r
}

// ────────────────────────────────────────────────────────────────────
// Per-section helpers
// ────────────────────────────────────────────────────────────────────

fn diff_lanes(r: &mut DiffReport, l: &[LaneEntry], rs: &[LaneEntry]) {
    let l_idx: std::collections::HashMap<&str, &LaneEntry> =
        l.iter().map(|e| (e.lane_id.as_str(), e)).collect();
    let r_idx: std::collections::HashMap<&str, &LaneEntry> =
        rs.iter().map(|e| (e.lane_id.as_str(), e)).collect();

    for id in r_idx.keys() {
        if !l_idx.contains_key(id) {
            r.push("lanes", DiffKind::Added, *id, "");
        }
    }
    for id in l_idx.keys() {
        if !r_idx.contains_key(id) {
            r.push("lanes", DiffKind::Removed, *id, "");
        }
    }
    for (id, lc) in &l_idx {
        let Some(rc) = r_idx.get(id) else { continue };
        if lc.max_concurrent_tasks != rc.max_concurrent_tasks {
            r.push(
                "lanes",
                DiffKind::Changed,
                format!("{id}.max_concurrent_tasks"),
                format!("{} → {}", lc.max_concurrent_tasks, rc.max_concurrent_tasks),
            );
        }
        if lc.max_cost_per_epoch != rc.max_cost_per_epoch {
            r.push(
                "lanes",
                DiffKind::Changed,
                format!("{id}.max_cost_per_epoch"),
                format!("{} → {}", lc.max_cost_per_epoch, rc.max_cost_per_epoch),
            );
        }
        if lc.priority != rc.priority {
            r.push(
                "lanes",
                DiffKind::Changed,
                format!("{id}.priority"),
                format!("{} → {}", lc.priority, rc.priority),
            );
        }
    }
}

fn diff_operators(r: &mut DiffReport, l: &[OperatorEntry], rs: &[OperatorEntry]) {
    let l_idx: std::collections::HashMap<&str, &OperatorEntry> = l
        .iter()
        .map(|e| (e.pubkey_fingerprint.as_str(), e))
        .collect();
    let r_idx: std::collections::HashMap<&str, &OperatorEntry> = rs
        .iter()
        .map(|e| (e.pubkey_fingerprint.as_str(), e))
        .collect();

    for fp in r_idx.keys() {
        if !l_idx.contains_key(fp) {
            r.push("operators", DiffKind::Added, *fp, "");
        }
    }
    for fp in l_idx.keys() {
        if !r_idx.contains_key(fp) {
            r.push("operators", DiffKind::Removed, *fp, "");
        }
    }
    for (fp, lop) in &l_idx {
        let Some(rop) = r_idx.get(fp) else { continue };
        let l_set: BTreeSet<&str> = lop.permitted_ops.iter().map(|s| s.as_str()).collect();
        let r_set: BTreeSet<&str> = rop.permitted_ops.iter().map(|s| s.as_str()).collect();
        let added: Vec<&&str> = r_set.difference(&l_set).collect();
        let removed: Vec<&&str> = l_set.difference(&r_set).collect();
        if !added.is_empty() || !removed.is_empty() {
            r.push(
                "operators",
                DiffKind::Changed,
                format!("{fp}.permitted_ops"),
                format!(
                    "+{added:?} -{removed:?}",
                    added = added.iter().map(|s| **s).collect::<Vec<_>>(),
                    removed = removed.iter().map(|s| **s).collect::<Vec<_>>(),
                ),
            );
        }
    }
}

fn diff_gates(r: &mut DiffReport, l: &[GateEntry], rs: &[GateEntry]) {
    let l_idx: std::collections::HashMap<&str, &GateEntry> =
        l.iter().map(|e| (e.gate_type.as_str(), e)).collect();
    let r_idx: std::collections::HashMap<&str, &GateEntry> =
        rs.iter().map(|e| (e.gate_type.as_str(), e)).collect();

    for k in r_idx.keys() {
        if !l_idx.contains_key(k) {
            r.push("gates", DiffKind::Added, *k, "");
        }
    }
    for k in l_idx.keys() {
        if !r_idx.contains_key(k) {
            r.push("gates", DiffKind::Removed, *k, "");
        }
    }
    for (k, lg) in &l_idx {
        let Some(rg) = r_idx.get(k) else { continue };
        if lg.verifier_command != rg.verifier_command {
            r.push(
                "gates",
                DiffKind::Changed,
                format!("{k}.verifier_command"),
                format!("{} → {}", lg.verifier_command, rg.verifier_command),
            );
        }
        if lg.max_wall_seconds != rg.max_wall_seconds {
            r.push(
                "gates",
                DiffKind::Changed,
                format!("{k}.max_wall_seconds"),
                format!("{} → {}", lg.max_wall_seconds, rg.max_wall_seconds),
            );
        }
        if lg.max_memory_bytes != rg.max_memory_bytes {
            r.push(
                "gates",
                DiffKind::Changed,
                format!("{k}.max_memory_bytes"),
                format!("{} → {}", lg.max_memory_bytes, rg.max_memory_bytes),
            );
        }
        if lg.network_allowed != rg.network_allowed {
            r.push(
                "gates",
                DiffKind::Changed,
                format!("{k}.network_allowed"),
                format!("{} → {}", lg.network_allowed, rg.network_allowed),
            );
        }
    }
}

fn diff_egress(r: &mut DiffReport, l: &[String], rs: &[String]) {
    let l_set: BTreeSet<&str> = l.iter().map(|s| s.as_str()).collect();
    let r_set: BTreeSet<&str> = rs.iter().map(|s| s.as_str()).collect();
    for added in r_set.difference(&l_set) {
        r.push("egress", DiffKind::Added, *added, "");
    }
    for removed in l_set.difference(&r_set) {
        r.push("egress", DiffKind::Removed, *removed, "");
    }
}

fn diff_gateway(r: &mut DiffReport, l: Option<&GatewaySection>, rs: Option<&GatewaySection>) {
    match (l, rs) {
        (None, None) => {}
        (Some(_), None) => {
            r.push(
                "gateway",
                DiffKind::Removed,
                "section",
                "removed (no [gateway] block in right)",
            );
        }
        (None, Some(_)) => {
            r.push(
                "gateway",
                DiffKind::Added,
                "section",
                "added (no [gateway] block in left)",
            );
        }
        (Some(lg), Some(rg)) => {
            if lg.binary_path != rg.binary_path {
                r.push(
                    "gateway",
                    DiffKind::Changed,
                    "binary_path",
                    format!("{} → {}", lg.binary_path, rg.binary_path),
                );
            }
            if lg.spawn_timeout_secs != rg.spawn_timeout_secs {
                r.push(
                    "gateway",
                    DiffKind::Changed,
                    "spawn_timeout_secs",
                    format!("{} → {}", lg.spawn_timeout_secs, rg.spawn_timeout_secs),
                );
            }
            if lg.respawn_backoff_ms != rg.respawn_backoff_ms {
                r.push(
                    "gateway",
                    DiffKind::Changed,
                    "respawn_backoff_ms",
                    format!("{} → {}", lg.respawn_backoff_ms, rg.respawn_backoff_ms),
                );
            }
            if lg.max_consecutive_respawns != rg.max_consecutive_respawns {
                r.push(
                    "gateway",
                    DiffKind::Changed,
                    "max_consecutive_respawns",
                    format!(
                        "{} → {}",
                        lg.max_consecutive_respawns, rg.max_consecutive_respawns
                    ),
                );
            }
        }
    }
}

fn diff_providers(r: &mut DiffReport, l: &[ProviderEntry], rs: &[ProviderEntry]) {
    let l_idx: std::collections::HashMap<&str, &ProviderEntry> =
        l.iter().map(|e| (e.provider_id.as_str(), e)).collect();
    let r_idx: std::collections::HashMap<&str, &ProviderEntry> =
        rs.iter().map(|e| (e.provider_id.as_str(), e)).collect();

    for id in r_idx.keys() {
        if !l_idx.contains_key(id) {
            r.push("providers", DiffKind::Added, *id, "");
        }
    }
    for id in l_idx.keys() {
        if !r_idx.contains_key(id) {
            r.push("providers", DiffKind::Removed, *id, "");
        }
    }
    for (id, lp) in &l_idx {
        let Some(rp) = r_idx.get(id) else { continue };
        if lp.kind != rp.kind {
            r.push(
                "providers",
                DiffKind::Changed,
                format!("{id}.kind"),
                format!("{} → {}", lp.kind, rp.kind),
            );
        }
        if lp.credentials_file != rp.credentials_file {
            r.push(
                "providers",
                DiffKind::Changed,
                format!("{id}.credentials_file"),
                format!("{} → {}", lp.credentials_file, rp.credentials_file),
            );
        }
        if lp.inference_timeout_ms != rp.inference_timeout_ms {
            r.push(
                "providers",
                DiffKind::Changed,
                format!("{id}.inference_timeout_ms"),
                format!("{} → {}", lp.inference_timeout_ms, rp.inference_timeout_ms),
            );
        }
        if lp.data_fetch_timeout_ms != rp.data_fetch_timeout_ms {
            r.push(
                "providers",
                DiffKind::Changed,
                format!("{id}.data_fetch_timeout_ms"),
                format!(
                    "{} → {}",
                    lp.data_fetch_timeout_ms, rp.data_fetch_timeout_ms
                ),
            );
        }
        if lp.max_response_bytes != rp.max_response_bytes {
            r.push(
                "providers",
                DiffKind::Changed,
                format!("{id}.max_response_bytes"),
                format!("{} → {}", lp.max_response_bytes, rp.max_response_bytes),
            );
        }
    }
}

fn diff_notifications(
    r: &mut DiffReport,
    l_chans: &[NotificationChannel],
    r_chans: &[NotificationChannel],
    l_def: &[String],
    r_def: &[String],
) {
    let l_idx: std::collections::HashMap<&str, &NotificationChannel> =
        l_chans.iter().map(|c| (c.id.as_str(), c)).collect();
    let r_idx: std::collections::HashMap<&str, &NotificationChannel> =
        r_chans.iter().map(|c| (c.id.as_str(), c)).collect();
    for id in r_idx.keys() {
        if !l_idx.contains_key(id) {
            r.push(
                "notifications",
                DiffKind::Added,
                format!("channel:{id}"),
                "",
            );
        }
    }
    for id in l_idx.keys() {
        if !r_idx.contains_key(id) {
            r.push(
                "notifications",
                DiffKind::Removed,
                format!("channel:{id}"),
                "",
            );
        }
    }
    for (id, lc) in &l_idx {
        let Some(rc) = r_idx.get(id) else { continue };
        if lc.kind != rc.kind {
            r.push(
                "notifications",
                DiffKind::Changed,
                format!("channel:{id}.kind"),
                format!("{:?} → {:?}", lc.kind, rc.kind),
            );
        }
        if lc.target != rc.target {
            r.push(
                "notifications",
                DiffKind::Changed,
                format!("channel:{id}.target"),
                format!("{} → {}", lc.target, rc.target),
            );
        }
    }
    if l_def != r_def {
        r.push(
            "notifications",
            DiffKind::Changed,
            "default_channels",
            format!("{:?} → {:?}", l_def, r_def),
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human
// ────────────────────────────────────────────────────────────────────

fn render_human<W: Write>(out: &mut W, opts: &PolicyDiffOpts, report: &DiffReport) {
    let _ = writeln!(
        out,
        "policy diff: {} → {}",
        opts.left.display(),
        opts.right.display(),
    );
    if report.entries.is_empty() {
        let _ = writeln!(out, "  (no semantic differences)");
        return;
    }
    let _ = writeln!(
        out,
        "  {n} change{plural}:",
        n = report.entries.len(),
        plural = if report.entries.len() == 1 { "" } else { "s" },
    );
    for e in &report.entries {
        let _ = writeln!(
            out,
            "  [{kind:<7}] {section}::{label}{sep}{detail}",
            kind = e.kind.token(),
            section = e.section,
            label = e.label,
            sep = if e.detail.is_empty() { "" } else { "  " },
            detail = e.detail,
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — JSON
// ────────────────────────────────────────────────────────────────────

fn render_json<W: Write>(out: &mut W, opts: &PolicyDiffOpts, report: &DiffReport) {
    let v = serde_json::json!({
        "left":  opts.left.display().to_string(),
        "right": opts.right.display().to_string(),
        "count": report.entries.len(),
        "changes": report.entries.iter().map(|e| serde_json::json!({
            "section": e.section,
            "kind":    e.kind.token(),
            "label":   e.label,
            "detail":  e.detail,
        })).collect::<Vec<_>>(),
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn lane(id: &str, max_conc: u32, max_cost: u64) -> LaneEntry {
        LaneEntry {
            lane_id: id.to_owned(),
            max_concurrent_tasks: max_conc,
            max_cost_per_epoch: max_cost,
            priority: 100,
        }
    }

    #[test]
    fn parse_args_requires_two_positionals() {
        assert!(matches!(parse_args(&[]).unwrap_err(), CliError::Usage(_)));
        assert!(matches!(
            parse_args(&["one.toml".to_owned()]).unwrap_err(),
            CliError::Usage(_)
        ));
    }

    #[test]
    fn parse_args_accepts_two_paths_and_json_flag() {
        let o = parse_args(&[
            "left.toml".to_owned(),
            "right.toml".to_owned(),
            "--json".to_owned(),
        ])
        .unwrap();
        assert_eq!(o.left, PathBuf::from("left.toml"));
        assert_eq!(o.right, PathBuf::from("right.toml"));
        assert!(o.json);
    }

    #[test]
    fn diff_lanes_detects_added_removed_and_changed() {
        let l = vec![lane("a", 1, 10), lane("b", 1, 10)];
        let r = vec![lane("a", 2, 10), lane("c", 1, 10)];
        let mut report = DiffReport::default();
        diff_lanes(&mut report, &l, &r);
        let kinds: Vec<DiffKind> = report.entries.iter().map(|e| e.kind).collect();
        // We expect: a.max_concurrent_tasks Changed, b Removed, c Added.
        assert!(kinds.iter().any(|k| *k == DiffKind::Added));
        assert!(kinds.iter().any(|k| *k == DiffKind::Removed));
        assert!(kinds.iter().any(|k| *k == DiffKind::Changed));
    }

    #[test]
    fn diff_egress_reports_added_and_removed_independently() {
        let mut report = DiffReport::default();
        diff_egress(
            &mut report,
            &["a".to_owned(), "b".to_owned()],
            &["b".to_owned(), "c".to_owned()],
        );
        let entries: Vec<(&str, DiffKind)> = report
            .entries
            .iter()
            .map(|e| (e.label.as_str(), e.kind))
            .collect();
        assert!(entries
            .iter()
            .any(|(l, k)| *l == "c" && *k == DiffKind::Added));
        assert!(entries
            .iter()
            .any(|(l, k)| *l == "a" && *k == DiffKind::Removed));
        // "b" appears in both — must NOT be in the report.
        assert!(!entries.iter().any(|(l, _)| *l == "b"));
    }

    #[test]
    fn diff_gateway_added_when_only_right_has_section() {
        let g = GatewaySection {
            binary_path: "/bin/raxis-gateway".to_owned(),
            spawn_timeout_secs: 5,
            respawn_backoff_ms: 1000,
            max_consecutive_respawns: 5,
            planner_max_turns_default: None,
            planner_max_turns_step_default: None,
        };
        let mut report = DiffReport::default();
        diff_gateway(&mut report, None, Some(&g));
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].kind, DiffKind::Added);
        assert_eq!(report.entries[0].section, "gateway");
    }

    #[test]
    fn diff_gateway_changed_per_field() {
        let l = GatewaySection {
            binary_path: "/bin/old".to_owned(),
            spawn_timeout_secs: 5,
            respawn_backoff_ms: 1000,
            max_consecutive_respawns: 5,
            planner_max_turns_default: None,
            planner_max_turns_step_default: None,
        };
        let r = GatewaySection {
            binary_path: "/bin/new".to_owned(),
            spawn_timeout_secs: 10,
            respawn_backoff_ms: 1000,
            max_consecutive_respawns: 5,
            planner_max_turns_default: None,
            planner_max_turns_step_default: None,
        };
        let mut report = DiffReport::default();
        diff_gateway(&mut report, Some(&l), Some(&r));
        let labels: Vec<&str> = report.entries.iter().map(|e| e.label.as_str()).collect();
        assert!(labels.contains(&"binary_path"));
        assert!(labels.contains(&"spawn_timeout_secs"));
        assert!(!labels.contains(&"respawn_backoff_ms"));
    }

    #[test]
    fn render_human_says_no_diff_when_empty() {
        let mut buf: Vec<u8> = Vec::new();
        let opts = PolicyDiffOpts {
            left: PathBuf::from("L"),
            right: PathBuf::from("R"),
            json: false,
        };
        render_human(&mut buf, &opts, &DiffReport::default());
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("(no semantic differences)"), "got: {s}");
    }

    #[test]
    fn render_json_emits_count_and_changes_array() {
        let opts = PolicyDiffOpts {
            left: PathBuf::from("L"),
            right: PathBuf::from("R"),
            json: true,
        };
        let mut report = DiffReport::default();
        report.push("lanes", DiffKind::Added, "alpha", "");
        let mut buf: Vec<u8> = Vec::new();
        render_json(&mut buf, &opts, &report);
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["count"], 1);
        assert_eq!(v["changes"][0]["section"], "lanes");
        assert_eq!(v["changes"][0]["kind"], "added");
    }
}
