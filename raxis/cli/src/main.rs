// raxis-cli — Operator CLI for the RAXIS kernel.
//
// Normative reference: specs/v1/cli-ceremony.md §4.1 (subcommands) and
// §4.2 (genesis ceremony).
//
// All commands that require kernel connectivity open the operator UDS,
// perform the Ed25519 challenge-response handshake, then send a typed
// OperatorRequest frame. Commands that don't require the kernel (genesis,
// policy sign, audit verify) run locally.
//
// Wire protocol: length-prefixed JSON frames on operator.sock.
// Auth: challenge-response per ipc/auth.rs (challenge → response → dispatch).
//
// Usage:
//   raxis-cli [--data-dir <path>] [--socket <path>] [--operator-key <path>] <subcommand>

mod closeness;
mod commands;
mod conn;
mod errors;
mod reveal;
mod signing;

use std::path::PathBuf;

use closeness::unknown_with_suggestion;
use errors::CliError;

// ---------------------------------------------------------------------------
// Canonical subcommand catalog
//
// Single source of truth for the closeness-suggestion ("did you mean")
// machinery. Every `match` arm in `run` MUST appear in this catalog
// (and vice versa) so an unknown-subcommand error can produce
// useful guidance instead of a bare "unknown subcommand: ..." line.
//
// The two consistency tests at the bottom of this file
// (`top_level_catalog_matches_run_dispatch` and the per-subcommand
// `*_catalog_matches_run_dispatch` tests) hard-fail when the catalog
// drifts from the dispatcher.
// ---------------------------------------------------------------------------

const TOP_LEVEL_SUBCOMMANDS: &[&str] = &[
    "genesis", "policy", "plan", "initiative", "operator", "task", "session",
    "delegation", "escalation", "epoch", "audit", "cert",
    "status", "log", "verify-chain", "queue", "inspect", "sessions",
    "escalations", "inbox", "doctor", "verifiers", "witnesses", "budget",
    "explain", "top",
];

const POLICY_SUBCOMMANDS:      &[&str] = &["sign", "show", "diff"];
const PLAN_SUBCOMMANDS:        &[&str] = &["submit", "approve", "reject"];
const INITIATIVE_SUBCOMMANDS:  &[&str] = &["abort", "quarantine"];
const OPERATOR_SUBCOMMANDS:    &[&str] = &["quarantine-plans-by"];
const TASK_SUBCOMMANDS:        &[&str] = &["abort", "resume", "retry"];
const SESSION_SUBCOMMANDS:     &[&str] = &["create", "revoke"];
const DELEGATION_SUBCOMMANDS:  &[&str] = &["grant"];
const ESCALATION_SUBCOMMANDS:  &[&str] = &["approve", "deny"];
const EPOCH_SUBCOMMANDS:       &[&str] = &["advance"];
const AUDIT_SUBCOMMANDS:       &[&str] = &["verify"];
const CERT_SUBCOMMANDS:        &[&str] = &[
    "mint", "mint-emergency", "show", "verify", "list", "install",
];

// ---------------------------------------------------------------------------
// Global CLI flags
// ---------------------------------------------------------------------------

struct GlobalFlags {
    data_dir: PathBuf,
    socket_path: Option<PathBuf>,
    operator_key_path: Option<PathBuf>,
}

impl GlobalFlags {
    fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    fn socket_path(&self) -> PathBuf {
        self.socket_path.clone().unwrap_or_else(|| {
            self.data_dir.join("sockets").join("operator.sock")
        })
    }
}

// ---------------------------------------------------------------------------
// Entry point — manual arg parsing (no external clap dep in v1)
// ---------------------------------------------------------------------------

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), CliError> {
    let args: Vec<String> = std::env::args().collect();
    let mut pos = 1usize;

    // Global flags.
    let mut data_dir: PathBuf = std::env::var("RAXIS_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_owned());
            PathBuf::from(home).join(".raxis")
        });
    let mut socket_path: Option<PathBuf> = None;
    let mut operator_key_path: Option<PathBuf> = None;

    while pos < args.len() {
        match args[pos].as_str() {
            "--data-dir" => {
                pos += 1;
                data_dir = PathBuf::from(require_arg(&args, pos, "--data-dir")?);
            }
            "--socket" => {
                pos += 1;
                socket_path = Some(PathBuf::from(require_arg(&args, pos, "--socket")?));
            }
            "--operator-key" => {
                pos += 1;
                operator_key_path =
                    Some(PathBuf::from(require_arg(&args, pos, "--operator-key")?));
            }
            _ => break,
        }
        pos += 1;
    }

    let flags = GlobalFlags {
        data_dir,
        socket_path,
        operator_key_path,
    };

    // Subcommand dispatch.
    let subcmd = args.get(pos).map(|s| s.as_str()).unwrap_or("");
    // `rest` is everything after the subcommand token. When `pos` is at
    // or past the end of `args`, slicing `args[pos+1..]` would panic; we
    // guard with `min(args.len())` so the result is an empty slice.
    let rest_start = pos.saturating_add(1).min(args.len());
    let rest = &args[rest_start..];

    match subcmd {
        "genesis" => commands::genesis::run(&flags, rest),
        "policy" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "sign" => commands::policy::run_sign(&flags, &rest[1..]),
                "show" => commands::policy_show::run(&flags, &rest[1..]),
                "diff" => commands::policy_diff::run(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "policy sub-command", sub2, POLICY_SUBCOMMANDS,
                ))),
            }
        }
        "plan" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "submit" => commands::plan::run_submit(&flags, &rest[1..]),
                "approve" => commands::plan::run_approve(&flags, &rest[1..]),
                "reject" => commands::plan::run_reject(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "plan sub-command", sub2, PLAN_SUBCOMMANDS,
                ))),
            }
        }
        "initiative" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "abort"      => commands::initiative::run_abort(&flags, &rest[1..]),
                "quarantine" => commands::initiative::run_quarantine(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "initiative sub-command", sub2, INITIATIVE_SUBCOMMANDS,
                ))),
            }
        }
        "operator" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "quarantine-plans-by" => {
                    commands::operator::run_quarantine_plans_by(&flags, &rest[1..])
                }
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "operator sub-command", sub2, OPERATOR_SUBCOMMANDS,
                ))),
            }
        }
        "task" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "abort" => commands::task::run_abort(&flags, &rest[1..]),
                "resume" => commands::task::run_resume(&flags, &rest[1..]),
                "retry" => commands::task::run_retry(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "task sub-command", sub2, TASK_SUBCOMMANDS,
                ))),
            }
        }
        "session" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "create" => commands::session::run_create(&flags, &rest[1..]),
                "revoke" => commands::session::run_revoke(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "session sub-command", sub2, SESSION_SUBCOMMANDS,
                ))),
            }
        }
        "delegation" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "grant" => commands::delegation::run_grant(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "delegation sub-command", sub2, DELEGATION_SUBCOMMANDS,
                ))),
            }
        }
        "escalation" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "approve" => commands::escalation::run_approve(&flags, &rest[1..]),
                "deny" => commands::escalation::run_deny(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "escalation sub-command", sub2, ESCALATION_SUBCOMMANDS,
                ))),
            }
        }
        "epoch" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "advance" => commands::epoch::run_advance(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "epoch sub-command", sub2, EPOCH_SUBCOMMANDS,
                ))),
            }
        }
        "audit" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "verify" => commands::audit::run_verify(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "audit sub-command", sub2, AUDIT_SUBCOMMANDS,
                ))),
            }
        }
        "cert" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "mint"           => commands::cert::run_mint(&flags, &rest[1..]),
                "mint-emergency" => commands::cert::run_mint_emergency(&flags, &rest[1..]),
                "show"           => commands::cert::run_show(&flags, &rest[1..]),
                "verify"         => commands::cert::run_verify(&flags, &rest[1..]),
                "list"           => commands::cert::run_list(&flags, &rest[1..]),
                "install"        => commands::cert::run_install(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "cert sub-command", sub2, CERT_SUBCOMMANDS,
                ))),
            }
        }
        "status" => commands::status::run(&flags, rest),
        "log" => commands::log::run(&flags, rest),
        "verify-chain" => commands::verify_chain::run(&flags, rest),
        "queue" => commands::queue::run(&flags, rest),
        "inspect" => commands::inspect::run(&flags, rest),
        "sessions" => commands::sessions::run(&flags, rest),
        "escalations" => commands::escalations::run(&flags, rest),
        "inbox" => commands::inbox::run(&flags, rest),
        "doctor" => commands::doctor::run(&flags, rest),
        "verifiers" => commands::verifiers::run(&flags, rest),
        "witnesses" => commands::witnesses::run(&flags, rest),
        "budget" => commands::budget::run(&flags, rest),
        "explain" => commands::explain::run(&flags, rest),
        "top" => commands::top::run(&flags, rest),
        "" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(CliError::Usage(unknown_with_suggestion(
            "subcommand", other, TOP_LEVEL_SUBCOMMANDS,
        ))),
    }
}

fn require_arg<'a>(args: &'a [String], pos: usize, flag: &str) -> Result<&'a str, CliError> {
    args.get(pos)
        .map(|s| s.as_str())
        .ok_or_else(|| CliError::Usage(format!("{flag} requires an argument")))
}

fn print_help() {
    println!(
        r#"raxis — RAXIS kernel operator CLI

USAGE:
    raxis [--data-dir <path>] [--socket <path>] [--operator-key <path>] <subcommand>

GLOBAL FLAGS:
    --data-dir <path>       Kernel data directory (default: ~/.raxis or $RAXIS_DATA_DIR)
    --socket <path>         Operator socket path (default: <data-dir>/sockets/operator.sock)
    --operator-key <path>   Operator Ed25519 private key for signing (PEM format)

SUBCOMMANDS:
    genesis [--force] [--operator-pubkey <path>]
        Run the initial key generation ceremony.

    policy sign <artifact.toml> --key <path>
        Sign a policy or plan artifact with the operator's private key.

    plan submit <initiative_id> <plan_dir>
        Submit a signed plan (plan.toml + plan.sig) to create an initiative.

    plan approve <initiative_id>
        Approve a pending initiative, admitting all tasks to the scheduler.

    plan reject <initiative_id>
        Reject a pending initiative without instantiating tasks.

    initiative abort <initiative_id>
        Force-terminate an initiative and bulk-cancel all non-terminal tasks.

    initiative quarantine <initiative_id> [--reason <text>]
        Freeze an initiative — every subsequent IntentRequest is
        rejected by the kernel with FAIL_INITIATIVE_QUARANTINED.
        In-flight tasks are NOT aborted (use `initiative abort` for
        that). Reason is capped at 512 bytes server-side and mirrored
        into the audit chain.

    operator quarantine-plans-by <target_fingerprint> [--reason <text>]
        Sweep every initiative whose plan was approved by the given
        operator fingerprint and quarantine each one in a single
        atomic transaction. Used as the immediate containment
        primitive when an operator key is suspected compromised;
        operator-key removal is a separate `policy sign` + `epoch
        advance` ceremony.

    task abort <task_id>
        Abort a running task immediately.

    task resume <task_id>
        Resume a BlockedRecoveryPending task after kernel crash recovery.

    task retry <task_id>
        Retry a Failed task (transitions Failed → Admitted).

    session create --role planner --worktree-root <path> [--lineage-id <uuid>]
                   [--base-tracking-ref <ref>] [--task <task_id>] [--reveal-token]
        Create a planner session. By default prints only a redacted
        session_token fingerprint to stderr; pass --reveal-token to
        print the raw RAXIS_SESSION_TOKEN value (typically captured
        with `2>session.env`).

    session revoke <session_id>
        Revoke an active session; subsequent IPC frames from that session are rejected.

    delegation grant --session <id> --capability <class> --role <role_id> --ttl <secs>
        Grant a capability delegation to a session for a bounded TTL.

    escalation approve <escalation_id> --scope <capability_class> --max-uses <n> --valid-for <secs>
                       [--reveal-token]
        Approve a pending escalation and issue an approval token. By
        default prints only the token id and fingerprint; pass
        --reveal-token to print approval_token_raw to stdout.

    escalation deny <escalation_id> [--reason <text>]
        Deny a pending escalation.

    epoch advance --policy <path> --sig <path>
        Advance the policy epoch by loading a new signed policy artifact.

    audit verify [--log-path <path>]
        Verify the integrity of the JSONL audit log chain.

READ-ONLY OBSERVATION:

    status [--json]
        One-screen kernel health snapshot. Reads heartbeat.json + a
        read-only kernel.db handle. Exit codes: 0 live, 1 stopped,
        2 ambiguous (heartbeat fresh but PID gone), 3 chain break.

    log [<initiative_id>] [--task <id>] [--session <id>] [--kind <substr>]
        [--since <duration>] [--limit <N>] [--json] [-f|--follow]
        Stream or page through the audit chain with filter combinators.
        --follow polls every 100ms; Ctrl-C exits cleanly.

    verify-chain [--quick] [--from <seq>] [--audit-dir <path>]
        Walk every audit segment, verify prev_sha256 + seq monotonicity.
        Exit 0 intact, 3 broken. --quick mirrors `raxis status`'s check.
        --from <seq> narrows the reported stats to records with seq ≥ <seq>;
        the whole chain is still walked end-to-end for linkage.

    queue [--lane <id>] [--blocked-only] [--limit <N>]
        DAG scheduler state — READY (Admitted | GatesPending) and
        BLOCKED (BlockedRecoveryPending) tables, plus the
        approximate pending-verifier-spawns count from heartbeat.

    inspect <task_id> [--json] [--gates-only] [--with-deps] [--reveal-paths]
        Forensic deep-dive into a single task: state, dependencies,
        witnesses. --reveal-paths shows path_allowlist + path_export_globs
        AND appends a PathReadAccessed audit event (cli-readonly.md §5.4.2).

    sessions [--limit N] [--json]
        List currently-active planner / gateway / verifier sessions
        and the global active/expired/revoked counts.

    escalations [--status pending|approved|denied|all] [--limit N] [--json]
        List escalations filtered by status (default: pending).

    policy show [--json] [--history]
        Print the active policy bundle and (optionally) the
        policy_epoch_history table.

    inbox [--kind K] [--since DURATION] [--limit N] [--json]
        Read <data_dir>/notifications/inbox.jsonl. Exit code 2 when
        the inbox file does not exist yet.

    doctor [--json]
        Preflight checks against <data_dir>: subdir presence + mode
        bits, policy.toml loadability, kernel.db schema pin,
        heartbeat freshness, audit chain quick-check, bundle/kernel
        epoch alignment.

    verifiers [--recent] [--limit N] [--json]
        Outstanding verifier subprocess tokens (default), or the
        last N issued tokens regardless of state with --recent.
        Heartbeat snapshot of active/max-concurrent runners.

    witnesses <task_id> [--gate G] [--result Pass|Fail|Inconclusive]
                        [--limit N] [--json]
        Witness records for one task, newest-first. Exit code 4
        when the task has no witnesses recorded yet.

    budget [<lane_id>] [--limit N] [--json]
        Per-lane budget pressure (reserved / max_cost_per_epoch).
        Drill into one lane's reservations by passing <lane_id>.

    explain <task_id> [--json]
        Decision-tree explanation for one task: state classification,
        unsatisfied predecessors, per-gate witness summary, plus the
        last 5 audit events tagged with the task. Exit 4 if missing.

    policy diff <left.toml> <right.toml> [--json]
        Semantic diff between two validated policy bundles. Reports
        per-section deltas (lanes, operators, gates, egress,
        gateway, providers, notifications) — not a textual diff.

    top [--interval N] [--once] [--no-clear]
        Auto-refreshing kernel snapshot (heartbeat + workload counts).
        Default interval: 2s. Use --once for one-shot; --no-clear
        disables ANSI clear-screen for log-friendly output.
"#
    );
}

// ---------------------------------------------------------------------------
// Catalog ↔ dispatcher consistency tests
//
// These tests exist purely to catch drift between the
// `*_SUBCOMMANDS` constants used for "did you mean" closeness
// suggestions and the `match` arms in `run`. If a new arm is added
// without updating the constant (or vice-versa), the CLI would print
// misleading suggestions ("did you mean `mint`?" when the dispatcher
// has actually been renamed to `issue`) — which is worse than no
// suggestion at all.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod catalog_consistency_tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::fs;

    /// Resolve `cli/src/main.rs` from `CARGO_MANIFEST_DIR` so the
    /// tests work regardless of the workspace test runner's CWD.
    fn main_rs_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("main.rs")
    }

    /// Source of truth: scrape the literal arm-strings out of the
    /// `match subcmd` in `fn run(...)` from this very file.
    ///
    /// We deliberately do NOT parse Rust syntax — a regex over the
    /// raw source is sufficient because every dispatcher arm in
    /// `run` follows the convention `"<name>" => commands::...` or
    /// `"<name>" => { ... }`.
    fn dispatcher_top_level_arms() -> BTreeSet<String> {
        let src = fs::read_to_string(main_rs_path())
            .expect("read main.rs source for catalog drift check");
        // Extract the `fn run` body to avoid catching arms from nested
        // inner `match`es when scanning the whole file.
        let run_body = extract_block(&src, "fn run(args: &[String]) -> Result")
            .or_else(|| extract_block(&src, "fn run() -> Result"))
            .unwrap_or_else(|| src.clone());
        // Top-level arms are those at the outermost `match subcmd`.
        // We approximate: take string literals immediately preceding
        // `=>` that are NOT preceded by another `match` keyword on
        // the same line. The catalog test below catches false
        // positives for us.
        scrape_arms(&run_body)
    }

    /// Extract a balanced-brace block immediately following the
    /// signature substring `needle`.
    fn extract_block(src: &str, needle: &str) -> Option<String> {
        let start = src.find(needle)?;
        let body_start = src[start..].find('{').map(|o| start + o)?;
        let mut depth = 0;
        for (i, c) in src[body_start..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(src[body_start..=body_start + i].to_owned());
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Returns the set of literal arm names found in the OUTERMOST
    /// `match` of the block.
    fn scrape_arms(block: &str) -> BTreeSet<String> {
        // Find the outermost `match subcmd {` and bound the scan there.
        let Some(match_at) = block.find("match subcmd {") else {
            return BTreeSet::new();
        };
        let after_match = &block[match_at + "match subcmd {".len()..];
        let Some(body) = balanced_match_body(after_match) else {
            return BTreeSet::new();
        };
        // Only collect arms at brace-depth 0 within the match body so
        // we don't pick up inner `match sub2` arms.
        let mut out = BTreeSet::new();
        let mut depth = 0usize;
        let mut chars = body.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            match c {
                '{' => depth += 1,
                '}' => depth = depth.saturating_sub(1),
                '"' if depth == 0 => {
                    let start = i + 1;
                    let mut end = start;
                    for (j, cc) in body[start..].char_indices() {
                        if cc == '"' && !body[start..start + j].ends_with('\\') {
                            end = start + j;
                            break;
                        }
                    }
                    let lit = &body[start..end];
                    let after = body[end + 1..].trim_start();
                    if after.starts_with("=>") || after.starts_with("|") {
                        if !lit.is_empty()
                            && lit != "--help"
                            && lit != "-h"
                            && !lit.contains(' ')
                        {
                            out.insert(lit.to_owned());
                        }
                    }
                    while let Some(&(_, ch)) = chars.peek() {
                        if ch == '"' { chars.next(); break; }
                        chars.next();
                    }
                }
                _ => {}
            }
        }
        out
    }

    fn balanced_match_body(src: &str) -> Option<&str> {
        let mut depth = 1usize;
        for (i, c) in src.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&src[..i]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    #[test]
    fn top_level_catalog_matches_dispatcher_arms() {
        let from_dispatcher = dispatcher_top_level_arms();
        let from_catalog: BTreeSet<String> = TOP_LEVEL_SUBCOMMANDS
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let only_in_dispatcher: Vec<&String> =
            from_dispatcher.difference(&from_catalog).collect();
        let only_in_catalog: Vec<&String> =
            from_catalog.difference(&from_dispatcher).collect();
        assert!(
            only_in_dispatcher.is_empty() && only_in_catalog.is_empty(),
            "TOP_LEVEL_SUBCOMMANDS drift!\n  in dispatcher only: {only_in_dispatcher:?}\n  in catalog only:    {only_in_catalog:?}"
        );
    }

    /// Static spot-check that every per-parent catalog has at least
    /// one entry — guarantees the closeness machinery has SOMETHING
    /// to suggest from for every parent command.
    #[test]
    fn per_parent_catalogs_are_non_empty() {
        for (name, list) in [
            ("policy",     POLICY_SUBCOMMANDS),
            ("plan",       PLAN_SUBCOMMANDS),
            ("initiative", INITIATIVE_SUBCOMMANDS),
            ("operator",   OPERATOR_SUBCOMMANDS),
            ("task",       TASK_SUBCOMMANDS),
            ("session",    SESSION_SUBCOMMANDS),
            ("delegation", DELEGATION_SUBCOMMANDS),
            ("escalation", ESCALATION_SUBCOMMANDS),
            ("epoch",      EPOCH_SUBCOMMANDS),
            ("audit",      AUDIT_SUBCOMMANDS),
            ("cert",       CERT_SUBCOMMANDS),
        ] {
            assert!(!list.is_empty(), "{name}_SUBCOMMANDS is empty");
        }
    }

    /// Walks the same source file and verifies that every per-parent
    /// catalog contains exactly the literal arm names dispatched
    /// inside that parent's `match sub2` block.
    #[test]
    fn per_parent_catalogs_match_dispatcher_arms() {
        let src = fs::read_to_string(main_rs_path()).expect("read main.rs source");

        let pairs: &[(&str, &[&str])] = &[
            ("\"policy\" =>",     POLICY_SUBCOMMANDS),
            ("\"plan\" =>",       PLAN_SUBCOMMANDS),
            ("\"initiative\" =>", INITIATIVE_SUBCOMMANDS),
            ("\"operator\" =>",   OPERATOR_SUBCOMMANDS),
            ("\"task\" =>",       TASK_SUBCOMMANDS),
            ("\"session\" =>",    SESSION_SUBCOMMANDS),
            ("\"delegation\" =>", DELEGATION_SUBCOMMANDS),
            ("\"escalation\" =>", ESCALATION_SUBCOMMANDS),
            ("\"epoch\" =>",      EPOCH_SUBCOMMANDS),
            ("\"audit\" =>",      AUDIT_SUBCOMMANDS),
            ("\"cert\" =>",       CERT_SUBCOMMANDS),
        ];

        for (anchor, catalog) in pairs {
            let arms = scrape_inner_match_arms(&src, anchor);
            let want: BTreeSet<String> =
                catalog.iter().map(|s| (*s).to_owned()).collect();
            let only_in_dispatcher: Vec<&String> =
                arms.difference(&want).collect();
            let only_in_catalog: Vec<&String> =
                want.difference(&arms).collect();
            assert!(
                only_in_dispatcher.is_empty() && only_in_catalog.is_empty(),
                "{anchor} catalog drift!\n  in dispatcher only: {only_in_dispatcher:?}\n  in catalog only:    {only_in_catalog:?}"
            );
        }
    }

    /// Scrape the inner `match sub2 { ... }` body that follows the
    /// supplied anchor, and return the literal arm names.
    fn scrape_inner_match_arms(src: &str, anchor: &str) -> BTreeSet<String> {
        let Some(idx) = src.find(anchor) else {
            return BTreeSet::new();
        };
        let after = &src[idx..];
        let Some(match_at) = after.find("match sub2 {") else {
            return BTreeSet::new();
        };
        let body_after = &after[match_at + "match sub2 {".len()..];
        let Some(body) = balanced_match_body(body_after) else {
            return BTreeSet::new();
        };
        let mut out = BTreeSet::new();
        let mut depth = 0usize;
        for (i, c) in body.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => depth = depth.saturating_sub(1),
                '"' if depth == 0 => {
                    let start = i + 1;
                    let rest = &body[start..];
                    let Some(end_off) = rest.find('"') else { continue };
                    let lit = &rest[..end_off];
                    let after_lit = body[start + end_off + 1..].trim_start();
                    if after_lit.starts_with("=>") && !lit.is_empty() {
                        out.insert(lit.to_owned());
                    }
                }
                _ => {}
            }
        }
        out
    }
}
