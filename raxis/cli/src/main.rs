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
mod operator_display;
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
    "delegation", "escalation", "epoch", "audit", "cert", "credential", "kernel",
    "submit",
    "status", "log", "verify-chain", "queue", "inspect",
    "sessions", "escalations", "inbox", "doctor", "verifiers", "witnesses",
    "budget", "explain", "top",
    // V2_GAPS §C10 / §12.6 — non-interactive first-run scaffolding.
    "setup",
];

const POLICY_SUBCOMMANDS:      &[&str] = &["sign", "show", "diff", "generate-sidecar-secret"];
const PLAN_SUBCOMMANDS:        &[&str] = &["approve", "reject", "validate", "fmt", "init"];
/// V2.1 atomic plan-bundle submit. Spec: plan-bundle-sealing.md §4.
/// Currently exposes only `plan`; future sub-commands (`policy`,
/// `operator-cert`) will plug in here without a third rename.
const SUBMIT_SUBCOMMANDS:      &[&str] = &["plan"];
const INITIATIVE_SUBCOMMANDS:  &[&str] = &["abort", "list", "quarantine", "show"];
const OPERATOR_SUBCOMMANDS:    &[&str] = &["quarantine-plans-by"];
const TASK_SUBCOMMANDS:        &[&str] = &["abort", "resume", "retry", "outputs"];
const SESSION_SUBCOMMANDS:     &[&str] = &["create", "revoke"];
const DELEGATION_SUBCOMMANDS:  &[&str] = &["grant"];
const ESCALATION_SUBCOMMANDS:  &[&str] = &["approve", "deny"];
const EPOCH_SUBCOMMANDS:       &[&str] = &["advance"];
const AUDIT_SUBCOMMANDS:       &[&str] = &["verify"];
const CERT_SUBCOMMANDS:        &[&str] = &[
    "mint", "mint-emergency", "show", "verify", "list", "install",
    // V2_GAPS §D1 — operator-cert revocation (admission-time MVP).
    "revoke", "list-revocations",
];
/// V2 §extensibility-traits.md §4 — local-only credential ops.
/// MVP scope (V2 GA) is the seven-command catalogue from
/// credential-proxy.md §12: `list`, `rotate`, `add`, `show`,
/// `remove`, `verify`, `audit`. The full per-proxy-type
/// validators (kubeconfig / AWS JSON / postgres URI parse) and
/// live-network `verify` probes are V3 — V2 stores bytes
/// verbatim and verifies structurally.
const CREDENTIAL_SUBCOMMANDS:  &[&str] = &[
    "list", "rotate", "add", "show", "remove", "verify", "audit",
];
/// V2 §kernel-lifecycle.md §3 — daemon mode. The MVP ships
/// `install` and `uninstall` (template + place / remove the
/// platform unit file). The full surface (`start --daemon`,
/// `stop`, `status`, `restart` with sd_notify and single-instance
/// enforcement) is a follow-up phase per kernel-lifecycle.md
/// §"Implementation checklist".
const KERNEL_SUBCOMMANDS:      &[&str] = &["install", "uninstall"];

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

    // Env-var fallback for `--operator-key`. Explicit flag wins; the
    // env var is consulted only when no flag was passed. We thread the
    // resolution through a pure helper (`resolve_operator_key_path`)
    // so the precedence rules are unit-testable without spinning up
    // the full CLI. The env var stores a *file path*, never the key
    // bytes themselves — see `specs/v1/env-vars.md` "Security model".
    let operator_key_path = resolve_operator_key_path(operator_key_path, |k| {
        std::env::var_os(k).map(PathBuf::from)
    });

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
                "generate-sidecar-secret" => {
                    commands::policy::run_generate_sidecar_secret(&flags, &rest[1..])
                }
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "policy sub-command", sub2, POLICY_SUBCOMMANDS,
                ))),
            }
        }
        "plan" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "approve"  => commands::plan::run_approve(&flags, &rest[1..]),
                "reject"   => commands::plan::run_reject(&flags, &rest[1..]),
                "validate" => commands::plan_validate::run(&flags, &rest[1..]),
                "fmt"      => commands::plan_fmt::run(&flags, &rest[1..]),
                "init"     => commands::plan_init::run(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "plan sub-command", sub2, PLAN_SUBCOMMANDS,
                ))),
            }
        }
        "initiative" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "abort"      => commands::initiative::run_abort(&flags, &rest[1..]),
                "list"       => commands::initiatives::run(&flags, &rest[1..]),
                "quarantine" => commands::initiative::run_quarantine(&flags, &rest[1..]),
                "show"       => commands::initiative_show::run(&flags, &rest[1..]),
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
                "outputs" => commands::task::run_outputs(&flags, &rest[1..]),
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
                "mint"             => commands::cert::run_mint(&flags, &rest[1..]),
                "mint-emergency"   => commands::cert::run_mint_emergency(&flags, &rest[1..]),
                "show"             => commands::cert::run_show(&flags, &rest[1..]),
                "verify"           => commands::cert::run_verify(&flags, &rest[1..]),
                "list"             => commands::cert::run_list(&flags, &rest[1..]),
                "install"          => commands::cert::run_install(&flags, &rest[1..]),
                "revoke"           => commands::cert::run_revoke(&flags, &rest[1..]),
                "list-revocations" => commands::cert::run_list_revocations(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "cert sub-command", sub2, CERT_SUBCOMMANDS,
                ))),
            }
        }
        "submit" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "plan" => commands::submit::run_plan(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "submit sub-command", sub2, SUBMIT_SUBCOMMANDS,
                ))),
            }
        }
        "credential" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "list"   => commands::credential::run_list  (&flags, &rest[1..]),
                "rotate" => commands::credential::run_rotate(&flags, &rest[1..]),
                "add"    => commands::credential::run_add   (&flags, &rest[1..]),
                "show"   => commands::credential::run_show  (&flags, &rest[1..]),
                "remove" => commands::credential::run_remove(&flags, &rest[1..]),
                "verify" => commands::credential::run_verify(&flags, &rest[1..]),
                "audit"  => commands::credential::run_audit (&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "credential sub-command", sub2, CREDENTIAL_SUBCOMMANDS,
                ))),
            }
        }
        "kernel" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "install"   => commands::kernel::run_install(&flags, &rest[1..]),
                "uninstall" => commands::kernel::run_uninstall(&flags, &rest[1..]),
                _ => Err(CliError::Usage(unknown_with_suggestion(
                    "kernel sub-command", sub2, KERNEL_SUBCOMMANDS,
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
        "setup" => commands::setup::run(&flags, rest),
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

/// Precedence resolver for `--operator-key` / `RAXIS_OPERATOR_KEY`.
///
/// Rules (pinned by `operator_key_resolution_*` tests below):
///
/// 1. Explicit `--operator-key <path>` (the `flag_value`) always
///    wins, even if `RAXIS_OPERATOR_KEY` is set. Defence-in-depth:
///    a stale shell export must not silently override the path the
///    operator just typed.
/// 2. If no flag was passed, fall back to `RAXIS_OPERATOR_KEY`
///    looked up through `env_lookup`. The lookup is injected so
///    tests can drive both branches without mutating the real
///    process environment (which would race with parallel cargo
///    test runners).
/// 3. If neither is set, return `None` and let the per-subcommand
///    validation surface the standard
///    "usage: --operator-key <path> is required" error so the
///    operator sees the same message they would have seen before
///    the env-var fallback existed (no silent skipping).
///
/// Security model: the env var stores a **path** (which is then
/// `chmod 600` on disk), never the key bytes themselves. This
/// preserves the §"Security model" invariant in
/// `specs/v1/env-vars.md` — no secret material ever transits the
/// process environment, where it would be visible to `ps eww`,
/// `/proc/$pid/environ`, kernel-exported core dumps, and any child
/// process inheriting the env block.
fn resolve_operator_key_path(
    flag_value: Option<PathBuf>,
    env_lookup: impl FnOnce(&str) -> Option<PathBuf>,
) -> Option<PathBuf> {
    flag_value.or_else(|| env_lookup("RAXIS_OPERATOR_KEY"))
}

fn print_help() {
    println!(
        r#"raxis — RAXIS kernel operator CLI

USAGE:
    raxis [--data-dir <path>] [--socket <path>] [--operator-key <path>] <subcommand>

GLOBAL FLAGS:
    --data-dir <path>       Kernel data directory
                            (default: ~/.raxis or $RAXIS_DATA_DIR)
    --socket <path>         Operator socket path
                            (default: <data-dir>/sockets/operator.sock)
    --operator-key <path>   Operator Ed25519 private key for signing (PEM format).
                            Falls back to $RAXIS_OPERATOR_KEY when not passed.
                            Stores a path only; the env var must NEVER hold
                            key bytes. See specs/v1/env-vars.md.

SUBCOMMANDS:
    genesis [--force]
            (--operator-cert <path> | --operator-key <path> --operator-name <name>
                                                            [--cert-validity-days <days>])
            [--force-misconfig]
        Run the initial key generation ceremony. Operator identity is
        cert-mandatory (INV-CERT-01); supply EITHER a pre-minted
        `*.cert.toml` (air-gapped: produced by `raxis cert mint` on a
        separate machine) OR a private-key PEM (the CLI mints the cert
        in-process; private bytes are never persisted).

    policy sign <artifact.toml> --key <path>
        Sign a policy.toml or other non-plan artifact with the operator's
        private key. Plans are signed and submitted atomically through
        `submit plan <plan.toml>`; this command intentionally rejects
        `plan.toml` artifacts (plan-bundle-sealing.md §4).

    submit plan <plan.toml> [--initiative-id <id>] [--dry-run | --no-dry-run]
        V2.1 atomic plan-bundle submission — the ONLY way to admit a
        plan to the kernel. Reads plan.toml, builds the canonical
        bundle, stamps a fresh nonce + signed_at, signs in memory, and
        submits via the V2 IPC envelope (kernel admission landed per
        plan-bundle-sealing.md §8.1). There is no intermediate
        `plan.sig` file. The default is `--dry-run`; pass `--no-dry-run`
        to commit the bundle to the kernel.

    plan approve <initiative_id>
        Approve a pending initiative, admitting all tasks to the scheduler.

    plan reject <initiative_id>
        Reject a pending initiative without instantiating tasks.

    plan validate <plan.toml>
        Local-only structural pre-flight for plan.toml. Catches the
        operator's common mistakes (TOML syntax, missing
        `[workspace] lane_id`, per-task `lane_id` overrides,
        Orchestrator declarations, invalid `clone_strategy`,
        duplicate / self-loop / dangling / cyclic predecessors,
        glob characters in `cross_cutting_artifacts` or
        `path_allowlist`) before the signed-bundle round-trip
        through `submit plan`. Exits 0 on success, non-zero on the
        first violation.

    plan fmt <plan.toml> [--check] [--stdout]
        Canonicalize plan.toml's formatting (2-space indent, trailing
        whitespace stripped, blank lines normalised, final newline
        ensured) while preserving all comments — including
        `@raxis-default` annotations. `--check` is a CI gate that
        exits non-zero if the file is not already canonical;
        `--stdout` prints the canonical bytes without modifying
        the file.

    initiative abort <initiative_id>
        Force-terminate an initiative and bulk-cancel all non-terminal tasks.

    initiative list [--state active|completed|quarantined|all] [--limit N] [--json]
        Read-only bucketed listing of initiatives. Default bucket is
        `active` (non-terminal states only). The `quarantined` bucket
        is orthogonal to the FSM — it returns ANY initiative with a
        row in `initiative_quarantines`, regardless of state. Each
        row carries a `[Q]` marker (or `quarantined: true` in JSON)
        when frozen. Reads kernel.db read-only; no kernel IPC.

    initiative quarantine <initiative_id> [--reason <text>]
        Freeze an initiative — every subsequent IntentRequest is
        rejected by the kernel with FAIL_INITIATIVE_QUARANTINED.
        In-flight tasks are NOT aborted (use `initiative abort` for
        that). Reason is capped at 512 bytes server-side and mirrored
        into the audit chain.

    initiative show <initiative_id>
                    [--bundle] [--to <dir>] [--json]
                    [--with-tasks] [--task-limit N]
        Canonical forensic surface for one initiative
        (plan-bundle-sealing.md §8.5). Always prints the base header
        (initiative id / state / created-at), the plan-bundle
        envelope summary (sha-256 prefix, schema version, signed-by
        operator-display, sealed-at, signed-at, artifact count,
        total bytes), and the quarantine block. Pass `--with-tasks`
        (with optional `--task-limit N`, default 100) to expand the
        per-task table; without it the renderer prints just the
        task count. With `--bundle`: adds the per-artifact
        `(seq, name)` listing. With `--bundle --to <dir>`: extracts
        every artifact under <dir>, preserving artifact_name as the
        relative path. Refuses to write into a non-empty directory.
        `--json` is supported in every mode except `--to` (where the
        side-effect IS the output). Reads kernel.db read-only; no
        kernel IPC.

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

    credential list [--json]
        List registered credentials (metadata only — never the value).
        Reads <data-dir>/credentials/*.env and <data-dir>/providers/*.toml
        directly; the kernel does not need to be running.

    credential rotate <name> [--stdin | --file <path> | --interactive]
        Replace the bytes of an existing credential through an atomic
        temp-write + rename ceremony. The new value is read via
        stdin (default), a file on disk, or a hidden terminal prompt.
        --value <bytes> is REJECTED — secrets must never enter argv.

    credential add <name> [--type <label>] [--env <label>] [--desc <text>]
        [--stdin | --file <path> | --interactive]
        Register a NEW credential (refuses if the credential
        already exists; use `rotate` to update). V2 stores the
        bytes verbatim; per-type validators are V3.

    credential show <name> [--json]
        Print metadata for a single credential (size, mode, uid,
        mtime). Values are NEVER printed.

    credential remove <name> --force
        Unlink a credential file. V2 requires --force because the
        CLI cannot probe active sessions without a live kernel
        IPC. Emits a CredentialRemoved{{forced=true}} record.

    credential verify <name> [--type <label>] [--timeout <ms>]
        V2 structural verification (mode 0600, uid match, body
        non-empty, env-form parse). Live network verification
        is V3. Emits CredentialVerified{{success=...,latency_ms=...}}.

    credential audit <name> [--limit <n>] [--since <duration>] [--json]
        Show the audit history for a credential, merging the
        operator-local CLI trail (<data-dir>/audit/credential-cli.jsonl)
        with the kernel main audit chain segments.

    kernel install [--system] [--binary <path>] [--force]
        Install RAXIS as a platform-native daemon. Writes a systemd
        unit (Linux) or launchd plist (macOS) populated with this
        binary's resolved raxis-kernel path and the operator's
        --data-dir. Without --system the unit is installed under
        the invoking user; with --system it is installed at the
        system level (sudo required). Prints the next-step
        `systemctl --user enable --now raxis-kernel` (Linux) or
        `launchctl bootstrap` (macOS) to start the service.

    kernel uninstall [--system]
        Remove the unit file written by `kernel install`. Does NOT
        stop a currently-running kernel; print the `systemctl
        disable` / `launchctl bootout` commands the operator should
        run for full cleanup.

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
// Operator-key resolution tests
//
// Pin the precedence rules between `--operator-key <path>` (the
// global flag) and the `RAXIS_OPERATOR_KEY` env-var fallback. We
// drive `resolve_operator_key_path` with an injected env-lookup
// closure rather than touching the real process environment so
// these tests are safe to run under `cargo test --jobs N` without
// inter-test bleed-over.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod operator_key_resolution_tests {
    use super::*;

    #[test]
    fn flag_wins_when_both_flag_and_env_are_set() {
        let flag = Some(PathBuf::from("/keys/from-flag.pem"));
        let resolved = resolve_operator_key_path(flag.clone(), |key| {
            assert_eq!(key, "RAXIS_OPERATOR_KEY");
            Some(PathBuf::from("/keys/from-env.pem"))
        });
        assert_eq!(
            resolved,
            Some(PathBuf::from("/keys/from-flag.pem")),
            "explicit --operator-key MUST override RAXIS_OPERATOR_KEY (a stale shell export must never silently take over from a freshly-typed flag)",
        );
    }

    #[test]
    fn env_is_consulted_when_flag_is_absent() {
        let resolved = resolve_operator_key_path(None, |key| {
            assert_eq!(key, "RAXIS_OPERATOR_KEY");
            Some(PathBuf::from("/keys/from-env.pem"))
        });
        assert_eq!(
            resolved,
            Some(PathBuf::from("/keys/from-env.pem")),
            "RAXIS_OPERATOR_KEY MUST be honored when --operator-key is not passed",
        );
    }

    #[test]
    fn returns_none_when_neither_flag_nor_env_is_set() {
        let resolved = resolve_operator_key_path(None, |_| None);
        assert_eq!(
            resolved, None,
            "neither flag nor env set MUST yield None so per-subcommand validation can surface the standard 'usage: --operator-key <path> is required' error",
        );
    }

    /// When `--operator-key` is passed, `resolve_operator_key_path`
    /// MUST NOT touch the env var at all — not even to read it.
    /// This pins the contract that an explicit flag short-circuits
    /// the lookup so a misconfigured env block (e.g. set to a
    /// path that no longer exists) cannot leak into a request the
    /// operator believes is fully self-contained.
    #[test]
    fn env_is_not_consulted_when_flag_is_set() {
        let mut env_was_consulted = false;
        let flag = Some(PathBuf::from("/keys/from-flag.pem"));
        let _ = resolve_operator_key_path(flag, |_| {
            env_was_consulted = true;
            Some(PathBuf::from("/keys/from-env.pem"))
        });
        assert!(
            !env_was_consulted,
            "env lookup MUST be short-circuited when --operator-key is set; otherwise a broken RAXIS_OPERATOR_KEY (e.g. unreadable file) could surface a confusing error after the user already supplied a valid path",
        );
    }

    /// Defensive: the helper MUST query exactly the canonical name
    /// `RAXIS_OPERATOR_KEY`. Drift to e.g. `RAXIS_OP_KEY` or
    /// `RAXIS_OPERATOR_KEY_PATH` would silently break operator
    /// muscle memory across releases.
    #[test]
    #[allow(non_snake_case)]
    fn env_var_name_is_exactly_RAXIS_OPERATOR_KEY() {
        let mut seen: Option<String> = None;
        let _ = resolve_operator_key_path(None, |key| {
            seen = Some(key.to_owned());
            None
        });
        assert_eq!(
            seen.as_deref(),
            Some("RAXIS_OPERATOR_KEY"),
            "env var name drifted; specs/v1/env-vars.md and the demo README pin RAXIS_OPERATOR_KEY",
        );
    }
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
            ("credential", CREDENTIAL_SUBCOMMANDS),
            ("kernel",     KERNEL_SUBCOMMANDS),
            ("submit",     SUBMIT_SUBCOMMANDS),
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

        // Anchor format note: every top-level dispatcher arm uses the
        // block form `"<name>" => { ... }`. Inner arms (e.g. `"submit"
        // => commands::plan::run_submit(...)` inside the `plan` block)
        // use the expression form `=> commands::...`. We therefore key
        // the anchor on `=> {` so the scraper unambiguously lands on
        // the top-level dispatcher arm even when the same literal
        // (e.g. `"submit"`) is also used as an inner arm name.
        let pairs: &[(&str, &[&str])] = &[
            ("\"policy\" => {",     POLICY_SUBCOMMANDS),
            ("\"plan\" => {",       PLAN_SUBCOMMANDS),
            ("\"initiative\" => {", INITIATIVE_SUBCOMMANDS),
            ("\"operator\" => {",   OPERATOR_SUBCOMMANDS),
            ("\"task\" => {",       TASK_SUBCOMMANDS),
            ("\"session\" => {",    SESSION_SUBCOMMANDS),
            ("\"delegation\" => {", DELEGATION_SUBCOMMANDS),
            ("\"escalation\" => {", ESCALATION_SUBCOMMANDS),
            ("\"epoch\" => {",      EPOCH_SUBCOMMANDS),
            ("\"audit\" => {",      AUDIT_SUBCOMMANDS),
            ("\"cert\" => {",       CERT_SUBCOMMANDS),
            ("\"credential\" => {", CREDENTIAL_SUBCOMMANDS),
            ("\"kernel\" => {",     KERNEL_SUBCOMMANDS),
            ("\"submit\" => {",     SUBMIT_SUBCOMMANDS),
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
