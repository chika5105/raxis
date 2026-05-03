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

mod commands;
mod conn;
mod errors;
mod signing;

use std::path::PathBuf;

use errors::CliError;

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
                _ => Err(CliError::Usage(format!("unknown policy sub-command: {sub2:?}"))),
            }
        }
        "plan" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "submit" => commands::plan::run_submit(&flags, &rest[1..]),
                "approve" => commands::plan::run_approve(&flags, &rest[1..]),
                "reject" => commands::plan::run_reject(&flags, &rest[1..]),
                _ => Err(CliError::Usage(format!("unknown plan sub-command: {sub2:?}"))),
            }
        }
        "initiative" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "abort" => commands::initiative::run_abort(&flags, &rest[1..]),
                _ => Err(CliError::Usage(format!(
                    "unknown initiative sub-command: {sub2:?}"
                ))),
            }
        }
        "task" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "abort" => commands::task::run_abort(&flags, &rest[1..]),
                "resume" => commands::task::run_resume(&flags, &rest[1..]),
                "retry" => commands::task::run_retry(&flags, &rest[1..]),
                _ => Err(CliError::Usage(format!("unknown task sub-command: {sub2:?}"))),
            }
        }
        "session" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "create" => commands::session::run_create(&flags, &rest[1..]),
                "revoke" => commands::session::run_revoke(&flags, &rest[1..]),
                _ => Err(CliError::Usage(format!(
                    "unknown session sub-command: {sub2:?}"
                ))),
            }
        }
        "delegation" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "grant" => commands::delegation::run_grant(&flags, &rest[1..]),
                _ => Err(CliError::Usage(format!(
                    "unknown delegation sub-command: {sub2:?}"
                ))),
            }
        }
        "escalation" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "approve" => commands::escalation::run_approve(&flags, &rest[1..]),
                "deny" => commands::escalation::run_deny(&flags, &rest[1..]),
                _ => Err(CliError::Usage(format!(
                    "unknown escalation sub-command: {sub2:?}"
                ))),
            }
        }
        "epoch" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "advance" => commands::epoch::run_advance(&flags, &rest[1..]),
                _ => Err(CliError::Usage(format!("unknown epoch sub-command: {sub2:?}"))),
            }
        }
        "audit" => {
            let sub2 = rest.first().map(|s| s.as_str()).unwrap_or("");
            match sub2 {
                "verify" => commands::audit::run_verify(&flags, &rest[1..]),
                _ => Err(CliError::Usage(format!("unknown audit sub-command: {sub2:?}"))),
            }
        }
        "status" => commands::status::run(&flags, rest),
        "log" => commands::log::run(&flags, rest),
        "verify-chain" => commands::verify_chain::run(&flags, rest),
        "queue" => commands::queue::run(&flags, rest),
        "inspect" => commands::inspect::run(&flags, rest),
        "" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(CliError::Usage(format!("unknown subcommand: {other:?}"))),
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

    task abort <task_id>
        Abort a running task immediately.

    task resume <task_id>
        Resume a BlockedRecoveryPending task after kernel crash recovery.

    task retry <task_id>
        Retry a Failed task (transitions Failed → Admitted).

    session create --role planner --worktree-root <path> [--lineage-id <uuid>]
        Create a planner session and print the session token to stderr.

    session revoke <session_id>
        Revoke an active session; subsequent IPC frames from that session are rejected.

    delegation grant --session <id> --capability <class> --role <role_id> --ttl <secs>
        Grant a capability delegation to a session for a bounded TTL.

    escalation approve <escalation_id> --scope <capability_class> --max-uses <n> --valid-for <secs>
        Approve a pending escalation and issue an approval token.

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

    verify-chain [--quick] [--audit-dir <path>]
        Walk every audit segment, verify prev_sha256 + seq monotonicity.
        Exit 0 intact, 3 broken. --quick mirrors `raxis status`'s check.

    queue [--lane <id>] [--blocked-only] [--limit <N>]
        DAG scheduler state — READY (Admitted | GatesPending) and
        BLOCKED (BlockedRecoveryPending) tables, plus the
        approximate pending-verifier-spawns count from heartbeat.

    inspect <task_id> [--json] [--gates-only] [--with-deps]
        Forensic deep-dive into a single task: state, dependencies,
        witnesses. --reveal-paths is reserved for v1.x.
"#
    );
}
