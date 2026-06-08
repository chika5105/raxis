// raxis-supervisor — small external wrapper that spawns + monitors
// `raxis-kernel` and decides whether to restart it on unexpected
// exits.
//
// Normative reference: `self-healing-supervisor.md §4.8` (CLI).
//
// **Subcommands.**
//
//   * `raxis-supervisor start [--data-dir <path>] [--kernel-binary <path>]`
//       The default. Spawns the kernel and enters the spawn-wait-
//       classify-decide loop. When `RAXIS_SUPERVISOR_AUTO_RESTART=1`
//       the loop honours restart-eligible exits per
//       `INV-SUPERVISOR-OPT-IN-01`; without the env var the
//       supervisor spawns the kernel exactly once and exits with
//       the kernel's exit code (bit-identical to running the kernel
//       directly — the safe fallback so live-e2e iter41+ behaviour
//       stays unchanged).
//
//   * `raxis-supervisor stop [--data-dir <path>] [--force]`
//       Sends SIGTERM to the running supervisor. With `--force`,
//       writes a one-shot request file first; the supervisor catches
//       SIGTERM and sends SIGKILL to the kernel child itself so it can
//       still write a final sentinel. Reads the supervisor PID from
//       the sentinel file (`<data_dir>/kernel_lifecycle_status.json`
//       -> `supervisor_pid`).
//
//   * `raxis-supervisor status [--data-dir <path>]`
//       Pretty-prints the current sentinel file.
//
//   * `raxis-supervisor reset-circuit-breaker [--data-dir <path>]`
//       Clears the breaker state (`<data_dir>/supervisor_state.json`)
//       after `--yes` or an interactive confirmation so the
//       supervisor will spawn the kernel again.

use std::path::PathBuf;
use std::sync::Arc;

use raxis_supervisor::circuit_breaker::CircuitBreaker;
use raxis_supervisor::log::SupervisorLog;
use raxis_supervisor::sentinel::{
    read_sentinel, update_existing_sentinel, write_force_stop_request, Sentinel,
};
use raxis_supervisor::signal::{install_handlers, IntentionalShutdownFlag};
use raxis_supervisor::supervisor::{run_supervisor_loop, FinalOutcome, SupervisorConfig};
use raxis_supervisor::{
    raise_nofile_soft_limit, DEFAULT_MAX_ATTEMPTS, DEFAULT_MIN_NOFILE, DEFAULT_RESTART_WINDOW_SECS,
    DEFAULT_SHUTDOWN_GRACE_SECS, ENV_KERNEL_BINARY, ENV_MIN_NOFILE, ENV_OPT_IN,
    ENV_REQUIRE_INITIALIZED_DATA_DIR, ENV_SHUTDOWN_GRACE_SECS,
};

fn print_usage_and_exit(code: i32) -> ! {
    eprintln!(
        "raxis-supervisor — wraps raxis-kernel with classified \
         restart-on-crash behaviour\n\
         \n\
         USAGE:\n  \
         raxis-supervisor [SUBCOMMAND] [OPTIONS] [-- KERNEL_ARGS]\n\
         \n\
         SUBCOMMANDS:\n  \
         start                       Spawn + supervise the kernel (default)\n  \
         stop [--force]              Stop the running supervisor\n  \
         status                      Print the current sentinel file\n  \
         reset-circuit-breaker       Clear the circuit-breaker state\n\
         \n\
         OPTIONS:\n  \
         --data-dir <PATH>           Override RAXIS_DATA_DIR / install default\n  \
         --kernel-binary <PATH>      Override RAXIS_SUPERVISOR_KERNEL_BINARY\n\
         --yes                       Confirm reset-circuit-breaker non-interactively\n\
         \n\
         ENVIRONMENT:\n  \
         RAXIS_SUPERVISOR_AUTO_RESTART=1   Opt-in to auto-restart\n  \
         RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS  Override grace period (default {DEFAULT_SHUTDOWN_GRACE_SECS}s)\n  \
         RAXIS_SUPERVISOR_MIN_NOFILE       Override pre-kernel FD soft-limit floor (default {DEFAULT_MIN_NOFILE})\n  \
         RAXIS_SUPERVISOR_REQUIRE_INITIALIZED_DATA_DIR=1  Wait for genesis artifacts before spawning\n  \
         RAXIS_SUPERVISOR_KERNEL_BINARY    Override kernel binary path\n\
         "
    );
    std::process::exit(code);
}

fn data_dir_from_env_or_default() -> PathBuf {
    raxis_runtime::data_dir_from_env_or_install_default()
}

fn kernel_binary_from_env_or_sibling() -> PathBuf {
    if let Ok(s) = std::env::var(ENV_KERNEL_BINARY) {
        return PathBuf::from(s);
    }
    if let Ok(self_exe) = std::env::current_exe() {
        if let Some(dir) = self_exe.parent() {
            return dir.join("raxis-kernel");
        }
    }
    PathBuf::from("raxis-kernel")
}

#[derive(Debug, Default)]
struct ParsedArgs {
    subcommand: Option<String>,
    data_dir: Option<PathBuf>,
    kernel_binary: Option<PathBuf>,
    force: bool,
    yes: bool,
    kernel_args: Vec<String>,
}

fn parse_args() -> ParsedArgs {
    let mut out = ParsedArgs::default();
    let mut iter = std::env::args().skip(1);
    let mut after_dashdash = false;
    while let Some(arg) = iter.next() {
        if after_dashdash {
            out.kernel_args.push(arg);
            continue;
        }
        match arg.as_str() {
            "--" => after_dashdash = true,
            "--help" | "-h" => print_usage_and_exit(0),
            "--data-dir" => {
                out.data_dir = iter.next().map(PathBuf::from);
                if out.data_dir.is_none() {
                    eprintln!("--data-dir requires a value");
                    print_usage_and_exit(2);
                }
            }
            "--kernel-binary" => {
                out.kernel_binary = iter.next().map(PathBuf::from);
                if out.kernel_binary.is_none() {
                    eprintln!("--kernel-binary requires a value");
                    print_usage_and_exit(2);
                }
            }
            "--force" => {
                out.force = true;
            }
            "--yes" => {
                out.yes = true;
            }
            "start" | "stop" | "status" | "reset-circuit-breaker" => {
                if out.subcommand.is_some() {
                    eprintln!("only one subcommand allowed");
                    print_usage_and_exit(2);
                }
                out.subcommand = Some(arg);
            }
            other if other.starts_with("--") => {
                eprintln!("unknown flag: {other}");
                print_usage_and_exit(2);
            }
            other => {
                eprintln!("unknown positional arg: {other}");
                print_usage_and_exit(2);
            }
        }
    }
    out
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let data_dir = args
        .data_dir
        .clone()
        .unwrap_or_else(data_dir_from_env_or_default);
    let kernel_binary = args
        .kernel_binary
        .clone()
        .unwrap_or_else(kernel_binary_from_env_or_sibling);

    let subcommand = args.subcommand.as_deref().unwrap_or("start");
    let exit_code: i32 = match subcommand {
        "start" => cmd_start(&args, &data_dir, &kernel_binary).await,
        "stop" => cmd_stop(&data_dir, args.force),
        "status" => cmd_status(&data_dir),
        "reset-circuit-breaker" => cmd_reset_breaker(&data_dir, args.yes),
        other => {
            eprintln!("unknown subcommand: {other}");
            print_usage_and_exit(2);
        }
    };
    std::process::exit(exit_code);
}

async fn cmd_start(
    args: &ParsedArgs,
    data_dir: &std::path::Path,
    kernel_binary: &std::path::Path,
) -> i32 {
    prepare_nofile_limit();

    // `INV-SUPERVISOR-OPT-IN-01`: when the operator hasn't opted
    // in, the supervisor degenerates to a one-shot wrapper that
    // exec's the kernel and forwards its exit code. This is the
    // SAFE fallback live-e2e + dev relies on — running
    // `raxis-supervisor` without the env var must be bit-
    // identical to running `raxis-kernel` directly.
    let opt_in = std::env::var(ENV_OPT_IN).map(|v| v == "1").unwrap_or(false);
    if !opt_in {
        return one_shot_passthrough(kernel_binary, &args.kernel_args, data_dir);
    }

    let log = match SupervisorLog::open(data_dir) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"supervisor_log_open_failed\",\
                 \"reason\":\"{e}\"}}"
            );
            return 1;
        }
    };
    let shutdown_grace_secs = std::env::var(ENV_SHUTDOWN_GRACE_SECS)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SHUTDOWN_GRACE_SECS);
    let require_initialized_data_dir = std::env::var(ENV_REQUIRE_INITIALIZED_DATA_DIR)
        .map(|v| v == "1")
        .unwrap_or(false);
    let cfg = SupervisorConfig {
        data_dir: data_dir.to_path_buf(),
        kernel_binary: kernel_binary.to_path_buf(),
        kernel_args: args.kernel_args.clone(),
        kernel_env: vec![(
            raxis_runtime::RAXIS_DATA_DIR_ENV.to_owned(),
            data_dir.display().to_string(),
        )],
        max_attempts: DEFAULT_MAX_ATTEMPTS,
        window_secs: DEFAULT_RESTART_WINDOW_SECS,
        shutdown_grace_secs,
        restart_backoff_ms: 250,
        max_child_runs: None,
        require_initialized_data_dir,
    };

    let intent_flag = IntentionalShutdownFlag::new();
    let shutdown_rx = install_handlers(intent_flag.clone());
    log.emit(
        "info",
        "supervisor_started",
        &serde_json::json!({
            "supervisor_pid":       std::process::id(),
            "kernel_binary":        kernel_binary.display().to_string(),
            "max_attempts":         cfg.max_attempts,
            "window_secs":          cfg.window_secs,
            "shutdown_grace_secs":  cfg.shutdown_grace_secs,
        }),
    );

    match run_supervisor_loop(cfg, intent_flag, shutdown_rx, Arc::clone(&log)).await {
        Ok(report) => {
            log.emit(
                "info",
                "supervisor_finished",
                &serde_json::json!({
                    "child_runs_observed": report.child_runs_observed,
                    "final_outcome":       format!("{:?}", report.final_outcome),
                    "last_exit_code":      report.last_exit_code,
                }),
            );
            match report.final_outcome {
                FinalOutcome::OperatorStop | FinalOutcome::OperatorStopForced => 0,
                FinalOutcome::CircuitOpen { .. } => 75, // EX_TEMPFAIL
                FinalOutcome::MaxRunsReached => 0,
            }
        }
        Err(e) => {
            log.emit(
                "error",
                "supervisor_loop_failed",
                &serde_json::json!({ "reason": e.to_string() }),
            );
            1
        }
    }
}

fn configured_min_nofile() -> u64 {
    std::env::var(ENV_MIN_NOFILE)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MIN_NOFILE)
}

fn prepare_nofile_limit() {
    let required = configured_min_nofile();
    match raise_nofile_soft_limit(required) {
        Ok(outcome) if outcome.changed() => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "level": "info",
                    "event": "supervisor_nofile_limit_raised",
                    "outcome": format!("{outcome:?}"),
                })
            );
        }
        Ok(outcome) if outcome.still_below_required() => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "level": "warn",
                    "event": "supervisor_nofile_limit_below_required",
                    "outcome": format!("{outcome:?}"),
                })
            );
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "level": "warn",
                    "event": "supervisor_nofile_limit_raise_failed",
                    "required": required,
                    "reason": e.to_string(),
                })
            );
        }
    }
}

/// One-shot passthrough used when the opt-in env var is unset.
/// On Unix this uses `exec`, replacing the supervisor process with
/// the kernel process. That is the only signal-correct way to make
/// opt-out mode behave like running `raxis-kernel` directly.
#[cfg(unix)]
fn one_shot_passthrough(
    kernel_binary: &std::path::Path,
    kernel_args: &[String],
    data_dir: &std::path::Path,
) -> i32 {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(kernel_binary)
        .args(kernel_args)
        .env(raxis_runtime::RAXIS_DATA_DIR_ENV, data_dir)
        .exec();
    eprintln!(
        "{{\"level\":\"error\",\"event\":\"kernel_exec_failed\",\
         \"reason\":\"{err}\"}}"
    );
    1
}

#[cfg(not(unix))]
fn one_shot_passthrough(
    kernel_binary: &std::path::Path,
    kernel_args: &[String],
    data_dir: &std::path::Path,
) -> i32 {
    let rt = tokio::runtime::Runtime::new().expect("build passthrough runtime");
    rt.block_on(async {
        let mut cmd = tokio::process::Command::new(kernel_binary);
        cmd.args(kernel_args);
        cmd.env(raxis_runtime::RAXIS_DATA_DIR_ENV, data_dir);
        match cmd.spawn() {
            Ok(mut child) => match child.wait().await {
                Ok(status) => status.code().unwrap_or_else(|| {
                    #[cfg(unix)]
                    {
                        use std::os::unix::process::ExitStatusExt;
                        128_i32.saturating_add(status.signal().unwrap_or(0))
                    }
                    #[cfg(not(unix))]
                    {
                        1
                    }
                }),
                Err(e) => {
                    eprintln!(
                        "{{\"level\":\"error\",\"event\":\"kernel_wait_failed\",\
                     \"reason\":\"{e}\"}}"
                    );
                    1
                }
            },
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"kernel_spawn_failed\",\
                 \"reason\":\"{e}\"}}"
                );
                1
            }
        }
    })
}

#[cfg(unix)]
fn cmd_stop(data_dir: &std::path::Path, force: bool) -> i32 {
    use nix::sys::signal::Signal;
    let sentinel = match read_sentinel(data_dir) {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!(
                "no sentinel file at {} — supervisor not running?",
                data_dir.display()
            );
            return 1;
        }
        Err(e) => {
            eprintln!("read sentinel failed: {e}");
            return 1;
        }
    };
    if sentinel.supervisor_pid == 0 {
        eprintln!("supervisor_pid is 0 in sentinel; nothing to signal");
        return 1;
    }
    if force {
        if let Err(e) = write_force_stop_request(data_dir) {
            eprintln!("write force-stop request failed: {e}");
            return 1;
        }
    }
    match raxis_supervisor::signal::send_signal(sentinel.supervisor_pid, Signal::SIGTERM) {
        Ok(()) => {
            println!(
                "sent {} to supervisor pid {}",
                if force {
                    "force-stop request + SIGTERM"
                } else {
                    "SIGTERM"
                },
                sentinel.supervisor_pid,
            );
            0
        }
        Err(e) => {
            eprintln!("kill failed: {e}");
            1
        }
    }
}

#[cfg(not(unix))]
fn cmd_stop(_data_dir: &std::path::Path, _force: bool) -> i32 {
    eprintln!("raxis-supervisor stop is unix-only");
    2
}

fn cmd_status(data_dir: &std::path::Path) -> i32 {
    match read_sentinel(data_dir) {
        Ok(Some(s)) => match serde_json::to_string_pretty(&s) {
            Ok(out) => {
                println!("{out}");
                0
            }
            Err(e) => {
                eprintln!("serialize failed: {e}");
                1
            }
        },
        Ok(None) => {
            // Render an explicit "supervisor not running" status
            // line so callers (xtask scripts, dashboard
            // bootstrap) can parse the JSON unconditionally.
            let s = Sentinel {
                schema_version: 1,
                status: "Halted".to_owned(),
                sub_state: Some("OperatorStop".to_owned()),
                attempt_n: 0,
                max_attempts: 0,
                last_restart_unix_ts: 0,
                last_restart_reason: None,
                prev_run_exit_code: None,
                attempts_in_window: 0,
                window_secs: 0,
                supervisor_pid: 0,
                kernel_pid: 0,
                updated_at_unix_secs: 0,
            };
            match serde_json::to_string_pretty(&s) {
                Ok(out) => {
                    println!("{out}");
                    0
                }
                Err(_) => 1,
            }
        }
        Err(e) => {
            eprintln!("read sentinel failed: {e}");
            1
        }
    }
}

fn confirm_reset_breaker(yes: bool) -> bool {
    if yes {
        return true;
    }
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        eprintln!("reset-circuit-breaker requires --yes when stdin is not a terminal");
        return false;
    }
    eprint!("Reset supervisor circuit breaker and allow the kernel to spawn again? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim(), "y" | "Y" | "yes" | "YES")
}

fn cmd_reset_breaker(data_dir: &std::path::Path, yes: bool) -> i32 {
    if !confirm_reset_breaker(yes) {
        eprintln!("circuit breaker reset aborted");
        return 1;
    }
    let mut breaker = CircuitBreaker::load_with_defaults(data_dir);
    breaker.reset();
    match breaker.save() {
        Ok(()) => {
            // Also clear the sentinel sub_state so the dashboard
            // banner clears immediately (the supervisor itself
            // will re-write `Healthy` on its next spawn).
            let _ = update_existing_sentinel(data_dir, |mut s| {
                if s.sub_state.as_deref() == Some("CircuitOpen") {
                    s.sub_state = Some("OperatorStop".to_owned());
                }
                s
            });
            if let Ok(log) = SupervisorLog::open(data_dir) {
                log.emit(
                    "info",
                    "circuit_breaker_reset",
                    &serde_json::json!({ "confirmed": true }),
                );
            }
            println!("circuit breaker cleared");
            0
        }
        Err(e) => {
            eprintln!("save failed: {e}");
            1
        }
    }
}
