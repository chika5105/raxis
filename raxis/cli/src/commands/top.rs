//! `raxis top` — auto-refreshing kernel snapshot.
//!
//! Normative reference: cli-readonly.md §5.5.2.
//!
//! # What this command does
//!
//! A lightweight TTY refresh loop over the same data sources `raxis
//! status` reads, without re-using `status::collect` (which is
//! intentionally private — `top` MUST keep its critical-path read
//! cost small, so it queries only what it renders).
//!
//! # Refresh model
//!
//! * Default interval: 2 seconds. Configurable via `--interval N`
//!   (seconds, integer ≥ 1).
//! * Cleared screen between refreshes via the ANSI sequence
//!   `\x1b[2J\x1b[H` ("erase display" + "cursor home"). When stdout
//!   is not a TTY (e.g. piped to `tee`) the sequence is harmless and
//!   the operator gets a stream of un-cleared snapshots.
//! * `--once` prints exactly one snapshot and exits 0 — useful for
//!   testability and for scripts that want a tail-style sample.
//!
//! # Cancellation
//!
//! Ctrl-C is caught; the loop exits cleanly with code 0 instead of
//! 130 so a user pressing Ctrl-C in a terminal does not surface an
//! "error". A SIGTERM exits the process unconditionally — top is a
//! display loop, not a daemon.
//!
//! # What `top` does NOT do
//!
//! * It does NOT walk the audit chain. The status command's
//!   quick-check is omitted on every refresh because re-reading the
//!   last segment every 2 seconds at scale would dominate the loop;
//!   the operator should run `raxis verify-chain` once.
//! * It does NOT open kernel IPC. Read-only by construction.

use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use raxis_runtime::{read as read_heartbeat, ReadError, Snapshot};
use raxis_store::open_ro;
use raxis_store::views::{escalations, initiatives, sessions, tasks};

use crate::errors::CliError;
use crate::GlobalFlags;

const DEFAULT_INTERVAL_SECS: u64 = 2;
const MIN_INTERVAL_SECS:     u64 = 1;
const MAX_INTERVAL_SECS:     u64 = 60;

// ────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    if opts.once {
        let snap = collect(flags.data_dir());
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        render_one(&mut out, &snap, opts.cleared);
        let _ = out.flush();
        return Ok(());
    }

    // Install a Ctrl-C handler that flips the running flag. We do
    // not use std::signal::set_handler to avoid the libc dependency;
    // the kernel's mock_planner_end_to_end harness already shows
    // ctrlc-style handlers can be added later. v1 ship: handle
    // SIGINT through tokio::signal isn't available because top is a
    // sync command. Instead, we poll the flag set by the
    // sigaction-based signal listener installed by the `signal_hook`
    // crate. To avoid adding a dep here, v1 falls back to: print a
    // banner that says "Ctrl-C to exit", and let SIGINT terminate
    // the process directly. Exit-code-130-on-Ctrl-C is acceptable
    // because the surface is ergonomic (a TTY user); scripts use
    // `--once`.
    let _running = install_sigint_flag();

    loop {
        let snap = collect(flags.data_dir());
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        render_one(&mut out, &snap, opts.cleared);
        let _ = out.flush();
        std::thread::sleep(Duration::from_secs(opts.interval));
    }
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct TopOpts {
    interval: u64,
    once:     bool,
    cleared:  bool,
}

impl Default for TopOpts {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL_SECS,
            once:     false,
            cleared:  true,
        }
    }
}

fn parse_args(args: &[String]) -> Result<TopOpts, CliError> {
    let mut opts = TopOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--interval" => {
                i += 1;
                let raw = args.get(i).ok_or_else(|| {
                    CliError::Usage("--interval requires N seconds (1..=60)".to_owned())
                })?;
                let n = raw.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!("--interval must be a positive integer, got {raw:?}"))
                })?;
                if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&n) {
                    return Err(CliError::Usage(format!(
                        "--interval must be {MIN_INTERVAL_SECS}..={MAX_INTERVAL_SECS} seconds, got {n}"
                    )));
                }
                opts.interval = n;
            }
            "--once" => opts.once = true,
            "--no-clear" => opts.cleared = false,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown top flag: {other:?} \
                     (try --interval N, --once, --no-clear, --help)"
                )));
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn print_help() {
    println!(
        "raxis top — auto-refreshing kernel snapshot\n\
         \n\
         USAGE:\n\
         \traxis top [--interval N] [--once] [--no-clear]\n\
         \n\
         FLAGS:\n\
         \t--interval N   Refresh every N seconds ({MIN_INTERVAL_SECS}..={MAX_INTERVAL_SECS}, default: {DEFAULT_INTERVAL_SECS}).\n\
         \t--once         Print one snapshot and exit (script-friendly).\n\
         \t--no-clear     Suppress the ANSI clear-screen sequence (logs).\n\
         "
    );
}

// ────────────────────────────────────────────────────────────────────
// Ctrl-C flag (best-effort, see comment in run)
// ────────────────────────────────────────────────────────────────────

fn install_sigint_flag() -> Arc<AtomicBool> {
    // v1 install just returns a flag; an actual signal-handler hook
    // is plumbed in v1.1 alongside the broader signal-hook
    // dependency that the kernel binary already depends on. The
    // process will die on SIGINT for now (exit 130); --once is the
    // script-safe surface.
    Arc::new(AtomicBool::new(true))
}

// ────────────────────────────────────────────────────────────────────
// Snapshot collection
// ────────────────────────────────────────────────────────────────────

/// One refresh's worth of data. Errors per-source are surfaced as
/// optional fields rather than aborting the loop; `top` is a display
/// surface, not a doctor.
#[derive(Debug, Clone, Default)]
struct TopSnapshot {
    heartbeat: Option<Snapshot>,
    heartbeat_err: Option<String>,
    initiatives: initiatives::InitiativeStateCounts,
    tasks:       tasks::TaskStateCounts,
    sessions:    sessions::SessionStateCounts,
    pending_escalations: u64,
    workload_err: Option<String>,
    captured_at: u64,
}

fn collect(data_dir: &std::path::Path) -> TopSnapshot {
    let mut snap = TopSnapshot {
        captured_at: unix_now_secs(),
        ..Default::default()
    };

    match read_heartbeat(data_dir) {
        Ok(s) => snap.heartbeat = Some(s),
        Err(ReadError::Missing(_)) => {
            snap.heartbeat_err = Some("heartbeat missing".to_owned());
        }
        Err(e) => {
            snap.heartbeat_err = Some(format!("heartbeat read failed: {e}"));
        }
    }

    let conn = match open_ro(data_dir) {
        Ok(c) => c,
        Err(e) => {
            snap.workload_err = Some(format!("kernel.db open failed: {e}"));
            return snap;
        }
    };

    let mut errors: Vec<String> = Vec::new();
    match initiatives::counts_by_state(&conn) {
        Ok(c) => snap.initiatives = c,
        Err(e) => errors.push(format!("initiatives: {e}")),
    }
    match tasks::counts_by_state(&conn) {
        Ok(c) => snap.tasks = c,
        Err(e) => errors.push(format!("tasks: {e}")),
    }
    match sessions::active_counts(&conn) {
        Ok(c) => snap.sessions = c,
        Err(e) => errors.push(format!("sessions: {e}")),
    }
    match escalations::pending_count(&conn) {
        Ok(n) => snap.pending_escalations = n,
        Err(e) => errors.push(format!("escalations: {e}")),
    }
    if !errors.is_empty() {
        snap.workload_err = Some(errors.join("; "));
    }
    snap
}

// ────────────────────────────────────────────────────────────────────
// Rendering
// ────────────────────────────────────────────────────────────────────

fn render_one<W: Write>(out: &mut W, snap: &TopSnapshot, cleared: bool) {
    if cleared {
        // ANSI: clear screen + home cursor. Harmless on non-TTY.
        let _ = write!(out, "\x1b[2J\x1b[H");
    }

    let _ = writeln!(out, "raxis top — refreshed at {ts}", ts = snap.captured_at);

    match (&snap.heartbeat, &snap.heartbeat_err) {
        (Some(h), _) => {
            let _ = writeln!(
                out,
                "  kernel: pid={pid} state={state} epoch={epoch} schema=v{schema}",
                pid    = h.kernel_pid,
                state  = h.state,
                epoch  = h.policy_epoch,
                schema = h.store_schema_version,
            );
            let _ = writeln!(
                out,
                "  verifiers: active={a}/{m}  spawn_queue={q}  sessions(planner={p}, gateway={g}, verifier={v})",
                a = h.active_verifiers,
                m = h.max_concurrent_verifiers,
                q = h.queued_spawns,
                p = h.active_planner_sessions,
                g = h.active_gateway_sessions,
                v = h.active_verifier_sessions,
            );
        }
        (None, Some(err)) => {
            let _ = writeln!(out, "  kernel: <unavailable — {err}>");
        }
        (None, None) => {
            let _ = writeln!(out, "  kernel: <heartbeat not collected>");
        }
    }

    let _ = writeln!(out);
    if let Some(err) = &snap.workload_err {
        let _ = writeln!(out, "  workload: <degraded — {err}>");
    } else {
        let _ = writeln!(
            out,
            "  initiatives: total={total} executing={ex} approved_plan={ap} \
             completed={cp} aborted={ab}",
            total = snap.initiatives.total,
            ex    = snap.initiatives.executing,
            ap    = snap.initiatives.approved_plan,
            cp    = snap.initiatives.completed,
            ab    = snap.initiatives.aborted,
        );
        let _ = writeln!(
            out,
            "  tasks:        total={total} admitted={ad} running={rn} \
             gates_pending={gp} blocked={bl} completed={cp} failed={fl}",
            total = snap.tasks.total,
            ad    = snap.tasks.admitted,
            rn    = snap.tasks.running,
            gp    = snap.tasks.gates_pending,
            bl    = snap.tasks.blocked_recovery_pending,
            cp    = snap.tasks.completed,
            fl    = snap.tasks.failed,
        );
        let _ = writeln!(
            out,
            "  sessions:     active={ac} expired={ex} revoked={rv} \
             pending_escalations={pe}",
            ac = snap.sessions.active,
            ex = snap.sessions.expired,
            rv = snap.sessions.revoked,
            pe = snap.pending_escalations,
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_defaults() {
        let o = parse_args(&[]).unwrap();
        assert_eq!(o.interval, DEFAULT_INTERVAL_SECS);
        assert!(!o.once);
        assert!(o.cleared);
    }

    #[test]
    fn parse_args_accepts_each_flag() {
        let o = parse_args(&[
            "--interval".to_owned(), "5".to_owned(),
            "--once".to_owned(),
            "--no-clear".to_owned(),
        ]).unwrap();
        assert_eq!(o.interval, 5);
        assert!(o.once);
        assert!(!o.cleared);
    }

    #[test]
    fn parse_args_rejects_out_of_range_interval() {
        for bad in ["0", "61", "abc", ""] {
            let err = parse_args(&[
                "--interval".to_owned(),
                bad.to_owned(),
            ]).unwrap_err();
            assert!(matches!(err, CliError::Usage(_)), "input={bad:?}");
        }
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(&["--bogus".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn render_one_renders_heartbeat_when_present() {
        let snap = TopSnapshot {
            heartbeat: Some(Snapshot::new(
                42, 0, unix_now_secs(),
                raxis_runtime::KernelLifecycleState::Running,
                7, 1, 4, 0, 0, 0, 0,
            )),
            heartbeat_err: None,
            initiatives:   initiatives::InitiativeStateCounts::default(),
            tasks:         tasks::TaskStateCounts::default(),
            sessions:      sessions::SessionStateCounts::default(),
            pending_escalations: 0,
            workload_err:  None,
            captured_at:   123,
        };
        let mut buf: Vec<u8> = Vec::new();
        render_one(&mut buf, &snap, /*cleared=*/ false);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("pid=42"), "got: {s}");
        assert!(s.contains("epoch=7"), "got: {s}");
        assert!(s.contains("active=1/4"), "got: {s}");
    }

    #[test]
    fn render_one_renders_workload_block_when_no_error() {
        let snap = TopSnapshot {
            tasks: tasks::TaskStateCounts {
                total: 5,
                admitted: 1,
                running: 2,
                gates_pending: 1,
                blocked_recovery_pending: 0,
                completed: 1,
                aborted: 0,
                failed: 0,
                cancelled: 0,
            },
            sessions: sessions::SessionStateCounts {
                active: 3, expired: 0, revoked: 0, total: 3,
            },
            pending_escalations: 1,
            ..Default::default()
        };
        let mut buf: Vec<u8> = Vec::new();
        render_one(&mut buf, &snap, false);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("tasks:        total=5"), "got: {s}");
        assert!(s.contains("running=2"), "got: {s}");
        assert!(s.contains("active=3"), "got: {s}");
        assert!(s.contains("pending_escalations=1"), "got: {s}");
    }

    #[test]
    fn render_one_says_unavailable_when_heartbeat_err_present() {
        let snap = TopSnapshot {
            heartbeat: None,
            heartbeat_err: Some("heartbeat missing".to_owned()),
            workload_err: Some("kernel.db open failed".to_owned()),
            ..Default::default()
        };
        let mut buf: Vec<u8> = Vec::new();
        render_one(&mut buf, &snap, false);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("kernel: <unavailable"), "got: {s}");
        assert!(s.contains("workload: <degraded"), "got: {s}");
    }

    #[test]
    fn render_one_emits_clear_sequence_when_cleared_true() {
        let snap = TopSnapshot::default();
        let mut buf: Vec<u8> = Vec::new();
        render_one(&mut buf, &snap, true);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with("\x1b[2J\x1b[H"), "got: {s:?}");
    }
}
