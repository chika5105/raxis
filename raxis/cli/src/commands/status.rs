//! `raxis status` — one-screen kernel health snapshot.
//!
//! Normative reference: cli-readonly.md §5.5.1.
//!
//! # Data sources (all read-only, no kernel IPC)
//!
//! 1. `<data_dir>/runtime/heartbeat.json`  → liveness, pid, uptime,
//!    policy_epoch, store_schema_version, in-memory verifier counters.
//!    Read via `raxis_runtime::read`.
//! 2. `<data_dir>/kernel.db` opened READ-ONLY via
//!    `raxis_store::open_ro` (schema-version pinned).
//!    - `views::tasks::counts_by_state`
//!    - `views::sessions::active_counts`
//!    - `views::initiatives::counts_by_state`
//!    - `views::escalations::pending_count`
//! 3. `<data_dir>/audit/segment-NNN.jsonl` quick-check on the
//!    last segment's last record (we do NOT walk the whole chain;
//!    `raxis verify-chain` does that).
//!
//! # Exit codes
//!
//! Per cli-readonly.md §5.5.1:
//!
//! | Code | Meaning |
//! |------|---------|
//! | `0`  | Kernel live + audit chain intact. |
//! | `1`  | Kernel stopped (heartbeat missing, stale, or `state="Stopping"`). |
//! | `2`  | Liveness ambiguous (heartbeat fresh but kernel PID no longer exists). |
//! | `3`  | Audit chain shows a break (last record fails to parse / has bad seq). |
//!
//! Codes are returned via `std::process::exit` from `run`; the call
//! site in `main.rs` does NOT wrap status errors as `CliError` because
//! status is the one command where a non-zero exit is *normal output*,
//! not an error.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use raxis_store::views::{escalations, initiatives, sessions, tasks};
use raxis_store::{open_ro, RoConn, RoError};

use crate::errors::CliError;
use crate::GlobalFlags;

/// Run the `status` command.
///
/// Never returns `Err(CliError)`; on every code path we render the
/// human-readable (or `--json`) report and call `std::process::exit`
/// with the spec-mandated code. Returning `Ok(())` only happens in
/// dead code (after `process::exit`, which `!` returns).
pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    let report = collect(flags.data_dir());

    if opts.json {
        // Single-line JSON, NOT pretty: easy for `jq` consumers and
        // doesn't waste a TTY width on indentation. Fields are
        // exhaustive; consumers can ignore what they don't need.
        let value = report.to_json_value();
        // `serde_json::to_writer` is preferred over `to_string +
        // println` because it avoids a redundant string allocation
        // and writes a trailing newline only via `writeln!` below.
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let _ = serde_json::to_writer(&mut out, &value);
        use std::io::Write;
        let _ = writeln!(out);
    } else {
        report.render_human(&mut std::io::stdout());
    }

    std::process::exit(report.exit_code());
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Copy)]
struct StatusOpts {
    json: bool,
}

fn parse_args(args: &[String]) -> Result<StatusOpts, CliError> {
    let mut opts = StatusOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => opts.json = true,
            "-h" | "--help" => {
                print_status_help();
                // Help is its own exit-0 path; doesn't render the
                // status report.
                std::process::exit(0);
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown status flag: {other:?} (try --json or --help)"
                )));
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn print_status_help() {
    println!(
        "raxis status — one-screen kernel health snapshot\n\
         \n\
         USAGE:\n\
         \tlraxis status [--json]\n\
         \n\
         FLAGS:\n\
         \t--json    Emit a single-line JSON object instead of human text.\n\
         \n\
         EXIT CODES:\n\
         \t0   kernel live + audit chain intact\n\
         \t1   kernel stopped (heartbeat missing, stale, or Stopping)\n\
         \t2   ambiguous liveness (heartbeat fresh, but kernel PID gone)\n\
         \t3   audit chain shows a break"
    );
}

// ────────────────────────────────────────────────────────────────────
// Report assembly
// ────────────────────────────────────────────────────────────────────

/// Per-source status verdict. Each variant is rendered to a single
/// human line and to one JSON field; mapping to the spec exit codes
/// happens in [`StatusReport::exit_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Liveness {
    /// Heartbeat present, fresh, state=Running, PID still alive.
    Running,
    /// Heartbeat fresh, state=Running, but kernel PID no longer
    /// exists (PID reaped before final heartbeat could be written).
    /// Spec-coded "ambiguous", exit 2.
    AmbiguousPidGone { pid: u32 },
    /// Heartbeat present but stale-by-time (older than
    /// HEARTBEAT_STALE_AFTER), or the kernel wrote `state="Stopping"`
    /// during a clean shutdown.
    Stopped { reason: StoppedReason },
    /// No heartbeat file present, OR heartbeat file unreadable. Same
    /// exit-code mapping as `Stopped` (1) per spec.
    Missing { detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StoppedReason {
    Stopping,
    Stale { age_secs: u64 },
}

/// Audit chain quick-check verdict. Cheap one-line scan of the most
/// recent segment file; full verification is `raxis verify-chain`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChainQuickCheck {
    /// Latest segment's last record parses as JSON with a valid `seq`.
    Ok { segment: PathBuf, last_seq: u64 },
    /// Audit directory has no segment files. Treated as "fresh
    /// kernel that hasn't booted yet" rather than a chain break.
    NoSegments,
    /// Latest segment's last record failed to parse. Spec-coded as
    /// "break", exit 3.
    Broken { segment: PathBuf, reason: String },
}

/// One-shot snapshot of every fact `raxis status` prints. Built by
/// [`collect`]; rendered by [`Self::render_human`] or
/// [`Self::to_json_value`].
#[derive(Debug, Clone)]
struct StatusReport {
    data_dir: PathBuf,
    install_origin: raxis_runtime::InstallOrigin,
    liveness: Liveness,
    /// Snapshot from heartbeat.json, only `Some` when liveness is
    /// `Running` or `AmbiguousPidGone` or `Stopped::Stopping`.
    heartbeat: Option<raxis_runtime::Snapshot>,
    /// Set when reading kernel.db succeeded.
    workload: Option<WorkloadCounts>,
    /// Set when at least one read of kernel.db failed; rendered
    /// alongside whatever DID succeed so the operator sees both.
    db_error: Option<String>,
    chain: ChainQuickCheck,
    /// Convenience: `unix_now_secs()` at report-build time. Used both
    /// for human-rendered "uptime" and for the `--json`
    /// `now_secs` field.
    now_secs: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
struct WorkloadCounts {
    initiatives: initiatives::InitiativeStateCounts,
    tasks: tasks::TaskStateCounts,
    sessions: sessions::SessionStateCounts,
    pending_escalations: u64,
}

/// Build a [`StatusReport`] from the on-disk state of `data_dir`.
/// Pure (no `process::exit`); the caller decides what to do with it.
fn collect(data_dir: &Path) -> StatusReport {
    let now_secs = unix_now_secs();
    let liveness_pair = collect_liveness(data_dir, now_secs);
    let liveness = liveness_pair.0;
    let heartbeat = liveness_pair.1;

    let (workload, db_error) = match open_ro(data_dir) {
        Ok(conn) => collect_workload(&conn),
        Err(e) => (None, Some(format_ro_error(&e))),
    };

    let chain = collect_chain_quick_check(data_dir);

    StatusReport {
        data_dir: data_dir.to_path_buf(),
        install_origin: raxis_runtime::current_install_origin(),
        liveness,
        heartbeat,
        workload,
        db_error,
        chain,
        now_secs,
    }
}

/// Inspect `runtime/heartbeat.json` + `kill(pid, 0)` to classify
/// liveness. Returns the verdict plus the heartbeat snapshot when
/// the snapshot is meaningful for downstream rendering.
fn collect_liveness(data_dir: &Path, now_secs: u64) -> (Liveness, Option<raxis_runtime::Snapshot>) {
    match raxis_runtime::read(data_dir) {
        Ok(snap) => {
            // Final-write semantics: state=Stopping is always exit 1
            // regardless of freshness. A clean shutdown also makes
            // the file fresh.
            if snap.state == raxis_runtime::KernelLifecycleState::Stopping.as_str() {
                return (
                    Liveness::Stopped {
                        reason: StoppedReason::Stopping,
                    },
                    Some(snap),
                );
            }
            if !snap.is_live(now_secs) {
                let age_secs = now_secs.saturating_sub(snap.last_heartbeat_at);
                return (
                    Liveness::Stopped {
                        reason: StoppedReason::Stale { age_secs },
                    },
                    Some(snap),
                );
            }
            // Heartbeat says `Running` AND is fresh. The only remaining
            // ambiguity is whether the PID actually exists — `kill -9`
            // could have reaped the process between the last write and
            // now.
            if !is_pid_alive(snap.kernel_pid) {
                let pid = snap.kernel_pid;
                return (Liveness::AmbiguousPidGone { pid }, Some(snap));
            }
            (Liveness::Running, Some(snap))
        }
        Err(raxis_runtime::ReadError::Missing(_)) => (
            Liveness::Missing {
                detail: "no heartbeat.json — kernel never started, or runtime/ not yet created"
                    .to_owned(),
            },
            None,
        ),
        Err(other) => (
            Liveness::Missing {
                detail: format!("heartbeat read failed: {other}"),
            },
            None,
        ),
    }
}

/// Run the four read-only view queries. If ANY fails, we still
/// return as much as we got plus a single error string for the
/// human/JSON output. The CLI continues — the operator wants to see
/// liveness + chain even when one DB read trips up.
fn collect_workload(conn: &RoConn) -> (Option<WorkloadCounts>, Option<String>) {
    let mut errors: Vec<String> = Vec::new();
    let mut counts = WorkloadCounts::default();

    match initiatives::counts_by_state(conn) {
        Ok(c) => counts.initiatives = c,
        Err(e) => errors.push(format!("initiatives: {e}")),
    }
    match tasks::counts_by_state(conn) {
        Ok(c) => counts.tasks = c,
        Err(e) => errors.push(format!("tasks: {e}")),
    }
    match sessions::active_counts(conn) {
        Ok(c) => counts.sessions = c,
        Err(e) => errors.push(format!("sessions: {e}")),
    }
    match escalations::pending_count(conn) {
        Ok(n) => counts.pending_escalations = n,
        Err(e) => errors.push(format!("escalations: {e}")),
    }

    let workload = if errors.is_empty() || partial_workload_useful(&counts) {
        Some(counts)
    } else {
        None
    };
    let err_str = if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    };
    (workload, err_str)
}

/// Heuristic: if at least one of the four queries gave us non-default
/// data, render what we have rather than collapsing to "no workload".
fn partial_workload_useful(c: &WorkloadCounts) -> bool {
    c.initiatives.total > 0
        || c.tasks.total > 0
        || c.sessions.total > 0
        || c.pending_escalations > 0
}

/// Quick chain check: locate the highest-numbered `segment-*.jsonl`
/// in `<data_dir>/audit/`, read the last non-empty line, ensure it
/// parses as JSON with a `seq` field. The full chain is verified by
/// `raxis verify-chain` — this routine is intentionally O(1)
/// reads per segment so `status` stays sub-100ms even on a 100MB
/// audit log.
fn collect_chain_quick_check(data_dir: &Path) -> ChainQuickCheck {
    let audit_dir = data_dir.join("audit");
    let entries = match std::fs::read_dir(&audit_dir) {
        Ok(e) => e,
        Err(_) => return ChainQuickCheck::NoSegments,
    };

    // Walk the directory entries to find the highest segment-NNN.jsonl
    // file. We bound to a single pass; absolutely no globbing crate
    // dependency for this one job.
    let mut best: Option<(u32, PathBuf)> = None;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let s = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        let stripped = match s
            .strip_prefix("segment-")
            .and_then(|rest| rest.strip_suffix(".jsonl"))
        {
            Some(num_str) => num_str,
            None => continue,
        };
        if let Ok(n) = stripped.parse::<u32>() {
            match &best {
                Some((bn, _)) if *bn >= n => {}
                _ => best = Some((n, entry.path())),
            }
        }
    }

    let (_, segment_path) = match best {
        Some(pair) => pair,
        None => return ChainQuickCheck::NoSegments,
    };

    match read_last_line(&segment_path) {
        Ok(None) => ChainQuickCheck::Broken {
            segment: segment_path,
            reason: "segment file is empty".to_owned(),
        },
        Ok(Some(line)) => match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(v) => match v.get("seq").and_then(|s| s.as_u64()) {
                Some(seq) => ChainQuickCheck::Ok {
                    segment: segment_path,
                    last_seq: seq,
                },
                None => ChainQuickCheck::Broken {
                    segment: segment_path,
                    reason: "last record missing or non-numeric `seq` field".to_owned(),
                },
            },
            Err(e) => ChainQuickCheck::Broken {
                segment: segment_path,
                reason: format!("last record JSON parse: {e}"),
            },
        },
        Err(e) => ChainQuickCheck::Broken {
            segment: segment_path,
            reason: format!("read last line: {e}"),
        },
    }
}

/// Read the LAST non-empty line of a file. We use a backward-byte
/// scan rather than `BufReader::lines().last()` so we don't read a
/// 100MB segment to find one line.
fn read_last_line(path: &Path) -> std::io::Result<Option<String>> {
    use std::io::{Read, Seek, SeekFrom};

    const SCAN_WINDOW: usize = 4096;
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }

    // Read up to SCAN_WINDOW bytes from the end. If the segment was
    // appended a single line longer than SCAN_WINDOW (extreme edge
    // case — audit lines are bounded by the largest payload kind +
    // metadata overhead, currently well under 4KiB), we accept that
    // this returns the line tail starting one window from EOF; the
    // JSON parse step below will then fail, and we report it as a
    // chain break — which IS the right answer (an unbounded line is
    // a corruption signal).
    let read_len = std::cmp::min(len, SCAN_WINDOW as u64) as usize;
    let mut buf = vec![0u8; read_len];
    f.seek(SeekFrom::End(-(read_len as i64)))?;
    f.read_exact(&mut buf)?;

    // Strip trailing newlines so the "last line" isn't empty.
    while let Some(&b) = buf.last() {
        if b == b'\n' || b == b'\r' {
            buf.pop();
        } else {
            break;
        }
    }
    if buf.is_empty() {
        return Ok(None);
    }

    let last_nl = buf.iter().rposition(|&b| b == b'\n');
    let start = last_nl.map(|i| i + 1).unwrap_or(0);
    let line_bytes = &buf[start..];
    Ok(Some(String::from_utf8_lossy(line_bytes).into_owned()))
}

// ────────────────────────────────────────────────────────────────────
// Rendering
// ────────────────────────────────────────────────────────────────────

impl StatusReport {
    fn exit_code(&self) -> i32 {
        // Audit-chain break trumps liveness — operators must see "fix
        // the chain" first because a broken chain means the kernel
        // can't safely emit new audit records.
        if matches!(self.chain, ChainQuickCheck::Broken { .. }) {
            return 3;
        }
        match &self.liveness {
            Liveness::Running => 0,
            Liveness::AmbiguousPidGone { .. } => 2,
            Liveness::Stopped { .. } | Liveness::Missing { .. } => 1,
        }
    }

    fn render_human<W: std::io::Write>(&self, out: &mut W) {
        // Headline.
        let (headline, summary) = match &self.liveness {
            Liveness::Running => ("RAXIS Kernel: RUNNING", String::new()),
            Liveness::AmbiguousPidGone { pid } => (
                "RAXIS Kernel: AMBIGUOUS",
                format!("(heartbeat fresh but PID {pid} no longer exists)"),
            ),
            Liveness::Stopped {
                reason: StoppedReason::Stopping,
            } => (
                "RAXIS Kernel: STOPPED",
                "(clean shutdown — final heartbeat said state=Stopping)".to_owned(),
            ),
            Liveness::Stopped {
                reason: StoppedReason::Stale { age_secs },
            } => (
                "RAXIS Kernel: STOPPED",
                format!("(heartbeat stale — last write {age_secs}s ago)"),
            ),
            Liveness::Missing { detail } => ("RAXIS Kernel: STOPPED", format!("({detail})")),
        };
        let _ = writeln!(
            out,
            "{headline}{}{summary}",
            if summary.is_empty() { "" } else { " " }
        );

        // First block: kernel-self facts (only when we have a heartbeat).
        if let Some(hb) = &self.heartbeat {
            let _ = writeln!(out, "  pid:                  {}", hb.kernel_pid);
            let _ = writeln!(
                out,
                "  uptime:               {}",
                format_uptime(self.now_secs.saturating_sub(hb.started_at))
            );
            let _ = writeln!(out, "  data_dir:             {}", self.data_dir.display());
            let _ = writeln!(
                out,
                "  install_origin:       {}",
                self.install_origin.detail()
            );
            let _ = writeln!(out, "  policy_epoch:         {}", hb.policy_epoch);
            let _ = writeln!(out, "  store_schema_version: {}", hb.store_schema_version);
            let _ = writeln!(out, "  binary version:       {}", env!("CARGO_PKG_VERSION"));
        } else {
            let _ = writeln!(out, "  data_dir:             {}", self.data_dir.display());
            let _ = writeln!(
                out,
                "  install_origin:       {}",
                self.install_origin.detail()
            );
            let _ = writeln!(out, "  binary version:       {}", env!("CARGO_PKG_VERSION"));
        }

        // Workload block.
        let _ = writeln!(out);
        let _ = writeln!(out, "Workload:");
        if let Some(w) = &self.workload {
            // Per-channel session split: per spec §5.2.2 the
            // planner / gateway / verifier counters live in heartbeat
            // (best-effort). When unavailable, render the SQL total
            // alone — the per-channel split is not load-bearing for
            // any operator decision.
            if let Some(hb) = &self.heartbeat {
                let _ = writeln!(
                    out,
                    "  active sessions:    {} (planner={}, gateway={}, verifier={})",
                    w.sessions.active,
                    hb.active_planner_sessions,
                    hb.active_gateway_sessions,
                    hb.active_verifier_sessions,
                );
                let _ = writeln!(
                    out,
                    "  active verifiers:   {} / {} cap",
                    hb.active_verifiers, hb.max_concurrent_verifiers,
                );
                let _ = writeln!(out, "  queued spawns:      {}", hb.queued_spawns);
            } else {
                let _ = writeln!(out, "  active sessions:    {}", w.sessions.active);
            }
            let _ = writeln!(out, "  initiatives running: {}", w.initiatives.executing);
            let _ = writeln!(out, "  tasks running:       {}", w.tasks.running);
            let _ = writeln!(
                out,
                "  tasks queued:        {}",
                w.tasks.admitted.saturating_add(w.tasks.gates_pending)
            );
            let _ = writeln!(
                out,
                "  tasks blocked:       {}",
                w.tasks.blocked_recovery_pending
            );
            let _ = writeln!(out, "  pending escalations: {}", w.pending_escalations);
        } else {
            let _ = writeln!(out, "  (kernel.db unavailable)");
        }
        if let Some(e) = &self.db_error {
            let _ = writeln!(out, "  WARNING: {e}");
        }

        // Audit chain block.
        let _ = writeln!(out);
        let chain_line = match &self.chain {
            ChainQuickCheck::Ok { segment, last_seq } => {
                format!(
                    "Audit chain:           OK ({}, last seq={last_seq})",
                    segment
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| segment.display().to_string())
                )
            }
            ChainQuickCheck::NoSegments => {
                "Audit chain:           (no segments yet — fresh kernel)".to_owned()
            }
            ChainQuickCheck::Broken { segment, reason } => {
                format!(
                    "Audit chain:           BROKEN ({}: {reason})",
                    segment.display()
                )
            }
        };
        let _ = writeln!(out, "{chain_line}");
    }

    /// Map the report onto a JSON object. Field set is a superset of
    /// the human output so `--json` consumers never have to reach
    /// for the human formatter.
    fn to_json_value(&self) -> serde_json::Value {
        let liveness_str = match &self.liveness {
            Liveness::Running => "Running",
            Liveness::AmbiguousPidGone { .. } => "AmbiguousPidGone",
            Liveness::Stopped { .. } => "Stopped",
            Liveness::Missing { .. } => "Missing",
        };
        let liveness_detail = match &self.liveness {
            Liveness::Running => serde_json::Value::Null,
            Liveness::AmbiguousPidGone { pid } => serde_json::json!({ "pid": pid }),
            Liveness::Stopped {
                reason: StoppedReason::Stopping,
            } => serde_json::json!({ "reason": "Stopping" }),
            Liveness::Stopped {
                reason: StoppedReason::Stale { age_secs },
            } => serde_json::json!({ "reason": "Stale", "age_secs": age_secs }),
            Liveness::Missing { detail } => serde_json::json!({ "detail": detail }),
        };

        let chain_obj = match &self.chain {
            ChainQuickCheck::Ok { segment, last_seq } => serde_json::json!({
                "status":   "Ok",
                "segment":  segment.display().to_string(),
                "last_seq": last_seq,
            }),
            ChainQuickCheck::NoSegments => serde_json::json!({
                "status": "NoSegments",
            }),
            ChainQuickCheck::Broken { segment, reason } => serde_json::json!({
                "status":  "Broken",
                "segment": segment.display().to_string(),
                "reason":  reason,
            }),
        };

        let heartbeat_age_ms = self.heartbeat.as_ref().map(|hb| {
            self.now_secs
                .saturating_sub(hb.last_heartbeat_at)
                .saturating_mul(1_000)
        });

        serde_json::json!({
            "data_dir":         self.data_dir.display().to_string(),
            "install_origin":   self.install_origin,
            "liveness":         liveness_str,
            "liveness_detail":  liveness_detail,
            "heartbeat":        self.heartbeat,
            "heartbeat_age_ms": heartbeat_age_ms,
            "workload":         self.workload,
            "db_error":         self.db_error,
            "audit_chain":      chain_obj,
            "now_secs":         self.now_secs,
            "exit_code":        self.exit_code(),
        })
    }
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

fn format_ro_error(e: &RoError) -> String {
    // Render specific RoError variants as one-liners. The full
    // `Display` is fine here; we just want it on its own line.
    e.to_string()
}

/// `kill(pid, 0)` semantics on POSIX: returns true iff the kernel can
/// see a process with this PID owned by a uid we can signal. The
/// docs spell out "errno=ESRCH means dead"; everything else (EPERM,
/// success) means "exists".
fn is_pid_alive(pid: u32) -> bool {
    // SAFETY: `kill(2)` with sig=0 is the documented existence check;
    // it dereferences no Rust-managed pointers and has no thread-
    // safety hazards.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    // EPERM means the process exists but we don't own it — we still
    // count that as "alive" because something IS holding the PID.
    // Anything else (notably ESRCH) is "dead".
    errno_value() == libc::EPERM
}

/// Portable read of POSIX `errno`. Apple platforms use the `__error`
/// symbol; glibc / musl Linux use `__errno_location`. Both return a
/// `*mut c_int` to a thread-local storage slot.
fn errno_value() -> i32 {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    unsafe {
        *libc::__error()
    }
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
    unsafe {
        *libc::__errno_location()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn format_uptime(secs: u64) -> String {
    // Spec output sample: `3h 17m 22s`. We render hours/minutes/
    // seconds (skipping zero leading components) and downgrade to
    // bare `<n>s` when uptime is less than one minute.
    let hours = secs / 3_600;
    let mins = (secs % 3_600) / 60;
    let s = secs % 60;
    if hours > 0 {
        format!("{hours}h {mins}m {s}s")
    } else if mins > 0 {
        format!("{mins}m {s}s")
    } else {
        format!("{s}s")
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
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
    use raxis_runtime::{write_atomic, KernelLifecycleState, HEARTBEAT_FILE, RUNTIME_DIR};
    use std::sync::Arc;
    use tempfile::TempDir;

    /// Build a tempdir that looks like a freshly-bootstrapped data_dir,
    /// optionally with a writable kernel.db preloaded.
    fn make_data_dir(with_db: bool) -> TempDir {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(RUNTIME_DIR)).unwrap();
        std::fs::create_dir_all(tmp.path().join("audit")).unwrap();
        if with_db {
            // Open + drop to materialise migrations + schema_version row.
            let _ = raxis_store::Store::open(&tmp.path().join("kernel.db")).unwrap();
        }
        tmp
    }

    fn write_heartbeat(data_dir: &Path, snap: raxis_runtime::Snapshot) {
        let path = data_dir.join(RUNTIME_DIR).join(HEARTBEAT_FILE);
        write_atomic(&path, &snap).unwrap();
    }

    fn fresh_running_snapshot(pid: u32, now: u64) -> raxis_runtime::Snapshot {
        // started_at = now - 5m, last_heartbeat_at = now - 1s (well
        // inside the staleness window).
        raxis_runtime::Snapshot::new(
            pid,
            now.saturating_sub(300),
            now.saturating_sub(1),
            KernelLifecycleState::Running,
            7,
            0,
            8,
            0,
            0,
            0,
            0,
        )
    }

    fn write_audit_segment_ok(data_dir: &Path, last_seq: u64) {
        let segment = data_dir.join("audit").join("segment-000.jsonl");
        let line = serde_json::json!({
            "seq": last_seq,
            "event_kind": "TestEvent",
            "prev_sha256": "00".repeat(32),
        })
        .to_string();
        std::fs::write(&segment, format!("{line}\n")).unwrap();
    }

    #[test]
    fn liveness_running_when_heartbeat_fresh_and_pid_alive() {
        let tmp = make_data_dir(true);
        let now = unix_now_secs();
        // Use OUR pid — guaranteed alive from inside the test.
        let snap = fresh_running_snapshot(std::process::id(), now);
        write_heartbeat(tmp.path(), snap);

        let report = collect(tmp.path());
        assert!(
            matches!(report.liveness, Liveness::Running),
            "expected Running; got {:?}",
            report.liveness
        );
    }

    #[test]
    fn liveness_missing_when_no_heartbeat_file_exists() {
        let tmp = make_data_dir(true);
        let report = collect(tmp.path());
        match &report.liveness {
            Liveness::Missing { detail } => {
                assert!(
                    detail.contains("no heartbeat") || detail.contains("never started"),
                    "unexpected detail: {detail}"
                );
            }
            other => panic!("expected Missing; got {other:?}"),
        }
        assert_eq!(report.exit_code(), 1, "missing heartbeat must exit 1");
    }

    #[test]
    fn liveness_stopped_when_heartbeat_state_is_stopping() {
        let tmp = make_data_dir(true);
        let now = unix_now_secs();
        let mut snap = fresh_running_snapshot(std::process::id(), now);
        snap.state = KernelLifecycleState::Stopping.as_str().to_owned();
        write_heartbeat(tmp.path(), snap);

        let report = collect(tmp.path());
        match report.liveness {
            Liveness::Stopped {
                reason: StoppedReason::Stopping,
            } => {}
            other => panic!("expected Stopped(Stopping); got {other:?}"),
        }
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn liveness_stopped_when_heartbeat_too_old() {
        let tmp = make_data_dir(true);
        let now = unix_now_secs();
        let mut snap = fresh_running_snapshot(std::process::id(), now);
        // Push last_heartbeat_at to one second past the stale window.
        snap.last_heartbeat_at =
            now.saturating_sub(raxis_runtime::HEARTBEAT_STALE_AFTER.as_secs() + 1);
        write_heartbeat(tmp.path(), snap);

        let report = collect(tmp.path());
        match report.liveness {
            Liveness::Stopped {
                reason: StoppedReason::Stale { age_secs },
            } => assert!(age_secs >= raxis_runtime::HEARTBEAT_STALE_AFTER.as_secs()),
            other => panic!("expected Stopped(Stale); got {other:?}"),
        }
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn liveness_ambiguous_when_heartbeat_fresh_but_pid_dead() {
        let tmp = make_data_dir(true);
        let now = unix_now_secs();
        // PID 1 typically exists (init), so use a clearly-dead very-
        // high PID. If the host happens to allocate this PID we'll
        // get a false negative; PID space on Linux is 32-bit but the
        // default sysctl cap is 4194304, so 4_000_000_000 is reliably
        // unused.
        let dead_pid = 4_000_000_000u32;
        let snap = fresh_running_snapshot(dead_pid, now);
        write_heartbeat(tmp.path(), snap);

        let report = collect(tmp.path());
        match report.liveness {
            Liveness::AmbiguousPidGone { pid } => assert_eq!(pid, dead_pid),
            other => panic!("expected AmbiguousPidGone; got {other:?}"),
        }
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn chain_quick_check_ok_for_well_formed_segment() {
        let tmp = make_data_dir(false);
        write_audit_segment_ok(tmp.path(), 123);
        let chain = collect_chain_quick_check(tmp.path());
        match chain {
            ChainQuickCheck::Ok { last_seq, .. } => assert_eq!(last_seq, 123),
            other => panic!("expected Ok; got {other:?}"),
        }
    }

    #[test]
    fn chain_quick_check_no_segments_when_audit_dir_empty() {
        let tmp = make_data_dir(false);
        let chain = collect_chain_quick_check(tmp.path());
        assert!(matches!(chain, ChainQuickCheck::NoSegments));
    }

    #[test]
    fn chain_quick_check_no_segments_when_audit_dir_missing() {
        let tmp = TempDir::new().unwrap();
        let chain = collect_chain_quick_check(tmp.path());
        assert!(matches!(chain, ChainQuickCheck::NoSegments));
    }

    #[test]
    fn chain_quick_check_broken_when_last_line_malformed() {
        let tmp = make_data_dir(false);
        let segment = tmp.path().join("audit").join("segment-000.jsonl");
        std::fs::write(&segment, "{malformed\n").unwrap();
        let chain = collect_chain_quick_check(tmp.path());
        assert!(matches!(chain, ChainQuickCheck::Broken { .. }));
    }

    #[test]
    fn chain_quick_check_broken_takes_precedence_over_running() {
        let tmp = make_data_dir(true);
        let now = unix_now_secs();
        write_heartbeat(tmp.path(), fresh_running_snapshot(std::process::id(), now));
        // Garbage last line.
        let segment = tmp.path().join("audit").join("segment-000.jsonl");
        std::fs::write(&segment, "garbage\n").unwrap();

        let report = collect(tmp.path());
        assert_eq!(
            report.exit_code(),
            3,
            "chain break must trump live liveness"
        );
    }

    #[test]
    fn chain_quick_check_picks_highest_numbered_segment() {
        let tmp = make_data_dir(false);
        // Three segments, latest is 002 with seq=42.
        std::fs::write(
            tmp.path().join("audit").join("segment-000.jsonl"),
            r#"{"seq":1,"prev_sha256":""}"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("audit").join("segment-001.jsonl"),
            r#"{"seq":10,"prev_sha256":""}"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("audit").join("segment-002.jsonl"),
            r#"{"seq":42,"prev_sha256":""}"#,
        )
        .unwrap();

        let chain = collect_chain_quick_check(tmp.path());
        match chain {
            ChainQuickCheck::Ok { segment, last_seq } => {
                assert_eq!(last_seq, 42);
                assert!(segment.to_string_lossy().ends_with("segment-002.jsonl"));
            }
            other => panic!("expected Ok on segment-002; got {other:?}"),
        }
    }

    #[test]
    fn workload_counts_combine_initiative_task_session_escalation() {
        const INITIATIVES: &str = raxis_store::Table::Initiatives.as_str();
        const TASKS: &str = raxis_store::Table::Tasks.as_str();
        const SESSIONS: &str = raxis_store::Table::Sessions.as_str();

        let tmp = make_data_dir(true);
        // Seed one initiative + two tasks + one session.
        let store = raxis_store::Store::open(&tmp.path().join("kernel.db")).unwrap();
        {
            let guard = store.lock_sync();
            guard.execute(
                &format!(
                    "INSERT INTO {INITIATIVES} \
                     (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                     VALUES ('i-1', 'Executing', '{{}}', 'sha-1', 1)"
                ),
                [],
            ).unwrap();
            guard
                .execute(
                    &format!(
                        "INSERT INTO {TASKS} \
                     (task_id, initiative_id, lane_id, state, actor, policy_epoch, \
                      admitted_at, transitioned_at) \
                     VALUES ('t-1', 'i-1', 'd', 'Running', 'op', 1, 1, 1), \
                            ('t-2', 'i-1', 'd', 'Admitted', 'op', 1, 1, 1)"
                    ),
                    [],
                )
                .unwrap();
            guard
                .execute(
                    &format!(
                        "INSERT INTO {SESSIONS} \
                     (session_id, role_id, session_token, lineage_id, fetch_quota, \
                      created_at, expires_at, revoked) \
                     VALUES ('s-1', 'planner', 'tok', 'lin', 0, 1, 9999999999, 0)"
                    ),
                    [],
                )
                .unwrap();
        }
        drop(store);

        // Force liveness to Missing so we exercise pure-DB rendering;
        // collect() opens its own RoConn.
        let report = collect(tmp.path());
        let w = report.workload.expect("workload should be populated");
        assert_eq!(w.initiatives.executing, 1);
        assert_eq!(w.tasks.running, 1);
        assert_eq!(w.tasks.admitted, 1);
        assert_eq!(w.sessions.active, 1);
        assert_eq!(w.pending_escalations, 0);
    }

    #[test]
    fn json_render_includes_every_required_field() {
        let tmp = make_data_dir(true);
        let now = unix_now_secs();
        write_heartbeat(tmp.path(), fresh_running_snapshot(std::process::id(), now));
        write_audit_segment_ok(tmp.path(), 5);

        let report = collect(tmp.path());
        let v = report.to_json_value();
        for k in [
            "data_dir",
            "liveness",
            "liveness_detail",
            "heartbeat",
            "heartbeat_age_ms",
            "workload",
            "db_error",
            "audit_chain",
            "now_secs",
            "exit_code",
        ] {
            assert!(
                v.get(k).is_some(),
                "missing JSON field {k}; got keys: {:?}",
                v.as_object().unwrap().keys().collect::<Vec<_>>()
            );
        }
        assert_eq!(v["liveness"], serde_json::json!("Running"));
        assert_eq!(v["audit_chain"]["status"], serde_json::json!("Ok"));
        assert_eq!(v["exit_code"], serde_json::json!(0));
    }

    #[test]
    fn human_render_handles_no_heartbeat_gracefully() {
        let tmp = make_data_dir(true);
        let report = collect(tmp.path());
        let mut buf: Vec<u8> = Vec::new();
        report.render_human(&mut buf);
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.contains("STOPPED"),
            "expected STOPPED headline; got: {text}"
        );
        assert!(
            text.contains("data_dir:"),
            "must render data_dir line: {text}"
        );
    }

    #[test]
    fn human_render_workload_block_uses_running_state_for_initiatives() {
        let tmp = make_data_dir(true);
        let now = unix_now_secs();
        write_heartbeat(tmp.path(), fresh_running_snapshot(std::process::id(), now));
        write_audit_segment_ok(tmp.path(), 5);
        let report = collect(tmp.path());
        let mut buf: Vec<u8> = Vec::new();
        report.render_human(&mut buf);
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("RAXIS Kernel: RUNNING"), "got: {text}");
        assert!(text.contains("initiatives running:"), "got: {text}");
        assert!(text.contains("tasks running:"), "got: {text}");
        assert!(text.contains("Audit chain:"), "got: {text}");
    }

    #[test]
    fn format_uptime_handles_three_branches() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(45), "45s");
        assert_eq!(format_uptime(125), "2m 5s");
        assert_eq!(format_uptime(3 * 3600 + 17 * 60 + 22), "3h 17m 22s");
    }

    #[test]
    fn is_pid_alive_returns_true_for_self() {
        assert!(is_pid_alive(std::process::id()));
    }

    #[test]
    fn is_pid_alive_returns_false_for_clearly_dead_pid() {
        // Same reasoning as the AmbiguousPidGone test.
        assert!(!is_pid_alive(4_000_000_000));
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(&["--bogus".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_accepts_json_flag() {
        let opts = parse_args(&["--json".to_owned()]).unwrap();
        assert!(opts.json);
    }

    // Sanity: `Arc<...>` should be hashable for verifying we don't
    // accidentally take ownership of `data_dir`. (Compile-only test.)
    #[allow(dead_code)]
    fn _arc_path_compiles() -> Arc<PathBuf> {
        Arc::new(PathBuf::from("/"))
    }
}
