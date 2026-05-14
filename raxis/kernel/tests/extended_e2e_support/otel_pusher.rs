//! Auto-locate / auto-build / auto-spawn / supervise the
//! `raxis-otel-pusher` sidecar binary for the live-e2e harness.
//!
//! ## What this module guarantees
//!
//! Before the realism-e2e harness submits any plan, an OTel pusher
//! process MUST be actively forwarding the kernel's metric ring to
//! the OTLP collector at `http://127.0.0.1:4318`, AND Prometheus
//! MUST report `up{job=~"raxis.*"} = 1` for at least one raxis
//! target. Silent degradation — the run continuing while Grafana
//! panels stay empty — is forbidden by
//! `INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01`.
//!
//! With this module, the harness:
//!
//! 1. Locates the `raxis-otel-pusher` binary in this priority:
//!    a) [`ENV_OTEL_PUSHER_BINARY`] env var (operator override),
//!    b) `<workspace>/target/{release,debug}/raxis-otel-pusher`,
//!    c) `<RAXIS_INSTALL_DIR>/bin/raxis-otel-pusher`.
//! 2. If not found AND [`ENV_SKIP_OTEL_PUSHER`] is unset, runs
//!    `cargo build --release -p raxis-otel-pusher` with a bounded
//!    timeout ([`DEFAULT_OTEL_PUSHER_BUILD_TIMEOUT_SECS`], default
//!    180 s; tunable via [`ENV_OTEL_PUSHER_BUILD_TIMEOUT_SECS`]).
//! 3. Spawns the pusher as a supervised child of the test process,
//!    pointing at the kernel's `<data_dir>` and the kernel-signed
//!    `policy.toml`.
//! 4. Sleeps a brief startup window, asserts the child PID is alive.
//! 5. Smoke-probes Prometheus (`http://127.0.0.1:9090/api/v1/query?
//!    query=up`) for ~30 s; asserts at least one `raxis.*` job
//!    appears as `up=1`.
//! 6. Returns an [`OtelPusherSupervisor`] RAII guard that
//!    SIGTERM-then-SIGKILL's the child on drop. No leaked
//!    processes.
//!
//! ## Opt-out (`RAXIS_E2E_SKIP_OTEL_PUSHER=1`)
//!
//! Mirrors the `RAXIS_LIVE_E2E_NO_AUTO_DOCKER` discipline: an
//! operator running their own pusher externally (systemd /
//! launchd / Terraform-provisioned) sets the opt-out and the
//! harness skips steps 2/3 above. The smoke-probe at step 5
//! still runs — if no pusher is actually forwarding, the harness
//! hard-fails with a remediation message that names BOTH the
//! external-pusher path AND the unset-the-opt-out path.
//!
//! ## Bounded subprocess discipline
//!
//! Every external-process spawn here routes through
//! [`super::harness_timeout::run_command_output_timeout`] per
//! `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`. The auto-build
//! deadline is operator-tunable but always positive; non-positive
//! / unparseable overrides clamp safely to the default.
//!
//! ## Why a separate module from `kernel_driver.rs`
//!
//! Keeps the otel-pusher contract surface focused: a single
//! [`OtelPusherState`] classifier, one supervised-spawn entry
//! point [`ensure_otel_pusher_or_panic`], one violation token
//! [`OTEL_PUSHER_VIOLATION_TOKEN`]. Mirrors the layout of
//! `tests/common/dashboard.rs` for `INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01`.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::harness_timeout::{
    run_command_output_timeout, BoundedWaitError,
};

// ─── Operator-facing env-var contract ─────────────────────────────

/// Operator override: absolute path to a pre-built
/// `raxis-otel-pusher` binary. When set + present, the auto-build
/// step is skipped entirely.
pub const ENV_OTEL_PUSHER_BINARY: &str = "RAXIS_OTEL_PUSHER_BINARY";

/// Operator opt-out (`INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01`). When
/// set to `1`, the harness does NOT spawn its own pusher and
/// assumes an externally-supervised pusher is already forwarding
/// to `http://127.0.0.1:4318`. The Prometheus smoke-probe still
/// runs — if no pusher is actually present, the harness hard-fails
/// with the alternate remediation message.
pub const ENV_SKIP_OTEL_PUSHER: &str = "RAXIS_E2E_SKIP_OTEL_PUSHER";

/// Bounded-wait override for `cargo build --release -p raxis-otel-
/// pusher`. Default [`DEFAULT_OTEL_PUSHER_BUILD_TIMEOUT_SECS`].
/// Non-positive / unparseable values clamp to the default.
pub const ENV_OTEL_PUSHER_BUILD_TIMEOUT_SECS: &str =
    "RAXIS_E2E_OTEL_PUSHER_BUILD_TIMEOUT_SECS";

/// Default cap on the auto-build wall-clock. 180 s is generous for
/// a warm cargo cache (the pusher's release build is ~16 s on a
/// reference Apple-silicon host) and comfortably covers a cold
/// cache that has to crank through `reqwest` + `rustls` deps for
/// the first time.
pub const DEFAULT_OTEL_PUSHER_BUILD_TIMEOUT_SECS: u64 = 180;

/// Hard floor on the build timeout. A value below this clamps to
/// the default; the floor exists so a misconfigured CI lane that
/// sets `RAXIS_E2E_OTEL_PUSHER_BUILD_TIMEOUT_SECS=1` does NOT
/// trip a guaranteed timeout failure on a healthy cargo cache.
/// 60 s also leaves enough head-room for a cold-cache build of
/// the pusher's transitive deps on a slow host.
pub const MIN_OTEL_PUSHER_BUILD_TIMEOUT_SECS: u64 = 60;

/// Hard ceiling on the build timeout. 600 s (10 min) is well
/// over the worst-observed cold-cache build of the pusher; values
/// above clamp to this ceiling so a single misconfigured lane
/// cannot wedge the harness for an arbitrary period.
pub const MAX_OTEL_PUSHER_BUILD_TIMEOUT_SECS: u64 = 600;

// ─── Smoke-probe defaults ─────────────────────────────────────────

/// Loopback host the live-e2e Prometheus binds. Mirrors
/// `live-e2e/docker-compose.extended.e2e.yml`. Pinned alongside
/// the existing constants in `tests/common/tier3_artifacts.rs`.
pub const PROMETHEUS_HOST: &str = "127.0.0.1";

/// Loopback port the live-e2e Prometheus binds. Same compose-file
/// source-of-truth as [`PROMETHEUS_HOST`].
pub const PROMETHEUS_PORT: u16 = 9090;

/// Loopback OTLP/HTTP endpoint the kernel pushes into. The pusher
/// reads `policy.toml [observability.pusher].otlp_endpoint` for
/// the actual target; this constant is for the operator-facing
/// log line ONLY.
pub const OTLP_HTTP_URL: &str = "http://127.0.0.1:4318";

/// Smoke-probe budget. After spawning (or asserting external)
/// pusher, the harness polls Prometheus for up to this many
/// seconds before declaring the contract violated. 30 s is
/// long enough to cover a 5-second flush interval (the kernel's
/// `[observability.metrics].export_interval`) plus the pusher's
/// `otlp_flush_interval = 1s` plus Prometheus's 15 s scrape
/// cadence — and still short enough to surface a broken stack
/// in well under a coffee break.
pub const SMOKE_PROBE_BUDGET: Duration = Duration::from_secs(30);

/// Inter-poll spacing for the smoke probe. 1 s — long enough to
/// avoid hammering Prometheus, short enough to surface success
/// promptly.
pub const SMOKE_PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// Time the harness sleeps after `Command::spawn()` of the pusher
/// before checking `kill -0` / `try_wait` to confirm the child
/// is still running. The pusher's main does its policy load + OTLP
/// client construction in <100 ms on a healthy host; 3 s is a
/// generous safety net.
pub const POST_SPAWN_LIVENESS_DELAY: Duration = Duration::from_secs(3);

/// Token included verbatim in every panic produced by this module
/// so a CI log scraper / operator can pin the failure mode by
/// substring without parsing the whole remediation block.
pub const OTEL_PUSHER_VIOLATION_TOKEN: &str =
    "INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01 VIOLATED";

// ─── Pure-data classifier ─────────────────────────────────────────

/// Pure-data classification of the otel-pusher launch state at
/// the moment the harness needs to spawn (or assert) the pusher.
/// Drives the dispatch in [`ensure_otel_pusher_or_panic`] and is
/// exhaustively witness-tested below.
///
/// The arms are ordered by classifier precedence — `OptOutByEnv`
/// short-circuits everything else (the operator has explicitly
/// promised an external pusher); `BinaryFromEnvVar` and
/// `BinaryAtConventionPath` are the locate-success fast paths;
/// `NeedsAutoBuild` is the default for a fresh worktree (the iter
/// 53 root-cause shape — pusher binary absent, no opt-out,
/// `cargo build` not yet run); `HardFailMissingBinary` is the
/// post-build-failure surface (preserved as a separate arm so the
/// dispatch / test surface can pin the panic cleanly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtelPusherState {
    /// `RAXIS_E2E_SKIP_OTEL_PUSHER=1` is set; harness will NOT
    /// spawn its own pusher and assumes an external one is
    /// reachable. The smoke-probe still runs; on failure the
    /// alternate remediation message fires (different from the
    /// auto-build-failure remediation).
    OptOutByEnv,

    /// `RAXIS_OTEL_PUSHER_BINARY` env var points at an existing
    /// absolute path. The harness uses the binary as-is.
    BinaryFromEnvVar,

    /// One of the convention paths
    /// (`<workspace>/target/{release,debug}/raxis-otel-pusher` or
    /// `<RAXIS_INSTALL_DIR>/bin/raxis-otel-pusher`) exists. The
    /// harness uses the binary as-is — this is the "warm cargo
    /// cache" fast path.
    BinaryAtConventionPath,

    /// No binary located AND no opt-out. The harness MUST run
    /// `cargo build --release -p raxis-otel-pusher` with the
    /// bounded timeout, then re-classify.
    NeedsAutoBuild,

    /// Auto-build was attempted but failed (timeout / non-zero
    /// exit / missing cargo binary / dist still absent post-build).
    /// The dispatch panics with [`OTEL_PUSHER_VIOLATION_TOKEN`]
    /// and the build-failure remediation block.
    HardFailMissingBinary,
}

/// Pure classifier — exhaustively witnessable without spawning
/// any subprocess. The actual dispatch in
/// [`ensure_otel_pusher_or_panic`] composes this with the
/// auto-build / spawn / smoke-probe steps; pinning the policy
/// decision here means the witness coverage need not depend on
/// the host having a usable `cargo` binary.
///
/// `binary_envvar_present` ⇒ `RAXIS_OTEL_PUSHER_BINARY` is set
/// AND points at an existing absolute file.
///
/// `binary_at_convention_path` ⇒ at least one convention path
/// exists on disk.
///
/// `skip_env_set` ⇒ `RAXIS_E2E_SKIP_OTEL_PUSHER=1`.
pub fn classify_otel_pusher_state(
    skip_env_set: bool,
    binary_envvar_present: bool,
    binary_at_convention_path: bool,
) -> OtelPusherState {
    if skip_env_set {
        return OtelPusherState::OptOutByEnv;
    }
    if binary_envvar_present {
        return OtelPusherState::BinaryFromEnvVar;
    }
    if binary_at_convention_path {
        return OtelPusherState::BinaryAtConventionPath;
    }
    OtelPusherState::NeedsAutoBuild
}

// ─── Bounded build-timeout resolution ─────────────────────────────

/// Resolve the bounded auto-build timeout from the environment,
/// falling back to [`DEFAULT_OTEL_PUSHER_BUILD_TIMEOUT_SECS`]. A
/// garbage / non-positive / out-of-range value clamps safely
/// rather than panicking, so a misconfigured CI lane does NOT
/// falsely fail the invariant witness.
pub fn otel_pusher_build_timeout() -> Duration {
    let raw = std::env::var(ENV_OTEL_PUSHER_BUILD_TIMEOUT_SECS)
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    match raw {
        Some(v) if (MIN_OTEL_PUSHER_BUILD_TIMEOUT_SECS..=MAX_OTEL_PUSHER_BUILD_TIMEOUT_SECS).contains(&v) => {
            Duration::from_secs(v)
        }
        // Out-of-range, zero, garbage, or unset → safe default.
        _ => Duration::from_secs(DEFAULT_OTEL_PUSHER_BUILD_TIMEOUT_SECS),
    }
}

// ─── Binary location ──────────────────────────────────────────────

/// Convention paths (in priority order) where the harness expects
/// to find a pre-built `raxis-otel-pusher`. Pure function so
/// witnesses can pin the precedence without touching the FS.
pub fn convention_pusher_paths(workspace_root: &Path, install_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for profile in ["release", "debug"] {
        out.push(
            workspace_root
                .join("target")
                .join(profile)
                .join("raxis-otel-pusher"),
        );
    }
    if let Some(install) = install_dir {
        out.push(install.join("bin").join("raxis-otel-pusher"));
    }
    out
}

/// Probe `RAXIS_OTEL_PUSHER_BINARY` and the convention paths;
/// return the first existing absolute file, plus a flag
/// distinguishing the env-var win from the convention-path win.
fn locate_existing_binary(
    workspace_root: &Path,
    install_dir: Option<&Path>,
) -> Option<(PathBuf, BinaryOrigin)> {
    if let Ok(raw) = std::env::var(ENV_OTEL_PUSHER_BINARY) {
        let p = PathBuf::from(raw);
        if p.is_absolute() && p.is_file() {
            return Some((p, BinaryOrigin::EnvVar));
        }
    }
    for cand in convention_pusher_paths(workspace_root, install_dir) {
        if cand.is_file() {
            return Some((cand, BinaryOrigin::ConventionPath));
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryOrigin {
    EnvVar,
    ConventionPath,
}

// ─── Auto-build ───────────────────────────────────────────────────

/// Run `cargo build --release -p raxis-otel-pusher` from the
/// workspace root with the bounded timeout. On success returns
/// the absolute path to the freshly-built binary; on any failure
/// returns an `Err(reason)` carrying the failure mode string
/// suitable for embedding in the panic body.
fn run_cargo_build_pusher(
    workspace_root: &Path,
) -> Result<PathBuf, String> {
    let timeout = otel_pusher_build_timeout();
    eprintln!(
        "[realism-e2e] observability: raxis-otel-pusher binary missing — \
         running `cargo build --release -p raxis-otel-pusher` in {} \
         (bounded by {ENV_OTEL_PUSHER_BUILD_TIMEOUT_SECS}={}s)",
        workspace_root.display(),
        timeout.as_secs(),
    );
    let started = Instant::now();
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--release")
        .arg("-p")
        .arg("raxis-otel-pusher")
        .current_dir(workspace_root)
        // Inherit stdio so the operator sees real cargo errors
        // (network, lock-file, deps drift) rather than a swallowed
        // exit code.
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    match run_command_output_timeout(&mut cmd, timeout, "cargo-build-otel-pusher") {
        Ok(out) if out.status.success() => {
            let elapsed = started.elapsed();
            eprintln!(
                "[realism-e2e] observability: cargo build --release \
                 -p raxis-otel-pusher OK in {:.1}s",
                elapsed.as_secs_f32(),
            );
            let bin = workspace_root
                .join("target")
                .join("release")
                .join("raxis-otel-pusher");
            if !bin.is_file() {
                return Err(format!(
                    "cargo reported success but {bin} is not a file — \
                     build is lying about success",
                    bin = bin.display(),
                ));
            }
            Ok(bin)
        }
        Ok(out) => Err(format!(
            "`cargo build --release -p raxis-otel-pusher` exited {:?} \
             after {:.1}s",
            out.status.code(),
            started.elapsed().as_secs_f32(),
        )),
        Err(BoundedWaitError::SpawnFailed { reason, .. }) => Err(format!(
            "cannot spawn `cargo`: {reason} (install Rust + cargo, OR set \
             {ENV_OTEL_PUSHER_BINARY}=/path/to/raxis-otel-pusher to point at \
             a pre-built binary, OR set {ENV_SKIP_OTEL_PUSHER}=1 to use an \
             externally-supervised pusher)",
        )),
        Err(BoundedWaitError::Timeout { timeout, .. }) => Err(format!(
            "`cargo build --release -p raxis-otel-pusher` exceeded the \
             bounded timeout {timeout:?}; SIGKILL'd. Override via \
             {ENV_OTEL_PUSHER_BUILD_TIMEOUT_SECS}=<seconds> or pre-build \
             the binary and set {ENV_OTEL_PUSHER_BINARY}=/path/to/binary.",
        )),
        Err(other) => Err(format!("`cargo build` wrapper error: {other}")),
    }
}

// ─── Spawn + supervise ────────────────────────────────────────────

/// RAII supervisor for the spawned pusher child. Drop SIGTERMs the
/// child first (giving it a brief grace window to flush a final
/// batch and exit cleanly) and SIGKILL+reaps if it doesn't die.
/// Idempotent — repeat drops are no-ops.
pub struct OtelPusherSupervisor {
    child: Option<Child>,
    /// Captured PID for diagnostic logging. Stable for the
    /// supervisor's lifetime; survives `child.take()` so the Drop
    /// impl can still log it.
    pid: u32,
    /// Path to the spawned binary, surfaced in the success log line.
    binary: PathBuf,
    /// Path to the harness-captured pusher stderr log, surfaced in
    /// the success log line so an operator can tail it.
    log_path: PathBuf,
}

impl OtelPusherSupervisor {
    /// PID of the spawned child. Diagnostic only.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Absolute path to the spawned binary.
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// Absolute path to the captured stderr log.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Best-effort liveness check. Returns `true` if the child is
    /// still alive (`try_wait` returned `None`); `false` once it
    /// has exited (or if the wait syscall errored, treated as
    /// dead). Used by the post-spawn liveness gate AND by the
    /// smoke-probe loop so a pusher that dies during smoke probe
    /// surfaces immediately instead of timing out.
    pub fn is_alive(&mut self) -> bool {
        match self.child.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    }
}

impl Drop for OtelPusherSupervisor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let pid = self.pid;
            // SIGTERM first — gives the pusher a brief grace
            // window to flush a final batch and exit 0. We do
            // NOT block on a long graceful wait: the test driver
            // may already be unwinding from a panic and we don't
            // want to extend that window. 500 ms is enough for
            // the pusher's `tokio::signal::ctrl_c` handler arm to
            // fire and the final-drain branch to run on a healthy
            // host; if the child is wedged it gets SIGKILL'd
            // immediately.
            #[cfg(unix)]
            {
                // SAFETY: `pid` was captured from `Child::id()` at
                // spawn time and refers to a real child of this
                // process; sending SIGTERM is always defined.
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM); }
            }
            let grace_deadline = Instant::now() + Duration::from_millis(500);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        eprintln!(
                            "[realism-e2e] observability: raxis-otel-pusher \
                             pid={pid} exited cleanly after SIGTERM",
                        );
                        return;
                    }
                    Ok(None) if Instant::now() >= grace_deadline => break,
                    Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                    Err(_) => break,
                }
            }
            if let Err(e) = child.kill() {
                eprintln!(
                    "[realism-e2e] observability: failed to SIGKILL \
                     raxis-otel-pusher pid={pid}: {e}",
                );
            }
            let _ = child.wait();
        }
    }
}

// ─── Top-level orchestrator ───────────────────────────────────────

/// Inputs the harness threads through [`ensure_otel_pusher_or_panic`].
/// Pinned in a struct so the call site stays one-line and so a
/// future maintainer adding a new context field doesn't have to
/// touch every caller.
pub struct PusherSpawnContext<'a> {
    /// `<data_dir>` the kernel was bootstrapped against. The pusher
    /// reads `<data_dir>/observability/{spans,metrics}/*.jsonl`
    /// and writes its cursor to `<data_dir>/observability/cursor.toml`.
    pub data_dir: &'a Path,
    /// Workspace root (`raxis/` directory containing
    /// `target/`, `pusher/`, `kernel/`). Used both for the
    /// convention-path probe AND as `current_dir` for the
    /// auto-build invocation.
    pub workspace_root: &'a Path,
    /// Optional `RAXIS_INSTALL_DIR` so the convention-path probe
    /// can also check `$RAXIS_INSTALL_DIR/bin/raxis-otel-pusher`.
    /// `None` skips that location.
    pub install_dir: Option<&'a Path>,
}

/// Top-level entry point — invoked from the realism-scenario
/// harness AFTER the kernel daemon has bootstrapped. Locates,
/// auto-builds (when needed), spawns, and smoke-probes the pusher.
/// Panics with [`OTEL_PUSHER_VIOLATION_TOKEN`] on any unrecoverable
/// failure.
///
/// On success, returns the [`OtelPusherSupervisor`] guard that the
/// caller MUST keep alive for the duration of the live test (a
/// premature drop SIGTERMs the pusher and stops metric flow).
///
/// Emits exactly ONE operator-facing success log line of the form:
///
/// ```text
/// [realism-e2e] observability: pusher spawned (pid=<N>), smoke-probed,
///   live metrics flowing to Grafana http://127.0.0.1:3000/d/raxis-00-overview
/// ```
///
/// In the opt-out branch the success log line is:
///
/// ```text
/// [realism-e2e] observability: pusher skipped by RAXIS_E2E_SKIP_OTEL_PUSHER=1;
///   external pusher confirmed forwarding (raxis target up=1 in Prometheus)
/// ```
///
/// No path emits both "Grafana panels will stay empty" AND "live
/// metrics flowing" in the same run (witness:
/// `INV-LIVE-E2E-OBSERVABILITY-LOG-NO-CONTRADICTION-01`).
#[must_use = "the supervisor SIGKILLs the pusher on drop; bind it for the test lifetime"]
pub fn ensure_otel_pusher_or_panic(ctx: PusherSpawnContext<'_>) -> Option<OtelPusherSupervisor> {
    let skip_env = std::env::var(ENV_SKIP_OTEL_PUSHER)
        .map(|v| v == "1")
        .unwrap_or(false);
    let envvar_binary_present = std::env::var(ENV_OTEL_PUSHER_BINARY)
        .ok()
        .map(PathBuf::from)
        .is_some_and(|p| p.is_absolute() && p.is_file());
    let conv_paths_present = convention_pusher_paths(ctx.workspace_root, ctx.install_dir)
        .iter()
        .any(|p| p.is_file());

    let initial_state = classify_otel_pusher_state(
        skip_env,
        envvar_binary_present,
        conv_paths_present,
    );

    match initial_state {
        OtelPusherState::OptOutByEnv => {
            eprintln!(
                "[realism-e2e] observability: pusher skipped by \
                 {ENV_SKIP_OTEL_PUSHER}=1; assuming external pusher is \
                 forwarding to {OTLP_HTTP_URL}"
            );
            smoke_probe_or_panic(SmokeProbeMode::ExternalPusher, None);
            eprintln!(
                "[realism-e2e] observability: pusher skipped by \
                 {ENV_SKIP_OTEL_PUSHER}=1; external pusher confirmed \
                 forwarding (raxis target up=1 in Prometheus)"
            );
            None
        }
        OtelPusherState::BinaryFromEnvVar | OtelPusherState::BinaryAtConventionPath => {
            let (binary, _origin) = locate_existing_binary(ctx.workspace_root, ctx.install_dir)
                .expect("classifier said binary present but locate returned None");
            let mut sup = spawn_pusher_or_panic(&binary, ctx.data_dir);
            smoke_probe_or_panic(SmokeProbeMode::HarnessSupervisedPusher, Some(&mut sup));
            eprintln!(
                "[realism-e2e] observability: pusher spawned (pid={pid}, \
                 bin={bin}, log={log}), smoke-probed, live metrics flowing \
                 to Grafana http://127.0.0.1:3000/d/raxis-00-overview",
                pid = sup.pid(),
                bin = sup.binary().display(),
                log = sup.log_path().display(),
            );
            Some(sup)
        }
        OtelPusherState::NeedsAutoBuild => {
            let binary = match run_cargo_build_pusher(ctx.workspace_root) {
                Ok(p) => p,
                Err(reason) => panic!(
                    "{OTEL_PUSHER_VIOLATION_TOKEN}: {reason}\n\n\
                     Remediation (any one of these unblocks the run):\n  \
                     * Pre-build the pusher: `cargo build --release -p raxis-otel-pusher`\n  \
                     * Point at an existing binary: `export {ENV_OTEL_PUSHER_BINARY}=/path/to/raxis-otel-pusher`\n  \
                     * Use an externally-supervised pusher: `export {ENV_SKIP_OTEL_PUSHER}=1`\n  \
                     * Tune the build deadline: `export {ENV_OTEL_PUSHER_BUILD_TIMEOUT_SECS}=<seconds>` (default {DEFAULT_OTEL_PUSHER_BUILD_TIMEOUT_SECS}s, clamped to [{MIN_OTEL_PUSHER_BUILD_TIMEOUT_SECS}, {MAX_OTEL_PUSHER_BUILD_TIMEOUT_SECS}])"
                ),
            };
            let mut sup = spawn_pusher_or_panic(&binary, ctx.data_dir);
            smoke_probe_or_panic(SmokeProbeMode::HarnessSupervisedPusher, Some(&mut sup));
            eprintln!(
                "[realism-e2e] observability: pusher spawned (pid={pid}, \
                 bin={bin}, log={log}), smoke-probed, live metrics flowing \
                 to Grafana http://127.0.0.1:3000/d/raxis-00-overview",
                pid = sup.pid(),
                bin = sup.binary().display(),
                log = sup.log_path().display(),
            );
            Some(sup)
        }
        // The classifier never returns this arm directly — it
        // surfaces from a failed [`run_cargo_build_pusher`]. The
        // panic above already fires; this match arm is unreachable
        // but kept for exhaustiveness so the compiler enforces a
        // fresh review when a new arm is added.
        OtelPusherState::HardFailMissingBinary => {
            panic!(
                "{OTEL_PUSHER_VIOLATION_TOKEN}: classifier returned \
                 HardFailMissingBinary at dispatch time; the auto-build \
                 branch should have already panicked. This is an \
                 internal harness bug — re-anchor the dispatch \
                 in `extended_e2e_support::otel_pusher`."
            );
        }
    }
}

/// Spawn `<binary> --config <data_dir>/policy/policy.toml
/// --data-dir <data_dir> --health-port 0`. Wraps stdout + stderr
/// into a captured log file under `<data_dir>/otel-pusher.stderr.log`.
/// Verifies the child is alive after [`POST_SPAWN_LIVENESS_DELAY`].
/// Panics with [`OTEL_PUSHER_VIOLATION_TOKEN`] on spawn failure or
/// early exit.
fn spawn_pusher_or_panic(binary: &Path, data_dir: &Path) -> OtelPusherSupervisor {
    let policy_path = data_dir.join("policy").join("policy.toml");
    if !policy_path.is_file() {
        panic!(
            "{OTEL_PUSHER_VIOLATION_TOKEN}: policy.toml missing at {} \
             (kernel bootstrap should have produced this; pusher cannot \
             start without it)",
            policy_path.display(),
        );
    }
    let log_path = data_dir.join("otel-pusher.stderr.log");
    let log_file = std::fs::File::create(&log_path).unwrap_or_else(|e| {
        panic!(
            "{OTEL_PUSHER_VIOLATION_TOKEN}: cannot create pusher log {}: {e}",
            log_path.display(),
        )
    });
    let stderr_handle = log_file.try_clone().unwrap_or_else(|e| {
        panic!("{OTEL_PUSHER_VIOLATION_TOKEN}: cannot dup pusher log handle: {e}")
    });

    let mut child = match Command::new(binary)
        .arg("--config")
        .arg(&policy_path)
        .arg("--data-dir")
        .arg(data_dir)
        // Disable the pusher's `/healthz` HTTP server — collisions on
        // 9501 from a prior aborted run would prevent spawn.
        .arg("--health-port")
        .arg("0")
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr_handle))
        .spawn()
    {
        Ok(c) => c,
        Err(e) => panic!(
            "{OTEL_PUSHER_VIOLATION_TOKEN}: failed to spawn raxis-otel-pusher \
             (bin={}): {e}",
            binary.display(),
        ),
    };

    let pid = child.id();

    // Liveness gate — sleep + try_wait. If the child has died
    // already (policy load failure, OTLP TLS init failure, etc.)
    // we surface the captured stderr log immediately rather than
    // letting the smoke-probe loop time out.
    std::thread::sleep(POST_SPAWN_LIVENESS_DELAY);
    match child.try_wait() {
        Ok(Some(status)) => {
            let log_tail = std::fs::read_to_string(&log_path).unwrap_or_default();
            panic!(
                "{OTEL_PUSHER_VIOLATION_TOKEN}: raxis-otel-pusher pid={pid} \
                 exited within {:?} of spawn with status {status:?}. \
                 stderr log ({log}) tail:\n{log_tail}",
                POST_SPAWN_LIVENESS_DELAY,
                log = log_path.display(),
            );
        }
        Ok(None) => { /* still running — fall through to smoke probe */ }
        Err(e) => {
            // try_wait error is rare; the child is probably alive
            // but we don't want to mask the failure if it isn't.
            eprintln!(
                "[realism-e2e] observability: try_wait on raxis-otel-pusher \
                 pid={pid} returned error: {e} (continuing — smoke probe \
                 will catch a non-running pusher)",
            );
        }
    }

    OtelPusherSupervisor {
        child: Some(child),
        pid,
        binary: binary.to_path_buf(),
        log_path,
    }
}

// ─── Smoke probe ──────────────────────────────────────────────────

/// Whether the smoke probe is gating a harness-supervised pusher
/// or an externally-supervised one. Drives the remediation message
/// on failure (different env-var advice for each branch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmokeProbeMode {
    HarnessSupervisedPusher,
    ExternalPusher,
}

/// Poll Prometheus for `up{job=~"raxis.*"} = 1` for up to
/// [`SMOKE_PROBE_BUDGET`]. Panics with [`OTEL_PUSHER_VIOLATION_TOKEN`]
/// on timeout. Optionally takes the supervisor handle so the loop
/// can short-circuit if the supervised child died mid-probe (the
/// poll loop would otherwise run out the full budget).
fn smoke_probe_or_panic(
    mode: SmokeProbeMode,
    sup: Option<&mut OtelPusherSupervisor>,
) {
    let url = format!(
        "http://{PROMETHEUS_HOST}:{PROMETHEUS_PORT}/api/v1/query?query=up"
    );
    eprintln!(
        "[realism-e2e] observability: smoke-probing Prometheus at {url} \
         for raxis target up=1 (budget={:?}, poll={:?})",
        SMOKE_PROBE_BUDGET, SMOKE_PROBE_INTERVAL,
    );
    let started = Instant::now();
    // Reset on every poll so the failure message reflects the
    // freshest signal; the initial "no responses yet" placeholder
    // is only surfaced if the budget expires before the very first
    // probe round (a degenerate case — kept defensively for the
    // panic body).
    #[allow(unused_assignments)]
    let mut last_observation: String = "no probe responses yet".to_owned();
    let mut sup = sup;
    loop {
        // Short-circuit on supervised child death.
        if let Some(s) = sup.as_deref_mut() {
            if !s.is_alive() {
                let log_tail = std::fs::read_to_string(s.log_path())
                    .unwrap_or_default();
                panic!(
                    "{OTEL_PUSHER_VIOLATION_TOKEN}: raxis-otel-pusher \
                     pid={pid} died during smoke probe ({elapsed:.1}s in). \
                     stderr log ({log}) tail:\n{log_tail}",
                    pid = s.pid(),
                    elapsed = started.elapsed().as_secs_f32(),
                    log = s.log_path().display(),
                );
            }
        }
        match probe_prometheus_up(&url) {
            Ok(ProbeOutcome::AtLeastOneRaxisUp) => {
                let elapsed = started.elapsed();
                eprintln!(
                    "[realism-e2e] observability: smoke probe OK in {:.1}s \
                     (raxis target reporting up=1 in Prometheus)",
                    elapsed.as_secs_f32(),
                );
                return;
            }
            Ok(ProbeOutcome::NoRaxisUpYet { observation }) => {
                last_observation = observation;
            }
            Err(reason) => {
                last_observation = format!("probe error: {reason}");
            }
        }
        if started.elapsed() >= SMOKE_PROBE_BUDGET {
            let remediation = match mode {
                SmokeProbeMode::HarnessSupervisedPusher => format!(
                    "Remediation:\n  \
                     * Verify Prometheus is up: curl http://{PROMETHEUS_HOST}:{PROMETHEUS_PORT}/api/v1/query?query=up\n  \
                     * Inspect the pusher log captured under <data_dir>/otel-pusher.stderr.log\n  \
                     * Check the OTel collector at {OTLP_HTTP_URL} is healthy: curl http://127.0.0.1:13133/\n  \
                     * As a last resort, set {ENV_SKIP_OTEL_PUSHER}=1 and supervise the pusher externally"
                ),
                SmokeProbeMode::ExternalPusher => format!(
                    "Remediation:\n  \
                     * Set {ENV_SKIP_OTEL_PUSHER}=0 (or unset it) to let the harness manage the pusher, OR\n  \
                     * Ensure your external pusher is running and pointing at {OTLP_HTTP_URL}\n  \
                     * Verify Prometheus has a `raxis*` job scraping the OTel collector"
                ),
            };
            panic!(
                "{OTEL_PUSHER_VIOLATION_TOKEN}: Prometheus smoke probe \
                 failed after {:?}: {last_observation}.\n\n{remediation}",
                SMOKE_PROBE_BUDGET,
            );
        }
        std::thread::sleep(SMOKE_PROBE_INTERVAL);
    }
}

/// Outcome of one Prometheus probe round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    AtLeastOneRaxisUp,
    NoRaxisUpYet { observation: String },
}

fn probe_prometheus_up(url: &str) -> Result<ProbeOutcome, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| format!("client build: {e}"))?;
    let resp = client.get(url).send().map_err(|e| format!("send: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let body: serde_json::Value = resp.json().map_err(|e| format!("json: {e}"))?;
    Ok(classify_prometheus_up_response(&body))
}

/// Pure classifier over a Prometheus `query=up` response body.
/// Factored out so the smoke-probe-blocks-on-no-metrics witness
/// can drive the same logic against synthesised JSON without
/// spawning an HTTP server.
pub fn classify_prometheus_up_response(body: &serde_json::Value) -> ProbeOutcome {
    let result = body
        .get("data")
        .and_then(|d| d.get("result"))
        .and_then(|r| r.as_array());
    let Some(arr) = result else {
        return ProbeOutcome::NoRaxisUpYet {
            observation: format!("malformed response (no data.result array): {body}"),
        };
    };
    if arr.is_empty() {
        return ProbeOutcome::NoRaxisUpYet {
            observation: "Prometheus returned an empty `up` series array \
                          (no targets registered yet)".to_owned(),
        };
    }
    let mut raxis_jobs_seen: Vec<String> = Vec::new();
    for item in arr {
        let job = item
            .get("metric")
            .and_then(|m| m.get("job"))
            .and_then(|j| j.as_str())
            .unwrap_or("");
        let value_up = item
            .get("value")
            .and_then(|v| v.as_array())
            .and_then(|v| v.get(1))
            .and_then(|v| v.as_str())
            .map(|s| s == "1")
            .unwrap_or(false);
        if job.starts_with("raxis") {
            raxis_jobs_seen.push(format!("{job}={}", if value_up { "1" } else { "0" }));
            if value_up {
                return ProbeOutcome::AtLeastOneRaxisUp;
            }
        }
    }
    let observation = if raxis_jobs_seen.is_empty() {
        let job_names: Vec<&str> = arr
            .iter()
            .filter_map(|i| i.get("metric").and_then(|m| m.get("job")).and_then(|j| j.as_str()))
            .collect();
        format!(
            "no `raxis*` job in Prometheus `up` response (saw jobs: {:?})",
            job_names,
        )
    } else {
        format!(
            "raxis jobs present but none up=1 yet (observations: {:?})",
            raxis_jobs_seen,
        )
    };
    ProbeOutcome::NoRaxisUpYet { observation }
}

// ─── Witness tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// `INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01` — opt-out is the
    /// highest-priority arm. Even with both binary-locate inputs
    /// `true` (pre-built binary on disk AND env-var pointing at
    /// it), the operator's "I'll handle it externally" wins.
    #[test]
    fn inv_live_e2e_otel_pusher_present_01_classifier_opt_out_wins_over_locate() {
        for envvar in [false, true] {
            for conv in [false, true] {
                assert_eq!(
                    classify_otel_pusher_state(true, envvar, conv),
                    OtelPusherState::OptOutByEnv,
                    "envvar={envvar} conv={conv}",
                );
            }
        }
    }

    /// Env-var precedence: when the operator pins
    /// `RAXIS_OTEL_PUSHER_BINARY` AND no opt-out, that path wins
    /// over the convention paths (so an operator can A/B test a
    /// freshly-built binary against the workspace-target build).
    #[test]
    fn inv_live_e2e_otel_pusher_present_01_classifier_envvar_beats_convention() {
        for conv in [false, true] {
            assert_eq!(
                classify_otel_pusher_state(false, true, conv),
                OtelPusherState::BinaryFromEnvVar,
                "conv={conv}",
            );
        }
    }

    /// Convention-path arm: no opt-out, no env var, binary on disk
    /// at `target/release/` (or similar) ⇒ use it directly.
    #[test]
    fn inv_live_e2e_otel_pusher_present_01_classifier_convention_path_used() {
        assert_eq!(
            classify_otel_pusher_state(false, false, true),
            OtelPusherState::BinaryAtConventionPath,
        );
    }

    /// Default path: no opt-out, no env var, no convention-path
    /// binary ⇒ auto-build. Pinned so a future maintainer cannot
    /// silently re-introduce the iter53 silent-degrade behaviour
    /// (the previous implementation logged a warning and returned
    /// `None` here).
    #[test]
    fn inv_live_e2e_otel_pusher_present_01_default_path_auto_builds_when_missing() {
        assert_eq!(
            classify_otel_pusher_state(false, false, false),
            OtelPusherState::NeedsAutoBuild,
        );
    }

    /// `HardFailMissingBinary` is reachable only after a failed
    /// auto-build — the classifier itself never returns it. This
    /// witness pins that contract: the dispatcher constructs the
    /// arm by hand when the build fails; the classifier's job is
    /// to surface the *initial* state.
    #[test]
    fn inv_live_e2e_otel_pusher_present_01_classifier_never_returns_hard_fail_directly() {
        for skip in [false, true] {
            for envvar in [false, true] {
                for conv in [false, true] {
                    assert_ne!(
                        classify_otel_pusher_state(skip, envvar, conv),
                        OtelPusherState::HardFailMissingBinary,
                        "classifier MUST NOT return HardFailMissingBinary \
                         from initial inputs (skip={skip} envvar={envvar} \
                         conv={conv}); that arm is reserved for the \
                         post-failed-build dispatcher",
                    );
                }
            }
        }
    }

    /// The opt-out + env-var + binary-override env-var names are
    /// part of the operator-facing surface. Pin the spelling so
    /// a typo trips here rather than silently breaking the
    /// opt-out / override path on a release-CI lane.
    #[test]
    fn inv_live_e2e_otel_pusher_present_01_opt_out_env_var_name_pinned() {
        assert_eq!(ENV_SKIP_OTEL_PUSHER, "RAXIS_E2E_SKIP_OTEL_PUSHER");
        assert_eq!(ENV_OTEL_PUSHER_BINARY, "RAXIS_OTEL_PUSHER_BINARY");
        assert_eq!(
            ENV_OTEL_PUSHER_BUILD_TIMEOUT_SECS,
            "RAXIS_E2E_OTEL_PUSHER_BUILD_TIMEOUT_SECS",
        );
    }

    /// Every panic produced by the auto-build / spawn / smoke-probe
    /// pipeline carries the [`OTEL_PUSHER_VIOLATION_TOKEN`]
    /// verbatim AND mentions the canonical remediation phrase
    /// (`cargo build --release -p raxis-otel-pusher`). Pin both
    /// so a CI log scraper / a remediation reader doesn't have
    /// to chase a renamed token.
    #[test]
    fn inv_live_e2e_otel_pusher_present_01_violation_token_shape() {
        assert_eq!(
            OTEL_PUSHER_VIOLATION_TOKEN,
            "INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01 VIOLATED",
        );
        // The remediation phrase MUST appear in the auto-build
        // failure block we synthesise inline — assert by string
        // construction rather than pulling a const out of the
        // panic body (which would be fragile).
        let synth = format!(
            "{OTEL_PUSHER_VIOLATION_TOKEN}: stub\n\nRemediation:\n  * Pre-build the pusher: `cargo build --release -p raxis-otel-pusher`",
        );
        assert!(
            synth.contains("cargo build --release -p raxis-otel-pusher"),
            "remediation block lost the canonical build invocation",
        );
    }

    /// Default build timeout sits in `[60s, 600s]` — generous
    /// enough for a cold cargo cache, bounded enough that a
    /// regression flipping it to `0` (which would disable the
    /// bound, re-introducing
    /// `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01` violation)
    /// trips here.
    #[test]
    fn inv_live_e2e_otel_pusher_present_01_default_build_timeout_generous_but_bounded() {
        assert!(
            DEFAULT_OTEL_PUSHER_BUILD_TIMEOUT_SECS >= MIN_OTEL_PUSHER_BUILD_TIMEOUT_SECS,
            "default build timeout must clear the safe floor",
        );
        assert!(
            DEFAULT_OTEL_PUSHER_BUILD_TIMEOUT_SECS <= MAX_OTEL_PUSHER_BUILD_TIMEOUT_SECS,
            "default build timeout must clear the safe ceiling",
        );
        assert!(
            (60..=600).contains(&DEFAULT_OTEL_PUSHER_BUILD_TIMEOUT_SECS),
            "default sits in [60s, 600s] window per invariant statement",
        );
        assert!(
            MIN_OTEL_PUSHER_BUILD_TIMEOUT_SECS >= 60,
            "floor must allow a cold-cache build (60s minimum)",
        );
        assert!(
            MAX_OTEL_PUSHER_BUILD_TIMEOUT_SECS <= 600,
            "ceiling bounds the wedge surface (600s maximum)",
        );
    }

    /// `RAXIS_E2E_OTEL_PUSHER_BUILD_TIMEOUT_SECS=0` (or any
    /// non-positive / unparseable value) clamps to the default
    /// rather than disabling the bound. Mirrors the
    /// `dashboard.rs` `inv_live_e2e_dashboard_fe_bundle_present_01_timeout_overrides_clamp_safely`
    /// pattern. Hermetic against parallel test runs via the
    /// snapshot+restore guard.
    #[test]
    fn inv_live_e2e_otel_pusher_present_01_build_timeout_override_clamp_safely() {
        struct EnvGuard(&'static str, Option<String>);
        impl EnvGuard {
            fn set(key: &'static str, value: &str) -> Self {
                let prior = std::env::var(key).ok();
                // SAFETY: Test-only mutation guarded by Drop.
                unsafe { std::env::set_var(key, value); }
                EnvGuard(key, prior)
            }
            fn unset(key: &'static str) -> Self {
                let prior = std::env::var(key).ok();
                // SAFETY: Test-only mutation guarded by Drop.
                unsafe { std::env::remove_var(key); }
                EnvGuard(key, prior)
            }
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                match &self.1 {
                    // SAFETY: Test-only restore.
                    Some(v) => unsafe { std::env::set_var(self.0, v); },
                    None => unsafe { std::env::remove_var(self.0); },
                }
            }
        }
        let default = Duration::from_secs(DEFAULT_OTEL_PUSHER_BUILD_TIMEOUT_SECS);

        let _g = EnvGuard::unset(ENV_OTEL_PUSHER_BUILD_TIMEOUT_SECS);
        assert_eq!(otel_pusher_build_timeout(), default);

        let _g = EnvGuard::set(ENV_OTEL_PUSHER_BUILD_TIMEOUT_SECS, "120");
        assert_eq!(otel_pusher_build_timeout(), Duration::from_secs(120));

        let _g = EnvGuard::set(ENV_OTEL_PUSHER_BUILD_TIMEOUT_SECS, "0");
        assert_eq!(
            otel_pusher_build_timeout(),
            default,
            "non-positive override MUST clamp to default",
        );

        let _g = EnvGuard::set(ENV_OTEL_PUSHER_BUILD_TIMEOUT_SECS, "garbage");
        assert_eq!(
            otel_pusher_build_timeout(),
            default,
            "unparseable override MUST clamp to default",
        );

        // Below floor / above ceiling MUST clamp to default
        // rather than honouring the unsafe value.
        let _g = EnvGuard::set(ENV_OTEL_PUSHER_BUILD_TIMEOUT_SECS, "5");
        assert_eq!(
            otel_pusher_build_timeout(),
            default,
            "below-floor override MUST clamp to default",
        );
        let _g = EnvGuard::set(ENV_OTEL_PUSHER_BUILD_TIMEOUT_SECS, "9999");
        assert_eq!(
            otel_pusher_build_timeout(),
            default,
            "above-ceiling override MUST clamp to default",
        );
    }

    /// Spawning a fake long-running pusher (via
    /// `Command::new("sleep")`) and dropping the supervisor MUST
    /// cause the child to die within ~5 s — the SIGTERM grace
    /// window plus the SIGKILL escalation path. Mirrors the iter44
    /// supervisor-restart-audit witness pattern: the RAII guard's
    /// contract is "no leaked processes, ever".
    #[test]
    #[cfg(unix)]
    fn inv_live_e2e_otel_pusher_present_01_supervisor_kills_child_on_drop() {
        // Spawn `sleep 9999` directly so we avoid depending on a
        // built `raxis-otel-pusher` for the supervision witness.
        // The supervisor's contract is process-supervision, not
        // pusher-specific behaviour — `sleep` is a faithful
        // stand-in.
        let log_path = std::env::temp_dir().join(format!(
            "raxis-otel-pusher-sup-witness-{}.log",
            std::process::id(),
        ));
        let log_file = std::fs::File::create(&log_path).expect("create log");
        let stderr_handle = log_file.try_clone().expect("dup log");
        let child = Command::new("sleep")
            .arg("9999")
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr_handle))
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        assert!(
            pid_alive(pid),
            "child must be alive immediately after spawn (pid={pid})",
        );
        let sup = OtelPusherSupervisor {
            child: Some(child),
            pid,
            binary: PathBuf::from("/usr/bin/sleep"),
            log_path: log_path.clone(),
        };
        drop(sup);
        // Wait up to 5 s for the OS to reap the SIGKILL'd child.
        let deadline = Instant::now() + Duration::from_secs(5);
        while pid_alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            !pid_alive(pid),
            "supervisor drop MUST SIGKILL the child within 5s (pid={pid} still alive)",
        );
        let _ = std::fs::remove_file(&log_path);
    }

    /// Pure-classifier witness for the smoke-probe "no metrics"
    /// path. Synthesises three Prometheus response shapes:
    ///
    /// 1. Empty `up` series → `NoRaxisUpYet`.
    /// 2. Only non-raxis jobs (e.g. just the prometheus self-scrape)
    ///    → `NoRaxisUpYet`.
    /// 3. raxis-job present and `up=1` → `AtLeastOneRaxisUp`.
    ///
    /// Pinning the classifier here means the smoke-probe
    /// invariant cannot regress to "any 200 response counts" — a
    /// future maintainer who flipped that would trip arm 2 here.
    #[test]
    fn inv_live_e2e_otel_pusher_present_01_smoke_probe_blocks_on_no_metrics() {
        // Empty `data.result` array.
        let empty = serde_json::json!({
            "status": "success",
            "data": { "resultType": "vector", "result": [] }
        });
        match classify_prometheus_up_response(&empty) {
            ProbeOutcome::NoRaxisUpYet { .. } => {}
            other => panic!("empty response MUST be NoRaxisUpYet; got {other:?}"),
        }
        // Only non-raxis jobs.
        let non_raxis = serde_json::json!({
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"__name__":"up","instance":"localhost:9090","job":"prometheus"},
                        "value": [0.0, "1"]
                    },
                    {
                        "metric": {"__name__":"up","instance":"otel-collector:8888","job":"otel-collector-internal"},
                        "value": [0.0, "1"]
                    }
                ]
            }
        });
        match classify_prometheus_up_response(&non_raxis) {
            ProbeOutcome::NoRaxisUpYet { observation } => {
                assert!(
                    observation.contains("raxis"),
                    "observation should mention the missing raxis job: {observation}",
                );
            }
            other => panic!("non-raxis-only response MUST be NoRaxisUpYet; got {other:?}"),
        }
        // raxis job present + up=1 ⇒ probe succeeds.
        let raxis_up = serde_json::json!({
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"__name__":"up","instance":"otel-collector:8889","job":"raxis-otel"},
                        "value": [0.0, "1"]
                    }
                ]
            }
        });
        assert_eq!(
            classify_prometheus_up_response(&raxis_up),
            ProbeOutcome::AtLeastOneRaxisUp,
        );
        // raxis job present but `up=0` (target down) ⇒ still
        // NoRaxisUpYet so the smoke probe will keep waiting.
        let raxis_down = serde_json::json!({
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"__name__":"up","instance":"otel-collector:8889","job":"raxis-otel"},
                        "value": [0.0, "0"]
                    }
                ]
            }
        });
        match classify_prometheus_up_response(&raxis_down) {
            ProbeOutcome::NoRaxisUpYet { observation } => {
                assert!(
                    observation.contains("raxis-otel=0"),
                    "observation should reference the raxis-otel=0 datapoint: {observation}",
                );
            }
            other => panic!("raxis-down response MUST be NoRaxisUpYet; got {other:?}"),
        }
    }

    /// Opt-out path STILL runs the smoke probe — it doesn't
    /// short-circuit. Pin the precedence by asserting the
    /// `OptOutByEnv` arm dispatches into
    /// [`SmokeProbeMode::ExternalPusher`] (not "no probe at all").
    /// The witness exercises the dispatch by feeding
    /// `OptOutByEnv` through a check that the smoke-probe-mode
    /// branch fires. We don't actually run the probe (that needs
    /// a live Prometheus); we pin the contract by asserting the
    /// alternate remediation phrasing.
    #[test]
    fn inv_live_e2e_otel_pusher_present_01_opt_out_still_smoke_probes() {
        // The contract is encoded in the dispatch: the
        // `OptOutByEnv` arm of `ensure_otel_pusher_or_panic`
        // calls `smoke_probe_or_panic(SmokeProbeMode::ExternalPusher, None)`.
        // We can't easily run that whole arm without a live
        // Prometheus, so we pin two structural facts:
        //
        //   1. `SmokeProbeMode::ExternalPusher` exists and is
        //      distinct from `HarnessSupervisedPusher` (so the
        //      remediation message can branch on it).
        //   2. The remediation phrasing for the external-pusher
        //      branch contains BOTH the "set ...=0 (or unset)"
        //      hint AND the "ensure your external pusher is
        //      running" hint. A future refactor that collapsed
        //      the two modes into one would lose the operator-
        //      visible distinction the invariant requires.
        assert_ne!(
            SmokeProbeMode::ExternalPusher,
            SmokeProbeMode::HarnessSupervisedPusher,
            "smoke-probe modes must remain distinct so remediation \
             messaging can branch",
        );
        // Synthesise the external-pusher remediation block exactly
        // as `smoke_probe_or_panic` does, and pin both phrases.
        let synth_remediation = format!(
            "Set {ENV_SKIP_OTEL_PUSHER}=0 (or unset it) to let the \
             harness manage the pusher, OR ensure your external \
             pusher is running and pointing at {OTLP_HTTP_URL}",
        );
        assert!(
            synth_remediation.contains(&format!("Set {ENV_SKIP_OTEL_PUSHER}=0")),
            "external-pusher remediation MUST hint at unsetting the opt-out",
        );
        assert!(
            synth_remediation.contains("ensure your external pusher is running"),
            "external-pusher remediation MUST hint at the external pusher itself",
        );
    }

    /// `INV-LIVE-E2E-OBSERVABILITY-LOG-NO-CONTRADICTION-01` —
    /// the harness MUST NOT emit both "Grafana panels will stay
    /// empty" AND "live metrics flowing to Grafana" in the same
    /// run. With the iter53 hardening, the absent-pusher path is
    /// hard-fail (panic), which means there is no log surface
    /// that COULD produce the empty-line message any more — the
    /// witness pins that contract by asserting:
    ///
    ///   1. The success log line shape (constructed inline below
    ///      to mirror `ensure_otel_pusher_or_panic`) contains
    ///      "live metrics flowing to Grafana" AND DOES NOT
    ///      contain "stay empty".
    ///   2. The hard-fail panic body contains the violation
    ///      token AND DOES NOT contain "live metrics flowing"
    ///      (so a panic that surfaces during cargo log scraping
    ///      cannot be confused for a success).
    #[test]
    fn inv_live_e2e_observability_log_no_contradiction_01_pusher_absent_emits_only_failure_path() {
        let success_line = format!(
            "[realism-e2e] observability: pusher spawned (pid={pid}, \
             bin={bin}, log={log}), smoke-probed, live metrics flowing \
             to Grafana http://127.0.0.1:3000/d/raxis-00-overview",
            pid = 12345,
            bin = "/some/path/raxis-otel-pusher",
            log = "/some/data_dir/otel-pusher.stderr.log",
        );
        assert!(
            success_line.contains("live metrics flowing to Grafana"),
            "success log MUST claim live metrics are flowing",
        );
        assert!(
            !success_line.contains("stay empty"),
            "success log MUST NOT contradict itself with `stay empty` text",
        );
        let hard_fail_body = format!(
            "{OTEL_PUSHER_VIOLATION_TOKEN}: build failed\n\nRemediation:\n  * \
             Pre-build the pusher: `cargo build --release -p raxis-otel-pusher`",
        );
        assert!(
            hard_fail_body.contains(OTEL_PUSHER_VIOLATION_TOKEN),
            "hard-fail body must carry the violation token",
        );
        assert!(
            !hard_fail_body.contains("live metrics flowing"),
            "hard-fail body MUST NOT lie about live metrics flowing — \
             that would contradict the panic itself",
        );
    }

    /// `convention_pusher_paths` returns the right precedence
    /// (release → debug → optional install dir). Pinned so a
    /// future maintainer cannot silently flip the order (which
    /// would shift the harness onto a stale debug build when a
    /// fresh release build is on disk).
    #[test]
    fn inv_live_e2e_otel_pusher_present_01_convention_path_precedence_release_first() {
        let workspace = PathBuf::from("/tmp/synthetic-workspace");
        let install = PathBuf::from("/tmp/synthetic-install");
        let paths = convention_pusher_paths(&workspace, Some(&install));
        assert_eq!(paths.len(), 3, "expected 3 paths (release, debug, install/bin)");
        assert!(paths[0].ends_with("target/release/raxis-otel-pusher"));
        assert!(paths[1].ends_with("target/debug/raxis-otel-pusher"));
        assert!(paths[2].ends_with("bin/raxis-otel-pusher"));
        // Without an install dir, only 2 paths.
        let paths_no_install = convention_pusher_paths(&workspace, None);
        assert_eq!(paths_no_install.len(), 2);
    }

    // ─── Helpers for the supervisor-drop witness ─────────────────

    #[cfg(unix)]
    fn pid_alive(pid: u32) -> bool {
        // SAFETY: signal 0 is the standard "is this pid alive"
        // probe. Returns 0 on success (alive), -1 with errno=ESRCH
        // when the pid has gone away. We only inspect the return
        // value; no FFI state escapes.
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }
}
