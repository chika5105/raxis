//! Docker-compose backing-stack auto-bring-up for the live-e2e
//! harness.
//!
//! ## What this module guarantees
//!
//! Before any `seed_*` helper runs, the harness MUST observe the
//! `raxis-live-e2e-test` docker-compose project up and healthy.
//! The previous default required the operator to remember to run
//! `docker compose -f live-e2e/docker-compose.extended.e2e.yml up
//! -d --wait` themselves; forgetting it caused the iter-17
//! `realistic_session_lifecycle` hang (the `seed_postgres` child
//! blocked indefinitely on a postgres container that wasn't up).
//!
//! With this module the harness:
//!
//! 1. Probes `docker compose -p raxis-live-e2e-test ps --format
//!    json` (bounded by `DOCKER_PROBE_TIMEOUT`, 30 s).
//! 2. If every service is `running` AND `healthy` (or running
//!    with no healthcheck), returns `Ok(())`.
//! 3. Otherwise auto-brings-up the stack via `docker compose
//!    -p raxis-live-e2e-test -f <extended-compose-file> up -d
//!    --wait` (bounded by `DOCKER_BRINGUP_TIMEOUT`, 240 s).
//! 4. Re-probes; reports `BringupFailed` if some service is
//!    still unhealthy after `--wait`.
//!
//! Operator opt-out: `RAXIS_LIVE_E2E_NO_AUTO_DOCKER=1` switches
//! the auto-bring-up off. In that mode an unhealthy stack
//! surfaces a fail-fast `AutoBringupDisabled` error containing
//! the literal token `RAXIS_LIVE_E2E_DOCKER_STACK_DOWN` so a CI
//! log scraper can pin the failure mode without parsing the
//! full message.
//!
//! ## Spec
//!
//! `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`
//! ([`raxis/specs/invariants.md`]) — every external-process spawn
//! in the live-e2e harness MUST be wrapped in a bounded timeout.
//! Every `docker compose ...` invocation in this module routes
//! through `harness_timeout::run_command_output_timeout`.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use super::harness_timeout::{
    run_command_output_timeout, BoundedWaitError, DOCKER_BRINGUP_TIMEOUT, DOCKER_PROBE_TIMEOUT,
};
use crate::common::keep_alive::keep_running_after_exit_with_workdir;

/// docker-compose project namespace shared by both compose files
/// (`docker-compose.e2e.yml` and `docker-compose.extended.e2e.yml`)
/// — see the `name:` field at the top of each YAML.
pub const COMPOSE_PROJECT: &str = "raxis-live-e2e-test";

/// Operator opt-out env var. When set (any non-empty value),
/// `ensure_extended_stack_up` skips the auto-bring-up branch and
/// surfaces `AutoBringupDisabled` if the stack is not already up.
pub const ENV_NO_AUTO_DOCKER: &str = "RAXIS_LIVE_E2E_NO_AUTO_DOCKER";

/// Magic token included in the fail-fast message for grep-friendly
/// CI scrape pipelines.
pub const STACK_DOWN_TOKEN: &str = "RAXIS_LIVE_E2E_DOCKER_STACK_DOWN";

/// Operator opt-out env var for the image pre-pull stage. When set
/// (any non-empty value), [`ensure_compose_images_cached_or_pull`]
/// short-circuits before any `docker` shell-out — for operators who
/// pre-pull and manage compose externally.
pub const ENV_NO_PREPULL: &str = "RAXIS_LIVE_E2E_NO_PREPULL";

/// Override env var for the pre-pull bounded timeout (seconds).
/// When unset / empty / non-positive / unparseable the default
/// [`DEFAULT_PULL_TIMEOUT`] is used. See
/// [`pull_timeout_from_env`] for the parse contract.
pub const ENV_PULL_TIMEOUT_SECS: &str = "RAXIS_LIVE_E2E_PULL_TIMEOUT_SECS";

/// Default bounded timeout for `docker compose pull` on a cold
/// image cache. 20 minutes covers a typical operator-laptop pull
/// of the extended stack (postgres / mongo / redis / smtp /
/// mysql / mssql / Grafana / Prometheus / OTel collector) over a
/// residential connection, with generous slack for layer
/// extraction. Override via [`ENV_PULL_TIMEOUT_SECS`].
pub const DEFAULT_PULL_TIMEOUT: Duration = Duration::from_secs(1200);

/// Failure surface for the docker-stack preflight.
#[derive(Debug)]
pub enum DockerStackError {
    /// Operator opted out of harness auto-bring-up via
    /// `RAXIS_LIVE_E2E_NO_AUTO_DOCKER=1` AND the stack is not up.
    /// The `Display` impl includes [`STACK_DOWN_TOKEN`] verbatim
    /// so a CI log scraper can match the failure mode.
    AutoBringupDisabled {
        project: String,
        compose_file: PathBuf,
        details: String,
    },

    /// `docker compose ps` exited non-zero or otherwise failed.
    ProbeFailed { reason: String },

    /// `docker compose up -d --wait` exited non-zero or some
    /// service was still unhealthy after the bring-up.
    BringupFailed { reason: String },

    /// `docker` binary missing on the host or otherwise un-spawnable.
    DockerMissing { reason: String },

    /// Pre-pull stage failed: either `docker compose ... config
    /// --images` could not resolve the image list, or
    /// `docker compose ... pull` exited non-zero / timed out.
    /// The `Display` impl includes a copy-pastable manual
    /// pre-pull command and points at the
    /// [`ENV_PULL_TIMEOUT_SECS`] knob.
    PullFailed {
        project: String,
        compose_file: PathBuf,
        reason: String,
    },
}

impl std::fmt::Display for DockerStackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AutoBringupDisabled {
                project,
                compose_file,
                details,
            } => write!(
                f,
                "{token}: docker-compose project `{project}` is not up + healthy \
                 and `{env}=1` opted out of harness auto-bring-up. \
                 Bring up the backing services first via `docker compose \
                 -p {project} -f {} up -d --wait` or unset {env}. (Probe \
                 details: {details})",
                compose_file.display(),
                token = STACK_DOWN_TOKEN,
                env = ENV_NO_AUTO_DOCKER,
            ),
            Self::ProbeFailed { reason } => {
                write!(f, "[live-e2e docker-stack] probe failed: {reason}")
            }
            Self::BringupFailed { reason } => {
                write!(f, "[live-e2e docker-stack] auto-bring-up failed: {reason}")
            }
            Self::DockerMissing { reason } => write!(
                f,
                "[live-e2e docker-stack] `docker` binary not usable: {reason}. \
                 Install Docker Desktop / docker-cli + docker-compose-plugin and re-run.",
            ),
            Self::PullFailed {
                project,
                compose_file,
                reason,
            } => {
                writeln!(f, "[live-e2e docker-stack] image pull failed: {reason}")?;
                writeln!(f, "Remediation:")?;
                writeln!(
                    f,
                    "  1. Confirm Docker Desktop has network access \
                     (curl https://registry-1.docker.io/v2/ -I).",
                )?;
                writeln!(f, "  2. Manually pre-pull from a network-stable terminal:",)?;
                writeln!(f, "       docker compose -p {project} \\")?;
                writeln!(f, "         -f {} pull", compose_file.display())?;
                write!(
                    f,
                    "  3. If pull succeeds outside the harness, set \
                     {env}=<seconds> to a larger value (default {default}s).",
                    env = ENV_PULL_TIMEOUT_SECS,
                    default = DEFAULT_PULL_TIMEOUT.as_secs(),
                )
            }
        }
    }
}

impl std::error::Error for DockerStackError {}

/// Resolve the absolute path to the extended docker-compose file
/// from the kernel-test crate's `CARGO_MANIFEST_DIR`. Stable
/// regardless of the test's runtime cwd.
pub fn extended_compose_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join("live-e2e/docker-compose.extended.e2e.yml"))
        .unwrap_or_else(|| PathBuf::from("raxis/live-e2e/docker-compose.extended.e2e.yml"))
}

/// Convenience entry point for the realistic-scenario harness.
/// Panics with a clean operator-readable message on any failure;
/// the underlying [`ensure_stack_up`] returns a `Result` for
/// regression-test consumption.
pub fn ensure_extended_stack_up_or_panic() {
    let compose_file = extended_compose_file();
    // INV-LIVE-E2E-HARNESS-IMAGE-PREPULL-01: verify (or pull)
    // every compose-referenced image BEFORE the 240 s up-wait
    // bound. A cold image cache routinely takes 5-15 minutes to
    // fill; without this pre-step the `up -d --wait` bounded
    // wait SIGKILLs the compose process mid-pull and surfaces a
    // misleading "stack startup failure" panic. Opt out via
    // `RAXIS_LIVE_E2E_NO_PREPULL=1` if you manage the stack
    // externally.
    if let Err(e) = ensure_compose_images_cached_or_pull(COMPOSE_PROJECT, &compose_file) {
        panic!("{e}");
    }
    if let Err(e) = ensure_stack_up(COMPOSE_PROJECT, &compose_file) {
        panic!("{e}");
    }
}

/// Ensure `(project, compose_file)` is up + healthy.
///
/// * Probes via `docker compose -p <project> ps --format json`.
/// * Brings up via `docker compose -p <project> -f <compose_file>
///   up -d --wait` when not opted out.
///
/// Parametrised over project + compose-file path so a regression
/// test can drive the same logic against a synthetic non-existent
/// project name.
pub fn ensure_stack_up(
    project: &str,
    compose_file: &std::path::Path,
) -> Result<(), DockerStackError> {
    let probe = probe_stack_health(project)?;
    if probe.healthy {
        return Ok(());
    }
    let opt_out = std::env::var(ENV_NO_AUTO_DOCKER)
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    if opt_out {
        return Err(DockerStackError::AutoBringupDisabled {
            project: project.to_owned(),
            compose_file: compose_file.to_path_buf(),
            details: probe.summary,
        });
    }
    bring_stack_up(project, compose_file)?;
    let recheck = probe_stack_health(project)?;
    if !recheck.healthy {
        return Err(DockerStackError::BringupFailed {
            reason: format!(
                "docker compose -p {project} reported unhealthy services even \
                 after `up -d --wait`: {summary}. Inspect: \
                 docker compose -p {project} ps",
                summary = recheck.summary,
            ),
        });
    }
    Ok(())
}

/// Result of a single `docker compose ps --format json` probe.
#[derive(Debug, Clone)]
pub struct StackProbe {
    /// True iff every observed service has `State == "running"`
    /// AND `Health` is either `"healthy"` or empty (no healthcheck
    /// declared).
    pub healthy: bool,
    /// Human-readable summary suitable for embedding in a panic
    /// message ("3 running/healthy, 1 unhealthy", or
    /// "no services in project").
    pub summary: String,
}

fn probe_stack_health(project: &str) -> Result<StackProbe, DockerStackError> {
    let mut cmd = Command::new("docker");
    cmd.arg("compose")
        .arg("-p")
        .arg(project)
        .arg("ps")
        .arg("--format")
        .arg("json");
    let out = match run_command_output_timeout(&mut cmd, DOCKER_PROBE_TIMEOUT, "docker-compose-ps")
    {
        Ok(o) => o,
        Err(BoundedWaitError::SpawnFailed { reason, .. }) => {
            return Err(DockerStackError::DockerMissing { reason });
        }
        Err(e) => {
            return Err(DockerStackError::ProbeFailed {
                reason: format!("docker compose ps: {e}"),
            });
        }
    };
    if !out.status.success() {
        return Err(DockerStackError::ProbeFailed {
            reason: format!(
                "docker compose ps exit {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim_end(),
            ),
        });
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(parse_compose_ps(&stdout))
}

/// Parse `docker compose ps --format json` output. v2 emits one
/// JSON object per line (NDJSON); v1 emitted a single JSON array.
/// We accept both to insulate the harness from the operator's
/// docker version drift.
pub fn parse_compose_ps(stdout: &str) -> StackProbe {
    let mut services: Vec<serde_json::Value> = Vec::new();
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return StackProbe {
            healthy: false,
            summary: "no services in project".to_owned(),
        };
    }
    if trimmed.starts_with('[') {
        if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str(trimmed) {
            services.extend(arr);
        }
    } else {
        for line in stdout.lines() {
            let l = line.trim();
            if l.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(l) {
                services.push(v);
            }
        }
    }
    if services.is_empty() {
        return StackProbe {
            healthy: false,
            summary: "no services in project (compose ps returned empty)".to_owned(),
        };
    }
    let mut total = 0usize;
    let mut ok = 0usize;
    let mut bad: Vec<String> = Vec::new();
    for svc in &services {
        total += 1;
        let name = svc
            .get("Name")
            .or_else(|| svc.get("Service"))
            .and_then(|v| v.as_str())
            .unwrap_or("<unnamed>");
        let state = svc.get("State").and_then(|v| v.as_str()).unwrap_or("");
        let health = svc.get("Health").and_then(|v| v.as_str()).unwrap_or("");
        let is_running = state == "running";
        // Empty `Health` string == no healthcheck declared; we
        // treat "running with no healthcheck" as OK so we don't
        // wedge on services like `mailserver` that intentionally
        // omit a healthcheck variant.
        let is_health_ok = health.is_empty() || health == "healthy";
        if is_running && is_health_ok {
            ok += 1;
        } else {
            bad.push(format!("{name} (State={state:?}, Health={health:?})",));
        }
    }
    let healthy = bad.is_empty() && ok == total && total > 0;
    let summary = if healthy {
        format!("{ok}/{total} services running + healthy")
    } else {
        format!("{ok}/{total} healthy; not-ready=[{}]", bad.join(", "),)
    };
    StackProbe { healthy, summary }
}

// ─── Image pre-pull stage (INV-LIVE-E2E-HARNESS-IMAGE-PREPULL-01) ─────
//
// Wraps `docker compose ... pull` under a generous (20 min)
// bounded wait that runs BEFORE the existing 240 s `up -d --wait`
// stage. The split matters: pulling a cold image cache routinely
// takes 5-15 minutes on a residential connection, but once the
// images are local `up --wait` reliably completes in 30-90 s.
// Wrapping both phases under a single 240 s bound caused the
// iter63 launch-attempt panic: `docker system prune --volumes
// -f` had cleared the cache, the merged `up --wait` ran past
// the 240 s deadline mid-pull, the bounded-wait machinery
// SIGKILLed the compose process, and the operator saw a
// `[bounded-wait:docker-compose-up] child did not exit within
// 240s; SIGKILLed` panic that misleadingly looked like a stack
// startup failure rather than a missing image.

/// Decision surface for the pre-pull dispatcher. Factored out as
/// a value type so witness tests can pin each branch without
/// shelling out to the real `docker` binary. See
/// [`decide_prepull_action_with`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepullDecision {
    /// `RAXIS_LIVE_E2E_NO_PREPULL=1` is in effect; the
    /// dispatcher MUST NOT shell out to docker at all.
    OptedOut,
    /// Every compose-referenced image is locally cached; the
    /// dispatcher MUST skip the pull and return `Ok(())`. The
    /// `count` is the total number of images verified for the
    /// operator banner.
    AllCached { count: usize },
    /// At least one compose-referenced image is missing locally.
    /// `all` is every image the compose file declares (for the
    /// banner / forensic context); `missing` is the subset
    /// `docker image inspect` reported absent. The dispatcher
    /// MUST shell out to `docker compose pull` under the bounded
    /// wait described by [`pull_timeout_from_env`].
    PullRequired {
        all: Vec<String>,
        missing: Vec<String>,
    },
}

/// Pure dispatcher: given the env-var opt-out signal and two
/// closures that resolve the compose-file image list + the local
/// presence of a single image, return the [`PrepullDecision`]
/// the runtime path should execute. The opt-out branch is
/// short-circuit: when `env_no_prepull=true` NEITHER closure is
/// invoked (witness arm c of `INV-LIVE-E2E-HARNESS-IMAGE-PREPULL-01`).
pub fn decide_prepull_action_with(
    env_no_prepull: bool,
    images_provider: impl FnOnce() -> Result<Vec<String>, DockerStackError>,
    presence_checker: impl Fn(&str) -> bool,
) -> Result<PrepullDecision, DockerStackError> {
    if env_no_prepull {
        return Ok(PrepullDecision::OptedOut);
    }
    let images = images_provider()?;
    if images.is_empty() {
        // No images means the compose file declares no services
        // that reference an image tag (or `config --images`
        // returned an empty list). Treat as "nothing to pull"
        // and let the downstream `up --wait` stage decide what
        // to do.
        return Ok(PrepullDecision::AllCached { count: 0 });
    }
    let missing: Vec<String> = images
        .iter()
        .filter(|img| !presence_checker(img))
        .cloned()
        .collect();
    if missing.is_empty() {
        Ok(PrepullDecision::AllCached {
            count: images.len(),
        })
    } else {
        Ok(PrepullDecision::PullRequired {
            all: images,
            missing,
        })
    }
}

/// Parse the `RAXIS_LIVE_E2E_PULL_TIMEOUT_SECS` override into a
/// [`Duration`]. Unset / empty / non-positive / unparseable
/// inputs clamp to [`DEFAULT_PULL_TIMEOUT`] rather than disabling
/// the bound — every external-process spawn in the live-e2e
/// harness must be bounded
/// (`INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`).
pub fn pull_timeout_from_env(raw: Option<&str>) -> Duration {
    match raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
    {
        Some(n) => Duration::from_secs(n),
        None => DEFAULT_PULL_TIMEOUT,
    }
}

/// Verify that every image referenced by `compose_file` is
/// locally cached; if any image is missing, pull all of them
/// under a configurable bounded wait BEFORE the existing
/// `docker compose ... up -d --wait` stage runs.
///
/// **Failure mode this prevents.** The realistic-scenario test
/// invokes `ensure_extended_stack_up_or_panic`, which wraps
/// `docker compose ... up -d --wait` under a 240 s
/// `bounded-wait`. On a cold image cache (e.g. immediately
/// after `docker system prune --volumes -f`) the pull step
/// alone exceeds 240 s on a typical machine; the bounded wait
/// then SIGKILLs the compose process and the test panics with
/// `[bounded-wait:docker-compose-up] child did not exit within
/// 240s; SIGKILLed` — a misleading "stack startup failure"
/// message that hides the real root cause (missing images).
/// This pre-step verifies presence cheaply via `docker image
/// inspect` and falls back to a 20-minute (configurable via
/// [`ENV_PULL_TIMEOUT_SECS`]) `docker compose pull` only when
/// genuinely needed, so the downstream 240 s `up --wait` bound
/// stays tight against the actual stack-startup phase.
///
/// **Opt-out.** `RAXIS_LIVE_E2E_NO_PREPULL=1` short-circuits
/// the entire stage (for operators who pre-pull and manage
/// compose externally).
pub fn ensure_compose_images_cached_or_pull(
    project: &str,
    compose_file: &std::path::Path,
) -> Result<(), DockerStackError> {
    let env_no_prepull = std::env::var(ENV_NO_PREPULL)
        .map(|v| !v.is_empty())
        .unwrap_or(false);

    let decision = decide_prepull_action_with(
        env_no_prepull,
        || compose_image_list(project, compose_file),
        image_present_locally,
    )?;

    match decision {
        PrepullDecision::OptedOut => {
            eprintln!(
                "[live-e2e docker-stack] {env}=1 set; skipping image pre-pull                  (operator-managed)",
                env = ENV_NO_PREPULL,
            );
            Ok(())
        }
        PrepullDecision::AllCached { count } => {
            eprintln!(
                "[live-e2e docker-stack] images cached locally: {count}                  images verified, skipping pull",
            );
            Ok(())
        }
        PrepullDecision::PullRequired { all: _, missing } => {
            let n = missing.len();
            eprintln!(
                "[live-e2e docker-stack] cold image cache; pulling {n}                  missing images (this can take 5-15 minutes on a fresh                  machine)...",
            );
            for m in &missing {
                eprintln!("    - {m}");
            }
            pull_compose_images(project, compose_file)
        }
    }
}

/// Shell-out to `docker compose -p <project> -f <compose_file>
/// config --images` and return one image per line. Bounded by
/// [`DOCKER_PROBE_TIMEOUT`] — `config --images` is a pure
/// YAML-resolution pass with no network or container IO, so 30 s
/// is ample. Non-zero exit / missing-binary / timeout all surface
/// as [`DockerStackError::PullFailed`] (we conflate config-failure
/// with pull-failure in the operator-facing remediation message
/// because the remediation step — re-run the same compose
/// invocation manually — is identical).
fn compose_image_list(
    project: &str,
    compose_file: &std::path::Path,
) -> Result<Vec<String>, DockerStackError> {
    let mut cmd = Command::new("docker");
    cmd.arg("compose")
        .arg("-p")
        .arg(project)
        .arg("-f")
        .arg(compose_file)
        .arg("config")
        .arg("--images");
    let out = match run_command_output_timeout(
        &mut cmd,
        DOCKER_PROBE_TIMEOUT,
        "docker-compose-config-images",
    ) {
        Ok(o) => o,
        Err(BoundedWaitError::SpawnFailed { reason, .. }) => {
            return Err(DockerStackError::DockerMissing { reason });
        }
        Err(e) => {
            return Err(DockerStackError::PullFailed {
                project: project.to_owned(),
                compose_file: compose_file.to_path_buf(),
                reason: format!("docker compose config --images: {e}"),
            });
        }
    };
    if !out.status.success() {
        return Err(DockerStackError::PullFailed {
            project: project.to_owned(),
            compose_file: compose_file.to_path_buf(),
            reason: format!(
                "docker compose config --images exit {:?}: stderr={}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim_end(),
            ),
        });
    }
    Ok(parse_compose_images(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse `docker compose config --images` stdout into one image
/// per line, dropping blanks. Pure (testable without `docker`).
pub fn parse_compose_images(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Check whether `image` (e.g. `postgres:16-alpine`) is locally
/// cached. Implemented as `docker image inspect <image>` — exit 0
/// iff present. Bounded by [`DOCKER_PROBE_TIMEOUT`] for parity
/// with the rest of the docker-stack helpers; a healthy inspect
/// returns in tens of milliseconds.
fn image_present_locally(image: &str) -> bool {
    let mut cmd = Command::new("docker");
    cmd.arg("image").arg("inspect").arg(image);
    match run_command_output_timeout(&mut cmd, DOCKER_PROBE_TIMEOUT, "docker-image-inspect") {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// Run `docker compose -p <project> -f <compose_file> pull`
/// under [`pull_timeout_from_env`] (default 20 minutes via
/// [`DEFAULT_PULL_TIMEOUT`]). Reuses the shared
/// `harness_timeout::run_command_output_timeout` machinery so
/// the pre-pull stage satisfies the same
/// `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01` bound as every
/// other live-e2e harness shell-out.
fn pull_compose_images(
    project: &str,
    compose_file: &std::path::Path,
) -> Result<(), DockerStackError> {
    let timeout = pull_timeout_from_env(std::env::var(ENV_PULL_TIMEOUT_SECS).ok().as_deref());
    eprintln!(
        "[live-e2e docker-stack] pre-pull: docker compose -p {project}          -f {file} pull (timeout: {timeout:?}; override via {env}=<seconds>)",
        file = compose_file.display(),
        env = ENV_PULL_TIMEOUT_SECS,
    );
    let mut cmd = Command::new("docker");
    cmd.arg("compose")
        .arg("-p")
        .arg(project)
        .arg("-f")
        .arg(compose_file)
        .arg("pull");
    let out = match run_command_output_timeout(&mut cmd, timeout, "docker-compose-pull") {
        Ok(o) => o,
        Err(BoundedWaitError::SpawnFailed { reason, .. }) => {
            return Err(DockerStackError::DockerMissing { reason });
        }
        Err(e) => {
            return Err(DockerStackError::PullFailed {
                project: project.to_owned(),
                compose_file: compose_file.to_path_buf(),
                reason: format!("{e}"),
            });
        }
    };
    if !out.status.success() {
        return Err(DockerStackError::PullFailed {
            project: project.to_owned(),
            compose_file: compose_file.to_path_buf(),
            reason: format!(
                "docker compose pull exit {:?}: stderr={}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim_end(),
            ),
        });
    }
    Ok(())
}

fn bring_stack_up(project: &str, compose_file: &std::path::Path) -> Result<(), DockerStackError> {
    eprintln!(
        "[live-e2e harness] auto-bring-up: docker compose -p {project} \
         -f {} up -d --wait (timeout: {:?}; opt out via {ENV}=1)",
        compose_file.display(),
        DOCKER_BRINGUP_TIMEOUT,
        ENV = ENV_NO_AUTO_DOCKER,
    );
    let mut cmd = Command::new("docker");
    cmd.arg("compose")
        .arg("-p")
        .arg(project)
        .arg("-f")
        .arg(compose_file)
        .arg("up")
        .arg("-d")
        .arg("--wait");
    let out =
        match run_command_output_timeout(&mut cmd, DOCKER_BRINGUP_TIMEOUT, "docker-compose-up") {
            Ok(o) => o,
            Err(BoundedWaitError::SpawnFailed { reason, .. }) => {
                return Err(DockerStackError::DockerMissing { reason });
            }
            Err(e) => {
                return Err(DockerStackError::BringupFailed {
                    reason: format!("{e}"),
                });
            }
        };
    if !out.status.success() {
        return Err(DockerStackError::BringupFailed {
            reason: format!(
                "docker compose up exit {:?}: stderr={}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim_end(),
            ),
        });
    }
    Ok(())
}

// ─── Compose-stack RAII guard (`ComposeStackGuard`) ───────────────
//
// The realism-e2e harness today brings the compose-backed stack
// (postgres + mongo + redis + smtp + mysql + mssql + Grafana +
// Prometheus + OTel collector) UP via [`ensure_extended_stack_up_or_panic`]
// and never tears it down — the operator runs `cargo xtask
// observability down` (or `docker compose -f <file> down -v`) by
// hand. This RAII guard is the forward-compatible Drop site for
// any future caller that DOES want the harness to issue
// `docker compose down` itself: the guard's `Drop` honours the
// keep-alive opt-out
// ([`crate::common::keep_alive::keep_running_after_exit_with_workdir`])
// so the operator's "leave services running for post-mortem"
// intent transparently composes with the compose stack the same
// way it composes with the kernel daemon, otel-pusher, AVF guests,
// and `<data_dir>` retention.
//
// **Default behaviour.** [`ComposeStackGuard::new`] returns a guard
// with `teardown_on_drop = false`, i.e. Drop is a no-op. The
// guard exists primarily to (a) carry the compose project / file
// metadata into the keep-alive banner so the operator sees the
// `docker compose -f … ps` / `down -v` lines, and (b) provide a
// testable Drop site for the
// `compose_stack_drop_skips_down_when_keep_running` witness.
// Callers that want active teardown opt in via
// [`ComposeStackGuard::with_teardown_on_drop`].
//
// **Default-off invariant.** Per
// `INV-E2E-KEEP-ALIVE-DEFAULT-OFF-01`, the keep-running flag is
// off-by-default; absent any of the three signals (env / CLI /
// touch file) the Drop runs the configured teardown action. The
// witness `compose_stack_drop_runs_teardown_when_no_keep_alive_signal`
// pins that branch so a future maintainer flipping the default
// trips the test.

/// Pure decision: should the Drop perform compose teardown given
/// the configured `teardown_on_drop` toggle and the keep-alive
/// flag? Factored out so the witness coverage need not touch the
/// FS to inspect the dispatch decision (the touch-file probe still
/// reads the FS, but the rest of the decision is pure logic).
pub fn should_run_compose_teardown(
    teardown_on_drop: bool,
    work_dir: Option<&std::path::Path>,
) -> bool {
    teardown_on_drop && !keep_running_after_exit_with_workdir(work_dir)
}

/// RAII guard for a docker-compose-managed service stack. Carries
/// the `(project, compose_file)` pair so the keep-alive banner
/// can render the canonical `docker compose -p <project> -f
/// <compose_file> down -v` teardown command, and gates an
/// optional Drop-side `docker compose down` behind both the
/// `teardown_on_drop` toggle AND the keep-alive opt-out.
///
/// Constructed via [`ComposeStackGuard::new`] (no teardown by
/// default) and tuned via the builder methods
/// [`with_teardown_on_drop`](ComposeStackGuard::with_teardown_on_drop),
/// [`with_work_dir`](ComposeStackGuard::with_work_dir).
pub struct ComposeStackGuard {
    project: String,
    compose_file: PathBuf,
    /// When set, the touch-file probe (`<work_dir>/KEEP_RUNNING`)
    /// composes with the env / CLI signals in the Drop dispatch.
    /// `None` skips that probe; env / CLI signals still apply.
    work_dir: Option<PathBuf>,
    /// When `false` (the default), Drop is a no-op even when the
    /// keep-alive flag is off. Existing harness callers leave the
    /// stack up after the test run (operator tears down manually
    /// via `cargo xtask observability down` or
    /// `docker compose down -v`).
    teardown_on_drop: bool,
    /// Drop-time bookkeeping so a witness test can pin "ran"
    /// vs "skipped" without depending on the docker subprocess
    /// being reachable. `Some(_)` means Drop fired the teardown
    /// branch; `None` means the gate skipped it.
    last_drop_decision: std::sync::Arc<std::sync::Mutex<Option<bool>>>,
}

impl ComposeStackGuard {
    /// Build a guard that surfaces the `(project, compose_file)`
    /// pair for the keep-alive banner. `teardown_on_drop` defaults
    /// to `false` — current callers leave the stack up after a
    /// test run.
    pub fn new(project: impl Into<String>, compose_file: impl Into<PathBuf>) -> Self {
        Self {
            project: project.into(),
            compose_file: compose_file.into(),
            work_dir: None,
            teardown_on_drop: false,
            last_drop_decision: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Convenience constructor for the realism-e2e harness:
    /// pins the canonical `(COMPOSE_PROJECT, extended_compose_file())`
    /// pair so callers don't repeat themselves.
    pub fn for_extended_stack() -> Self {
        Self::new(COMPOSE_PROJECT, extended_compose_file())
    }

    /// Opt the guard into running `docker compose -p <project>
    /// -f <compose_file> down -v` on Drop, gated by the keep-alive
    /// opt-out. Builder; consumes self.
    pub fn with_teardown_on_drop(mut self, on: bool) -> Self {
        self.teardown_on_drop = on;
        self
    }

    /// Wire the work_dir for the touch-file branch of the
    /// keep-alive opt-out. Builder; consumes self.
    pub fn with_work_dir(mut self, work_dir: impl Into<PathBuf>) -> Self {
        self.work_dir = Some(work_dir.into());
        self
    }

    pub fn project(&self) -> &str {
        &self.project
    }
    pub fn compose_file(&self) -> &std::path::Path {
        &self.compose_file
    }
    pub fn teardown_on_drop_enabled(&self) -> bool {
        self.teardown_on_drop
    }
    pub fn work_dir(&self) -> Option<&std::path::Path> {
        self.work_dir.as_deref()
    }

    /// Diagnostic for tests: did the most-recent Drop decide to
    /// run the teardown branch? `None` if the guard has not been
    /// dropped yet OR if the gate skipped the branch.
    pub fn last_drop_ran_teardown(&self) -> Option<bool> {
        *self
            .last_drop_decision
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Run `docker compose -p <project> -f <compose_file> down -v`
    /// with the standard bounded timeout. Public so a manual
    /// teardown helper or a future operator-driven path can invoke
    /// the same code as the Drop branch.
    pub fn run_down(&self) -> Result<(), DockerStackError> {
        let mut cmd = Command::new("docker");
        cmd.arg("compose")
            .arg("-p")
            .arg(&self.project)
            .arg("-f")
            .arg(&self.compose_file)
            .arg("down")
            .arg("-v");
        let out = match run_command_output_timeout(
            &mut cmd,
            DOCKER_BRINGUP_TIMEOUT,
            "docker-compose-down",
        ) {
            Ok(o) => o,
            Err(BoundedWaitError::SpawnFailed { reason, .. }) => {
                return Err(DockerStackError::DockerMissing { reason });
            }
            Err(e) => {
                return Err(DockerStackError::BringupFailed {
                    reason: format!("docker compose down: {e}"),
                });
            }
        };
        if !out.status.success() {
            return Err(DockerStackError::BringupFailed {
                reason: format!(
                    "docker compose down exit {:?}: stderr={}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr).trim_end(),
                ),
            });
        }
        Ok(())
    }
}

impl Drop for ComposeStackGuard {
    fn drop(&mut self) {
        // Pure-logic gate — keep-alive opt-out composes with the
        // explicit `teardown_on_drop` toggle. See
        // `INV-E2E-KEEP-ALIVE-DEFAULT-OFF-01` and the
        // `compose_stack_drop_skips_down_when_keep_running`
        // / `compose_stack_drop_runs_teardown_when_no_keep_alive_signal`
        // witness pair.
        let should_run =
            should_run_compose_teardown(self.teardown_on_drop, self.work_dir.as_deref());
        if !should_run {
            // Poison-tolerant: Drop may run on the unwind path where a
            // prior holder of the mutex panicked; the bookkeeping bit
            // is purely diagnostic and we never want a second panic
            // from inside a Drop.
            if let Ok(mut g) = self.last_drop_decision.lock().or_else(
                |p: std::sync::PoisonError<std::sync::MutexGuard<'_, Option<bool>>>| {
                    Ok::<
                        std::sync::MutexGuard<'_, Option<bool>>,
                        std::sync::PoisonError<std::sync::MutexGuard<'_, Option<bool>>>,
                    >(p.into_inner())
                },
            ) {
                *g = Some(false);
            }
            return;
        }
        // Best-effort `docker compose down -v`; never panic from
        // a Drop. A failed teardown is an operator-fix path
        // (`docker compose -p <project> -f <compose_file> down -v`
        // by hand), surfaced via the eprintln! line — the test's
        // verdict has already been computed and we MUST NOT
        // re-panic during unwind.
        eprintln!(
            "[live-e2e harness] ComposeStackGuard::Drop running \
             `docker compose -p {project} -f {compose} down -v`",
            project = self.project,
            compose = self.compose_file.display(),
        );
        if let Err(e) = self.run_down() {
            eprintln!(
                "[live-e2e harness] ComposeStackGuard::Drop teardown \
                 failed: {e}; rerun manually via \
                 `docker compose -p {project} -f {compose} down -v`",
                project = self.project,
                compose = self.compose_file.display(),
            );
        }
        if let Ok(mut g) = self.last_drop_decision.lock().or_else(
            |p: std::sync::PoisonError<std::sync::MutexGuard<'_, Option<bool>>>| {
                Ok::<
                    std::sync::MutexGuard<'_, Option<bool>>,
                    std::sync::PoisonError<std::sync::MutexGuard<'_, Option<bool>>>,
                >(p.into_inner())
            },
        ) {
            *g = Some(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `RAXIS_LIVE_E2E_NO_AUTO_DOCKER=1` against a non-existent
    /// project name MUST surface `DockerStackError::AutoBringupDisabled`
    /// containing the literal `RAXIS_LIVE_E2E_DOCKER_STACK_DOWN`
    /// token a CI log scraper greps for. This is the regression
    /// test the brief asks for: prove the auto-bring-up opt-out
    /// is wired.
    ///
    /// Skipped when `docker` is not on PATH (matching the
    /// upstream-binary-missing skip pattern the rest of the
    /// harness uses). The skip path keeps `cargo test` green on
    /// a developer laptop without docker installed.
    #[test]
    fn opt_out_against_missing_project_surfaces_stack_down_token() {
        if !docker_binary_present() {
            eprintln!(
                "[docker-stack-test] `docker` not on PATH; skipping \
                 opt_out_against_missing_project_surfaces_stack_down_token"
            );
            return;
        }
        // `ensure_stack_up` runs `docker compose ps` before the
        // opt-out branch resolves, so a stopped daemon surfaces
        // `ProbeFailed` instead of the `AutoBringupDisabled` outcome
        // this test exists to pin. Skip silently in that environment
        // (matches the live-infra exclusion policy: tests gated on a
        // running Docker daemon must not fail on a laptop without it).
        if !docker_daemon_reachable() {
            eprintln!(
                "[docker-stack-test] docker daemon not reachable; skipping \
                 opt_out_against_missing_project_surfaces_stack_down_token"
            );
            return;
        }
        let _guard = SetEnvGuard::set(ENV_NO_AUTO_DOCKER, "1");
        let project_name = format!("raxis-live-e2e-nonexistent-{}", std::process::id(),);
        let r = ensure_stack_up(
            &project_name,
            &PathBuf::from("/dev/null/no-such-compose.yml"),
        );
        match r {
            Err(DockerStackError::AutoBringupDisabled { ref project, .. }) => {
                assert_eq!(project, &project_name);
                let rendered = format!("{}", r.unwrap_err());
                assert!(
                    rendered.contains(STACK_DOWN_TOKEN),
                    "rendered must contain {STACK_DOWN_TOKEN}: {rendered}",
                );
                assert!(
                    rendered.contains(ENV_NO_AUTO_DOCKER),
                    "rendered must mention {ENV_NO_AUTO_DOCKER}: {rendered}",
                );
            }
            other => panic!(
                "expected AutoBringupDisabled with stack-down token; \
                 got: {other:?}"
            ),
        }
    }

    #[test]
    fn parse_compose_ps_handles_ndjson() {
        let out = "\
            {\"Name\":\"raxis-e2e-pg\",\"State\":\"running\",\"Health\":\"healthy\"}\n\
            {\"Name\":\"raxis-e2e-mongo\",\"State\":\"running\",\"Health\":\"healthy\"}\n\
        ";
        let p = parse_compose_ps(out);
        assert!(p.healthy, "summary: {}", p.summary);
        assert!(p.summary.contains("2/2"), "summary: {}", p.summary);
    }

    #[test]
    fn parse_compose_ps_flags_unhealthy_services() {
        let out = "\
            {\"Name\":\"raxis-e2e-pg\",\"State\":\"running\",\"Health\":\"healthy\"}\n\
            {\"Name\":\"raxis-e2e-mssql\",\"State\":\"exited\",\"Health\":\"\"}\n\
        ";
        let p = parse_compose_ps(out);
        assert!(!p.healthy, "summary: {}", p.summary);
        assert!(
            p.summary.contains("raxis-e2e-mssql"),
            "summary: {}",
            p.summary
        );
    }

    #[test]
    fn parse_compose_ps_handles_v1_array_format() {
        let out = "[\
            {\"Name\":\"raxis-e2e-pg\",\"State\":\"running\",\"Health\":\"healthy\"},\
            {\"Name\":\"raxis-e2e-redis\",\"State\":\"running\",\"Health\":\"\"}\
        ]";
        let p = parse_compose_ps(out);
        assert!(p.healthy, "summary: {}", p.summary);
    }

    #[test]
    fn parse_compose_ps_empty_means_not_healthy() {
        let p = parse_compose_ps("");
        assert!(!p.healthy);
    }

    // ─── Pre-pull stage witnesses (INV-LIVE-E2E-HARNESS-IMAGE-PREPULL-01) ─

    /// Witness arm (b): when `docker image inspect` reports any
    /// image absent, the dispatcher MUST return
    /// `PrepullDecision::PullRequired` carrying the missing
    /// subset. Drives the pure dispatcher
    /// [`decide_prepull_action_with`] with closures so the test
    /// stays green on a developer laptop without `docker`.
    #[test]
    fn prepull_any_missing_triggers_pull() {
        let images = vec![
            "postgres:16-alpine".to_owned(),
            "mongo:7".to_owned(),
            "redis:7-alpine".to_owned(),
        ];
        let missing_target = "mongo:7";
        let decision =
            decide_prepull_action_with(false, || Ok(images.clone()), |img| img != missing_target)
                .expect("dispatcher must not error");
        match decision {
            PrepullDecision::PullRequired { all, missing } => {
                assert_eq!(all, images, "PullRequired must carry the full image list");
                assert_eq!(missing, vec![missing_target.to_owned()]);
            }
            other => panic!("expected PullRequired, got: {other:?}"),
        }
    }

    /// Witness arm (a): when `docker image inspect` reports every
    /// image present, the dispatcher MUST return
    /// `PrepullDecision::AllCached` and the runtime path MUST
    /// skip the pull. Pins the fast path so a future maintainer
    /// who flips the gate to "always pull" trips here.
    #[test]
    fn prepull_all_cached_skips_pull() {
        let images = vec!["postgres:16-alpine".to_owned(), "mongo:7".to_owned()];
        let decision = decide_prepull_action_with(false, || Ok(images.clone()), |_| true)
            .expect("dispatcher must not error");
        assert_eq!(decision, PrepullDecision::AllCached { count: 2 });
    }

    /// Witness arm (c): `RAXIS_LIVE_E2E_NO_PREPULL=1` MUST
    /// short-circuit before ANY docker shell-out. We assert this
    /// at the dispatcher level by passing closures that panic if
    /// invoked — if either fires the env-var gate has regressed.
    #[test]
    fn prepull_opt_out_skips_all_docker_shell_outs() {
        let decision = decide_prepull_action_with(
            true,
            || panic!("images_provider MUST NOT be invoked under opt-out"),
            |_| panic!("presence_checker MUST NOT be invoked under opt-out"),
        )
        .expect("dispatcher must not error on opt-out");
        assert_eq!(decision, PrepullDecision::OptedOut);
    }

    /// Edge case: empty compose file (no images declared) MUST
    /// short-circuit as `AllCached { count: 0 }` and NOT crash.
    /// Documents the contract for the
    /// `docker compose config --images returned empty list` path.
    #[test]
    fn prepull_empty_image_list_is_all_cached_zero() {
        let decision = decide_prepull_action_with(
            false,
            || Ok(Vec::new()),
            |_| panic!("presence_checker MUST NOT be invoked when image list is empty"),
        )
        .expect("dispatcher must not error on empty image list");
        assert_eq!(decision, PrepullDecision::AllCached { count: 0 });
    }

    /// Errors from the `images_provider` (e.g. compose-file
    /// parse failure) MUST propagate verbatim, NOT be swallowed
    /// as `AllCached { count: 0 }`. Pins the error-bubble so a
    /// future maintainer who reorders the early-return doesn't
    /// silently hide a broken compose file.
    #[test]
    fn prepull_images_provider_error_propagates() {
        let r = decide_prepull_action_with(
            false,
            || {
                Err(DockerStackError::PullFailed {
                    project: "test-project".to_owned(),
                    compose_file: PathBuf::from("/dev/null/no-such.yml"),
                    reason: "synthetic error".to_owned(),
                })
            },
            |_| true,
        );
        match r {
            Err(DockerStackError::PullFailed { reason, .. }) => {
                assert!(
                    reason.contains("synthetic error"),
                    "reason MUST surface verbatim: {reason}",
                );
            }
            other => panic!("expected PullFailed to propagate; got: {other:?}"),
        }
    }

    /// Pure-parse witness for `docker compose config --images`
    /// output: one image per line, blanks dropped, no
    /// transformation. Pins the contract so a future maintainer
    /// who switches to a different parse strategy (e.g. JSON)
    /// reflects the change in this test.
    #[test]
    fn parse_compose_images_one_per_line_skipping_blanks() {
        let out = "postgres:16-alpine\nmongo:7\n\n  redis:7-alpine  \n";
        let images = parse_compose_images(out);
        assert_eq!(
            images,
            vec![
                "postgres:16-alpine".to_owned(),
                "mongo:7".to_owned(),
                "redis:7-alpine".to_owned(),
            ],
        );
    }

    /// `pull_timeout_from_env` MUST clamp to
    /// [`DEFAULT_PULL_TIMEOUT`] for every input that is not a
    /// strictly-positive integer — every external-process spawn
    /// in the live-e2e harness must be bounded per
    /// `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`.
    #[test]
    fn pull_timeout_env_clamps_invalid_inputs_to_default() {
        assert_eq!(pull_timeout_from_env(None), DEFAULT_PULL_TIMEOUT);
        assert_eq!(pull_timeout_from_env(Some("")), DEFAULT_PULL_TIMEOUT);
        assert_eq!(pull_timeout_from_env(Some("   ")), DEFAULT_PULL_TIMEOUT);
        assert_eq!(pull_timeout_from_env(Some("0")), DEFAULT_PULL_TIMEOUT);
        assert_eq!(pull_timeout_from_env(Some("-15")), DEFAULT_PULL_TIMEOUT);
        assert_eq!(
            pull_timeout_from_env(Some("not-a-number")),
            DEFAULT_PULL_TIMEOUT
        );
        // Positive integer (in seconds) MUST be honoured verbatim.
        assert_eq!(pull_timeout_from_env(Some("90")), Duration::from_secs(90),);
        // Leading + trailing whitespace MUST not defeat the parse.
        assert_eq!(
            pull_timeout_from_env(Some("  600 ")),
            Duration::from_secs(600),
        );
    }

    /// PullFailed rendering MUST include both the operator
    /// remediation steps and the literal manual `docker compose
    /// pull` command (with the project + compose-file path
    /// substituted in). Pins the copy-pastable contract — a
    /// regression that drops either field re-creates the
    /// misleading-error UX the pre-pull stage exists to fix.
    #[test]
    fn pull_failed_display_carries_manual_remediation_command() {
        let e = DockerStackError::PullFailed {
            project: "raxis-live-e2e-test".to_owned(),
            compose_file: PathBuf::from("/path/to/docker-compose.extended.e2e.yml"),
            reason: "docker compose pull exit Some(1): stderr=connection refused".to_owned(),
        };
        let rendered = format!("{e}");
        assert!(
            rendered.contains("image pull failed"),
            "must lead with failure summary: {rendered}",
        );
        assert!(
            rendered.contains("Remediation:"),
            "must include remediation block: {rendered}",
        );
        assert!(
            rendered.contains("docker compose -p raxis-live-e2e-test"),
            "must include manual pre-pull command with project: {rendered}",
        );
        assert!(
            rendered.contains("/path/to/docker-compose.extended.e2e.yml"),
            "must include compose file path: {rendered}",
        );
        assert!(
            rendered.contains(ENV_PULL_TIMEOUT_SECS),
            "must mention the timeout-override env var: {rendered}",
        );
        assert!(
            rendered.contains(&format!("default {}s", DEFAULT_PULL_TIMEOUT.as_secs())),
            "must mention the default timeout: {rendered}",
        );
    }

    fn docker_binary_present() -> bool {
        Command::new("docker")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// `docker info` exits 0 only when the daemon socket is reachable.
    /// `--version` (used by `docker_binary_present`) does NOT need
    /// the daemon, so the binary can be installed while the daemon is
    /// stopped (the common case on a developer laptop without
    /// Docker Desktop running). Tests that depend on the daemon
    /// must skip when this returns `false` so `cargo test` stays
    /// green in that environment.
    fn docker_daemon_reachable() -> bool {
        Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// RAII env-var guard: sets the var on `set` and restores
    /// the prior value (or removes it) on drop. Unsafe-style
    /// `set_var` is fine in single-threaded test scope.
    struct SetEnvGuard {
        key: &'static str,
        prior: Option<String>,
    }

    impl SetEnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prior = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prior }
        }
        fn unset(key: &'static str) -> Self {
            let prior = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, prior }
        }
    }

    impl Drop for SetEnvGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    // ─── ComposeStackGuard witnesses ─────────────────────────────
    //
    // Pure-decision coverage for the Drop dispatcher
    // ([`should_run_compose_teardown`]) plus a behavioural
    // witness that drives the actual `Drop` impl through both
    // arms of the keep-alive flag. Mirrors the existing
    // `harness_drop_skips_teardown_when_keep_running` pattern in
    // `kernel/tests/common/keep_alive.rs::tests`.

    /// Serialise every witness that mutates the
    /// `RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT` env var so parallel
    /// `cargo test` runs in the same binary cannot poison each
    /// other. Reuses the cross-`mod` lock declared in
    /// `kernel/tests/common/keep_alive.rs` so docker-stack
    /// witnesses serialise against the keep-alive module's own
    /// `tests::lock()`-protected witnesses.
    fn keep_alive_env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::common::keep_alive::lock_keep_running_env()
    }

    const KEEP_RUNNING_ENV: &str = "RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT";
    const KEEP_RUNNING_TOUCH: &str = "KEEP_RUNNING";

    /// `INV-E2E-KEEP-ALIVE-DEFAULT-OFF-01` (compose-stack arm) —
    /// the `should_run_compose_teardown` dispatcher MUST return
    /// `true` when teardown is enabled AND no keep-alive signal
    /// is active. Pinning the default branch catches a future
    /// maintainer who flipped the gate to "default to skipping
    /// teardown".
    #[test]
    fn compose_stack_drop_runs_teardown_when_no_keep_alive_signal() {
        let _g = keep_alive_env_lock();
        let _env = SetEnvGuard::unset(KEEP_RUNNING_ENV);
        let tmp = tempfile::tempdir().expect("tempdir");
        // No env, no touch file, teardown_on_drop=true → run.
        assert!(should_run_compose_teardown(true, Some(tmp.path())));
        assert!(should_run_compose_teardown(true, None));
        // teardown_on_drop=false → never run, regardless.
        assert!(!should_run_compose_teardown(false, Some(tmp.path())));
        assert!(!should_run_compose_teardown(false, None));
    }

    /// Witness for the keep-alive composition: with
    /// `teardown_on_drop=true` AND the env-var signal active OR
    /// the touch-file signal active OR the CLI-flag signal
    /// active, the dispatcher MUST skip the teardown.
    #[test]
    fn compose_stack_drop_skips_down_when_keep_running() {
        let _g = keep_alive_env_lock();

        // Env-var arm.
        let _env = SetEnvGuard::set(KEEP_RUNNING_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(
            !should_run_compose_teardown(true, Some(tmp.path())),
            "env-var arm MUST gate teardown off",
        );
        assert!(
            !should_run_compose_teardown(true, None),
            "env-var arm MUST gate teardown off even without work_dir",
        );
        drop(_env);

        // Touch-file arm.
        let _env = SetEnvGuard::unset(KEEP_RUNNING_ENV);
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join(KEEP_RUNNING_TOUCH), b"").expect("write touch file");
        assert!(
            !should_run_compose_teardown(true, Some(tmp.path())),
            "touch-file arm MUST gate teardown off",
        );
        drop(_env);

        // CLI-flag arm. Hold the bit on for the duration of the
        // assertion; the guard restores prior state on drop.
        let _env = SetEnvGuard::unset(KEEP_RUNNING_ENV);
        let _cli = crate::common::keep_alive::CliFlagGuard::set(true);
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(
            !should_run_compose_teardown(true, Some(tmp.path())),
            "CLI-flag arm MUST gate teardown off",
        );
        drop(_cli);
        drop(_env);

        // Behavioural witness against the actual Drop impl: under
        // env-var keep-alive, the guard's Drop MUST set its
        // bookkeeping cell to `Some(false)` (i.e. teardown
        // skipped). The actual `docker compose down` is never
        // invoked because the gate fires before the subprocess
        // spawn.
        let _env = SetEnvGuard::set(KEEP_RUNNING_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        let probe = {
            let g = ComposeStackGuard::for_extended_stack()
                .with_teardown_on_drop(true)
                .with_work_dir(tmp.path());
            g.last_drop_decision.clone()
        };
        // After the inner block ends, `g` is dropped. Inspect the
        // shared cell to confirm the gate fired.
        assert_eq!(
            *probe.lock().unwrap(),
            Some(false),
            "ComposeStackGuard::Drop under keep-alive MUST record \
             a skipped-teardown decision",
        );
    }

    /// Default constructor MUST NOT enable teardown — the existing
    /// harness behavior is "leave the stack up after the test".
    /// Pin so a future refactor flipping the default trips here.
    #[test]
    fn compose_stack_guard_default_teardown_disabled() {
        let g = ComposeStackGuard::new("project", PathBuf::from("/tmp/no-such.yml"));
        assert!(!g.teardown_on_drop_enabled());
        assert_eq!(g.project(), "project");
        assert_eq!(g.compose_file(), std::path::Path::new("/tmp/no-such.yml"));
        assert!(g.work_dir().is_none());
        // Drop with teardown disabled MUST be a no-op (no docker
        // subprocess spawned, decision recorded as Some(false)).
        let probe = g.last_drop_decision.clone();
        drop(g);
        assert_eq!(*probe.lock().unwrap(), Some(false));
    }

    /// `for_extended_stack` is the realism-e2e convenience
    /// constructor; it MUST pin the realism project name and the
    /// extended compose file path. A typo in either would
    /// mis-target the keep-alive banner's teardown command.
    #[test]
    fn compose_stack_guard_for_extended_stack_constants_pinned() {
        let g = ComposeStackGuard::for_extended_stack();
        assert_eq!(g.project(), COMPOSE_PROJECT);
        assert_eq!(g.compose_file(), extended_compose_file());
    }
}
