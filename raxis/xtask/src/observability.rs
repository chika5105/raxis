//! `cargo xtask observability {up,down,status,urls}` — standalone
//! lifecycle wrapper around the OTel-collector + Prometheus + Grafana
//! subset of the live-e2e compose stack.
//!
//! # Why this exists
//!
//! `observability(v3)` (commit `07ad9be`) landed the full mission-
//! control surface — 10 auto-provisioned Grafana dashboards, 14-day
//! Prometheus retention, an OTLP/HTTP collector — but parked it
//! inside the live-e2e compose file. The only way to get the
//! dashboards in front of an operator was to bring up the entire
//! live-e2e (postgres + mongo + redis + smtp + mysql + mssql +
//! observability triple) or to run a `cargo test
//! --test extended_e2e_realistic_scenario` slice. Both have
//! prerequisites and runtime costs that are unreasonable for the
//! "I just want to look at the dashboards" workflow.
//!
//! This module bridges that gap by exposing a thin subcommand that:
//!
//!   * Brings up *only* the observability triple
//!     (`otel-collector` + `prometheus` + `grafana`) under the canonical
//!     `raxis-live-e2e-test` compose project namespace established at
//!     commit `9a2fbb3`. Same image tags, same named volumes, same
//!     scrape config — anything we land here Just Works against the
//!     live-e2e flow.
//!   * Waits for healthchecks (`docker compose up -d --wait`).
//!   * Prints copy-pasteable URLs (Grafana, Prometheus, OTel collector
//!     OTLP/HTTP, OTel collector self-metrics, OTel zPages) plus per-
//!     dashboard deep links pulled from the Grafana provisioning API.
//!   * On macOS, calls `open(1)` against the Grafana home + the
//!     `raxis-00-overview` dashboard; on Linux it calls `xdg-open`. A
//!     `--no-open` flag turns this off for CI / SSH contexts where
//!     spawning a browser is meaningless or harmful.
//!
//! No new dependencies are introduced — every Grafana / Prometheus
//! probe is a stdlib `TcpStream::connect_timeout` + a `curl(1)`
//! shell-out, mirroring the convention `xtask::perf::probe_live_e2e_stack`
//! already uses.
//!
//! # Subcommands
//!
//! * `up [--no-open] [--detach-only] [--full]`
//!     - Default: bring up `otel-collector` + `prometheus` + `grafana`
//!       only.
//!     - `--full`: bring up the entire live-e2e compose stack (every
//!       upstream-service container PLUS the observability triple).
//!       Uses `docker-compose.extended.e2e.yml` so the realistic
//!       scenario's seeded Postgres/Mongo fixtures converge too.
//!     - `--no-open`: skip the auto-browser-open step.
//!     - `--detach-only`: skip the URL print + open even when stdout
//!       is a TTY; used by callers that just want the side-effect.
//!
//! * `down [--volumes]`
//!     - Tear down the compose project. `--volumes` (`-v`) also drops
//!       the named `prometheus_data` / `grafana_data` volumes so the
//!       next `up` is a clean slate.
//!
//! * `status`
//!     - Read-only: probe Grafana `/api/health`, Prometheus
//!       `/-/healthy`, and the OTel collector's `:13133/` zPages
//!       endpoint. Prints reachable / unreachable per service with the
//!       exact URL.
//!
//! * `urls [--open] [--dashboard <UID>]`
//!     - Read-only: print the URL block without trying to bring the
//!       stack up. `--open` opens Grafana + the named dashboard in
//!       the default browser; defaults to `raxis-00-overview`.
//!
//! # Invariant: no licence / SPDX / copyright text
//!
//! The repo is SSPL; per the standing licensing directive this module
//! emits no `// SPDX-License-Identifier: ...` header, no copyright
//! line, and never reads or writes `LICENSE` / `CONTRIBUTING` /
//! `NOTICE` files. It is a pure operator-experience helper.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use crate::browser::{open_in_best_browser, preference_from_env, BrowserPreference, OpenOutcome};

/// Canonical compose project name pinned at commit `9a2fbb3`.
///
/// Hard-coding it here keeps the xtask in lock-step with the
/// top-level `name:` field in both `live-e2e/docker-compose.e2e.yml`
/// and `live-e2e/docker-compose.extended.e2e.yml`. If those files
/// ever bump the project name the test
/// `project_name_matches_compose_file` (below) tells us before a
/// dev does a confusing `docker compose ps` that finds no
/// containers.
pub const COMPOSE_PROJECT: &str = "raxis-live-e2e-test";

/// Host port for Grafana. Mirrors `live-e2e/docker-compose.e2e.yml`.
pub const GRAFANA_PORT: u16 = 3000;

/// Host port for Prometheus. Mirrors `live-e2e/docker-compose.e2e.yml`.
pub const PROMETHEUS_PORT: u16 = 9090;

/// Host port for the OTel collector's OTLP/HTTP receiver. The kernel
/// emits to this endpoint when `[observability]` is enabled.
pub const OTLP_HTTP_PORT: u16 = 4318;

/// Host port for the OTel collector's Prometheus exposition endpoint
/// (the one Prometheus scrapes).
pub const OTEL_PROM_PORT: u16 = 8889;

/// Host port for the OTel collector's own internal-metrics endpoint
/// (collector self-stats: dropped points, exporter failures, etc.).
pub const OTEL_SELF_PORT: u16 = 8888;

/// Host port for the OTel collector's zPages / health endpoint.
pub const OTEL_ZPAGES_PORT: u16 = 13133;

/// Default Grafana admin user. Anonymous Viewer is enabled too;
/// these creds are needed only when editing dashboards from the UI
/// or hitting the Grafana HTTP API directly.
pub const GRAFANA_ADMIN_USER: &str = "admin";

/// Default Grafana admin password (matches
/// `GF_SECURITY_ADMIN_PASSWORD` in the compose file).
pub const GRAFANA_ADMIN_PASS: &str = "raxis-e2e";

/// The dashboard UID `cargo xtask observability up` opens by
/// default. Provisioned by
/// `observability/grafana/dashboards/00-overview.json`.
pub const DEFAULT_OPEN_DASHBOARD_UID: &str = "raxis-00-overview";

/// CLI entry point. Called from `xtask::main` after the leading
/// `observability` token has been stripped.
pub fn run(args: &[String]) -> Result<()> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("urls");
    let tail = &args[args.len().min(1)..];
    match sub {
        "up" => run_up(tail),
        "down" => run_down(tail),
        "status" => run_status(),
        "urls" => run_urls(tail),
        other => anyhow::bail!(
            "unknown observability subcommand: {other:?}; \
             available: up, down, status, urls"
        ),
    }
}

// ── `up` ────────────────────────────────────────────────────────────

fn run_up(tail: &[String]) -> Result<()> {
    let no_open = tail.iter().any(|a| a == "--no-open");
    let detach_only = tail.iter().any(|a| a == "--detach-only");
    let full = tail.iter().any(|a| a == "--full");

    let compose_file = if full {
        find_extended_compose_file().context("locate extended live-e2e compose file")?
    } else {
        find_compose_file().context("locate live-e2e compose file")?
    };
    eprintln!(
        "==> observability up: compose-file={} project={} mode={}",
        compose_file.display(),
        COMPOSE_PROJECT,
        if full { "full-stack" } else { "obs-triple" },
    );

    // The compose `up -d --wait` blocks on every selected service's
    // healthcheck. Passing only the observability triple keeps the
    // boot cost to the OTel + Prometheus + Grafana images even when
    // the compose file declares postgres / mongo / redis etc.
    let mut argv: Vec<String> = vec![
        "compose".into(),
        "-f".into(),
        compose_file.to_string_lossy().into_owned(),
        "-p".into(),
        COMPOSE_PROJECT.into(),
        "up".into(),
        "-d".into(),
        "--wait".into(),
    ];
    if !full {
        argv.extend(
            ["otel-collector", "prometheus", "grafana"]
                .iter()
                .map(|s| s.to_string()),
        );
    }
    let status = Command::new("docker")
        .args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("spawn `docker compose up`")?;
    anyhow::ensure!(
        status.success(),
        "`docker compose up` exited with status {status}; \
         see the docker-compose output above for the failing service \
         (run `docker compose -f {} -p {} logs <service>` for details)",
        compose_file.display(),
        COMPOSE_PROJECT,
    );

    if detach_only {
        return Ok(());
    }

    print_url_block();
    print_dashboard_block();

    if no_open || !should_auto_open() {
        eprintln!(
            "==> observability up: skipped auto-open (no-open / non-TTY / RAXIS_E2E_NO_OPEN=1); \
             paste the URLs above into a browser when ready."
        );
        return Ok(());
    }
    open_browser_best_effort();
    Ok(())
}

fn should_auto_open() -> bool {
    // `RAXIS_E2E_BROWSER=none` is the canonical suppression knob;
    // the legacy `RAXIS_E2E_NO_OPEN=1` is honoured for backcompat
    // with the README's pre-Cursor surface. `CI` / `SSH_CONNECTION`
    // are conservative guards so a scripted CI runner or a
    // headless SSH session doesn't try to spawn a window.
    if matches!(preference_from_env(), BrowserPreference::None) {
        return false;
    }
    if std::env::var("RAXIS_E2E_NO_OPEN").as_deref() == Ok("1") {
        return false;
    }
    if std::env::var("CI").is_ok() {
        return false;
    }
    if std::env::var("SSH_CONNECTION").is_ok() {
        return false;
    }
    true
}

// ── `down` ──────────────────────────────────────────────────────────

fn run_down(tail: &[String]) -> Result<()> {
    let volumes = tail.iter().any(|a| a == "--volumes" || a == "-v");
    let compose_file = find_compose_file().context("locate live-e2e compose file")?;
    eprintln!(
        "==> observability down: compose-file={} project={} volumes={}",
        compose_file.display(),
        COMPOSE_PROJECT,
        volumes,
    );
    let mut argv: Vec<String> = vec![
        "compose".into(),
        "-f".into(),
        compose_file.to_string_lossy().into_owned(),
        "-p".into(),
        COMPOSE_PROJECT.into(),
        "down".into(),
    ];
    if volumes {
        argv.push("-v".into());
    }
    let status = Command::new("docker")
        .args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("spawn `docker compose down`")?;
    anyhow::ensure!(
        status.success(),
        "`docker compose down` exited with status {status}",
    );
    if volumes {
        eprintln!(
            "    dropped named volumes ({COMPOSE_PROJECT}_prometheus_data, \
             {COMPOSE_PROJECT}_grafana_data)"
        );
    } else {
        eprintln!(
            "    kept named volumes ({COMPOSE_PROJECT}_prometheus_data, \
             {COMPOSE_PROJECT}_grafana_data); rerun with `-v` to wipe."
        );
    }
    Ok(())
}

// ── `status` ────────────────────────────────────────────────────────

fn run_status() -> Result<()> {
    eprintln!(
        "==> observability status: probing live-e2e endpoints \
         (project={COMPOSE_PROJECT})"
    );
    let services: &[(&str, &str)] = &[
        ("grafana", &grafana_health_url()),
        ("prometheus", &prometheus_health_url()),
        ("otel-collector", &otel_health_url()),
    ];
    let mut all_reachable = true;
    for (label, url) in services {
        let ok = http_probe_ok(url);
        if !ok {
            all_reachable = false;
        }
        eprintln!(
            "    {label:<15} {} {url}",
            if ok { "UP   " } else { "DOWN " },
        );
    }
    if !all_reachable {
        eprintln!(
            "==> observability status: at least one endpoint unreachable; \
             bring the stack up with `cargo xtask observability up`."
        );
    }
    Ok(())
}

// ── `urls` ──────────────────────────────────────────────────────────

fn run_urls(tail: &[String]) -> Result<()> {
    let open_flag = tail.iter().any(|a| a == "--open");
    let dashboard_uid = parse_str_flag(tail, "--dashboard")
        .unwrap_or_else(|| DEFAULT_OPEN_DASHBOARD_UID.to_string());

    print_url_block();
    print_dashboard_block();

    if open_flag {
        if should_auto_open() {
            open_url_best_effort(&grafana_home_url());
            open_url_best_effort(&grafana_dashboard_url(&dashboard_uid));
        } else {
            eprintln!(
                "==> observability urls: --open suppressed (RAXIS_E2E_NO_OPEN=1 / CI / SSH); \
                 paste the URLs above into a browser when ready."
            );
        }
    }
    Ok(())
}

// ── URL helpers (compose constants) ─────────────────────────────────

fn grafana_home_url() -> String {
    format!("http://127.0.0.1:{GRAFANA_PORT}/")
}

fn grafana_health_url() -> String {
    format!("http://127.0.0.1:{GRAFANA_PORT}/api/health")
}

fn grafana_dashboard_url(uid: &str) -> String {
    format!("http://127.0.0.1:{GRAFANA_PORT}/d/{uid}")
}

fn prometheus_home_url() -> String {
    format!("http://127.0.0.1:{PROMETHEUS_PORT}/")
}

fn prometheus_health_url() -> String {
    format!("http://127.0.0.1:{PROMETHEUS_PORT}/-/healthy")
}

fn prometheus_targets_url() -> String {
    format!("http://127.0.0.1:{PROMETHEUS_PORT}/targets")
}

fn otel_otlp_http_url() -> String {
    format!("http://127.0.0.1:{OTLP_HTTP_PORT}")
}

fn otel_health_url() -> String {
    format!("http://127.0.0.1:{OTEL_ZPAGES_PORT}/")
}

fn otel_self_metrics_url() -> String {
    format!("http://127.0.0.1:{OTEL_SELF_PORT}/metrics")
}

fn otel_collector_exposition_url() -> String {
    format!("http://127.0.0.1:{OTEL_PROM_PORT}/metrics")
}

// ── Pretty-print: top-level URL block ───────────────────────────────

/// Public so the live-e2e harnesses can render the same block at
/// startup AND at end-of-run from inside the kernel test binaries.
/// Writes to stderr to mirror every other harness log line.
pub fn print_url_block() {
    let mut out = std::io::stderr().lock();
    let _ = writeln!(out, "==> observability surface (project={COMPOSE_PROJECT})");
    let _ = writeln!(
        out,
        "    Grafana    : {} (admin/{GRAFANA_ADMIN_PASS}, anonymous Viewer OK)",
        grafana_home_url()
    );
    let _ = writeln!(out, "    Prometheus : {}", prometheus_home_url());
    let _ = writeln!(out, "    Prom targets: {}", prometheus_targets_url());
    let _ = writeln!(
        out,
        "    OTLP/HTTP  : {} (kernel `[observability]` push target)",
        otel_otlp_http_url()
    );
    let _ = writeln!(out, "    OTel zPages: {}", otel_health_url());
    let _ = writeln!(out, "    OTel self  : {}", otel_self_metrics_url());
    let _ = writeln!(out, "    OTel→Prom  : {}", otel_collector_exposition_url());
}

// ── Pretty-print: per-dashboard deep-links from Grafana API ─────────

/// Print each provisioned Grafana dashboard as a copy-pasteable
/// URL. Best-effort: a Grafana that is not yet up emits a single
/// "not reachable" line and returns cleanly.
pub fn print_dashboard_block() {
    let mut out = std::io::stderr().lock();
    let _ = writeln!(out, "    dashboards :");
    let dashboards = fetch_dashboards();
    match dashboards {
        Ok(entries) if !entries.is_empty() => {
            for d in &entries {
                let _ = writeln!(
                    out,
                    "      - {title:<54} {url}",
                    title = d.title,
                    url = grafana_dashboard_url(&d.uid),
                );
            }
        }
        Ok(_) => {
            let _ = writeln!(
                out,
                "      (Grafana returned 0 provisioned dashboards — check \
                 `observability/grafana/provisioning/dashboards/raxis.yaml` \
                 + the bind mount in `live-e2e/docker-compose.e2e.yml`)"
            );
        }
        Err(e) => {
            let _ = writeln!(
                out,
                "      (Grafana not reachable yet: {e}; \
                 run `cargo xtask observability up` first)"
            );
        }
    }
}

/// One provisioned dashboard surfaced by Grafana's `/api/search`.
#[derive(Debug, Clone)]
struct Dashboard {
    title: String,
    uid: String,
}

fn fetch_dashboards() -> Result<Vec<Dashboard>> {
    // 1-second timeout — the Grafana API is local. If it's not
    // responding within a second the operator's better served by
    // the "not reachable" branch above than by a long hang.
    let probe = Command::new("curl")
        .args([
            "-sf",
            "--max-time",
            "2",
            "-u",
            &format!("{GRAFANA_ADMIN_USER}:{GRAFANA_ADMIN_PASS}"),
            &format!("http://127.0.0.1:{GRAFANA_PORT}/api/search?type=dash-db"),
        ])
        .stdin(Stdio::null())
        .output()
        .context("spawn curl against Grafana /api/search")?;
    anyhow::ensure!(
        probe.status.success(),
        "Grafana /api/search returned non-success (exit={:?}); \
         stack may still be coming up",
        probe.status.code(),
    );
    let body = String::from_utf8_lossy(&probe.stdout);
    parse_dashboards(&body)
}

/// Parse Grafana's `/api/search?type=dash-db` JSON response. We
/// avoid pulling `serde_json` into the xtask binary for this one
/// call by doing a tiny hand-written extraction — the response
/// shape is a flat array of `{title, uid, ...}` objects and a
/// minimal regex-free scan is enough. If the response ever grows
/// more nested fields, swap this for `serde_json::from_str` (the
/// crate is already a workspace dep).
fn parse_dashboards(json: &str) -> Result<Vec<Dashboard>> {
    let value: serde_json::Value =
        serde_json::from_str(json).context("parse Grafana /api/search body as JSON")?;
    let arr = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Grafana /api/search did not return a JSON array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let title = v
            .get("title")
            .and_then(|t| t.as_str())
            .unwrap_or("<unnamed dashboard>")
            .to_string();
        let uid = match v.get("uid").and_then(|u| u.as_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        out.push(Dashboard { title, uid });
    }
    // Stable order by UID so repeated invocations diff cleanly.
    out.sort_by(|a, b| a.uid.cmp(&b.uid));
    Ok(out)
}

// ── Browser-open helpers ────────────────────────────────────────────

fn open_browser_best_effort() {
    open_url_best_effort(&grafana_home_url());
    open_url_best_effort(&grafana_dashboard_url(DEFAULT_OPEN_DASHBOARD_UID));
}

fn open_url_best_effort(url: &str) {
    // `crate::browser::open_in_best_browser` handles the full
    // Cursor-vs-system dispatch + per-OS fallback + URL-printing
    // fallback. It never panics; its `OpenOutcome` is informational
    // (the eprintln side effects already cover the operator-facing
    // "opened in <X>" line).
    let _outcome: OpenOutcome = open_in_best_browser(url);
}

// ── Probe helpers ───────────────────────────────────────────────────

/// Returns `true` when the given URL responds with HTTP < 500
/// within a 1-second deadline. We accept 401 / 403 (Grafana
/// `/api/health` may require admin on some configs) and 404
/// (zPages root sometimes 404s and serves on `/healthz` instead);
/// the operator-meaningful signal is "is the listener alive."
fn http_probe_ok(url: &str) -> bool {
    let probe = Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "1",
            url,
        ])
        .stdin(Stdio::null())
        .output();
    match probe {
        Ok(o) if o.status.success() => {
            let body = String::from_utf8_lossy(&o.stdout);
            let code: u16 = body.trim().parse().unwrap_or(0);
            (200..500).contains(&code)
        }
        _ => false,
    }
}

// ── Compose-file location ───────────────────────────────────────────

fn find_compose_file() -> Result<PathBuf> {
    // Strategy: walk up from CARGO_MANIFEST_DIR (set by `cargo xtask`)
    // looking for a `live-e2e/docker-compose.e2e.yml`. The xtask is
    // pinned at `raxis/xtask`, so the file is always at
    // `<CARGO_MANIFEST_DIR>/../live-e2e/docker-compose.e2e.yml`.
    // We do not search ancestor `raxis/` directories outside the
    // workspace — a single stable resolution path is enough and
    // avoids surprising behavior on a worktree that happens to be
    // nested in another raxis checkout.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    let candidate = manifest_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("CARGO_MANIFEST_DIR has no parent: {manifest_dir:?}"))?
        .join("live-e2e")
        .join("docker-compose.e2e.yml");
    anyhow::ensure!(
        candidate.exists(),
        "expected live-e2e compose file at {} (CARGO_MANIFEST_DIR={})",
        candidate.display(),
        manifest_dir.display(),
    );
    Ok(candidate)
}

fn find_extended_compose_file() -> Result<PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    let candidate = manifest_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("CARGO_MANIFEST_DIR has no parent: {manifest_dir:?}"))?
        .join("live-e2e")
        .join("docker-compose.extended.e2e.yml");
    anyhow::ensure!(
        candidate.exists(),
        "expected extended live-e2e compose file at {} (CARGO_MANIFEST_DIR={})",
        candidate.display(),
        manifest_dir.display(),
    );
    Ok(candidate)
}

// ── Arg parsing ─────────────────────────────────────────────────────

fn parse_str_flag(args: &[String], flag: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().cloned();
        }
        if let Some(rest) = a.strip_prefix(&format!("{flag}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hard-coded compose project name must match the `name:`
    /// pinned in BOTH compose files. Catches a future rename that
    /// would silently break `cargo xtask observability status` and
    /// the dev-loop env-var docs.
    #[test]
    fn project_name_matches_compose_file() {
        let compose = std::fs::read_to_string(
            std::env::var("CARGO_MANIFEST_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
                .parent()
                .unwrap()
                .join("live-e2e/docker-compose.e2e.yml"),
        )
        .expect("read docker-compose.e2e.yml");
        assert!(
            compose.contains(&format!("name: {COMPOSE_PROJECT}")),
            "compose file must pin `name: {COMPOSE_PROJECT}` to keep the xtask in lock-step",
        );
    }

    #[test]
    fn project_name_matches_extended_compose_file() {
        let path = std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .parent()
            .unwrap()
            .join("live-e2e/docker-compose.extended.e2e.yml");
        if !path.exists() {
            // Extended compose file is optional; ditto the rename
            // invariant for it. Skip rather than fail if missing.
            return;
        }
        let compose = std::fs::read_to_string(&path).expect("read extended compose");
        assert!(
            compose.contains(&format!("name: {COMPOSE_PROJECT}")),
            "extended compose file must pin `name: {COMPOSE_PROJECT}` too",
        );
    }

    #[test]
    fn parse_dashboards_extracts_title_and_uid() {
        let json = r#"[
            {"title":"raxis | 00 Overview","uid":"raxis-00-overview","type":"dash-db"},
            {"title":"raxis | 10 Isolation","uid":"raxis-10-isolation","type":"dash-db"}
        ]"#;
        let parsed = parse_dashboards(json).expect("parse ok");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].uid, "raxis-00-overview");
        assert_eq!(parsed[0].title, "raxis | 00 Overview");
        assert_eq!(parsed[1].uid, "raxis-10-isolation");
    }

    #[test]
    fn parse_dashboards_skips_entry_without_uid() {
        let json = r#"[{"title":"unnamed","type":"dash-db"}]"#;
        let parsed = parse_dashboards(json).expect("parse ok");
        assert!(parsed.is_empty(), "entry without uid must be skipped");
    }

    #[test]
    fn parse_dashboards_rejects_non_array_root() {
        let err = parse_dashboards(r#"{"not":"an array"}"#).unwrap_err();
        assert!(
            err.to_string().contains("did not return a JSON array"),
            "got: {err}"
        );
    }

    fn dashboard_dir() -> PathBuf {
        std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .parent()
            .unwrap()
            .join("observability/grafana/dashboards")
    }

    #[test]
    fn grafana_dashboards_are_valid_json_and_include_otel_pipeline() {
        let mut saw_otel = false;
        for entry in std::fs::read_dir(dashboard_dir()).expect("dashboard dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let body = std::fs::read_to_string(&path).expect("read dashboard json");
            let json: serde_json::Value = serde_json::from_str(&body)
                .unwrap_or_else(|e| panic!("{} must parse as JSON: {e}", path.display()));
            if json.get("uid").and_then(|v| v.as_str()) == Some("raxis-05-otel-pipeline") {
                saw_otel = true;
            }
        }
        assert!(
            saw_otel,
            "observability pusher health card links to raxis-05-otel-pipeline; \
             the provisioned dashboard JSON must exist"
        );
    }

    #[test]
    fn grafana_dashboards_do_not_use_stale_metric_labels() {
        for entry in std::fs::read_dir(dashboard_dir()).expect("dashboard dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let body = std::fs::read_to_string(&path).expect("read dashboard json");
            assert!(
                !body.contains("sum by (kind)")
                    && !body.contains("sum by (kind,")
                    && !body.contains("{{kind}}"),
                "{} uses stale audit label `kind`; kernel emits `event_kind`",
                path.display()
            );
            assert!(
                !body.contains("sum by (lane)")
                    && !body.contains("sum by (lane,")
                    && !body.contains("{{lane}}"),
                "{} uses stale budget label `lane`; kernel emits `lane_id`",
                path.display()
            );
        }
    }

    #[test]
    fn parse_str_flag_supports_space_form() {
        let args = vec![
            "--dashboard".to_string(),
            "raxis-50-credproxies".to_string(),
        ];
        assert_eq!(
            parse_str_flag(&args, "--dashboard").as_deref(),
            Some("raxis-50-credproxies"),
        );
    }

    #[test]
    fn parse_str_flag_supports_equals_form() {
        let args = vec!["--dashboard=raxis-50-credproxies".to_string()];
        assert_eq!(
            parse_str_flag(&args, "--dashboard").as_deref(),
            Some("raxis-50-credproxies"),
        );
    }
}
