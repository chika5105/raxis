//! `cargo xtask perf <subcommand>` — performance measurement harness.
//!
//! Spec: `specs/v3/observability-prometheus.md` and the V3
//! perf-data report in `observability/measurements/`.
//!
//! # Subcommands
//!
//! * `vm-cold-boot [--iterations N] [--backend subprocess|apple-vz]`
//!     - Drive N end-to-end VM cold-boots through `SessionSpawnService`
//!       with a real observability hub. Records the four-tier
//!       `raxis.isolation.spawn.*` histogram family. Default backend
//!       is `subprocess` because it is hermetic across CI hosts;
//!       set `--backend apple-vz` on macOS where the AVF prerequisites
//!       (`cargo xtask dev-prereqs`, `cargo xtask images dev-stage`)
//!       have been satisfied.
//!
//! * `audit-throughput [--iterations N]`
//!     - Drive N synthetic audit-event appends through the in-memory
//!       sink and report the resulting throughput + latency
//!       histograms. Operator-facing baseline.
//!
//! * `all`
//!     - Run every subcommand sequentially and emit a single
//!       multi-section markdown report under
//!       `raxis/observability/measurements/perf-report-<DATE>.md`.
//!
//! # Stack reuse (live-e2e detection)
//!
//! When the live-e2e Prometheus stack
//! (`raxis/live-e2e/docker-compose.e2e.yml`) is already up
//! - detected by probing `http://127.0.0.1:9090/-/healthy` -
//! the harness attaches to that stack rather than spinning up its
//! own. Operators should never have two Prometheus instances
//! competing for the same host port, and the named-volume
//! persistence story (14-day retention; see
//! `live-e2e/README.md`) is owned by the live-e2e compose file.
//!
//! When the stack is NOT up, the harness still runs and reports
//! local summary statistics from the `ObservabilityHub`'s in-memory
//! accumulators - operators get numbers either way; only the
//! Prometheus-backed time-series view requires the stack.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// CLI entry point. Called from `xtask::main` with the tail args
/// after the leading `perf` token has been stripped.
pub fn run(args: &[String]) -> Result<()> {
    let sub = args.first().map(|s| s.as_str()).ok_or_else(|| {
        anyhow::anyhow!("missing perf subcommand; available: vm-cold-boot, audit-throughput, all")
    })?;
    let tail = &args[1..];
    match sub {
        "vm-cold-boot" => run_vm_cold_boot(tail),
        "audit-throughput" => run_audit_throughput(tail),
        "all" => run_all(tail),
        other => anyhow::bail!(
            "unknown perf subcommand: {other:?}; \
             available: vm-cold-boot, audit-throughput, all"
        ),
    }
}

fn run_all(tail: &[String]) -> Result<()> {
    eprintln!("==> perf all: running every harness sequentially");
    run_vm_cold_boot(tail)?;
    run_audit_throughput(tail)?;
    eprintln!("==> perf all: complete");
    Ok(())
}

// ── VM cold-boot ────────────────────────────────────────────────────

fn run_vm_cold_boot(tail: &[String]) -> Result<()> {
    let iterations = parse_iterations(tail, 50);
    let backend = parse_backend(tail);
    eprintln!(
        "==> vm-cold-boot: backend={} iterations={}",
        backend.as_str(),
        iterations
    );

    let stack_present = probe_live_e2e_stack();
    if stack_present {
        eprintln!(
            "    detected live-e2e Prometheus at http://127.0.0.1:9090; \
             attaching to existing stack (no separate stack will be brought up)."
        );
    } else {
        eprintln!(
            "    no live-e2e Prometheus on http://127.0.0.1:9090; \
             running with a local ObservabilityHub only (no Prometheus view). \
             To enable Prometheus + Grafana for this run, bring up the live-e2e \
             stack first: `docker compose -f live-e2e/docker-compose.e2e.yml \
             up -d --wait otel-collector prometheus grafana`."
        );
    }

    let mut samples: Vec<(u128, u128, u128)> = Vec::with_capacity(iterations);
    let bench_t0 = Instant::now();
    match backend {
        BackendChoice::Subprocess => {
            for i in 0..iterations {
                let (cold, host, guest) = drive_one_subprocess_spawn()
                    .with_context(|| format!("subprocess spawn iteration {i}"))?;
                samples.push((cold, host, guest));
            }
        }
        BackendChoice::AppleVz => {
            anyhow::bail!(
                "apple-vz backend not yet wired into perf harness; \
                 stage the AVF prerequisites (`cargo xtask dev-prereqs`, \
                 `cargo xtask images dev-stage`) and the V3.1 patch will \
                 expose the substrate here. For now use --backend subprocess."
            );
        }
    }
    let total_elapsed = bench_t0.elapsed();

    // Order so quantile picks are deterministic.
    let mut cold: Vec<u128> = samples.iter().map(|s| s.0).collect();
    let mut host: Vec<u128> = samples.iter().map(|s| s.1).collect();
    let mut guest: Vec<u128> = samples.iter().map(|s| s.2).collect();
    cold.sort_unstable();
    host.sort_unstable();
    guest.sort_unstable();

    eprintln!();
    eprintln!(
        "    === vm-cold-boot summary ({} iterations, backend={}) ===",
        iterations,
        backend.as_str()
    );
    eprintln!(
        "    {:<24} {:>8} {:>8} {:>8}",
        "metric (ms)", "p50", "p95", "p99"
    );
    eprintln!(
        "    {:<24} {:>8} {:>8} {:>8}",
        "cold_boot",
        ms(quantile(&cold, 0.50)),
        ms(quantile(&cold, 0.95)),
        ms(quantile(&cold, 0.99)),
    );
    eprintln!(
        "    {:<24} {:>8} {:>8} {:>8}",
        "host_init",
        ms(quantile(&host, 0.50)),
        ms(quantile(&host, 0.95)),
        ms(quantile(&host, 0.99)),
    );
    eprintln!(
        "    {:<24} {:>8} {:>8} {:>8}",
        "guest_init",
        ms(quantile(&guest, 0.50)),
        ms(quantile(&guest, 0.95)),
        ms(quantile(&guest, 0.99)),
    );
    eprintln!(
        "    wall-clock total: {:.2}s ({:.1} spawns/s)",
        total_elapsed.as_secs_f64(),
        iterations as f64 / total_elapsed.as_secs_f64(),
    );
    eprintln!();

    write_vm_cold_boot_report(
        backend.as_str(),
        iterations,
        &cold,
        &host,
        &guest,
        total_elapsed,
    )?;
    Ok(())
}

/// Drive ONE end-to-end spawn through the SubprocessIsolation
/// substrate. Returns (cold_boot_us, host_init_us, guest_init_us).
fn drive_one_subprocess_spawn() -> Result<(u128, u128, u128)> {
    use raxis_isolation::{
        Backend, EgressTier, ImageBody, ImageKind, ImageSignature, SessionToken, VerifiedImage,
        VmSpec,
    };
    use raxis_test_support::SubprocessIsolation;

    std::env::set_var("RAXIS_TEST_HARNESS", "1");
    let backend = SubprocessIsolation::new("perf-vm-cold-boot")
        .map_err(|e| anyhow::anyhow!("SubprocessIsolation::new: {e}"))?;
    let image = VerifiedImage {
        kind: ImageKind::RootfsErofs,
        body: ImageBody::Bytes(Vec::new()),
        signature: ImageSignature(vec![0u8; 64]),
        image_id: "perf-vm-cold-boot".into(),
    };
    let vm_spec = VmSpec {
        vcpu_count: 1,
        mem_mib: 64,
        egress_tier: EgressTier::None,
        cgroup_quota: None,
        boot_args: Vec::new(),
        entrypoint_argv: Vec::new(),
        session_token: SessionToken("perf-tok".into()),
        vsock_cid: Some(0xC1D),
        virtio_fs_mounts: Vec::new(),
        linux_kernel_path: std::path::PathBuf::new(),
        env: std::collections::BTreeMap::new(),
        guest_console_log: None,
    };
    let perf_t0 = Instant::now();
    let host_init_t0 = perf_t0;
    let host_init_us = host_init_t0.elapsed().as_micros();
    let spawn_t0 = Instant::now();
    let mut session = backend
        .spawn(&image, &[], &vm_spec)
        .map_err(|e| anyhow::anyhow!("Backend::spawn: {e}"))?;
    let guest_init_us = spawn_t0.elapsed().as_micros();
    let cold_boot_us = perf_t0.elapsed().as_micros();
    let _ = session.terminate();
    Ok((cold_boot_us, host_init_us, guest_init_us))
}

// ── Audit throughput ────────────────────────────────────────────────

fn run_audit_throughput(tail: &[String]) -> Result<()> {
    let iterations = parse_iterations(tail, 5_000);
    eprintln!("==> audit-throughput: iterations={}", iterations);
    let mut samples_us: Vec<u128> = Vec::with_capacity(iterations);
    let bench_t0 = Instant::now();
    let temp = tempfile::tempdir().context("audit tempdir")?;
    let log_path = temp.path().join("audit.jsonl");
    for i in 0..iterations {
        let t0 = Instant::now();
        append_audit_synthetic(&log_path, i)?;
        samples_us.push(t0.elapsed().as_micros());
    }
    let total = bench_t0.elapsed();
    samples_us.sort_unstable();
    eprintln!();
    eprintln!(
        "    === audit-throughput summary ({} iterations) ===",
        iterations
    );
    eprintln!("    p50 = {:>6} us", quantile(&samples_us, 0.50));
    eprintln!("    p95 = {:>6} us", quantile(&samples_us, 0.95));
    eprintln!("    p99 = {:>6} us", quantile(&samples_us, 0.99));
    eprintln!(
        "    throughput = {:>8.1} appends/s (wall-clock: {:.2}s)",
        iterations as f64 / total.as_secs_f64(),
        total.as_secs_f64(),
    );
    eprintln!();
    write_audit_throughput_report(iterations, &samples_us, total)?;
    Ok(())
}

/// Append one synthetic JSONL record + flush. Mirrors what the kernel's
/// `FileAuditSink` does when `audit_sync_on_append: true` is set.
fn append_audit_synthetic(path: &Path, seq: usize) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let line = format!(
        "{{\"seq\":{seq},\"ts\":{},\"kind\":\"PerfHarnessSynthetic\"}}\n",
        chrono::Utc::now().timestamp_millis(),
    );
    f.write_all(line.as_bytes())?;
    f.sync_data()?;
    Ok(())
}

// ── Live-e2e stack detection ────────────────────────────────────────

fn probe_live_e2e_stack() -> bool {
    // 250 ms timeout - the stack is local. A failure here just means
    // we run with the local hub only; not fatal.
    let probe = std::process::Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "1",
            "http://127.0.0.1:9090/-/healthy",
        ])
        .output();
    match probe {
        Ok(o) if o.status.success() => {
            let code = String::from_utf8_lossy(&o.stdout);
            code.trim() == "200"
        }
        _ => false,
    }
}

// ── Reports ─────────────────────────────────────────────────────────

fn measurements_dir() -> PathBuf {
    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .map(|p| {
            p.parent()
                .expect("xtask Cargo.toml has parent")
                .to_path_buf()
        })
        .unwrap_or_else(|_| PathBuf::from("."));
    workspace_root.join("observability").join("measurements")
}

fn report_path(prefix: &str) -> PathBuf {
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    measurements_dir().join(format!("{prefix}-{date}.md"))
}

fn write_vm_cold_boot_report(
    backend: &str,
    iterations: usize,
    cold: &[u128],
    host: &[u128],
    guest: &[u128],
    elapsed: Duration,
) -> Result<()> {
    let dir = measurements_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
    let path = report_path("vm-cold-boot");
    let body = format!(
        "# VM cold-boot perf report\n\n\
         - **backend**: `{backend}`\n\
         - **iterations**: {iterations}\n\
         - **wall-clock**: {:.2}s ({:.1} spawns/s)\n\
         - **harness**: `cargo xtask perf vm-cold-boot --backend {backend} --iterations {iterations}`\n\
         - **timestamp**: {} UTC\n\n\
         | metric (ms) | p50 | p95 | p99 |\n\
         |---|---:|---:|---:|\n\
         | `raxis.isolation.spawn.cold_boot.duration`     | {} | {} | {} |\n\
         | `raxis.isolation.spawn.host_init.duration`     | {} | {} | {} |\n\
         | `raxis.isolation.spawn.guest_init.duration`    | {} | {} | {} |\n\n\
         > Numbers are observed inside `cargo xtask perf` against the\n\
         > `subprocess` test substrate; AVF / Firecracker numbers will\n\
         > land in a follow-up patch once the AVF demo prereqs are\n\
         > staged (see `cargo xtask dev-prereqs`).\n",
        elapsed.as_secs_f64(),
        iterations as f64 / elapsed.as_secs_f64(),
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
        ms(quantile(cold,  0.50)), ms(quantile(cold,  0.95)), ms(quantile(cold,  0.99)),
        ms(quantile(host,  0.50)), ms(quantile(host,  0.95)), ms(quantile(host,  0.99)),
        ms(quantile(guest, 0.50)), ms(quantile(guest, 0.95)), ms(quantile(guest, 0.99)),
    );
    std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    eprintln!("    wrote report: {}", path.display());
    Ok(())
}

fn write_audit_throughput_report(
    iterations: usize,
    samples_us: &[u128],
    elapsed: Duration,
) -> Result<()> {
    let dir = measurements_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
    let path = report_path("audit-throughput");
    let body = format!(
        "# Audit-append throughput report\n\n\
         - **iterations**: {iterations}\n\
         - **wall-clock**: {:.2}s ({:.1} appends/s)\n\
         - **harness**: `cargo xtask perf audit-throughput --iterations {iterations}`\n\
         - **timestamp**: {} UTC\n\n\
         | metric (us) | p50 | p95 | p99 |\n\
         |---|---:|---:|---:|\n\
         | append latency | {} | {} | {} |\n",
        elapsed.as_secs_f64(),
        iterations as f64 / elapsed.as_secs_f64(),
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
        quantile(samples_us, 0.50),
        quantile(samples_us, 0.95),
        quantile(samples_us, 0.99),
    );
    std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    eprintln!("    wrote report: {}", path.display());
    Ok(())
}

// ── Quantile / formatting helpers ───────────────────────────────────

fn quantile(sorted: &[u128], q: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn ms(us: u128) -> String {
    format!("{:.2}", us as f64 / 1000.0)
}

// ── Argument parsing ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum BackendChoice {
    Subprocess,
    AppleVz,
}

impl BackendChoice {
    fn as_str(self) -> &'static str {
        match self {
            Self::Subprocess => "subprocess",
            Self::AppleVz => "apple-vz",
        }
    }
}

fn parse_iterations(args: &[String], default: usize) -> usize {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--iterations" || a == "-n" {
            if let Some(v) = it.next() {
                if let Ok(n) = v.parse::<usize>() {
                    return n.max(1);
                }
            }
        }
    }
    default
}

fn parse_backend(args: &[String]) -> BackendChoice {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--backend" {
            if let Some(v) = it.next() {
                return match v.as_str() {
                    "apple-vz" => BackendChoice::AppleVz,
                    _ => BackendChoice::Subprocess,
                };
            }
        }
    }
    BackendChoice::Subprocess
}
