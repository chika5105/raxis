//! Generic kernel-driver helpers for `RAXIS_LIVE_E2E=1` tests.
//!
//! Mirrors the inline helpers in
//! `extended_e2e_concurrent_lifecycle.rs` but parametrised over
//! the plan-toml builder so multiple `live-e2e` tests can share
//! the same bootstrap / IPC / polling pipeline without
//! duplicating ~700 lines of infrastructure.
//!
//! The existing extended-scenario test continues to use its own
//! inline helpers (deliberately — refactoring them in lockstep
//! would couple two unrelated tests together). New tests
//! (`extended_e2e_realistic_scenario.rs`, future realism
//! follow-ups) call into THIS module instead.
//!
//! Every function panics on failure rather than returning a
//! `Result` — the call sites are test-only and a panic surfaces
//! more cleanly through `cargo test` than a `Result<()>` rip-tide.

#![allow(dead_code)]

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use raxis_audit_tools::{verify_chain_full, AuditEvent, AuditEventKind, ChainReader};
use raxis_crypto::{
    bundle_sha256 as crypto_bundle_sha256, canonical_encode, mint_bundle_nonce,
    sha256_of_artifact_bytes, signing_input,
};
use raxis_ipc::{read_json_frame_raw, write_json_frame};
use raxis_test_support::{ephemeral_cert_with_key, CertOpts};
use raxis_types::{BundleArtifact, OperatorFingerprint, PlanBundle};
use serde_json::Value;
use sha2::{Digest, Sha256};

// `crate::common` is the sibling `mod common;` each test binary
// (`extended_e2e_concurrent_lifecycle.rs`,
// `extended_e2e_realistic_scenario.rs`, …) declares at its root.
// Both test binaries that pull this module in must `mod common;`
// alongside `mod extended_e2e_support;`.
use super::harness_timeout::{run_command_output_timeout, BoundedWaitError};
use super::witnesses::typed;
use crate::common::kernel_harness::{build_and_locate_kernel, KernelInstance};

pub const LIVE_E2E_GATE: &str = "RAXIS_LIVE_E2E";
pub const READY_DEADLINE: Duration = Duration::from_secs(15);
pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(60);

/// Distinct seed from the extended scenario's `[0xCE; 32]` so
/// the two live-e2e tests can be run back-to-back without
/// cross-contaminating operator identity in audit attribution.
pub const REALISTIC_OPERATOR_SEED: [u8; 32] = [0xD0; 32];

/// Operator override: absolute path to a pre-built `raxis-gateway`.
/// Default live-e2e runs still auto-build the workspace release
/// gateway first so stale target binaries do not sneak into policy.
pub const ENV_GATEWAY_BINARY: &str = "RAXIS_GATEWAY_BINARY";

/// Set to `1` only for packaged/system-install validation where the
/// harness must not invoke cargo. Normal source-tree e2e runs should
/// leave this unset so the gateway is rebuilt before policy injection.
pub const ENV_SKIP_GATEWAY_AUTO_BUILD: &str = "RAXIS_E2E_SKIP_GATEWAY_AUTO_BUILD";

/// Optional bounded-wait override for
/// `cargo build --release -p raxis-gateway`.
pub const ENV_GATEWAY_BUILD_TIMEOUT_SECS: &str = "RAXIS_E2E_GATEWAY_BUILD_TIMEOUT_SECS";

pub const DEFAULT_GATEWAY_BUILD_TIMEOUT_SECS: u64 = 300;
pub const MIN_GATEWAY_BUILD_TIMEOUT_SECS: u64 = 60;
pub const MAX_GATEWAY_BUILD_TIMEOUT_SECS: u64 = 900;

// ---------------------------------------------------------------------------
// Preflight — every external dependency reachable before we
// bother bootstrapping a kernel.
// ---------------------------------------------------------------------------

pub fn require_tcp_reachable(host_port: &str, what: &str) {
    if std::net::TcpStream::connect_timeout(
        &host_port.parse().expect("static literal parses"),
        Duration::from_millis(500),
    )
    .is_err()
    {
        panic!(
            "{what} not reachable at {host_port}. Run:\n  \
             docker compose -f live-e2e/docker-compose.extended.e2e.yml up -d --wait",
        );
    }
}

pub fn require_anthropic_dev_key() {
    let env_path = workspace_dotenv_path();
    let body = std::fs::read_to_string(&env_path).unwrap_or_else(|e| {
        panic!(
            "{} is required for the live LLM round-trip but read failed: {e}\n\
         Create it with one line:\n  ANTHROPIC-API-DEV-KEY=sk-ant-...",
            env_path.display(),
        )
    });
    let has_key = body.lines().any(|l| {
        l.starts_with("ANTHROPIC-API-DEV-KEY=") && l.len() > "ANTHROPIC-API-DEV-KEY=".len()
    });
    assert!(
        has_key,
        "{} must contain a non-empty ANTHROPIC-API-DEV-KEY=... line",
        env_path.display(),
    );
}

pub fn require_gcp_adc() {
    let adc = match dirs_home() {
        Some(h) => h.join(".config/gcloud/application_default_credentials.json"),
        None => panic!("HOME is unset; cannot locate gcloud ADC"),
    };
    assert!(
        adc.exists(),
        "GCP application default credentials not found at {}.\n\
         Run: gcloud auth application-default login",
        adc.display(),
    );
}

pub fn require_gateway_binary() -> PathBuf {
    static GATEWAY_BINARY: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    GATEWAY_BINARY.get_or_init(resolve_gateway_binary).clone()
}

fn resolve_gateway_binary() -> PathBuf {
    let workspace = realism_workspace_root();
    if !env_flag(ENV_SKIP_GATEWAY_AUTO_BUILD) {
        return run_cargo_build_gateway_or_panic(&workspace);
    }
    locate_existing_gateway_binary(&workspace).unwrap_or_else(|| {
        panic!(
            "{ENV_SKIP_GATEWAY_AUTO_BUILD}=1 was set, but no gateway binary \
             was found.\n\
             Remediation:\n  \
             * unset {ENV_SKIP_GATEWAY_AUTO_BUILD} and let live-e2e run:\n      \
               cargo build --release -p raxis-gateway\n  \
             * or set {ENV_GATEWAY_BINARY}=/absolute/path/to/raxis-gateway\n  \
             * or build it manually at target/release/raxis-gateway",
        )
    })
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn gateway_build_timeout() -> Duration {
    let raw = std::env::var(ENV_GATEWAY_BUILD_TIMEOUT_SECS)
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    gateway_build_timeout_from_raw(raw)
}

fn gateway_build_timeout_from_raw(raw: Option<u64>) -> Duration {
    match raw {
        Some(v)
            if (MIN_GATEWAY_BUILD_TIMEOUT_SECS..=MAX_GATEWAY_BUILD_TIMEOUT_SECS).contains(&v) =>
        {
            Duration::from_secs(v)
        }
        _ => Duration::from_secs(DEFAULT_GATEWAY_BUILD_TIMEOUT_SECS),
    }
}

fn convention_gateway_paths(workspace_root: &Path) -> Vec<PathBuf> {
    let mut out = vec![
        workspace_root
            .join("target")
            .join("release")
            .join("raxis-gateway"),
        workspace_root
            .join("target")
            .join("debug")
            .join("raxis-gateway"),
    ];
    if let Ok(raw) = std::env::var("RAXIS_INSTALL_DIR") {
        out.push(PathBuf::from(raw).join("bin").join("raxis-gateway"));
    }
    out
}

fn locate_existing_gateway_binary(workspace_root: &Path) -> Option<PathBuf> {
    if let Ok(raw) = std::env::var(ENV_GATEWAY_BINARY) {
        let p = PathBuf::from(&raw);
        assert!(
            p.is_absolute(),
            "{ENV_GATEWAY_BINARY} must be absolute; got {raw:?}"
        );
        if p.is_file() {
            return Some(p);
        }
        panic!("{ENV_GATEWAY_BINARY}={raw:?} does not exist or is not a file");
    }
    convention_gateway_paths(workspace_root)
        .into_iter()
        .find(|p| p.is_file())
}

fn run_cargo_build_gateway_or_panic(workspace_root: &Path) -> PathBuf {
    let timeout = gateway_build_timeout();
    eprintln!(
        "[realism-e2e] gateway: building latest release gateway with \
         `cargo build --release -p raxis-gateway` in {} \
         (bounded by {ENV_GATEWAY_BUILD_TIMEOUT_SECS}={}s). \
         Set {ENV_SKIP_GATEWAY_AUTO_BUILD}=1 only for packaged binary tests.",
        workspace_root.display(),
        timeout.as_secs(),
    );
    let started = Instant::now();
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--release")
        .arg("-p")
        .arg("raxis-gateway")
        .current_dir(workspace_root);
    match run_command_output_timeout(&mut cmd, timeout, "cargo-build-raxis-gateway") {
        Ok(out) if out.status.success() => {
            eprintln!(
                "[realism-e2e] gateway: cargo build --release -p raxis-gateway OK in {:.1}s",
                started.elapsed().as_secs_f32(),
            );
            let bin = workspace_root
                .join("target")
                .join("release")
                .join("raxis-gateway");
            assert!(
                bin.is_file(),
                "cargo reported success but {} is not a file",
                bin.display(),
            );
            bin
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            panic!(
                "`cargo build --release -p raxis-gateway` exited {:?} \
                 after {:.1}s.\n--- stdout ---\n{}\n--- stderr ---\n{}\n\
                 Remediation: fix the gateway build or set \
                 {ENV_SKIP_GATEWAY_AUTO_BUILD}=1 with {ENV_GATEWAY_BINARY}=/absolute/path/to/a \
                 known-good packaged gateway.",
                out.status.code(),
                started.elapsed().as_secs_f32(),
                stdout,
                stderr,
            );
        }
        Err(BoundedWaitError::SpawnFailed { reason, .. }) => {
            panic!(
                "cannot spawn `cargo` to build raxis-gateway: {reason}.\n\
                 Remediation: install Rust + cargo, or set \
                 {ENV_SKIP_GATEWAY_AUTO_BUILD}=1 and \
                 {ENV_GATEWAY_BINARY}=/absolute/path/to/raxis-gateway."
            );
        }
        Err(BoundedWaitError::Timeout { timeout, .. }) => {
            panic!(
                "`cargo build --release -p raxis-gateway` exceeded {timeout:?}; \
                 the child was killed. Override with \
                 {ENV_GATEWAY_BUILD_TIMEOUT_SECS}=<seconds> up to \
                 {MAX_GATEWAY_BUILD_TIMEOUT_SECS}, or prebuild and set \
                 {ENV_SKIP_GATEWAY_AUTO_BUILD}=1 plus {ENV_GATEWAY_BINARY}."
            );
        }
        Err(other) => panic!("gateway auto-build wrapper failed: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Host disk-pressure preflight (INV-HOST-HYGIENE-01).
//
// Mirrors the `cargo xtask hygiene-check --threshold-pct 90` probe
// inline so the live-e2e harness never blocks on a `cargo run`
// rebuild of the xtask binary mid-test. Converts what was a 31-min
// mid-flight `DiskFullHaltEntered` (iter 16, 1867 s, every
// activation rejected with `FailDiskFull`) into a sub-second
// preflight skip.
//
// On detected pressure, the preflight builds a typed
// `raxis_types::HostPreflightError::DiskPressure` and:
//   1. Prints one stable-prefixed line to stderr —
//      `OPERATOR_ATTENTION_REQUIRED HostHygieneDiskPressure {json}`
//      — for harness / terminal / CI-log consumers. This is the
//      only surface for the host-hygiene signal; it is a
//      developer-/CI-host concern and is deliberately not routed
//      to the operator dashboard or the kernel's audit chain
//      (see `INV-HOST-HYGIENE-01` scope clause and
//      `dashboard-hardening.md §5.7`).
//   2. Panics with the structured `Display` rendering, which
//      surfaces the offending volume + remediation command in the
//      `cargo test` failure summary so a developer who never
//      reads stderr still sees the right next step.
// ---------------------------------------------------------------------------

/// Stable stderr prefix consumed by the live-e2e harness, the
/// developer's terminal, and CI log scrapers when the preflight
/// detects host disk pressure. The kernel itself does not emit a
/// `HostHygieneDiskPressure` audit event — this envelope is the
/// single surface for the dev-host signal.
pub const HOST_PREFLIGHT_LOG_PREFIX: &str = "OPERATOR_ATTENTION_REQUIRED";

/// Host disk-pressure preflight — see module docs above. Panics on
/// detected pressure with a structured `HostPreflightError::DiskPressure`
/// rendering. Returns silently when the host is clear.
pub fn require_disk_hygiene() {
    require_disk_hygiene_with_threshold(90);
}

/// `INV-PLANNER-IPC-IDLE-WATCHDOG-01` test-side companion — reap
/// orphaned Apple Virtualization.framework VM XPC processes left
/// behind by a prior SIGKILL'd kernel run.
///
/// **Why this lives in the test harness, not the kernel.** Production
/// kernels DO NOT kill arbitrary AVF VMs at boot because the host may
/// be running a parallel Virtualization-framework consumer
/// (xcrun simctl, a coworker's VM, a desktop emulator). In a live
/// e2e run the host is dedicated and any AVF VM XPC alive at the
/// start of a test is by definition an orphan from a previous run —
/// the previous kernel was SIGKILL'd and its VMs survived as
/// launchd-rooted XPCs that retain vsock CIDs and virtiofs daemon
/// handles. Those leftovers race against fresh kernel spawns and
/// produce the iter71/iter72 stall pattern documented in
/// `specs/v2/planner-ipc-idle-watchdog.md §1.1`.
///
/// Operators can opt their production kernel into the same reaper
/// via `RAXIS_BOOT_REAP_AVF_ORPHANS=1` (TODO — not yet wired into
/// the kernel binary; tracked alongside this helper for symmetry).
///
/// **Co-tenant VMM exclusion.** The Virtualization.framework XPC
/// binary (`com.apple.Virtualization.VirtualMachine.xpc`) is shared
/// by every framework consumer on the host — including Docker
/// Desktop (`com.docker.virtualization`), Xcode simulators, and any
/// other developer-tool VMM. Killing those XPCs out from under their
/// parent VMM crashes that VMM ("Internal Virtualization error.
/// The virtual machine stopped unexpectedly."), which on a dev host
/// running iter73 manifests as the live-e2e Docker compose stack
/// becoming unreachable within ~30 s of the reaper firing. We
/// therefore walk each candidate XPC's ancestry and skip any whose
/// parent chain leads back to a known co-tenant VMM, only reaping
/// XPCs that are either parented to launchd directly (true orphans
/// from a SIGKILL'd raxis-kernel) or descended from a `raxis-*`
/// process. iter73 regression — see `specs/v3/avf-orphan-reaper-cotenant-skip.md`.
///
/// On non-macOS hosts this is a no-op.
pub fn reap_avf_orphan_vms() {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        // List all com.apple.Virtualization.VirtualMachine.xpc
        // processes. `pgrep -f` matches against the full command
        // line, which is what we want because AVF VM XPCs all share
        // the same binary path.
        const NEEDLE: &str = "com.apple.Virtualization.VirtualMachine.xpc";
        let pgrep = match Command::new("/usr/bin/pgrep").args(["-f", NEEDLE]).output() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("[realism-e2e] AVF-orphan reaper: pgrep unavailable ({e}); skipping",);
                return;
            }
        };
        if !pgrep.status.success() {
            // No matches is a non-zero exit; treat as "nothing to
            // do" not "broken host".
            eprintln!("[realism-e2e] AVF-orphan reaper: no orphan VMs found");
            return;
        }
        let mut candidate_pids: Vec<u32> = Vec::new();
        for line in String::from_utf8_lossy(&pgrep.stdout).lines() {
            if let Ok(pid) = line.trim().parse::<u32>() {
                candidate_pids.push(pid);
            }
        }
        if candidate_pids.is_empty() {
            return;
        }

        // Partition into (orphan, cotenant) by walking each XPC's
        // ancestry. An XPC is a true orphan iff its parent chain
        // does NOT pass through any of the known cotenant VMMs
        // before terminating at launchd (pid 1).
        let mut pids: Vec<u32> = Vec::new();
        let mut skipped: Vec<(u32, String)> = Vec::new();
        for &pid in &candidate_pids {
            match ancestor_cotenant_vmm_macos(pid) {
                Some(owner) => skipped.push((pid, owner)),
                None => pids.push(pid),
            }
        }
        if !skipped.is_empty() {
            eprintln!(
                "[realism-e2e] AVF-orphan reaper: skipped {} co-tenant VM XPC \
                 process(es) owned by other VMMs (skipped={skipped:?})",
                skipped.len(),
            );
        }
        if pids.is_empty() {
            eprintln!(
                "[realism-e2e] AVF-orphan reaper: no raxis-attributable \
                 orphan VMs found ({} candidate(s) all belonged to co-tenant \
                 VMMs)",
                candidate_pids.len(),
            );
            return;
        }
        eprintln!(
            "[realism-e2e] AVF-orphan reaper: found {} orphan VM XPC \
             process(es) (pids={pids:?}); sending SIGKILL",
            pids.len(),
        );
        for pid in &pids {
            let _ = Command::new("/bin/kill")
                .args(["-KILL", &pid.to_string()])
                .status();
        }
        // Give launchd a moment to reap.
        std::thread::sleep(std::time::Duration::from_secs(2));
        // Verify they're gone — log a warn if any survived so the
        // operator can investigate manually rather than have the
        // test silently fail later.
        let verify = Command::new("/usr/bin/pgrep")
            .args(["-f", NEEDLE])
            .output()
            .ok();
        if let Some(v) = verify {
            if v.status.success() {
                // Re-apply the co-tenant filter so we only WARN
                // about XPCs that we actually tried to kill but
                // failed — co-tenant VMMs (Docker, etc.) are
                // expected to still be running.
                let surviving: Vec<u32> = String::from_utf8_lossy(&v.stdout)
                    .lines()
                    .filter_map(|s| s.trim().parse::<u32>().ok())
                    .filter(|pid| ancestor_cotenant_vmm_macos(*pid).is_none())
                    .collect();
                if !surviving.is_empty() {
                    eprintln!(
                        "[realism-e2e] AVF-orphan reaper: WARNING — \
                         {} orphan VM XPC process(es) survived SIGKILL \
                         (pids={surviving:?}); the test may stall on a \
                         vsock CID collision. Run `sudo killall -KILL \
                         com.apple.Virtualization.VirtualMachine.xpc` \
                         manually.",
                        surviving.len(),
                    );
                }
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Firecracker on Linux uses regular processes parented to
        // the spawning kernel; SIGKILL'ing the kernel reaps them
        // through the normal kernel-side `wait4` path. No orphan
        // class equivalent to AVF XPC has been observed on Linux.
    }
}

/// Identifies the co-tenant VMM (if any) that "owns" an
/// AVF `com.apple.Virtualization.VirtualMachine.xpc` process by
/// inspecting the files it has open.
///
/// Returns `Some(owner_label)` if `pid`'s open-file set contains a
/// path fragment that uniquely identifies a known co-tenant VMM's
/// disk image, kernel image, or boot image; or `None` when no
/// match — which is the signature of a raxis-attributable AVF
/// orphan.
///
/// **Why open files, not the parent chain.** macOS XPC services
/// are launched via `xpcproxy`/launchd, so the AVF VM XPC is
/// **always** parented to launchd (pid 1) regardless of who
/// requested it. Walking ppid is therefore useless: Docker's XPC
/// and a SIGKILL'd-raxis-kernel's leftover XPC are both
/// indistinguishable parent-chain-wise. The actual disk and boot
/// images opened by the XPC, however, live under VMM-private
/// directories (e.g. `Library/Containers/com.docker.docker/` for
/// Docker Desktop) and are visible to `lsof -p`.
///
/// The needle list is intentionally narrow: we only suppress
/// reaping for VMMs we have actually observed colliding with
/// iter73 on developer hosts. Adding a new cotenant should require
/// a fresh regression report — see
/// `specs/v3/avf-orphan-reaper-cotenant-skip.md`.
#[cfg(target_os = "macos")]
fn ancestor_cotenant_vmm_macos(pid: u32) -> Option<String> {
    use std::process::Command;
    // Substrings that uniquely identify a co-tenant VMM's
    // private disk/boot artefacts. Matching on file paths instead
    // of process metadata is robust against XPC re-parenting.
    const COTENANT_PATH_NEEDLES: &[(&str, &str)] = &[
        ("/Library/Containers/com.docker.docker/", "docker-desktop"),
        ("/Applications/Docker.app/", "docker-desktop"),
        ("/Library/Developer/CoreSimulator/", "xcode-simulator"),
        (
            "/Applications/Xcode.app/Contents/Developer/Platforms/",
            "xcode-simulator",
        ),
        ("/Applications/Tart.app/", "tart"),
        ("/Library/Application Support/com.utmapp.UTM/", "utm"),
        ("/Applications/OrbStack.app/", "orbstack"),
        // ColIma/Lima/podman-machine use AVF too; their VM images
        // live under ~/.lima or ~/.colima.
        ("/.lima/", "lima"),
        ("/.colima/", "colima"),
    ];
    let lsof = match Command::new("/usr/sbin/lsof")
        // -p PID, -F n = field-mode names only (one per line),
        // -a = AND the filters, -d ^cwd,^rtd,^txt = skip the
        // working-dir / root-dir / text segment so we don't
        // false-positive on a Docker VM that opened
        // /Applications/Docker.app as its CWD.
        .args(["-p", &pid.to_string(), "-Fn"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return None,
    };
    // lsof exits non-zero when the pid has no matching fds or has
    // died between pgrep and lsof — both cases we treat as "no
    // discriminating info" and fall through to None so the caller
    // applies its normal reap policy.
    let stdout = String::from_utf8_lossy(&lsof.stdout);
    for line in stdout.lines() {
        // -Fn produces lines like "n/path/to/file"; skip header
        // lines starting with 'p' (pid) or 'c' (command).
        let path = match line.strip_prefix('n') {
            Some(p) => p,
            None => continue,
        };
        for (needle, owner) in COTENANT_PATH_NEEDLES {
            if path.contains(needle) {
                return Some((*owner).to_owned());
            }
        }
    }
    None
}

/// Underlying probe — split out so unit tests can drive it with a
/// 0% threshold against the live host (which always exceeds 0%).
pub fn require_disk_hygiene_with_threshold(threshold_pct: u32) {
    let report = probe_disk_pressure(threshold_pct);
    let over_threshold: Vec<&raxis_types::DiskVolumeReport> = report
        .iter()
        .filter(|v| v.used_pct >= threshold_pct)
        .collect();
    if over_threshold.is_empty() {
        eprintln!(
            "[realism-e2e] preflight: host disk hygiene clear ({} volumes below {threshold_pct}%)",
            report.len(),
        );
        return;
    }
    let err = raxis_types::HostPreflightError::disk_pressure(threshold_pct, report);
    emit_operator_attention_to_stderr(&err);
    panic!("{err}");
}

/// Returns one [`DiskVolumeReport`] per unique mount across the
/// repo volume, `/private/tmp`, and every `/var/folders/*` (AVF
/// guest dir). De-duped by the `Mounted on` column so a single
/// physical volume backing several monitored paths is reported
/// once.
///
/// Probe-failure handling: when `df` itself fails unexpectedly on
/// a path that exists (command spawn error, non-zero exit,
/// unparseable output), emit a structured stderr line so the
/// developer sees that the hygiene probe could NOT measure that
/// volume — silently dropping the probe would let a host with a
/// broken mount pass the preflight even though we have no
/// evidence it has free space. Paths that simply do not exist
/// (`/private/tmp` on a minimal CI image, `/var/folders` outside
/// macOS) are still skipped silently — they're optional inputs.
fn probe_disk_pressure(_threshold_pct: u32) -> Vec<raxis_types::DiskVolumeReport> {
    let repo_root = workspace_repo_root();
    let mut targets: Vec<PathBuf> = vec![repo_root, PathBuf::from("/private/tmp")];
    if let Ok(read_dir) = std::fs::read_dir("/var/folders") {
        for entry in read_dir.flatten() {
            let p = entry.path();
            if p.is_dir() {
                targets.push(p);
            }
        }
    }
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<raxis_types::DiskVolumeReport> = Vec::new();
    for t in targets {
        if !t.exists() {
            continue;
        }
        match df_mount_and_pct(&t) {
            Ok((mount, used_pct, free_kb)) => {
                if !seen.insert(mount.clone()) {
                    continue;
                }
                out.push(raxis_types::DiskVolumeReport {
                    mount,
                    used_pct,
                    free_human: human_bytes(free_kb.saturating_mul(1024)),
                });
            }
            Err(reason) => {
                eprintln!(
                    "{HOST_PREFLIGHT_LOG_PREFIX} HostHygieneDiskProbeFailed \
                     {{\"path\":{path_json},\"reason\":{reason_json}}}",
                    path_json = serde_json::to_string(&t.to_string_lossy())
                        .unwrap_or_else(|_| "\"<unserialisable>\"".to_owned()),
                    reason_json = serde_json::to_string(&reason)
                        .unwrap_or_else(|_| "\"<unserialisable>\"".to_owned()),
                );
            }
        }
    }
    out
}

/// Emit the structured payload to stderr with the
/// `OPERATOR_ATTENTION_REQUIRED HostHygieneDiskPressure {json}`
/// envelope. This is the only surface for the dev-host
/// hygiene signal — see `INV-HOST-HYGIENE-01` scope clause and
/// `dashboard-hardening.md §5.7`. The envelope is consumed by
/// the harness, the developer's terminal, and CI log scrapers;
/// it is deliberately not routed to the kernel audit chain or
/// the operator dashboard (those are reserved for kernel
/// runtime invariants).
pub fn emit_operator_attention_to_stderr(err: &raxis_types::HostPreflightError) {
    eprintln!(
        "{HOST_PREFLIGHT_LOG_PREFIX} {} {}",
        raxis_types::HostPreflightError::ATTENTION_KIND,
        err.to_envelope_json(),
    );
}

fn df_mount_and_pct(target: &Path) -> Result<(String, u32, u64), String> {
    let out = std::process::Command::new("df")
        .args(["-Pk", &target.to_string_lossy()])
        .output()
        .map_err(|e| format!("spawn df: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "df exit={:?}: {}",
            out.status.code(),
            stderr.trim()
        ));
    }
    let body = String::from_utf8_lossy(&out.stdout);
    let line = body
        .lines()
        .nth(1)
        .ok_or_else(|| "df output had fewer than 2 lines".to_owned())?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 6 {
        return Err(format!(
            "df output had {} fields (expected ≥6): {line:?}",
            fields.len()
        ));
    }
    let avail_kb: u64 = fields[3]
        .parse()
        .map_err(|e| format!("parse avail_kb {:?}: {e}", fields[3]))?;
    let used_pct: u32 = fields[4]
        .trim_end_matches('%')
        .parse()
        .map_err(|e| format!("parse used_pct {:?}: {e}", fields[4]))?;
    let mount = fields[5..].join(" ");
    Ok((mount, used_pct, avail_kb))
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut idx = 0;
    while v >= 1024.0 && idx < UNITS.len() - 1 {
        v /= 1024.0;
        idx += 1;
    }
    format!("{v:.1}{}", UNITS[idx])
}

fn workspace_repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if p.join(".git").exists() {
            return p;
        }
        if !p.pop() {
            return PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        }
    }
}

#[cfg(test)]
mod hygiene_preflight_tests {
    use super::*;
    use raxis_types::HostPreflightError;

    /// Synthetic-fixture probe: assert the structured JSON the
    /// preflight prints to stderr is byte-identical to the
    /// stderr-envelope wire shape harness / CI-log consumers
    /// scrape. Pinning the JSON shape here catches a serde-rename
    /// or field-rename break before downstream consumers find
    /// out via a silent envelope.
    #[test]
    fn synthesised_disk_pressure_round_trips_to_attention_envelope() {
        let err = HostPreflightError::disk_pressure(
            90,
            vec![raxis_types::DiskVolumeReport {
                mount: "/System/Volumes/Data".into(),
                used_pct: 92,
                free_human: "64.0GiB".into(),
            }],
        );
        let json = err.to_envelope_json();
        assert!(
            json.contains("\"pressure_kind\":\"DiskPressure\""),
            "envelope consumers would miss the event without the tag: {json}"
        );
        assert!(
            json.contains("/System/Volumes/Data"),
            "offending volume missing from JSON: {json}"
        );
        // `Display` impl pins the developer-facing one-liner that
        // lands in the panic message AND the `cargo test`
        // failure summary.
        let rendered = format!("{err}");
        assert!(rendered.contains("Run `cargo xtask hygiene` to remediate"));
        assert!(rendered.contains("/System/Volumes/Data at 92%"));
    }

    /// `ATTENTION_KIND` is the stderr-envelope filter string the
    /// harness / CI log scraper match on. Pin it here so a future
    /// `HostPreflightError` rename cannot silently disconnect the
    /// envelope from the consumers without flagging this test.
    #[test]
    fn attention_kind_is_stable_for_envelope_consumers() {
        assert_eq!(
            HostPreflightError::ATTENTION_KIND,
            "HostHygieneDiskPressure"
        );
    }

    /// The preflight returns silently when the host is clear; we
    /// drive it with a synthetic 100% threshold so the assertion
    /// holds regardless of the live-host disk usage at test time.
    #[test]
    fn clear_host_returns_silently_under_high_threshold() {
        // Threshold of 100 means "panic only if a volume is at
        // 100% used" — vanishingly rare in practice, so this
        // exercises the no-op happy path.
        require_disk_hygiene_with_threshold(100);
    }
}

pub fn require_canonical_images() {
    let install_dir_raw = std::env::var("RAXIS_INSTALL_DIR")
        .unwrap_or_else(|_| panic!("RAXIS_INSTALL_DIR env var is required",));
    let install_dir = PathBuf::from(&install_dir_raw);
    let kernel_version = env!("CARGO_PKG_VERSION");

    // Auto-bake: if the canonical images are missing or are stub
    // builds (no `/bin/bash` etc.), drive the full xtask pipeline
    // (`bake-rootfs → dev-stage → build-all`) so the live-e2e harness
    // is self-contained on a fresh dev host. Idempotent: re-runs
    // skip every role whose .img already passes the cpio preflight.
    //
    // Opt-out via `RAXIS_LIVE_E2E_SKIP_AUTO_BAKE=1` for operators
    // who manage canonical images themselves (e.g. CI machines that
    // pre-populate `RAXIS_INSTALL_DIR` from a packaged tarball and
    // do NOT have docker / podman / buildah on the host).
    if std::env::var("RAXIS_LIVE_E2E_SKIP_AUTO_BAKE").is_err() {
        ensure_canonical_images_baked(&install_dir, kernel_version);
        // INV-LIVE-E2E-VMLINUX-PRESENT-01 (auto-stage): the AVF /
        // Firecracker substrates resolve their boot kernel from
        // `<install_dir>/kernel/vmlinux` via
        // `canonical_images_preflight::linux_kernel_path`. Without
        // this file, the FIRST orchestrator session-spawn surfaces
        // `AVF VM start failed: Invalid virtual machine
        // configuration. The boot loader is invalid.` 2 seconds
        // into the run — symptom is fatal but the diagnostic only
        // points the operator at the substrate, never at the
        // missing canonical asset. Stage it during auto-bake so
        // `RAXIS_INSTALL_DIR=$(mktemp -d)` is sufficient setup
        // (matching the auto-bake contract for the rootfs images).
        ensure_canonical_kernel_binary_staged(&install_dir);
    }

    for role in &["orchestrator-core", "executor-starter", "reviewer-core"] {
        let img = install_dir
            .join("images")
            .join(format!("raxis-{role}-{kernel_version}.img"));
        let manifest = install_dir
            .join("images")
            .join(format!("raxis-{role}-{kernel_version}.manifest.toml"));
        assert!(img.exists(), "missing canonical image {}", img.display());
        assert!(
            manifest.exists(),
            "missing canonical manifest {}",
            manifest.display()
        );

        // ── Cpio content preflight ────────────────────────────────
        //
        // Iter-12 surfaced canonical-image stub regression: the
        // manifest verified, the file existed, but the cpio
        // contained nothing but the cross-compiled planner binary.
        // `BashTool` returned `ENOENT` for every command the
        // executor LLM tried to spawn. Walk the cpio.gz and assert
        // every role-required binary is present BEFORE the kernel
        // even boots — the test fails fast with an actionable
        // remediation instead of timing out 4 minutes in.
        //
        // Fix: `cargo xtask images bake-rootfs --role <ROLE>`. The
        // remediation in the panic message points at it.
        let required = required_binaries_for_canonical_role(role);
        if required.is_empty() {
            // Orch + reviewer are intentionally binary-only today;
            // the planner binary is checked below.
        }
        let entries = crate::common::cpio_inspect::list_initramfs_paths(&img).unwrap_or_else(|e| {
            panic!(
                "failed to walk canonical image {}: {e}\n\
                 The cpio.gz may be corrupted; rebuild via:\n  \
                 cargo xtask images bake-rootfs --role {role}\n  \
                 cargo xtask images dev-stage    --role {role}\n  \
                 cargo xtask images build-all    --role {role}",
                img.display(),
            )
        });
        let missing: Vec<&&'static str> = required
            .iter()
            .filter(|bin| !entries.contains_key(**bin))
            .collect();
        assert!(
            missing.is_empty(),
            "canonical {role} image is a stub — missing {n} required \
             binar{plural} from {img}:\n{lines}\n\
             \n\
             This usually means `cargo xtask images bake-rootfs --role {role}` \
             was skipped before `dev-stage` / `build-all`. The dev-host \
             pipeline now bakes the rootfs FROM the canonical \
             images/{role}/Containerfile via docker / podman / buildah; \
             without that step the cpio.gz contains only the \
             cross-compiled planner binary and `BashTool` returns ENOENT \
             for every LLM-issued shell command (the iter-12 failure \
             mode). Remediation:\n  \
             cargo xtask images bake-rootfs --role {role}\n  \
             cargo xtask images dev-stage    --role {role}\n  \
             cargo xtask images build-all    --role {role}\n\
             then re-run this test.",
            n = missing.len(),
            plural = if missing.len() == 1 { "y" } else { "ies" },
            img = img.display(),
            lines = missing
                .iter()
                .map(|b| format!("  - {b}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}

/// Per-role inventory of cpio paths that MUST be present in the
/// canonical signed initramfs. Mirrors xtask's `required_os_binaries`
/// (the dev-stage stub guard) so a test failure here points at a
/// pipeline regression in the same row of the same table.
///
/// The lists are deliberately tight (role-required, not nice-to-have)
/// so they never go out of step with the canonical Containerfiles.
/// Adding entries here without amending the Containerfile would
/// surface as a pipeline regression rather than catching one.
fn required_binaries_for_canonical_role(role: &str) -> &'static [&'static str] {
    match role {
        // Executor LLM writes `psycopg2` / `pymongo` / `redis` /
        // `smtplib` scripts and runs them via `bash -c 'python3 -c
        // "..."'`; a missing bash, python3, or git here is the
        // iter-12 failure mode. The planner binary itself is
        // overlaid by `dev-stage` and lands at usr/local/bin/.
        "executor-starter" => &[
            // `usr/bin/bash` (not `bin/bash`): debian:bookworm-slim
            // ships `usrmerge`, so the cpio encodes `/bin -> /usr/bin`
            // as a single `S_IFLNK` entry named `bin` and the actual
            // `bash` binary lives at `usr/bin/bash`. A literal
            // `bin/bash` lookup against the cpio entry table would
            // always miss (iter-15) even though PID 1 reaches the
            // binary via the `/bin -> /usr/bin` symlink that
            // `mount_pid1_essentials` materialises at boot. The
            // sibling stub-guard in `xtask::images::required_os_
            // binaries` keeps `bin/bash` because it walks the
            // **staging tree** with `Path::exists()` (symlink-
            // following); this preflight walks the packed cpio.gz
            // with a literal `BTreeMap` lookup. Sharing the path
            // string would require teaching one of the two callers
            // to chase symlinks - tracked as cleanup-sweep work.
            "usr/bin/bash",
            "usr/bin/python3",
            "usr/bin/git",
            "usr/local/bin/raxis-executor",
        ],
        // Orchestrator + Reviewer are binary-only by current spec
        // (INV-PLANNER-HARNESS-02 minimalism) — only the planner
        // PID-1 binary is required to ship in the canonical cpio.
        // Branch B follow-up will enrich orch / reviewer Containerfiles
        // and update this table in lockstep.
        "orchestrator-core" => &["usr/local/bin/raxis-orchestrator"],
        "reviewer-core" => &["usr/local/bin/raxis-reviewer"],
        other => panic!(
            "unknown canonical role {other:?}; \
                         expected one of: orchestrator-core, \
                         executor-starter, reviewer-core"
        ),
    }
}

/// Drive the three-stage `xtask images` pipeline (`bake-rootfs →
/// dev-stage → build-all`) for any canonical role whose
/// `<install_dir>/images/raxis-<role>-<v>.img` is missing or is a
/// binary-only stub. Idempotent: roles that already pass the cpio
/// preflight are skipped — we never re-run the docker bake when a
/// good image is already on disk.
///
/// This is the live-e2e harness's "self-contained on a fresh dev
/// host" feature. Without it, every operator (and the iter-13
/// fix-loop) had to remember to run six xtask invocations by hand
/// before kicking the test off, and a forgotten `bake-rootfs` step
/// surfaced as the iter-12 `BashTool: ENOENT` storm.
///
/// # Panics
///
/// On any pipeline-stage failure (bake / stage / pack / sign).
/// We deliberately do NOT surface a `Result` — a test that cannot
/// boot the kernel cannot proceed and a panic produces a clearer
/// `cargo test` failure than a silent skip. The panic message
/// includes the failed stage and the role.
///
/// # Workspace location
///
/// Resolves the workspace root by walking ancestors of `CARGO_MANIFEST_DIR`
/// (set by Cargo for every crate) until a `Cargo.toml` containing
/// `[workspace]` appears — same algorithm xtask uses for its own
/// `workspace_root_from_cwd()`. We do NOT use `CWD` because Cargo
/// runs integration tests from the per-crate manifest dir, not from
/// the workspace root, and we want this helper to work whether the
/// operator runs `cargo test --workspace` or `cd kernel && cargo test`.
fn ensure_canonical_images_baked(install_dir: &Path, kernel_version: &str) {
    let workspace_root = workspace_root_from_manifest_dir();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());

    for role in &["orchestrator-core", "executor-starter", "reviewer-core"] {
        let img = install_dir
            .join("images")
            .join(format!("raxis-{role}-{kernel_version}.img"));
        let manifest = install_dir
            .join("images")
            .join(format!("raxis-{role}-{kernel_version}.manifest.toml"));

        // Idempotency check: skip if BOTH the image and manifest
        // exist AND the cpio walk finds every required binary. This
        // matches the assertion `require_canonical_images` does next,
        // so a green idempotency check guarantees no rebake.
        if img.exists() && manifest.exists() && cpio_passes_preflight(&img, role) {
            eprintln!(
                "[live-e2e auto-bake] skip {role} (canonical image already complete at {})",
                img.display(),
            );
            continue;
        }

        eprintln!(
            "[live-e2e auto-bake] {role}: rebaking (img missing or stub at {})",
            img.display(),
        );

        // The harness identifies roles by their `images/<subdir>/`
        // (orchestrator-core / reviewer-core / executor-starter) so
        // diagnostics line up with `cpio_passes_preflight` and the
        // `<install_dir>/images/raxis-<role>-<v>.img` filenames. The
        // xtask CLI uses the planner-crate-short name (orchestrator
        // / reviewer / executor-starter). Translate once here.
        let xtask_role = xtask_cli_role_for(role);

        // ── 1. bake-rootfs ───────────────────────────────────────
        // Only `executor-starter` needs a Docker rootfs bake today
        // (its planner LLM shells out to `bash`/`python3`/`git`).
        // Orch + reviewer ship binary-only per INV-PLANNER-HARNESS-02
        // minimalism; their `required_binaries_for_canonical_role`
        // contains only the planner binary, which `dev-stage`
        // produces, so no Containerfile bake is required.
        if role_needs_rootfs_bake(role) {
            run_xtask_or_panic(
                &cargo,
                &workspace_root,
                role,
                "bake-rootfs",
                &["--role", xtask_role],
            );
        } else {
            eprintln!(
                "[live-e2e auto-bake] skip bake-rootfs for {role} \
                 (binary-only by spec; no Containerfile build needed)"
            );
        }

        // ── 2. dev-stage ─────────────────────────────────────────
        // For binary-only roles, pass --allow-stub so the post-stage
        // guard does not fire; for executor-starter (which DID just
        // bake the rootfs) the guard validates the bake worked.
        let stage_args: Vec<&str> = if role_needs_rootfs_bake(role) {
            vec!["--role", xtask_role]
        } else {
            vec!["--role", xtask_role, "--allow-stub"]
        };
        run_xtask_or_panic(&cargo, &workspace_root, role, "dev-stage", &stage_args);

        // ── 3. build-all ────────────────────────────────────────
        // Pack into the signed cpio.gz at <install_dir>/images/.
        run_xtask_or_panic(
            &cargo,
            &workspace_root,
            role,
            "build-all",
            &[
                "--role",
                xtask_role,
                "--install-dir",
                install_dir.to_str().unwrap_or_else(|| {
                    panic!(
                        "install_dir contains non-utf8 bytes: {}",
                        install_dir.display(),
                    )
                }),
            ],
        );
    }
}

/// Assert the canonical AVF / Firecracker boot kernel binary at
/// `<install_dir>/kernel/vmlinux` is present. The `cargo xtask
/// images bake` driver now stages vmlinux as part of its own
/// preflight + main flow (resolution order: `--kernel-from-file`
/// → `$RAXIS_DEV_KERNEL_SOURCE` → already-staged → canonical
/// host install), so the harness no longer needs the pre-bake
/// copy logic this helper used to carry. The assertion is kept
/// so that an operator who ran the legacy 3-step pipeline
/// (`bake-rootfs → dev-stage → build-all`, which does NOT stage
/// vmlinux) gets a clean, actionable diagnostic instead of the
/// fatal `AVF VM start failed: Invalid virtual machine
/// configuration. The boot loader is invalid.` two seconds into
/// the run.
///
/// **Idempotent and pure-read.** No filesystem mutation; an
/// existing kernel binary is accepted, a missing one panics with
/// a remediation message naming the new bake command. See
/// `INV-IMAGE-BAKE-VMLINUX-STAGED-01` for the normative contract.
fn ensure_canonical_kernel_binary_staged(install_dir: &Path) {
    let dest = install_dir.join("kernel").join("vmlinux");
    if let Ok(meta) = std::fs::metadata(&dest) {
        if meta.is_file() && meta.len() > 0 {
            return;
        }
    }
    panic!(
        "[live-e2e] canonical boot kernel missing at {dest}\n\n\
         AVF / Firecracker resolve the Linux kernel binary from \
         `<install_dir>/kernel/vmlinux` per \
         `canonical_images_preflight::linux_kernel_path`. Without it, \
         the first session-spawn fails with `AVF VM start failed: \
         Invalid virtual machine configuration. The boot loader is \
         invalid.` and the test cannot proceed.\n\n\
         Remediation: run the single-command bake pipeline (it stages \
         vmlinux at the canonical path as part of its preflight):\n  \
         cargo xtask images bake --install-dir {install_dir}\n\
         \n\
         Or stage just the kernel:\n  \
         cargo xtask images dev-kernel --from-file <path-to-vmlinux>\n\
         \n\
         (`INV-IMAGE-BAKE-VMLINUX-STAGED-01`)",
        dest = dest.display(),
        install_dir = install_dir.display(),
    );
}

/// Map the harness-internal `images/<subdir>` role name to the
/// `cargo xtask images <sub> --role <…>` CLI name.
///
/// The harness uses the directory-style name everywhere (so it
/// composes cleanly with `cpio_passes_preflight`, the
/// `<install_dir>/images/raxis-<role>-<v>.img` filenames, and the
/// `[live-e2e auto-bake] <role>: …` diagnostic lines). The xtask
/// CLI uses the planner-crate-short name (`orchestrator` instead
/// of `orchestrator-core`, `reviewer` instead of `reviewer-core`,
/// and the unchanged `executor-starter`). Drift between these two
/// surfaced as iter-46 where auto-bake invoked
/// `cargo xtask images bake-rootfs --role orchestrator-core` and
/// xtask rejected the role with an `unsupported --role` error.
///
/// Rather than teach `xtask::Role::parse` a second name per role,
/// we keep the CLI surface minimal (each role has exactly one
/// stable `--role` value) and translate in the harness — this is
/// the lone caller that ever hits xtask with the directory-style
/// name, and a one-line translation here is cheaper than expanding
/// the public xtask CLI vocabulary.
fn xtask_cli_role_for(image_subdir_role: &str) -> &'static str {
    match image_subdir_role {
        "orchestrator-core" => "orchestrator",
        "reviewer-core" => "reviewer",
        "executor-starter" => "executor-starter",
        other => panic!(
            "unknown canonical role {other:?}; \
             expected one of: orchestrator-core, executor-starter, reviewer-core"
        ),
    }
}

/// Whether the role needs a Docker rootfs bake (`bake-rootfs`)
/// before `dev-stage`.
///
/// Orchestrator + reviewer are binary-only by current spec
/// (INV-PLANNER-HARNESS-02 minimalism) — their canonical cpio
/// contains only the planner binary, which `dev-stage` produces
/// directly. The Docker rootfs bake is reserved for roles whose
/// LLM shells out to OS tooling (`bash` / `python3` / `git` for
/// executor-starter). Branch B will enrich orch / reviewer
/// Containerfiles and flip the corresponding entries here.
fn role_needs_rootfs_bake(image_subdir_role: &str) -> bool {
    match image_subdir_role {
        "executor-starter" => true,
        "orchestrator-core" => false,
        "reviewer-core" => false,
        other => panic!(
            "unknown canonical role {other:?}; \
             expected one of: orchestrator-core, executor-starter, reviewer-core"
        ),
    }
}

/// Walk a candidate canonical image and report whether it contains
/// every binary `require_canonical_images` will assert. Returns
/// `false` on any I/O failure (treat unreadable images as
/// preflight-failing so the auto-bake will rebuild them).
fn cpio_passes_preflight(img: &Path, role: &str) -> bool {
    let entries = match crate::common::cpio_inspect::list_initramfs_paths(img) {
        Ok(e) => e,
        Err(_) => return false,
    };
    required_binaries_for_canonical_role(role)
        .iter()
        .all(|b| entries.contains_key(*b))
}

/// Walk ancestors of `CARGO_MANIFEST_DIR` looking for a `Cargo.toml`
/// that contains `[workspace]`. Mirrors xtask's
/// `workspace_root_from_cwd()` but anchored at the test's manifest
/// dir so it works whether the operator runs the test from the
/// workspace root or from `kernel/`.
fn workspace_root_from_manifest_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = p.join("Cargo.toml");
        if candidate.exists() {
            if let Ok(s) = std::fs::read_to_string(&candidate) {
                if s.contains("[workspace]") {
                    return p;
                }
            }
        }
        if !p.pop() {
            panic!(
                "could not locate workspace root (no Cargo.toml with \
                 [workspace] in any ancestor of {})",
                env!("CARGO_MANIFEST_DIR"),
            );
        }
    }
}

fn run_xtask_or_panic(cargo: &str, workspace_root: &Path, role: &str, sub: &str, extra: &[&str]) {
    let mut argv: Vec<&str> = vec!["xtask", "images", sub];
    argv.extend(extra);
    eprintln!(
        "[live-e2e auto-bake] {role}: running {} {}",
        cargo,
        argv.join(" "),
    );
    let status = Command::new(cargo)
        .current_dir(workspace_root)
        .args(&argv)
        .status()
        .unwrap_or_else(|e| panic!("spawn `{cargo} {}`: {e}", argv.join(" "),));
    if !status.success() {
        panic!(
            "live-e2e auto-bake stage `{sub}` failed for role {role:?} \
             (exit {status}). Re-run manually for richer diagnostics:\n  \
             {cargo} {}\n\
             Set RAXIS_LIVE_E2E_SKIP_AUTO_BAKE=1 to disable auto-bake \
             entirely (operator-managed canonical images).",
            argv.join(" "),
        );
    }
}

// ---------------------------------------------------------------------------
// Bootstrap + spawn.
// ---------------------------------------------------------------------------

/// Build a fresh operator signing key from `seed`. Returns the
/// key + its 8-byte fingerprint (the kernel's stable operator id
/// in audit rows).
pub fn build_operator_key(seed: &[u8; 32]) -> (SigningKey, OperatorFingerprint) {
    let key = SigningKey::from_bytes(seed);
    let pubkey = key.verifying_key().to_bytes();
    (key, fingerprint_8(&pubkey))
}

/// Bootstrap a fresh kernel under a tempdir-data-dir with a
/// custom operator cert that grants the full lifecycle ops.
pub fn bootstrap_with_custom_cert(signing_key: &SigningKey) -> (PathBuf, PathBuf) {
    let kernel_bin = build_and_locate_kernel();

    #[cfg(target_os = "macos")]
    codesign_kernel_for_avf(&kernel_bin);

    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is post-epoch")
        .as_secs() as i64;
    // The realism-e2e operator runs as **dashboard Admin** so live-e2e
    // exercises the full operator surface (reveal-plaintext on system
    // credentials, policy install via dashboard, every audit-emitting
    // grant/deny path) — not just the read-only subset. Admin is granted
    // by the dashboard-kernel mapping
    // (`crates/dashboard-kernel/src/lib.rs::roles_from_permitted_ops`)
    // when both `RotateEpoch` AND `OperatorCertInstall` appear in
    // `permitted_ops`.
    let cert = ephemeral_cert_with_key(
        signing_key,
        CertOpts {
            now_unix_secs,
            permitted_ops: vec![
                "CreateInitiative".to_owned(),
                "ApprovePlan".to_owned(),
                "AbortInitiative".to_owned(),
                "RotateEpoch".to_owned(),
                "OperatorCertInstall".to_owned(),
            ],
            display_name: "realism-e2e-operator".to_owned(),
            ..CertOpts::default()
        },
    );

    let data_dir: PathBuf = tempfile::tempdir()
        .expect("tempdir for kernel data dir")
        .keep();
    let cert_path = data_dir.join("operator.cert.toml");
    let toml_body = toml::to_string(&cert).expect("serialise realism-e2e cert");
    std::fs::write(&cert_path, toml_body).expect("write operator cert");

    let bootstrap_output = Command::new(&kernel_bin)
        .env("RAXIS_BOOTSTRAP", "1")
        .env("RAXIS_DATA_DIR", &data_dir)
        .env("RAXIS_OPERATOR_CERT", &cert_path)
        .output()
        .expect("spawn kernel in bootstrap mode");
    assert!(
        bootstrap_output.status.success(),
        "kernel bootstrap failed (exit {:?}):\n--- stderr ---\n{}",
        bootstrap_output.status.code(),
        String::from_utf8_lossy(&bootstrap_output.stderr),
    );

    (kernel_bin, data_dir)
}

pub fn spawn_kernel_normal(
    kernel_bin: &Path,
    data_dir: PathBuf,
    install_dir: &Path,
) -> KernelInstance {
    use std::io::{BufRead, BufReader};
    use std::process::{Command as ProcCommand, Stdio};
    use std::sync::{Arc, Mutex};

    // iter73 follow-up — shrink the planner-IPC idle watchdog
    // from the 900 s production default to 300 s (5 min) for the
    // extended-e2e harness. iter73's executor wedge (BUG-B in
    // `specs/v3/iter73-networking-dry-run-trace.md`) sat in the
    // 15-minute "dead-zone" of the production watchdog, which is
    // an entire iteration loop for an interactive operator.
    // The 5-minute threshold is still well above the legitimate
    // worst-case orchestrator turn (LLM responses regularly take
    // 30-60 s; a worst-case 4-minute reasoning pass still fits)
    // so it cannot false-positive on slow-but-honest sessions.
    // Production callers (real kernels, not the harness) inherit
    // the 900 s default unchanged via
    // `PLANNER_IPC_IDLE_TIMEOUT_DEFAULT_SECS` so the safety
    // contract on customer deployments is unchanged.
    // Operator override (`RAXIS_PLANNER_IPC_IDLE_TIMEOUT_SECS=N`
    // in the harness's parent env) still wins — the harness only
    // sets the var if it is not already set.
    let mut cmd = ProcCommand::new(kernel_bin);
    cmd.env("RAXIS_DATA_DIR", &data_dir)
        .env("RAXIS_INSTALL_DIR", install_dir);
    if std::env::var_os("RAXIS_PLANNER_IPC_IDLE_TIMEOUT_SECS").is_none() {
        cmd.env("RAXIS_PLANNER_IPC_IDLE_TIMEOUT_SECS", "300");
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kernel in normal mode");

    let stderr = child.stderr.take().expect("kernel stderr captured");
    let stderr_lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let log_path = data_dir.join("kernel.stderr.log");
    let log_handle = std::fs::File::create(&log_path)
        .ok()
        .map(|f| Arc::new(Mutex::new(f)));
    {
        let lines = Arc::clone(&stderr_lines);
        let log_handle = log_handle.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                if let Some(h) = &log_handle {
                    if let Ok(mut g) = h.lock() {
                        use std::io::Write as _;
                        let _ = writeln!(g, "{line}");
                    }
                }
                lines.lock().unwrap().push(line);
            }
        });
    }

    KernelInstance::from_parts(child, stderr_lines, data_dir)
}

pub fn enable_gateway_in_policy(data_dir: &Path, gateway_binary: &Path) {
    let policy_path = data_dir.join("policy").join("policy.toml");
    let mut body = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", policy_path.display()));
    assert!(
        !body.contains("\n[gateway]\n"),
        "policy.toml already has a [gateway] block; bootstrap template changed",
    );
    let injected = format!(
        "\n# ── [gateway] + [[providers]] + [egress] + [[lanes]] (realism-e2e) ──\n\
         [gateway]\n\
         binary_path              = \"{gw}\"\n\
         spawn_timeout_secs       = 30\n\
         respawn_backoff_ms       = 1000\n\
         max_consecutive_respawns = 5\n\
         \n\
         # `example.com` admits the iter65 dep-fetch-evidence task's\n\
         # one HTTPS GET via Path A3; the witness in\n\
         # `extended_e2e_support::dep_fetch_evidence` pins exactly one\n\
         # `TproxyAdmissionGranted{{host_or_sni=\"example.com\",port=443}}`\n\
         # per executor session. RFC-2606 reserved, IANA-maintained.\n\
         #\n\
         # `pypi.org` + `files.pythonhosted.org` are the two hosts\n\
         # `pip install` reaches at runtime — pypi.org for the\n\
         # simple-index resolution + JSON metadata, then\n\
         # files.pythonhosted.org for the wheel download. The same\n\
         # dep-fetch-evidence task chains a `pip install` after the\n\
         # example.com fetch, and the witness verifies the install\n\
         # via the `--report` JSON (wheel sha256 + package version).\n\
         [egress]\n\
         domains = [\"api.anthropic.com\", \"example.com\", \"pypi.org\", \"files.pythonhosted.org\"]\n\
         patterns = []\n\
         \n\
         [[providers]]\n\
         provider_id           = \"anthropic-realism-e2e\"\n\
         kind                  = \"Anthropic\"\n\
         credentials_file      = \"anthropic-realism-e2e.toml\"\n\
         inference_timeout_ms  = 120000\n\
         data_fetch_timeout_ms = 30000\n\
         pricing.input_tokens_per_dollar      = 200000\n\
         pricing.output_tokens_per_dollar     = 50000\n\
         pricing.cache_read_tokens_per_dollar = 2000000\n\
         \n\
         # ── [[lanes]] registration (V2 §Step 28 + INV-SCHED-03) ─────────\n\
         # The realistic-scenario plans declare `[workspace] lane_id =\n\
         # \"e2e-realistic-lane\"` (primary plan, `plan_realistic.rs`)\n\
         # and `[workspace] lane_id = \"e2e-realistic-sibling-lane\"`\n\
         # (sibling plan, `multi_initiative.rs`). The kernel-side\n\
         # `lifecycle::validate_workspace_lane_in_policy` rejects any\n\
         # plan whose workspace lane has no matching `[[lanes]]` entry\n\
         # — without these blocks `lifecycle::approve_plan` returns\n\
         # `LifecycleError::PlanLaneNotInPolicy` BEFORE the tx opens,\n\
         # and the harness sees an admission failure instead of an\n\
         # `IntegrationMergeCompleted`. (Pre-fix, the lane absence\n\
         # collapsed silently to a per-IntegrationMerge\n\
         # `FailBudgetExceeded` rejection because `lane_config_for_row`\n\
         # returned `NoLaneAssigned` and `intent.rs::run_phase_c` Step\n\
         # 10 maps that to the wire-level budget error — the\n\
         # iter-38/39 reproduction.)\n\
         #\n\
         # Caps are sized generously so the per-task cost\n\
         # (`base_cost_for_intent_kind` + `cost_per_touched_path *\n\
         # |touched_paths|`) on every realistic-scenario task clears\n\
         # comfortably with margin for the synthetic IntegrationMerge\n\
         # coordinator slice.\n\
         [[lanes]]\n\
         lane_id              = \"e2e-realistic-lane\"\n\
         max_concurrent_tasks = 8\n\
         max_cost_per_epoch   = 100000\n\
         priority             = 100\n\
         \n\
         [[lanes]]\n\
         lane_id              = \"e2e-realistic-sibling-lane\"\n\
         max_concurrent_tasks = 8\n\
         max_cost_per_epoch   = 100000\n\
         priority             = 100\n",
        gw = gateway_binary.display(),
    );
    body.push_str(&injected);
    body.push_str(&observability_policy_block());

    // ── iter62/iter63: real witness verifier (additive, FOLLOWUP-B) ────────
    //
    // INV-WITNESS-VERIFIER-LIVE-E2E-EXERCISED-01: every live-e2e
    // run MUST drive at least one verifier-backed gate through
    // `kernel/src/scheduler/dag.rs::transition_to_admitted`. Mirror
    // of the block in `extended_e2e_concurrent_lifecycle.rs`. The
    // injection is conditional on the verifier binary existing on
    // disk; absent binary → skip + eprintln (avoids hanging the
    // test on a broken policy).
    if let Some(verifier_bin) = sibling_verifier_binary(gateway_binary) {
        // The comment below mirrors the checked-in
        // `live-e2e/examples/policy.toml` block so an operator
        // diffing the live runtime config against the example
        // reads the same prose verbatim. Keep them in lock-step
        // when either side is edited (the
        // `examples_policy_carries_no_secret_strings_gate`
        // regression test pins the example side; the
        // `iter65_harness_gate_block_mirrors_examples_comment`
        // test below pins this side).
        let gate_block = format!(
            "\n# ── [[gates]] — witness verifier (iter62 / iter63) ──\n\
             # Real, fast worktree-scanning gate. Source:\n\
             # `crates/verifier-no-secrets/`. Every `IntegrationMerge`\n\
             # intent transitions `Admitted → GatesPending` and the kernel\n\
             # `scheduler/dag.rs::transition_to_admitted` blocks the merge\n\
             # until a `VerifierWitnessReceived{{gate_type=\"NoSecretStrings\",\n\
             # verdict=\"Pass\"}}` row lands on the audit chain. See\n\
             # `INV-WITNESS-VERIFIER-LIVE-E2E-EXERCISED-01` for the rationale\n\
             # (this is the live coverage point for the iter63 recheck-clear\n\
             # paired-write audit row) and `INV-GATE-PRECEDENCE-01` for the\n\
             # kernel's gate-then-merge ordering contract.\n\
             [[gates]]\n\
             gate_type        = \"NoSecretStrings\"\n\
             verifier_command = \"{vb}\"\n\
             max_wall_seconds = 30\n\
             max_memory_bytes = 268435456\n\
             network_allowed  = false\n\
             # iter65 — tier-2 fallback for the `agent_hint` resolution chain\n\
             # (`INV-WITNESS-AGENT-HINT-RESOLUTION-TIERS-01`). The verifier's\n\
             # `body.agent_hint` (tier 1) is the preferred source — populated\n\
             # per failure code path by `raxis-verifier-no-secrets`. This\n\
             # `agent_hint_default` only fires when a verifier author shipped\n\
             # a Fail / Inconclusive without a wire-valid hint (e.g. an early\n\
             # build before the verifier was migrated to the typestate SDK).\n\
             # Required at policy load whenever `[gate_fixup].enabled = true`.\n\
             agent_hint_default = \"A `NoSecretStrings` gate detected secret-shaped material in your commit. Remove any literal API keys, tokens, or credentials and reference them via env vars or your secret store instead. Re-run your local secret scanner before resubmitting.\"\n",
            vb = verifier_bin.display(),
        );
        body.push_str(&gate_block);
        eprintln!(
            "[live-e2e] enabling NoSecretStrings gate; verifier={}",
            verifier_bin.display()
        );
    } else {
        eprintln!(
            "[live-e2e] skipping NoSecretStrings gate injection — \
             raxis-verifier-no-secrets binary not found alongside \
             {} (build with `cargo build -p raxis-verifier-no-secrets --release` \
             to enable iter63 recheck-clear coverage)",
            gateway_binary.display(),
        );
    }
    std::fs::write(&policy_path, body)
        .unwrap_or_else(|e| panic!("rewrite {}: {e}", policy_path.display()));
}

/// Resolve the absolute path of the `raxis-verifier-no-secrets`
/// binary built into the same `target/<profile>/` tree as
/// `gateway_binary`. Returns `None` when the binary has not been
/// built — callers MUST short-circuit gate injection in that case.
/// Cf. `extended_e2e_concurrent_lifecycle::sibling_verifier_binary`
/// for the canonical definition; duplicated here to keep each
/// extended-e2e slice self-contained at its file-ownership boundary.
fn sibling_verifier_binary(gateway_binary: &std::path::Path) -> Option<std::path::PathBuf> {
    let parent = gateway_binary.parent()?;
    let candidate = parent.join("raxis-verifier-no-secrets");
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

/// Seed `<data_dir>/repositories/main` as a real (non-bare) git
/// repository with `refs/heads/main` pointing at an initial empty
/// commit. The orchestrator-spawn path's
/// `worktree_provisioning::provision_orchestrator_worktree` clones
/// from this repository at the initiative's `target_ref`
/// (defaults to `refs/heads/main`) into
/// `<data_dir>/worktrees/<initiative>/orch-<task>`. Without this
/// seed every `ApprovePlan` succeeds at the IPC boundary but the
/// orchestrator never spawns: the kernel's `orchestrator_spawn_failed`
/// path logs `does not appear to be a git repository` and the
/// downstream worktree under `<data_dir>/worktrees/<initiative>/<task>`
/// is never created — the realistic-scenario test then times out
/// in `materialise_realistic_seed`.
///
/// Mirrors `full_e2e_session_lifecycle::seed_main_repository`. The
/// helper lives in `kernel_driver` so every shared `RAXIS_LIVE_E2E`
/// driver (realistic scenario, future scenarios that adopt the
/// `kernel_driver` module) gets a single source of truth.
///
/// Idempotent: a re-entry into a populated `repositories/main`
/// short-circuits because the bootstrap creates the data dir fresh
/// per run, but a future test that re-uses the same data_dir is not
/// punished for it.
pub fn seed_main_repository(data_dir: &Path) {
    let repos_root = data_dir.join("repositories");
    std::fs::create_dir_all(&repos_root)
        .unwrap_or_else(|e| panic!("mkdir {}: {e}", repos_root.display()));

    let main_repo = repos_root.join("main");
    if main_repo.join(".git").exists() {
        return;
    }
    std::fs::create_dir_all(&main_repo)
        .unwrap_or_else(|e| panic!("mkdir {}: {e}", main_repo.display()));

    // `git init -b main` is git 2.28+; older host gits (e.g. macOS
    // XCode CLT 2.24) reject `-b`. We `git init` then explicitly
    // point HEAD at refs/heads/main.
    let init = Command::new("git")
        .args(["init", "-q"])
        .arg(&main_repo)
        .status()
        .unwrap_or_else(|e| panic!("spawn git init: {e}"));
    assert!(init.success(), "git init failed at {}", main_repo.display());

    let head_set = Command::new("git")
        .current_dir(&main_repo)
        .args(["symbolic-ref", "HEAD", "refs/heads/main"])
        .status()
        .unwrap_or_else(|e| panic!("spawn git symbolic-ref: {e}"));
    assert!(
        head_set.success(),
        "git symbolic-ref HEAD refs/heads/main failed in {}",
        main_repo.display(),
    );

    // Stamp deterministic author / committer identity so the seed
    // commit's hash is reproducible across developer machines (no
    // `~/.gitconfig` dependency, no UID-derived defaults).
    let env: &[(&str, &str)] = &[
        ("GIT_AUTHOR_NAME", "raxis-e2e"),
        ("GIT_AUTHOR_EMAIL", "e2e@raxis.invalid"),
        ("GIT_COMMITTER_NAME", "raxis-e2e"),
        ("GIT_COMMITTER_EMAIL", "e2e@raxis.invalid"),
        ("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z"),
        ("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z"),
    ];
    let commit = Command::new("git")
        .current_dir(&main_repo)
        .envs(env.iter().copied())
        .args([
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "raxis-e2e: seed repository",
        ])
        .status()
        .unwrap_or_else(|e| panic!("spawn git commit: {e}"));
    assert!(
        commit.success(),
        "git commit failed in {}",
        main_repo.display()
    );

    let rev = Command::new("git")
        .current_dir(&main_repo)
        .args(["rev-parse", "refs/heads/main"])
        .output()
        .unwrap_or_else(|e| panic!("spawn git rev-parse: {e}"));
    assert!(
        rev.status.success(),
        "git rev-parse refs/heads/main failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&rev.stdout),
        String::from_utf8_lossy(&rev.stderr),
    );
    eprintln!(
        "[realism-e2e] seeded main repo at {} -> {}",
        main_repo.display(),
        String::from_utf8_lossy(&rev.stdout).trim(),
    );
}

/// Seed `<data_dir>/repositories/main` with the **rich-multilang-001
/// fixture history** (11 commits, including a feature-branch merge
/// and a cross-language rename), then layer on the realistic
/// scenario's per-task overlays — the bait `.env` carrying the FAKE
/// credential canaries the credential-substitution-canary task
/// inspects, plus the stock-Python service-integrity scripts the
/// transparent-proxy-realscripts task runs — and commit them as a
/// single 12th commit.
///
/// **Why bake the per-task overlays into `repositories/main`.** The
/// kernel's worktree provisioner uses the layout
/// `<data_dir>/worktrees/orch-<initiative_id>/` for the
/// orchestrator's clone of `main` and `<data_dir>/worktrees/<session_id>/`
/// for each per-session executor / reviewer clone. None of these
/// layouts match `<data_dir>/worktrees/<initiative_id>/<task_id>/`,
/// so a poll-based "wait for the executor's worktree to appear and
/// then drop a fixture into it" overlay cannot succeed (the path
/// the test driver was polling never existed). Committing the
/// overlay into `repositories/main` BEFORE plan submission is the
/// kernel-faithful equivalent: every downstream worktree is a
/// `gix::clone` (full history) of `main`, so each executor inherits
/// the seed history + bait `.env` + proxy scripts deterministically
/// the moment the orchestrator finishes its own clone — with zero
/// timing race against the executor VM boot.
///
/// `materialize_seed.sh` itself wipes the target dir if it exists
/// (idempotent contract documented in the script header), then
/// `git init` + 11 commits. After it returns we add the bait `.env`
/// + proxy scripts at the worktree root and commit them with a
///   pinned identity / date so HEAD is byte-stable across developer
///   machines (no `~/.gitconfig` dependency).
///
/// **Replaces** `seed_main_repository` for the realistic-scenario
/// driver. `seed_main_repository` (single empty commit) remains for
/// `full_e2e_session_lifecycle`, which neither needs the rich
/// history nor the per-task overlays.
pub fn seed_realistic_main_repository(data_dir: &Path) {
    let repos_root = data_dir.join("repositories");
    std::fs::create_dir_all(&repos_root)
        .unwrap_or_else(|e| panic!("mkdir {}: {e}", repos_root.display()));
    let main_repo = repos_root.join("main");

    // `materialize_seed.sh` insists on either an empty target or a
    // previously-seeded target marked by `.seed-head-sha`. The
    // tempdir bootstrap leaves `repositories/main` non-existent,
    // but a re-entry into the same data_dir (rare but possible
    // for ad-hoc local debug) would have a populated dir. Wipe it
    // unconditionally — the helper is single-purpose, the dir is
    // always under the per-test tempdir.
    if main_repo.exists() {
        std::fs::remove_dir_all(&main_repo)
            .unwrap_or_else(|e| panic!("wipe {}: {e}", main_repo.display()));
    }

    let workspace_root = realism_workspace_root();
    let seed_script =
        workspace_root.join("live-e2e/seed/repo/rich-multilang-001/scripts/materialize_seed.sh");
    assert!(
        seed_script.exists(),
        "rich-multilang seed script missing at {}; \
         is `live-e2e/seed/repo/rich-multilang-001/` present in the worktree?",
        seed_script.display(),
    );

    let status = Command::new(&seed_script)
        .arg(&main_repo)
        .status()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", seed_script.display()));
    assert!(
        status.success(),
        "{} exited non-zero: {status:?}",
        seed_script.display(),
    );

    // Stage the bait `.env` (FAKE credential canaries the
    // credential-substitution-canary task's witness scans for) and
    // the stock-Python service-integrity scripts (the
    // transparent-proxy-realscripts task runs them).
    crate::extended_e2e_support::credential_substitution_evidence::stage_fake_creds_env(&main_repo)
        .unwrap_or_else(|e| panic!("stage_fake_creds_env in main repo: {e}"));
    crate::extended_e2e_support::transparent_proxy_evidence::stage_scripts_into_worktree(
        &main_repo,
        &workspace_root,
    )
    .unwrap_or_else(|e| panic!("stage_scripts_into_worktree in main repo: {e}"));

    // Commit the overlay as the 12th commit on `main`. Use a
    // pinned identity / date for byte-stable HEAD across machines.
    let env: &[(&str, &str)] = &[
        ("GIT_AUTHOR_NAME", "raxis-realistic-seed"),
        ("GIT_AUTHOR_EMAIL", "realistic@raxis.invalid"),
        ("GIT_COMMITTER_NAME", "raxis-realistic-seed"),
        ("GIT_COMMITTER_EMAIL", "realistic@raxis.invalid"),
        ("GIT_AUTHOR_DATE", "2026-01-02T00:00:00Z"),
        ("GIT_COMMITTER_DATE", "2026-01-02T00:00:00Z"),
    ];
    let add = Command::new("git")
        .current_dir(&main_repo)
        .args(["add", "-A", "."])
        .status()
        .unwrap_or_else(|e| panic!("spawn git add: {e}"));
    assert!(add.success(), "git add failed in {}", main_repo.display());
    let commit = Command::new("git")
        .current_dir(&main_repo)
        .envs(env.iter().copied())
        .args([
            "commit",
            "-q",
            "-m",
            "test(realistic): bait .env + transparent-proxy scripts overlay",
        ])
        .status()
        .unwrap_or_else(|e| panic!("spawn git commit: {e}"));
    assert!(
        commit.success(),
        "git commit failed in {}",
        main_repo.display()
    );

    let rev = Command::new("git")
        .current_dir(&main_repo)
        .args(["rev-parse", "refs/heads/main"])
        .output()
        .unwrap_or_else(|e| panic!("spawn git rev-parse: {e}"));
    assert!(
        rev.status.success(),
        "git rev-parse refs/heads/main failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&rev.stdout),
        String::from_utf8_lossy(&rev.stderr),
    );
    eprintln!(
        "[realism-e2e] seeded rich-multilang main repo at {} -> {}",
        main_repo.display(),
        String::from_utf8_lossy(&rev.stdout).trim(),
    );
}

/// Resolve the workspace root (the `raxis/` directory containing
/// the integration-test crate, the `live-e2e/` tree with the seed
/// scripts, etc.). `CARGO_MANIFEST_DIR` for the integration-test
/// binary points at `raxis/kernel/`, so the workspace root is its
/// parent.
///
/// `pub` so the realistic-scenario test driver can pass it to
/// [`maybe_refresh_examples`] without re-deriving the same path.
pub fn realism_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .expect("CARGO_MANIFEST_DIR for kernel integration tests has a parent (workspace root)")
}

/// V3 `otel-observability.md §5` — `[observability]` policy section
/// the live-e2e harness appends so the kernel boots with a real
/// `ObservabilityHub` (not the disabled `disabled_default()` hub).
///
/// The endpoint, ports, and admin credentials mirror
/// `live-e2e/docker-compose.e2e.yml` (kept in lockstep by the
/// `tier3_artifacts::observability_urls_match_compose_file` test).
/// Field names mirror `crates/policy/src/observability.rs`
/// `ObservabilityConfig` exactly — anything off-shape is rejected
/// at policy load with a `FAIL_OBS_*` code.
fn observability_policy_block() -> String {
    // The kernel writes JSONL frames into `<data_dir>/observability/`
    // (see `kernel/src/observability_boot.rs::build_obs_hub`); the
    // out-of-process `raxis-otel-pusher` (spawned later via
    // `extended_e2e_support::otel_pusher::ensure_otel_pusher_or_panic`)
    // reads those frames and ships them to the OTel collector at
    // 127.0.0.1:4318.
    "\n# ── [observability] (realism-e2e — V3 OTel push) ──\n\
     [observability]\n\
     enabled = true\n\
     \n\
     [observability.ring]\n\
     segment_max_bytes = 16777216\n\
     max_total_bytes   = 268435456\n\
     max_queue_depth   = 4096\n\
     \n\
     [observability.metrics]\n\
     enabled         = true\n\
     export_interval = \"5s\"\n\
     \n\
     [observability.resource]\n\
     service_name = \"raxis-kernel-live-e2e\"\n\
     environment  = \"live-e2e\"\n\
     \n\
     [observability.resource.extra]\n\
     run_kind = \"realistic-scenario\"\n\
     \n\
     [observability.pusher]\n\
     otlp_endpoint       = \"http://127.0.0.1:4318\"\n\
     otlp_protocol       = \"http\"\n\
     otlp_compression    = \"gzip\"\n\
     otlp_export_timeout = \"10s\"\n\
     otlp_batch_size     = 256\n\
     otlp_flush_interval = \"1s\"\n\
     otlp_max_inflight   = 4\n"
        .to_owned()
}

// `spawn_otel_pusher_or_warn` + `locate_raxis_otel_pusher_binary`
// (legacy best-effort implementations that silently degraded the
// run when the pusher binary was missing) were removed in the
// iter53(harness) sweep. The hard-fail / auto-build / supervised-
// spawn / smoke-probe surface that supersedes them lives in
// [`super::otel_pusher::ensure_otel_pusher_or_panic`] per
// `INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01`.

pub fn write_credentials(data_dir: &Path) {
    let cred_dir = data_dir.join("credentials");
    std::fs::create_dir_all(&cred_dir).expect("mkdir credentials");

    // Credential value format is normative per `credential-proxy.md §3`
    // (table at "proxy_type": `postgres` row): the resolved credential
    // bytes MUST be a libpq URL `postgresql://user:pass@host:port/db`
    // (RFC 3986). `credential-proxy-postgres::ParsedUpstreamUrl::parse`
    // is the consumer; non-URL bytes are rejected with
    // `FAIL_PROXY_UPSTREAM_URL_INVALID`. The `.env` file extension is
    // a path-suffix convention (`<name>.env`), independent of the
    // value encoding — the legacy `PGHOST=...\nPGPORT=...` env-style
    // form documented in operator examples was never wired through
    // and is being aligned with §3 in the same commit.
    write_with_mode_0600(
        &cred_dir.join("test-pg-dev.env"),
        b"postgresql://raxis_test:raxis_test_pass@127.0.0.1:54399/raxis_e2e_pg",
    );

    // MongoDB proxy expects a plaintext `mongodb://` URI per
    // `credential-proxy.md §3` and
    // `credential-proxy-mongodb::ParsedUpstreamUrl::parse`.
    // `mongodb+srv://` is explicitly rejected for the MVP.
    write_with_mode_0600(
        &cred_dir.join("test-mongo-dev.env"),
        b"mongodb://raxis_test:raxis_test_pass@127.0.0.1:27399/raxis_e2e_mongo?authSource=admin",
    );

    // Redis proxy expects either a single password line OR a
    // `.env`-style `RAXIS_REDIS_USER=…\nRAXIS_REDIS_PASSWORD=…`
    // pair per `credential-proxy.md §3` (Redis row) and
    // `credential-proxy-redis::parse_redis_credential`. The
    // extended docker-compose stack runs `redis-server` with
    // `--requirepass raxis_test_pass` and no ACL user
    // (`live-e2e/docker-compose.extended.e2e.yml §redis`), so the
    // single-line password form is the canonical wire match. The
    // `realistic_session_lifecycle` service-round-trip task mounts
    // this credential as `REDIS_URL` against
    // `127.0.0.1:63799` — without this file the proxy's
    // `backend.resolve` call hard-fails, the listener accepts the
    // agent's TCP connection, and serve_one closes it before
    // sending a single byte of RESP. The executor sees "TCP
    // accept + immediate close" which surfaces as
    // `redis.exceptions.ConnectionError: Connection closed by
    // server` (live-e2e iter34 root cause).
    write_with_mode_0600(&cred_dir.join("test-redis-dev.env"), b"raxis_test_pass");

    // SMTP proxy expects raw upstream-relay password bytes per
    // `credential-proxy.md §3` (SMTP row). The wire driver
    // (`credential-proxy-smtp::wire::drive_auth_through_quit`)
    // assembles the on-wire `AUTH PLAIN base64("\0<user>\0<pw>")`
    // payload using the password from this file and the username
    // from the plan's `tasks.credentials.auth_mode.user`
    // (`SmtpAuthMode::Plain { user: "raxis-tenant@live-e2e.test" }`
    // in the realistic plan). The docker-mailserver container
    // (`live-e2e/seed/smtp/postfix-accounts.cf`) stores the
    // single account `raxis-tenant@live-e2e.test` with the
    // password baked in below as a plaintext SASL secret.
    write_with_mode_0600(
        &cred_dir.join("test-smtp-dev.env"),
        b"live-e2e-upstream-secret",
    );
}

pub fn write_provider_credentials(data_dir: &Path) {
    let providers_dir = data_dir.join("providers");
    std::fs::create_dir_all(&providers_dir).expect("mkdir providers");

    let env_path = workspace_dotenv_path();
    let body = std::fs::read_to_string(&env_path).expect("preflight verified .env");
    let api_key = body
        .lines()
        .find_map(|l| l.strip_prefix("ANTHROPIC-API-DEV-KEY="))
        .map(str::trim)
        .expect("preflight verified ANTHROPIC-API-DEV-KEY=...")
        .to_owned();

    let provider_toml = format!(
        "api_key     = \"{api_key}\"\n\
         auth_header = \"x-api-key\"\n\
         auth_prefix = \"\"\n",
    );
    write_with_mode_0600(
        &providers_dir.join("anthropic-realism-e2e.toml"),
        provider_toml.as_bytes(),
    );
}

/// Write a credentials-bearing file at exactly mode 0600.
///
/// The sequence matches `kernel/src/bootstrap.rs::write_file_0400`:
///
/// 1. `OpenOptions::create(true).truncate(true).mode(0o600)` — on
///    the `O_CREAT` path the file comes into existence at 0600.
///    On the existing-file path the mode is preserved and may be
///    wider (e.g. an operator hand-edited `creds/foo.env` and
///    accidentally left it world-readable). Bytes have not yet
///    been written.
///
/// 2. `set_permissions(0o600)` — tightens the mode BEFORE we write
///    the body. The file is still empty at this point, so even
///    if the existing file had been at 0644 we never expose body
///    bytes at the wider mode. The open file descriptor retains
///    its write access regardless of the on-disk permission bits.
///
/// 3. `write_all(body)` then `sync_all` durably land the bytes at
///    the now-correct 0600 mode.
fn write_with_mode_0600(path: &Path, body: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|e| panic!("open {} O_CREAT|0600: {e}", path.display()));
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| panic!("chmod 0600 {}: {e}", path.display()));
    f.write_all(body)
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    f.sync_all()
        .unwrap_or_else(|e| panic!("fsync {}: {e}", path.display()));
}

// ---------------------------------------------------------------------------
// Auto-refresh of the checked-in `raxis/live-e2e/examples/` bundle
// (INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01).
//
// The checked-in `raxis/live-e2e/examples/` directory mirrors what
// the realistic-scenario harness writes into its per-run tmpdir at
// bootstrap, so an operator auditing "what policy.toml / plan.toml /
// credential files produced this iter?" can answer without re-running
// the test. The auto-refresh hook here is what keeps the mirror
// up-to-date.
//
// The hook is **opt-in** via `RAXIS_E2E_REFRESH_EXAMPLES=1`. Default-
// off keeps casual `cargo test` runs from dirtying the worktree.
// The fix-loop / CI / a `working e2e` commit MUST set the env var
// before the run that lands the commit so the checked-in bundle
// always matches the most recent passing iter. See
// `raxis/live-e2e/examples/README.md` for the full contract.
//
// The Anthropic credential rule is structural, not cosmetic: the
// hook (a) rewrites `anthropic.env.placeholder` from a hardcoded
// template (NOT a copy of whatever real `ANTHROPIC-API-DEV-KEY` the
// harness loaded into the kernel's `providers/` dir), so the real
// bytes never enter the refresh path; (b) at end of refresh,
// `assert_no_real_anthropic_key` scans every file under
// `examples/credentials/` for the real-key regex and panics with a
// copy-pastable remediation hint if a match is found.
//
// The hook is wired into `realistic_session_lifecycle` AFTER the
// run's TOMLs are assembled but BEFORE the kernel daemon starts, so
// a refresh failure short-circuits the whole iter instead of landing
// a half-baked diff. The same hook is exercised by a unit test
// against a tmpdir fixture (see `tests::refresh_examples_*`) so a
// regression in the refresh shape is caught on every
// `cargo test -p raxis-kernel` even without the live docker stack.
// ---------------------------------------------------------------------------

/// Opt-in env var that gates the example-bundle auto-refresh.
/// Default-off keeps casual `cargo test` runs from dirtying the
/// worktree.
pub const REFRESH_EXAMPLES_ENV: &str = "RAXIS_E2E_REFRESH_EXAMPLES";

/// Hardcoded template body for `examples/credentials/anthropic.env.placeholder`.
/// This is the single source of truth — the refresh hook rewrites
/// the file from this constant on every refresh, so the real
/// Anthropic key bytes never enter the refresh code path. Any
/// future drift between this string and what
/// `examples/credentials/anthropic.env.placeholder` contains on
/// disk is a real signal — either the README contract changed or
/// the hook regressed. The initial-seed commit's on-disk file
/// matches this template byte-for-byte.
const ANTHROPIC_PLACEHOLDER_BODY: &str = r#"# Live-e2e Anthropic API credential — PLACEHOLDER ONLY
#
# This file documents the expected format + filename of the Anthropic
# credential that the planner-core HTTP fetcher reads at runtime. The
# real API key MUST NOT be checked in; it lives in:
#
#   ~/.config/raxis/credentials/anthropic.env
#
# (or whatever path your operator deployment sources via the
# `RAXIS_ANTHROPIC_KEY_PATH` env var).
#
# The realistic-scenario live-e2e harness instead sources its key
# from `<workspace>/raxis/.env` (line `ANTHROPIC-API-DEV-KEY=...`)
# via `kernel_driver::write_provider_credentials` and writes
# `<data_dir>/providers/anthropic-realism-e2e.toml` (mode 0600) at
# kernel-bootstrap time. The `.env` itself is `.gitignore`d.
#
# Format:
#   ANTHROPIC_API_KEY=sk-ant-api03-...
#
# The harness has a witness — `assert_no_real_anthropic_key` in
# `kernel/tests/extended_e2e_support/kernel_driver.rs` — that
# REJECTS the run if this file contains anything matching the
# real-key regex:
#
#   sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}
#
# The same regex is enforced by the pre-commit guard at
# `raxis/scripts/check-no-real-anthropic-key.sh`. Together they
# prevent accidental key leakage via `git add` of a refreshed
# examples bundle.
#
# See `raxis/live-e2e/examples/README.md` for the full refresh
# contract; `raxis/specs/v2/secrets-model.md §2.5` for the
# operator-supplied-placeholder discipline; and
# `INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01` in
# `raxis/specs/invariants.md §11.10`.

ANTHROPIC_API_KEY=PLACEHOLDER_REPLACE_ME_WITH_REAL_KEY
"#;

/// Per-credential body the harness writes via `write_credentials`.
/// Mirrors the literals in [`write_credentials`] verbatim so a
/// future change there is caught by the
/// `refresh_examples_writes_plan_and_credentials_under_env_gate`
/// unit test (the test reads both sides and asserts they match
/// byte-for-byte).
pub const EXAMPLE_PG_CRED: &str =
    "postgresql://raxis_test:raxis_test_pass@127.0.0.1:54399/raxis_e2e_pg";
pub const EXAMPLE_MONGO_CRED: &str =
    "mongodb://raxis_test:raxis_test_pass@127.0.0.1:27399/raxis_e2e_mongo?authSource=admin";
pub const EXAMPLE_REDIS_CRED: &str = "raxis_test_pass";
pub const EXAMPLE_SMTP_CRED: &str = "live-e2e-upstream-secret";

/// Pre-bundled prompt filenames the auto-refresh mirrors from
/// `raxis/live-e2e/seed/prompts/` into `examples/seed/prompts/`.
/// Kept in lock-step with what `plan_realistic.rs` /
/// `multi_initiative.rs` actually `include_str!`. A new prompt
/// added to the realistic plan WITHOUT being added here would
/// leave the examples mirror incomplete — the
/// `refresh_examples_mirrors_seed_prompts` unit test pins the
/// list.
const EXAMPLE_SEED_PROMPTS: &[&str] = &[
    "allowlist_positive.md",
    "credential_substitution_canary.md",
    "cross_file_refactor.md",
    "dep_fetch_evidence.md",
    "injection_payloads.toml",
    "lint_defect.md",
    "materializer.md",
    "service_round_trip.md",
    "transparent_proxy_real_scripts.md",
];

/// Bundle of paths the auto-refresh hook needs. Built once per
/// iter so the harness call site stays a single function call.
#[derive(Debug, Clone)]
pub struct ExampleRefreshInputs<'a> {
    /// Path to the kernel's live `policy.toml`
    /// (`<data_dir>/policy/policy.toml`). Copied verbatim into
    /// `examples/policy.toml`.
    pub live_policy_toml: &'a Path,
    /// The realistic-plan primary TOML body the harness submits.
    /// Pre-computed by the caller via
    /// [`crate::extended_e2e_support::plan_realistic::realistic_plan_toml`].
    pub plan_primary_toml: &'a str,
    /// The sibling-plan TOML body. Pre-computed by the caller via
    /// [`crate::extended_e2e_support::multi_initiative::sibling_plan_toml`].
    pub plan_sibling_toml: &'a str,
    /// Workspace root containing the canonical
    /// `raxis/live-e2e/seed/prompts/` source the mirror copies
    /// from. Mirrors [`realism_workspace_root`].
    pub workspace_root: &'a Path,
}

/// Optionally refresh the checked-in
/// `raxis/live-e2e/examples/` bundle.
///
/// Behaviour:
///
///   * **Default (env unset / != "1"):** returns `None` immediately;
///     the worktree is left untouched.
///   * **Opt-in (`RAXIS_E2E_REFRESH_EXAMPLES=1`):** locates the
///     repo's `raxis/live-e2e/examples/` directory, rewrites every
///     file from the harness's authoritative source (`live_policy_toml`
///     for `policy.toml`, the pre-built plan TOMLs, the
///     [`write_credentials`]-mirroring credential bodies, the
///     hardcoded Anthropic placeholder template, the verbatim copy
///     of `live-e2e/seed/prompts/`), and at end of refresh runs
///     [`assert_no_real_anthropic_key`] over
///     `examples/credentials/`. Returns the absolute path of the
///     refreshed directory so the harness can surface it in the
///     post-run Tier-3 artifact block.
///
/// **Where in the harness this runs:** AFTER plan TOMLs are
/// assembled but BEFORE the kernel daemon starts. A refresh
/// failure (missing examples/ dir, real-key match in the
/// placeholder, etc.) short-circuits the whole iter — no
/// half-baked examples diff can land.
///
/// # Panics
///
/// * If `RAXIS_E2E_REFRESH_EXAMPLES=1` but the
///   `raxis/live-e2e/examples/` directory does not exist in the
///   workspace. This means the layout changed and the harness
///   needs an update; we deliberately fail loudly rather than
///   silently `mkdir -p` because the new layout is a real signal.
/// * If `assert_no_real_anthropic_key` finds a real-key match.
///   The panic message carries a copy-pastable remediation hint.
/// * On any I/O error while writing the refreshed files. The
///   refresh is intentionally `panic!`-on-error so the failure
///   mode is identical to every other harness invariant.
pub fn maybe_refresh_examples(inputs: ExampleRefreshInputs<'_>) -> Option<PathBuf> {
    if std::env::var(REFRESH_EXAMPLES_ENV).as_deref() != Ok("1") {
        return None;
    }
    let examples_dir = inputs.workspace_root.join("live-e2e/examples");
    assert!(
        examples_dir.is_dir(),
        "[realism-e2e] {REFRESH_EXAMPLES_ENV}=1 set but {} does not exist; \
         the layout changed and `maybe_refresh_examples` needs an update. \
         (Or run the refresh from a checkout that has the examples bundle.)",
        examples_dir.display(),
    );
    refresh_examples_inner(&examples_dir, inputs);
    Some(examples_dir)
}

/// Inner refresh — extracted so the unit test can drive it
/// against a tmpdir fixture WITHOUT depending on the
/// `RAXIS_E2E_REFRESH_EXAMPLES` env var (env-var
/// side-effects across parallel tests are notoriously brittle).
/// Pub-crate so the test can call it; the public API is
/// [`maybe_refresh_examples`].
pub(crate) fn refresh_examples_inner(examples_dir: &Path, inputs: ExampleRefreshInputs<'_>) {
    // 1. policy.toml — copy verbatim from the kernel's live file.
    let dest_policy = examples_dir.join("policy.toml");
    let policy_body = std::fs::read(inputs.live_policy_toml).unwrap_or_else(|e| {
        panic!(
            "[realism-e2e] refresh_examples: read live policy.toml {}: {e}",
            inputs.live_policy_toml.display(),
        )
    });
    std::fs::write(&dest_policy, &policy_body).unwrap_or_else(|e| {
        panic!(
            "[realism-e2e] refresh_examples: write {}: {e}",
            dest_policy.display(),
        )
    });

    // 2. plan_primary.toml + plan_sibling.toml — pre-assembled by
    // the caller from the same constants the harness submits, so
    // there's no byte drift risk between the example and what the
    // kernel actually saw.
    std::fs::write(
        examples_dir.join("plan_primary.toml"),
        inputs.plan_primary_toml,
    )
    .unwrap_or_else(|e| panic!("[realism-e2e] refresh_examples: write plan_primary.toml: {e}",));
    std::fs::write(
        examples_dir.join("plan_sibling.toml"),
        inputs.plan_sibling_toml,
    )
    .unwrap_or_else(|e| panic!("[realism-e2e] refresh_examples: write plan_sibling.toml: {e}",));

    // 3. credentials/*.env — mirror what `write_credentials` writes.
    let creds_dir = examples_dir.join("credentials");
    std::fs::create_dir_all(&creds_dir).unwrap_or_else(|e| {
        panic!(
            "[realism-e2e] refresh_examples: mkdir {}: {e}",
            creds_dir.display()
        )
    });
    for (name, body) in [
        ("test-pg-dev.env", EXAMPLE_PG_CRED),
        ("test-mongo-dev.env", EXAMPLE_MONGO_CRED),
        ("test-redis-dev.env", EXAMPLE_REDIS_CRED),
        ("test-smtp-dev.env", EXAMPLE_SMTP_CRED),
    ] {
        let p = creds_dir.join(name);
        std::fs::write(&p, body).unwrap_or_else(|e| {
            panic!("[realism-e2e] refresh_examples: write {}: {e}", p.display())
        });
    }

    // 4. anthropic.env.placeholder — rewritten from the hardcoded
    // template. The real Anthropic key value at
    // `<data_dir>/providers/anthropic-realism-e2e.toml` is NOT
    // consulted; the placeholder body is the same constant on
    // every refresh, so a real key can never leak through the
    // refresh path.
    let anth = creds_dir.join("anthropic.env.placeholder");
    std::fs::write(&anth, ANTHROPIC_PLACEHOLDER_BODY).unwrap_or_else(|e| {
        panic!(
            "[realism-e2e] refresh_examples: write {}: {e}",
            anth.display()
        )
    });

    // 5. seed/prompts/* — verbatim copy of the canonical seed
    // prompts the realistic plan `include_str!`s. Keeping the
    // mirror in lock-step lets an operator skimming `examples/`
    // see the complete bundle without cross-referencing
    // `live-e2e/seed/prompts/` separately.
    let dest_prompts = examples_dir.join("seed").join("prompts");
    std::fs::create_dir_all(&dest_prompts).unwrap_or_else(|e| {
        panic!(
            "[realism-e2e] refresh_examples: mkdir {}: {e}",
            dest_prompts.display(),
        )
    });
    let src_prompts = inputs.workspace_root.join("live-e2e/seed/prompts");
    for name in EXAMPLE_SEED_PROMPTS {
        let src = src_prompts.join(name);
        let dst = dest_prompts.join(name);
        let body = std::fs::read(&src).unwrap_or_else(|e| {
            panic!(
                "[realism-e2e] refresh_examples: read seed prompt {}: {e}",
                src.display(),
            )
        });
        std::fs::write(&dst, body).unwrap_or_else(|e| {
            panic!(
                "[realism-e2e] refresh_examples: write seed prompt {}: {e}",
                dst.display(),
            )
        });
    }

    // 6. Witness: scan everything under `credentials/` for the
    // real Anthropic-key regex. If a match is found we panic
    // with a copy-pastable remediation hint BEFORE the kernel
    // daemon starts, so the failed iter never produces an
    // examples diff that could be `git add`-ed.
    assert_no_real_anthropic_key(examples_dir);
}

/// INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01 witness. Scans every
/// file under `<examples_dir>/credentials/` for the real
/// Anthropic-key regex
/// `sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}` and panics with a
/// copy-pastable remediation hint on the first match. Called by
/// [`refresh_examples_inner`] as the LAST step of the refresh,
/// so a real key in any credential file fails the whole iter
/// before the kernel even spawns.
///
/// Implementation note: we deliberately do NOT depend on the
/// `regex` crate here. The pattern is simple enough to scan
/// byte-by-byte, and avoiding the dep keeps `kernel_driver.rs`'s
/// build graph minimal. The same regex is enforced by
/// `raxis/scripts/check-no-real-anthropic-key.sh` at commit
/// time; that script does use `rg`/`grep -P`.
pub fn assert_no_real_anthropic_key(examples_dir: &Path) {
    let creds_dir = examples_dir.join("credentials");
    if !creds_dir.is_dir() {
        // The refresh hook creates the dir before calling us, so
        // a missing dir here means a caller invoked the witness
        // independently against an empty examples_dir. That is
        // not a security failure — there is nothing to check.
        return;
    }
    let entries = std::fs::read_dir(&creds_dir).unwrap_or_else(|e| {
        panic!(
            "[realism-e2e] assert_no_real_anthropic_key: read_dir {}: {e}",
            creds_dir.display(),
        )
    });
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| {
            panic!(
                "[realism-e2e] assert_no_real_anthropic_key: dir entry under {}: {e}",
                creds_dir.display(),
            )
        });
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let body = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "[realism-e2e] assert_no_real_anthropic_key: read {}: {e}",
                path.display(),
            )
        });
        if let Some(hit) = find_real_anthropic_key(&body) {
            panic!(
                "[realism-e2e] INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01 \
                 VIOLATED: real-looking Anthropic API key found in {}:\n\
                 \n  matched bytes: `{}`\n\n\
                 The only allowed Anthropic-credential file in \
                 examples/credentials/ is anthropic.env.placeholder, and \
                 its value MUST NOT match the real-key regex \
                 sk-ant-api[0-9]{{2}}-[A-Za-z0-9_-]{{20,}}.\n\n\
                 Remediation:\n  \
                   1. git checkout {}\n  \
                   2. Inspect maybe_refresh_examples in \
                 kernel/tests/extended_e2e_support/kernel_driver.rs — \
                 a regression there is the only way a real key reaches \
                 this code path (the refresh rewrites the file from a \
                 hardcoded template, NOT from the loaded \
                 ANTHROPIC-API-DEV-KEY value).\n  \
                   3. If you intentionally pasted a real key into this \
                 file, ROTATE THE KEY IN YOUR ANTHROPIC CONSOLE \
                 IMMEDIATELY — assume it is compromised the moment it \
                 touched the worktree.",
                path.display(),
                hit,
                path.display(),
            );
        }
    }
}

/// Byte-scan helper for [`assert_no_real_anthropic_key`].
///
/// Searches `body` for the regex
/// `sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}` and returns the
/// matching substring on the first hit. We hand-roll this
/// instead of pulling in `regex` because the kernel test crate's
/// build graph already pays a heavy compile-time tax and adding
/// `regex` for one literal-prefix scan is wildly out of
/// proportion.
fn find_real_anthropic_key(body: &[u8]) -> Option<String> {
    const PREFIX: &[u8] = b"sk-ant-api";
    let mut i = 0;
    while i + PREFIX.len() < body.len() {
        if !body[i..].starts_with(PREFIX) {
            i += 1;
            continue;
        }
        let after_prefix = i + PREFIX.len();
        // Two ASCII digits.
        if after_prefix + 2 >= body.len()
            || !body[after_prefix].is_ascii_digit()
            || !body[after_prefix + 1].is_ascii_digit()
        {
            i += 1;
            continue;
        }
        let dash = after_prefix + 2;
        if body[dash] != b'-' {
            i += 1;
            continue;
        }
        // Body: at least 20 chars of `[A-Za-z0-9_-]`.
        let body_start = dash + 1;
        let mut end = body_start;
        while end < body.len() && is_key_body_char(body[end]) {
            end += 1;
        }
        if end - body_start >= 20 {
            let slice = &body[i..end];
            return Some(String::from_utf8_lossy(slice).into_owned());
        }
        i += 1;
    }
    None
}

#[inline]
fn is_key_body_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

// ---------------------------------------------------------------------------
// Operator IPC — generic over plan TOML body.
// ---------------------------------------------------------------------------

pub struct OperatorIpc {
    pub stream: UnixStream,
    /// Operator signing key, used by `submit_plan` and
    /// `approve_plan`. Captured at connect time so callers don't
    /// need to thread it through every call site.
    seed: [u8; 32],
}

impl OperatorIpc {
    pub fn connect(
        socket_path: &Path,
        signing_key: &SigningKey,
        seed: [u8; 32],
        _fingerprint: &OperatorFingerprint,
    ) -> Self {
        let mut stream = UnixStream::connect(socket_path)
            .unwrap_or_else(|e| panic!("connect {}: {e}", socket_path.display()));

        let challenge = read_json_blocking(&mut stream);
        let challenge_hex = challenge["challenge_hex"]
            .as_str()
            .expect("kernel sends challenge_hex");
        let challenge_bytes = hex::decode(challenge_hex).expect("challenge_hex is hex");
        assert_eq!(challenge_bytes.len(), 32, "challenge is 32 bytes");

        let sig = signing_key.sign(&challenge_bytes);
        let pubkey = signing_key.verifying_key().to_bytes();
        let policy_fingerprint_hex = policy_fingerprint_32(&pubkey);
        let response = serde_json::json!({
            "fingerprint":          policy_fingerprint_hex,
            "signed_challenge_hex": hex::encode(sig.to_bytes()),
        });
        write_json_frame(&mut stream, &response).expect("write auth response");

        let ack = read_json_blocking(&mut stream);
        assert_eq!(
            ack["status"].as_str(),
            Some("Ok"),
            "kernel rejected auth: {ack:#}",
        );

        Self { stream, seed }
    }

    /// Submit `plan_toml` verbatim as the plan bundle for
    /// `initiative_id`. Caller chose the plan body — this method
    /// only handles signing + framing.
    pub fn submit_plan(&mut self, initiative_id: &str, plan_toml: &str) {
        let bundle = build_plan_bundle(plan_toml);
        let canonical = canonical_encode(&bundle).expect("canonical_encode");
        let bundle_sha = crypto_bundle_sha256(&canonical);
        let signing_key = SigningKey::from_bytes(&self.seed);
        let sig_input = signing_input(&bundle_sha);
        let signature = signing_key.sign(&sig_input);
        let pubkey = signing_key.verifying_key().to_bytes();
        let fingerprint = fingerprint_8(&pubkey);

        let req = serde_json::json!({
            "op": "CreateInitiative",
            "payload": {
                "initiative_id":     initiative_id,
                "plan_bundle_hex":   hex::encode(&canonical),
                "bundle_sha256_hex": hex::encode(bundle_sha.as_bytes()),
                "signature_hex":     hex::encode(signature.to_bytes()),
                "signed_by_hex":     hex::encode(fingerprint.as_bytes()),
            },
        });
        write_json_frame(&mut self.stream, &req).expect("write CreateInitiative");
        let resp = read_json_blocking(&mut self.stream);
        assert_eq!(
            resp["status"].as_str(),
            Some("InitiativeCreated"),
            "CreateInitiative must succeed; got: {resp:#}",
        );
        let returned_id = resp["payload"]["initiative_id"]
            .as_str()
            .expect("InitiativeCreated carries payload.initiative_id");
        assert_eq!(returned_id, initiative_id, "initiative id roundtrip");
    }

    pub fn approve_plan(&mut self, initiative_id: &str, _fingerprint: &OperatorFingerprint) {
        let signing_key = SigningKey::from_bytes(&self.seed);
        let pubkey = signing_key.verifying_key().to_bytes();
        let approving_operator_32 = policy_fingerprint_32(&pubkey);
        let req = serde_json::json!({
            "op": "ApprovePlan",
            "payload": {
                "initiative_id":      initiative_id,
                "approving_operator": approving_operator_32,
            },
        });
        write_json_frame(&mut self.stream, &req).expect("write ApprovePlan");
        let resp = read_json_blocking(&mut self.stream);
        assert_eq!(
            resp["status"].as_str(),
            Some("PlanApproved"),
            "ApprovePlan must succeed; got: {resp:#}",
        );
    }
}

fn read_json_blocking(stream: &mut UnixStream) -> Value {
    let body = read_json_frame_raw(stream).expect("read kernel frame");
    serde_json::from_str(&body).expect("kernel frame is JSON")
}

fn build_plan_bundle(plan_toml: &str) -> PlanBundle {
    let plan_bytes = plan_toml.as_bytes().to_vec();
    let plan_sha = sha256_of_artifact_bytes(&plan_bytes);
    let artifacts = vec![BundleArtifact {
        name: "plan.toml".to_owned(),
        bytes: plan_bytes,
        sha256: plan_sha,
    }];
    let signed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let nonce = mint_bundle_nonce().expect("mint_bundle_nonce");
    PlanBundle::new_v2_1(
        signed_at,
        signed_at,
        nonce,
        "/raxis/realism-e2e".to_owned(),
        artifacts,
    )
}

#[cfg(target_os = "macos")]
fn codesign_kernel_for_avf(kernel_bin: &Path) {
    let mut anchor = kernel_bin
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    loop {
        let manifest = anchor.join("Cargo.toml");
        if manifest.exists() {
            if let Ok(s) = std::fs::read_to_string(&manifest) {
                if s.contains("[workspace]") {
                    break;
                }
            }
        }
        if !anchor.pop() {
            eprintln!(
                "[realism-e2e] codesign: workspace root not found from {}",
                kernel_bin.display()
            );
            return;
        }
    }
    let entitlements = anchor.join("release/raxis.entitlements");
    if !entitlements.exists() {
        eprintln!(
            "[realism-e2e] codesign: entitlements missing at {}",
            entitlements.display()
        );
        return;
    }
    let status = Command::new("codesign")
        .arg("--sign")
        .arg("-")
        .arg("--entitlements")
        .arg(&entitlements)
        .arg("--options")
        .arg("runtime")
        .arg("--force")
        .arg(kernel_bin)
        .status()
        .expect("codesign required for AVF on macOS");
    if !status.success() {
        panic!(
            "codesign failed (exit {:?}) for {}",
            status.code(),
            kernel_bin.display()
        );
    }
}

fn fingerprint_8(pubkey: &[u8; 32]) -> OperatorFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let hash = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    OperatorFingerprint::new(out)
}

fn policy_fingerprint_32(pubkey: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

// ---------------------------------------------------------------------------
// Audit-chain polling + post-mortem.
// ---------------------------------------------------------------------------

/// Default deadline for the realistic scenario lifecycle. Larger
/// than the extended scenario's 15 min because the realistic plan
/// carries materializer + cross-file refactor + lint-defect +
/// path-allowlist + secrets + reviewer-substantive + sibling
/// initiative — three executor re-spawns and two review rounds
/// across two initiatives, plus a one-shot sibling initiative.
///
/// **Empirical sizing (Live-e2e iter31, 2026-05-13).** The
/// realistic plan submits **9 primary-lane tasks + 1 sibling
/// task = 10 executor sessions**. Each session is one Apple-VZ
/// VM boot (~30 s) + 1-5 min of planner dispatch + 1 orchestrator
/// respawn cycle in between (~15 s). The empirical wall-clock
/// breakdown observed in iter31 was: 6 primary tasks completed
/// in 25 min (avg ~4 min / task), with 3 tasks still
/// `Admitted` + 1 task `Active` at the 1800 s deadline. Linear
/// extrapolation: 10 tasks × ~4 min = ~40 min + integration-merge
/// orchestrator + sibling initiative ≈ 50 min worst case.
/// `3600` (60 min) gives the lifecycle deadline 20 % headroom
/// over the linear projection, and the harness still cleanly
/// fast-fails on any spawn-failure event via
/// `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01` so the deadline
/// is the worst-case wait, not the typical wait.
pub fn realistic_lifecycle_deadline() -> Duration {
    let secs = std::env::var("RAXIS_E2E_REALISTIC_DEADLINE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600); // 60 min
    Duration::from_secs(secs)
}

/// Poll the audit chain until BOTH `initiative_ids` emit
/// `IntegrationMergeCompleted`. Surfaces `SecurityViolation`
/// AND `OrchestratorRespawnCeilingExceeded` (per
/// `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`) instantly.
/// Returns the merged chain at completion.
///
/// **Fast-fail on `OrchestratorRespawnCeilingExceeded`** (per
/// `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`): when the per-
/// initiative no-progress respawn counter exceeds its ceiling
/// (`INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01`), the kernel
/// commits `initiatives.state = 'Failed'` in the same paired
/// write that emits the chain-side audit row. No further audit
/// events fire on that initiative's lane, so polling for
/// `IntegrationMergeCompleted` is a guaranteed indefinite wait.
/// The chain-side scan in the poll loop panics immediately with
/// the upstream blind-ask hypothesis cited so the operator can
/// triage the LLM behaviour in seconds.
///
/// **Fast-fail on terminal spawn failure** (extension of
/// `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`):
/// the kernel emits structured terminal-failure events on
/// `stderr` after exhausting its transient-retry budget for a
/// session VM. Two event shapes both qualify as a terminal
/// failure that the harness must surface:
///
///   * `orchestrator_spawn_failed` — the root Orchestrator VM
///     for an initiative could not be spawned. Emitted by
///     `kernel/src/ipc/operator.rs::handle_approve_plan_op`.
///   * `ActivateSubTaskSpawnFailed` — an Executor or Reviewer
///     sub-session VM for a sub-task of the initiative could
///     not be spawned (cpio.gz unpack ENOSPC, vsock listener
///     bind timeout, kernel-config mismatch on the AVF kernel,
///     …). Emitted by
///     `kernel/src/handlers/intent.rs::handle_activate_sub_task`.
///
/// Once either event lands for one of the watched initiatives
/// the lifecycle cannot make further progress without an
/// operator command (`recovery::reconcile` is not driven by
/// the harness), so polling further is a guaranteed indefinite
/// wait. The harness scans `<data_dir>/kernel.stderr.log` for
/// the matching JSON token on every poll iteration and panics
/// immediately with the kernel's own `error` + `hint` fields
/// surfaced so the operator sees the root cause in seconds
/// instead of waiting 30 min for
/// [`realistic_lifecycle_deadline`].
///
/// The bound on filesystem reads is the deadline itself: the
/// scan reads only the NEW bytes of `kernel.stderr.log` at most
/// once per 500 ms (the existing poll cadence) via a
/// byte-offset cursor (`StderrTailScanner`). On long runs with
/// verbose logging this avoids the previous O(N²) behaviour
/// where each iteration re-read the entire log from byte zero.
pub fn poll_for_dual_lifecycle_completion(
    data_dir: &Path,
    initiative_ids: [&str; 2],
    deadline: Duration,
) -> Vec<AuditEvent> {
    let audit_dir = data_dir.join("audit");
    let stderr_path = data_dir.join("kernel.stderr.log");
    let start = Instant::now();
    let mut last_len = 0usize;
    let mut tail = StderrTailScanner::new();
    loop {
        if start.elapsed() > deadline {
            let stderr_tail = std::fs::read_to_string(&stderr_path)
                .ok()
                .map(|s| {
                    let lines: Vec<&str> = s.lines().collect();
                    let n = lines.len();
                    let take = n.min(60);
                    lines[n.saturating_sub(take)..].join("\n")
                })
                .unwrap_or_else(|| "<no kernel.stderr.log on disk>".to_owned());
            panic!(
                "realistic dual-lifecycle deadline of {deadline:?} exceeded \
                 without IntegrationMergeCompleted for both {} and {}; \
                 audit chain at exit ({} events):\n{}\n\n\
                 ── kernel.stderr (tail) ──\n{}",
                initiative_ids[0],
                initiative_ids[1],
                last_len,
                summarize_chain_for_panic(&audit_dir),
                stderr_tail,
            );
        }

        // Fast-fail on terminal `orchestrator_spawn_failed` for either
        // watched initiative. See the function-level docstring for the
        // rationale; without this branch a substrate that fails every
        // spawn attempt (e.g. an apple-vz host that cannot map the
        // canonical image because the kernel's trust anchor is
        // unpopulated and the verifier silently degraded to
        // `RootfsErofs`) leaves the test waiting the full
        // [`realistic_lifecycle_deadline`] for an event that will
        // never arrive.
        if let Some(failure) = tail.scan_for_terminal_spawn_failure(&stderr_path, &initiative_ids) {
            let stderr_tail = std::fs::read_to_string(&stderr_path)
                .ok()
                .map(|s| {
                    let lines: Vec<&str> = s.lines().collect();
                    let n = lines.len();
                    let take = n.min(60);
                    lines[n.saturating_sub(take)..].join("\n")
                })
                .unwrap_or_else(|| "<no kernel.stderr.log on disk>".to_owned());
            panic!(
                "kernel emitted terminal `{event}` \
                 for initiative {bad_initiative}{role_tail} after exhausting its \
                 transient-retry budget; the lifecycle cannot complete \
                 without operator-driven recovery, so the harness will \
                 not poll further (would be a guaranteed indefinite \
                 wait per INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01).\n\
                 \n\
                 kernel.error: {error}\n\
                 kernel.hint:  {hint}\n\
                 \n\
                 ── kernel.stderr (tail) ──\n{stderr_tail}",
                event = failure.event,
                bad_initiative = failure.initiative_id,
                role_tail = failure
                    .agent_kind
                    .as_deref()
                    .map(|k| format!(" (sub-task role={k})"))
                    .unwrap_or_default(),
                error = failure.error,
                hint = failure.hint,
            );
        }

        let events = match read_audit_chain(&audit_dir) {
            Ok(e) => e,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
        };
        last_len = events.len();

        for e in &events {
            if e.event_kind == "SecurityViolation" || e.event_kind == "SecurityViolationDetected" {
                panic!(
                    "SecurityViolation fired during realistic lifecycle: \
                     event_kind={}, payload={:#}",
                    e.event_kind, e.payload,
                );
            }
            // Fast-fail on `OrchestratorRespawnCeilingExceeded` for
            // either watched initiative. The kernel emits this event
            // AND commits `initiatives.state = 'Failed'` in one paired
            // write
            // (`session_spawn_orchestrator.rs::orchestrator_post_exit_respawn_trigger`)
            // — the initiative is now terminal and no further audit
            // events fire on its lane. Without this branch the harness
            // would poll the full `realistic_lifecycle_deadline` for an
            // `IntegrationMergeCompleted` that will never arrive (the
            // same indefinite-wait class the spawn-failure scanner
            // above covers per `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`).
            // iter48 reproduced this (then on the legacy Tier1Tproxy
            // egress, since removed in favour of Mediated)
            // supervisor-free when the orchestrator NNSP blind-asked
            // `retry_subtask`
            // against a `lint-defect` task whose
            // `capabilities.tasks[*].retry_admissible=false reason="prior
            // state PendingActivation; …"` — the kernel correctly
            // rejected each retry per
            // `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01` and the
            // ceiling fired after three no-progress respawn cycles.
            if e.event_kind == "OrchestratorRespawnCeilingExceeded" {
                if let Some(bad_initiative) = e.initiative_id.as_deref() {
                    if initiative_ids.contains(&bad_initiative) {
                        let stderr_tail = std::fs::read_to_string(&stderr_path)
                            .ok()
                            .map(|s| {
                                let lines: Vec<&str> = s.lines().collect();
                                let n = lines.len();
                                let take = n.min(60);
                                lines[n.saturating_sub(take)..].join("\n")
                            })
                            .unwrap_or_else(|| "<no kernel.stderr.log on disk>".to_owned());
                        panic!(
                            "kernel emitted terminal \
                             `OrchestratorRespawnCeilingExceeded` for \
                             initiative {bad_initiative} (payload: {payload:#}); \
                             the per-initiative no-progress respawn ceiling \
                             has been reached and the kernel has marked the \
                             initiative `Failed` — the lifecycle cannot \
                             complete without operator-driven recovery, so \
                             the harness will not poll further (would be a \
                             guaranteed indefinite wait per \
                             INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01). \
                             Common upstream cause: orchestrator NNSP \
                             blind-asks `retry_subtask` against a task whose \
                             `capabilities.tasks[*].retry_admissible=false` — \
                             see `crates/planner-core/src/driver.rs` rule \
                             3a + `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`.\n\
                             \n\
                             ── kernel.stderr (tail) ──\n{stderr_tail}",
                            payload = e.payload,
                        );
                    }
                }
            }
        }

        let merged_a = events.iter().any(|e| {
            e.event_kind == "IntegrationMergeCompleted"
                && e.initiative_id.as_deref() == Some(initiative_ids[0])
        });
        let merged_b = events.iter().any(|e| {
            e.event_kind == "IntegrationMergeCompleted"
                && e.initiative_id.as_deref() == Some(initiative_ids[1])
        });
        if merged_a && merged_b {
            return events;
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Structured shape returned by [`scan_stderr_for_terminal_spawn_failure`]
/// when a terminal spawn-failure event is observed against one of the
/// watched initiatives. The `event` field distinguishes the two
/// terminal-failure schemas the kernel can emit (orchestrator vs
/// sub-task) so the surfaced panic body can format both uniformly.
#[derive(Debug)]
struct TerminalSpawnFailure {
    /// `"orchestrator_spawn_failed"` or
    /// `"ActivateSubTaskSpawnFailed"` — verbatim from the JSON
    /// `event` field.
    event: String,
    /// Watched initiative whose lifecycle is now blocked.
    initiative_id: String,
    /// Sub-task role (`Executor` / `Reviewer`) for
    /// `ActivateSubTaskSpawnFailed`; `None` for the orchestrator
    /// schema (whose role is implied).
    agent_kind: Option<String>,
    /// Kernel's `error` field, surfaced verbatim.
    error: String,
    /// Kernel's `hint` field, surfaced verbatim.
    hint: String,
}

/// Cursor over `kernel.stderr.log` that remembers how many bytes
/// have already been scanned, so the polling loop only inspects
/// new bytes on each iteration.
///
/// Without this, a 60-minute realistic-scenario run with verbose
/// kernel logging makes the watchdog re-read the entire log file
/// every 500 ms — O(N²) on log size — which can pin a core and
/// inflate iteration latency to the point of starving the audit
/// poll itself.
///
/// The cursor only advances past complete (newline-terminated)
/// lines. A trailing partial line (write-in-progress, kernel
/// buffer not yet flushed) stays unscanned and is re-read on the
/// next iteration. False-positive cost is bounded to one
/// partial-line read per iteration.
pub(crate) struct StderrTailScanner {
    offset: u64,
}

impl StderrTailScanner {
    pub(crate) fn new() -> Self {
        Self { offset: 0 }
    }

    /// Scan only the new (post-cursor) bytes for either of the
    /// kernel's terminal spawn-failure JSON lines bound to one of
    /// `watched_initiatives`. Returns a [`TerminalSpawnFailure`] on
    /// the first match, `None` otherwise. Advances the cursor past
    /// every complete line read.
    fn scan_for_terminal_spawn_failure(
        &mut self,
        stderr_path: &Path,
        watched_initiatives: &[&str; 2],
    ) -> Option<TerminalSpawnFailure> {
        use std::io::{Read, Seek, SeekFrom};

        let mut file = std::fs::File::open(stderr_path).ok()?;
        let file_len = file.metadata().ok()?.len();
        // Log rotation / truncation: cursor would be past EOF;
        // restart from the beginning so we don't silently miss
        // the new file's contents.
        if self.offset > file_len {
            self.offset = 0;
        }
        file.seek(SeekFrom::Start(self.offset)).ok()?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).ok()?;
        if bytes.is_empty() {
            return None;
        }
        // Only inspect complete (newline-terminated) lines; carry
        // any trailing partial line over to the next iteration.
        let last_newline = bytes.iter().rposition(|&b| b == b'\n');
        let scan_end = match last_newline {
            Some(idx) => idx + 1,
            // No newline yet in the new bytes — entire buffer is a
            // partial line. Don't advance the cursor.
            None => return None,
        };
        let scan_bytes = &bytes[..scan_end];
        let hit = scan_stderr_bytes(scan_bytes, watched_initiatives);
        self.offset = self.offset.saturating_add(scan_end as u64);
        hit
    }
}

/// Test-friendly wrapper: scan a stderr fixture from the
/// beginning each call. Production callers use
/// [`StderrTailScanner`] to avoid re-reading old bytes.
fn scan_stderr_for_terminal_spawn_failure(
    stderr_path: &Path,
    watched_initiatives: &[&str; 2],
) -> Option<TerminalSpawnFailure> {
    StderrTailScanner::new().scan_for_terminal_spawn_failure(stderr_path, watched_initiatives)
}

/// Scan a byte slice (one or more newline-terminated JSON lines)
/// for either of the kernel's terminal spawn-failure events
/// bound to one of `watched_initiatives`.
///
/// The two schemas we match on, verbatim from the kernel:
///
/// ```jsonc
/// // orchestrator root-VM failure (kernel/src/ipc/operator.rs):
/// {"level":"error","event":"orchestrator_spawn_failed",
///  "initiative_id":"019e20c9-…","session_id":"…",
///  "error":"session-spawn failed: …",
///  "hint":"PlanApproved was committed; …"}
///
/// // sub-task (executor/reviewer) VM failure
/// // (kernel/src/handlers/intent.rs::handle_activate_sub_task):
/// {"level":"error","event":"ActivateSubTaskSpawnFailed",
///  "task_id":"…","new_session_id":"…",
///  "initiative_id":"019e20c9-…","agent_kind":"Executor",
///  "error":"…","hint":"sub-task activation exhausted its …"}
/// ```
///
/// We intentionally do NOT match on
/// `session_vm_transient_retry` — those are mid-flight retries
/// the kernel may still resolve. Only the two
/// `*_spawn_failed` / `*SpawnFailed` events are *terminal* for
/// the boot path.
fn scan_stderr_bytes(
    bytes: &[u8],
    watched_initiatives: &[&str; 2],
) -> Option<TerminalSpawnFailure> {
    /// Token shared by both terminal-failure event names.
    const TERMINAL_TOKEN: &[u8] = b"SpawnFailed";
    /// The historical orchestrator schema uses snake_case.
    const ORCH_TOKEN: &[u8] = b"orchestrator_spawn_failed";

    for line in bytes.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        // Cheap pre-filter so we don't parse every line as JSON.
        // We accept either spelling because the two schemas differ
        // in case but share the "SpawnFailed" / "spawn_failed"
        // tail; the second `memmem` keeps the false-positive rate
        // low for unrelated `*spawn_failed*` log lines like
        // `gateway_spawn_failed` (gateway / git-push spawn failure
        // never causes the lifecycle to wedge).
        if !memmem(line, TERMINAL_TOKEN) && !memmem(line, ORCH_TOKEN) {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let event = match value.get("event").and_then(|e| e.as_str()) {
            Some("orchestrator_spawn_failed") => "orchestrator_spawn_failed",
            Some("ActivateSubTaskSpawnFailed") => "ActivateSubTaskSpawnFailed",
            _ => continue,
        };
        let initiative_id = match value.get("initiative_id").and_then(|i| i.as_str()) {
            Some(s) => s.to_owned(),
            None => continue,
        };
        if !watched_initiatives.iter().any(|w| *w == initiative_id) {
            continue;
        }
        let error = value
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("<no `error` field on terminal spawn-failure event>")
            .to_owned();
        let hint = value
            .get("hint")
            .and_then(|h| h.as_str())
            .unwrap_or("<no `hint` field on terminal spawn-failure event>")
            .to_owned();
        let agent_kind = value
            .get("agent_kind")
            .and_then(|k| k.as_str())
            .map(|s| s.to_owned());
        return Some(TerminalSpawnFailure {
            event: event.to_owned(),
            initiative_id,
            agent_kind,
            error,
            hint,
        });
    }
    None
}

/// Byte-level substring search. Cheap pre-filter so the polling
/// loop doesn't pay JSON-parse cost on every stderr line.
fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

pub fn read_audit_chain(audit_dir: &Path) -> Result<Vec<AuditEvent>, ()> {
    if !audit_dir.exists() {
        return Err(());
    }
    let mut events = Vec::new();
    for entry in std::fs::read_dir(audit_dir).map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        if entry.file_name().to_string_lossy().ends_with(".jsonl") {
            let bytes = std::fs::read(entry.path()).map_err(|_| ())?;
            for line in bytes.split(|&b| b == b'\n') {
                if line.is_empty() {
                    continue;
                }
                if let Ok(ev) = serde_json::from_slice::<AuditEvent>(line) {
                    events.push(ev);
                }
            }
        }
    }
    events.sort_by_key(|e| e.seq);
    Ok(events)
}

pub fn summarize_chain_for_panic(audit_dir: &Path) -> String {
    match read_audit_chain(audit_dir) {
        Ok(events) => {
            let kinds: Vec<&str> = events.iter().map(|e| e.event_kind.as_str()).collect();
            format!(
                "seqs={}…{}, kinds={kinds:#?}",
                events.first().map(|e| e.seq).unwrap_or(0),
                events.last().map(|e| e.seq).unwrap_or(0),
            )
        }
        Err(_) => "(audit dir not yet present)".to_owned(),
    }
}

pub fn walk_chain_or_panic(data_dir: &Path) -> Vec<AuditEvent> {
    let audit_dir = data_dir.join("audit");
    verify_chain_full(&audit_dir)
        .unwrap_or_else(|e| panic!("verify_chain_full({audit_dir:?}) failed: {e:?}"));
    let reader = ChainReader::open(&audit_dir)
        .unwrap_or_else(|e| panic!("ChainReader::open({audit_dir:?}) failed: {e:?}"));
    reader
        .records()
        .map(|r| {
            let row = r.unwrap_or_else(|e| panic!("chain record decode failed: {e:?}"));
            let value = row
                .parsed_value
                .unwrap_or_else(|| panic!("chain row seq={} has no parsed_value", row.seq,));
            serde_json::from_value::<AuditEvent>(value)
                .unwrap_or_else(|e| panic!("decode AuditEvent from chain row {}: {e}", row.seq))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Worktree locator.
// ---------------------------------------------------------------------------

/// Resolve the on-disk path of the executor / reviewer worktree
/// for `task_id` by walking the audit chain to the matching
/// `SessionVmSpawned.session_id`.
///
/// **Why audit-chain-based.** The kernel's worktree provisioner
/// writes per-session worktrees at the flat
/// `<data_dir>/worktrees/<session_id>/` layout
/// (`worktree_provisioning::provision_executor_worktree` /
/// `provision_reviewer_worktree`). Orchestrator worktrees use
/// `<data_dir>/worktrees/orch-<initiative_id>/`. The hypothetical
/// `<data_dir>/worktrees/<initiative_id>/<task_id>/` layout the
/// previous helper assumed does not exist on disk and never has —
/// the assumption was a documentation drift carried into the
/// realistic-scenario harness from an earlier V2 prototype.
///
/// This helper takes the resolved audit chain (from
/// `poll_for_dual_lifecycle_completion` / `walk_chain_or_panic`)
/// and resolves `task_id -> session_id` via
/// `locate_session_id_for_task`, then returns the matching
/// worktree path. Panics with a precise diagnostic if either step
/// fails.
pub fn locate_executor_worktree_via_chain(
    data_dir: &Path,
    chain: &[AuditEvent],
    task_id: &str,
) -> PathBuf {
    let session_id = locate_session_id_for_task(chain, task_id).unwrap_or_else(|| {
        panic!(
            "no SessionVmSpawned event for task_id={task_id} in audit chain \
             ({} events); cannot locate executor worktree without a session_id",
            chain.len(),
        )
    });
    let candidate = data_dir.join("worktrees").join(&session_id);
    assert!(
        candidate.exists(),
        "session_id={session_id} for task_id={task_id} found in chain but \
         worktree directory {} does not exist on disk",
        candidate.display(),
    );
    assert!(
        candidate.join(".git").exists(),
        "worktree {} for session_id={session_id} (task_id={task_id}) is not \
         a git repository — kernel-side `provision_executor_worktree` should \
         leave a `.git/` directory behind",
        candidate.display(),
    );
    candidate
}

/// Legacy path-based locator. Retained for callers that pre-date
/// the audit-chain-based locator above. New callers should prefer
/// `locate_executor_worktree_via_chain`. This still searches the
/// historic `<data_dir>/worktrees/<initiative_id>/<task_id>/`
/// layout for compatibility with non-realistic e2e drivers that
/// have not yet migrated.
pub fn locate_executor_worktree(data_dir: &Path, initiative_id: &str, task_id: &str) -> PathBuf {
    let candidates = [
        data_dir.join("worktrees").join(initiative_id).join(task_id),
        data_dir
            .join("workspaces")
            .join(initiative_id)
            .join(task_id),
        data_dir.join("sessions").join(initiative_id).join(task_id),
    ];
    for c in &candidates {
        if c.exists() && c.join(".git").exists() {
            return c.clone();
        }
    }
    panic!(
        "could not locate executor worktree for initiative={initiative_id} \
         task={task_id}; tried {:?}; if this is the realistic-scenario test, \
         migrate the call site to `locate_executor_worktree_via_chain`",
        candidates,
    );
}

// ---------------------------------------------------------------------------
// Misc helpers.
// ---------------------------------------------------------------------------

pub fn workspace_dotenv_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join(".env"))
        .unwrap_or_else(|| PathBuf::from("raxis/.env"))
}

pub fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// First `SessionVmSpawned.session_id` for `task_id` (used to
/// thread per-task session ids into witnesses that key on them).
pub fn locate_session_id_for_task(chain: &[AuditEvent], task_id: &str) -> Option<String> {
    chain.iter().find_map(|ev| match typed(ev) {
        Some(AuditEventKind::SessionVmSpawned {
            session_id,
            task_id: Some(t),
            ..
        }) if t == task_id => Some(session_id),
        _ => None,
    })
}

/// Earliest `seq` of any `SessionVmSpawned{task_id}`. Used by
/// the crash-recovery driver to mark the moment "this task is
/// in-flight" just before delivering SIGTERM.
pub fn first_spawn_seq(chain: &[AuditEvent], task_id: &str) -> Option<u64> {
    chain
        .iter()
        .filter_map(|ev| match typed(ev) {
            Some(AuditEventKind::SessionVmSpawned {
                task_id: Some(t), ..
            }) if t == task_id => Some(ev.seq),
            _ => None,
        })
        .min()
}

// ---------------------------------------------------------------------------
// Tests.
//
// Live-e2e support code is normally exercised only by the gated
// integration tests (`RAXIS_LIVE_E2E_REALISTIC=1`). The unit tests
// below cover the pure-data helpers — most importantly
// [`observability_policy_block`], which MUST round-trip cleanly
// through `toml::from_str` so the kernel doesn't reject our
// injected `[observability]` section at policy-load time. A
// regression here means empty Grafana panels in every subsequent
// fix-loop iteration.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_auto_build_timeout_uses_bounded_defaults() {
        assert_eq!(
            gateway_build_timeout_from_raw(None),
            Duration::from_secs(DEFAULT_GATEWAY_BUILD_TIMEOUT_SECS)
        );
        assert_eq!(
            gateway_build_timeout_from_raw(Some(0)),
            Duration::from_secs(DEFAULT_GATEWAY_BUILD_TIMEOUT_SECS)
        );
        assert_eq!(
            gateway_build_timeout_from_raw(Some(MIN_GATEWAY_BUILD_TIMEOUT_SECS - 1)),
            Duration::from_secs(DEFAULT_GATEWAY_BUILD_TIMEOUT_SECS)
        );
        assert_eq!(
            gateway_build_timeout_from_raw(Some(120)),
            Duration::from_secs(120)
        );
        assert_eq!(
            gateway_build_timeout_from_raw(Some(MAX_GATEWAY_BUILD_TIMEOUT_SECS + 1)),
            Duration::from_secs(DEFAULT_GATEWAY_BUILD_TIMEOUT_SECS)
        );
    }

    #[test]
    fn convention_gateway_paths_prefer_workspace_release_then_debug() {
        let root = PathBuf::from("/tmp/raxis-workspace");
        let paths = convention_gateway_paths(&root);
        assert_eq!(
            paths[0],
            PathBuf::from("/tmp/raxis-workspace/target/release/raxis-gateway")
        );
        assert_eq!(
            paths[1],
            PathBuf::from("/tmp/raxis-workspace/target/debug/raxis-gateway")
        );
    }

    /// The injected block must be a valid TOML document standalone
    /// (no other sections required) AND its `[observability]`
    /// surface must satisfy `ObservabilityConfig::validate` so the
    /// kernel boots with `enabled = true`. If this fails, the
    /// realistic-scenario harness writes a policy.toml the kernel
    /// rejects before opening the operator IPC socket.
    #[test]
    fn observability_policy_block_parses_and_validates() {
        let block = observability_policy_block();

        // 1. Document-level: must parse as TOML.
        let doc: toml::Value = toml::from_str(&block).unwrap_or_else(|e| {
            panic!(
                "observability_policy_block did not parse as TOML: {e}\n\
             ── block ──\n{block}",
            )
        });

        // 2. Spec-level: every required field is present.
        let obs = doc
            .get("observability")
            .and_then(|v| v.as_table())
            .expect("[observability] table present");
        assert_eq!(
            obs.get("enabled").and_then(|v| v.as_bool()),
            Some(true),
            "[observability].enabled must be true",
        );
        assert!(
            doc.get("observability")
                .and_then(|o| o.get("pusher"))
                .and_then(|p| p.as_table())
                .and_then(|p| p.get("otlp_endpoint"))
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with("http://"))
                .unwrap_or(false),
            "[observability.pusher].otlp_endpoint must be an http:// URL",
        );

        // 3. The block does NOT contain the legacy fields the
        //    validator-recommended block in the live-e2e brief
        //    (`exporter`, `endpoint`, `resource_attributes`) which
        //    `RawPolicy` does not understand — those would parse as
        //    unknown fields the kernel rejects in strict mode.
        assert!(
            !block.contains("\nexporter "),
            "block must not include legacy `exporter = ...`"
        );
        assert!(
            !block.contains("\nendpoint "),
            "block must not include legacy `endpoint = ...`"
        );
        assert!(
            !block.contains("resource_attributes"),
            "block must not include legacy `resource_attributes = {{...}}`"
        );
    }

    // ─── orchestrator_spawn_failed fast-fail watchdog ───────────────
    //
    // Regression tests for the audit-poll fast-fail extension of
    // `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`.
    //
    // The scanner is a pure function over a stderr-log file plus the
    // two watched `initiative_id`s; we synthesise the kernel's exact
    // JSON shape in a tempdir and assert detection vs. non-detection
    // on the lines that matter.

    /// The kernel emits `orchestrator_spawn_failed` for an initiative
    /// the harness is waiting on → scan returns `Some` with the
    /// kernel's `error` + `hint` fields surfaced verbatim.
    #[test]
    fn scan_stderr_matches_terminal_spawn_failed_for_watched_initiative() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = tmp.path().join("kernel.stderr.log");
        let initiative_a = "019e20c9-e093-7052-a0d1-1c97ef8b0090";
        let initiative_b = "019e20c9-e093-7052-a0d1-1ca53d8b8fd8";
        let body = format!(
            "{{\"level\":\"info\",\"event\":\"session_vm_transient_retry\",\
              \"session_id\":\"sess-1\",\"attempt\":1}}\n\
             {{\"level\":\"error\",\"event\":\"orchestrator_spawn_failed\",\
              \"initiative_id\":\"{initiative_b}\",\"session_id\":\"sess-7\",\
              \"error\":\"session-spawn failed: apple-vz-14.x: \
              block device rootfs: Invalid disk image. The disk image \
              format is not recognized.\",\
              \"hint\":\"PlanApproved was committed; recovery::reconcile \
              or a follow-up operator command is needed to drive the \
              orchestrator boot once the substrate is available\"}}\n",
        );
        std::fs::write(&log, body).expect("write stderr fixture");

        let hit = scan_stderr_for_terminal_spawn_failure(&log, &[initiative_a, initiative_b])
            .expect("scanner must surface the matching line");
        assert_eq!(
            hit.event, "orchestrator_spawn_failed",
            "event field must propagate verbatim"
        );
        assert_eq!(
            hit.initiative_id, initiative_b,
            "initiative_id of the matched line must surface verbatim"
        );
        assert!(
            hit.agent_kind.is_none(),
            "orchestrator schema has no agent_kind (got: {:?})",
            hit.agent_kind,
        );
        assert!(
            hit.error.contains("Invalid disk image"),
            "kernel `error` field must propagate to the panic body \
             (got: {})",
            hit.error
        );
        assert!(
            hit.hint.contains("recovery::reconcile"),
            "kernel `hint` field must propagate so the operator sees \
             the kernel's own remediation hint (got: {})",
            hit.hint
        );
    }

    /// The sub-task schema (`ActivateSubTaskSpawnFailed`) is the
    /// twin of the orchestrator schema for Executor / Reviewer VMs.
    /// The watchdog must surface both with the same urgency: an
    /// Executor that cannot boot blocks the parent initiative's
    /// completion just as definitively as a root-Orchestrator that
    /// cannot boot. Regression for the
    /// `Kernel panic - not syncing: VFS: Unable to mount root fs`
    /// failure mode on the dev-host AVF substrate (host-capacity.md
    /// §5.1 — under-sized `executor_mem_mib`).
    #[test]
    fn scan_stderr_matches_terminal_subtask_spawn_failed_for_watched_initiative() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = tmp.path().join("kernel.stderr.log");
        let initiative_a = "019e20c9-e093-7052-a0d1-1c97ef8b0090";
        let initiative_b = "019e20c9-e093-7052-a0d1-1ca53d8b8fd8";
        let body = format!(
            "{{\"level\":\"info\",\"event\":\"session_vm_transient_retry\",\
              \"session_id\":\"sess-1\",\"attempt\":1}}\n\
             {{\"level\":\"error\",\"event\":\"ActivateSubTaskSpawnFailed\",\
              \"task_id\":\"sibling-materialize-records\",\
              \"new_session_id\":\"sess-7\",\
              \"initiative_id\":\"{initiative_a}\",\
              \"agent_kind\":\"Executor\",\
              \"error\":\"session-spawn failed: isolation spawn failed: \
              transport fault: apple-vz-14.x: vsock CONNECT 1024: AVF \
              connect_vsock did not succeed within 30s\",\
              \"hint\":\"sub-task activation exhausted its transient-retry \
              budget; the parent initiative cannot make further progress \
              without operator-driven recovery (recovery::reconcile)\"}}\n",
        );
        std::fs::write(&log, body).expect("write stderr fixture");

        let hit = scan_stderr_for_terminal_spawn_failure(&log, &[initiative_a, initiative_b])
            .expect("scanner must surface the sub-task failure line");
        assert_eq!(
            hit.event, "ActivateSubTaskSpawnFailed",
            "event field must propagate verbatim"
        );
        assert_eq!(hit.initiative_id, initiative_a);
        assert_eq!(
            hit.agent_kind.as_deref(),
            Some("Executor"),
            "Executor / Reviewer role must surface in the panic body so \
             the operator knows which canonical image to inspect",
        );
        assert!(
            hit.error.contains("vsock CONNECT 1024"),
            "kernel `error` field must propagate (got: {})",
            hit.error
        );
        assert!(
            hit.hint.contains("sub-task activation exhausted"),
            "kernel `hint` field must propagate (got: {})",
            hit.hint
        );
    }

    /// Unrelated `*spawn_failed*` events (`gateway_spawn_failed`,
    /// `verifier` spawn failure in a gate) must NOT trip the
    /// initiative-lifecycle watchdog. They are independent failure
    /// modes the kernel surfaces via separate audit-event paths;
    /// folding them into the audit-poll watchdog would short-circuit
    /// the gateway-respawn supervisor's own retry budget before it
    /// has a chance to recover.
    #[test]
    fn scan_stderr_ignores_unrelated_spawn_failed_events() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = tmp.path().join("kernel.stderr.log");
        let initiative_watched = "019e20c9-e093-7052-a0d1-1c97ef8b0090";
        let body = format!(
            "{{\"level\":\"error\",\"event\":\"gateway_spawn_failed\",\
              \"binary_path\":\"/var/empty/raxis-gateway\",\"attempt\":1,\
              \"reason\":\"No such file or directory\"}}\n\
             {{\"level\":\"error\",\"event\":\"orchestrator_respawn_failed\",\
              \"initiative_id\":\"{initiative_watched}\",\"reason\":\"…\"}}\n",
        );
        std::fs::write(&log, body).expect("write stderr fixture");

        let hit =
            scan_stderr_for_terminal_spawn_failure(&log, &[initiative_watched, initiative_watched]);
        assert!(
            hit.is_none(),
            "unrelated spawn-failed events (gateway / respawn) must NOT \
             trip the audit-poll watchdog; got {hit:?}",
        );
    }

    /// `session_vm_transient_retry` is a mid-flight retry the kernel
    /// may still resolve — it must NOT trip the fast-fail watchdog.
    /// Only the terminal `orchestrator_spawn_failed` line should.
    #[test]
    fn scan_stderr_ignores_transient_retry_lines() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = tmp.path().join("kernel.stderr.log");
        let initiative_a = "019e20c9-e093-7052-a0d1-1c97ef8b0090";
        let initiative_b = "019e20c9-e093-7052-a0d1-1ca53d8b8fd8";
        let body = format!(
            "{{\"level\":\"info\",\"event\":\"session_vm_transient_retry\",\
              \"initiative_id\":\"{initiative_a}\",\
              \"session_id\":\"sess-1\",\"attempt\":1,\
              \"previous_reason\":\"isolation spawn failed: ...\"}}\n\
             {{\"level\":\"info\",\"event\":\"session_vm_transient_retry\",\
              \"initiative_id\":\"{initiative_b}\",\
              \"session_id\":\"sess-2\",\"attempt\":2,\
              \"previous_reason\":\"isolation spawn failed: ...\"}}\n",
        );
        std::fs::write(&log, body).expect("write stderr fixture");

        let hit = scan_stderr_for_terminal_spawn_failure(&log, &[initiative_a, initiative_b]);
        assert!(
            hit.is_none(),
            "transient retries must not trip the watchdog; got {hit:?}",
        );
    }

    /// A `orchestrator_spawn_failed` line bound to an initiative the
    /// harness is NOT waiting on (e.g. a leftover from a prior boot
    /// of the same data_dir) must not panic the current poll. Filters
    /// strictly by `watched_initiatives`.
    #[test]
    fn scan_stderr_ignores_spawn_failed_for_unwatched_initiative() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = tmp.path().join("kernel.stderr.log");
        let initiative_watched = "019e20c9-e093-7052-a0d1-1c97ef8b0090";
        let initiative_unwatched = "019eFFFF-ffff-ffff-ffff-fffffffffff0";
        let body = format!(
            "{{\"level\":\"error\",\"event\":\"orchestrator_spawn_failed\",\
              \"initiative_id\":\"{initiative_unwatched}\",\
              \"session_id\":\"sess-1\",\
              \"error\":\"...\",\"hint\":\"...\"}}\n",
        );
        std::fs::write(&log, body).expect("write stderr fixture");

        let hit =
            scan_stderr_for_terminal_spawn_failure(&log, &[initiative_watched, initiative_watched]);
        assert!(
            hit.is_none(),
            "spawn_failed for unwatched initiative must be filtered; got {hit:?}",
        );
    }

    /// Missing stderr log file is a no-op (the kernel may have crashed
    /// before opening it, or rotated it away). Scanner must not panic
    /// and must return None so the outer deadline path can surface the
    /// underlying failure mode instead.
    #[test]
    fn scan_stderr_missing_file_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = tmp.path().join("does-not-exist.log");
        let hit = scan_stderr_for_terminal_spawn_failure(&log, &["a", "b"]);
        assert!(hit.is_none(), "missing-file must be a no-op, got {hit:?}");
    }

    /// `StderrTailScanner` only inspects bytes past its internal
    /// cursor. The polling loop appends new lines between calls, and
    /// each scan should pay for only the new bytes — not the full
    /// log every iteration. Regression for the O(N²) behaviour where
    /// a 60-min run re-read the entire kernel.stderr.log every 500 ms.
    #[test]
    fn stderr_tail_scanner_skips_already_seen_bytes() {
        use std::io::Write;
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = tmp.path().join("kernel.stderr.log");
        let initiative = "019e20c9-e093-7052-a0d1-1c97ef8b0090";

        // Round 1: write some unrelated lines.
        std::fs::write(
            &log,
            b"{\"level\":\"info\",\"event\":\"sockets_bound\"}\n\
              {\"level\":\"info\",\"event\":\"session_vm_transient_retry\",\
                \"attempt\":1}\n",
        )
        .expect("seed stderr fixture");

        let mut tail = StderrTailScanner::new();
        let before_offset = tail.offset;
        let hit = tail.scan_for_terminal_spawn_failure(&log, &[initiative, initiative]);
        assert!(hit.is_none(), "no terminal failure in round 1");
        assert!(
            tail.offset > before_offset,
            "cursor must advance past complete lines we scanned",
        );

        // Round 2: append the terminal failure. Scanner should pick
        // it up and the cursor should advance to the new EOF.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .expect("append-open stderr fixture");
        writeln!(
            f,
            "{{\"level\":\"error\",\"event\":\"orchestrator_spawn_failed\",\
              \"initiative_id\":\"{initiative}\",\
              \"session_id\":\"sess-1\",\
              \"error\":\"boom\",\"hint\":\"recovery::reconcile\"}}"
        )
        .expect("append failure line");
        drop(f);

        let pre = tail.offset;
        let hit = tail
            .scan_for_terminal_spawn_failure(&log, &[initiative, initiative])
            .expect("must surface the appended failure");
        assert_eq!(hit.event, "orchestrator_spawn_failed");
        assert!(tail.offset > pre, "cursor must advance past appended line");

        // Round 3: no new bytes. Scanner must short-circuit and
        // not return the (already-reported) failure again.
        let stable = tail.offset;
        let hit = tail.scan_for_terminal_spawn_failure(&log, &[initiative, initiative]);
        assert!(
            hit.is_none(),
            "already-scanned failure must not re-fire on the next poll iteration; \
             got {hit:?}",
        );
        assert_eq!(
            tail.offset, stable,
            "cursor must not advance with no new bytes"
        );
    }

    /// Log rotation / truncation: the file shrinks below the cursor.
    /// The scanner must restart from byte zero so the new file's
    /// contents are not silently skipped.
    #[test]
    fn stderr_tail_scanner_handles_truncation() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log = tmp.path().join("kernel.stderr.log");
        let initiative = "019e20c9-e093-7052-a0d1-1c97ef8b0090";

        // Seed a big file, advance the cursor past it.
        std::fs::write(&log, "filler\n".repeat(64)).expect("seed");
        let mut tail = StderrTailScanner::new();
        let _ = tail.scan_for_terminal_spawn_failure(&log, &[initiative, initiative]);
        assert!(tail.offset > 0, "cursor must have advanced");

        // Truncate to a smaller file with a terminal failure on the
        // very first line. The scanner must NOT skip it.
        std::fs::write(
            &log,
            format!(
                "{{\"level\":\"error\",\"event\":\"orchestrator_spawn_failed\",\
                  \"initiative_id\":\"{initiative}\",\
                  \"session_id\":\"sess-1\",\
                  \"error\":\"truncated\",\"hint\":\"...\"}}\n"
            ),
        )
        .expect("truncate");

        let hit = tail
            .scan_for_terminal_spawn_failure(&log, &[initiative, initiative])
            .expect("post-truncation failure must surface");
        assert_eq!(hit.event, "orchestrator_spawn_failed");
    }

    // ─── INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01 ───────────────
    //
    // Regression tests for the example-bundle auto-refresh hook
    // (`maybe_refresh_examples` / `refresh_examples_inner`) and
    // the real-Anthropic-key witness
    // (`assert_no_real_anthropic_key`). The witness is the
    // structural guarantee that a refreshed bundle can NEVER
    // carry a real key, even if the harness or fix-loop worker
    // makes a future mistake elsewhere.

    /// Build a complete tmpdir fixture that looks like a freshly
    /// initialised `raxis/live-e2e/examples/` checkout, with the
    /// matching `live-e2e/seed/prompts/` source the hook copies
    /// from. Returns the workspace-root path so the test can
    /// drive `refresh_examples_inner` against it.
    fn build_examples_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().expect("fixture tempdir");
        let workspace = tmp.path().to_path_buf();
        let examples = workspace.join("live-e2e/examples");
        let creds = examples.join("credentials");
        let prompts = examples.join("seed/prompts");
        let src_prompts = workspace.join("live-e2e/seed/prompts");
        for d in [&examples, &creds, &prompts, &src_prompts] {
            std::fs::create_dir_all(d).expect("mkdir fixture subdir");
        }
        // Stage prompt sources mirroring the real layout — every
        // file the EXAMPLE_SEED_PROMPTS list mentions must exist.
        for name in EXAMPLE_SEED_PROMPTS {
            std::fs::write(
                src_prompts.join(name),
                format!("# fixture prompt body for {name}\n"),
            )
            .expect("write fixture prompt");
        }
        (tmp, workspace)
    }

    /// Happy path: a fresh fixture, a valid live policy.toml, two
    /// pre-assembled plan strings — the hook must rewrite every
    /// file in `examples/` AND leave the witness happy.
    #[test]
    fn refresh_examples_writes_plan_and_credentials_under_env_gate() {
        let (_tmp, workspace) = build_examples_fixture();
        let examples = workspace.join("live-e2e/examples");

        // Live policy.toml — minimal but non-empty so we can
        // assert the copy is byte-for-byte.
        let live_policy = workspace.join("policy.toml");
        std::fs::write(
            &live_policy,
            b"# live policy.toml fixture\n[meta]\nepoch = 1\n",
        )
        .expect("write fixture policy.toml");

        let inputs = ExampleRefreshInputs {
            live_policy_toml: &live_policy,
            plan_primary_toml: "# primary plan fixture\n[plan.initiative]\n",
            plan_sibling_toml: "# sibling plan fixture\n[plan.initiative]\n",
            workspace_root: &workspace,
        };
        refresh_examples_inner(&examples, inputs);

        // policy.toml — byte-for-byte from the live source.
        let copied_policy =
            std::fs::read(examples.join("policy.toml")).expect("read refreshed policy.toml");
        let live_policy_body = std::fs::read(&live_policy).expect("read live policy.toml");
        assert_eq!(
            copied_policy, live_policy_body,
            "refreshed policy.toml must be byte-for-byte from the live source",
        );

        // Plans — pre-assembled body, written verbatim.
        let primary = std::fs::read_to_string(examples.join("plan_primary.toml"))
            .expect("read refreshed plan_primary.toml");
        assert!(primary.contains("primary plan fixture"));
        let sibling = std::fs::read_to_string(examples.join("plan_sibling.toml"))
            .expect("read refreshed plan_sibling.toml");
        assert!(sibling.contains("sibling plan fixture"));

        // Credentials — match the EXAMPLE_*_CRED constants verbatim.
        let creds = examples.join("credentials");
        for (name, want) in [
            ("test-pg-dev.env", EXAMPLE_PG_CRED),
            ("test-mongo-dev.env", EXAMPLE_MONGO_CRED),
            ("test-redis-dev.env", EXAMPLE_REDIS_CRED),
            ("test-smtp-dev.env", EXAMPLE_SMTP_CRED),
        ] {
            let got = std::fs::read_to_string(creds.join(name))
                .unwrap_or_else(|e| panic!("read {name}: {e}"));
            assert_eq!(
                got, want,
                "refreshed {name} must match the EXAMPLE_*_CRED constant",
            );
        }

        // Anthropic placeholder — rewritten from the hardcoded
        // template; MUST NOT contain anything matching the
        // real-key regex.
        let anth = std::fs::read_to_string(creds.join("anthropic.env.placeholder"))
            .expect("read refreshed anthropic.env.placeholder");
        assert_eq!(
            anth, ANTHROPIC_PLACEHOLDER_BODY,
            "refreshed anthropic.env.placeholder must match the hardcoded template",
        );
        assert!(
            find_real_anthropic_key(anth.as_bytes()).is_none(),
            "refreshed anthropic.env.placeholder must NOT contain anything \
             matching the real-key regex",
        );

        // Seed prompts mirror — every file in EXAMPLE_SEED_PROMPTS
        // copied verbatim from the source.
        for name in EXAMPLE_SEED_PROMPTS {
            let got = std::fs::read_to_string(examples.join("seed/prompts").join(name))
                .unwrap_or_else(|e| panic!("read seed/prompts/{name}: {e}"));
            assert!(
                got.contains(&format!("# fixture prompt body for {name}")),
                "refreshed seed/prompts/{name} must be the verbatim source body",
            );
        }
    }

    /// `maybe_refresh_examples` is the env-gated wrapper. Without
    /// `RAXIS_E2E_REFRESH_EXAMPLES=1` it must return `None` and
    /// must NOT touch the worktree. The unit test sets the var
    /// to an explicit `"0"` so it neutralises any ambient value
    /// the shell might carry.
    #[test]
    fn maybe_refresh_examples_default_off_is_no_op() {
        let (_tmp, workspace) = build_examples_fixture();
        let examples = workspace.join("live-e2e/examples");

        // Pre-place a sentinel file in examples/ so we can prove
        // the no-op path didn't touch the dir.
        std::fs::write(examples.join("policy.toml"), b"SENTINEL_DO_NOT_OVERWRITE")
            .expect("write sentinel");

        let live_policy = workspace.join("policy.toml");
        std::fs::write(&live_policy, b"# live policy fixture\n")
            .expect("write fixture live policy");

        // Save + restore the env var so we don't poison other
        // tests in the same process. `std::env::set_var` is
        // unsafe for parallel tests in general, but the harness
        // already serialises every test that touches the env via
        // `acquire_test_lock`; this micro-test does not interact
        // with the kernel, so a brief overwrite is OK.
        let prior = std::env::var(REFRESH_EXAMPLES_ENV).ok();
        std::env::set_var(REFRESH_EXAMPLES_ENV, "0");
        let result = maybe_refresh_examples(ExampleRefreshInputs {
            live_policy_toml: &live_policy,
            plan_primary_toml: "primary",
            plan_sibling_toml: "sibling",
            workspace_root: &workspace,
        });
        match prior {
            Some(v) => std::env::set_var(REFRESH_EXAMPLES_ENV, v),
            None => std::env::remove_var(REFRESH_EXAMPLES_ENV),
        }
        assert!(result.is_none(), "no-op path must return None");

        let sentinel =
            std::fs::read_to_string(examples.join("policy.toml")).expect("read sentinel back");
        assert_eq!(
            sentinel, "SENTINEL_DO_NOT_OVERWRITE",
            "default-off path must NOT touch the worktree"
        );
    }

    /// The witness must REJECT a credential file that contains a
    /// real-looking Anthropic key. The synthetic key uses the
    /// `sk-ant-api03-` prefix + 32 chars of `[A-Za-z0-9_-]` body
    /// so it matches the regex without involving any real
    /// credential material.
    #[test]
    #[should_panic(expected = "INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01 VIOLATED")]
    fn assert_no_real_anthropic_key_rejects_real_looking_key() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let examples = tmp.path().join("examples");
        let creds = examples.join("credentials");
        std::fs::create_dir_all(&creds).expect("mkdir credentials");
        // Synthetic 32-char body of `[A-Za-z0-9_-]` — enough to
        // satisfy the 20+ minimum length. The key does NOT come
        // from any real Anthropic account; the bytes were
        // hand-typed to mimic the shape.
        std::fs::write(
            creds.join("anthropic.env.placeholder"),
            b"ANTHROPIC_API_KEY=sk-ant-api03-AAAA1111BBBB2222CCCC3333DDDDEEEE\n",
        )
        .expect("write fixture key");
        assert_no_real_anthropic_key(&examples);
    }

    /// The witness must ACCEPT the canonical placeholder body —
    /// it carries the literal `PLACEHOLDER_REPLACE_ME_WITH_REAL_KEY`
    /// which obviously does not match the real-key regex.
    #[test]
    fn assert_no_real_anthropic_key_accepts_canonical_placeholder() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let examples = tmp.path().join("examples");
        let creds = examples.join("credentials");
        std::fs::create_dir_all(&creds).expect("mkdir credentials");
        std::fs::write(
            creds.join("anthropic.env.placeholder"),
            ANTHROPIC_PLACEHOLDER_BODY,
        )
        .expect("write canonical placeholder");
        // The other credential files in the bundle are real test-
        // tenant secrets for the local docker-compose stack and
        // do not match the Anthropic regex. Stage them too so the
        // witness scans a realistic set.
        for (name, body) in [
            ("test-pg-dev.env", EXAMPLE_PG_CRED),
            ("test-mongo-dev.env", EXAMPLE_MONGO_CRED),
            ("test-redis-dev.env", EXAMPLE_REDIS_CRED),
            ("test-smtp-dev.env", EXAMPLE_SMTP_CRED),
        ] {
            std::fs::write(creds.join(name), body).expect("write cred fixture");
        }
        assert_no_real_anthropic_key(&examples);
    }

    /// The witness's regex MUST NOT false-positive on prefixes
    /// that look like but do not match the real-key shape:
    /// `sk-ant-apiX-` (single digit), `sk-ant-api03-short`
    /// (body shorter than 20 chars), arbitrary `sk-ant-` strings
    /// in unrelated contexts. A false positive here would
    /// reject legitimate placeholder/documentation text and
    /// degrade operator trust in the witness.
    #[test]
    fn find_real_anthropic_key_negative_cases() {
        // Single-digit version: regex requires `[0-9]{2}`.
        assert!(find_real_anthropic_key(b"sk-ant-api3-AAAA1111BBBB2222CCCC3333").is_none());
        // Body too short: regex requires `{20,}`.
        assert!(find_real_anthropic_key(b"sk-ant-api03-tooshort").is_none());
        // `sk-ant-` without the `api` infix.
        assert!(find_real_anthropic_key(b"sk-ant-other-AAAA1111BBBB2222CCCC3333").is_none());
        // The literal placeholder string.
        assert!(find_real_anthropic_key(b"PLACEHOLDER_REPLACE_ME_WITH_REAL_KEY").is_none());
    }

    /// Positive sanity: a real-shape key buried in a longer body
    /// must surface (the harness uses this to fail-fast at refresh
    /// time so the operator sees the offending bytes verbatim in
    /// the panic message).
    #[test]
    fn find_real_anthropic_key_positive_case() {
        let body =
            b"prefix junk\nANTHROPIC_API_KEY=sk-ant-api03-AAAA1111BBBB2222CCCC3333DDDDEEEE\nsuffix";
        let hit = find_real_anthropic_key(body).expect("real-shape key must surface");
        assert!(
            hit.starts_with("sk-ant-api03-"),
            "hit must include the leading regex match: {hit}"
        );
        assert!(
            hit.len() >= "sk-ant-api03-".len() + 20,
            "hit must include the full key body: {hit}"
        );
    }

    /// **`INV-WITNESS-VERIFIER-LIVE-E2E-EXERCISED-01` mirror pin.**
    ///
    /// The checked-in `live-e2e/examples/policy.toml` MUST carry
    /// a `[[gates]]` block declaring the `NoSecretStrings`
    /// witness verifier. An operator reading the example must be
    /// able to see, in one place, every kernel-side enforcement
    /// gate the realism harness wires up — otherwise the harness's
    /// dynamic `enable_gateway_in_policy` injection becomes the
    /// only place the gate is expressed, and the example drifts
    /// silently out of sync with what the live kernel actually
    /// runs (which is what the operator saw in iter65 when the
    /// `VerifierWitnessReceived` events were present in the audit
    /// chain but the example carried no gate row).
    ///
    /// Mirrors `iter65_harness_gate_block_mirrors_examples_comment`
    /// below — that test pins the runtime side, this one pins the
    /// example side, and the two together guarantee the
    /// example→harness mirror stays bidirectional.
    #[test]
    fn examples_policy_carries_no_secret_strings_gate() {
        let path = realism_workspace_root().join("live-e2e/examples/policy.toml");
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read examples policy.toml at {}: {e}", path.display(),));
        let v: toml::Value = toml::from_str(&body).unwrap_or_else(|e| {
            panic!(
                "parse examples policy.toml at {} as TOML: {e}",
                path.display(),
            )
        });
        let gates = v
            .get("gates")
            .and_then(|g| g.as_array())
            .unwrap_or_else(|| {
                panic!(
                    "examples policy.toml {} MUST carry a [[gates]] array; \
                     INV-WITNESS-VERIFIER-LIVE-E2E-EXERCISED-01 requires \
                     the witness verifier gate be visible to operators",
                    path.display(),
                )
            });
        let gate_types: Vec<&str> = gates
            .iter()
            .filter_map(|g| g.get("gate_type").and_then(|t| t.as_str()))
            .collect();
        assert!(
            gate_types.contains(&"NoSecretStrings"),
            "examples policy.toml {} MUST declare a [[gates]] row with \
             gate_type=\"NoSecretStrings\"; got gate_types={gate_types:?}",
            path.display(),
        );
        // Verify the load-bearing knobs are present (not the
        // PLACEHOLDER value — operators may substitute their own
        // build paths — but the field MUST exist so the schema
        // is complete enough to load).
        let row = gates
            .iter()
            .find(|g| g.get("gate_type").and_then(|t| t.as_str()) == Some("NoSecretStrings"))
            .expect("NoSecretStrings row located above");
        for required in [
            "verifier_command",
            "max_wall_seconds",
            "max_memory_bytes",
            "network_allowed",
            // iter65 — `INV-WITNESS-AGENT-HINT-RESOLUTION-TIERS-01`
            // tier-2. Must be present in the example so operators see
            // the contract before they enable `[gate_fixup]`.
            "agent_hint_default",
        ] {
            assert!(
                row.get(required).is_some(),
                "NoSecretStrings gate row in {} is missing `{required}`",
                path.display(),
            );
        }
        // The `agent_hint_default` value must be a non-empty string
        // — empty defaults would silently route through to the
        // defensive gate-name fallback at runtime, and that
        // fallback is intended to be unreachable in steady state.
        let default_hint = row
            .get("agent_hint_default")
            .and_then(|t| t.as_str())
            .unwrap_or("");
        assert!(
            !default_hint.trim().is_empty(),
            "NoSecretStrings agent_hint_default in {} must be a \
             non-empty string (tier-2 of the agent-hint resolution \
             chain). Got: {default_hint:?}",
            path.display(),
        );
        // The comment block that explains WHY the gate is wired
        // is the operator-facing prose; check a key invariant
        // reference is present so a future "drop the explanation"
        // diff is caught here.
        assert!(
            body.contains("INV-WITNESS-VERIFIER-LIVE-E2E-EXERCISED-01"),
            "examples policy.toml {} MUST cite \
             INV-WITNESS-VERIFIER-LIVE-E2E-EXERCISED-01 in the \
             [[gates]] comment so operators can find the rationale",
            path.display(),
        );
        // iter65 — the example must also cite the new tier-resolution
        // invariant so operators inspecting policy.toml see the chain
        // contract documented in-place.
        assert!(
            body.contains("INV-WITNESS-AGENT-HINT-RESOLUTION-TIERS-01"),
            "examples policy.toml {} MUST cite \
             INV-WITNESS-AGENT-HINT-RESOLUTION-TIERS-01 in the \
             agent_hint_default comment so operators see the \
             tier-2 fallback contract before enabling [gate_fixup]",
            path.display(),
        );
    }

    /// Mirror pin for the runtime side of the gate block.
    ///
    /// `enable_gateway_in_policy` appends the gate block at run
    /// time, with the same operator-facing comment the example
    /// carries (so an operator diffing the live kernel's resolved
    /// policy.toml against the checked-in example reads the same
    /// prose verbatim). This test reproduces the gate-injection
    /// path in isolation and asserts the load-bearing markers are
    /// present — the invariant ID, the gate_type, and the four
    /// schema fields.
    ///
    /// Paired with `examples_policy_carries_no_secret_strings_gate`
    /// above; together they pin the example↔harness mirror.
    #[test]
    fn iter65_harness_gate_block_mirrors_examples_comment() {
        // Reproduce the harness's gate block with a synthetic
        // verifier path so the format!() expansion runs without
        // requiring the real binary on disk.
        let synthetic_verifier =
            std::path::PathBuf::from("/synthetic/target/release/raxis-verifier-no-secrets");
        let gate_block = format!(
            "\n# ── [[gates]] — witness verifier (iter62 / iter63) ──\n\
             # Real, fast worktree-scanning gate. Source:\n\
             # `crates/verifier-no-secrets/`. Every `IntegrationMerge`\n\
             # intent transitions `Admitted → GatesPending` and the kernel\n\
             # `scheduler/dag.rs::transition_to_admitted` blocks the merge\n\
             # until a `VerifierWitnessReceived{{gate_type=\"NoSecretStrings\",\n\
             # verdict=\"Pass\"}}` row lands on the audit chain. See\n\
             # `INV-WITNESS-VERIFIER-LIVE-E2E-EXERCISED-01` for the rationale\n\
             # (this is the live coverage point for the iter63 recheck-clear\n\
             # paired-write audit row) and `INV-GATE-PRECEDENCE-01` for the\n\
             # kernel's gate-then-merge ordering contract.\n\
             [[gates]]\n\
             gate_type        = \"NoSecretStrings\"\n\
             verifier_command = \"{vb}\"\n\
             max_wall_seconds = 30\n\
             max_memory_bytes = 268435456\n\
             network_allowed  = false\n\
             # iter65 — tier-2 fallback for the `agent_hint` resolution chain\n\
             # (`INV-WITNESS-AGENT-HINT-RESOLUTION-TIERS-01`). The verifier's\n\
             # `body.agent_hint` (tier 1) is the preferred source — populated\n\
             # per failure code path by `raxis-verifier-no-secrets`. This\n\
             # `agent_hint_default` only fires when a verifier author shipped\n\
             # a Fail / Inconclusive without a wire-valid hint (e.g. an early\n\
             # build before the verifier was migrated to the typestate SDK).\n\
             # Required at policy load whenever `[gate_fixup].enabled = true`.\n\
             agent_hint_default = \"A `NoSecretStrings` gate detected secret-shaped material in your commit. Remove any literal API keys, tokens, or credentials and reference them via env vars or your secret store instead. Re-run your local secret scanner before resubmitting.\"\n",
            vb = synthetic_verifier.display(),
        );
        // The comment markers MUST be present.
        for needle in [
            "witness verifier (iter62 / iter63)",
            "Real, fast worktree-scanning gate",
            "INV-WITNESS-VERIFIER-LIVE-E2E-EXERCISED-01",
            "INV-GATE-PRECEDENCE-01",
            "scheduler/dag.rs::transition_to_admitted",
            "VerifierWitnessReceived",
            // iter65 mirror — the agent-hint comment block must also
            // be present in the runtime side so the example diff is
            // byte-for-byte stable.
            "INV-WITNESS-AGENT-HINT-RESOLUTION-TIERS-01",
            "tier-2 fallback for the `agent_hint` resolution chain",
        ] {
            assert!(
                gate_block.contains(needle),
                "runtime gate block must contain `{needle}` so the\n\
                 example mirror stays in lock-step with the live\n\
                 policy.toml the kernel actually loads; got:\n{gate_block}",
            );
        }
        // The block MUST parse as a valid TOML fragment.
        let parsed: toml::Value =
            toml::from_str(&gate_block).expect("runtime gate block must parse as TOML");
        let gates = parsed
            .get("gates")
            .and_then(|g| g.as_array())
            .expect("runtime gate block parses to a [[gates]] array");
        assert_eq!(gates.len(), 1, "exactly one [[gates]] row");
        let row = &gates[0];
        assert_eq!(
            row.get("gate_type").and_then(|t| t.as_str()),
            Some("NoSecretStrings"),
        );
        // verifier_command must carry the synthetic path verbatim
        // — proves the `format!` substitution is wired correctly.
        assert_eq!(
            row.get("verifier_command").and_then(|t| t.as_str()),
            Some(synthetic_verifier.to_string_lossy().as_ref()),
        );
        // iter65 — the runtime block must carry the tier-2
        // `agent_hint_default` so when the operator enables
        // `[gate_fixup]` the policy passes the per-gate validator
        // even at first boot.
        let default_hint = row
            .get("agent_hint_default")
            .and_then(|t| t.as_str())
            .unwrap_or("");
        assert!(
            !default_hint.trim().is_empty(),
            "runtime gate block must carry a non-empty \
             agent_hint_default; got: {default_hint:?}",
        );
        assert!(
            default_hint.contains("NoSecretStrings"),
            "agent_hint_default must reference the gate by name so \
             the resolved tier-2 critique is gate-self-identifying \
             when surfaced to the agent",
        );
    }

    /// The refresh hook is intentionally pinned to a specific
    /// repo layout. If `raxis/live-e2e/examples/` doesn't exist
    /// — meaning the layout changed and the hook needs an update
    /// — the refresh MUST panic loudly rather than `mkdir -p` and
    /// produce a half-baked diff. Drive the panic via
    /// `maybe_refresh_examples` with the env gate ON against a
    /// workspace_root whose `live-e2e/examples/` is absent.
    #[test]
    #[should_panic(expected = "does not exist")]
    fn maybe_refresh_examples_panics_when_examples_dir_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let workspace = tmp.path().to_path_buf();
        // Deliberately do NOT create `live-e2e/examples/`.
        let live_policy = workspace.join("policy.toml");
        std::fs::write(&live_policy, b"# fixture\n").expect("write live policy");

        let prior = std::env::var(REFRESH_EXAMPLES_ENV).ok();
        std::env::set_var(REFRESH_EXAMPLES_ENV, "1");
        let _capture = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            maybe_refresh_examples(ExampleRefreshInputs {
                live_policy_toml: &live_policy,
                plan_primary_toml: "primary",
                plan_sibling_toml: "sibling",
                workspace_root: &workspace,
            });
        }));
        match prior {
            Some(v) => std::env::set_var(REFRESH_EXAMPLES_ENV, v),
            None => std::env::remove_var(REFRESH_EXAMPLES_ENV),
        }
        // Re-raise the captured panic with the expected message so
        // `#[should_panic(expected = "does not exist")]` matches.
        if let Err(e) = _capture {
            std::panic::resume_unwind(e);
        }
    }
}
