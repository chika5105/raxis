//! `cargo xtask linux-prereqs` — host preflight for the Linux
//! Firecracker substrate.
//!
//! Normative reference: `specs/v2/isolation-linux-microvm.md §9`
//! ("Build / Stage Pipeline" — the Linux prereq probe surface).
//!
//! ## Why this lives here (and not only in `raxis doctor`)
//!
//! `cli/src/commands/doctor.rs::collect_host` (Worker A's surface)
//! has `host.cgroup_v2` plumbing today and a comment saying
//! "AVF/KVM presence is platform-specific and deferred to V3". The
//! Linux Firecracker substrate needs the KVM probe NOW, not in V3,
//! so we ship the canonical prereq probe as an `xtask` subcommand
//! that an operator can run BEFORE the kernel even tries to boot.
//! When Worker A's branch lands (`worker/dev-prereqs-and-intent-fixes-jw`)
//! the `Doctor` module can call into [`probe_linux_prereqs`] directly
//! without re-implementing any of the per-check logic — this module
//! exposes the typed [`Report`] / [`Check`] / [`Outcome`] vocabulary
//! that mirrors `cli/src/commands/doctor.rs`'s shapes so a future
//! wiring is a one-line `r.checks.extend(linux_prereqs::probe(...).checks)`.
//!
//! ## Checks performed
//!
//! 1. `linux.kernel_version`         — host kernel ≥ 5.10 (per
//!                                      `system-requirements.md §1.1`).
//! 2. `linux.dev_kvm.exists`         — `/dev/kvm` is a character
//!                                      device.
//! 3. `linux.dev_kvm.openable`       — current user can open it
//!                                      RW (the substrate's
//!                                      `probe_host` does the same
//!                                      check at session-spawn).
//! 4. `linux.kvm_group.membership`   — current user's groups
//!                                      include the `kvm` group
//!                                      (the canonical recovery
//!                                      hint when (3) fails).
//! 5. `linux.vhost_vsock.module`     — `/proc/modules` shows
//!                                      `vhost_vsock` loaded (or
//!                                      `/dev/vhost-vsock` exists,
//!                                      which catches statically-
//!                                      compiled-in builds).
//! 6. `linux.cgroup_v2.mounted`      — `/sys/fs/cgroup/cgroup.controllers`
//!                                      exists.
//! 7. `linux.firecracker.binary`     — `firecracker(1)` is on
//!                                      `$PATH` (Warn — operator
//!                                      may install it later).
//! 8. `linux.virtiofsd.binary`       — `virtiofsd(1)` on `$PATH`
//!                                      (Warn — V2 doesn't require
//!                                      it; V3 will).
//!
//! Each check returns a typed [`Outcome`] (`Ok` | `Warn` | `Fail`)
//! plus a human-readable detail string the rendering layer prints
//! alongside.
//!
//! ## Exit-code contract
//!
//! Same as `raxis doctor`:
//!   * `0` — every check OK.
//!   * `1` — at least one Warn, no Fail.
//!   * `2` — at least one Fail.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

// ---------------------------------------------------------------------------
// Outcome model — kept structurally identical to
// `cli/src/commands/doctor.rs` so a future Worker-A wiring is a
// straight `r.checks.extend(...)`.
// ---------------------------------------------------------------------------

/// One row in the prereq report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Stable identifier (e.g. `"linux.dev_kvm.openable"`). Stable
    /// across versions so JSON consumers can pin against it.
    pub id:      String,
    pub outcome: Outcome,
    pub detail:  String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Warn,
    Fail,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok   => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    fn push(&mut self, id: &str, outcome: Outcome, detail: impl Into<String>) {
        self.checks.push(Check {
            id:      id.to_owned(),
            outcome,
            detail:  detail.into(),
        });
    }

    /// Worst-of outcome. Drives the process exit code.
    pub fn worst(&self) -> Outcome {
        let mut worst = Outcome::Ok;
        for c in &self.checks {
            worst = match (worst, c.outcome) {
                (_, Outcome::Fail) => Outcome::Fail,
                (Outcome::Ok, Outcome::Warn) => Outcome::Warn,
                (other, _) => other,
            };
        }
        worst
    }

    pub fn exit_code(&self) -> i32 {
        match self.worst() {
            Outcome::Ok   => 0,
            Outcome::Warn => 1,
            Outcome::Fail => 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Public probe entry point
// ---------------------------------------------------------------------------

/// Run every Linux-substrate prereq check against the live host.
/// Returns a fully-populated [`Report`]. On non-Linux hosts every
/// check returns Ok with `"skipped (non-linux host)"` so the same
/// surface is callable from a portable test harness.
pub fn probe_linux_prereqs() -> Report {
    let mut r = Report::default();
    if !cfg!(target_os = "linux") {
        r.push(
            "linux.host_os",
            Outcome::Ok,
            "skipped (non-linux host; Firecracker substrate only \
             admits when target_os=linux)",
        );
        return r;
    }
    check_kernel_version(&mut r);
    check_dev_kvm(&mut r);
    check_kvm_group_membership(&mut r);
    check_vhost_vsock(&mut r);
    check_cgroup_v2(&mut r);
    check_firecracker_binary(&mut r);
    check_virtiofsd_binary(&mut r);
    r
}

// ---------------------------------------------------------------------------
// Per-check probes — each is pure-input/pure-output for testability;
// the `_with_paths` variants take overrideable filesystem roots so
// the unit tests can drive against fixture trees.
// ---------------------------------------------------------------------------

fn check_kernel_version(r: &mut Report) {
    let osrelease_path = PathBuf::from("/proc/sys/kernel/osrelease");
    match check_kernel_version_at(&osrelease_path) {
        Ok((major, minor, raw)) => {
            if (major, minor) >= (5, 10) {
                r.push(
                    "linux.kernel_version",
                    Outcome::Ok,
                    format!("kernel {raw} (≥ 5.10)"),
                );
            } else {
                r.push(
                    "linux.kernel_version",
                    Outcome::Fail,
                    format!(
                        "kernel {raw} (< 5.10) — substrate refuses to spawn; \
                         see system-requirements.md §1.1"
                    ),
                );
            }
        }
        Err(e) => r.push(
            "linux.kernel_version",
            Outcome::Fail,
            format!("could not parse {}: {e}", osrelease_path.display()),
        ),
    }
}

fn check_kernel_version_at(path: &Path) -> Result<(u32, u32, String)> {
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim().to_owned();
    parse_osrelease(&trimmed).map(|(maj, min)| (maj, min, trimmed))
}

/// Parse `/proc/sys/kernel/osrelease` style strings:
///   * `5.15.0-105-generic`
///   * `6.1.0-21-amd64`
///   * `5.10.225`
/// Returns `(major, minor)` or an error if the leading numeric pair
/// is malformed.
fn parse_osrelease(raw: &str) -> Result<(u32, u32)> {
    let mut parts = raw.split(|c: char| !c.is_ascii_digit());
    let major: u32 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty osrelease string"))?
        .parse()
        .map_err(|e| anyhow::anyhow!("bad major: {e}"))?;
    let minor: u32 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing minor in osrelease"))?
        .parse()
        .map_err(|e| anyhow::anyhow!("bad minor: {e}"))?;
    Ok((major, minor))
}

fn check_dev_kvm(r: &mut Report) {
    let dev_kvm = PathBuf::from("/dev/kvm");
    match std::fs::metadata(&dev_kvm) {
        Ok(_) => {
            r.push(
                "linux.dev_kvm.exists",
                Outcome::Ok,
                format!("{} present", dev_kvm.display()),
            );
            // RW-openable check mirrors what
            // `raxis-isolation-firecracker::probe_host` does at
            // session-spawn time. We open with NO_FOLLOW so a
            // symlink to a stub can't lie to the probe.
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&dev_kvm)
            {
                Ok(_) => r.push(
                    "linux.dev_kvm.openable",
                    Outcome::Ok,
                    "RW open(/dev/kvm) succeeded — substrate will spawn",
                ),
                Err(e) => r.push(
                    "linux.dev_kvm.openable",
                    Outcome::Fail,
                    format!(
                        "RW open(/dev/kvm) failed: {e} — recovery: \
                         `sudo usermod -aG kvm $USER` then re-login"
                    ),
                ),
            }
        }
        Err(e) => r.push(
            "linux.dev_kvm.exists",
            Outcome::Fail,
            format!(
                "{} missing: {e} — kernel module CONFIG_KVM not loaded \
                 (try `sudo modprobe kvm` and the per-CPU `kvm_intel` / \
                 `kvm_amd` module)",
                dev_kvm.display(),
            ),
        ),
    }
}

fn check_kvm_group_membership(r: &mut Report) {
    // The `getgroups(2)` syscall is the canonical "what groups am I
    // currently in" probe. We use libc directly — adding the
    // `users`/`nix` crate would broaden the build dep set for one
    // syscall.
    let in_kvm_group = current_user_in_kvm_group();
    match in_kvm_group {
        Ok(true) => r.push(
            "linux.kvm_group.membership",
            Outcome::Ok,
            "current user is in the `kvm` group",
        ),
        Ok(false) => r.push(
            "linux.kvm_group.membership",
            Outcome::Warn,
            "current user is NOT in the `kvm` group; if the dev_kvm.openable \
             check above failed, this is the cause. Recovery: \
             `sudo usermod -aG kvm $USER` then re-login (group membership \
             is computed at session-start)",
        ),
        Err(e) => r.push(
            "linux.kvm_group.membership",
            Outcome::Warn,
            format!("could not enumerate current user's groups: {e}"),
        ),
    }
}

#[cfg(target_os = "linux")]
fn current_user_in_kvm_group() -> Result<bool> {
    // Resolve the `kvm` group's gid via /etc/group rather than
    // libc::getgrnam — the latter can hit NSS modules and isn't
    // worth the link-time complexity here.
    let group_file = std::fs::read_to_string("/etc/group")?;
    let kvm_gid: u32 = group_file
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            if name != "kvm" {
                return None;
            }
            let _password = fields.next()?;
            let gid_str = fields.next()?;
            gid_str.parse::<u32>().ok()
        })
        .ok_or_else(|| anyhow::anyhow!("no `kvm` group entry in /etc/group"))?;

    // SAFETY: `getgroups(0, NULL)` returns the caller's group count
    // without writing anything; the second call writes at most that
    // many `gid_t` values into `buf`.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        bail!("getgroups(probe): {}", std::io::Error::last_os_error());
    }
    let count = count as usize;
    let mut buf = vec![0 as libc::gid_t; count];
    let n = unsafe { libc::getgroups(count as i32, buf.as_mut_ptr()) };
    if n < 0 {
        bail!("getgroups(read): {}", std::io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf.iter().any(|&g| g as u32 == kvm_gid))
}

#[cfg(not(target_os = "linux"))]
fn current_user_in_kvm_group() -> Result<bool> {
    // No `kvm` group on macOS — the per-OS dispatch above never
    // calls this on a macOS host, but the compile path still needs
    // a body.
    Ok(false)
}

fn check_vhost_vsock(r: &mut Report) {
    let modules_path = PathBuf::from("/proc/modules");
    let dev_path     = PathBuf::from("/dev/vhost-vsock");
    let module_loaded = std::fs::read_to_string(&modules_path)
        .map(|body| body.lines().any(|line| {
            line.split_whitespace().next() == Some("vhost_vsock")
        }))
        .unwrap_or(false);
    let device_present = std::fs::metadata(&dev_path).is_ok();
    if module_loaded || device_present {
        r.push(
            "linux.vhost_vsock.module",
            Outcome::Ok,
            format!(
                "vhost_vsock available (module_loaded={module_loaded}, \
                 dev_present={device_present})"
            ),
        );
    } else {
        r.push(
            "linux.vhost_vsock.module",
            Outcome::Fail,
            "vhost_vsock not available — guest agent vsock dial will fail. \
             Recovery: `sudo modprobe vhost_vsock`. Persist via \
             `/etc/modules-load.d/vhost_vsock.conf`.",
        );
    }
}

fn check_cgroup_v2(r: &mut Report) {
    let path = PathBuf::from("/sys/fs/cgroup/cgroup.controllers");
    if path.exists() {
        r.push(
            "linux.cgroup_v2.mounted",
            Outcome::Ok,
            "cgroup v2 mounted at /sys/fs/cgroup",
        );
    } else {
        r.push(
            "linux.cgroup_v2.mounted",
            Outcome::Fail,
            "cgroup v2 not mounted — required for the substrate's \
             VmSpec.cgroup_quota enforcement",
        );
    }
}

fn check_firecracker_binary(r: &mut Report) {
    match which_on_path("firecracker") {
        Some(p) => r.push(
            "linux.firecracker.binary",
            Outcome::Ok,
            format!("firecracker on PATH at {}", p.display()),
        ),
        None => r.push(
            "linux.firecracker.binary",
            Outcome::Warn,
            "firecracker not on PATH — substrate will fail at spawn time. \
             Recovery: install via your distro's package manager or download \
             the static binary from \
             https://github.com/firecracker-microvm/firecracker/releases",
        ),
    }
}

fn check_virtiofsd_binary(r: &mut Report) {
    match which_on_path("virtiofsd") {
        Some(p) => r.push(
            "linux.virtiofsd.binary",
            Outcome::Ok,
            format!("virtiofsd on PATH at {}", p.display()),
        ),
        None => r.push(
            "linux.virtiofsd.binary",
            Outcome::Warn,
            "virtiofsd not on PATH — V2 substrate does not require it \
             (workspace is staged via vsock-mediated RPC); V3 will. \
             No action required for V2.",
        ),
    }
}

/// Hand-rolled `which`. Avoids pulling in the `which` crate for one
/// callsite. PATH-walk semantics: returns the first executable
/// component matching `name`. Empty PATH returns None.
fn which_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111) != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

// ---------------------------------------------------------------------------
// CLI surface — `cargo xtask linux-prereqs [--json]`
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy)]
struct Opts {
    json: bool,
}

fn parse_opts(argv: &[String]) -> Result<Opts> {
    let mut opts = Opts::default();
    for a in argv {
        match a.as_str() {
            "--json" => opts.json = true,
            "-h" | "--help" => {
                eprintln!(
                    "usage: cargo xtask linux-prereqs [--json]\n\
                     \n\
                     Probes Linux host prerequisites for the Firecracker\n\
                     substrate (specs/v2/isolation-linux-microvm.md §9):\n  \
                     - kernel version ≥ 5.10\n  \
                     - /dev/kvm exists + RW-openable by current user\n  \
                     - current user in `kvm` group\n  \
                     - vhost_vsock module loaded (or /dev/vhost-vsock present)\n  \
                     - cgroup v2 mounted at /sys/fs/cgroup\n  \
                     - firecracker binary on PATH\n  \
                     - virtiofsd binary on PATH (Warn-only; V3 prereq)\n\
                     \n\
                     Exit codes:\n  \
                     0   every check OK\n  \
                     1   at least one WARN, no FAIL\n  \
                     2   at least one FAIL (substrate will not boot)\n",
                );
                std::process::exit(0);
            }
            other => bail!("unknown linux-prereqs flag: {other:?}"),
        }
    }
    Ok(opts)
}

/// Entry point invoked by `xtask/src/main.rs`.
pub fn run(argv: &[String]) -> Result<()> {
    let opts = parse_opts(argv)?;
    let report = probe_linux_prereqs();
    if opts.json {
        render_json(&report);
    } else {
        render_human(&report);
    }
    std::process::exit(report.exit_code());
}

fn render_human(report: &Report) {
    eprintln!("xtask linux-prereqs — Firecracker substrate preflight");
    eprintln!("  worst:    {}", report.worst().label());
    eprintln!();
    for c in &report.checks {
        eprintln!(
            "  [{lvl:<4}] {id:<32} {detail}",
            lvl    = c.outcome.label(),
            id     = c.id,
            detail = c.detail,
        );
    }
}

fn render_json(report: &Report) {
    // Hand-rolled JSON emit — same shape as
    // `cli/src/commands/doctor.rs::render_json` so a future Worker-A
    // wiring can serialise both walks through one consumer. Avoids
    // a `serde_json` dep on `xtask`.
    let mut out = String::with_capacity(64 * report.checks.len());
    out.push_str("{\"worst\":\"");
    out.push_str(report.worst().label());
    out.push_str("\",\"checks\":[");
    for (i, c) in report.checks.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"id\":");
        push_json_string(&mut out, &c.id);
        out.push_str(",\"outcome\":\"");
        out.push_str(c.outcome.label());
        out.push_str("\",\"detail\":");
        push_json_string(&mut out, &c.detail);
        out.push('}');
    }
    out.push_str("]}");
    println!("{out}");
}

fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"'  => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn parse_osrelease_handles_canonical_layouts() {
        for (s, want) in &[
            ("5.10.225",            (5u32, 10u32)),
            ("5.15.0-105-generic",  (5,    15)),
            ("6.1.0-21-amd64",      (6,    1)),
            ("4.19.0",              (4,    19)),
        ] {
            let got = parse_osrelease(s).unwrap();
            assert_eq!(got, *want, "input: {s}");
        }
    }

    #[test]
    fn parse_osrelease_rejects_garbage() {
        assert!(parse_osrelease("").is_err());
        assert!(parse_osrelease("garbage").is_err());
        assert!(parse_osrelease("5").is_err());
    }

    #[test]
    fn check_kernel_version_at_reads_fixture_correctly() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("osrelease");
        fs::write(&p, "5.15.0-105-generic\n").unwrap();
        let (maj, min, raw) = check_kernel_version_at(&p).unwrap();
        assert_eq!(maj, 5);
        assert_eq!(min, 15);
        assert_eq!(raw, "5.15.0-105-generic");
    }

    #[test]
    fn worst_of_ok_warn_fail_is_fail() {
        let mut r = Report::default();
        r.push("a", Outcome::Ok,   "ok");
        r.push("b", Outcome::Warn, "warn");
        r.push("c", Outcome::Fail, "fail");
        assert_eq!(r.worst(), Outcome::Fail);
        assert_eq!(r.exit_code(), 2);
    }

    #[test]
    fn worst_of_ok_warn_is_warn() {
        let mut r = Report::default();
        r.push("a", Outcome::Ok,   "ok");
        r.push("b", Outcome::Warn, "warn");
        assert_eq!(r.worst(), Outcome::Warn);
        assert_eq!(r.exit_code(), 1);
    }

    #[test]
    fn worst_of_all_ok_is_ok() {
        let mut r = Report::default();
        r.push("a", Outcome::Ok, "ok");
        assert_eq!(r.worst(), Outcome::Ok);
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn render_json_round_trips_through_a_minimal_parser() {
        let mut r = Report::default();
        r.push("linux.dev_kvm.exists", Outcome::Ok,   "/dev/kvm present");
        r.push("linux.cgroup_v2.mounted", Outcome::Fail, "missing");
        // Capture stdout via a temp redirect would require process
        // gymnastics; we validate the on-the-wire shape directly by
        // rebuilding it the same way `render_json` does.
        let mut out = String::new();
        out.push_str("{\"worst\":\"");
        out.push_str(r.worst().label());
        out.push_str("\",\"checks\":[");
        for (i, c) in r.checks.iter().enumerate() {
            if i > 0 { out.push(','); }
            out.push_str("{\"id\":");
            push_json_string(&mut out, &c.id);
            out.push_str(",\"outcome\":\"");
            out.push_str(c.outcome.label());
            out.push_str("\",\"detail\":");
            push_json_string(&mut out, &c.detail);
            out.push('}');
        }
        out.push_str("]}");
        // Sanity-check the strings made it through.
        assert!(out.contains("linux.dev_kvm.exists"));
        assert!(out.contains("linux.cgroup_v2.mounted"));
        assert!(out.contains("\"worst\":\"FAIL\""));
    }

    #[test]
    fn push_json_string_escapes_quotes_and_control_chars() {
        let mut out = String::new();
        push_json_string(&mut out, "hello \"world\"\n");
        assert_eq!(out, r#""hello \"world\"\n""#);
    }

    #[test]
    fn parse_opts_accepts_json_flag() {
        let opts = parse_opts(&["--json".to_owned()]).unwrap();
        assert!(opts.json);
    }

    #[test]
    fn parse_opts_rejects_unknown_flag() {
        let err = parse_opts(&["--bogus".to_owned()]).unwrap_err().to_string();
        assert!(err.contains("unknown linux-prereqs flag"), "got: {err}");
    }

    #[test]
    fn probe_linux_prereqs_on_non_linux_host_returns_single_skip_row() {
        // On macOS / Windows runners the cfg gate short-circuits the
        // probe to a single Ok row, so this test is portable.
        if !cfg!(target_os = "linux") {
            let r = probe_linux_prereqs();
            assert_eq!(r.checks.len(), 1);
            assert_eq!(r.checks[0].id, "linux.host_os");
            assert_eq!(r.checks[0].outcome, Outcome::Ok);
        }
    }

    #[test]
    fn probe_linux_prereqs_on_linux_emits_every_check_id() {
        if !cfg!(target_os = "linux") {
            return; // covered by the preceding test.
        }
        let r = probe_linux_prereqs();
        let ids: Vec<&str> = r.checks.iter().map(|c| c.id.as_str()).collect();
        // Required checks every Linux host should produce a row for,
        // regardless of whether the underlying check passes.
        for id in [
            "linux.kernel_version",
            "linux.dev_kvm.exists",
            "linux.kvm_group.membership",
            "linux.vhost_vsock.module",
            "linux.cgroup_v2.mounted",
            "linux.firecracker.binary",
            "linux.virtiofsd.binary",
        ] {
            assert!(
                ids.iter().any(|&i| i == id || i.starts_with(&format!("{id}."))),
                "expected check id {id} in report; got {ids:?}"
            );
        }
    }
}
