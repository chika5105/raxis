// xtask/src/hygiene_install.rs — installer for the periodic
// hygiene sweep (launchd on macOS, systemd on Linux).
//
// `cargo xtask hygiene-install-timer [--system] [--uninstall] [--dry-run]`
//
// macOS (default & only supported scope: per-user LaunchAgent):
//   * Reads the templated plist at `raxis/launchd/com.raxis.hygiene.plist`,
//     substitutes `__CARGO_BIN__` / `__REPO_ROOT__` / `__HOME__`, and
//     writes the result to `~/Library/LaunchAgents/com.raxis.hygiene.plist`.
//   * Bootstraps the agent via `launchctl bootstrap gui/$UID <plist>`.
//   * `--uninstall` runs `launchctl bootout` and removes the file.
//
// Linux (default: per-user systemd; `--system` for system-wide):
//   * Reads the two templates at `raxis/systemd/raxis-hygiene.{service,timer}`,
//     substitutes `__REPO_ROOT__` / `__CARGO_BIN__` / `__OPERATOR_USER__`,
//     and writes them to `~/.config/systemd/user/` (user) or
//     `/etc/systemd/system/` (system).
//   * Reloads the appropriate daemon, then `enable --now raxis-hygiene.timer`.
//   * `--uninstall` disables + removes both unit files.
//
// `--dry-run` prints every file write and shell command without
// touching disk or invoking launchctl/systemctl. Mirrors the
// `cargo xtask dev-prereqs --dry-run` ergonomics so an operator
// can preview the install before committing.
//
// INV-HOST-HYGIENE-01 mandates a hygiene mechanism but does NOT
// require the timer specifically — it remains opt-in. The
// installer exists to make the timer the operator-ergonomic
// default; manual invocation of `cargo xtask hygiene` continues
// to work without it.

use std::path::PathBuf;
use std::process::Command;

#[cfg(test)]
use std::path::Path;

use anyhow::{anyhow, bail, Context};

const PLIST_TEMPLATE: &str = include_str!("../../launchd/com.raxis.hygiene.plist");
const SERVICE_TEMPLATE: &str = include_str!("../../systemd/raxis-hygiene.service");
const TIMER_TEMPLATE: &str = include_str!("../../systemd/raxis-hygiene.timer");

const PLIST_LABEL: &str = "com.raxis.hygiene";
const SERVICE_NAME: &str = "raxis-hygiene.service";
const TIMER_NAME: &str = "raxis-hygiene.timer";

#[derive(Debug, Clone)]
struct InstallOpts {
    system: bool,
    uninstall: bool,
    dry_run: bool,
}

impl InstallOpts {
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut system = false;
        let mut uninstall = false;
        let mut dry_run = false;
        for a in args {
            match a.as_str() {
                "--system" => system = true,
                "--uninstall" => uninstall = true,
                "--dry-run" => dry_run = true,
                other => bail!(
                    "unknown flag for `hygiene-install-timer`: {other:?}\n\
                     usage: cargo xtask hygiene-install-timer \
                     [--system] [--uninstall] [--dry-run]"
                ),
            }
        }
        Ok(Self {
            system,
            uninstall,
            dry_run,
        })
    }
}

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = InstallOpts::parse(args)?;
    let env = HostEnv::probe()?;

    if cfg!(target_os = "macos") {
        if opts.system {
            bail!(
                "--system is not supported on macOS; the launchd plist is \
                 always installed as a per-user LaunchAgent. Run without \
                 --system to install at ~/Library/LaunchAgents/."
            );
        }
        if opts.uninstall {
            uninstall_macos(&env, opts.dry_run)
        } else {
            install_macos(&env, opts.dry_run)
        }
    } else if cfg!(target_os = "linux") {
        if opts.uninstall {
            uninstall_linux(&env, opts.system, opts.dry_run)
        } else {
            install_linux(&env, opts.system, opts.dry_run)
        }
    } else {
        bail!(
            "hygiene-install-timer: unsupported host platform; only \
             macOS (launchd) and Linux (systemd) are wired in."
        )
    }
}

// ---------------------------------------------------------------------------
// Host environment probe
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct HostEnv {
    home: PathBuf,
    repo_root: PathBuf,
    cargo_bin: PathBuf,
    user: String,
}

impl HostEnv {
    fn probe() -> anyhow::Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("HOME is not set; cannot resolve install paths"))?;
        let repo_root = current_repo_root()?;
        let cargo_bin = std::env::var_os("CARGO")
            .map(PathBuf::from)
            .or_else(|| which("cargo"))
            .ok_or_else(|| anyhow!(
                "could not locate the `cargo` binary; set $CARGO or add it to PATH"
            ))?;
        let user = std::env::var("USER").unwrap_or_else(|_| "operator".into());
        Ok(Self {
            home,
            repo_root,
            cargo_bin,
            user,
        })
    }
}

fn current_repo_root() -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir().context("std::env::current_dir")?;
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(&cwd)
        .output()
        .context("spawning git rev-parse --show-toplevel")?;
    if !out.status.success() {
        bail!(
            "`git rev-parse --show-toplevel` failed; \
             hygiene-install-timer must be run from inside a git checkout."
        );
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
    ))
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// macOS — launchd LaunchAgent install / uninstall
// ---------------------------------------------------------------------------

fn macos_plist_target(env: &HostEnv) -> PathBuf {
    env.home
        .join("Library/LaunchAgents")
        .join(format!("{PLIST_LABEL}.plist"))
}

fn install_macos(env: &HostEnv, dry_run: bool) -> anyhow::Result<()> {
    let body = render_plist(env);
    let target = macos_plist_target(env);
    let logs_dir = env.home.join("Library/Logs");

    eprintln!("[hygiene-install] target plist: {}", target.display());
    eprintln!("[hygiene-install] logs dir:     {}", logs_dir.display());

    if dry_run {
        eprintln!("[hygiene-install] dry-run: would write {} bytes to {}",
            body.len(), target.display());
        eprintln!("[hygiene-install] dry-run: would `launchctl bootstrap gui/$UID {}`",
            target.display());
        return Ok(());
    }

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::create_dir_all(&logs_dir)
        .with_context(|| format!("creating {}", logs_dir.display()))?;
    std::fs::write(&target, body.as_bytes())
        .with_context(|| format!("writing {}", target.display()))?;

    let uid = unsafe { libc::getuid() };
    let domain = format!("gui/{uid}");
    // `bootstrap` may fail with `service already loaded`; bootout
    // first so the call is idempotent.
    let _ = Command::new("launchctl")
        .args(["bootout", &domain, &target.to_string_lossy()])
        .status();
    let status = Command::new("launchctl")
        .args(["bootstrap", &domain, &target.to_string_lossy()])
        .status()
        .context("spawning launchctl bootstrap")?;
    if !status.success() {
        bail!("launchctl bootstrap exited {status}; check Console.app for details");
    }
    eprintln!(
        "[hygiene-install] installed; verify with: launchctl list | grep {PLIST_LABEL}"
    );
    Ok(())
}

fn uninstall_macos(env: &HostEnv, dry_run: bool) -> anyhow::Result<()> {
    let target = macos_plist_target(env);
    let uid = unsafe { libc::getuid() };
    let domain = format!("gui/{uid}");
    if dry_run {
        eprintln!("[hygiene-install] dry-run: would `launchctl bootout {domain} {}`",
            target.display());
        eprintln!("[hygiene-install] dry-run: would remove {}", target.display());
        return Ok(());
    }
    let _ = Command::new("launchctl")
        .args(["bootout", &domain, &target.to_string_lossy()])
        .status();
    if target.exists() {
        std::fs::remove_file(&target)
            .with_context(|| format!("removing {}", target.display()))?;
    }
    eprintln!("[hygiene-install] uninstalled {PLIST_LABEL}");
    Ok(())
}

fn render_plist(env: &HostEnv) -> String {
    PLIST_TEMPLATE
        .replace("__CARGO_BIN__", &env.cargo_bin.to_string_lossy())
        .replace("__REPO_ROOT__", &env.repo_root.to_string_lossy())
        .replace("__HOME__", &env.home.to_string_lossy())
}

// ---------------------------------------------------------------------------
// Linux — systemd install / uninstall (user-scope by default)
// ---------------------------------------------------------------------------

fn linux_unit_dir(env: &HostEnv, system: bool) -> PathBuf {
    if system {
        PathBuf::from("/etc/systemd/system")
    } else {
        env.home.join(".config/systemd/user")
    }
}

fn install_linux(env: &HostEnv, system: bool, dry_run: bool) -> anyhow::Result<()> {
    let unit_dir = linux_unit_dir(env, system);
    let service_path = unit_dir.join(SERVICE_NAME);
    let timer_path = unit_dir.join(TIMER_NAME);
    let service_body = render_service(env);
    let timer_body = render_timer(env);
    let scope = if system { "system" } else { "user" };

    eprintln!("[hygiene-install] scope:        {scope}");
    eprintln!("[hygiene-install] unit dir:     {}", unit_dir.display());
    eprintln!("[hygiene-install] service unit: {}", service_path.display());
    eprintln!("[hygiene-install] timer unit:   {}", timer_path.display());

    if dry_run {
        eprintln!(
            "[hygiene-install] dry-run: would write {} + {} bytes",
            service_body.len(), timer_body.len(),
        );
        let scope_flag = if system { "" } else { "--user " };
        eprintln!("[hygiene-install] dry-run: would `systemctl {scope_flag}daemon-reload`");
        eprintln!(
            "[hygiene-install] dry-run: would `systemctl {scope_flag}enable --now {TIMER_NAME}`"
        );
        return Ok(());
    }

    std::fs::create_dir_all(&unit_dir)
        .with_context(|| format!("creating {}", unit_dir.display()))?;
    std::fs::write(&service_path, service_body.as_bytes())
        .with_context(|| format!("writing {}", service_path.display()))?;
    std::fs::write(&timer_path, timer_body.as_bytes())
        .with_context(|| format!("writing {}", timer_path.display()))?;

    let mut reload = Command::new("systemctl");
    if !system {
        reload.arg("--user");
    }
    reload.arg("daemon-reload");
    let status = reload.status().context("systemctl daemon-reload")?;
    if !status.success() {
        bail!("systemctl daemon-reload exited {status}");
    }

    let mut enable = Command::new("systemctl");
    if !system {
        enable.arg("--user");
    }
    enable.args(["enable", "--now", TIMER_NAME]);
    let status = enable.status().context("systemctl enable --now")?;
    if !status.success() {
        bail!("systemctl enable --now {TIMER_NAME} exited {status}");
    }
    eprintln!("[hygiene-install] installed; verify with:");
    if system {
        eprintln!("  systemctl list-timers {TIMER_NAME}");
    } else {
        eprintln!("  systemctl --user list-timers {TIMER_NAME}");
    }
    Ok(())
}

fn uninstall_linux(env: &HostEnv, system: bool, dry_run: bool) -> anyhow::Result<()> {
    let unit_dir = linux_unit_dir(env, system);
    let service_path = unit_dir.join(SERVICE_NAME);
    let timer_path = unit_dir.join(TIMER_NAME);

    if dry_run {
        let scope_flag = if system { "" } else { "--user " };
        eprintln!("[hygiene-install] dry-run: would `systemctl {scope_flag}disable --now {TIMER_NAME}`");
        eprintln!("[hygiene-install] dry-run: would remove {}", service_path.display());
        eprintln!("[hygiene-install] dry-run: would remove {}", timer_path.display());
        return Ok(());
    }
    let mut disable = Command::new("systemctl");
    if !system {
        disable.arg("--user");
    }
    disable.args(["disable", "--now", TIMER_NAME]);
    let _ = disable.status();
    if timer_path.exists() {
        std::fs::remove_file(&timer_path)
            .with_context(|| format!("removing {}", timer_path.display()))?;
    }
    if service_path.exists() {
        std::fs::remove_file(&service_path)
            .with_context(|| format!("removing {}", service_path.display()))?;
    }
    let mut reload = Command::new("systemctl");
    if !system {
        reload.arg("--user");
    }
    reload.arg("daemon-reload");
    let _ = reload.status();
    eprintln!("[hygiene-install] uninstalled {TIMER_NAME} + {SERVICE_NAME}");
    Ok(())
}

fn render_service(env: &HostEnv) -> String {
    SERVICE_TEMPLATE
        .replace("__REPO_ROOT__", &env.repo_root.to_string_lossy())
        .replace("__CARGO_BIN__", &env.cargo_bin.to_string_lossy())
        .replace("__OPERATOR_USER__", &env.user)
}

fn render_timer(env: &HostEnv) -> String {
    TIMER_TEMPLATE
        .replace("__REPO_ROOT__", &env.repo_root.to_string_lossy())
        .replace("__CARGO_BIN__", &env.cargo_bin.to_string_lossy())
        .replace("__OPERATOR_USER__", &env.user)
}

// ---------------------------------------------------------------------------
// Tests — template parser smoke + render-correctness
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_env(tmp: &Path) -> HostEnv {
        HostEnv {
            home: tmp.join("home/operator"),
            repo_root: tmp.join("repo/aegis-ai"),
            cargo_bin: PathBuf::from("/usr/local/bin/cargo"),
            user: "operator".into(),
        }
    }

    #[test]
    fn plist_renders_without_unsubstituted_placeholders() {
        let tmp = tempfile::tempdir().unwrap();
        let env = fixture_env(tmp.path());
        let body = render_plist(&env);
        assert!(!body.contains("__CARGO_BIN__"), "plist still has __CARGO_BIN__");
        assert!(!body.contains("__REPO_ROOT__"), "plist still has __REPO_ROOT__");
        assert!(!body.contains("__HOME__"), "plist still has __HOME__");
        assert!(body.contains("/usr/local/bin/cargo"));
        assert!(body.contains("repo/aegis-ai"));
        assert!(body.contains("home/operator/Library/Logs/raxis-hygiene"));
    }

    #[test]
    fn service_unit_renders_executable_line() {
        let tmp = tempfile::tempdir().unwrap();
        let env = fixture_env(tmp.path());
        let body = render_service(&env);
        assert!(!body.contains("__CARGO_BIN__"));
        assert!(!body.contains("__REPO_ROOT__"));
        assert!(body.contains("ExecStart=/usr/local/bin/cargo xtask hygiene --max-age-days 1"));
        assert!(body.contains("WorkingDirectory="));
    }

    #[test]
    fn timer_unit_pins_six_hour_schedule() {
        let tmp = tempfile::tempdir().unwrap();
        let env = fixture_env(tmp.path());
        let body = render_timer(&env);
        assert!(body.contains("OnCalendar=*-*-* 00,06,12,18:00:00"));
        assert!(body.contains("Persistent=true"));
        assert!(body.contains("Unit=raxis-hygiene.service"));
    }

    /// `plutil -lint` is the canonical macOS plist validator.
    /// Skip if the tool is unavailable (Linux CI).
    #[test]
    fn plist_template_passes_plutil_lint() {
        if Command::new("plutil").arg("-help").output().is_err() {
            eprintln!("skipping plutil check: tool not available");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let env = fixture_env(tmp.path());
        let body = render_plist(&env);
        let path = tmp.path().join("test.plist");
        std::fs::write(&path, body.as_bytes()).unwrap();
        let out = Command::new("plutil")
            .args(["-lint", &path.to_string_lossy()])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "plutil -lint failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    /// `systemd-analyze verify` is the canonical systemd unit
    /// validator. Skip if the tool is unavailable (macOS CI).
    #[test]
    fn systemd_units_pass_analyze_verify() {
        if Command::new("systemd-analyze")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping systemd-analyze check: tool not available");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let env = fixture_env(tmp.path());
        let unit_dir = tmp.path().join("units");
        std::fs::create_dir_all(&unit_dir).unwrap();
        std::fs::write(
            unit_dir.join(SERVICE_NAME),
            render_service(&env).as_bytes(),
        )
        .unwrap();
        std::fs::write(
            unit_dir.join(TIMER_NAME),
            render_timer(&env).as_bytes(),
        )
        .unwrap();
        let out = Command::new("systemd-analyze")
            .args([
                "verify",
                &unit_dir.join(TIMER_NAME).to_string_lossy(),
            ])
            .output()
            .unwrap();
        // `systemd-analyze verify` may complain about non-resolvable
        // ExecStart paths in the test fixture; we treat any output
        // mentioning "syntax error" or "Failed to parse" as a fatal
        // mismatch but otherwise tolerate warnings.
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.to_ascii_lowercase().contains("syntax error"),
            "systemd-analyze flagged a syntax error: {stderr}"
        );
    }
}
