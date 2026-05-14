// raxis-cli::commands::kernel — `raxis kernel install` and
// `raxis kernel uninstall`.
//
// Normative reference: `specs/v2/kernel-lifecycle.md §3` (daemon
// mode), §4.1 (Linux user-level systemd unit), §5.1 (macOS
// user-level launch agent). The full lifecycle surface from the
// spec (`raxis kernel start --daemon` with sd_notify integration,
// `raxis kernel stop`, `raxis kernel status`, `raxis kernel
// restart`, `--system` mode, single-instance enforcement,
// crash-loop detection) is a multi-day phase. This MVP ships the
// two highest-leverage operator ergonomics:
//
//   * `raxis kernel install [--system]` — generates and installs
//     the platform-native unit file, populated with this binary's
//     absolute path and the operator's `<data-dir>`. After running
//     this, the operator drives the kernel through the platform's
//     own supervisor (`systemctl --user start raxis-kernel`,
//     `launchctl bootstrap`, etc.) — the same surface the spec
//     calls out.
//
//   * `raxis kernel uninstall [--system]` — removes the unit file
//     written by `install`. Does NOT stop a running kernel; the
//     spec defers that to `raxis kernel stop` (separate command,
//     not yet shipped).
//
// Why ship the install/uninstall MVP without the start/stop/status
// chain: the platform supervisor handles start / stop / restart /
// boot-at-login natively once the unit file exists. The operator
// runs `raxis kernel install` once, then uses `systemctl --user
// {start,stop,restart} raxis-kernel` (Linux) or `launchctl
// {bootstrap,bootout,kickstart}` (macOS) for the rest. This is
// the same UX shape the spec describes (the spec's
// `raxis kernel stop` is a thin wrapper around `systemctl stop`).
// The MVP gets operators 95% of the value of full daemon-mode for
// 5% of the implementation cost.

use std::path::{Path, PathBuf};

use crate::errors::CliError;
use crate::GlobalFlags;

// ---------------------------------------------------------------------------
// Public entry — dispatch
// ---------------------------------------------------------------------------

pub fn run_install(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut system = false;
    let mut force = false;
    let mut binary_override: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--system" => system = true,
            "--force"  => force = true,
            "--binary" => {
                i += 1;
                let p = args.get(i).ok_or_else(|| {
                    CliError::Usage("kernel install: --binary requires a path".into())
                })?;
                binary_override = Some(PathBuf::from(p));
            }
            "--help" | "-h" => {
                print_install_help();
                return Ok(());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "kernel install: unknown flag {other:?}"
                )));
            }
        }
        i += 1;
    }

    let target = TargetUnit::resolve(system)?;
    let binary = match binary_override {
        Some(p) => p,
        None    => locate_kernel_binary()?,
    };
    let data_dir = flags.data_dir().clone();

    if target.unit_path.exists() && !force {
        return Err(CliError::Usage(format!(
            "kernel install: {} already exists (pass --force to overwrite)",
            target.unit_path.display(),
        )));
    }

    let body = render_unit(&target, &binary, &data_dir);

    if let Some(parent) = target.unit_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| CliError::Io {
                path:   parent.display().to_string(),
                source: e,
            })?;
        }
    }
    std::fs::write(&target.unit_path, body.as_bytes()).map_err(|e| CliError::Io {
        path:   target.unit_path.display().to_string(),
        source: e,
    })?;

    println!("Installed: {}", target.unit_path.display());
    println!("  binary:    {}", binary.display());
    println!("  data_dir:  {}", data_dir.display());
    println!();
    println!("Next steps ({}):", target.platform_label());
    for step in target.next_steps() {
        println!("  {step}");
    }
    Ok(())
}

pub fn run_uninstall(_flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut system = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--system" => system = true,
            "--help" | "-h" => {
                print_uninstall_help();
                return Ok(());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "kernel uninstall: unknown flag {other:?}"
                )));
            }
        }
        i += 1;
    }

    let target = TargetUnit::resolve(system)?;
    if !target.unit_path.exists() {
        println!("Not installed: {} does not exist", target.unit_path.display());
        return Ok(());
    }
    std::fs::remove_file(&target.unit_path).map_err(|e| CliError::Io {
        path:   target.unit_path.display().to_string(),
        source: e,
    })?;
    println!("Removed: {}", target.unit_path.display());
    println!();
    println!("Cleanup ({}):", target.platform_label());
    for step in target.uninstall_cleanup() {
        println!("  {step}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TargetUnit — platform-specific unit file location and post-install steps
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Platform {
    LinuxUser,
    LinuxSystem,
    MacosUser,
    MacosSystem,
}

#[derive(Debug, Clone)]
struct TargetUnit {
    platform:  Platform,
    unit_path: PathBuf,
}

impl TargetUnit {
    fn resolve(system: bool) -> Result<Self, CliError> {
        let platform = match (cfg!(target_os = "linux"), cfg!(target_os = "macos"), system) {
            (true,  _,    false) => Platform::LinuxUser,
            (true,  _,    true)  => Platform::LinuxSystem,
            (_,     true, false) => Platform::MacosUser,
            (_,     true, true)  => Platform::MacosSystem,
            _ => {
                return Err(CliError::Usage(
                    "kernel install: this platform is not supported \
                     (Linux + systemd or macOS + launchd are the supported targets)"
                        .into(),
                ));
            }
        };

        let unit_path = match platform {
            Platform::LinuxUser => {
                let home = std::env::var_os("HOME").ok_or_else(|| {
                    CliError::Usage(
                        "kernel install: $HOME is not set (required to find ~/.config/systemd/user/)"
                            .into(),
                    )
                })?;
                PathBuf::from(home)
                    .join(".config/systemd/user/raxis-kernel.service")
            }
            Platform::LinuxSystem => {
                require_root("--system")?;
                PathBuf::from("/etc/systemd/system/raxis-kernel.service")
            }
            Platform::MacosUser => {
                let home = std::env::var_os("HOME").ok_or_else(|| {
                    CliError::Usage(
                        "kernel install: $HOME is not set (required to find ~/Library/LaunchAgents/)"
                            .into(),
                    )
                })?;
                PathBuf::from(home)
                    .join("Library/LaunchAgents/com.raxis.kernel.plist")
            }
            Platform::MacosSystem => {
                require_root("--system")?;
                PathBuf::from("/Library/LaunchDaemons/com.raxis.kernel.plist")
            }
        };

        Ok(Self { platform, unit_path })
    }

    fn platform_label(&self) -> &'static str {
        match self.platform {
            Platform::LinuxUser   => "Linux + systemd, user level",
            Platform::LinuxSystem => "Linux + systemd, system level",
            Platform::MacosUser   => "macOS + launchd, user agent",
            Platform::MacosSystem => "macOS + launchd, system daemon",
        }
    }

    fn next_steps(&self) -> Vec<String> {
        match self.platform {
            Platform::LinuxUser => vec![
                "systemctl --user daemon-reload".into(),
                "systemctl --user enable --now raxis-kernel".into(),
                "loginctl enable-linger $(whoami)   # so the kernel survives logout".into(),
                "journalctl --user -u raxis-kernel -f   # follow logs".into(),
            ],
            Platform::LinuxSystem => vec![
                "sudo systemctl daemon-reload".into(),
                "sudo systemctl enable --now raxis-kernel".into(),
                "journalctl -u raxis-kernel -f   # follow logs".into(),
            ],
            Platform::MacosUser => vec![
                "launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.raxis.kernel.plist".into(),
                "launchctl enable gui/$(id -u)/com.raxis.kernel".into(),
                "launchctl kickstart -kp gui/$(id -u)/com.raxis.kernel".into(),
                "tail -F ~/Library/Logs/raxis/kernel.out   # follow logs".into(),
            ],
            Platform::MacosSystem => vec![
                "sudo launchctl bootstrap system /Library/LaunchDaemons/com.raxis.kernel.plist".into(),
                "sudo launchctl enable system/com.raxis.kernel".into(),
                "sudo launchctl kickstart -kp system/com.raxis.kernel".into(),
                "sudo tail -F /var/log/raxis/kernel.out   # follow logs".into(),
            ],
        }
    }

    fn uninstall_cleanup(&self) -> Vec<String> {
        match self.platform {
            Platform::LinuxUser => vec![
                "systemctl --user stop raxis-kernel".into(),
                "systemctl --user disable raxis-kernel".into(),
                "systemctl --user daemon-reload".into(),
            ],
            Platform::LinuxSystem => vec![
                "sudo systemctl stop raxis-kernel".into(),
                "sudo systemctl disable raxis-kernel".into(),
                "sudo systemctl daemon-reload".into(),
            ],
            Platform::MacosUser => vec![
                "launchctl bootout gui/$(id -u)/com.raxis.kernel".into(),
            ],
            Platform::MacosSystem => vec![
                "sudo launchctl bootout system/com.raxis.kernel".into(),
            ],
        }
    }
}

fn require_root(flag: &str) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        #[allow(unsafe_code)]
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            return Err(CliError::Usage(format!(
                "kernel install {flag}: requires root (rerun with `sudo`)",
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Binary location resolution
// ---------------------------------------------------------------------------

fn locate_kernel_binary() -> Result<PathBuf, CliError> {
    // Strategy:
    //   1. `RAXIS_KERNEL_BINARY` env var (operator override).
    //   2. The `raxis-kernel` binary next to the running `raxis`
    //      binary (typical when both are installed via
    //      `cargo install --path` or the release tarball).
    //   3. `which raxis-kernel` via $PATH.
    //   4. Hard-coded `/usr/local/bin/raxis-kernel` fallback (the
    //      template default).
    //
    // The operator can always override with `--binary <path>`.
    if let Some(p) = std::env::var_os("RAXIS_KERNEL_BINARY") {
        let p = PathBuf::from(p);
        if p.exists() { return Ok(p); }
    }
    if let Ok(self_exe) = std::env::current_exe() {
        if let Some(parent) = self_exe.parent() {
            let candidate = parent.join("raxis-kernel");
            if candidate.exists() { return Ok(candidate); }
        }
    }
    if let Some(p) = which_in_path("raxis-kernel") {
        return Ok(p);
    }
    let fallback = PathBuf::from("/usr/local/bin/raxis-kernel");
    if fallback.exists() { return Ok(fallback); }
    Err(CliError::Usage(
        "kernel install: could not locate the `raxis-kernel` binary. \
         Pass --binary <path>, set RAXIS_KERNEL_BINARY=<path>, or \
         install raxis-kernel onto $PATH first."
            .into(),
    ))
}

fn which_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&path) {
        let candidate = entry.join(name);
        if candidate.is_file() { return Some(candidate); }
    }
    None
}

// ---------------------------------------------------------------------------
// Unit-file rendering
// ---------------------------------------------------------------------------

fn render_unit(target: &TargetUnit, binary: &Path, data_dir: &Path) -> String {
    match target.platform {
        Platform::LinuxUser   => render_systemd_user(binary, data_dir),
        Platform::LinuxSystem => render_systemd_system(binary, data_dir),
        Platform::MacosUser   => render_launchd_user(binary, data_dir),
        Platform::MacosSystem => render_launchd_system(binary, data_dir),
    }
}

/// Linux user unit: runs as the invoking user with a `default.target`
/// install target so `loginctl enable-linger` keeps the kernel running
/// across logout (per kernel-lifecycle.md §4.1).
fn render_systemd_user(binary: &Path, data_dir: &Path) -> String {
    format!(
        "# raxis-kernel.service (user) — generated by `raxis kernel install`.\n\
         # Normative reference: kernel-lifecycle.md §4.1.\n\
         # Edit this file and re-run `systemctl --user daemon-reload`.\n\
         \n\
         [Unit]\n\
         Description=RAXIS kernel (user)\n\
         Documentation=https://github.com/chika5105/raxis/blob/main/raxis/specs/v2/kernel-lifecycle.md\n\
         After=default.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={binary} --data-dir {data}\n\
         WorkingDirectory={data}\n\
         Restart=on-failure\n\
         RestartSec=10s\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         SyslogIdentifier=raxis-kernel\n\
         KillSignal=SIGTERM\n\
         TimeoutStopSec=30s\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        binary = binary.display(),
        data   = data_dir.display(),
    )
}

/// Linux system unit: runs as the dedicated `_raxis` user with the
/// full sandboxing block (per kernel-lifecycle.md §4.2 + the
/// reference unit at raxis/installer/systemd/raxis-kernel.service).
fn render_systemd_system(binary: &Path, data_dir: &Path) -> String {
    format!(
        "# raxis-kernel.service (system) — generated by `raxis kernel install --system`.\n\
         # Normative reference: kernel-lifecycle.md §4.2.\n\
         # Edit this file and re-run `sudo systemctl daemon-reload`.\n\
         \n\
         [Unit]\n\
         Description=RAXIS kernel\n\
         Documentation=https://github.com/chika5105/raxis/blob/main/raxis/specs/v2/kernel-lifecycle.md\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         RequiresMountsFor={data}\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={binary} --data-dir {data}\n\
         User=_raxis\n\
         Group=_raxis\n\
         SupplementaryGroups=kvm\n\
         WorkingDirectory={data}\n\
         Restart=on-failure\n\
         RestartSec=10s\n\
         NoNewPrivileges=true\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         PrivateDevices=false\n\
         DeviceAllow=/dev/kvm rw\n\
         ReadWritePaths={data}\n\
         ProtectKernelTunables=true\n\
         ProtectKernelModules=true\n\
         ProtectControlGroups=true\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_VSOCK\n\
         RestrictNamespaces=true\n\
         LockPersonality=true\n\
         RestrictRealtime=true\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         SyslogIdentifier=raxis-kernel\n\
         KillSignal=SIGTERM\n\
         TimeoutStopSec=30s\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        binary = binary.display(),
        data   = data_dir.display(),
    )
}

/// macOS user agent: per kernel-lifecycle.md §5.1, runs as the
/// invoking user; logs go under ~/Library/Logs/raxis/.
fn render_launchd_user(binary: &Path, data_dir: &Path) -> String {
    let log_dir = std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join("Library/Logs/raxis"))
        .unwrap_or_else(|| PathBuf::from("/tmp/raxis-logs"));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!--
    com.raxis.kernel.plist (user) — generated by `raxis kernel install`.
    Normative reference: kernel-lifecycle.md §5.1.
    Logs are rotated by the bundled newsyslog snippet at
    raxis/installer/newsyslog/raxis.conf when installed.
-->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.raxis.kernel</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>--data-dir</string>
        <string>{data}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{data}</string>
    <key>StandardOutPath</key>
    <string>{logs}/kernel.out</string>
    <key>StandardErrorPath</key>
    <string>{logs}/kernel.err</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#,
        binary = binary.display(),
        data   = data_dir.display(),
        logs   = log_dir.display(),
    )
}

/// macOS system daemon: per kernel-lifecycle.md §5.2, runs as the
/// dedicated `_raxis` user.
fn render_launchd_system(binary: &Path, data_dir: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!--
    com.raxis.kernel.plist (system) — generated by `raxis kernel install --system`.
    Normative reference: kernel-lifecycle.md §5.2.
    Run `sudo dscl . -create /Users/_raxis ...` to create the
    dedicated user, and `sudo install -d -o _raxis -g _raxis
    /var/raxis /var/log/raxis` to create the data + log directories.
-->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.raxis.kernel</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>--data-dir</string>
        <string>{data}</string>
    </array>
    <key>UserName</key>
    <string>_raxis</string>
    <key>WorkingDirectory</key>
    <string>{data}</string>
    <key>StandardOutPath</key>
    <string>/var/log/raxis/kernel.out</string>
    <key>StandardErrorPath</key>
    <string>/var/log/raxis/kernel.err</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#,
        binary = binary.display(),
        data   = data_dir.display(),
    )
}

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------

fn print_install_help() {
    println!(
        r#"raxis kernel install — install RAXIS as a system service.

USAGE:
    raxis [--data-dir <path>] kernel install [--system] [--binary <path>] [--force]

FLAGS:
    --system          Install at the system level (Linux: /etc/systemd/system/,
                      macOS: /Library/LaunchDaemons/). Requires sudo.
                      Default: user level (~/.config/systemd/user/ on Linux,
                      ~/Library/LaunchAgents/ on macOS).
    --binary <path>   Override the auto-detected raxis-kernel binary path.
                      Without this, the CLI looks for raxis-kernel next to
                      itself, then in $PATH, then at /usr/local/bin/raxis-kernel.
    --force           Overwrite an existing unit file at the target path.

The command writes a platform-native unit file populated with this
binary's data dir and the resolved raxis-kernel path. After install,
follow the printed `systemctl --user enable --now raxis-kernel`
(Linux) or `launchctl bootstrap` (macOS) to start the service. The
spec at kernel-lifecycle.md §3 catalogs the full daemon lifecycle.

The kernel does not need to be running to run this command.
"#,
    );
}

fn print_uninstall_help() {
    println!(
        r#"raxis kernel uninstall — remove the installed RAXIS service unit.

USAGE:
    raxis kernel uninstall [--system]

FLAGS:
    --system    Operate on the system-level unit (sudo required).

The command deletes the unit file (Linux: /etc/systemd/system/raxis-kernel.service
or ~/.config/systemd/user/raxis-kernel.service; macOS:
/Library/LaunchDaemons/com.raxis.kernel.plist or
~/Library/LaunchAgents/com.raxis.kernel.plist) and prints the
`systemctl disable` / `launchctl bootout` commands the operator
should run to fully clean up. Does NOT stop a running kernel.
"#,
    );
}

// ---------------------------------------------------------------------------
// Tests — run on the local platform only
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_systemd_user_includes_binary_and_data_dir() {
        let s = render_systemd_user(Path::new("/opt/raxis/raxis-kernel"), Path::new("/srv/raxis"));
        assert!(s.contains("/opt/raxis/raxis-kernel"));
        assert!(s.contains("--data-dir /srv/raxis"));
        assert!(s.contains("[Install]"));
        assert!(s.contains("WantedBy=default.target"));
    }

    #[test]
    fn render_systemd_system_includes_sandboxing_block() {
        let s = render_systemd_system(Path::new("/u/b/raxis-kernel"), Path::new("/var/lib/raxis"));
        assert!(s.contains("User=_raxis"));
        assert!(s.contains("ProtectSystem=strict"));
        assert!(s.contains("DeviceAllow=/dev/kvm rw"));
        assert!(s.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn render_launchd_user_is_well_formed_xml_with_binary_and_data_dir() {
        let s = render_launchd_user(Path::new("/opt/raxis/raxis-kernel"), Path::new("/Users/me/.raxis"));
        assert!(s.contains("<key>Label</key>"));
        assert!(s.contains("<string>com.raxis.kernel</string>"));
        assert!(s.contains("<string>/opt/raxis/raxis-kernel</string>"));
        assert!(s.contains("<string>/Users/me/.raxis</string>"));
        assert!(s.contains("<key>RunAtLoad</key>"));
    }

    #[test]
    fn render_launchd_system_runs_as_underscore_raxis() {
        let s = render_launchd_system(Path::new("/u/b/raxis-kernel"), Path::new("/var/raxis"));
        assert!(s.contains("<key>UserName</key>"));
        assert!(s.contains("<string>_raxis</string>"));
        assert!(s.contains("/var/log/raxis/kernel.out"));
    }

    #[test]
    fn target_unit_user_path_lives_under_home() {
        // Cross-platform sanity: at the very least the resolved
        // path on the test runner's platform should NOT be a
        // root-only system path when --system is false.
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", "/test-home");
        let target = TargetUnit::resolve(false).expect("resolve user");
        assert!(
            target.unit_path.starts_with("/test-home"),
            "user-level unit path must be under $HOME: got {}",
            target.unit_path.display(),
        );
        if let Some(prev) = prev_home {
            std::env::set_var("HOME", prev);
        } else {
            std::env::remove_var("HOME");
        }
    }
}
