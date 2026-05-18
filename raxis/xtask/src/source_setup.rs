//! `cargo xtask source-setup` — one-shot local source setup.
//!
//! This is the operator-facing "fresh checkout to runnable local
//! artefacts" path. It delegates to the existing typed xtask modules
//! instead of duplicating their logic:
//!
//! 1. Host prerequisites (`dev-prereqs --install` on macOS,
//!    `linux-prereqs` on Linux).
//! 2. Host release tools except `raxis-kernel`.
//! 3. Dashboard frontend build (`npm ci`, `npm run build`).
//! 4. Guest image bake (`images bake`) including guest-kernel
//!    nftables validation.
//! 5. Host `raxis-kernel` rebuild with the bake's trust anchor.
//! 6. Trust-anchor verification and optional macOS ad-hoc codesign.
//!
//! The goal is not to hide the steps; it is to make the canonical
//! sequence reproducible and loud about the long waits operators will
//! otherwise mistake for a hang.

use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use anyhow::{bail, Context, Result};

const DEFAULT_INSTALL_DIR: &str = "/usr/local/lib/raxis";

#[derive(Debug, Clone)]
struct Args {
    install_dir: PathBuf,
    kernel_from_file: Option<PathBuf>,
    kernel_url: Option<String>,
    kernel_sha256: Option<String>,
    kernel_config: Option<PathBuf>,
    builder: Option<String>,
    no_cache: bool,
    force: bool,
    skip_prereqs: bool,
    skip_dashboard: bool,
    skip_codesign: bool,
    with_observability: bool,
    dry_run: bool,
}

impl Args {
    fn parse(argv: &[String]) -> Result<Self> {
        let mut install_dir = std::env::var_os("RAXIS_INSTALL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_INSTALL_DIR));
        let mut kernel_from_file = None;
        let mut kernel_url = None;
        let mut kernel_sha256 = None;
        let mut kernel_config = None;
        let mut builder = None;
        let mut no_cache = false;
        let mut force = false;
        let mut skip_prereqs = false;
        let mut skip_dashboard = false;
        let mut skip_codesign = false;
        let mut with_observability = false;
        let mut dry_run = false;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--install-dir" => {
                    i += 1;
                    install_dir =
                        PathBuf::from(argv.get(i).context("--install-dir requires a path")?);
                }
                "--kernel-from-file" => {
                    i += 1;
                    kernel_from_file = Some(PathBuf::from(
                        argv.get(i).context("--kernel-from-file requires a path")?,
                    ));
                }
                "--kernel-url" => {
                    i += 1;
                    kernel_url = Some(argv.get(i).context("--kernel-url requires a URL")?.clone());
                }
                "--kernel-sha256" => {
                    i += 1;
                    let value = argv
                        .get(i)
                        .context("--kernel-sha256 requires a 64-hex digest")?;
                    if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                        bail!("--kernel-sha256 must be a 64-character hex digest");
                    }
                    kernel_sha256 = Some(value.to_ascii_lowercase());
                }
                "--kernel-config" => {
                    i += 1;
                    kernel_config = Some(PathBuf::from(
                        argv.get(i).context("--kernel-config requires a path")?,
                    ));
                }
                "--builder" => {
                    i += 1;
                    builder = Some(argv.get(i).context("--builder requires a value")?.clone());
                }
                "--no-cache" => no_cache = true,
                "--force" => force = true,
                "--skip-prereqs" => skip_prereqs = true,
                "--skip-dashboard" => skip_dashboard = true,
                "--skip-codesign" => skip_codesign = true,
                "--with-observability" => with_observability = true,
                "--dry-run" => dry_run = true,
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                other => bail!("unknown source-setup arg: {other}"),
            }
            i += 1;
        }

        if kernel_from_file.is_some() && kernel_url.is_some() {
            bail!("pass either --kernel-from-file or --kernel-url, not both");
        }
        if kernel_url.is_some() && kernel_sha256.is_none() {
            bail!("--kernel-url requires --kernel-sha256 so downloaded vmlinux bytes are pinned");
        }
        if kernel_url.is_none() && kernel_sha256.is_some() {
            bail!("--kernel-sha256 is only valid with --kernel-url");
        }

        Ok(Self {
            install_dir,
            kernel_from_file,
            kernel_url,
            kernel_sha256,
            kernel_config,
            builder,
            no_cache,
            force,
            skip_prereqs,
            skip_dashboard,
            skip_codesign,
            with_observability,
            dry_run,
        })
    }

    fn bake_argv(&self) -> Vec<String> {
        let mut argv = vec![
            "--install-dir".to_owned(),
            self.install_dir.display().to_string(),
        ];
        if let Some(path) = &self.kernel_from_file {
            argv.push("--kernel-from-file".to_owned());
            argv.push(path.display().to_string());
        }
        if let Some(path) = &self.kernel_config {
            argv.push("--kernel-config".to_owned());
            argv.push(path.display().to_string());
        }
        if let Some(builder) = &self.builder {
            argv.push("--builder".to_owned());
            argv.push(builder.clone());
        }
        if self.force {
            argv.push("--force".to_owned());
        }
        if self.no_cache {
            argv.push("--no-cache".to_owned());
        }
        argv
    }

    fn dev_kernel_argv(&self) -> Option<Vec<String>> {
        let url = self.kernel_url.as_ref()?;
        let sha256 = self
            .kernel_sha256
            .as_ref()
            .expect("parse requires --kernel-sha256 with --kernel-url");
        let mut argv = vec![
            "--install-dir".to_owned(),
            self.install_dir.display().to_string(),
            "--url".to_owned(),
            url.clone(),
            "--sha256".to_owned(),
            sha256.clone(),
        ];
        if let Some(path) = &self.kernel_config {
            argv.push("--config".to_owned());
            argv.push(path.display().to_string());
        }
        if self.force {
            argv.push("--force".to_owned());
        }
        Some(argv)
    }
}

fn print_help() {
    eprintln!(
        "usage: cargo xtask source-setup \n         \
         [--install-dir <PATH>]\n         \
         [--kernel-from-file <PATH> | --kernel-url <URL> --kernel-sha256 <HEX>]\n         \
         [--kernel-config <PATH>]\n         \
         [--builder docker|podman|buildah] [--force] [--no-cache]\n         \
         [--skip-prereqs] [--skip-dashboard] [--skip-codesign]\n         \
         [--with-observability] [--dry-run]\n\
         \n\
         One-shot source setup for a local development/e2e host. It prints\n\
         every phase with expected duration, then runs prereqs, host builds,\n\
         dashboard build, guest image bake, trust-anchored raxis-kernel build,\n\
         trust-anchor verification, and optional macOS codesign.\n\
         \n\
         Typical macOS command:\n\
           cargo xtask source-setup --install-dir $HOME/.raxis-install \\\n\
             --kernel-from-file /path/to/vmlinux \\\n\
             --kernel-config /path/to/vmlinux.config --no-cache\n\
         \n\
         Pinned prebuilt kernel variant:\n\
           cargo xtask source-setup --install-dir $HOME/.raxis-install \\\n\
             --kernel-url https://example.com/vmlinux-aarch64 \\\n\
             --kernel-sha256 <64-hex> \\\n\
             --kernel-config /path/to/vmlinux.config\n\
         \n\
         Notes:\n  \
         * Prefer a user-writable --install-dir for dev. /usr/local/lib/raxis\n\
           may require elevated permissions.\n  \
         * The guest kernel must satisfy images/kernel/raxis-guest-a3-netfilter.config.\n  \
         * --dry-run prints the plan and exits without changing anything.\n"
    );
}

pub fn run(argv: &[String]) -> Result<()> {
    let args = Args::parse(argv)?;
    let workspace_root = workspace_root_from_cwd()?;
    print_plan(&args, &workspace_root);
    if args.dry_run {
        eprintln!(
            "{}",
            serde_json::json!({
                "level": "info",
                "event": "source_setup_dry_run_ok",
                "message": "plan printed; no commands executed",
            })
        );
        return Ok(());
    }

    if !args.skip_prereqs {
        if cfg!(target_os = "macos") {
            run_module_step(
                "host_prereqs",
                "2-20 min first run; usually seconds after that",
                "Install/verify host prerequisites. macOS may prompt for Homebrew downloads and sudo for the firewall allowlist.",
                || crate::dev_prereqs::run(&["--install".to_owned()]),
            )?;
        } else if cfg!(target_os = "linux") {
            run_command_step(
                "host_prereqs",
                "2-20 min first run; usually seconds after that",
                "Verify Linux KVM, vsock, cgroup, and Firecracker substrate prerequisites.",
                xtask_self_command(&workspace_root, &["linux-prereqs"])?,
            )?;
        } else {
            bail!("source-setup supports macOS and Linux hosts only");
        }
    }

    run_command_step(
        "host_tools_build",
        "3-15 min first run; usually under 2 min incrementally",
        "Build operator CLI, gateway, pusher, and supervisor with the checked-in lockfile.",
        cargo_command(
            &workspace_root,
            &[
                "build",
                "--release",
                "--locked",
                "-p",
                "raxis-cli",
                "-p",
                "raxis-gateway",
                "-p",
                "raxis-otel-pusher",
                "-p",
                "raxis-supervisor",
            ],
        ),
    )?;

    if !args.skip_dashboard {
        let dashboard_dir = workspace_root.join("dashboard-fe");
        run_command_step(
            "dashboard_npm_ci",
            "1-5 min first run; seconds when npm cache is warm",
            "Install dashboard frontend dependencies from package-lock.json.",
            command_in(&dashboard_dir, "npm", &["ci"]),
        )?;
        run_command_step(
            "dashboard_build",
            "30-90 sec",
            "Compile the dashboard frontend bundle.",
            command_in(&dashboard_dir, "npm", &["run", "build"]),
        )?;
    }

    if let Some(dev_kernel_args) = args.dev_kernel_argv() {
        run_module_step(
            "guest_kernel_stage",
            "1-10 min depending on download speed; seconds when cached locally",
            "Download or stage the pinned prebuilt Linux guest kernel, verify SHA-256, and validate/stage its nftables config.",
            || crate::dev_kernel::run(&dev_kernel_args),
        )?;
    }

    let bake_args = args.bake_argv();
    run_module_step(
        "guest_image_bake",
        "10-45 min with --no-cache; seconds-minutes when manifests are unchanged",
        "Bake rootfs-producing roles, cross-compile guest binaries, validate/stage vmlinux, pack signed initramfs images.",
        || crate::images::run_bake(&bake_args),
    )?;

    let resolved_anchor = crate::trust_anchor::resolve_signing_key_pk_hex(&workspace_root)
        .map_err(anyhow::Error::new)
        .context("resolve image-signing public key for host raxis-kernel rebuild")?;
    let mut kernel_build = cargo_command(
        &workspace_root,
        &["build", "--release", "--locked", "-p", "raxis-kernel"],
    );
    kernel_build.env("RAXIS_KERNEL_SIGNING_KEY_HEX", &resolved_anchor.pk_hex);
    run_command_step(
        "host_kernel_build",
        "2-10 min first run; usually under 2 min incrementally",
        "Rebuild raxis-kernel with the same public trust anchor used by the baked images.",
        kernel_build,
    )?;

    let kernel_path = workspace_root.join("target/release/raxis-kernel");
    run_module_step(
        "trust_anchor_verify",
        "under 5 sec",
        "Verify target/release/raxis-kernel embeds the expected canonical-image trust anchor.",
        || {
            crate::images::run_verify_trust_anchor(&[
                "--kernel".to_owned(),
                kernel_path.display().to_string(),
            ])
        },
    )?;

    if cfg!(target_os = "macos") && !args.skip_codesign {
        run_module_step(
            "macos_codesign",
            "under 30 sec",
            "Ad-hoc sign target/release/raxis-kernel with AVF entitlements.",
            || crate::dev_codesign::run(&["--profile".to_owned(), "release".to_owned()]),
        )?;
    }

    if args.with_observability {
        run_module_step(
            "observability_stack",
            "30-120 sec if images already exist; longer on first Docker pull",
            "Start OTel Collector, Prometheus, and Grafana for local validation.",
            || crate::observability::run(&["up".to_owned(), "--no-open".to_owned()]),
        )?;
    }

    eprintln!(
        "{}",
        serde_json::json!({
            "level": "info",
            "event": "source_setup_ok",
            "install_dir": args.install_dir.display().to_string(),
            "kernel_binary": kernel_path.display().to_string(),
            "next": "run `target/release/raxis-kernel` or continue with `raxis setup --interactive`",
        })
    );
    Ok(())
}

fn print_plan(args: &Args, workspace_root: &std::path::Path) {
    eprintln!(
        "{}",
        serde_json::json!({
            "level": "info",
            "event": "source_setup_plan",
            "workspace_root": workspace_root.display().to_string(),
            "install_dir": args.install_dir.display().to_string(),
            "steps": [
                {"name": "host_prereqs", "estimate": "2-20 min first run", "skipped": args.skip_prereqs},
                {"name": "host_tools_build", "estimate": "3-15 min first run"},
                {"name": "dashboard_build", "estimate": "1-6 min", "skipped": args.skip_dashboard},
                {"name": "guest_kernel_stage", "estimate": "1-10 min when --kernel-url is used", "skipped": args.kernel_url.is_none()},
                {"name": "guest_image_bake", "estimate": "10-45 min with --no-cache"},
                {"name": "host_kernel_build", "estimate": "2-10 min first run"},
                {"name": "trust_anchor_verify", "estimate": "under 5 sec"},
                {"name": "macos_codesign", "estimate": "under 30 sec", "skipped": args.skip_codesign || !cfg!(target_os = "macos")},
                {"name": "observability_stack", "estimate": "30-120 sec", "skipped": !args.with_observability}
            ],
            "long_wait_hint": "During clean bakes, Docker pulls, apt installs, Rust cross-compiles, and cpio packing may sit quiet for several minutes; bake emits step-specific progress events before each long phase.",
        })
    );
}

fn run_module_step<F>(name: &str, estimate: &str, detail: &str, f: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let started = begin_step(name, estimate, detail);
    f().with_context(|| format!("source-setup step {name}"))?;
    finish_step(name, started);
    Ok(())
}

fn run_command_step(name: &str, estimate: &str, detail: &str, mut cmd: Command) -> Result<()> {
    let started = begin_step(name, estimate, detail);
    eprintln!(
        "{}",
        serde_json::json!({
            "level": "info",
            "event": "source_setup_command",
            "step": name,
            "program": cmd.get_program().to_string_lossy(),
            "args": cmd
                .get_args()
                .map(|a| a.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
        })
    );
    let status = cmd
        .status()
        .with_context(|| format!("spawn source-setup command for step {name}"))?;
    if !status.success() {
        bail!("source-setup step {name} exited {status}");
    }
    finish_step(name, started);
    Ok(())
}

fn begin_step(name: &str, estimate: &str, detail: &str) -> Instant {
    eprintln!(
        "{}",
        serde_json::json!({
            "level": "info",
            "event": "source_setup_step_begin",
            "step": name,
            "estimate": estimate,
            "detail": detail,
        })
    );
    Instant::now()
}

fn finish_step(name: &str, started: Instant) {
    eprintln!(
        "{}",
        serde_json::json!({
            "level": "info",
            "event": "source_setup_step_ok",
            "step": name,
            "elapsed_ms": started.elapsed().as_millis(),
        })
    );
}

fn cargo_command(workspace_root: &std::path::Path, args: &[&str]) -> Command {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    command_in(workspace_root, &cargo, args)
}

fn xtask_self_command(workspace_root: &std::path::Path, args: &[&str]) -> Result<Command> {
    let exe = std::env::current_exe().context("resolve current xtask executable")?;
    let mut cmd = Command::new(exe);
    cmd.current_dir(workspace_root).args(args);
    Ok(cmd)
}

fn command_in(cwd: &std::path::Path, program: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(program);
    cmd.current_dir(cwd).args(args);
    cmd
}

fn workspace_root_from_cwd() -> Result<PathBuf> {
    let mut cwd = std::env::current_dir().context("cannot read CWD")?;
    loop {
        let candidate = cwd.join("Cargo.toml");
        if candidate.exists() {
            let s = std::fs::read_to_string(&candidate)
                .with_context(|| format!("read {}", candidate.display()))?;
            if s.contains("[workspace]") {
                return Ok(cwd);
            }
        }
        if !cwd.pop() {
            bail!("could not find workspace root from current directory");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_defaults_to_standard_install_dir() {
        let args = Args::parse(&[]).unwrap();
        let expected = std::env::var_os("RAXIS_INSTALL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_INSTALL_DIR));
        assert_eq!(args.install_dir, expected);
        assert!(!args.no_cache);
        assert!(!args.skip_dashboard);
    }

    #[test]
    fn parse_accepts_one_shot_flags() {
        let argv = vec![
            "--install-dir".to_owned(),
            "/tmp/raxis-install".to_owned(),
            "--kernel-from-file".to_owned(),
            "/tmp/vmlinux".to_owned(),
            "--kernel-config".to_owned(),
            "/tmp/vmlinux.config".to_owned(),
            "--builder".to_owned(),
            "docker".to_owned(),
            "--force".to_owned(),
            "--no-cache".to_owned(),
            "--skip-prereqs".to_owned(),
            "--skip-dashboard".to_owned(),
            "--skip-codesign".to_owned(),
            "--with-observability".to_owned(),
            "--dry-run".to_owned(),
        ];
        let args = Args::parse(&argv).unwrap();
        assert_eq!(args.install_dir, PathBuf::from("/tmp/raxis-install"));
        assert_eq!(args.kernel_from_file, Some(PathBuf::from("/tmp/vmlinux")));
        assert_eq!(args.kernel_url, None);
        assert_eq!(args.kernel_sha256, None);
        assert_eq!(
            args.kernel_config,
            Some(PathBuf::from("/tmp/vmlinux.config"))
        );
        assert_eq!(args.builder.as_deref(), Some("docker"));
        assert!(args.force);
        assert!(args.no_cache);
        assert!(args.skip_prereqs);
        assert!(args.skip_dashboard);
        assert!(args.skip_codesign);
        assert!(args.with_observability);
        assert!(args.dry_run);
    }

    #[test]
    fn bake_argv_threads_kernel_and_cache_flags() {
        let args = Args {
            install_dir: PathBuf::from("/tmp/install"),
            kernel_from_file: Some(PathBuf::from("/tmp/vmlinux")),
            kernel_url: None,
            kernel_sha256: None,
            kernel_config: Some(PathBuf::from("/tmp/config")),
            builder: Some("docker".to_owned()),
            force: true,
            no_cache: true,
            skip_prereqs: false,
            skip_dashboard: false,
            skip_codesign: false,
            with_observability: false,
            dry_run: false,
        };
        let argv = args.bake_argv();
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--install-dir" && w[1] == "/tmp/install"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--kernel-from-file" && w[1] == "/tmp/vmlinux"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--kernel-config" && w[1] == "/tmp/config"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--builder" && w[1] == "docker"));
        assert!(argv.contains(&"--force".to_owned()));
        assert!(argv.contains(&"--no-cache".to_owned()));
    }

    #[test]
    fn prebuilt_kernel_url_requires_sha_and_builds_dev_kernel_argv() {
        let sha = "a".repeat(64);
        let argv = vec![
            "--install-dir".to_owned(),
            "/tmp/install".to_owned(),
            "--kernel-url".to_owned(),
            "https://example.test/vmlinux".to_owned(),
            "--kernel-sha256".to_owned(),
            sha.clone(),
            "--kernel-config".to_owned(),
            "/tmp/config".to_owned(),
            "--force".to_owned(),
        ];
        let args = Args::parse(&argv).unwrap();
        let dev_kernel_argv = args.dev_kernel_argv().unwrap();
        assert!(dev_kernel_argv
            .windows(2)
            .any(|w| w[0] == "--url" && w[1] == "https://example.test/vmlinux"));
        assert!(dev_kernel_argv
            .windows(2)
            .any(|w| w[0] == "--sha256" && w[1] == sha));
        assert!(dev_kernel_argv
            .windows(2)
            .any(|w| w[0] == "--config" && w[1] == "/tmp/config"));
        assert!(dev_kernel_argv.contains(&"--force".to_owned()));
        assert!(!args.bake_argv().contains(&"--kernel-from-file".to_owned()));

        let missing_sha = Args::parse(&[
            "--kernel-url".to_owned(),
            "https://example.test/vmlinux".to_owned(),
        ])
        .unwrap_err()
        .to_string();
        assert!(missing_sha.contains("--kernel-url requires --kernel-sha256"));
    }
}
