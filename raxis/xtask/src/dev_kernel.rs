//! `cargo xtask images dev-kernel` — install a Linux guest-kernel
//! binary into `$RAXIS_INSTALL_DIR/kernel/vmlinux` for AVF / Firecracker
//! microVM boot.
//!
//! Normative references:
//!
//! * `raxis/specs/v2/system-requirements.md §11` — `$RAXIS_INSTALL_DIR`
//!   layout. The kernel binary resolves the guest-kernel path via
//!   [`raxis_kernel::canonical_images_preflight::linux_kernel_path`],
//!   which is `<install_dir>/kernel/vmlinux`.
//! * `raxis/specs/v2/extensibility-traits.md §3.4` — `VmSpec.linux_kernel_path`
//!   contract: substrate hands this exact path to AVF's
//!   `VZLinuxBootLoader.kernelURL` / Firecracker's
//!   `PUT /boot-source { kernel_image_path }`.
//! * `raxis/kernel/src/canonical_images_preflight.rs::linux_kernel_path`
//!   — the operative path-resolution helper.
//!
//! ## What this command does
//!
//! Stages a guest-kernel binary at the V2-canonical layout location,
//! verifying the bytes against an operator-supplied SHA-256.
//!
//! Two source modes:
//!
//! * `--from-file PATH` — copy a local kernel binary into place.
//!   Hermetic, recommended for CI and air-gapped environments.
//! * `--url URL --sha256 HEX` — `curl -fL` the URL, verify SHA-256,
//!   install on success. We shell out to `curl(1)` (universally
//!   available on macOS + Linux dev boxes) rather than introducing a
//!   `reqwest` dependency in `xtask` — `xtask` is a build-tooling
//!   crate, not an end-user surface, so the dependency hygiene goal
//!   is "zero new transitive deps unless they pay rent".
//!
//! ## Why we don't hardcode a single pinned URL
//!
//! Firecracker, Cloud-Hypervisor, and lima-vm all publish "known good"
//! Linux kernels, but each has a different distribution layout, mirror
//! latency, and SHA-256 cadence. Pinning one URL in this binary would
//! either (a) couple the workspace to one upstream's CDN policy, or
//! (b) require us to mirror those binaries ourselves — both worse
//! outcomes than letting the operator name the source.
//!
//! The `release/scripts/dev-bootstrap.sh` shell wrapper (out of scope
//! here) is the right place to encode an opinionated default URL +
//! SHA-256 for the demo, since that's a release-pipeline concern.
//!
//! ## Arch handling
//!
//! `--arch` defaults to the host's architecture (so `cargo xtask images
//! dev-kernel --from-file vmlinux-aarch64` "just works" on macOS arm64).
//! It's recorded in the success log so the operator can spot a
//! cross-arch staging mistake before they try to boot the VM and get
//! an opaque AVF error.
//!
//! ## Exit-code contract
//!
//! * `0` — kernel binary is in place at `<install_dir>/kernel/vmlinux`,
//!   bytes match the SHA-256 (when supplied).
//! * `non-zero` (anyhow::bail) — bad arg, missing source, SHA-256
//!   mismatch, filesystem error, `curl` failure.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// Default install directory when neither `--install-dir` nor
/// `RAXIS_INSTALL_DIR` is set. Matches the documented dev-host layout
/// from `system-requirements.md §11.2`.
const DEFAULT_DEV_INSTALL_DIR: &str = "/usr/local/lib/raxis";

/// Subdir under `$RAXIS_INSTALL_DIR` for the guest kernel. Mirrors
/// `canonical_images_preflight::linux_kernel_path`.
const KERNEL_SUBDIR: &str = "kernel";

/// Filename for the guest kernel binary. Mirrors
/// `canonical_images_preflight::linux_kernel_path`.
const KERNEL_FILENAME: &str = "vmlinux";

/// Recognised host architectures we'll auto-detect / accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arch {
    Aarch64,
    X86_64,
}

impl Arch {
    fn from_host() -> Self {
        if cfg!(target_arch = "aarch64") {
            Arch::Aarch64
        } else {
            Arch::X86_64
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "aarch64" | "arm64" => Ok(Arch::Aarch64),
            "x86_64" | "amd64" => Ok(Arch::X86_64),
            other => bail!(
                "unsupported --arch {other:?}; expected one of: aarch64, arm64, x86_64, amd64"
            ),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Arch::Aarch64 => "aarch64",
            Arch::X86_64 => "x86_64",
        }
    }
}

/// Source mode for the kernel bytes.
#[derive(Debug, Clone)]
enum Source {
    /// Local file we copy into place.
    File(PathBuf),
    /// Remote URL + expected SHA-256. The SHA-256 is required; we will
    /// not stage bytes the operator hasn't pinned a digest for.
    Url { url: String, sha256: String },
}

/// Parsed arguments for `cargo xtask images dev-kernel`.
#[derive(Debug)]
struct Args {
    install_dir: PathBuf,
    arch: Arch,
    source: Source,
    /// Optional SHA-256 to verify the local-file source (always
    /// verified when `Source::Url`). Lowercase hex.
    sha256: Option<String>,
    /// If `false`, the command refuses to overwrite an existing
    /// `<install_dir>/kernel/vmlinux`.
    force: bool,
}

impl Args {
    fn parse(argv: &[String]) -> Result<Self> {
        let mut install_dir: Option<PathBuf> = None;
        let mut arch: Option<Arch> = None;
        let mut from_file: Option<PathBuf> = None;
        let mut url: Option<String> = None;
        let mut sha256: Option<String> = None;
        let mut force = false;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--install-dir" => {
                    i += 1;
                    install_dir = Some(PathBuf::from(
                        argv.get(i).context("--install-dir requires a path")?,
                    ));
                }
                "--arch" => {
                    i += 1;
                    arch = Some(Arch::parse(
                        argv.get(i).context("--arch requires a value")?,
                    )?);
                }
                "--from-file" => {
                    i += 1;
                    from_file = Some(PathBuf::from(
                        argv.get(i).context("--from-file requires a path")?,
                    ));
                }
                "--url" => {
                    i += 1;
                    url = Some(argv.get(i).context("--url requires a value")?.clone());
                }
                "--sha256" => {
                    i += 1;
                    sha256 = Some(
                        argv.get(i)
                            .context("--sha256 requires a 64-hex-char digest")?
                            .to_lowercase(),
                    );
                }
                "--force" => force = true,
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                other => bail!("unknown dev-kernel arg: {other}"),
            }
            i += 1;
        }

        let install_dir = match install_dir {
            Some(p) => p,
            None => match std::env::var_os("RAXIS_INSTALL_DIR") {
                Some(v) => PathBuf::from(v),
                None => PathBuf::from(DEFAULT_DEV_INSTALL_DIR),
            },
        };
        let arch = arch.unwrap_or_else(Arch::from_host);

        let source = match (from_file, url.clone(), sha256.clone()) {
            (Some(p), None, _) => Source::File(p),
            (None, Some(u), Some(d)) => Source::Url { url: u, sha256: d },
            (None, Some(_), None) => {
                bail!("--url requires --sha256 (refusing to install bytes you have not pinned)")
            }
            (Some(_), Some(_), _) => bail!("pass exactly one of --from-file or --url, not both"),
            (None, None, _) => {
                bail!("must pass either --from-file <PATH> or --url <URL> --sha256 <HEX>")
            }
        };

        // Re-bind sha256 so File-mode can keep the operator-supplied
        // digest (Url-mode already moved it into Source::Url).
        let local_sha256 = match &source {
            Source::File(_) => sha256,
            Source::Url { .. } => None,
        };

        Ok(Self {
            install_dir,
            arch,
            source,
            sha256: local_sha256,
            force,
        })
    }
}

fn print_help() {
    eprintln!(
        "usage: cargo xtask images dev-kernel \n           \
           (--from-file <PATH> [--sha256 <HEX>] | --url <URL> --sha256 <HEX>)\n           \
           [--install-dir <PATH>] [--arch aarch64|x86_64] [--force]\n\
         \n\
         Stages a Linux guest-kernel binary at \n           \
         <install_dir>/kernel/vmlinux\n\
         which is the path the kernel hands to AVF / Firecracker as \n         \
         `VmSpec.linux_kernel_path`. Verifies SHA-256 when supplied.\n\
         Refuses to overwrite an existing kernel without --force.\n\
         \n\
         Defaults:\n  \
         --install-dir   $RAXIS_INSTALL_DIR (or /usr/local/lib/raxis)\n  \
         --arch          host arch\n"
    );
}

/// Entry point invoked by `xtask/src/main.rs`.
pub fn run(argv: &[String]) -> Result<()> {
    let args = Args::parse(argv)?;
    install(&args)
}

/// Pure-function variant for tests: runs the install, returns `Ok(())`
/// on success or the structured anyhow::Error on failure.
fn install(args: &Args) -> Result<()> {
    let dest_dir = args.install_dir.join(KERNEL_SUBDIR);
    let dest_path = dest_dir.join(KERNEL_FILENAME);

    fs::create_dir_all(&dest_dir)
        .with_context(|| format!("create kernel dir {}", dest_dir.display()))?;

    if dest_path.exists() && !args.force {
        bail!(
            "refusing to overwrite existing kernel at {} (pass --force \
             to replace; the existing kernel signs-of-life every running \
             VM that already booted from it)",
            dest_path.display(),
        );
    }

    // Stage into a temp file in the same dir, fsync, atomically rename.
    // Keeps the canonical path either old-or-new, never half-written —
    // important because `kernel/main.rs` probes this path at boot.
    let tmp_path = dest_dir.join(format!(".{}.tmp", KERNEL_FILENAME));
    let bytes = match &args.source {
        Source::File(p) => read_local_file(p)?,
        Source::Url { url, sha256 } => fetch_url_with_curl(url, sha256)?,
    };

    if let Source::File(_) = &args.source {
        if let Some(expected) = &args.sha256 {
            verify_sha256(&bytes, expected).context("--from-file SHA-256 verification failed")?;
        }
    }

    {
        let mut f = fs::File::create(&tmp_path)
            .with_context(|| format!("create temp file {}", tmp_path.display()))?;
        f.write_all(&bytes)
            .with_context(|| format!("write temp file {}", tmp_path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync temp file {}", tmp_path.display()))?;
    }

    fs::rename(&tmp_path, &dest_path).with_context(|| {
        format!(
            "atomic rename {} -> {}",
            tmp_path.display(),
            dest_path.display(),
        )
    })?;

    let staged_sha = sha256_hex(&bytes);
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"dev_kernel_installed\",\
         \"path\":\"{}\",\"arch\":\"{}\",\"size\":{},\"sha256\":\"{}\"}}",
        dest_path.display(),
        args.arch.as_str(),
        bytes.len(),
        staged_sha,
    );

    Ok(())
}

fn read_local_file(p: &Path) -> Result<Vec<u8>> {
    if !p.exists() {
        bail!("--from-file path does not exist: {}", p.display());
    }
    let mut f = fs::File::open(p).with_context(|| format!("open {}", p.display()))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .with_context(|| format!("read {}", p.display()))?;
    Ok(buf)
}

/// Shell out to `curl -fL` and return the response body. Verifies the
/// SHA-256 against the operator-supplied digest. We do NOT pipe `curl`
/// directly into the kernel path because we want to fail BEFORE
/// touching the canonical layout if the bytes don't match.
fn fetch_url_with_curl(url: &str, expected_sha256: &str) -> Result<Vec<u8>> {
    let tmp =
        tempfile_in_curdir("dev-kernel-fetch-").context("allocate temp file for curl download")?;
    let status = Command::new("curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--output",
        ])
        .arg(&tmp)
        .arg(url)
        .status()
        .context(
            "failed to spawn `curl` (install curl, or use --from-file with a \
             pre-downloaded kernel)",
        )?;
    if !status.success() {
        let _ = fs::remove_file(&tmp);
        bail!("curl exited non-zero ({status}) fetching {url}");
    }
    let bytes = fs::read(&tmp).with_context(|| format!("read curl output {}", tmp.display()))?;
    let _ = fs::remove_file(&tmp);

    verify_sha256(&bytes, expected_sha256).context("--url SHA-256 verification failed")?;

    Ok(bytes)
}

fn verify_sha256(bytes: &[u8], expected_lowercase_hex: &str) -> Result<()> {
    if expected_lowercase_hex.len() != 64
        || !expected_lowercase_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!(
            "--sha256 must be exactly 64 lowercase-hex chars; got {:?}",
            expected_lowercase_hex,
        );
    }
    let actual = sha256_hex(bytes);
    if actual != expected_lowercase_hex {
        bail!("SHA-256 mismatch: got {actual}, expected {expected_lowercase_hex}");
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Allocate a uniquely named temp file under the system's tempdir.
/// We don't take a `tempfile` dep — `xtask` is build tooling and a
/// hand-rolled monotonic-counter+pid approach is fine.
fn tempfile_in_curdir(prefix: &str) -> Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let name = format!("{prefix}{}-{}-{}", pid, seq, now_nanos());
    Ok(std::env::temp_dir().join(name))
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("dev-kernel-test-{}-{}", name, now_nanos()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn args_parser_defaults_install_dir_to_env_then_documented_layout() {
        // SAFETY: env mutation is fine in single-threaded test that
        // restores the var.
        let prev = std::env::var_os("RAXIS_INSTALL_DIR");
        // SAFETY: see comment above. Test is single-threaded.
        unsafe { std::env::remove_var("RAXIS_INSTALL_DIR") };
        let argv = vec!["--from-file".to_owned(), "/tmp/anything".to_owned()];
        let args = Args::parse(&argv).unwrap();
        assert_eq!(args.install_dir, PathBuf::from(DEFAULT_DEV_INSTALL_DIR));

        // SAFETY: see comment above.
        unsafe { std::env::set_var("RAXIS_INSTALL_DIR", "/opt/raxis-dev") };
        let args = Args::parse(&argv).unwrap();
        assert_eq!(args.install_dir, PathBuf::from("/opt/raxis-dev"));

        match prev {
            Some(v) => unsafe { std::env::set_var("RAXIS_INSTALL_DIR", v) },
            None => unsafe { std::env::remove_var("RAXIS_INSTALL_DIR") },
        };
    }

    #[test]
    fn args_parser_rejects_url_without_sha256() {
        let argv = vec!["--url".to_owned(), "https://example/x".to_owned()];
        let err = Args::parse(&argv).unwrap_err().to_string();
        assert!(err.contains("--url requires --sha256"), "got: {err}");
    }

    #[test]
    fn args_parser_rejects_both_from_file_and_url() {
        let argv = vec![
            "--from-file".to_owned(),
            "/tmp/k".to_owned(),
            "--url".to_owned(),
            "https://example/x".to_owned(),
            "--sha256".to_owned(),
            "00".repeat(32),
        ];
        let err = Args::parse(&argv).unwrap_err().to_string();
        assert!(err.contains("exactly one of"), "got: {err}");
    }

    #[test]
    fn args_parser_rejects_neither_source_mode() {
        let argv: Vec<String> = vec![];
        let err = Args::parse(&argv).unwrap_err().to_string();
        assert!(err.contains("must pass either"), "got: {err}");
    }

    #[test]
    fn args_parser_normalises_sha256_to_lowercase() {
        let argv = vec![
            "--url".to_owned(),
            "https://x/y".to_owned(),
            "--sha256".to_owned(),
            "ABCDEF".to_owned() + &"0".repeat(58),
        ];
        let args = Args::parse(&argv).unwrap();
        match args.source {
            Source::Url { sha256, .. } => {
                assert!(sha256.starts_with("abcdef"), "got: {sha256}");
                assert_eq!(sha256.len(), 64);
            }
            Source::File(_) => panic!("expected Url source"),
        }
    }

    #[test]
    fn install_from_local_file_writes_canonical_layout_with_correct_bytes() {
        let install_dir = temp_dir("install");
        let src = temp_dir("src").join("vmlinux.bin");
        fs::write(&src, b"DUMMY KERNEL BYTES").unwrap();

        let args = Args {
            install_dir: install_dir.clone(),
            arch: Arch::Aarch64,
            source: Source::File(src.clone()),
            sha256: None,
            force: false,
        };
        install(&args).unwrap();

        let staged = install_dir.join("kernel").join("vmlinux");
        assert!(
            staged.exists(),
            "expected staged kernel at {}",
            staged.display()
        );
        assert_eq!(fs::read(&staged).unwrap(), b"DUMMY KERNEL BYTES");
    }

    #[test]
    fn install_refuses_to_overwrite_without_force() {
        let install_dir = temp_dir("overwrite");
        let kdir = install_dir.join("kernel");
        fs::create_dir_all(&kdir).unwrap();
        fs::write(kdir.join("vmlinux"), b"OLD").unwrap();

        let src = temp_dir("src2").join("k");
        fs::write(&src, b"NEW").unwrap();

        let args = Args {
            install_dir: install_dir.clone(),
            arch: Arch::Aarch64,
            source: Source::File(src.clone()),
            sha256: None,
            force: false,
        };
        let err = install(&args).unwrap_err().to_string();
        assert!(err.contains("refusing to overwrite"), "got: {err}");
        assert_eq!(
            fs::read(install_dir.join("kernel").join("vmlinux")).unwrap(),
            b"OLD"
        );

        let args_force = Args {
            force: true,
            ..args
        };
        install(&args_force).unwrap();
        assert_eq!(
            fs::read(install_dir.join("kernel").join("vmlinux")).unwrap(),
            b"NEW"
        );
    }

    #[test]
    fn install_verifies_sha256_when_supplied_and_rejects_mismatch() {
        let install_dir = temp_dir("sha256");
        let src = temp_dir("sha256-src").join("k");
        fs::write(&src, b"hello").unwrap();
        let actual_sha = sha256_hex(b"hello");

        let bad_args = Args {
            install_dir: install_dir.clone(),
            arch: Arch::X86_64,
            source: Source::File(src.clone()),
            sha256: Some("0".repeat(64)),
            force: false,
        };
        let err = install(&bad_args).unwrap_err();
        // anyhow::to_string() returns only the top context; we want
        // to assert against the root cause, which is `SHA-256 mismatch`.
        let chain = format!("{err:#}");
        assert!(chain.contains("SHA-256 mismatch"), "got chain: {chain}");

        let good_args = Args {
            install_dir: install_dir.clone(),
            arch: Arch::X86_64,
            source: Source::File(src),
            sha256: Some(actual_sha.clone()),
            force: false,
        };
        install(&good_args).unwrap();
        let staged = install_dir.join("kernel").join("vmlinux");
        assert_eq!(sha256_hex(&fs::read(&staged).unwrap()), actual_sha);
    }

    #[test]
    fn verify_sha256_rejects_malformed_input() {
        let bytes = b"x";
        assert!(verify_sha256(bytes, "TOOSHORT").is_err());
        assert!(verify_sha256(bytes, &"Z".repeat(64)).is_err());
        assert!(verify_sha256(bytes, &sha256_hex(bytes).to_uppercase()).is_err());
    }

    #[test]
    fn arch_parse_accepts_documented_aliases() {
        assert_eq!(Arch::parse("aarch64").unwrap(), Arch::Aarch64);
        assert_eq!(Arch::parse("arm64").unwrap(), Arch::Aarch64);
        assert_eq!(Arch::parse("x86_64").unwrap(), Arch::X86_64);
        assert_eq!(Arch::parse("amd64").unwrap(), Arch::X86_64);
        assert!(Arch::parse("riscv64").is_err());
    }
}
