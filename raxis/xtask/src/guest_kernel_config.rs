//! Guest-kernel config validation shared by `cargo xtask images
//! dev-kernel` and `cargo xtask images bake`.
//!
//! Path A3's in-guest chokepoint installs an iptables-nft NAT
//! REDIRECT chain during PID-1 setup. Seeing `/usr/sbin/iptables-nft`
//! on the rootfs is not enough: the guest kernel must also expose
//! the nfnetlink/nftables ABI and the NAT/REDIRECT expressions the
//! userspace binary targets. This module makes that an image-bake
//! invariant instead of discovering it minutes later as:
//!
//! ```text
//! iptables v1.8.x (nf_tables): Could not fetch rule set generation id
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;

pub const STAGED_KERNEL_CONFIG_FILENAME: &str = "vmlinux.config";
pub const REQUIRED_FRAGMENT_PATH: &str = "images/kernel/raxis-guest-a3-netfilter.config";
pub const INVARIANT: &str = "INV-GUEST-KERNEL-A3-NFTABLES-01";

const IKCONFIG_START: &[u8] = b"IKCFG_ST";
const IKCONFIG_END: &[u8] = b"IKCFG_ED";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelConfigSource {
    Explicit(PathBuf),
    Sidecar(PathBuf),
    EmbeddedIkconfig,
}

#[derive(Debug, Clone)]
pub struct ResolvedKernelConfig {
    pub source: KernelConfigSource,
    pub text: String,
}

#[derive(Debug, Clone, Copy)]
struct Requirement {
    why: &'static str,
    any_of: &'static [&'static str],
}

impl Requirement {
    fn satisfied_by(&self, config: &ParsedKernelConfig) -> bool {
        self.any_of.iter().any(|key| config.is_builtin_yes(key))
    }

    fn display(&self) -> String {
        match self.any_of {
            [one] => format!("{one} ({})", self.why),
            many => format!("one of {} ({})", many.join(" / "), self.why),
        }
    }
}

const REQUIRED_A3_NFTABLES_CONFIG: &[Requirement] = &[
    Requirement {
        why: "netfilter core",
        any_of: &["CONFIG_NETFILTER"],
    },
    Requirement {
        why: "nfnetlink control plane, including nftables generation id",
        any_of: &["CONFIG_NETFILTER_NETLINK"],
    },
    Requirement {
        why: "nftables core",
        any_of: &["CONFIG_NF_TABLES"],
    },
    Requirement {
        why: "inet/IPv4 nftables family used by iptables-nft",
        any_of: &["CONFIG_NF_TABLES_INET", "CONFIG_NF_TABLES_IPV4"],
    },
    Requirement {
        why: "connection tracking required by NAT",
        any_of: &["CONFIG_NF_CONNTRACK"],
    },
    Requirement {
        why: "NAT core",
        any_of: &["CONFIG_NF_NAT"],
    },
    Requirement {
        why: "nftables NAT expression",
        any_of: &["CONFIG_NFT_NAT"],
    },
    Requirement {
        why: "nftables REDIRECT expression",
        any_of: &["CONFIG_NFT_REDIR"],
    },
    Requirement {
        why: "base NAT chain support for the nat OUTPUT hook",
        any_of: &["CONFIG_NFT_CHAIN_NAT"],
    },
];

#[derive(Debug, Default)]
struct ParsedKernelConfig {
    values: BTreeMap<String, String>,
}

impl ParsedKernelConfig {
    fn parse(text: &str) -> Self {
        let mut values = BTreeMap::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("# ") {
                if let Some(key) = rest.strip_suffix(" is not set") {
                    values.insert(key.to_owned(), "n".to_owned());
                }
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.starts_with("CONFIG_") {
                values.insert(key.to_owned(), value.trim().to_owned());
            }
        }
        Self { values }
    }

    fn is_builtin_yes(&self, key: &str) -> bool {
        self.values.get(key).is_some_and(|value| value == "y")
    }
}

pub fn resolve_and_validate_kernel_config(
    kernel_path: &Path,
    explicit_config: Option<&Path>,
) -> Result<ResolvedKernelConfig> {
    let resolved = resolve_kernel_config(kernel_path, explicit_config)?;
    validate_kernel_config_text(&resolved.text).with_context(|| {
        format!(
            "{INVARIANT}: guest kernel config from {:?} does not satisfy A3 nftables requirements",
            resolved.source,
        )
    })?;
    Ok(resolved)
}

pub fn validate_kernel_config_text(text: &str) -> Result<()> {
    let parsed = ParsedKernelConfig::parse(text);
    let missing: Vec<String> = REQUIRED_A3_NFTABLES_CONFIG
        .iter()
        .filter(|req| !req.satisfied_by(&parsed))
        .map(Requirement::display)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    bail!(
        "{INVARIANT} VIOLATED: guest kernel config is missing built-in \
         nftables/netfilter support required by Path A3 iptables-nft. \
         Missing built-in options:\n  - {}\n\n\
         Rebuild the guest kernel with {REQUIRED_FRAGMENT_PATH} merged \
         into the kernel .config (built in, not modules), then stage it \
         with:\n  cargo xtask images dev-kernel --from-file <vmlinux> --config <.config> --force",
        missing.join("\n  - "),
    )
}

pub fn stage_kernel_config(install_dir: &Path, resolved: &ResolvedKernelConfig) -> Result<PathBuf> {
    let dest_dir = install_dir.join("kernel");
    fs::create_dir_all(&dest_dir).with_context(|| format!("create {}", dest_dir.display()))?;
    let dest = dest_dir.join(STAGED_KERNEL_CONFIG_FILENAME);
    let tmp = dest_dir.join(format!(".{STAGED_KERNEL_CONFIG_FILENAME}.tmp"));
    fs::write(&tmp, resolved.text.as_bytes())
        .with_context(|| format!("write temp kernel config {}", tmp.display()))?;
    fs::rename(&tmp, &dest)
        .with_context(|| format!("atomic rename {} -> {}", tmp.display(), dest.display()))?;
    Ok(dest)
}

fn resolve_kernel_config(
    kernel_path: &Path,
    explicit_config: Option<&Path>,
) -> Result<ResolvedKernelConfig> {
    if let Some(path) = explicit_config {
        let text = fs::read_to_string(path)
            .with_context(|| format!("read explicit guest-kernel config {}", path.display()))?;
        return Ok(ResolvedKernelConfig {
            source: KernelConfigSource::Explicit(path.to_path_buf()),
            text,
        });
    }

    for candidate in sidecar_config_candidates(kernel_path) {
        match fs::read_to_string(&candidate) {
            Ok(text) => {
                return Ok(ResolvedKernelConfig {
                    source: KernelConfigSource::Sidecar(candidate),
                    text,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("read {}", candidate.display())),
        }
    }

    let bytes =
        fs::read(kernel_path).with_context(|| format!("read kernel {}", kernel_path.display()))?;
    if let Some(text) = extract_embedded_ikconfig(&bytes)? {
        return Ok(ResolvedKernelConfig {
            source: KernelConfigSource::EmbeddedIkconfig,
            text,
        });
    }

    bail!(
        "{INVARIANT} VIOLATED: unable to find a kernel .config for {}. \
         Provide `--config <.config>` to `cargo xtask images dev-kernel` \
         or `cargo xtask images bake --kernel-config <.config>`, place a \
         sidecar at {} or {}, or rebuild with CONFIG_IKCONFIG=y so the \
         config is embedded in vmlinux. The config is required because \
         Path A3 depends on nftables NAT/REDIRECT support inside the \
         guest kernel.",
        kernel_path.display(),
        kernel_path.with_extension("config").display(),
        kernel_path
            .with_file_name(STAGED_KERNEL_CONFIG_FILENAME)
            .display(),
    )
}

fn sidecar_config_candidates(kernel_path: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    out.push(kernel_path.with_extension("config"));
    out.push(kernel_path.with_file_name(STAGED_KERNEL_CONFIG_FILENAME));
    out.push(kernel_path.with_file_name("config"));
    out.sort();
    out.dedup();
    out
}

fn extract_embedded_ikconfig(bytes: &[u8]) -> Result<Option<String>> {
    let Some(start) = find_subslice(bytes, IKCONFIG_START) else {
        return Ok(None);
    };
    let payload_start = start + IKCONFIG_START.len();
    let Some(end_rel) = find_subslice(&bytes[payload_start..], IKCONFIG_END) else {
        return Ok(None);
    };
    let payload = &bytes[payload_start..payload_start + end_rel];
    let Some(gzip_start) = payload.windows(3).position(|w| w == [0x1f, 0x8b, 0x08]) else {
        return Ok(None);
    };
    let gzip = &payload[gzip_start..];
    let mut decoder = GzDecoder::new(gzip);
    let mut text = String::new();
    decoder
        .read_to_string(&mut text)
        .context("decompress embedded Linux IKCONFIG")?;
    Ok(Some(text))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> String {
        REQUIRED_A3_NFTABLES_CONFIG
            .iter()
            .flat_map(|req| req.any_of.first().copied())
            .map(|key| format!("{key}=y\n"))
            .collect()
    }

    #[test]
    fn validates_required_a3_nftables_config() {
        validate_kernel_config_text(&valid_config()).unwrap();
    }

    #[test]
    fn rejects_missing_generation_id_abi_support() {
        let config = valid_config().replace("CONFIG_NETFILTER_NETLINK=y\n", "");
        let err = validate_kernel_config_text(&config)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("CONFIG_NETFILTER_NETLINK"),
            "missing option should be named: {err}",
        );
    }

    #[test]
    fn treats_modules_as_missing_for_initramfs_kernel() {
        let config = valid_config().replace("CONFIG_NFT_REDIR=y", "CONFIG_NFT_REDIR=m");
        let err = validate_kernel_config_text(&config)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("CONFIG_NFT_REDIR"),
            "module-only option should be rejected: {err}",
        );
    }

    #[test]
    fn accepts_kernel_version_alternative_for_nftables_family() {
        let config = valid_config().replace("CONFIG_NF_TABLES_INET=y", "CONFIG_NF_TABLES_IPV4=y");
        validate_kernel_config_text(&config).unwrap();
    }

    #[test]
    fn resolves_explicit_config_before_sidecars() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("vmlinux");
        fs::write(&kernel, b"fake").unwrap();
        let sidecar = tmp.path().join("vmlinux.config");
        fs::write(&sidecar, "# CONFIG_NETFILTER is not set\n").unwrap();
        let explicit = tmp.path().join("explicit.config");
        fs::write(&explicit, valid_config()).unwrap();

        let resolved = resolve_and_validate_kernel_config(&kernel, Some(&explicit)).unwrap();
        assert_eq!(resolved.source, KernelConfigSource::Explicit(explicit));
    }

    #[test]
    fn resolves_sidecar_config_when_embedded_config_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("vmlinux");
        fs::write(&kernel, b"fake").unwrap();
        let sidecar = tmp.path().join("vmlinux.config");
        fs::write(&sidecar, valid_config()).unwrap();

        let resolved = resolve_and_validate_kernel_config(&kernel, None).unwrap();
        assert_eq!(resolved.source, KernelConfigSource::Sidecar(sidecar));
    }
}
