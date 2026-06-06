//! Host install-context helpers shared by the CLI, kernel, and
//! supervisor.
//!
//! Explicit operator configuration always wins. These helpers only
//! choose the default data directory when neither `--data-dir` nor
//! `RAXIS_DATA_DIR` was supplied.

use std::path::{Component, Path, PathBuf};

pub const RAXIS_DATA_DIR_ENV: &str = "RAXIS_DATA_DIR";
pub const HOMEBREW_DATA_DIR_SUFFIX: &str = "var/lib/raxis";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InstallOrigin {
    Homebrew { prefix: PathBuf },
    Source,
}

impl InstallOrigin {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Homebrew { .. } => "homebrew",
            Self::Source => "source",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::Homebrew { prefix } => {
                format!("homebrew prefix={}", prefix.display())
            }
            Self::Source => "source/default install".to_owned(),
        }
    }

    pub fn default_data_dir(&self) -> PathBuf {
        match self {
            Self::Homebrew { prefix } => prefix.join(HOMEBREW_DATA_DIR_SUFFIX),
            Self::Source => home_data_dir(),
        }
    }
}

pub fn data_dir_from_env_or_install_default() -> PathBuf {
    std::env::var_os(RAXIS_DATA_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| current_install_origin().default_data_dir())
}

pub fn current_install_origin() -> InstallOrigin {
    let Some(prefix) = homebrew_prefix_from_current_exe() else {
        return InstallOrigin::Source;
    };
    InstallOrigin::Homebrew { prefix }
}

pub fn homebrew_data_dir_from_exe_path(path: &Path) -> Option<PathBuf> {
    homebrew_prefix_from_exe_path(path).map(|prefix| prefix.join(HOMEBREW_DATA_DIR_SUFFIX))
}

pub fn homebrew_prefix_from_exe_path(path: &Path) -> Option<PathBuf> {
    let components: Vec<Component<'_>> = path.components().collect();
    for (idx, component) in components.iter().enumerate() {
        let name = component.as_os_str().to_string_lossy();
        let Some(next) = components.get(idx + 1) else {
            continue;
        };
        if next.as_os_str() != "raxis" {
            continue;
        }
        if name == "Cellar" || name == "opt" {
            return prefix_from_components(&components[..idx]);
        }
    }
    None
}

fn homebrew_prefix_from_current_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    if let Some(prefix) = homebrew_prefix_from_exe_path(&exe) {
        return Some(prefix);
    }
    std::fs::canonicalize(&exe)
        .ok()
        .and_then(|canonical| homebrew_prefix_from_exe_path(&canonical))
}

fn prefix_from_components(components: &[Component<'_>]) -> Option<PathBuf> {
    if components.is_empty() {
        return None;
    }
    let mut out = PathBuf::new();
    for component in components {
        out.push(component.as_os_str());
    }
    Some(out)
}

fn home_data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"))
        .join(".raxis")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_macos_arm_homebrew_cellar_path() {
        let path = Path::new("/opt/homebrew/Cellar/raxis/0.2.5/bin/raxis");
        assert_eq!(
            homebrew_data_dir_from_exe_path(path),
            Some(PathBuf::from("/opt/homebrew/var/lib/raxis"))
        );
    }

    #[test]
    fn detects_macos_intel_homebrew_opt_path() {
        let path = Path::new("/usr/local/opt/raxis/bin/raxis-kernel");
        assert_eq!(
            homebrew_data_dir_from_exe_path(path),
            Some(PathBuf::from("/usr/local/var/lib/raxis"))
        );
    }

    #[test]
    fn detects_linuxbrew_cellar_path() {
        let path = Path::new("/home/linuxbrew/.linuxbrew/Cellar/raxis/0.2.5/bin/raxis");
        assert_eq!(
            homebrew_data_dir_from_exe_path(path),
            Some(PathBuf::from("/home/linuxbrew/.linuxbrew/var/lib/raxis"))
        );
    }

    #[test]
    fn ignores_source_build_paths() {
        let path = Path::new("/Users/me/raxis/target/debug/raxis");
        assert_eq!(homebrew_data_dir_from_exe_path(path), None);
    }
}
