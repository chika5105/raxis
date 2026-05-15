//! `cargo xtask license-check` — workspace-wide SSPL-1.0 licence enforcement.
//!
//! Walks every `Cargo.toml` reachable under the workspace root and verifies:
//!
//! - **Check L1 — Workspace root declares `SSPL-1.0`.**
//!   `[workspace.package] license = "SSPL-1.0"` must be present in the
//!   root `Cargo.toml`. Any other value (including the previous
//!   `"MIT OR Apache-2.0"` placeholder) is a finding.
//!
//! - **Check L2 — Every member crate is SSPL-1.0 or inherits it.**
//!   Each `[package]` section must have `license = "SSPL-1.0"` or the
//!   workspace-inheritance forms (`license.workspace = true` /
//!   `license = { workspace = true }`). Any other explicit value is a
//!   finding.
//!
//! Run as:
//!   `cargo xtask license-check`           — informational, exit 0
//!   `cargo xtask license-check --strict`  — CI gate, exit non-zero on findings

use std::path::{Path, PathBuf};

use anyhow::Context;
use walkdir::WalkDir;

/// Expected SPDX identifier.
const EXPECTED_SPDX: &str = "SSPL-1.0";

/// A single license violation found during the check.
#[derive(Debug)]
pub struct LicenseFinding {
    pub toml_path: PathBuf,
    pub detail: String,
}

/// Entry point called from `main.rs`.
pub fn run(strict: bool) -> anyhow::Result<()> {
    let workspace_root = workspace_root()?;
    let findings = check_workspace(&workspace_root)?;

    let toml_count = count_cargo_tomls(&workspace_root);
    println!("license-check: scanned {} Cargo.toml files", toml_count,);

    if findings.is_empty() {
        println!("license-check: ok — all crates declare {EXPECTED_SPDX}");
        return Ok(());
    }

    for f in &findings {
        eprintln!(
            "LINT_LICENSE_VIOLATION — {}\n  {}",
            f.toml_path.display(),
            f.detail,
        );
    }

    if strict {
        anyhow::bail!("{} license-check findings (--strict)", findings.len());
    } else {
        eprintln!(
            "\nlicense-check: {} findings (informational; pass --strict to gate)",
            findings.len(),
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Core checks
// ---------------------------------------------------------------------------

fn check_workspace(root: &Path) -> anyhow::Result<Vec<LicenseFinding>> {
    let mut findings = Vec::new();

    // ── Check L1: workspace root ───────────────────────────────────────────
    let root_toml_path = root.join("raxis/Cargo.toml");
    let root_toml = read_toml(&root_toml_path)?;

    match workspace_license(&root_toml) {
        Some(lic) if lic == EXPECTED_SPDX => {}
        Some(other) => findings.push(LicenseFinding {
            toml_path: root_toml_path.clone(),
            detail: format!("[workspace.package] license = {other:?}; expected {EXPECTED_SPDX:?}",),
        }),
        None => findings.push(LicenseFinding {
            toml_path: root_toml_path.clone(),
            detail: format!(
                "[workspace.package] license field is missing; expected {EXPECTED_SPDX:?}",
            ),
        }),
    }

    // ── Check L2: member crates ────────────────────────────────────────────
    let specs_root = root.join("raxis");
    for entry in WalkDir::new(&specs_root)
        .min_depth(2)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name() == "Cargo.toml")
        // skip the workspace root itself — already checked above
        .filter(|e| e.path() != root_toml_path)
    {
        let path = entry.path();
        let doc = match read_toml(path) {
            Ok(d) => d,
            Err(e) => {
                findings.push(LicenseFinding {
                    toml_path: path.to_path_buf(),
                    detail: format!("could not parse Cargo.toml: {e}"),
                });
                continue;
            }
        };

        // Only check files that have a [package] table (member crates).
        // Dependency overrides, build-dep patches, etc. don't have one.
        if doc.get("package").is_none() {
            continue;
        }

        match crate_license(&doc) {
            CrateLicense::WorkspaceInherited => {}
            CrateLicense::Explicit(lic) if lic == EXPECTED_SPDX => {}
            CrateLicense::Explicit(other) => findings.push(LicenseFinding {
                toml_path: path.to_path_buf(),
                detail: format!(
                    "[package] license = {other:?}; expected {EXPECTED_SPDX:?} \
                     or `license.workspace = true`",
                ),
            }),
            CrateLicense::Missing => findings.push(LicenseFinding {
                toml_path: path.to_path_buf(),
                detail: format!(
                    "[package] license field is missing; add \
                     `license.workspace = true` or `license = {EXPECTED_SPDX:?}`",
                ),
            }),
        }
    }

    Ok(findings)
}

// ---------------------------------------------------------------------------
// TOML parsing helpers
// ---------------------------------------------------------------------------

fn read_toml(path: &Path) -> anyhow::Result<toml::Table> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    text.parse::<toml::Table>()
        .with_context(|| format!("parsing {}", path.display()))
}

/// Extract `[workspace.package] license` as a plain string, if present.
fn workspace_license(doc: &toml::Table) -> Option<String> {
    doc.get("workspace")?
        .as_table()?
        .get("package")?
        .as_table()?
        .get("license")?
        .as_str()
        .map(str::to_owned)
}

#[derive(Debug)]
enum CrateLicense {
    /// `license.workspace = true`  or  `license = { workspace = true }`
    WorkspaceInherited,
    /// `license = "some-spdx-string"`
    Explicit(String),
    /// No `license` key at all under `[package]`.
    Missing,
}

fn crate_license(doc: &toml::Table) -> CrateLicense {
    let Some(pkg) = doc.get("package").and_then(|v| v.as_table()) else {
        return CrateLicense::Missing;
    };

    match pkg.get("license") {
        // `license = "SSPL-1.0"` or any plain string
        Some(toml::Value::String(s)) => CrateLicense::Explicit(s.clone()),
        // `license = { workspace = true }`
        Some(toml::Value::Table(t)) => {
            if t.get("workspace").and_then(|v| v.as_bool()) == Some(true) {
                CrateLicense::WorkspaceInherited
            } else {
                CrateLicense::Missing
            }
        }
        _ => CrateLicense::Missing,
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn workspace_root() -> anyhow::Result<PathBuf> {
    // cargo sets CARGO_MANIFEST_DIR to the xtask crate's dir at build time.
    // At runtime we want the *workspace* root (two levels up from xtask/).
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let xtask_dir = PathBuf::from(manifest_dir);
    // xtask lives at <workspace>/raxis/xtask — so go up two dirs.
    let root = xtask_dir
        .parent() // raxis/
        .and_then(|p| p.parent()) // workspace root (raxis/)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    Ok(root)
}

fn count_cargo_tomls(root: &Path) -> usize {
    WalkDir::new(root.join("raxis"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name() == "Cargo.toml")
        .count()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn table(s: &str) -> toml::Table {
        s.parse().unwrap()
    }

    #[test]
    fn workspace_license_found() {
        let doc = table(
            r#"[workspace.package]
license = "SSPL-1.0"
"#,
        );
        assert_eq!(workspace_license(&doc).as_deref(), Some("SSPL-1.0"));
    }

    #[test]
    fn workspace_license_wrong_value() {
        let doc = table(
            r#"[workspace.package]
license = "MIT OR Apache-2.0"
"#,
        );
        assert_eq!(
            workspace_license(&doc).as_deref(),
            Some("MIT OR Apache-2.0"),
        );
    }

    #[test]
    fn workspace_license_missing() {
        let doc = table("[workspace.package]\nversion = \"0.1.0\"\n");
        assert_eq!(workspace_license(&doc), None);
    }

    #[test]
    fn crate_license_explicit_sspl() {
        let doc = table("[package]\nlicense = \"SSPL-1.0\"\n");
        matches!(crate_license(&doc), CrateLicense::Explicit(s) if s == "SSPL-1.0");
    }

    #[test]
    fn crate_license_workspace_dotted() {
        // license.workspace = true  (dotted key form)
        let doc = table("[package]\nlicense.workspace = true\n");
        assert!(matches!(
            crate_license(&doc),
            CrateLicense::WorkspaceInherited
        ));
    }

    #[test]
    fn crate_license_workspace_table() {
        // license = { workspace = true }  (inline table form)
        let doc = table("[package]\nlicense = { workspace = true }\n");
        assert!(matches!(
            crate_license(&doc),
            CrateLicense::WorkspaceInherited
        ));
    }

    #[test]
    fn crate_license_missing() {
        let doc = table("[package]\nname = \"foo\"\n");
        assert!(matches!(crate_license(&doc), CrateLicense::Missing));
    }

    #[test]
    fn crate_license_wrong_value() {
        let doc = table("[package]\nlicense = \"MIT\"\n");
        matches!(crate_license(&doc), CrateLicense::Explicit(s) if s == "MIT");
    }
}
