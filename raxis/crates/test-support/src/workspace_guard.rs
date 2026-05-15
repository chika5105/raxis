// workspace_guard — Layer 2 enforcement for "raxis-test-support is dev-dep-only".
//
// What this does:
//   At `cargo test --workspace` time, walks every workspace member's
//   `Cargo.toml` (including the workspace root) and asserts that
//   `raxis-test-support` appears NOWHERE except under `[dev-dependencies]`.
//   Any appearance under `[dependencies]`, `[build-dependencies]`, or
//   `[workspace.dependencies]` fails the test with a precise locator
//   pointing the offending file.
//
// Why a runtime test rather than a compile-time check:
//   The `cfg(any(debug_assertions, test))` gate (Layer 1) already breaks
//   `cargo build --release` of any release-graph consumer. But Layer 1
//   has two gaps:
//     (a) A consumer that adds `raxis-test-support` to `[dependencies]`
//         in a debug-only build will not fire Layer 1 — debug_assertions
//         are on, so the public items exist.
//     (b) `[build-dependencies]` evaluate during `cargo build` regardless
//         of profile, so a misuse there can compile fine and still ship.
//   This guard test catches both at PR-time (any reviewer running
//   `cargo test --workspace` triggers it) and at CI time.
//
// Rationale lives in `specs/v1/philosophy.md` §1.6 "crates/test-support/".

#![cfg(test)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Locate the workspace root by walking up from this crate's manifest dir
/// until we hit a `Cargo.toml` whose `[workspace]` table has a `members`
/// list. Panics if not found within 5 ancestors (the workspace is at
/// `<repo>/raxis/Cargo.toml`, this crate is at
/// `<repo>/raxis/crates/test-support/Cargo.toml`, so 2 ancestors suffice
/// — the extra slack is just paranoia for unusual checkouts).
fn workspace_root() -> PathBuf {
    let start = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for candidate in start.ancestors().take(5) {
        let toml_path = candidate.join("Cargo.toml");
        if !toml_path.is_file() {
            continue;
        }
        let text = match fs::read_to_string(&toml_path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let parsed: toml::Value = match toml::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if parsed
            .get("workspace")
            .and_then(|w| w.get("members"))
            .and_then(|m| m.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false)
        {
            return candidate.to_path_buf();
        }
    }
    panic!(
        "workspace_guard: could not locate workspace root from {start:?} \
         within 5 ancestors — has the repo layout moved?"
    );
}

/// Read a TOML file or panic with a locator-rich message.
fn read_toml(path: &Path) -> toml::Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("workspace_guard: cannot read {}: {e}", path.display()));
    toml::from_str(&text)
        .unwrap_or_else(|e| panic!("workspace_guard: cannot parse {}: {e}", path.display()))
}

/// Returns the list of every `[dependencies.<name>]`-style block name
/// declared under `section_path` in `manifest`. Walks both the inline
/// `name = "..."` form and the table form.
///
/// `section_path` examples: `["dependencies"]`, `["build-dependencies"]`,
/// `["workspace", "dependencies"]`, `["target", "cfg(unix)", "dependencies"]`.
fn collect_dep_names(manifest: &toml::Value, section_path: &[&str]) -> Vec<String> {
    let mut node = manifest;
    for key in section_path {
        node = match node.get(*key) {
            Some(n) => n,
            None => return Vec::new(),
        };
    }
    let table = match node.as_table() {
        Some(t) => t,
        None => return Vec::new(),
    };
    table.keys().cloned().collect()
}

/// Recursively collect `[target.'cfg(...)'.dependencies]` blocks too,
/// since cargo allows dependencies to be tucked there.
fn collect_target_deps(manifest: &toml::Value, leaf: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let target = match manifest.get("target").and_then(|t| t.as_table()) {
        Some(t) => t,
        None => return out,
    };
    for (cfg_expr, value) in target {
        let inner = match value.get(leaf).and_then(|d| d.as_table()) {
            Some(t) => t,
            None => continue,
        };
        out.push((cfg_expr.clone(), inner.keys().cloned().collect()));
    }
    out
}

/// The crate name we're protecting. Centralised so a future rename
/// updates exactly one place.
const PROTECTED: &str = "raxis-test-support";

/// The ONLY section a consumer is allowed to put us in.
const ALLOWED_SECTION: &str = "dev-dependencies";

#[test]
fn protected_crate_appears_only_under_dev_dependencies() {
    let root = workspace_root();
    let workspace_toml_path = root.join("Cargo.toml");
    let workspace_manifest = read_toml(&workspace_toml_path);

    // 1. The workspace root MUST NOT list `raxis-test-support` under
    //    `[workspace.dependencies]`. If it did, any member could pull
    //    us in via `raxis-test-support = { workspace = true }` under
    //    `[dependencies]` and bypass the per-member check below.
    let ws_deps = collect_dep_names(&workspace_manifest, &["workspace", "dependencies"]);
    assert!(
        !ws_deps.iter().any(|d| d == PROTECTED),
        "workspace_guard: {} appears in [workspace.dependencies] of {}\n\
         → MUST NOT be listed there. Each consumer must spell out the path \
         dependency under its own [dev-dependencies]. See \
         specs/v1/philosophy.md §1.6 `crates/test-support/`.",
        PROTECTED,
        workspace_toml_path.display(),
    );

    // 2. Walk every workspace member's Cargo.toml and check that
    //    `raxis-test-support` only appears under [dev-dependencies] —
    //    not under [dependencies], [build-dependencies], or any
    //    [target.'cfg(...)'.dependencies] / [target.'cfg(...)'.build-dependencies]
    //    table.
    let members = workspace_manifest
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_owned()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut violations: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();

    for member in &members {
        let member_toml_path = root.join(member).join("Cargo.toml");
        if !member_toml_path.is_file() {
            // A member directory without a Cargo.toml is itself a problem,
            // but unrelated to this guard. Skip and let cargo's own
            // validation catch it elsewhere.
            continue;
        }
        // The protected crate is allowed to mention itself however it
        // wants — it can't actually depend on itself.
        if member == "crates/test-support" {
            continue;
        }
        // `live-e2e` is itself a test driver binary, not a production
        // binary: it exercises the real stack against real upstreams
        // (Anthropic, Postgres, etc.) and is invoked via
        // `cargo run -p raxis-live-e2e -- <slice>`. The same isolation
        // discipline that exempts `crates/test-support` from itself
        // applies — `live-e2e` is allowed to consume test-support
        // helpers (ephemeral_signing_key, ephemeral_cert_with_key,
        // FakeClock, …) because no release binary ever links it.
        // The build artefact is gated behind `--release` invocations
        // that production never runs.
        if member == "live-e2e" {
            continue;
        }
        let member_manifest = read_toml(&member_toml_path);

        // [dependencies] — production
        if collect_dep_names(&member_manifest, &["dependencies"])
            .iter()
            .any(|d| d == PROTECTED)
        {
            violations
                .entry(member_toml_path.clone())
                .or_default()
                .push("[dependencies]".into());
        }
        // [build-dependencies] — affects production builds via build.rs
        if collect_dep_names(&member_manifest, &["build-dependencies"])
            .iter()
            .any(|d| d == PROTECTED)
        {
            violations
                .entry(member_toml_path.clone())
                .or_default()
                .push("[build-dependencies]".into());
        }

        // [target.'cfg(...)'.dependencies] / .build-dependencies
        for (cfg_expr, names) in collect_target_deps(&member_manifest, "dependencies") {
            if names.iter().any(|d| d == PROTECTED) {
                violations
                    .entry(member_toml_path.clone())
                    .or_default()
                    .push(format!("[target.'{cfg_expr}'.dependencies]"));
            }
        }
        for (cfg_expr, names) in collect_target_deps(&member_manifest, "build-dependencies") {
            if names.iter().any(|d| d == PROTECTED) {
                violations
                    .entry(member_toml_path.clone())
                    .or_default()
                    .push(format!("[target.'{cfg_expr}'.build-dependencies]"));
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = format!(
            "workspace_guard: {PROTECTED} MUST appear only under \
             [{ALLOWED_SECTION}], never in any production-graph section.\n\n\
             Violations:\n"
        );
        for (path, sections) in &violations {
            for section in sections {
                msg.push_str(&format!("  - {}: {section}\n", path.display()));
            }
        }
        msg.push_str(
            "\nFix: move the dependency to the [dev-dependencies] table. \
             See specs/v1/philosophy.md §1.6 `crates/test-support/` for \
             the rationale (FakeClock, GitRepo, etc. must never appear in \
             a release binary's dependency closure).",
        );
        panic!("{msg}");
    }
}

// ---------------------------------------------------------------------------
// Self-tests for the guard's parsing helpers.
//
// We synthesise small TOML strings and verify `collect_dep_names` /
// `collect_target_deps` extract exactly what the workspace guard would
// flag in a real Cargo.toml. These test the GUARD's correctness; the
// guard itself tests the workspace's hygiene.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod helper_tests {
    use super::*;

    fn parse(s: &str) -> toml::Value {
        toml::from_str(s).expect("test fixture must be valid TOML")
    }

    #[test]
    fn collect_dep_names_finds_inline_form() {
        let m = parse(
            r#"
            [dependencies]
            foo = "1"
            bar = { version = "2", features = ["x"] }
            "#,
        );
        let mut names = collect_dep_names(&m, &["dependencies"]);
        names.sort();
        assert_eq!(names, vec!["bar", "foo"]);
    }

    #[test]
    fn collect_dep_names_returns_empty_on_missing_section() {
        let m = parse(
            r#"[package]
name = "x"
version = "0.1.0""#,
        );
        assert!(collect_dep_names(&m, &["dependencies"]).is_empty());
        assert!(collect_dep_names(&m, &["build-dependencies"]).is_empty());
        assert!(collect_dep_names(&m, &["workspace", "dependencies"]).is_empty());
    }

    #[test]
    fn collect_dep_names_walks_nested_workspace_path() {
        let m = parse(
            r#"
            [workspace]
            members = ["a", "b"]

            [workspace.dependencies]
            shared = "1"
            "#,
        );
        let names = collect_dep_names(&m, &["workspace", "dependencies"]);
        assert_eq!(names, vec!["shared".to_owned()]);
    }

    #[test]
    fn collect_target_deps_finds_cfg_gated_dependencies() {
        let m = parse(
            r#"
            [target.'cfg(unix)'.dependencies]
            foo = "1"

            [target.'cfg(windows)'.build-dependencies]
            bar = "2"
            "#,
        );
        let unix = collect_target_deps(&m, "dependencies");
        assert_eq!(unix.len(), 1);
        assert_eq!(unix[0].0, "cfg(unix)");
        assert_eq!(unix[0].1, vec!["foo"]);

        let windows = collect_target_deps(&m, "build-dependencies");
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].0, "cfg(windows)");
        assert_eq!(windows[0].1, vec!["bar"]);
    }

    #[test]
    fn workspace_root_locator_finds_a_real_workspace_toml() {
        let root = workspace_root();
        let cargo_toml = root.join("Cargo.toml");
        assert!(
            cargo_toml.is_file(),
            "workspace_root() returned {root:?} which has no Cargo.toml"
        );
        let parsed = read_toml(&cargo_toml);
        assert!(
            parsed.get("workspace").is_some(),
            "workspace_root() returned a Cargo.toml without [workspace]"
        );
    }
}
