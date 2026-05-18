//! Witness tests for the executor-starter image's pre-baked lint
//! toolchain.
//!
//! Normative reference:
//!
//! * `raxis/specs/invariants.md`
//!   - `INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01`
//!   - `INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01`
//! * `raxis/specs/v2/planner-harness.md §10.6` (canonical executor
//!   starter image manifest — "Pre-installed lint toolchain"
//!   subsection) and `§14.4` (image-build pipeline).
//! * `raxis/images/executor-starter/{Containerfile, verify.sh,
//!   manifest.toml}` — the source of truth this test cross-checks.
//!
//! ## What this file pins
//!
//! The realistic-scenario `lint-runner-{python,js}` Executor tasks
//! invoke language-native lint pipelines verbatim inside an
//! executor VM whose default egress allowlist is empty. Iter56
//! exposed the failure mode: the executor-starter rootfs did not
//! ship `ruff` (Python) or `eslint`/`prettier`/`tsc`/`tsx` (JS), so
//! the task body's `python -m ruff check` / `npx --no-install
//! eslint` failed deterministically. The fix bakes pinned linters
//! into the rootfs at Containerfile-build time and asserts the
//! bake via `images/executor-starter/verify.sh`.
//!
//! These witness tests drive `verify.sh` against synthetic-rootfs
//! fixtures so the invariants' fail-closed remediation contract
//! is exercised WITHOUT needing a real ~2 GiB rootfs bake. The
//! verifier shell script is the load-bearing call site; if a
//! future Containerfile / manifest / verify.sh edit drifts the
//! triple, these tests catch it before the next `lint-runner-*`
//! task burns its turn budget.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Path to the `verify.sh` script under the workspace's
/// `images/executor-starter/` dir. Resolves relative to this test
/// crate's `CARGO_MANIFEST_DIR` so the tests work both from a
/// `cargo test -p xtask` invocation and from `cargo test
/// --manifest-path raxis/Cargo.toml`.
fn verify_sh_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // CARGO_MANIFEST_DIR for xtask is `<workspace>/xtask`. The
    // verify script lives at `<workspace>/images/executor-starter/
    // verify.sh`; pop one level to reach the workspace root.
    let workspace_root = manifest_dir
        .parent()
        .expect("xtask is a workspace member; parent dir must exist")
        .to_owned();
    workspace_root
        .join("images")
        .join("executor-starter")
        .join("verify.sh")
}

/// Build a minimal fixture rootfs at `dst` that satisfies every
/// pre-existing `verify.sh` structural check (planner binary,
/// init symlink, bash, git, python3, node, etc.). Individual
/// witness tests then add or remove the lint-toolchain files to
/// drive the specific invariant arm under test.
///
/// The fixture writes regular-file stubs (not real binaries),
/// which is sufficient because `verify.sh` only `-e`-tests for
/// existence and runs `python3 -c "import ruff"` only on Linux
/// hosts — the stubbed `usr/bin/python3` is harmless on macOS
/// dev hosts (the verifier falls back to the static dist-info
/// check) and the test compiles to a non-zero-byte file that
/// `[ -e ]` accepts.
fn build_base_rootfs_fixture(dst: &Path) {
    fs::create_dir_all(dst).expect("create fixture root");
    for rel in [
        "usr/local/bin/raxis-planner-executor",
        "bin/bash",
        "usr/bin/git",
        "usr/bin/curl",
        "usr/bin/wget",
        "usr/sbin/nft",
        "usr/bin/node",
        "usr/bin/python3",
        "usr/bin/make",
    ] {
        let p = dst.join(rel);
        fs::create_dir_all(p.parent().unwrap()).expect("create parent dir");
        fs::write(&p, b"#!/bin/sh\nexit 0\n").expect("write stub");
        // Mark executable so a future Linux-host run that tries
        // `chroot`-style python3 invocation does not panic on a
        // perms-check; `[ -e ]` does not require this but it
        // keeps the fixture realistic.
        let mut perms = fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&p, perms).unwrap();
    }
    // `/sbin/init` is symlinked from the dev-stage pipeline; we
    // emulate that here so the loop in verify.sh accepting either
    // a regular file or a symlink passes.
    let sbin = dst.join("sbin");
    fs::create_dir_all(&sbin).unwrap();
    std::os::unix::fs::symlink("/usr/local/bin/raxis-planner-executor", sbin.join("init"))
        .expect("symlink /sbin/init");
}

/// Drop the pinned ruff layout under the fixture: the CLI shim at
/// `usr/local/bin/ruff` and the dist-info dir under one of the
/// canonical site-packages roots. `version` parameterises which
/// dist-info filename we write so witnesses can simulate a
/// version-drift scenario.
fn install_ruff(rootfs: &Path, version: &str) {
    let shim = rootfs.join("usr/local/bin/ruff");
    fs::create_dir_all(shim.parent().unwrap()).unwrap();
    fs::write(&shim, b"#!/bin/sh\necho ruff stub\n").unwrap();
    let dist = rootfs
        .join("usr/lib/python3.11/dist-packages")
        .join(format!("ruff-{version}.dist-info"));
    fs::create_dir_all(&dist).unwrap();
    fs::write(
        dist.join("METADATA"),
        format!("Metadata-Version: 2.1\nName: ruff\nVersion: {version}\n"),
    )
    .unwrap();
}

/// Drop the pinned JS toolchain layout under the fixture: global
/// node_modules entries for each linter plus the CLI shims on
/// `$PATH`. Witnesses can selectively skip a package or shim to
/// drive the specific arm under test.
fn install_js_toolchain(rootfs: &Path, include_packages: &[&str], include_shims: &[&str]) {
    for pkg in include_packages {
        let dir = rootfs.join("usr/lib/node_modules").join(pkg);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("package.json"),
            format!("{{\"name\":\"{pkg}\",\"version\":\"0.0.0\"}}"),
        )
        .unwrap();
    }
    for bin in include_shims {
        let p = rootfs.join("usr/bin").join(bin);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut perms = fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&p, perms).unwrap();
    }
}

/// All four JS toolchain global node_modules entries the verifier
/// asserts. Kept centralised so a future contract change (e.g.,
/// adding a `@types/node` check) updates every witness in one
/// place.
const JS_PACKAGES: &[&str] = &["eslint", "prettier", "typescript", "tsx"];

/// CLI shims `verify.sh` asserts are on `$PATH`. Note that the
/// `typescript` npm package provides the `tsc` shim (not `typescript`).
const JS_SHIMS: &[&str] = &["eslint", "prettier", "tsc"];

/// Run `verify.sh <fixture>` and return (exit_code, stdout+stderr).
/// We capture combined output because the verifier mixes
/// remediation hints across both streams.
fn run_verify(fixture: &Path) -> (i32, String) {
    let out = Command::new("sh")
        .arg(verify_sh_path())
        .arg(fixture)
        .output()
        .expect("spawn verify.sh");
    let code = out.status.code().unwrap_or(-1);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    (code, combined)
}

// ──────────────────────────────────────────────────────────────────
// INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01 witnesses
// ──────────────────────────────────────────────────────────────────

#[test]
fn inv_executor_image_lint_toolchain_python_01_happy_path_passes() {
    // Fixture: base OS tooling + pinned ruff dist-info + CLI
    // shim. The full JS toolchain is also present so the JS
    // invariant does not preempt this witness.
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path();
    build_base_rootfs_fixture(rootfs);
    install_ruff(rootfs, "0.7.4");
    install_js_toolchain(rootfs, JS_PACKAGES, JS_SHIMS);

    let (code, out) = run_verify(rootfs);
    assert_eq!(
        code, 0,
        "verify.sh must exit 0 on a fully-baked fixture; got {code}\n--- output ---\n{out}",
    );
    assert!(
        out.contains("passes structural checks"),
        "verify.sh must emit the success line: {out}",
    );
}

#[test]
fn inv_executor_image_lint_toolchain_python_01_missing_cli_shim_fails_closed() {
    // Fixture: dist-info present but CLI shim missing → fails.
    // This is the "pip installed but symlink step failed" shape.
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path();
    build_base_rootfs_fixture(rootfs);
    // Skip install_ruff; install only the dist-info, NOT the shim.
    let dist = rootfs.join("usr/lib/python3.11/dist-packages/ruff-0.7.4.dist-info");
    fs::create_dir_all(&dist).unwrap();
    fs::write(dist.join("METADATA"), b"Name: ruff\nVersion: 0.7.4\n").unwrap();
    install_js_toolchain(rootfs, JS_PACKAGES, JS_SHIMS);

    let (code, out) = run_verify(rootfs);
    assert_ne!(code, 0, "verify.sh must reject missing ruff CLI shim");
    assert!(
        out.contains("INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01 VIOLATED"),
        "remediation must cite the invariant token: {out}",
    );
    assert!(
        out.contains("/usr/local/bin/ruff"),
        "remediation must name the missing path: {out}",
    );
    assert!(
        out.contains("images bake --role executor-starter"),
        "remediation must name the images bake command: {out}",
    );
}

#[test]
fn inv_executor_image_lint_toolchain_python_01_missing_dist_info_fails_closed() {
    // Fixture: CLI shim present but no dist-info → fails. This is
    // the "someone hand-placed a ruff binary outside pip" shape;
    // the verifier rejects because pin verification requires the
    // dist-info file.
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path();
    build_base_rootfs_fixture(rootfs);
    let shim = rootfs.join("usr/local/bin/ruff");
    fs::create_dir_all(shim.parent().unwrap()).unwrap();
    fs::write(&shim, b"#!/bin/sh\necho ruff stub\n").unwrap();
    install_js_toolchain(rootfs, JS_PACKAGES, JS_SHIMS);

    let (code, out) = run_verify(rootfs);
    assert_ne!(code, 0);
    assert!(
        out.contains("INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01 VIOLATED"),
        "remediation must cite the Python invariant token: {out}",
    );
    assert!(
        out.contains("dist-info") || out.contains("site-packages"),
        "remediation must name the missing dist-info / site-packages: {out}",
    );
}

#[test]
fn inv_executor_image_lint_toolchain_python_01_version_drift_fails_closed() {
    // Fixture: CLI shim + a dist-info, but the dist-info encodes
    // a version that disagrees with verify.sh's RUFF_PINNED_VERSION.
    // This is the "operator bumped the Containerfile but forgot
    // to bump the verifier pin" shape.
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path();
    build_base_rootfs_fixture(rootfs);
    install_ruff(rootfs, "0.8.0"); // pin is 0.7.4
    install_js_toolchain(rootfs, JS_PACKAGES, JS_SHIMS);

    let (code, out) = run_verify(rootfs);
    assert_ne!(code, 0, "verify.sh must reject the version-drift fixture");
    assert!(
        out.contains("INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01 VIOLATED"),
        "version-drift remediation must cite the invariant token: {out}",
    );
    // The remediation embeds the pinned version so an operator
    // reading the error can answer "which version SHOULD be here?"
    // without grepping the Containerfile.
    assert!(
        out.contains("0.7.4"),
        "remediation must embed the pinned ruff version: {out}",
    );
}

// ──────────────────────────────────────────────────────────────────
// INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01 witnesses
// ──────────────────────────────────────────────────────────────────

#[test]
fn inv_executor_image_lint_toolchain_js_01_happy_path_passes() {
    // Symmetric to the Python happy-path witness: every linter
    // present, every CLI shim present, verify.sh exits 0. This
    // pins that JS_PACKAGES + JS_SHIMS together satisfy the
    // verifier's contract.
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path();
    build_base_rootfs_fixture(rootfs);
    install_ruff(rootfs, "0.7.4");
    install_js_toolchain(rootfs, JS_PACKAGES, JS_SHIMS);

    let (code, out) = run_verify(rootfs);
    assert_eq!(code, 0, "verify.sh happy path: {out}");
}

#[test]
fn inv_executor_image_lint_toolchain_js_01_missing_eslint_module_fails_closed() {
    // Fixture: every linter except eslint. The "drop one"
    // arm is replicated per-package so a future regression that
    // accidentally removes ONE linter from the npm-install-g
    // line surfaces with the correct package name in the
    // violation body.
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path();
    build_base_rootfs_fixture(rootfs);
    install_ruff(rootfs, "0.7.4");
    let without_eslint: Vec<&str> = JS_PACKAGES
        .iter()
        .copied()
        .filter(|p| *p != "eslint")
        .collect();
    install_js_toolchain(rootfs, &without_eslint, JS_SHIMS);

    let (code, out) = run_verify(rootfs);
    assert_ne!(code, 0);
    assert!(
        out.contains("INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01 VIOLATED"),
        "JS invariant token must appear: {out}",
    );
    assert!(
        out.contains("eslint"),
        "violation must name the missing package: {out}",
    );
}

#[test]
fn inv_executor_image_lint_toolchain_js_01_missing_prettier_module_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path();
    build_base_rootfs_fixture(rootfs);
    install_ruff(rootfs, "0.7.4");
    let without_prettier: Vec<&str> = JS_PACKAGES
        .iter()
        .copied()
        .filter(|p| *p != "prettier")
        .collect();
    install_js_toolchain(rootfs, &without_prettier, JS_SHIMS);

    let (code, out) = run_verify(rootfs);
    assert_ne!(code, 0);
    assert!(
        out.contains("INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01 VIOLATED"),
        "{out}"
    );
    assert!(out.contains("prettier"), "{out}");
}

#[test]
fn inv_executor_image_lint_toolchain_js_01_missing_typescript_module_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path();
    build_base_rootfs_fixture(rootfs);
    install_ruff(rootfs, "0.7.4");
    let without_ts: Vec<&str> = JS_PACKAGES
        .iter()
        .copied()
        .filter(|p| *p != "typescript")
        .collect();
    install_js_toolchain(rootfs, &without_ts, JS_SHIMS);

    let (code, out) = run_verify(rootfs);
    assert_ne!(code, 0);
    assert!(
        out.contains("INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01 VIOLATED"),
        "{out}"
    );
    assert!(out.contains("typescript"), "{out}");
}

#[test]
fn inv_executor_image_lint_toolchain_js_01_missing_tsx_module_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path();
    build_base_rootfs_fixture(rootfs);
    install_ruff(rootfs, "0.7.4");
    let without_tsx: Vec<&str> = JS_PACKAGES
        .iter()
        .copied()
        .filter(|p| *p != "tsx")
        .collect();
    install_js_toolchain(rootfs, &without_tsx, JS_SHIMS);

    let (code, out) = run_verify(rootfs);
    assert_ne!(code, 0);
    assert!(
        out.contains("INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01 VIOLATED"),
        "{out}"
    );
    assert!(out.contains("tsx"), "{out}");
}

#[test]
fn inv_executor_image_lint_toolchain_js_01_missing_cli_shim_fails_closed() {
    // Fixture: every node_modules entry present, but the CLI
    // shim for eslint is missing. This is the load-bearing
    // arm: even with the module installed, `npx --no-install
    // eslint` from the task body relies on `$PATH` resolution.
    // The verifier rejects when the shim is absent.
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path();
    build_base_rootfs_fixture(rootfs);
    install_ruff(rootfs, "0.7.4");
    let without_eslint_shim: Vec<&str> = JS_SHIMS
        .iter()
        .copied()
        .filter(|b| *b != "eslint")
        .collect();
    install_js_toolchain(rootfs, JS_PACKAGES, &without_eslint_shim);

    let (code, out) = run_verify(rootfs);
    assert_ne!(code, 0, "verify.sh must reject missing CLI shim");
    assert!(
        out.contains("INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01 VIOLATED"),
        "{out}",
    );
    assert!(
        out.contains("eslint") && (out.contains("/usr/bin/") || out.contains("/usr/local/bin/")),
        "remediation must name the missing shim path: {out}",
    );
}

#[test]
fn inv_executor_image_lint_toolchain_js_01_accepts_usr_local_lib_mirror() {
    // The verifier accepts either `/usr/lib/node_modules/<pkg>`
    // OR `/usr/local/lib/node_modules/<pkg>` (npm install -g
    // path depends on the npm version and prefix config). Pin
    // that contract: a fixture that places modules under
    // /usr/local/lib MUST still pass.
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path();
    build_base_rootfs_fixture(rootfs);
    install_ruff(rootfs, "0.7.4");
    for pkg in JS_PACKAGES {
        let dir = rootfs.join("usr/local/lib/node_modules").join(pkg);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("package.json"),
            format!("{{\"name\":\"{pkg}\",\"version\":\"0.0.0\"}}"),
        )
        .unwrap();
    }
    // Shims live under /usr/local/bin (matching the
    // /usr/local/lib install prefix).
    for bin in JS_SHIMS {
        let p = rootfs.join("usr/local/bin").join(bin);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut perms = fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&p, perms).unwrap();
    }

    let (code, out) = run_verify(rootfs);
    assert_eq!(
        code, 0,
        "verify.sh must accept the /usr/local/lib mirror: {out}",
    );
}

// ──────────────────────────────────────────────────────────────────
// Containerfile / manifest / verify.sh pin-triple cross-check
// ──────────────────────────────────────────────────────────────────

#[test]
fn lint_toolchain_pins_agree_across_containerfile_manifest_and_verifier() {
    // Read the three files and assert they all carry the same
    // pinned versions. This is the load-bearing guard against
    // an asymmetric bump (e.g., operator updates Containerfile
    // but forgets manifest.toml and verify.sh). It is also what
    // makes the pin-triple normative: a future bump that fails
    // this test must update ALL THREE files atomically.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap();
    let img_dir = workspace_root.join("images/executor-starter");

    let containerfile =
        fs::read_to_string(img_dir.join("Containerfile")).expect("read Containerfile");
    let manifest = fs::read_to_string(img_dir.join("manifest.toml")).expect("read manifest.toml");
    let verify = fs::read_to_string(img_dir.join("verify.sh")).expect("read verify.sh");

    // ── ruff ──────────────────────────────────────────────────
    let containerfile_ruff = extract_after(&containerfile, "\"ruff==", "\"")
        .expect("Containerfile must pin ruff==<X.Y.Z>");
    let manifest_ruff = extract_manifest_field(&manifest, "ruff_version")
        .expect("manifest.toml must declare [lint_toolchain] ruff_version");
    let verify_ruff = extract_after(&verify, "RUFF_PINNED_VERSION=\"", "\"")
        .expect("verify.sh must declare RUFF_PINNED_VERSION");
    assert_eq!(
        containerfile_ruff, manifest_ruff,
        "Containerfile ruff pin ({containerfile_ruff}) must match \
         manifest.toml [lint_toolchain] ruff_version ({manifest_ruff})",
    );
    assert_eq!(
        containerfile_ruff, verify_ruff,
        "Containerfile ruff pin ({containerfile_ruff}) must match \
         verify.sh RUFF_PINNED_VERSION ({verify_ruff})",
    );

    // ── JS toolchain ──────────────────────────────────────────
    for (pkg, manifest_field) in [
        ("eslint", "eslint_version"),
        ("prettier", "prettier_version"),
        ("typescript", "typescript_version"),
        ("tsx", "tsx_version"),
    ] {
        let needle_cf = format!("\"{pkg}@");
        let cf_ver = extract_after(&containerfile, &needle_cf, "\"")
            .unwrap_or_else(|| panic!("Containerfile must pin {pkg}@<X.Y.Z>",));
        let mf_ver = extract_manifest_field(&manifest, manifest_field).unwrap_or_else(|| {
            panic!("manifest.toml must declare [lint_toolchain] {manifest_field}",)
        });
        assert_eq!(
            cf_ver, mf_ver,
            "Containerfile {pkg} pin ({cf_ver}) must match \
             manifest.toml [lint_toolchain] {manifest_field} ({mf_ver})",
        );
    }
}

/// Extract a quoted-string TOML scalar value for `field` from
/// `text`, tolerant of arbitrary whitespace around the `=`.
/// Returns the unquoted value or `None` if the field is absent.
/// Inlined here (rather than depending on the toml crate or
/// regex) to keep this witness test crate's compile surface tiny.
fn extract_manifest_field(text: &str, field: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(field) {
            let rest = rest.trim_start();
            let rest = rest.strip_prefix('=')?.trim_start();
            let rest = rest.strip_prefix('"')?;
            let end = rest.find('"')?;
            return Some(rest[..end].to_owned());
        }
    }
    None
}

/// Cheap substring extractor: find `start`, return everything from
/// just past it up to the next `end`. Returns `None` if `start` is
/// absent OR `end` does not follow within the same line span.
/// Inlined here to avoid pulling a regex crate just for three
/// fields in a witness test.
fn extract_after(haystack: &str, start: &str, end: &str) -> Option<String> {
    let i = haystack.find(start)?;
    let rest = &haystack[i + start.len()..];
    let j = rest.find(end)?;
    Some(rest[..j].to_owned())
}
