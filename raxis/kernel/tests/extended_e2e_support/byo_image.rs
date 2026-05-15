//! BYO (Bring-Your-Own-Image) Executor harness — bakes the sample
//! Containerfile under `raxis/live-e2e/seed/byoi-executor/`,
//! computes its rootfs SHA-256, stages the bytes in the kernel's
//! `<data_dir>/oci-cache/` per `image-cache.md §4`, and amends
//! `policy.toml` with the matching `[[vm_images]]` +
//! `[default_executor_image]` registration.
//!
//! ## Why a dedicated module
//!
//! The realism harness (`kernel_driver.rs`) auto-bakes the
//! kernel-canonical images (Reviewer / Orchestrator / Executor-
//! starter) at preflight time so live-e2e tests never run against
//! a stub rootfs. The BYO scenario is a different code path
//! entirely — operator-published image, resolved at session-spawn
//! through `ImageResolver::resolve` against the on-disk
//! `oci-cache/` rather than against the kernel-version-locked
//! `$RAXIS_INSTALL_DIR/images/`. Treating the BYO bake +
//! `[[vm_images]]` injection as its own helper keeps the existing
//! canonical-image flow untouched and lets future BYO scenarios
//! (multi-image plans, role-restricted Verifier images, etc.)
//! reuse the primitives below.
//!
//! ## Cross-references
//!
//! * `raxis/specs/v2/canonical-images.md §3` — the BYO flow this
//!   helper exercises end-to-end.
//! * `raxis/specs/v2/image-cache.md §4` — on-disk cache layout
//!   (`<data_dir>/oci-cache/blobs|images|locks/sha256/<aa>/<full>`).
//! * `raxis/specs/invariants.md INV-OPERATOR-CUSTOM-IMAGE-01,02` —
//!   the trust contract this harness validates (digest pinning at
//!   resolution; tampered rootfs fails closed).
//! * `raxis/guides/recipes/ops/17-bring-your-own-executor-image.md`
//!   — the operator-facing recipe walking the same workflow this
//!   helper automates for the test.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Public constants — pinned across the harness, the witness regex,
// and the policy injection. Bumping any of these MUST be a single
// surgical commit that updates BOTH the Containerfile and the
// witness-regex constants in tandem; otherwise the live-e2e
// version assertion drifts silently.
// ---------------------------------------------------------------------------

/// `[[vm_images]]` alias the helper writes into `policy.toml`.
/// Operator-facing identifier; appears verbatim in the
/// `VmImageResolved` audit event the witness asserts on.
pub const BYO_ALIAS: &str = "byo-executor-py312-node22";

/// Human-readable description recorded in the `[[vm_images]]`
/// entry. Surfaced by `raxis-cli plan explain` / dashboard
/// inspectors; not security-sensitive.
pub const BYO_DESCRIPTION: &str = "BYO Executor: Python 3.12 + Node 22 (live-e2e fixture)";

/// `linux_kernel_version_min` declared on the `[[vm_images]]`
/// entry — the operator-supplied minimum guest Linux kernel
/// version. Set to `5.14` per `INV-PLANNER-HARNESS-03`
/// (cgroup v2 floor for the harness's `cgroup.kill` discipline).
pub const BYO_LINUX_KERNEL_MIN: &str = "5.14";

/// Major.minor pin the Containerfile bakes (`python:3.12.7-slim-
/// bookworm`); the witness regex `Python 3\.12\.\d+` matches any
/// patch version inside this minor track so a transparent base-
/// image patch bump does not break the test, but a major / minor
/// drift fails loudly.
pub const PINNED_PYTHON_MAJOR_MINOR: &str = "3.12";

/// Major version of the Node LTS line the Containerfile installs
/// via the NodeSource `setup_22.x` apt source. The witness regex
/// `v22\.\d+\.\d+` keys on this major; NodeSource patches the 22.x
/// repo silently, so leaving the patch / minor unconstrained is
/// the right shape for the regex.
pub const PINNED_NODE_MAJOR: &str = "22";

/// Subdirectory under `raxis/live-e2e/seed/` where the BYO
/// Containerfile + future fixtures live. The bake helper resolves
/// the absolute path via the workspace root.
pub const SEED_SUBDIR: &str = "live-e2e/seed/byoi-executor";

// ---------------------------------------------------------------------------
// BakedByoImage — output of the bake step
// ---------------------------------------------------------------------------

/// Result of `bake_byo_executor_image_for_test`: a freshly-baked
/// rootfs blob staged in a per-test temp dir (NOT yet copied into
/// the kernel's oci-cache; that is `stage_byo_image_in_oci_cache`'s
/// job). The digest is the SHA-256 of `rootfs_blob_path`'s bytes.
#[derive(Debug, Clone)]
pub struct BakedByoImage {
    /// `sha256:<64 lower-hex>` form, ready to drop into a
    /// `[[vm_images]] oci_digest` field verbatim.
    pub oci_digest: String,
    /// Absolute path to the staged rootfs bytes (the source the
    /// per-cache copy step reads from). Lives under a
    /// `tempfile::TempDir` the caller owns; the harness keeps the
    /// file alive for the duration of the test.
    pub rootfs_blob_path: PathBuf,
    /// Size in bytes of `rootfs_blob_path`. Surfaced for the
    /// Tier-3 artifact line so post-run triage knows whether the
    /// bake produced a ~50 MiB BYO image (real bake) or a ~1 KiB
    /// synthetic blob (smoke-test mode).
    pub size_bytes: u64,
}

// ---------------------------------------------------------------------------
// bake — synthetic mode (no docker required) and full mode (docker)
// ---------------------------------------------------------------------------

/// **Smoke-test bake.** Produce a small deterministic byte-blob
/// representing the BYO rootfs. Used by:
///   * the audit-emit witness path (the resolver only cares about
///     the SHA-256 matching the policy-declared digest; a
///     synthetic blob is sufficient to exercise
///     `VmImageResolved` / `OperatorImageDigestMismatch` emit
///     wiring even though the substrate cannot boot it),
///   * smoke-test fallback when the live-e2e gates are off so
///     the BYO test binary still exercises the helper APIs at
///     `cargo test -p raxis-kernel` time without docker on the
///     host.
///
/// Returns a `BakedByoImage` whose `oci_digest` matches
/// `rootfs_blob_path`'s on-disk SHA-256. The blob lives under
/// `staging_dir`; the caller keeps `staging_dir` alive (typically
/// a `tempfile::TempDir`).
pub fn bake_byo_executor_image_synthetic(staging_dir: &Path) -> std::io::Result<BakedByoImage> {
    fs::create_dir_all(staging_dir)?;
    let path = staging_dir.join("rootfs.img");

    // Deterministic content keyed on the BYO_ALIAS so the digest is
    // reproducible across runs of the harness — useful for offline
    // triage when an audit chain references the alias and the
    // operator wants to re-derive the digest without re-baking.
    // NOT secure-as-such (anyone can compute it); the trust anchor
    // is the policy signature over `oci_digest`, not the bytes
    // themselves.
    let body = format!(
        "raxis-byo-executor-synthetic-fixture v1\n\
         alias={BYO_ALIAS}\n\
         python={PINNED_PYTHON_MAJOR_MINOR}\n\
         node={PINNED_NODE_MAJOR}\n\
         purpose=audit-emit-witness\n\
         note=this byte-blob is intentionally not a bootable rootfs;\n\
              the substrate spawn will fail past the kernel's audit emit\n\
              of VmImageResolved, which is what the witness asserts on.\n",
    );
    fs::write(&path, body.as_bytes())?;

    let digest = sha256_of_file(&path)?;
    let size = fs::metadata(&path)?.len();
    Ok(BakedByoImage {
        oci_digest: format!("sha256:{digest}"),
        rootfs_blob_path: path,
        size_bytes: size,
    })
}

/// **Full bake (docker required).** Build the BYO Containerfile,
/// export its filesystem, write the resulting tar payload to
/// `staging_dir/rootfs.img`, and compute its SHA-256.
///
/// Mirrors the canonical executor-starter bake (per
/// `xtask::images::bake_one_role`) shape:
///   1. `docker build -f <Containerfile> --platform linux/<arch>
///       -t <tag> <context>`
///   2. `docker create <tag>` → captures container id
///   3. `docker export <container-id>` → tar to `rootfs.img`
///   4. `docker rm <container-id>` (cleanup; non-fatal on failure)
///
/// `target_arch` controls the `--platform` flag. Pass `None` to
/// auto-detect via `default_target_arch_for_oci`. The
/// `Containerfile` itself uses `dpkg --print-architecture` for
/// per-arch package selection (Node, Go, GH CLI), so cross-arch
/// builds work transparently as long as docker has the matching
/// QEMU emulator wired in (`docker buildx ls`).
///
/// Panics with a remediation message if `docker` is not on `PATH`,
/// because the live-e2e BYO test cannot proceed without it. Use
/// `bake_byo_executor_image_synthetic` for the docker-free smoke
/// path.
pub fn bake_byo_executor_image_full(
    workspace_root: &Path,
    staging_dir: &Path,
    target_arch: Option<&str>,
) -> std::io::Result<BakedByoImage> {
    fs::create_dir_all(staging_dir)?;
    require_docker_on_path();

    let context = workspace_root.join(SEED_SUBDIR);
    let dockerfile = context.join("Containerfile");
    if !dockerfile.exists() {
        panic!(
            "BYO Containerfile missing at {} — checkout corruption?",
            dockerfile.display(),
        );
    }
    let arch: String = match target_arch {
        Some(a) => a.to_owned(),
        None => default_target_arch_for_oci().to_owned(),
    };
    let platform = format!("linux/{arch}");
    // Stable tag (no time-stamp) so re-bakes within a single test
    // run hit docker's layer cache. The tag is pruned on docker GC;
    // we deliberately do NOT `docker rmi` it so successive `cargo
    // test` runs amortise the bake cost.
    let tag = format!("raxis-byo-executor-py312-node22:dev-{arch}");

    eprintln!(
        "[live-e2e byo-image] docker build --platform {platform} -t {tag} \
         (context={})",
        context.display(),
    );
    let status = Command::new("docker")
        .arg("build")
        .arg("--platform")
        .arg(&platform)
        .arg("-t")
        .arg(&tag)
        .arg("-f")
        .arg(&dockerfile)
        .arg(&context)
        .status()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("spawn `docker build` for BYO image: {e}"),
            )
        })?;
    if !status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "docker build for BYO image failed (exit {status}); \
                 re-run manually for richer diagnostics:\n  \
                 docker build --platform {platform} -t {tag} \
                 -f {} {}",
                dockerfile.display(),
                context.display(),
            ),
        ));
    }

    // Create the container WITHOUT starting it. The default `sh`
    // entrypoint from the upstream image does not matter here — we
    // are only interested in the filesystem the next `docker export`
    // step extracts.
    let create = Command::new("docker")
        .args(["create", "--platform"])
        .arg(&platform)
        .arg(&tag)
        .output()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("spawn `docker create`: {e}"),
            )
        })?;
    if !create.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "docker create failed for BYO image (exit {}): {}",
                create.status,
                String::from_utf8_lossy(&create.stderr),
            ),
        ));
    }
    let container_id = String::from_utf8_lossy(&create.stdout).trim().to_owned();
    if container_id.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "docker create returned an empty container id",
        ));
    }

    // Stream the filesystem tarball to disk, hashing as we go.
    // `docker export <id>` writes the rootfs as a single tar to
    // stdout; we capture it byte-for-byte into `rootfs.img` so the
    // SHA-256 the kernel's resolver computes (over the same bytes
    // staged in `<data_dir>/oci-cache/.../rootfs.img`) matches the
    // policy-declared `oci_digest` exactly.
    let path = staging_dir.join("rootfs.img");
    let result = (|| -> std::io::Result<()> {
        let mut child = Command::new("docker")
            .arg("export")
            .arg(&container_id)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdout = child.stdout.take().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "docker export had no stdout pipe",
            )
        })?;
        let mut file = fs::File::create(&path)?;
        std::io::copy(&mut stdout, &mut file)?;
        let status = child.wait()?;
        if !status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("docker export failed (exit {status})"),
            ));
        }
        Ok(())
    })();

    // Cleanup the container regardless of export success — leaving
    // it around accumulates noise on the dev host.
    let _ = Command::new("docker")
        .args(["rm", "-f", &container_id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    result?;
    let digest = sha256_of_file(&path)?;
    let size = fs::metadata(&path)?.len();
    eprintln!(
        "[live-e2e byo-image] baked rootfs at {} ({} bytes), \
         oci_digest=sha256:{digest}",
        path.display(),
        size,
    );
    Ok(BakedByoImage {
        oci_digest: format!("sha256:{digest}"),
        rootfs_blob_path: path,
        size_bytes: size,
    })
}

// ---------------------------------------------------------------------------
// stage — copy the baked rootfs bytes into the kernel's oci-cache
// ---------------------------------------------------------------------------

/// Copy the baked rootfs bytes into
/// `<data_dir>/oci-cache/images/sha256/<aa>/<full>/rootfs.img` and
/// synthesise the minimal `manifest.json` + `config.json`
/// sidecars `image-cache.md §4` requires. Returns the absolute
/// path to the staged `rootfs.img` (what
/// `ResolvedImage.rootfs_image_path` will resolve to).
///
/// The shard prefix is the first two hex chars of the digest;
/// directories are created idempotently so a re-run of the test
/// against the same `data_dir` is cheap.
///
/// **Tampering hook.** When `tamper` is `true`, the helper
/// flips the LAST byte of the rootfs payload before writing,
/// so the on-disk SHA-256 will diverge from the policy-declared
/// `oci_digest` by exactly one byte. This is the negative-path
/// fixture for `INV-OPERATOR-CUSTOM-IMAGE-01` — the kernel
/// resolver MUST detect the mismatch and emit
/// `SecurityViolationDetected { violation_kind:
/// "OperatorImageDigestMismatch" }`. We tamper at stage time
/// rather than bake time so the policy's `oci_digest` field
/// continues to reference the ORIGINAL (un-tampered) bake's hash;
/// the test asserts the kernel notices the mismatch even though
/// the operator's policy said "this digest is fine".
pub fn stage_byo_image_in_oci_cache(
    data_dir: &Path,
    image: &BakedByoImage,
    tamper: bool,
) -> std::io::Result<PathBuf> {
    let hex = image.oci_digest.strip_prefix("sha256:").unwrap_or_else(|| {
        panic!(
            "BakedByoImage carries malformed oci_digest {:?} (expected `sha256:` prefix)",
            image.oci_digest,
        )
    });
    let shard = &hex[0..2];
    let dest_dir = data_dir
        .join("oci-cache")
        .join("images")
        .join("sha256")
        .join(shard)
        .join(hex);
    fs::create_dir_all(&dest_dir)?;
    let dest_rootfs = dest_dir.join("rootfs.img");

    let mut bytes = fs::read(&image.rootfs_blob_path)?;
    if tamper {
        let last = bytes.len().saturating_sub(1);
        // XOR the last byte with 0x55 to guarantee a flip even if
        // the byte happens to already be 0xFF (a `+= 1` would wrap
        // to 0x00 unconditionally too, but XOR preserves bit
        // diversity which is mildly nicer for any future
        // hex-distance assertion).
        bytes[last] ^= 0x55;
    }
    fs::write(&dest_rootfs, &bytes)?;

    // Synthesise minimal sidecars. The kernel's `PrePopulatedResolver`
    // does not currently parse these — it returns the layout-derived
    // paths verbatim and lets the substrate read them on demand —
    // but writing them keeps the on-disk shape honest against
    // `image-cache.md §4` so a future production-resolver swap does
    // not surface a "missing manifest.json" error from a stale
    // test fixture.
    let manifest_json = format!(
        "{{\"schemaVersion\":2,\
           \"mediaType\":\"application/vnd.raxis.image.rootfs.v1+erofs\",\
           \"config\":{{\"mediaType\":\"application/vnd.raxis.image.config.v1+json\",\
                        \"digest\":\"{0}\",\"size\":{1}}},\
           \"layers\":[{{\"mediaType\":\"application/vnd.raxis.image.rootfs.v1+erofs\",\
                         \"digest\":\"{0}\",\"size\":{1}}}]}}",
        image.oci_digest,
        bytes.len(),
    );
    fs::write(dest_dir.join("manifest.json"), manifest_json)?;

    let config_json = format!(
        "{{\"architecture\":\"unknown\",\"os\":\"linux\",\
           \"config\":{{\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:\
                                  /usr/sbin:/usr/bin:/sbin:/bin\"],\
                        \"Cmd\":[\"/usr/local/bin/raxis-executor\"]}},\
           \"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[\"{0}\"]}},\
           \"raxis_byo_alias\":\"{1}\"}}",
        image.oci_digest, BYO_ALIAS,
    );
    fs::write(dest_dir.join("config.json"), config_json)?;

    eprintln!(
        "[live-e2e byo-image] staged rootfs.img at {} ({} bytes, tampered={tamper})",
        dest_rootfs.display(),
        bytes.len(),
    );
    Ok(dest_rootfs)
}

// ---------------------------------------------------------------------------
// inject — amend policy.toml with [[vm_images]] + [default_executor_image]
// ---------------------------------------------------------------------------

/// Append a `[[vm_images]]` block referencing the BYO alias +
/// digest, and a `[default_executor_image]` block selecting that
/// alias as the fallback for Executor tasks omitting `vm_image`.
///
/// Pattern reference: `enable_gateway_in_policy` in
/// `kernel_driver.rs` — same "read existing policy.toml, append
/// new block, write back" shape; the live-e2e bootstrap rewrites
/// the operator-signed policy in-place BEFORE the kernel daemon
/// reads it, so no signature-verification failure surfaces.
///
/// Idempotency: panics if `[[vm_images]]` is already present
/// referencing the same alias — the helper is meant to run once
/// per test against a fresh `data_dir` (the bootstrap creates a
/// new one per test), and a duplicate-alias signal usually means
/// a test ordering bug.
pub fn inject_byo_executor_image_in_policy(data_dir: &Path, oci_digest: &str) {
    let policy_path = data_dir.join("policy").join("policy.toml");
    let mut body = fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", policy_path.display()));
    assert!(
        !body.contains(&format!("name = \"{BYO_ALIAS}\"")),
        "policy.toml already declares [[vm_images]] alias `{BYO_ALIAS}` — \
         test ordering bug? helper is single-shot per data_dir.",
    );
    let injected = format!(
        "\n# ── [[vm_images]] + [default_executor_image] (BYO live-e2e) ──\n\
         [[vm_images]]\n\
         name                     = \"{BYO_ALIAS}\"\n\
         oci_digest               = \"{oci_digest}\"\n\
         role_restriction         = [\"Executor\"]\n\
         linux_kernel_version_min = \"{BYO_LINUX_KERNEL_MIN}\"\n\
         description              = \"{BYO_DESCRIPTION}\"\n\
         \n\
         [default_executor_image]\n\
         alias = \"{BYO_ALIAS}\"\n",
    );
    body.push_str(&injected);
    fs::write(&policy_path, body)
        .unwrap_or_else(|e| panic!("rewrite {}: {e}", policy_path.display()));
    eprintln!(
        "[live-e2e byo-image] injected [[vm_images]] alias `{BYO_ALIAS}` \
         + [default_executor_image] into {}",
        policy_path.display(),
    );
}

// ---------------------------------------------------------------------------
// digest helpers
// ---------------------------------------------------------------------------

/// Stream-hash a file with SHA-256 and return the lower-hex
/// digest body (no `sha256:` prefix). Mirrors what the kernel's
/// `PrePopulatedResolver` does at resolve time so the harness's
/// `oci_digest` is byte-for-byte the same value the resolver
/// would derive.
pub fn sha256_of_file(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Flip the last hex character of a `sha256:<64-hex>` digest,
/// producing a syntactically-valid but semantically-different
/// digest. Used by `inject_tampered_byo_executor_image_in_policy`
/// to seed the negative-path test where the policy declares one
/// digest and the on-disk bytes hash to another.
///
/// Panics on malformed input — the input is expected to come
/// straight off a `BakedByoImage::oci_digest` field, so any
/// shape drift is a harness bug worth surfacing loudly.
pub fn tampered_digest_one_hex_off(digest: &str) -> String {
    let body = digest.strip_prefix("sha256:").unwrap_or_else(|| {
        panic!("tampered_digest_one_hex_off: expected `sha256:` prefix, got {digest:?}",)
    });
    assert_eq!(
        body.len(),
        64,
        "expected 64-char hex body, got {} chars: {digest:?}",
        body.len(),
    );
    let mut chars: Vec<char> = body.chars().collect();
    let last = chars[63];
    // Map any hex char to a neighbouring hex char, looping at the
    // end of the alphabet. Both '0'..='9' and 'a'..='f' are handled.
    let flipped = match last {
        '0'..='8' => char::from_u32(last as u32 + 1).unwrap_or('a'),
        '9' => 'a',
        'a'..='e' => char::from_u32(last as u32 + 1).unwrap_or('0'),
        'f' => '0',
        other => {
            panic!("tampered_digest_one_hex_off: digest body contains non-hex char {other:?}",)
        }
    };
    chars[63] = flipped;
    let body: String = chars.into_iter().collect();
    format!("sha256:{body}")
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

fn require_docker_on_path() {
    let probe = Command::new("docker")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(probe, Ok(s) if s.success()) {
        panic!(
            "BYO live-e2e bake requires `docker` on PATH (the helper builds \
             the BYO Containerfile via `docker build`). Install Docker \
             Desktop / Colima / podman+`alias docker=podman`, then re-run \
             the test. Set RAXIS_LIVE_E2E_BYO=0 (or unset) to skip the \
             docker-bound test variant entirely.",
        );
    }
}

/// OCI platform string for `docker build --platform linux/<arch>`.
/// Mirrors `xtask::images::oci_platform_for_target_triple` for the
/// host arch — keeps the bake the kernel will eventually load
/// matching the harness's expected substrate (Apple VZ on
/// aarch64-apple-darwin → linux/arm64; Linux x86_64 hosts →
/// linux/amd64). Future cross-arch CI workers can override via
/// the `target_arch` arg on `bake_byo_executor_image_full`.
fn default_target_arch_for_oci() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    }
}

// ---------------------------------------------------------------------------
// Tests — unit-test the helpers without docker / kernel
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_bake_produces_matching_digest() {
        let staging = tempfile::tempdir().expect("tempdir");
        let baked = bake_byo_executor_image_synthetic(staging.path()).expect("synthetic bake");
        let recomputed = format!(
            "sha256:{}",
            sha256_of_file(&baked.rootfs_blob_path).expect("rehash"),
        );
        assert_eq!(
            baked.oci_digest, recomputed,
            "synthetic bake must declare a digest matching the on-disk bytes \
             (the audit-emit witness depends on this byte-equality)",
        );
        assert!(baked.size_bytes > 0, "bake produced empty rootfs");
        assert!(
            baked.size_bytes < 1_024 * 16,
            "synthetic bake is supposed to be tiny"
        );
    }

    #[test]
    fn tampered_digest_one_hex_off_changes_last_char_only() {
        let original = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let tampered = tampered_digest_one_hex_off(original);
        assert_eq!(tampered.len(), original.len(), "shape preserved");
        assert!(tampered.starts_with("sha256:"), "prefix preserved");
        assert_ne!(tampered, original, "must actually differ");
        // Only the LAST hex char differs.
        let head_orig = &original[..original.len() - 1];
        let head_tamp = &tampered[..tampered.len() - 1];
        assert_eq!(head_orig, head_tamp, "only the last char flips");
    }

    #[test]
    fn tampered_digest_round_trips_known_endpoints() {
        // (input, expected output) — only the LAST hex char flips:
        //   '0'..='8' → next digit; '9' → 'a';
        //   'a'..='e' → next letter; 'f' → '0'.
        let pairs: &[(&str, &str)] = &[
            (
                "sha256:00000000000000000000000000000000000000000000000000000000000000ff",
                "sha256:00000000000000000000000000000000000000000000000000000000000000f0",
            ),
            (
                "sha256:00000000000000000000000000000000000000000000000000000000000000a9",
                "sha256:00000000000000000000000000000000000000000000000000000000000000aa",
            ),
            (
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "sha256:0000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                "sha256:0000000000000000000000000000000000000000000000000000000000000009",
                "sha256:000000000000000000000000000000000000000000000000000000000000000a",
            ),
            (
                "sha256:000000000000000000000000000000000000000000000000000000000000000e",
                "sha256:000000000000000000000000000000000000000000000000000000000000000f",
            ),
        ];
        for (input, expected) in pairs {
            let got = tampered_digest_one_hex_off(input);
            assert_eq!(&got, expected, "endpoint case mis-mapped: input={input:?}",);
        }
    }

    #[test]
    fn stage_writes_rootfs_at_layout_derived_path() {
        let data_dir = tempfile::tempdir().expect("tempdir for data_dir");
        let staging = tempfile::tempdir().expect("tempdir for bake staging");
        let baked = bake_byo_executor_image_synthetic(staging.path()).expect("synthetic bake");

        let staged = stage_byo_image_in_oci_cache(data_dir.path(), &baked, false).expect("stage");

        let hex = baked.oci_digest.strip_prefix("sha256:").unwrap();
        let shard = &hex[..2];
        let expected = data_dir
            .path()
            .join("oci-cache")
            .join("images")
            .join("sha256")
            .join(shard)
            .join(hex)
            .join("rootfs.img");
        assert_eq!(
            staged, expected,
            "rootfs.img must land at the image-cache.md §4 layout-derived path"
        );
        assert!(expected.exists(), "rootfs.img missing on disk");
        assert!(
            expected.with_file_name("manifest.json").exists(),
            "manifest.json sidecar missing"
        );
        assert!(
            expected.with_file_name("config.json").exists(),
            "config.json sidecar missing"
        );

        let staged_bytes = fs::read(&staged).unwrap();
        let original = fs::read(&baked.rootfs_blob_path).unwrap();
        assert_eq!(
            staged_bytes, original,
            "non-tampered stage must preserve the bake's bytes byte-for-byte"
        );
    }

    #[test]
    fn stage_with_tamper_diverges_by_one_byte() {
        let data_dir = tempfile::tempdir().expect("tempdir for data_dir");
        let staging = tempfile::tempdir().expect("tempdir for bake staging");
        let baked = bake_byo_executor_image_synthetic(staging.path()).expect("synthetic bake");
        let staged =
            stage_byo_image_in_oci_cache(data_dir.path(), &baked, true).expect("stage tampered");
        let staged_bytes = fs::read(&staged).unwrap();
        let original = fs::read(&baked.rootfs_blob_path).unwrap();
        assert_eq!(staged_bytes.len(), original.len(), "length preserved");
        let differing: usize = staged_bytes
            .iter()
            .zip(original.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(
            differing, 1,
            "tampered stage must differ by exactly one byte (last-byte XOR)"
        );
    }
}
