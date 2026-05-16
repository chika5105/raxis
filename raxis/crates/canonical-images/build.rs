//! `raxis-canonical-images` build script — emits the kernel-pinned
//! trust anchor [`EXPECTED_KERNEL_SIGNING_KEY_BYTES`] **and** the
//! V1-fallback per-role image digests
//! ([`EXPECTED_REVIEWER_IMAGE_DIGEST`] / [`EXPECTED_ORCHESTRATOR_IMAGE_DIGEST`])
//! as a generated Rust file under `OUT_DIR`.
//!
//! ## Why a build script
//!
//! The trust anchor is **not** a free-form constant; per
//! `planner-harness.md §14.4` it is the SHA-256-fingerprintable
//! Ed25519 verifying-key half of the kernel's release-signing
//! keypair. The release pipeline owns it; the kernel binary embeds
//! the public half so every shipped manifest can be verified against
//! exactly one known key. Hand-editing the `lib.rs` constant is the
//! ONLY legal way to repoint it (see `EXPECTED_KERNEL_SIGNING_KEY_BYTES`'
//! doc comment), and that hand-edit is a release-pipeline operation,
//! not a developer commit.
//!
//! Embedding the anchor through a build script collapses the manual
//! "edit `lib.rs`" step into "set one of two environment variables
//! before `cargo build`":
//!
//! * `RAXIS_KERNEL_SIGNING_KEY_HEX` — 64 lowercase hex characters
//!   (the output of `xxd -p -c 64 signing.pub`). Preferred for CI
//!   pipelines that already shuttle short strings.
//! * `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` — absolute path to a
//!   32-byte raw file. Preferred for HSM-backed pipelines that
//!   never materialise the bytes as a hex string.
//!
//! ## Resolution chain (iter62, INV-IMAGE-TRUST-ANCHOR-DEV-FALLBACK-01)
//!
//! 1. `RAXIS_KERNEL_SIGNING_KEY_HEX` (highest priority — explicit
//!    operator override; CI / release pipelines).
//! 2. `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` (alt env var for
//!    HSM-backed pipelines that hand a path rather than a hex
//!    string).
//! 3. `<workspace_root>/.git/info/raxis-signing-key/pk.hex`
//!    (per-clone dev key — written by `cargo xtask images bake`
//!    OR by this build script's dev-profile auto-mint, see step 4).
//! 4. **Profile-dependent fallback.**
//!    * Release builds (`PROFILE=release`): emit the all-zero
//!      placeholder. The kernel boot's `assert_trust_anchor_present_or_panic`
//!      then trips fail-loud at runtime — preserving the
//!      `INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01` contract for production.
//!    * Dev / test builds (any other `PROFILE`): mint a fresh
//!      Ed25519 keypair from the OS RNG, persist it to
//!      `.git/info/raxis-signing-key/{sk,pk}.hex` (modes `0600` /
//!      `0644`, parent dir `0700`), and use the public half. The
//!      same artefact the xtask's `ensure_dev_signing_keypair`
//!      writes — both seams converge by routing through
//!      `raxis_dev_signing_key::ensure_dev_signing_keypair`.
//!
//! Step 4's dev-mint exists to fix the iter60 regression where a
//! bare `cargo test -p raxis-kernel` (which does NOT go through
//! xtask) would build a kernel binary with the all-zero placeholder
//! and panic at boot. The fail-loud guarantee was always about
//! preventing a SILENT disablement of image integrity verification
//! in production — it was never about making `cargo test` unusable.
//! Release builds keep the fail-loud posture; dev / test builds
//! materialise a per-clone key on first build and reuse it
//! thereafter.
//!
//! Validation failure on a hex / path env var input is a hard
//! build error so a mistyped value never silently degrades to the
//! placeholder branch.
//!
//! ## Why we do NOT bake the secret half here
//!
//! The build script reads the **public** key only. Even on a
//! compromised builder, the secret half never enters the kernel
//! binary. The matching secret stays inside the release pipeline
//! (HSM / Vault / signed-by-CI workflow) and only the manifest
//! signature crosses the trust boundary onto operator disks. This
//! mirrors the manifest-trust model laid out in the lib.rs module
//! comment (V2 inverts the trust direction so the kernel anchors the
//! key, not the per-image digest).
//!
//! ## Why a build script and not `option_env!`
//!
//! `option_env!` cannot decode hex into a `[u8; 32]` array at
//! compile-time without a procedural macro, and we deliberately
//! refuse to introduce a proc-macro dependency here for a 30-line
//! constant emission. The build script is single-file, single-
//! purpose, and visible at the same level as the constant it
//! generates.
//!
//! ## V1-fallback per-role image digests
//!
//! The V2 boot path uses the manifest-trust model and does NOT
//! consult the per-role digest constants. They remain on the public
//! API of `raxis-canonical-images` for two reasons:
//!
//! * `verify_canonical_image_pinned` — out-of-band tools
//!   (`raxis doctor`, ad-hoc image audits) want a single self-
//!   contained "does this `.img` byte-equal the kernel's expected
//!   digest" check that does not require loading a manifest.
//! * `CanonicalImageKind::expected_digest` — audit-event payloads
//!   carry the V1 digest as a stable identifier even when the V2
//!   manifest path is the one actually enforcing.
//!
//! The build script therefore emits **two extra optional**
//! per-role digest constants alongside the trust anchor:
//!
//! * `RAXIS_EXPECTED_REVIEWER_IMAGE_DIGEST_HEX`     — 64 lowercase
//!   hex chars committing to the Reviewer image's SHA-256.
//! * `RAXIS_EXPECTED_ORCHESTRATOR_IMAGE_DIGEST_HEX` — 64 lowercase
//!   hex chars committing to the Orchestrator image's SHA-256.
//!
//! Each defaults to the all-zero placeholder when its env var is
//! absent. The kernel V2 boot path is unaffected by either default
//! (the manifest path is the source of truth); the `verify_canonical_image_pinned`
//! callers see `DigestNotPopulated` exactly when these values are
//! unset, matching the existing V1 contract.

use std::env;
use std::fs;
use std::path::PathBuf;

const TRUST_ANCHOR_HEX_VAR: &str = "RAXIS_KERNEL_SIGNING_KEY_HEX";
const TRUST_ANCHOR_PATH_VAR: &str = "RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH";
const REVIEWER_DIGEST_HEX_VAR: &str = "RAXIS_EXPECTED_REVIEWER_IMAGE_DIGEST_HEX";
const ORCHESTRATOR_DIGEST_HEX_VAR: &str = "RAXIS_EXPECTED_ORCHESTRATOR_IMAGE_DIGEST_HEX";
// === iter62 verifier-runtime: V1-fallback per-role digest env vars ===
// Two new compile-time-pinned digests that the kernel binary embeds
// alongside Reviewer / Orchestrator. They follow the SAME validation
// chain (`resolve_role_digest`) and the SAME placeholder-default
// shape so a kernel built without populating them still compiles
// but `verify_canonical_image_pinned` fails-loud at spawn with
// `DigestNotPopulated` — preserving the V1 trust posture for
// out-of-band tools (`raxis doctor`) and the kernel-canonical
// symbol-index image's "digest is the SOLE truth at spawn" rule.
const VERIFIER_STARTER_DIGEST_HEX_VAR: &str =
    "RAXIS_EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST_HEX";
const VERIFIER_SYMBOL_INDEX_DIGEST_HEX_VAR: &str =
    "RAXIS_EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST_HEX";
const TRUST_ANCHOR_LEN_BYTES: usize = 32;
const TRUST_ANCHOR_LEN_HEX: usize = TRUST_ANCHOR_LEN_BYTES * 2;
const TRUST_ANCHOR_OUT_FILE: &str = "trust_anchor.rs";

/// Build profile classification used by the resolution chain.
/// `Release` keeps the fail-loud posture (no auto-mint); `Dev`
/// materialises a per-clone keypair on first build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildProfile {
    /// `PROFILE=release`. The kernel boot path's
    /// `assert_trust_anchor_present_or_panic` is the only
    /// fallback — the build script does NOT auto-mint.
    Release,
    /// Anything else (`debug`, custom profiles, `cargo test`, …).
    /// Auto-mint the per-clone dev key on first build.
    Dev,
}

impl BuildProfile {
    fn from_env() -> Self {
        // Cargo always sets `PROFILE` for build scripts. Treat the
        // absence as `Dev` so an unusual cargo invocation that omits
        // it (e.g. a bare `rustc` driver in a niche tooling test)
        // takes the dev-mint path rather than baking placeholder
        // bytes into a binary the developer plans to run.
        match env::var("PROFILE").as_deref() {
            Ok("release") => BuildProfile::Release,
            _ => BuildProfile::Dev,
        }
    }
}

/// Source of the trust-anchor bytes — emitted on stderr at
/// build-script time so a `cargo build -vv` log carries the
/// resolution decision and integration witnesses can pin the
/// branch taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorSource {
    EnvHex,
    EnvBytesPath,
    DotGitInfoFile,
    DevAutoMint,
    PlaceholderRelease,
    PlaceholderNoWorkspaceRoot,
}

impl AnchorSource {
    fn as_str(self) -> &'static str {
        match self {
            AnchorSource::EnvHex => "env_RAXIS_KERNEL_SIGNING_KEY_HEX",
            AnchorSource::EnvBytesPath => "env_RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH",
            AnchorSource::DotGitInfoFile => "git_info_pk_hex",
            AnchorSource::DevAutoMint => "dev_auto_mint",
            AnchorSource::PlaceholderRelease => "placeholder_release_no_input",
            AnchorSource::PlaceholderNoWorkspaceRoot => "placeholder_no_workspace_root",
        }
    }
}

fn main() {
    // Re-run the build script when any input variable changes.
    // Without this, `cargo` will cache the previous output even after
    // the operator has populated an env var.
    println!("cargo:rerun-if-env-changed={TRUST_ANCHOR_HEX_VAR}");
    println!("cargo:rerun-if-env-changed={TRUST_ANCHOR_PATH_VAR}");
    println!("cargo:rerun-if-env-changed={REVIEWER_DIGEST_HEX_VAR}");
    println!("cargo:rerun-if-env-changed={ORCHESTRATOR_DIGEST_HEX_VAR}");
    // iter62 verifier-runtime D6: rerun when the verifier digest envs change.
    println!("cargo:rerun-if-env-changed={VERIFIER_STARTER_DIGEST_HEX_VAR}");
    println!("cargo:rerun-if-env-changed={VERIFIER_SYMBOL_INDEX_DIGEST_HEX_VAR}");
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-changed=build.rs");

    let profile = BuildProfile::from_env();
    let (trust_anchor, source) = resolve_trust_anchor_bytes(profile);

    // Surface the resolution decision so a `cargo build -vv` reader
    // and the iter62 integration witnesses can both observe which
    // arm fired.
    println!(
        "cargo:warning=raxis-canonical-images: trust anchor source = {}",
        source.as_str()
    );

    let reviewer_digest = resolve_role_digest(REVIEWER_DIGEST_HEX_VAR);
    let orchestrator_digest = resolve_role_digest(ORCHESTRATOR_DIGEST_HEX_VAR);
    // iter62 verifier-runtime D6: resolve the two new verifier digests
    // through the same validated path as the existing role digests.
    let verifier_starter_digest = resolve_role_digest(VERIFIER_STARTER_DIGEST_HEX_VAR);
    let verifier_symbol_index_digest = resolve_role_digest(VERIFIER_SYMBOL_INDEX_DIGEST_HEX_VAR);

    let out_dir = env::var_os("OUT_DIR").expect("cargo always sets OUT_DIR for build scripts");
    let dest = PathBuf::from(out_dir).join(TRUST_ANCHOR_OUT_FILE);
    fs::write(
        &dest,
        render_anchor_module(
            &trust_anchor,
            &reviewer_digest,
            &orchestrator_digest,
            &verifier_starter_digest,
            &verifier_symbol_index_digest,
        ),
    )
    .expect("write generated trust_anchor.rs");

    // Re-run if the on-disk key file is touched. We only register
    // this when the path variable is set; otherwise rerun-if-changed
    // on a non-existent path is a no-op that confuses cargo.
    if let Ok(p) = env::var(TRUST_ANCHOR_PATH_VAR) {
        println!("cargo:rerun-if-changed={p}");
    }

    // Also re-run when the dev-key file changes. Once `cargo xtask
    // images bake` (or this build script's auto-mint) lands the file,
    // a subsequent rotation (the operator deletes + re-runs bake)
    // must propagate into the next kernel build.
    if let Some(ws_root) = current_workspace_root() {
        let pk = raxis_dev_signing_key::pk_path(&ws_root);
        println!("cargo:rerun-if-changed={}", pk.display());
    }
}

/// Read the trust-anchor source-of-truth in priority order:
///
///   1. `RAXIS_KERNEL_SIGNING_KEY_HEX`   (64 lowercase hex chars)
///   2. `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` (path to 32-byte raw file)
///   3. `<workspace>/.git/info/raxis-signing-key/pk.hex` (per-clone
///      dev key seam shared with `cargo xtask images bake`)
///   4. Profile-dependent fallback: dev profiles auto-mint a fresh
///      keypair to the same `.git/info/raxis-signing-key/` location;
///      release profiles emit the all-zero placeholder so the
///      kernel boot fails loud.
///
/// Each input source is validated for length and (in the hex case)
/// alphabet membership. Validation failure is a hard build error so
/// a mistyped value never silently degrades to the placeholder
/// branch — the boot-path verifier would then accept "no trust anchor"
/// in a build that the operator believed was signed.
///
/// `INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01` (iter60) — the placeholder
/// arm under release profile is the kernel-boot trip wire.
/// `INV-IMAGE-TRUST-ANCHOR-DEV-FALLBACK-01` (iter62) — the dev-profile
/// auto-mint avoids the trip wire on local workflows by minting the
/// per-clone key on first build, while keeping the file on the same
/// disk path the xtask seam writes to. See the module-level doc
/// comment + `specs/v3/canonical-image-trust-anchor.md` for the
/// full operator workflow.
fn resolve_trust_anchor_bytes(
    profile: BuildProfile,
) -> ([u8; TRUST_ANCHOR_LEN_BYTES], AnchorSource) {
    if let Ok(hex_input) = env::var(TRUST_ANCHOR_HEX_VAR) {
        let trimmed = hex_input.trim();
        if !trimmed.is_empty() {
            let bytes =
                decode_hex(trimmed).unwrap_or_else(|e| panic!("{TRUST_ANCHOR_HEX_VAR}: {e}"));
            return (bytes, AnchorSource::EnvHex);
        }
    }

    if let Ok(path_input) = env::var(TRUST_ANCHOR_PATH_VAR) {
        let trimmed = path_input.trim();
        if !trimmed.is_empty() {
            let bytes =
                read_raw_bytes(trimmed).unwrap_or_else(|e| panic!("{TRUST_ANCHOR_PATH_VAR}: {e}"));
            return (bytes, AnchorSource::EnvBytesPath);
        }
    }

    // Discover the workspace root — required for both the
    // .git/info/raxis-signing-key/ seam and the dev auto-mint.
    let workspace_root = match current_workspace_root() {
        Some(p) => p,
        None => {
            // No workspace root visible (e.g. a `cargo publish`-staged
            // tarball extracted under `~/.cargo/registry/`). The
            // .git directory does not exist, so neither the file-read
            // nor the auto-mint can succeed. Leave the placeholder;
            // the kernel boot's fail-loud panic still fires for
            // release builds and the operator's recovery is to set
            // `RAXIS_KERNEL_SIGNING_KEY_HEX` explicitly.
            return (
                [0u8; TRUST_ANCHOR_LEN_BYTES],
                AnchorSource::PlaceholderNoWorkspaceRoot,
            );
        }
    };

    // Step 3: read an existing pk.hex if present (the iter61 xtask
    // seam, OR a prior dev-mint from this build script).
    match raxis_dev_signing_key::read_existing_pk_bytes(&workspace_root) {
        Ok(Some(bytes)) => return (bytes, AnchorSource::DotGitInfoFile),
        Ok(None) => {}
        Err(e) => panic!(
            "raxis-canonical-images/build.rs: failed to read existing dev signing pk.hex: {e}"
        ),
    }

    // Step 4: profile-dependent fallback.
    match profile {
        BuildProfile::Release => {
            // RELEASE BUILD — never silently mint a key. The
            // kernel boot's `assert_trust_anchor_present_or_panic`
            // is the trip wire. INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01.
            (
                [0u8; TRUST_ANCHOR_LEN_BYTES],
                AnchorSource::PlaceholderRelease,
            )
        }
        BuildProfile::Dev => {
            // DEV / TEST BUILD — auto-mint a per-clone keypair so
            // `cargo test -p raxis-kernel` (and any other dev-loop
            // cargo command) produces a kernel binary that boots
            // without manual env-var ceremony. The same artefact
            // shape `cargo xtask images bake` writes — both seams
            // converge by routing through this single helper.
            // INV-IMAGE-TRUST-ANCHOR-DEV-FALLBACK-01.
            let kp = raxis_dev_signing_key::ensure_dev_signing_keypair(&workspace_root)
                .unwrap_or_else(|e| {
                    panic!(
                        "raxis-canonical-images/build.rs: failed to auto-mint dev signing keypair \
                     at {} (set RAXIS_KERNEL_SIGNING_KEY_HEX explicitly to bypass the \
                     auto-mint): {e}",
                        raxis_dev_signing_key::git_info_signing_key_dir(&workspace_root).display(),
                    )
                });
            // ensure_dev_signing_keypair guarantees pk_hex is 64
            // lowercase hex chars; route through the same decoder
            // used for the env-var arms so a malformed shape would
            // surface with the same diagnostic.
            let bytes = decode_hex(&kp.pk_hex).expect(
                "ensure_dev_signing_keypair returns 64 lowercase hex chars by construction",
            );
            (bytes, AnchorSource::DevAutoMint)
        }
    }
}

/// Resolve a per-role image-digest env var. Hex-only input (the raw-
/// file form is reserved for the trust anchor where HSM-backed
/// pipelines need it; per-role digests are SHA-256s and always
/// round-trip cleanly through hex). Returns the all-zero placeholder
/// when unset; panics on a mistyped non-empty value.
fn resolve_role_digest(env_var: &str) -> [u8; TRUST_ANCHOR_LEN_BYTES] {
    let raw = match env::var(env_var) {
        Ok(s) => s,
        Err(_) => return [0u8; TRUST_ANCHOR_LEN_BYTES],
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return [0u8; TRUST_ANCHOR_LEN_BYTES];
    }
    decode_hex(trimmed).unwrap_or_else(|e| panic!("{env_var}: {e}"))
}

/// Discover the workspace root from `CARGO_MANIFEST_DIR`. We use
/// the cargo-supplied per-package manifest dir as the walk seed
/// because the build script's `current_dir()` is also that path,
/// but threading it through `CARGO_MANIFEST_DIR` makes the
/// derivation explicit (and survives a future cargo flag that
/// changes the build-script CWD).
fn current_workspace_root() -> Option<PathBuf> {
    let crate_dir = env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from)?;
    raxis_dev_signing_key::find_workspace_root_from(&crate_dir)
}

fn decode_hex(input: &str) -> Result<[u8; TRUST_ANCHOR_LEN_BYTES], String> {
    if input.len() != TRUST_ANCHOR_LEN_HEX {
        return Err(format!(
            "expected {TRUST_ANCHOR_LEN_HEX} lowercase hex characters \
             (got {} characters)",
            input.len(),
        ));
    }
    let mut out = [0u8; TRUST_ANCHOR_LEN_BYTES];
    for (i, byte) in out.iter_mut().enumerate() {
        let lo = nybble(input.as_bytes()[2 * i + 1])
            .ok_or_else(|| format!("non-hex character at offset {}", 2 * i + 1))?;
        let hi = nybble(input.as_bytes()[2 * i])
            .ok_or_else(|| format!("non-hex character at offset {}", 2 * i))?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn nybble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn read_raw_bytes(path: &str) -> Result<[u8; TRUST_ANCHOR_LEN_BYTES], String> {
    let raw = fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    if raw.len() != TRUST_ANCHOR_LEN_BYTES {
        return Err(format!(
            "expected exactly {TRUST_ANCHOR_LEN_BYTES} bytes (got {} bytes from {path})",
            raw.len(),
        ));
    }
    let mut out = [0u8; TRUST_ANCHOR_LEN_BYTES];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn render_anchor_module(
    trust_anchor: &[u8; TRUST_ANCHOR_LEN_BYTES],
    reviewer_digest: &[u8; TRUST_ANCHOR_LEN_BYTES],
    orchestrator_digest: &[u8; TRUST_ANCHOR_LEN_BYTES],
    // iter62 verifier-runtime D6: append-only — the new digests
    // sit at the end of the generated module so a release pipeline
    // that has not yet started populating them keeps producing the
    // same prefix bytes for the existing constants.
    verifier_starter_digest: &[u8; TRUST_ANCHOR_LEN_BYTES],
    verifier_symbol_index_digest: &[u8; TRUST_ANCHOR_LEN_BYTES],
) -> String {
    let mut s = String::with_capacity(4096);
    s.push_str(
        "// AUTO-GENERATED by raxis-canonical-images/build.rs.\n\
         // DO NOT EDIT — set the relevant env var(s) before `cargo build`:\n\
         //   RAXIS_KERNEL_SIGNING_KEY_HEX                            (trust anchor)\n\
         //   RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH                     (trust anchor, alt)\n\
         //   RAXIS_EXPECTED_REVIEWER_IMAGE_DIGEST_HEX                (V1 fallback)\n\
         //   RAXIS_EXPECTED_ORCHESTRATOR_IMAGE_DIGEST_HEX            (V1 fallback)\n\
         //   RAXIS_EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST_HEX        (iter62 V1 fallback)\n\
         //   RAXIS_EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST_HEX   (iter62 V1 fallback)\n\
         // The generated constants are consumed by lib.rs at\n\
         // `EXPECTED_KERNEL_SIGNING_KEY_BYTES`,\n\
         // `EXPECTED_REVIEWER_IMAGE_DIGEST`,\n\
         // `EXPECTED_ORCHESTRATOR_IMAGE_DIGEST`,\n\
         // `EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST`, and\n\
         // `EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST`.\n",
    );
    push_byte_array(&mut s, "GENERATED_KERNEL_SIGNING_KEY_BYTES", trust_anchor);
    push_byte_array(&mut s, "GENERATED_REVIEWER_IMAGE_DIGEST", reviewer_digest);
    push_byte_array(
        &mut s,
        "GENERATED_ORCHESTRATOR_IMAGE_DIGEST",
        orchestrator_digest,
    );
    // iter62 verifier-runtime D6 — append-only generation.
    push_byte_array(
        &mut s,
        "GENERATED_VERIFIER_STARTER_IMAGE_DIGEST",
        verifier_starter_digest,
    );
    push_byte_array(
        &mut s,
        "GENERATED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST",
        verifier_symbol_index_digest,
    );
    s
}

fn push_byte_array(s: &mut String, name: &str, bytes: &[u8; TRUST_ANCHOR_LEN_BYTES]) {
    s.push_str("pub(crate) const ");
    s.push_str(name);
    s.push_str(": [u8; 32] = [");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&format!("0x{:02x}", b));
    }
    s.push_str("];\n");
}
