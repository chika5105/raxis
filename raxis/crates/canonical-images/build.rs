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
//! If neither is set, the constant defaults to the all-zero
//! `UNPOPULATED_SIGNING_KEY_BYTES` placeholder — same compile-time
//! shape as before this build script existed, so developer builds
//! continue to work without ceremony. The boot-path verifier
//! (`verify_canonical_image_via_manifest`) detects the placeholder
//! and surfaces `CanonicalImageError::SigningKeyFpNotPopulated`,
//! making "I forgot to set the env var" loud and obvious in
//! production.
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

const TRUST_ANCHOR_HEX_VAR:    &str = "RAXIS_KERNEL_SIGNING_KEY_HEX";
const TRUST_ANCHOR_PATH_VAR:   &str = "RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH";
const REVIEWER_DIGEST_HEX_VAR:     &str = "RAXIS_EXPECTED_REVIEWER_IMAGE_DIGEST_HEX";
const ORCHESTRATOR_DIGEST_HEX_VAR: &str = "RAXIS_EXPECTED_ORCHESTRATOR_IMAGE_DIGEST_HEX";
const TRUST_ANCHOR_LEN_BYTES:  usize = 32;
const TRUST_ANCHOR_LEN_HEX:    usize = TRUST_ANCHOR_LEN_BYTES * 2;
const TRUST_ANCHOR_OUT_FILE:   &str = "trust_anchor.rs";

fn main() {
    // Re-run the build script when any input variable changes.
    // Without this, `cargo` will cache the previous output even after
    // the operator has populated an env var.
    println!("cargo:rerun-if-env-changed={TRUST_ANCHOR_HEX_VAR}");
    println!("cargo:rerun-if-env-changed={TRUST_ANCHOR_PATH_VAR}");
    println!("cargo:rerun-if-env-changed={REVIEWER_DIGEST_HEX_VAR}");
    println!("cargo:rerun-if-env-changed={ORCHESTRATOR_DIGEST_HEX_VAR}");
    println!("cargo:rerun-if-changed=build.rs");

    let trust_anchor          = resolve_trust_anchor_bytes();
    let reviewer_digest       = resolve_role_digest(REVIEWER_DIGEST_HEX_VAR);
    let orchestrator_digest   = resolve_role_digest(ORCHESTRATOR_DIGEST_HEX_VAR);

    let out_dir = env::var_os("OUT_DIR")
        .expect("cargo always sets OUT_DIR for build scripts");
    let dest    = PathBuf::from(out_dir).join(TRUST_ANCHOR_OUT_FILE);
    fs::write(
        &dest,
        render_anchor_module(&trust_anchor, &reviewer_digest, &orchestrator_digest),
    )
    .expect("write generated trust_anchor.rs");

    // Re-run if the on-disk key file is touched. We only register
    // this when the path variable is set; otherwise rerun-if-changed
    // on a non-existent path is a no-op that confuses cargo.
    if let Ok(p) = env::var(TRUST_ANCHOR_PATH_VAR) {
        println!("cargo:rerun-if-changed={p}");
    }
}

/// Read the trust-anchor source-of-truth in priority order:
///
///   1. `RAXIS_KERNEL_SIGNING_KEY_HEX`   (64 lowercase hex chars)
///   2. `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` (path to 32-byte raw file)
///   3. fallback — all-zero placeholder
///
/// Each input source is validated for length and (in the hex case)
/// alphabet membership. Validation failure is a hard build error so
/// a mistyped value never silently degrades to the placeholder
/// branch — the boot-path verifier would then accept "no trust anchor"
/// in a build that the operator believed was signed.
fn resolve_trust_anchor_bytes() -> [u8; TRUST_ANCHOR_LEN_BYTES] {
    if let Ok(hex_input) = env::var(TRUST_ANCHOR_HEX_VAR) {
        let trimmed = hex_input.trim();
        if !trimmed.is_empty() {
            return decode_hex(trimmed)
                .unwrap_or_else(|e| panic!("{TRUST_ANCHOR_HEX_VAR}: {e}"));
        }
    }

    if let Ok(path_input) = env::var(TRUST_ANCHOR_PATH_VAR) {
        let trimmed = path_input.trim();
        if !trimmed.is_empty() {
            return read_raw_bytes(trimmed)
                .unwrap_or_else(|e| panic!("{TRUST_ANCHOR_PATH_VAR}: {e}"));
        }
    }

    // Placeholder. lib.rs `EXPECTED_KERNEL_SIGNING_KEY_BYTES` doc
    // explains how this is detected at runtime
    // (`SigningKeyFpNotPopulated`); developer builds rely on this.
    [0u8; TRUST_ANCHOR_LEN_BYTES]
}

/// Resolve a per-role image-digest env var. Hex-only input (the raw-
/// file form is reserved for the trust anchor where HSM-backed
/// pipelines need it; per-role digests are SHA-256s and always
/// round-trip cleanly through hex). Returns the all-zero placeholder
/// when unset; panics on a mistyped non-empty value.
fn resolve_role_digest(env_var: &str) -> [u8; TRUST_ANCHOR_LEN_BYTES] {
    let raw = match env::var(env_var) {
        Ok(s)  => s,
        Err(_) => return [0u8; TRUST_ANCHOR_LEN_BYTES],
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return [0u8; TRUST_ANCHOR_LEN_BYTES];
    }
    decode_hex(trimmed)
        .unwrap_or_else(|e| panic!("{env_var}: {e}"))
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
        _           => None,
    }
}

fn read_raw_bytes(path: &str) -> Result<[u8; TRUST_ANCHOR_LEN_BYTES], String> {
    let raw = fs::read(path)
        .map_err(|e| format!("cannot read {path}: {e}"))?;
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
    trust_anchor:        &[u8; TRUST_ANCHOR_LEN_BYTES],
    reviewer_digest:     &[u8; TRUST_ANCHOR_LEN_BYTES],
    orchestrator_digest: &[u8; TRUST_ANCHOR_LEN_BYTES],
) -> String {
    let mut s = String::with_capacity(4096);
    s.push_str(
        "// AUTO-GENERATED by raxis-canonical-images/build.rs.\n\
         // DO NOT EDIT — set the relevant env var(s) before `cargo build`:\n\
         //   RAXIS_KERNEL_SIGNING_KEY_HEX                   (trust anchor)\n\
         //   RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH            (trust anchor, alt)\n\
         //   RAXIS_EXPECTED_REVIEWER_IMAGE_DIGEST_HEX       (V1 fallback)\n\
         //   RAXIS_EXPECTED_ORCHESTRATOR_IMAGE_DIGEST_HEX   (V1 fallback)\n\
         // The generated constants are consumed by lib.rs at\n\
         // `EXPECTED_KERNEL_SIGNING_KEY_BYTES`,\n\
         // `EXPECTED_REVIEWER_IMAGE_DIGEST`, and\n\
         // `EXPECTED_ORCHESTRATOR_IMAGE_DIGEST`.\n",
    );
    push_byte_array(&mut s, "GENERATED_KERNEL_SIGNING_KEY_BYTES",   trust_anchor);
    push_byte_array(&mut s, "GENERATED_REVIEWER_IMAGE_DIGEST",      reviewer_digest);
    push_byte_array(&mut s, "GENERATED_ORCHESTRATOR_IMAGE_DIGEST",  orchestrator_digest);
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
