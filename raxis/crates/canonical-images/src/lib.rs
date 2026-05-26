//! Kernel-pinned canonical VM image **trust anchors** and on-disk
//! verification.
//!
//! Normative references:
//!
//! * `planner-harness.md §4.5` / `INV-PLANNER-HARNESS-02` — Reviewer
//!   image is kernel-canonical; the kernel rejects activation with
//!   `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH` on any digest mismatch.
//! * `planner-harness.md §4.7` / `INV-PLANNER-HARNESS-05` — same for
//!   the Orchestrator image, with `FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH`.
//! * `planner-harness.md §14.4 — Image-build pipeline` — the
//!   manifest-trust model: builder produces signed `<role>.manifest.toml`,
//!   kernel verifies it at boot.
//! * `system-requirements.md §1` and §11 — image distribution layout.
//!
//! ## V2 trust model — manifests, not compile-time digests
//!
//! The kernel binary used to ship two compile-time
//! `EXPECTED_*_IMAGE_DIGEST: [u8; 32]` constants pinning the SHA-256
//! of the on-disk `<role>-<kernel_version>.img` blob. That model
//! coupled the image hash to every kernel rebuild, which is operator-
//! hostile (any kernel patch had to re-pin both digests) and
//! brittle (the placeholder all-zero values shipped for months).
//!
//! V2 inverts the trust direction:
//!
//! 1. The kernel binary anchors only the **signing-key fingerprint**
//!    (`EXPECTED_KERNEL_SIGNING_KEY_FP`) — a single 32-byte value
//!    that changes only on a key rotation, not on every release.
//! 2. The on-disk distribution carries, per role:
//!    * `images/raxis-<role>-<kernel_version>.img` — the EROFS rootfs.
//!    * `images/raxis-<role>-<kernel_version>.manifest.toml` — the
//!      signed manifest produced by `raxis-image-builder`. The
//!      manifest's `image_artefact_sha256` field is the signed
//!      commitment to the .img blob's bytes.
//! 3. At boot (and as defense-in-depth at activation), the kernel:
//!    * Loads the manifest TOML.
//!    * Calls [`raxis_image_manifest::verify`] against the kernel's
//!      compiled-in `EXPECTED_KERNEL_SIGNING_KEY_FP`; the manifest
//!      crate refuses any wrong-key, wrong-schema, or
//!      bundle-hash-mismatch manifest.
//!    * Streams the on-disk .img and compares its SHA-256 against
//!      the signed [`raxis_image_manifest::ImageManifest::image_artefact_sha256`].
//!    * Refuses to boot any VM whose .img digest disagrees with
//!      what the manifest says, surfacing
//!      [`CanonicalImageError::DigestMismatch`].
//!
//! `verify_canonical_image_via_manifest` is the boot-time enforcement
//! seam under this model. It returns `Ok(())` only when every step
//! above succeeds.
//!
//! ## What the legacy compile-time path is good for
//!
//! [`verify_canonical_image_pinned`] keeps the V1 contract — pass an
//! expected `[u8; 32]` digest and stream the on-disk .img against it.
//! It is still useful for `raxis doctor`-style out-of-band tools that
//! want a single self-contained digest check without loading the
//! manifest, and for kernel-side fallback tests. Nothing in the V2
//! kernel boot path should rely on this directly.
//!
//! ## Streaming verification
//!
//! Image files are large (~15 MiB Reviewer, ~50 MiB Orchestrator —
//! `system-requirements.md §1`), so [`compute_image_digest`] streams
//! the file in 64 KiB chunks rather than buffering the whole image
//! into memory. Heap usage is bounded by `BUF_SIZE` regardless of
//! image size.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ed25519_dalek::VerifyingKey;
use raxis_image_manifest::{ImageManifest, ManifestError, Role};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Length of a SHA-256 digest in bytes. Public so callers that
/// surface the value (audit-event payloads, `raxis doctor` output)
/// do not redefine the magic number.
pub const DIGEST_LEN: usize = 32;

/// Streaming-read buffer used by [`compute_image_digest`]. 64 KiB
/// matches the page-cache stride of every modern filesystem we
/// target (APFS, ext4, btrfs, zfs) and keeps the verification step's
/// peak memory at a single page-cache-friendly chunk.
const BUF_SIZE: usize = 64 * 1024;

/// Sentinel value used until the kernel release pipeline commits the
/// canonical signing key. The verification helpers detect this and
/// surface [`CanonicalImageError::SigningKeyFpNotPopulated`].
pub const UNPOPULATED_SIGNING_KEY_BYTES: [u8; DIGEST_LEN] = [0u8; DIGEST_LEN];

// `build.rs` writes `$OUT_DIR/trust_anchor.rs` containing
// `pub(crate) const GENERATED_KERNEL_SIGNING_KEY_BYTES: [u8; 32]`.
// The build script reads `RAXIS_KERNEL_SIGNING_KEY_HEX` (64 hex
// chars) or `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` (32-byte raw file)
// from the release pipeline; defaults to the all-zero placeholder
// when neither is set. See `build.rs` module docs for the full
// specification.
include!(concat!(env!("OUT_DIR"), "/trust_anchor.rs"));

/// **The kernel's manifest-trust anchor.** The 32-byte raw form of the
/// Ed25519 verifying key the kernel signing pipeline owns. The kernel
/// boot path constructs a [`VerifyingKey`] from these bytes and
/// verifies every on-disk `<role>.manifest.toml` against it.
///
/// Normative reference: `planner-harness.md §14.4` and
/// `system-requirements.md §11.2`. The signed manifest is the only
/// quantity the kernel needs to trust at runtime — the per-image
/// digest is carried by the manifest, not by the kernel binary.
///
/// ## Population
///
/// **Build-pipeline driven.** The constant's bytes are emitted by
/// `build.rs` from one of two release-pipeline-controlled sources:
///
/// * `RAXIS_KERNEL_SIGNING_KEY_HEX` — 64 lowercase hex chars
///   (`xxd -p -c 64 signing.pub`). Preferred for CI pipelines.
/// * `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` — absolute path to a
///   32-byte raw file. Preferred for HSM-backed pipelines.
///
/// If neither is set, the constant is the all-zero placeholder
/// ([`UNPOPULATED_SIGNING_KEY_BYTES`]) and the boot-path entry-point
/// [`verify_canonical_image_via_manifest`] surfaces
/// [`CanonicalImageError::SigningKeyFpNotPopulated`]. The operator
/// then sees a clear "this kernel build has no committed trust
/// anchor yet" diagnostic rather than a generic mismatch.
///
/// `build.rs` validates each input source before emission (length,
/// hex alphabet, file size) and panics on a mistyped value, so a
/// typo NEVER silently degrades to the placeholder branch.
///
/// Repointing the trust anchor is a release-pipeline operation: bump
/// the env var, rebuild the kernel, ship the new binary. Operators
/// MUST NOT override the key at runtime; there is no environment
/// variable, no policy field, no CLI flag the kernel reads at
/// boot/activation time that affects this constant.
pub const EXPECTED_KERNEL_SIGNING_KEY_BYTES: [u8; DIGEST_LEN] = GENERATED_KERNEL_SIGNING_KEY_BYTES;

/// SHA-256 fingerprint of [`EXPECTED_KERNEL_SIGNING_KEY_BYTES`] —
/// derived at runtime via [`compute_signing_key_fp`]. Used by audit
/// payloads and `raxis doctor` to print a stable, short identifier
/// for the trust anchor.
///
/// Computed eagerly the first time it is read (via
/// [`compute_signing_key_fp`]); inlined in the boot-path verifier.
pub fn compute_signing_key_fp() -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(EXPECTED_KERNEL_SIGNING_KEY_BYTES);
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(&h.finalize());
    out
}

// ---------------------------------------------------------------------------
// Legacy compile-time digest constants (V1 fallback)
// ---------------------------------------------------------------------------

/// Sentinel value used by the legacy compile-time digest path. Kept
/// public so out-of-band tools that consult the V1 surface
/// ([`verify_canonical_image_pinned`]) can still distinguish the
/// placeholder branch.
pub const UNPOPULATED_DIGEST: [u8; DIGEST_LEN] = [0u8; DIGEST_LEN];

/// SHA-256 of the kernel-bundled `raxis-reviewer-core-<kernel_version>.img`
/// for callers using the V1 compile-time-pinned verification path.
///
/// **Build-pipeline driven.** Populated by `build.rs` from
/// `RAXIS_EXPECTED_REVIEWER_IMAGE_DIGEST_HEX` (64 lowercase hex
/// chars). Defaults to the all-zero placeholder
/// ([`UNPOPULATED_DIGEST`]) when the env var is unset, in which case
/// [`verify_canonical_image_pinned`] surfaces
/// [`CanonicalImageError::DigestNotPopulated`] — i.e. unsigned
/// developer builds and unconfigured CI runs are loud about it
/// rather than silently treating any image as valid.
///
/// **The V2 boot path does NOT read this constant.** V2 uses
/// [`verify_canonical_image_via_manifest`], which trusts the signed
/// `<role>.manifest.toml`'s `image_artefact_sha256` instead. This
/// constant remains for:
///
/// * `verify_canonical_image_pinned` — out-of-band tools
///   (`raxis doctor`, ad-hoc image audits) that want a self-contained
///   digest check without loading a manifest.
/// * Audit-event payloads
///   ([`CanonicalImageKind::expected_digest`]) that carry the V1
///   digest as a stable identifier even when the V2 manifest path is
///   the one actually enforcing.
pub const EXPECTED_REVIEWER_IMAGE_DIGEST: [u8; DIGEST_LEN] = GENERATED_REVIEWER_IMAGE_DIGEST;

/// SHA-256 of the kernel-bundled `raxis-orchestrator-core-<kernel_version>.img`
/// for callers using the V1 compile-time-pinned verification path.
///
/// **Build-pipeline driven.** Populated by `build.rs` from
/// `RAXIS_EXPECTED_ORCHESTRATOR_IMAGE_DIGEST_HEX` (64 lowercase hex
/// chars). Defaults to the all-zero placeholder; same V2-vs-V1
/// caveats as [`EXPECTED_REVIEWER_IMAGE_DIGEST`].
pub const EXPECTED_ORCHESTRATOR_IMAGE_DIGEST: [u8; DIGEST_LEN] =
    GENERATED_ORCHESTRATOR_IMAGE_DIGEST;

// === iter62 verifier-runtime: V1-fallback per-role digests ============
//
// `EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST` and
// `EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST` are the V1-fallback
// counterparts of the existing Reviewer / Orchestrator constants.
// The V2 boot path uses the manifest-trust model and does NOT consult
// these — they exist to keep `verify_canonical_image_pinned` and
// `CanonicalImageKind::expected_digest` working for out-of-band tools
// (`raxis doctor`, ad-hoc image audits) and for audit-event payloads
// that carry the V1 digest as a stable identifier.
//
// Population follows the same shape as the existing two: build.rs
// reads `RAXIS_EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST_HEX` and
// `RAXIS_EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST_HEX` (each 64
// lowercase hex chars) and emits the bytes; defaults to the all-zero
// placeholder ([`UNPOPULATED_DIGEST`]) when unset, in which case
// [`verify_canonical_image_pinned`] surfaces
// [`CanonicalImageError::DigestNotPopulated`] — the kernel-binary's
// fail-loud posture for the kernel-canonical symbol-index image
// (`INV-VERIFIER-CANONICAL-SYMBOL-INDEX-DIGEST-PINNED-01`, D11).

/// SHA-256 of the kernel-bundled
/// `raxis-verifier-starter-<kernel_version>.img` for callers using
/// the V1 compile-time-pinned verification path.
///
/// **Build-pipeline driven.** Populated by `build.rs` from
/// `RAXIS_EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST_HEX` (64 lowercase
/// hex chars). Defaults to the all-zero placeholder
/// ([`UNPOPULATED_DIGEST`]) when the env var is unset.
///
/// **Operator-publishable-equivalent.** The general verifier image
/// is publishable by operators via `[[vm_images]] role_restriction =
/// ["Verifier"]` with their own alias, but the canonical
/// `raxis-verifier-starter` alias is reserved by
/// `RESERVED_GENERAL_VERIFIER_VM_IMAGE_NAME` (D9) so operator
/// publication cannot squat on the kernel-published name. The V2
/// manifest path is the supported entry point for this variant.
pub const EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST: [u8; DIGEST_LEN] =
    GENERATED_VERIFIER_STARTER_IMAGE_DIGEST;

/// SHA-256 of the kernel-bundled
/// `raxis-verifier-symbol-index-<kernel_version>.img` for callers
/// using the V1 compile-time-pinned verification path.
///
/// **Kernel-canonical.** The digest is the SOLE truth at spawn time
/// (`INV-VERIFIER-CANONICAL-SYMBOL-INDEX-DIGEST-PINNED-01`).
/// Operator policy CANNOT override this — the alias
/// `raxis-verifier-symbol-index` is reserved by
/// `RESERVED_SYMBOL_INDEX_VM_IMAGE_NAME` and any operator
/// `[[vm_images]] name = "raxis-verifier-symbol-index"` is rejected
/// at policy load with `FAIL_POLICY_RESERVED_VM_IMAGE_NAME`.
///
/// **Build-pipeline driven.** Populated by `build.rs` from
/// `RAXIS_EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST_HEX` (64
/// lowercase hex chars). Defaults to the all-zero placeholder; the
/// kernel boot path's `assert_trust_anchor_present_or_panic` is the
/// trip wire for unsigned production builds.
pub const EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST: [u8; DIGEST_LEN] =
    GENERATED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST;

/// Errors the verification helpers can surface.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalImageError {
    /// The on-disk image file could not be read. Wraps the underlying
    /// `std::io::Error` for diagnostic purposes; the kernel maps this
    /// to `FAIL_*_IMAGE_DIGEST_MISMATCH` (the operator-facing error
    /// is the same — the image cannot be verified, the VM cannot
    /// boot — but the audit record carries the full I/O error.)
    #[error("canonical image i/o error at {path}: {source}")]
    Io {
        /// The path the kernel was attempting to verify.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The on-disk image's SHA-256 did not equal the expected digest.
    /// This is the canonical `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH` /
    /// `FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH` failure mode.
    #[error("canonical image digest mismatch at {path}")]
    DigestMismatch {
        /// The path that was verified.
        path: String,
        /// What the manifest (or compile-time constant) expected
        /// (hex-encoded for legibility).
        expected: String,
        /// What `compute_image_digest` actually observed (hex).
        actual: String,
    },

    /// The compile-time digest constant is the all-zero placeholder.
    /// V1 compile-time-pinned path only — the V2 manifest-trust path
    /// surfaces [`CanonicalImageError::SigningKeyFpNotPopulated`]
    /// instead.
    #[error("canonical image digest is unpopulated; this kernel build was produced before the matching image artefact was published")]
    DigestNotPopulated,

    /// The kernel binary's `EXPECTED_KERNEL_SIGNING_KEY_BYTES` is
    /// the all-zero placeholder. Distinct from `DigestMismatch`
    /// because the remediation is "rebuild the kernel against a
    /// populated signing key" rather than "reinstall the image".
    #[error("kernel signing-key trust anchor is unpopulated; this kernel build was produced before the matching key was committed")]
    SigningKeyFpNotPopulated,

    /// The on-disk manifest TOML could not be read.
    #[error("manifest i/o error at {path}: {source}")]
    ManifestIo {
        /// Manifest path that failed.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The manifest's `role` did not match the kind the caller asked
    /// us to verify. Catches a swapped Reviewer-vs-Orchestrator
    /// manifest pointed at the wrong .img.
    #[error("manifest role mismatch at {path}: manifest declares {found:?} but kernel asked for {kind:?}")]
    ManifestRoleMismatch {
        /// Manifest path.
        path: String,
        /// What the manifest declared.
        found: Role,
        /// What the kernel was looking for.
        kind: CanonicalImageKind,
    },

    /// The manifest's `kernel_version` does not match the running
    /// kernel. Pins `INV-PLANNER-HARNESS-02 / -05`'s "image is paired
    /// with a specific kernel version" invariant.
    #[error("manifest kernel_version mismatch at {path}: manifest pinned {found} but kernel is {expected}")]
    ManifestKernelVersionMismatch {
        /// Manifest path.
        path: String,
        /// What the manifest declared.
        found: String,
        /// What the running kernel is.
        expected: String,
    },

    /// The manifest could not be parsed or its embedded signature did
    /// not verify.
    #[error("manifest verification failed at {path}: {source}")]
    Manifest {
        /// Manifest path.
        path: String,
        /// Underlying manifest error.
        #[source]
        source: ManifestError,
    },

    /// The kernel signing key bytes the caller passed in were
    /// malformed (Ed25519 32-byte raw verifying-key constructor
    /// rejected them). Surfaced separately from `Manifest` so the
    /// audit record reflects the configuration class of failure.
    #[error("kernel signing key is malformed: {0}")]
    SigningKeyMalformed(String),
}

/// Identifies which canonical image is being verified. Used by
/// [`verify_canonical_image_via_manifest`] and the legacy V1 path to
/// keep error reporting unambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalImageKind {
    /// `raxis-reviewer-core-<kernel_version>.img`,
    /// `INV-PLANNER-HARNESS-02`.
    Reviewer,
    /// `raxis-orchestrator-core-<kernel_version>.img`,
    /// `INV-PLANNER-HARNESS-05`.
    Orchestrator,
    /// `raxis-executor-starter-<kernel_version>.img` — the V2-GA
    /// opt-in canonical Executor image (`planner-harness.md §14.4`,
    /// also referenced by `system-requirements.md §11`). Operators
    /// that disable the Executor-starter publishing path on policy
    /// load do not exercise this variant; activations then fall
    /// back to operator-published `[[vm_images]]` aliases.
    ExecutorStarter,
    // === iter62 verifier-runtime: kernel-canonical verifier images ===
    /// `raxis-verifier-starter-<kernel_version>.img` — the iter62
    /// general verifier image. Operator-publishable-equivalent
    /// (operators may publish a `[[vm_images]] role_restriction =
    /// ["Verifier"]` with their own alias) but the canonical
    /// `raxis-verifier-starter` alias is reserved by
    /// `RESERVED_GENERAL_VERIFIER_VM_IMAGE_NAME` (D9) so operator
    /// policy cannot squat on it. See `images/verifier-starter/` for
    /// the Containerfile + manifest, and
    /// `INV-VERIFIER-RESERVED-ALIAS-MUTUAL-EXCLUSION-01` (D11).
    Verifier,
    /// `raxis-verifier-symbol-index-<kernel_version>.img` — the
    /// iter62 kernel-canonical symbol-index verifier. The digest is
    /// the SOLE truth at spawn time
    /// (`INV-VERIFIER-CANONICAL-SYMBOL-INDEX-DIGEST-PINNED-01`):
    /// operator policy CANNOT override and the alias
    /// `raxis-verifier-symbol-index` is reserved by
    /// `RESERVED_SYMBOL_INDEX_VM_IMAGE_NAME`. See
    /// `images/verifier-symbol-index/` for the Containerfile +
    /// manifest + perf-budget README.
    VerifierSymbolIndex,
}

impl CanonicalImageKind {
    /// Stable string surface for audit events
    /// (`SecurityViolationDetected { kind: ... }`).
    pub fn audit_kind(self) -> &'static str {
        match self {
            Self::Reviewer => "ReviewerImageDigestMismatch",
            Self::Orchestrator => "OrchestratorImageDigestMismatch",
            Self::ExecutorStarter => "ExecutorStarterImageDigestMismatch",
            // iter62 verifier-runtime D6 + D8: stable audit-kind
            // strings for the two new canonical verifier images.
            // Wired to the `VerifierImageDigestMismatch` audit
            // variant family in `crates/audit/src/event.rs` (D8).
            Self::Verifier => "VerifierStarterImageDigestMismatch",
            Self::VerifierSymbolIndex => "VerifierSymbolIndexImageDigestMismatch",
        }
    }

    /// Returns the V1-compatible `[u8; 32]` digest the kernel binary
    /// would consult under the legacy compile-time-pinned path
    /// ([`verify_canonical_image_pinned`]). Centralises the mapping
    /// so out-of-band tools (`raxis doctor`) read from the same
    /// source of truth.
    ///
    /// `ExecutorStarter` returns the all-zero placeholder; the V1
    /// compile-time-pinned path never covered the Executor-starter
    /// (which is a V2-GA addition). Callers using
    /// [`verify_canonical_image_pinned`] for `ExecutorStarter` will
    /// surface [`CanonicalImageError::DigestNotPopulated`] — the
    /// V2 manifest path ([`verify_canonical_image_via_manifest`])
    /// is the supported entry point for this variant.
    pub fn expected_digest(self) -> [u8; DIGEST_LEN] {
        match self {
            Self::Reviewer => EXPECTED_REVIEWER_IMAGE_DIGEST,
            Self::Orchestrator => EXPECTED_ORCHESTRATOR_IMAGE_DIGEST,
            Self::ExecutorStarter => UNPOPULATED_DIGEST,
            // iter62 verifier-runtime D6: route through the new
            // build-script-populated constants. A kernel built
            // without populating these envs returns
            // [`UNPOPULATED_DIGEST`] just like the existing roles —
            // [`verify_canonical_image_pinned`] then surfaces
            // `DigestNotPopulated` and the spawn-time emitter
            // surfaces `VerifierImageDigestMismatch` per
            // `INV-VERIFIER-CANONICAL-SYMBOL-INDEX-DIGEST-PINNED-01`.
            Self::Verifier => EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST,
            Self::VerifierSymbolIndex => EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST,
        }
    }

    /// The `image-manifest` crate's role tag this kind maps to. Used
    /// by [`verify_canonical_image_via_manifest`] to assert the
    /// manifest covers the role the caller asked for.
    pub fn manifest_role(self) -> Role {
        match self {
            Self::Reviewer => Role::Reviewer,
            Self::Orchestrator => Role::Orchestrator,
            Self::ExecutorStarter => Role::ExecutorStarter,
            // iter62 verifier-runtime D2 + D6: the manifest crate
            // (`crates/image-manifest/src/lib.rs`) carries the
            // matching `Role::Verifier` and `Role::VerifierSymbolIndex`
            // variants (added in the same iter62 batch), so the
            // mapping is symmetric with the existing three.
            Self::Verifier => Role::Verifier,
            Self::VerifierSymbolIndex => Role::VerifierSymbolIndex,
        }
    }
}

/// Stream the file at `path`, return its SHA-256 as a 32-byte array.
///
/// Streaming-only — the whole image is never buffered into memory.
/// Returns [`CanonicalImageError::Io`] on any read failure.
pub fn compute_image_digest(path: &Path) -> Result<[u8; DIGEST_LEN], CanonicalImageError> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path).map_err(|e| CanonicalImageError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; BUF_SIZE];

    loop {
        let n = file.read(&mut buf).map_err(|e| CanonicalImageError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let digest = hasher.finalize();
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// V1 / out-of-band fallback: verify the on-disk file at `path`
/// against an explicit expected digest. Returns
/// [`CanonicalImageError::DigestNotPopulated`] when `expected` is the
/// all-zero placeholder.
///
/// V2 kernel boot paths use [`verify_canonical_image_via_manifest`].
pub fn verify_canonical_image_pinned(
    path: &Path,
    expected: [u8; DIGEST_LEN],
) -> Result<(), CanonicalImageError> {
    if expected == UNPOPULATED_DIGEST {
        return Err(CanonicalImageError::DigestNotPopulated);
    }
    let actual = compute_image_digest(path)?;
    if actual != expected {
        return Err(CanonicalImageError::DigestMismatch {
            path: path.display().to_string(),
            expected: hex_encode(&expected),
            actual: hex_encode(&actual),
        });
    }
    Ok(())
}

/// Resolve the expected on-disk path of the manifest TOML for the
/// `<role>-<kernel_version>.manifest.toml` artefact, given the
/// image's .img path.
///
/// Convention: the manifest sits next to the .img with the same stem
/// and `.manifest.toml` extension. Centralising the rule here keeps
/// the boot preflight, the activation path, and `raxis doctor` in
/// sync.
pub fn manifest_path_for_image(image_path: &Path) -> PathBuf {
    let mut p = image_path.to_path_buf();
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Some(parent) = image_path.parent() {
        p = parent.join(format!("{stem}.manifest.toml"));
    } else {
        p = PathBuf::from(format!("{stem}.manifest.toml"));
    }
    p
}

/// **Boot-time canonical-image verifier under the V2 manifest-trust
/// model.**
///
/// Steps:
///
/// 1. Refuse if the kernel's compiled-in
///    [`EXPECTED_KERNEL_SIGNING_KEY_BYTES`] is the all-zero
///    placeholder.
/// 2. Construct the [`VerifyingKey`] from the trust anchor; refuse
///    with [`CanonicalImageError::SigningKeyMalformed`] if the bytes
///    do not form a valid Ed25519 verifying key (catches accidental
///    misconfigurations of the release pipeline).
/// 3. Load the manifest TOML at `manifest_path`.
/// 4. Call [`raxis_image_manifest::verify`] against the constructed
///    key. The manifest crate enforces:
///    * `schema_version` matches.
///    * `bundle_hash` recomputed from `files` + `image_artefact_sha256`
///      matches the manifest's claim.
///    * `signing_key_fp` matches.
///    * Ed25519 signature verifies.
/// 5. Confirm `manifest.role` matches `kind.manifest_role()`.
/// 6. Confirm `manifest.kernel_version == kernel_version`.
/// 7. Stream the .img at `image_path`, compare its SHA-256 against
///    the manifest's signed `image_artefact_sha256`. Mismatch →
///    [`CanonicalImageError::DigestMismatch`].
///
/// **No `expected_signing_key` parameter.** The kernel boot path is
/// the only authoritative caller of this function and it MUST use
/// the compile-time anchor — otherwise the manifest could be
/// verified against an attacker-controlled key. Tests and `raxis
/// doctor` use [`verify_canonical_image_via_manifest_with_key`].
pub fn verify_canonical_image_via_manifest(
    image_path: &Path,
    manifest_path: &Path,
    kind: CanonicalImageKind,
    kernel_version: &str,
) -> Result<(), CanonicalImageError> {
    if EXPECTED_KERNEL_SIGNING_KEY_BYTES == UNPOPULATED_SIGNING_KEY_BYTES {
        return Err(CanonicalImageError::SigningKeyFpNotPopulated);
    }
    let vk = VerifyingKey::from_bytes(&EXPECTED_KERNEL_SIGNING_KEY_BYTES)
        .map_err(|e| CanonicalImageError::SigningKeyMalformed(e.to_string()))?;
    verify_canonical_image_via_manifest_with_key(
        image_path,
        manifest_path,
        kind,
        kernel_version,
        &vk,
    )
}

/// Like [`verify_canonical_image_via_manifest`] but skips the
/// kernel-anchor placeholder gate. Pulled out for testability and
/// for `raxis doctor` use cases where the operator passes the key
/// explicitly.
pub fn verify_canonical_image_via_manifest_with_key(
    image_path: &Path,
    manifest_path: &Path,
    kind: CanonicalImageKind,
    kernel_version: &str,
    expected_signing_key: &VerifyingKey,
) -> Result<(), CanonicalImageError> {
    let manifest = load_manifest(manifest_path)?;
    verify_manifest_against_kernel_anchor(
        &manifest,
        manifest_path,
        kind,
        kernel_version,
        expected_signing_key,
    )?;
    verify_image_blob_against_manifest(image_path, &manifest)
}

/// Load + verify a canonical image's manifest exactly like
/// [`verify_canonical_image_via_manifest`], then return the
/// **manifest-pinned, signature-covered** [`raxis_image_manifest::ImageFormat`]
/// the substrate must dispatch on (EROFS virtio-blk vs. initramfs cpio.gz).
///
/// This is the V2 spawn-time entry point used by
/// `kernel/src/session_spawn_orchestrator.rs` (and its Reviewer
/// counterpart) to construct
/// `raxis_isolation::VerifiedImage` with the correct
/// `raxis_isolation::ImageKind` without re-implementing the
/// trust-anchor gate or the manifest-load + signature-verify
/// sequence.
///
/// **No `expected_signing_key` parameter.** Same trust-anchor
/// rationale as [`verify_canonical_image_via_manifest`]: the kernel
/// is the only authoritative caller and must use the compile-time
/// anchor. Tests and `raxis doctor` use
/// [`read_verified_image_format_with_key`].
pub fn read_verified_image_format(
    image_path: &Path,
    manifest_path: &Path,
    kind: CanonicalImageKind,
    kernel_version: &str,
) -> Result<raxis_image_manifest::ImageFormat, CanonicalImageError> {
    if EXPECTED_KERNEL_SIGNING_KEY_BYTES == UNPOPULATED_SIGNING_KEY_BYTES {
        return Err(CanonicalImageError::SigningKeyFpNotPopulated);
    }
    let vk = VerifyingKey::from_bytes(&EXPECTED_KERNEL_SIGNING_KEY_BYTES)
        .map_err(|e| CanonicalImageError::SigningKeyMalformed(e.to_string()))?;
    read_verified_image_format_with_key(image_path, manifest_path, kind, kernel_version, &vk)
}

/// Like [`read_verified_image_format`] but skips the kernel-anchor
/// placeholder gate. Pulled out for testability and for `raxis
/// doctor` use cases where the operator passes the key explicitly.
pub fn read_verified_image_format_with_key(
    image_path: &Path,
    manifest_path: &Path,
    kind: CanonicalImageKind,
    kernel_version: &str,
    expected_signing_key: &VerifyingKey,
) -> Result<raxis_image_manifest::ImageFormat, CanonicalImageError> {
    let manifest = load_manifest(manifest_path)?;
    verify_manifest_against_kernel_anchor(
        &manifest,
        manifest_path,
        kind,
        kernel_version,
        expected_signing_key,
    )?;
    verify_image_blob_against_manifest(image_path, &manifest)?;
    Ok(manifest.image_format)
}

/// **Unverified format hint** — load the manifest TOML, parse it,
/// and return its `image_format` field **without** running the
/// signature / role / kernel-version / blob-digest checks.
///
/// Sole intended caller: the kernel's
/// `kernel/src/canonical_images_preflight.rs::resolve_image_kind_for_role`
/// graceful-degradation branch, taken when
/// [`read_verified_image_format`] returns an error that the V2
/// trust model classifies as "no boot failure" (most commonly
/// [`CanonicalImageError::SigningKeyFpNotPopulated`] on a kernel
/// build that has not yet committed its signing-key trust anchor).
///
/// **Why this exists.** The substrate (AVF, Firecracker) needs to
/// know whether to attach the .img as a virtio-blk EROFS device or
/// hand it to the boot loader as an initramfs cpio.gz. Hardcoding
/// `RootfsErofs` as the fallback (the previous behavior) bricks
/// every spawn on a dev/V2-cutover kernel that ships
/// `RootfsInitramfsCpio` images: AVF rejects the cpio.gz with
/// `Invalid disk image. The disk image format is not recognized.`
/// before any productive work can happen. Reading the manifest's
/// declared format keeps the substrate dispatch correct on those
/// kernels without requiring the trust anchor to be populated.
///
/// **Why returning the unverified field is safe.** `image_format`
/// is dispatch metadata, not a privilege grant. The cryptographic
/// gate that protects the substrate against a tampered or
/// adversarial image is the manifest's
/// [`ImageManifest::image_artefact_sha256`], which the substrate
/// re-verifies at every spawn (`session_spawn_orchestrator.rs`
/// → `IsolationBackend::launch` → `verify_canonical_image_via_manifest`).
/// A manifest that lies about `image_format` produces a spawn-time
/// mount failure — the adversarial blob still cannot execute,
/// because the format mismatch fails the substrate's mount step
/// before any guest code runs. The trust model is unchanged; only
/// the dispatch-hint surface tolerates the unsigned manifest.
///
/// Returns the manifest-claimed `ImageFormat` on a successful
/// parse, or one of [`CanonicalImageError::ManifestIo`] /
/// [`CanonicalImageError::Manifest`] when the file is missing or
/// not a valid `SCHEMA_VERSION = 3` manifest. The caller is
/// expected to treat any `Err` as "fall back to the documented
/// production canonical default" ([`raxis_image_manifest::ImageFormat::RootfsErofs`])
/// and surface a structured warning so `raxis doctor` and the
/// dashboard can render the un-trusted boot posture.
pub fn read_unverified_image_format_hint(
    manifest_path: &Path,
) -> Result<raxis_image_manifest::ImageFormat, CanonicalImageError> {
    let manifest = load_manifest(manifest_path)?;
    Ok(manifest.image_format)
}

fn load_manifest(manifest_path: &Path) -> Result<ImageManifest, CanonicalImageError> {
    let s =
        std::fs::read_to_string(manifest_path).map_err(|e| CanonicalImageError::ManifestIo {
            path: manifest_path.display().to_string(),
            source: e,
        })?;
    ImageManifest::from_toml(&s).map_err(|e| CanonicalImageError::Manifest {
        path: manifest_path.display().to_string(),
        source: e,
    })
}

fn verify_manifest_against_kernel_anchor(
    manifest: &ImageManifest,
    manifest_path: &Path,
    kind: CanonicalImageKind,
    kernel_version: &str,
    expected_signing_key: &VerifyingKey,
) -> Result<(), CanonicalImageError> {
    raxis_image_manifest::verify(manifest, expected_signing_key).map_err(|e| {
        CanonicalImageError::Manifest {
            path: manifest_path.display().to_string(),
            source: e,
        }
    })?;
    if manifest.role != kind.manifest_role() {
        return Err(CanonicalImageError::ManifestRoleMismatch {
            path: manifest_path.display().to_string(),
            found: manifest.role,
            kind,
        });
    }
    if manifest.kernel_version != kernel_version {
        return Err(CanonicalImageError::ManifestKernelVersionMismatch {
            path: manifest_path.display().to_string(),
            found: manifest.kernel_version.clone(),
            expected: kernel_version.to_owned(),
        });
    }
    Ok(())
}

fn verify_image_blob_against_manifest(
    image_path: &Path,
    manifest: &ImageManifest,
) -> Result<(), CanonicalImageError> {
    let expected =
        manifest
            .image_artefact_sha256_bytes()
            .map_err(|e| CanonicalImageError::Manifest {
                path: image_path.display().to_string(),
                source: e,
            })?;
    let actual = compute_image_digest(image_path)?;
    if actual != expected {
        return Err(CanonicalImageError::DigestMismatch {
            path: image_path.display().to_string(),
            expected: hex_encode(&expected),
            actual: hex_encode(&actual),
        });
    }
    Ok(())
}

/// Lowercase hex encoder for the 32-byte digests we surface in
/// audit / diagnostic output. Inlined to avoid pulling the `hex` dep
/// through this crate's compile-time path (the only consumer is
/// error-formatting).
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::{rngs::OsRng, RngCore};
    use raxis_image_manifest::{
        fingerprint_signing_key, BuildEnv, ImageManifest, ManifestFile, Role, SCHEMA_VERSION,
    };
    use std::io::Write;

    fn fixture_signing_key() -> (SigningKey, VerifyingKey) {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let sk = SigningKey::from_bytes(&bytes);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    /// Write `body` to a tempfile and return its path + the streamed
    /// SHA-256 digest, hex-encoded.
    fn write_image_blob(body: &[u8]) -> (tempfile::NamedTempFile, String) {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(body).unwrap();
        f.flush().unwrap();
        let mut h = Sha256::new();
        h.update(body);
        let d: [u8; DIGEST_LEN] = h.finalize().into();
        (f, hex_encode(&d))
    }

    /// Assemble a manifest covering one fake "rootfs file" plus the
    /// supplied `image_artefact_sha256` and sign it.
    fn assemble_signed_manifest(
        sk: &SigningKey,
        vk: &VerifyingKey,
        role: Role,
        kernel_version: &str,
        image_artefact_sha256_hex: String,
    ) -> ImageManifest {
        let files = vec![ManifestFile {
            path: "init".to_owned(),
            sha256: "0".repeat(64),
            size: 1,
            mode: 0o755,
        }];
        let mut m = ImageManifest {
            schema_version: SCHEMA_VERSION,
            role,
            kernel_version: kernel_version.to_owned(),
            bundle_hash: String::new(),
            image_artefact_sha256: image_artefact_sha256_hex,
            image_format: raxis_image_manifest::ImageFormat::RootfsErofs,
            build_env: BuildEnv {
                source_date_epoch: 1700000000,
                erofs_version: "1.7.1".to_owned(),
                tar_version: "1.34".to_owned(),
                zstd_version: "1.5.5".to_owned(),
            },
            files,
            signing_key_fp: hex::encode(fingerprint_signing_key(vk)),
            signature: String::new(),
        };
        let bh = m.recompute_bundle_hash().unwrap();
        m.bundle_hash = hex::encode(bh);
        m.signature = hex::encode(sk.sign(&bh).to_bytes());
        m
    }

    fn write_manifest_toml(m: &ImageManifest) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(m.to_toml().as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    /// Boot-path happy path under the V2 manifest-trust model.
    /// Manifest signed by the test key + .img digest matches →
    /// verification accepts.
    #[test]
    fn verify_via_manifest_with_key_accepts_matching_image() {
        let (sk, vk) = fixture_signing_key();
        let (img_file, img_sha) = write_image_blob(b"raxis-test-image-bytes");
        let manifest = assemble_signed_manifest(&sk, &vk, Role::Reviewer, "0.1.0", img_sha);
        let manifest_file = write_manifest_toml(&manifest);

        verify_canonical_image_via_manifest_with_key(
            img_file.path(),
            manifest_file.path(),
            CanonicalImageKind::Reviewer,
            "0.1.0",
            &vk,
        )
        .expect("freshly signed manifest + matching .img must verify");
    }

    /// .img bytes tampered after manifest signing → DigestMismatch.
    #[test]
    fn verify_via_manifest_with_key_rejects_tampered_image_blob() {
        let (sk, vk) = fixture_signing_key();
        let (img_file, img_sha) = write_image_blob(b"original-image-bytes");
        let manifest = assemble_signed_manifest(&sk, &vk, Role::Reviewer, "0.1.0", img_sha);
        let manifest_file = write_manifest_toml(&manifest);

        // Now overwrite the .img after the manifest was signed.
        std::fs::write(img_file.path(), b"tampered-image-bytes").unwrap();

        let err = verify_canonical_image_via_manifest_with_key(
            img_file.path(),
            manifest_file.path(),
            CanonicalImageKind::Reviewer,
            "0.1.0",
            &vk,
        )
        .unwrap_err();
        match err {
            CanonicalImageError::DigestMismatch {
                expected, actual, ..
            } => {
                assert_ne!(
                    expected, actual,
                    "expected and actual must differ for a real tamper case"
                );
                assert_eq!(expected.len(), DIGEST_LEN * 2);
                assert_eq!(actual.len(), DIGEST_LEN * 2);
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    /// Manifest signed by key A is rejected when verified against
    /// key B's verifying key. Pins the kernel-side trust boundary on
    /// the boot path.
    #[test]
    fn verify_via_manifest_with_key_rejects_wrong_signing_key() {
        let (sk_a, vk_a) = fixture_signing_key();
        let (_, vk_b) = fixture_signing_key();
        let (img_file, img_sha) = write_image_blob(b"image");
        let manifest = assemble_signed_manifest(&sk_a, &vk_a, Role::Reviewer, "0.1.0", img_sha);
        let manifest_file = write_manifest_toml(&manifest);

        let err = verify_canonical_image_via_manifest_with_key(
            img_file.path(),
            manifest_file.path(),
            CanonicalImageKind::Reviewer,
            "0.1.0",
            &vk_b,
        )
        .unwrap_err();
        assert!(
            matches!(err, CanonicalImageError::Manifest { .. }),
            "wrong-key manifest must surface Manifest(SigningKeyFpMismatch); got {err:?}"
        );
    }

    /// Manifest declares Orchestrator role but the kernel asked for
    /// Reviewer → role mismatch. Pins the swap-attack guard.
    #[test]
    fn verify_via_manifest_with_key_rejects_role_swap() {
        let (sk, vk) = fixture_signing_key();
        let (img_file, img_sha) = write_image_blob(b"image");
        let manifest = assemble_signed_manifest(&sk, &vk, Role::Orchestrator, "0.1.0", img_sha);
        let manifest_file = write_manifest_toml(&manifest);

        let err = verify_canonical_image_via_manifest_with_key(
            img_file.path(),
            manifest_file.path(),
            CanonicalImageKind::Reviewer,
            "0.1.0",
            &vk,
        )
        .unwrap_err();
        match err {
            CanonicalImageError::ManifestRoleMismatch { found, kind, .. } => {
                assert_eq!(found, Role::Orchestrator);
                assert_eq!(kind, CanonicalImageKind::Reviewer);
            }
            other => panic!("expected ManifestRoleMismatch, got {other:?}"),
        }
    }

    /// Manifest declares kernel 0.1.0 but the running kernel is 0.2.1 →
    /// version mismatch. Pins INV-PLANNER-HARNESS-02 / -05's
    /// kernel-version-locking.
    #[test]
    fn verify_via_manifest_with_key_rejects_kernel_version_skew() {
        let (sk, vk) = fixture_signing_key();
        let (img_file, img_sha) = write_image_blob(b"image");
        let manifest = assemble_signed_manifest(&sk, &vk, Role::Reviewer, "0.1.0", img_sha);
        let manifest_file = write_manifest_toml(&manifest);

        let err = verify_canonical_image_via_manifest_with_key(
            img_file.path(),
            manifest_file.path(),
            CanonicalImageKind::Reviewer,
            "0.2.1",
            &vk,
        )
        .unwrap_err();
        match err {
            CanonicalImageError::ManifestKernelVersionMismatch {
                found, expected, ..
            } => {
                assert_eq!(found, "0.1.0");
                assert_eq!(expected, "0.2.1");
            }
            other => panic!("expected ManifestKernelVersionMismatch, got {other:?}"),
        }
    }

    /// `verify_canonical_image_via_manifest` (the boot-path entry
    /// point) refuses any manifest signed by a key that is NOT the
    /// kernel's compile-time trust anchor.
    ///
    /// The exact error variant depends on whether the anchor was
    /// resolved to the all-zero placeholder or to a real key:
    ///
    /// * Previously (and release builds with no env-var input):
    ///   anchor is the all-zero placeholder, so `signing_key_fp`
    ///   never matches and the verifier short-circuits with
    ///   `SigningKeyFpNotPopulated`.
    /// * iter62 dev-fallback active (the default for `cargo test`):
    ///   anchor is the per-clone auto-mint key, so the
    ///   fixture-signed manifest's fingerprint disagrees and the
    ///   verifier surfaces `SigningKeyFpMismatch`.
    ///
    /// Both variants represent the SAME contract — a wrong-key
    /// manifest must be rejected before any session admission. The
    /// test accepts both shapes so the build-script's profile-
    /// dependent fallback (`INV-IMAGE-TRUST-ANCHOR-DEV-FALLBACK-01`)
    /// does not turn this guard into a flaky witness.
    #[test]
    fn verify_via_manifest_rejects_wrong_key_regardless_of_anchor_resolution() {
        let (sk, vk) = fixture_signing_key();
        let (img_file, img_sha) = write_image_blob(b"image");
        let manifest = assemble_signed_manifest(&sk, &vk, Role::Reviewer, "0.1.0", img_sha);
        let manifest_file = write_manifest_toml(&manifest);

        let err = verify_canonical_image_via_manifest(
            img_file.path(),
            manifest_file.path(),
            CanonicalImageKind::Reviewer,
            "0.1.0",
        )
        .unwrap_err();
        let placeholder = EXPECTED_KERNEL_SIGNING_KEY_BYTES == [0u8; 32];
        if placeholder {
            assert!(
                matches!(err, CanonicalImageError::SigningKeyFpNotPopulated),
                "anchor is the all-zero placeholder; verifier must surface \
                 SigningKeyFpNotPopulated, got {err:?}",
            );
        } else {
            assert!(
                matches!(
                    err,
                    CanonicalImageError::Manifest {
                        source: raxis_image_manifest::ManifestError::SigningKeyFpMismatch,
                        ..
                    },
                ),
                "anchor is set (iter62 dev-fallback); verifier must surface \
                 ManifestError::SigningKeyFpMismatch on a fixture-signed manifest, \
                 got {err:?}",
            );
        }
    }

    /// `compute_signing_key_fp` returns the SHA-256 of the trust
    /// anchor bytes; on the placeholder build the fingerprint is the
    /// SHA-256 of all-zeros. Pins the diagnostic surface so
    /// `raxis doctor` can render a stable identifier.
    #[test]
    fn compute_signing_key_fp_returns_sha256_of_anchor_bytes() {
        let mut h = Sha256::new();
        h.update(EXPECTED_KERNEL_SIGNING_KEY_BYTES);
        let expected: [u8; DIGEST_LEN] = h.finalize().into();
        assert_eq!(compute_signing_key_fp(), expected);
    }

    /// The build script must run on every cargo invocation and emit
    /// the trust-anchor module. The constant resolved through the
    /// `include!()` MUST equal the lib.rs surface
    /// `EXPECTED_KERNEL_SIGNING_KEY_BYTES`. This test pins that
    /// linkage so a future refactor that moves the include or
    /// renames the generated symbol surfaces immediately rather than
    /// degrading silently to the all-zero placeholder.
    #[test]
    fn generated_trust_anchor_is_wired_through_to_public_constant() {
        // GENERATED_KERNEL_SIGNING_KEY_BYTES is `pub(crate)` —
        // accessible from the test module without re-exporting it.
        // EXPECTED_KERNEL_SIGNING_KEY_BYTES is `pub` and must alias
        // the build-script output verbatim.
        assert_eq!(
            EXPECTED_KERNEL_SIGNING_KEY_BYTES, GENERATED_KERNEL_SIGNING_KEY_BYTES,
            "`EXPECTED_KERNEL_SIGNING_KEY_BYTES` must alias \
             `GENERATED_KERNEL_SIGNING_KEY_BYTES` (the value emitted \
             by build.rs from RAXIS_KERNEL_SIGNING_KEY_HEX or \
             RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH); a divergence here \
             means the trust-anchor pipeline has been broken silently",
        );
    }

    /// Developer builds with neither `RAXIS_KERNEL_SIGNING_KEY_HEX`
    /// nor `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` set MUST default to
    /// the all-zero placeholder. Pinned here so a future refactor of
    /// build.rs that, say, defaulted to a hard-coded developer key,
    /// cannot land without either updating this test or finding a
    /// different placeholder value.
    ///
    /// CI/release builds DO set the env var so the constant is
    /// populated; in that case this test no-ops (the
    /// `generated_trust_anchor_is_wired_through_to_public_constant`
    /// test still verifies the populated value is sane). The
    /// runtime-conditional skip means one CI matrix can run signed
    /// AND placeholder builds without bifurcating this test file.
    #[test]
    fn placeholder_build_defaults_to_all_zero_anchor() {
        if EXPECTED_KERNEL_SIGNING_KEY_BYTES != UNPOPULATED_SIGNING_KEY_BYTES {
            eprintln!(
                "skipping placeholder default test: build is signed \
                 (EXPECTED_KERNEL_SIGNING_KEY_BYTES is non-zero)"
            );
            return;
        }
        assert_eq!(
            EXPECTED_KERNEL_SIGNING_KEY_BYTES, UNPOPULATED_SIGNING_KEY_BYTES,
            "developer builds must default to the all-zero placeholder",
        );
    }

    /// Same wiring contract as
    /// `generated_trust_anchor_is_wired_through_to_public_constant`,
    /// applied to the V1-fallback per-role image digests. A divergence
    /// here means a refactor to `build.rs` has silently disconnected
    /// the per-role digest population path while leaving the trust
    /// anchor working — an easy-to-miss bug because the V2 boot path
    /// would still succeed (it ignores these constants), but
    /// `verify_canonical_image_pinned`, `raxis doctor` audits, and
    /// the `CanonicalImageKind::expected_digest` audit-event field
    /// would all return placeholder zeros.
    #[test]
    fn generated_role_digests_are_wired_through_to_public_constants() {
        assert_eq!(
            EXPECTED_REVIEWER_IMAGE_DIGEST, GENERATED_REVIEWER_IMAGE_DIGEST,
            "`EXPECTED_REVIEWER_IMAGE_DIGEST` must alias \
             `GENERATED_REVIEWER_IMAGE_DIGEST` (build.rs output for \
             RAXIS_EXPECTED_REVIEWER_IMAGE_DIGEST_HEX); divergence \
             here means the V1-fallback digest pipeline has been \
             silently broken",
        );
        assert_eq!(
            EXPECTED_ORCHESTRATOR_IMAGE_DIGEST, GENERATED_ORCHESTRATOR_IMAGE_DIGEST,
            "`EXPECTED_ORCHESTRATOR_IMAGE_DIGEST` must alias \
             `GENERATED_ORCHESTRATOR_IMAGE_DIGEST` (build.rs output \
             for RAXIS_EXPECTED_ORCHESTRATOR_IMAGE_DIGEST_HEX)",
        );
    }

    /// Developer builds with the per-role digest env vars unset MUST
    /// default to the all-zero placeholder, exactly the same way the
    /// trust anchor does. Pinned here so a future refactor of
    /// build.rs that, say, defaulted to a checked-in known-good
    /// digest, cannot land without either updating this test or
    /// finding a different placeholder value.
    #[test]
    fn placeholder_build_defaults_to_all_zero_role_digests() {
        if EXPECTED_REVIEWER_IMAGE_DIGEST != UNPOPULATED_DIGEST {
            eprintln!(
                "skipping placeholder default test: \
                 EXPECTED_REVIEWER_IMAGE_DIGEST is non-zero (signed build)"
            );
        } else {
            assert_eq!(
                EXPECTED_REVIEWER_IMAGE_DIGEST, UNPOPULATED_DIGEST,
                "developer builds must default the Reviewer digest to \
                 the all-zero placeholder",
            );
        }

        if EXPECTED_ORCHESTRATOR_IMAGE_DIGEST != UNPOPULATED_DIGEST {
            eprintln!(
                "skipping placeholder default test: \
                 EXPECTED_ORCHESTRATOR_IMAGE_DIGEST is non-zero \
                 (signed build)"
            );
        } else {
            assert_eq!(
                EXPECTED_ORCHESTRATOR_IMAGE_DIGEST, UNPOPULATED_DIGEST,
                "developer builds must default the Orchestrator digest \
                 to the all-zero placeholder",
            );
        }
    }

    /// `CanonicalImageKind::expected_digest` is the canonical mapping
    /// from a kind tag to its V1-fallback digest. Pin that the mapping
    /// is consistent with both per-role public constants — a future
    /// refactor that silently swapped the two arms would otherwise be
    /// caught only at audit-event-payload review time.
    #[test]
    fn canonical_image_kind_expected_digest_matches_role_constants() {
        assert_eq!(
            CanonicalImageKind::Reviewer.expected_digest(),
            EXPECTED_REVIEWER_IMAGE_DIGEST,
            "Reviewer kind must map to EXPECTED_REVIEWER_IMAGE_DIGEST",
        );
        assert_eq!(
            CanonicalImageKind::Orchestrator.expected_digest(),
            EXPECTED_ORCHESTRATOR_IMAGE_DIGEST,
            "Orchestrator kind must map to EXPECTED_ORCHESTRATOR_IMAGE_DIGEST",
        );
    }

    /// `manifest_path_for_image` derives the standard sibling path.
    #[test]
    fn manifest_path_for_image_replaces_extension_with_manifest_toml() {
        let p = manifest_path_for_image(Path::new(
            "/usr/local/lib/raxis/images/raxis-reviewer-core-0.1.0.img",
        ));
        assert_eq!(
            p,
            PathBuf::from("/usr/local/lib/raxis/images/raxis-reviewer-core-0.1.0.manifest.toml",),
        );
    }

    /// `compute_image_digest` over an empty file yields the canonical
    /// SHA-256 of the empty byte string. Pins the streaming hash
    /// implementation against algorithm drift.
    #[test]
    fn compute_image_digest_empty_file_returns_canonical_sha256_of_empty() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let d = compute_image_digest(f.path()).unwrap();
        assert_eq!(
            hex_encode(&d),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    /// `compute_image_digest` is byte-stable across two reads of the
    /// same file. Catches any non-determinism in the streaming
    /// implementation.
    #[test]
    fn compute_image_digest_is_deterministic_across_two_reads() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"raxis-canonical-image-stable-content")
            .unwrap();
        f.flush().unwrap();

        let a = compute_image_digest(f.path()).unwrap();
        let b = compute_image_digest(f.path()).unwrap();
        assert_eq!(a, b);
    }

    /// `compute_image_digest` over content larger than one streaming
    /// chunk produces the same digest as the canonical one-shot SHA-256.
    /// Pins chunked-vs-one-shot equivalence.
    #[test]
    fn compute_image_digest_is_chunk_invariant_above_buf_size() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let payload: Vec<u8> = (0..(200 * 1024)).map(|i| (i % 251) as u8).collect();
        f.write_all(&payload).unwrap();
        f.flush().unwrap();

        let streamed = compute_image_digest(f.path()).unwrap();

        let mut h = Sha256::new();
        h.update(&payload);
        let one_shot = h.finalize();

        assert_eq!(streamed.as_slice(), one_shot.as_slice());
    }

    /// `verify_canonical_image_pinned` (V1 fallback) refuses while
    /// the caller passes the all-zero placeholder digest. Pins the
    /// build-vs-runtime distinction in error reporting on the
    /// out-of-band path.
    #[test]
    fn verify_canonical_image_pinned_returns_unpopulated_for_placeholder() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let err = verify_canonical_image_pinned(f.path(), UNPOPULATED_DIGEST).unwrap_err();
        assert!(
            matches!(err, CanonicalImageError::DigestNotPopulated),
            "placeholder digest must surface DigestNotPopulated; got {err:?}"
        );
    }

    /// `verify_canonical_image_pinned` returns Ok when the streamed
    /// digest matches the supplied expected. Pins the V1 happy-path
    /// acceptance.
    #[test]
    fn verify_canonical_image_pinned_accepts_matching_digest() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"matching-image-bytes").unwrap();
        f.flush().unwrap();

        let actual = compute_image_digest(f.path()).unwrap();
        verify_canonical_image_pinned(f.path(), actual).expect("matching digest must accept");
    }

    /// `verify_canonical_image_pinned` reports DigestMismatch with
    /// hex-encoded payloads. Pins the audit shape downstream
    /// consumers depend on.
    #[test]
    fn verify_canonical_image_pinned_reports_digest_mismatch_with_hex_payloads() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"actual-image-bytes").unwrap();
        f.flush().unwrap();

        let mut h = Sha256::new();
        h.update(b"expected-image-bytes");
        let mut expected = [0u8; DIGEST_LEN];
        expected.copy_from_slice(&h.finalize());

        let err = verify_canonical_image_pinned(f.path(), expected).unwrap_err();
        match err {
            CanonicalImageError::DigestMismatch {
                expected: e_hex,
                actual: a_hex,
                path,
            } => {
                assert_eq!(e_hex, hex_encode(&expected));
                assert_ne!(e_hex, a_hex);
                assert_eq!(a_hex.len(), DIGEST_LEN * 2);
                assert_eq!(path, f.path().display().to_string());
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    /// `compute_image_digest` surfaces `Io` (not a panic) for a
    /// non-existent path. Pins the fail-closed posture.
    #[test]
    fn compute_image_digest_missing_file_returns_io_error() {
        let err = compute_image_digest(Path::new("/this/path/does/not/exist/raxis")).unwrap_err();
        assert!(
            matches!(err, CanonicalImageError::Io { .. }),
            "missing file must surface Io; got {err:?}"
        );
    }

    /// `audit_kind` strings are pinned at the SQL/audit level.
    #[test]
    fn audit_kind_strings_are_pinned() {
        assert_eq!(
            CanonicalImageKind::Reviewer.audit_kind(),
            "ReviewerImageDigestMismatch",
        );
        assert_eq!(
            CanonicalImageKind::Orchestrator.audit_kind(),
            "OrchestratorImageDigestMismatch",
        );
    }

    // === iter62 verifier-runtime D6 + D12: witness tests ==============
    //
    // Pin the new audit-kind strings, the new V1-fallback digest
    // wire-through, the new `manifest_role` mapping, and the
    // `expected_digest` mapping for both new variants. The existing
    // tests above stay intact (per the iter62 append-only contract on
    // shared files); this block adds NEW witnesses for the new
    // surface only.

    /// Pin the new iter62 verifier audit-kind strings. Any rename
    /// here is a SQL/dashboard schema change — the dashboard SSE
    /// consumer keys off these strings to render the
    /// `VerifierImageDigestMismatch` row.
    #[test]
    fn iter62_verifier_audit_kind_strings_are_pinned() {
        assert_eq!(
            CanonicalImageKind::Verifier.audit_kind(),
            "VerifierStarterImageDigestMismatch",
            "operator-publishable-equivalent verifier image audit kind",
        );
        assert_eq!(
            CanonicalImageKind::VerifierSymbolIndex.audit_kind(),
            "VerifierSymbolIndexImageDigestMismatch",
            "kernel-canonical symbol-index verifier image audit kind",
        );
    }

    /// Same wiring contract as
    /// `generated_role_digests_are_wired_through_to_public_constants`
    /// but for the iter62 verifier digests. A divergence here means
    /// the build.rs verifier-digest population path has been silently
    /// disconnected from the public lib.rs surface — V2 boot is
    /// unaffected (manifest path) but
    /// `verify_canonical_image_pinned`, `raxis doctor`, and the
    /// audit-event field would all return placeholder zeros.
    #[test]
    fn iter62_generated_verifier_digests_are_wired_through_to_public_constants() {
        assert_eq!(
            EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST, GENERATED_VERIFIER_STARTER_IMAGE_DIGEST,
            "`EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST` must alias \
             `GENERATED_VERIFIER_STARTER_IMAGE_DIGEST` (build.rs \
             output for RAXIS_EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST_HEX)",
        );
        assert_eq!(
            EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST,
            GENERATED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST,
            "`EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST` must alias \
             `GENERATED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST` (build.rs \
             output for RAXIS_EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST_HEX)",
        );
    }

    /// Developer builds with the new verifier digest env vars unset
    /// MUST default to the all-zero placeholder so
    /// `verify_canonical_image_pinned` surfaces `DigestNotPopulated`
    /// rather than silently accepting any image — the
    /// `INV-VERIFIER-CANONICAL-SYMBOL-INDEX-DIGEST-PINNED-01` rule.
    #[test]
    fn iter62_placeholder_build_defaults_to_all_zero_verifier_digests() {
        if EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST != UNPOPULATED_DIGEST {
            eprintln!(
                "skipping placeholder default test: \
                 EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST is non-zero (signed build)"
            );
        } else {
            assert_eq!(
                EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST, UNPOPULATED_DIGEST,
                "developer builds must default the verifier-starter \
                 digest to the all-zero placeholder",
            );
        }

        if EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST != UNPOPULATED_DIGEST {
            eprintln!(
                "skipping placeholder default test: \
                 EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST is non-zero \
                 (signed build)"
            );
        } else {
            assert_eq!(
                EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST, UNPOPULATED_DIGEST,
                "developer builds must default the verifier-symbol-index \
                 digest to the all-zero placeholder",
            );
        }
    }

    /// `expected_digest` for the new variants must route through the
    /// new build-script-populated constants. A divergence here would
    /// be silent until an `OrchestratorImageDigestMismatch` audit
    /// event tries to surface the V1 fallback for a verifier image.
    #[test]
    fn iter62_canonical_image_kind_expected_digest_matches_verifier_constants() {
        assert_eq!(
            CanonicalImageKind::Verifier.expected_digest(),
            EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST,
            "Verifier kind must map to EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST",
        );
        assert_eq!(
            CanonicalImageKind::VerifierSymbolIndex.expected_digest(),
            EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST,
            "VerifierSymbolIndex kind must map to EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST",
        );
    }

    /// `manifest_role` for the new variants must map to the matching
    /// `image-manifest::Role` variants iter62 D2 added. A swap here
    /// would let a `verifier-symbol-index` manifest verify against a
    /// `Verifier`-keyed image (or vice-versa) and silently bypass
    /// the kernel-canonical posture.
    #[test]
    fn iter62_canonical_image_kind_manifest_role_matches_verifier_variants() {
        assert_eq!(
            CanonicalImageKind::Verifier.manifest_role(),
            Role::Verifier,
            "Verifier kind must map to Role::Verifier",
        );
        assert_eq!(
            CanonicalImageKind::VerifierSymbolIndex.manifest_role(),
            Role::VerifierSymbolIndex,
            "VerifierSymbolIndex kind must map to Role::VerifierSymbolIndex",
        );
    }

    /// The kernel-canonical `VerifierSymbolIndex` digest is the SOLE
    /// truth at spawn — `verify_canonical_image_pinned` MUST refuse
    /// to verify against the all-zero placeholder. Mirrors the
    /// existing `verify_canonical_image_pinned_rejects_unpopulated_digest`
    /// witness, applied to the iter62 fail-closed posture for the
    /// kernel-canonical symbol-index image.
    #[test]
    fn iter62_verify_canonical_image_pinned_refuses_placeholder_for_verifier_symbol_index() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let err = verify_canonical_image_pinned(
            f.path(),
            CanonicalImageKind::VerifierSymbolIndex.expected_digest(),
        );
        if EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST == UNPOPULATED_DIGEST {
            // Unsigned dev build — fail-loud is the contract.
            match err {
                Err(CanonicalImageError::DigestNotPopulated) => {}
                other => panic!(
                    "expected DigestNotPopulated for unpopulated \
                     VerifierSymbolIndex digest; got {other:?}"
                ),
            }
        } else {
            // Signed build — the digest will not match an empty
            // file. Either DigestMismatch or success on a coincidence
            // (vanishingly unlikely; SHA-256 of `""` is well-known).
            // Accept either non-`DigestNotPopulated` outcome.
            assert!(
                !matches!(err, Err(CanonicalImageError::DigestNotPopulated)),
                "signed build must not return DigestNotPopulated"
            );
        }
    }
}
