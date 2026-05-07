//! Kernel-pinned canonical VM image digests and on-disk verification.
//!
//! Normative references:
//!
//! * `planner-harness.md §4.5` / `INV-PLANNER-HARNESS-02` — Reviewer
//!   image is kernel-canonical; the kernel binary carries
//!   `EXPECTED_REVIEWER_IMAGE_DIGEST: [u8; 32]` and refuses to boot
//!   the Reviewer VM with `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH` on any
//!   on-disk digest mismatch.
//! * `planner-harness.md §4.7` / `INV-PLANNER-HARNESS-05` — Orchestrator
//!   image is kernel-canonical; the kernel binary carries
//!   `EXPECTED_ORCHESTRATOR_IMAGE_DIGEST: [u8; 32]` and refuses to boot
//!   the Orchestrator VM with `FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH`
//!   on any mismatch.
//! * `system-requirements.md §1` and §11 — image distribution layout.
//! * `policy-plan-authority.md §FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH`
//!   and `§FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH` — operator-facing
//!   rejection codes; this crate is the kernel-side enforcement seam.
//!
//! ## What this crate does
//!
//! Exposes two compile-time `[u8; 32]` digest constants and a small
//! verification API. The kernel calls
//! [`verify_reviewer_image`] / [`verify_orchestrator_image`] at every
//! Reviewer / Orchestrator activation; on mismatch it surfaces a
//! [`CanonicalImageError::DigestMismatch`] which the kernel maps to
//! the matching `FAIL_*_IMAGE_DIGEST_MISMATCH` admission code and
//! emits a `SecurityViolationDetected { kind: ... }` audit event.
//!
//! ## Why a separate crate
//!
//! The digest values are kernel-binary-locked: a kernel release
//! ships exactly one Reviewer + one Orchestrator image whose digests
//! the kernel knows. Centralising them here:
//!
//! 1. Mirrors `raxis-prompts` (which carries `ORCHESTRATOR_NNSP_BYTES`)
//!    — the NNSP and the image are version-locked together with the
//!    kernel binary; both belong in their own kernel-pinned crate so
//!    a single `cargo expand` shows the embedded value in CI.
//! 2. Lets out-of-band tools (`raxis doctor canonical-images`) reach
//!    the constants without dragging the kernel binary into the
//!    dep graph.
//! 3. Cleanly separates the "what digest do we expect" (compile-time
//!    constant) from "how do we verify it against the on-disk image"
//!    (the streaming SHA-256 in [`compute_image_digest`]).
//!
//! ## Constant population
//!
//! The two digests below are populated at kernel build time once the
//! corresponding canonical image artefact is published. Until the
//! `raxis-image-builder` crate (`planner-harness.md §10.4 / §10.5`)
//! lands and produces a stable artefact, both constants ship as the
//! all-zero placeholder (`[0u8; 32]`). The verification helpers
//! detect the placeholder and surface
//! [`CanonicalImageError::DigestNotPopulated`] so callers can
//! distinguish "the image is on disk but tampered" from "this build
//! of the kernel does not yet have a canonical digest pinned".
//!
//! When the canonical images land, the constants will be replaced
//! with the published 32-byte SHA-256 of each image; that is a
//! single-line edit per constant, and it is the **only** legal way
//! to repoint them. Operators MUST NOT override the digests at
//! runtime; there is no environment variable, no policy field, and
//! no CLI flag that does so.
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

use sha2::{Digest, Sha256};
use std::path::Path;

/// Length of a SHA-256 digest in bytes. Public so callers that
/// surface the value (e.g. audit-event payloads, `raxis doctor`
/// output) do not redefine the magic number.
pub const DIGEST_LEN: usize = 32;

/// Streaming-read buffer used by [`compute_image_digest`]. 64 KiB
/// matches the page-cache stride of every modern filesystem we
/// target (APFS, ext4, btrfs, zfs) and keeps the verification step's
/// peak memory at a single page-cache-friendly chunk.
const BUF_SIZE: usize = 64 * 1024;

/// Sentinel value published by the kernel build until the matching
/// canonical image artefact lands. The verification helpers refuse
/// to accept this value as a real digest match — see
/// [`CanonicalImageError::DigestNotPopulated`].
pub const UNPOPULATED_DIGEST: [u8; DIGEST_LEN] = [0u8; DIGEST_LEN];

/// SHA-256 of the kernel-bundled `raxis-reviewer-core-<kernel_version>.img`.
///
/// Normative reference: `planner-harness.md §4.5` /
/// `INV-PLANNER-HARNESS-02`. At every Reviewer-task activation, the
/// kernel re-computes the SHA-256 of the on-disk image and refuses
/// to boot the VM with `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH` on any
/// mismatch.
///
/// **Currently unpopulated.** Until the `raxis-image-builder` crate
/// (`planner-harness.md §10.4`) produces a stable Reviewer image
/// artefact and CI captures its SHA-256, this constant is the
/// all-zero placeholder. Verification helpers detect the placeholder
/// and surface [`CanonicalImageError::DigestNotPopulated`] so
/// callers can distinguish "the image is on disk but tampered" from
/// "this build of the kernel does not yet have a digest pinned".
pub const EXPECTED_REVIEWER_IMAGE_DIGEST: [u8; DIGEST_LEN] = UNPOPULATED_DIGEST;

/// SHA-256 of the kernel-bundled `raxis-orchestrator-core-<kernel_version>.img`.
///
/// Normative reference: `planner-harness.md §4.7` /
/// `INV-PLANNER-HARNESS-05`. At every Orchestrator activation
/// (one per initiative), the kernel re-computes the SHA-256 of the
/// on-disk image and refuses to boot the VM with
/// `FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH` on any mismatch.
///
/// **Currently unpopulated.** Same caveat as
/// [`EXPECTED_REVIEWER_IMAGE_DIGEST`]: the all-zero placeholder ships
/// until `raxis-image-builder` (`planner-harness.md §10.5`) produces
/// the Orchestrator image artefact.
pub const EXPECTED_ORCHESTRATOR_IMAGE_DIGEST: [u8; DIGEST_LEN] = UNPOPULATED_DIGEST;

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
        path:   String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The on-disk image's SHA-256 did not equal the kernel's
    /// compiled-in expected digest. This is the canonical
    /// `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH` /
    /// `FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH` failure mode.
    #[error("canonical image digest mismatch at {path}")]
    DigestMismatch {
        /// The path that was verified.
        path:     String,
        /// What the kernel binary expects (hex-encoded for legibility).
        expected: String,
        /// What `compute_image_digest` actually observed (hex).
        actual:   String,
    },

    /// The compile-time digest constant is the all-zero
    /// placeholder. Distinct from `DigestMismatch` because the
    /// remediation is "rebuild the kernel against a populated
    /// digest" rather than "reinstall the image".
    #[error("canonical image digest is unpopulated; this kernel build was produced before the matching image artefact was published")]
    DigestNotPopulated,
}

/// Identifies which canonical image is being verified. Used by
/// [`verify_canonical_image`] to keep error reporting unambiguous
/// when an embedder calls the generic helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalImageKind {
    /// `raxis-reviewer-core-<kernel_version>.img`,
    /// `INV-PLANNER-HARNESS-02`.
    Reviewer,
    /// `raxis-orchestrator-core-<kernel_version>.img`,
    /// `INV-PLANNER-HARNESS-05`.
    Orchestrator,
}

impl CanonicalImageKind {
    /// Stable string surface for audit events
    /// (`SecurityViolationDetected { kind: ... }`).
    pub fn audit_kind(self) -> &'static str {
        match self {
            Self::Reviewer     => "ReviewerImageDigestMismatch",
            Self::Orchestrator => "OrchestratorImageDigestMismatch",
        }
    }

    /// Returns the `[u8; 32]` digest the kernel expects for this
    /// image kind. Centralises the mapping so the verifier and any
    /// out-of-band diagnostic tool (e.g. `raxis doctor`) read from
    /// the same source of truth.
    pub fn expected_digest(self) -> [u8; DIGEST_LEN] {
        match self {
            Self::Reviewer     => EXPECTED_REVIEWER_IMAGE_DIGEST,
            Self::Orchestrator => EXPECTED_ORCHESTRATOR_IMAGE_DIGEST,
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
        path:   path.display().to_string(),
        source: e,
    })?;

    let mut hasher = Sha256::new();
    let mut buf    = vec![0u8; BUF_SIZE];

    loop {
        let n = file.read(&mut buf).map_err(|e| CanonicalImageError::Io {
            path:   path.display().to_string(),
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

/// Verify the on-disk file at `path` against the digest the kernel
/// expects for `kind`. Returns `Ok(())` only if both:
///
/// 1. The kernel's compiled-in digest is populated (not the
///    [`UNPOPULATED_DIGEST`] sentinel) — otherwise we surface
///    [`CanonicalImageError::DigestNotPopulated`] so the caller can
///    bubble up a build-time misconfiguration distinct from the
///    runtime tamper case.
/// 2. The streamed SHA-256 of the on-disk image bytes equals the
///    expected digest exactly — otherwise
///    [`CanonicalImageError::DigestMismatch`].
///
/// This is the canonical `FAIL_*_IMAGE_DIGEST_MISMATCH` enforcement
/// seam: every kernel boot path that would launch a Reviewer or
/// Orchestrator VM goes through this helper before issuing any
/// hypervisor call.
pub fn verify_canonical_image(
    path: &Path,
    kind: CanonicalImageKind,
) -> Result<(), CanonicalImageError> {
    let expected = kind.expected_digest();
    if expected == UNPOPULATED_DIGEST {
        return Err(CanonicalImageError::DigestNotPopulated);
    }

    let actual = compute_image_digest(path)?;
    if actual != expected {
        return Err(CanonicalImageError::DigestMismatch {
            path:     path.display().to_string(),
            expected: hex_encode(&expected),
            actual:   hex_encode(&actual),
        });
    }
    Ok(())
}

/// Convenience wrapper around [`verify_canonical_image`] for the
/// Reviewer image. Pinned to make the call site self-documenting.
pub fn verify_reviewer_image(path: &Path) -> Result<(), CanonicalImageError> {
    verify_canonical_image(path, CanonicalImageKind::Reviewer)
}

/// Convenience wrapper around [`verify_canonical_image`] for the
/// Orchestrator image. Pinned to make the call site
/// self-documenting.
pub fn verify_orchestrator_image(path: &Path) -> Result<(), CanonicalImageError> {
    verify_canonical_image(path, CanonicalImageKind::Orchestrator)
}

/// Lowercase hex encoder for the 32-byte digests we surface in
/// audit / diagnostic output. Inlined to avoid pulling the `hex`
/// dep through this crate (the only consumer is two error paths).
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

    /// `compute_image_digest` over an empty file yields the canonical
    /// SHA-256 of the empty byte string
    /// (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
    /// Pinning this guards against accidental algorithm drift
    /// (e.g. someone swaps in `Sha512::new()` thinking it's a no-op).
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
    /// implementation (e.g. read-buffer aliasing bugs).
    #[test]
    fn compute_image_digest_is_deterministic_across_two_reads() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"raxis-canonical-image-stable-content").unwrap();
        f.flush().unwrap();

        let a = compute_image_digest(f.path()).unwrap();
        let b = compute_image_digest(f.path()).unwrap();
        assert_eq!(a, b);
    }

    /// `compute_image_digest` over content larger than one streaming
    /// chunk (`BUF_SIZE = 64 KiB`) produces the same digest as the
    /// canonical one-shot SHA-256. Pins the chunked-vs-one-shot
    /// equivalence the streaming impl depends on.
    #[test]
    fn compute_image_digest_is_chunk_invariant_above_buf_size() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // 200 KiB of a repeating pattern — well above BUF_SIZE so
        // the streaming loop iterates >1 time.
        let payload: Vec<u8> = (0..(200 * 1024)).map(|i| (i % 251) as u8).collect();
        f.write_all(&payload).unwrap();
        f.flush().unwrap();

        let streamed = compute_image_digest(f.path()).unwrap();

        // Independent one-shot reference.
        let mut h = Sha256::new();
        h.update(&payload);
        let one_shot = h.finalize();

        assert_eq!(streamed.as_slice(), one_shot.as_slice());
    }

    /// `verify_canonical_image` fails with `DigestNotPopulated` while
    /// the kernel ships the all-zero placeholder. Pins the build-vs-
    /// runtime distinction in error reporting.
    #[test]
    fn verify_canonical_image_returns_unpopulated_while_constant_is_placeholder() {
        let f   = tempfile::NamedTempFile::new().unwrap();
        let err = verify_canonical_image(f.path(), CanonicalImageKind::Reviewer).unwrap_err();
        assert!(matches!(err, CanonicalImageError::DigestNotPopulated),
            "while EXPECTED_REVIEWER_IMAGE_DIGEST is the placeholder, \
             verify must surface DigestNotPopulated; got {err:?}");

        let err = verify_canonical_image(f.path(), CanonicalImageKind::Orchestrator).unwrap_err();
        assert!(matches!(err, CanonicalImageError::DigestNotPopulated),
            "same for the Orchestrator image; got {err:?}");
    }

    /// When the constant is populated (we patch it via the test-only
    /// re-implementation `verify_against`), a digest mismatch on a
    /// fixture image surfaces `DigestMismatch` carrying both the
    /// expected and the observed hex digest. Pins the audit payload
    /// shape `SecurityViolationDetected { kind, expected, actual }`
    /// downstream consumers depend on.
    #[test]
    fn verify_against_reports_digest_mismatch_with_expected_and_actual_hex() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"actual-image-bytes").unwrap();
        f.flush().unwrap();

        // Pretend the kernel embeds a digest of `expected-image-bytes`,
        // not the on-disk content. We compute the expected digest
        // independently and feed it to `verify_against`.
        let mut h = Sha256::new();
        h.update(b"expected-image-bytes");
        let mut expected = [0u8; DIGEST_LEN];
        expected.copy_from_slice(&h.finalize());

        let err = verify_against(f.path(), expected).unwrap_err();
        match err {
            CanonicalImageError::DigestMismatch { expected: e_hex, actual: a_hex, path } => {
                assert_eq!(e_hex, hex_encode(&expected));
                assert_ne!(e_hex, a_hex,
                    "expected and actual hex must differ for a real mismatch");
                assert_eq!(a_hex.len(), DIGEST_LEN * 2);
                assert_eq!(path, f.path().display().to_string());
            }
            other => panic!("expected DigestMismatch; got {other:?}"),
        }
    }

    /// Test-only twin of [`verify_canonical_image`] that lets us pass
    /// an arbitrary expected digest, so we can exercise the
    /// mismatch path without mutating the compile-time constants.
    fn verify_against(
        path:     &Path,
        expected: [u8; DIGEST_LEN],
    ) -> Result<(), CanonicalImageError> {
        if expected == UNPOPULATED_DIGEST {
            return Err(CanonicalImageError::DigestNotPopulated);
        }
        let actual = compute_image_digest(path)?;
        if actual != expected {
            return Err(CanonicalImageError::DigestMismatch {
                path:     path.display().to_string(),
                expected: hex_encode(&expected),
                actual:   hex_encode(&actual),
            });
        }
        Ok(())
    }

    /// `verify_against` returns `Ok` when the streamed digest equals
    /// the expected digest. Pins the happy-path acceptance contract.
    #[test]
    fn verify_against_accepts_matching_digest() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let bytes = b"matching-image-bytes";
        f.write_all(bytes).unwrap();
        f.flush().unwrap();

        let actual = compute_image_digest(f.path()).unwrap();
        verify_against(f.path(), actual).expect("matching digest must accept");
    }

    /// The `audit_kind` strings are pinned at the SQL/audit level so
    /// downstream consumers can drift-detect a spec rename.
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

    /// The `expected_digest` accessor returns the same constant as
    /// the public re-export. Guards against accidental drift between
    /// the per-kind dispatcher and the canonical source-of-truth
    /// constants.
    #[test]
    fn expected_digest_accessor_returns_canonical_constants() {
        assert_eq!(
            CanonicalImageKind::Reviewer.expected_digest(),
            EXPECTED_REVIEWER_IMAGE_DIGEST,
        );
        assert_eq!(
            CanonicalImageKind::Orchestrator.expected_digest(),
            EXPECTED_ORCHESTRATOR_IMAGE_DIGEST,
        );
    }

    /// `compute_image_digest` surfaces `Io` (not a panic) for a
    /// non-existent path. Pins the fail-closed posture of the
    /// kernel's enforcement seam.
    #[test]
    fn compute_image_digest_missing_file_returns_io_error() {
        let err = compute_image_digest(Path::new("/this/path/does/not/exist/raxis"))
            .unwrap_err();
        assert!(matches!(err, CanonicalImageError::Io { .. }),
            "missing file must surface Io; got {err:?}");
    }
}
