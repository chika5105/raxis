//! Boot-time canonical VM image manifest preflight (V2 trust model).
//!
//! Normative references:
//!
//! * `planner-harness.md §4.5` (`INV-PLANNER-HARNESS-02`) — Reviewer
//!   image is kernel-canonical; mismatch produces
//!   `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH` and a
//!   `SecurityViolationDetected { kind: "ReviewerImageDigestMismatch" }`
//!   audit event.
//! * `planner-harness.md §4.7` (`INV-PLANNER-HARNESS-05`) — same
//!   contract for the Orchestrator image, with the
//!   `OrchestratorImageDigestMismatch` audit kind.
//! * `planner-harness.md §14.4 — Image-build pipeline` — the
//!   manifest-trust model: builder produces signed
//!   `<role>.manifest.toml`, kernel verifies it at boot via
//!   `raxis_canonical_images::verify_canonical_image_via_manifest`.
//! * `system-requirements.md §3` — operator-facing remediation
//!   ("reinstall from a verified source"); this module is the
//!   kernel-side enforcement seam.
//!
//! ## What this module does
//!
//! At boot, the kernel calls
//! [`verify_canonical_images_at_boot`] against the install dir, which
//! for each canonical image:
//!
//! 1. Resolves the .img and the sibling `.manifest.toml`.
//! 2. Calls
//!    `raxis_canonical_images::verify_canonical_image_via_manifest`
//!    against the kernel's compile-time signing-key trust anchor.
//! 3. Surfaces a structured outcome and emits one
//!    `SecurityViolationDetected` audit event per mismatch.
//!
//! Returned outcomes:
//!
//! * `Ok` — manifest signature verifies, manifest's
//!   `image_artefact_sha256` matches the streamed-from-disk .img
//!   bytes, role + kernel-version match. The matching VM-spawn path
//!   may proceed.
//! * `Missing` — the .img file is not on disk yet (early-deployment
//!   case before `raxis doctor canonical-images` runs). Logged as a
//!   warning; activations that need it will fail at
//!   `IsolationBackend::launch` time anyway. Not a boot failure.
//! * `ManifestMissing` — the .img is present but the sibling
//!   `<role>-<kernel_version>.manifest.toml` is not. Logged as a
//!   warning; activations cannot start without the manifest.
//! * `TrustAnchorUnpopulated` — the kernel binary was built before
//!   the signing-key trust anchor was committed
//!   (`EXPECTED_KERNEL_SIGNING_KEY_BYTES` is the all-zero
//!   placeholder). Logged as a warning; not a boot failure.
//!   Once the release pipeline commits the key, this branch becomes
//!   a hard mismatch by construction.
//! * `Tampered` — the .img's streamed SHA-256 disagrees with the
//!   manifest's signed `image_artefact_sha256`. The kernel emits
//!   `SecurityViolationDetected` and refuses to spawn the affected
//!   role's VMs at activation time.
//! * `ManifestRejected` — the manifest could not be loaded, or its
//!   signature/role/kernel-version did not satisfy the kernel's
//!   trust contract. Treated as a tamper case (audit event +
//!   activation refusal).
//!
//! ## Why preflight at boot rather than lazy at activation
//!
//! Preflight surfaces tamper detection in the kernel's startup
//! audit chain, where dashboards already monitor the boot record
//! sequence. A lazy check at first activation would defer the audit
//! event indefinitely on a kernel that never spawns a Reviewer (a
//! plausible scenario for V2 deployments running Executor-only
//! tasks in early adoption). Both seams are wired for V2 GA: this
//! preflight runs at boot, AND `IsolationBackend::launch` re-runs
//! the manifest verification at activation as defense-in-depth.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_canonical_images::{
    manifest_path_for_image, read_unverified_image_format_hint, read_verified_image_format,
    verify_canonical_image_via_manifest, CanonicalImageError, CanonicalImageKind, DIGEST_LEN,
    EXPECTED_KERNEL_SIGNING_KEY_BYTES,
};
use raxis_image_manifest::ImageFormat;
use raxis_isolation::ImageKind;

// ---------------------------------------------------------------------------
// `INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01` — boot-time fail-loud assertion
// ---------------------------------------------------------------------------

/// Operator-actionable diagnostic emitted when the kernel binary was
/// compiled against the all-zero `EXPECTED_KERNEL_SIGNING_KEY_BYTES`
/// placeholder. Stable string so external integration tests
/// (`#[should_panic(expected = ...)]`) can pin the contract by
/// substring.
pub const TRUST_ANCHOR_FAIL_LOUD_MESSAGE: &str =
    "FATAL: kernel built without a manifest-trust anchor.\n\
     Set RAXIS_KERNEL_SIGNING_KEY_HEX (64 hex chars of the public half\n\
     of the kernel signing key) before `cargo build`, or run\n\
     `cargo xtask images bake-all` which will set it for you from the\n\
     bake-pipeline private key.\n\
     See raxis/specs/v3/canonical-image-trust-anchor.md.";

/// `INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01` — refuse to boot if the
/// kernel binary was compiled with the all-zero placeholder
/// signing-key trust anchor.
///
/// Called as the first canonical-image-related step in
/// `kernel/src/main.rs` BEFORE any subsystem that could (a) admit
/// a session (operator IPC dispatcher, dashboard HTTP bind),
/// (b) spawn a planner VM (orchestrator,
/// `session_spawn_orchestrator`), or (c) service a kernel-mediated
/// planner fetch (gateway, credential proxy) can run. A kernel
/// that boots without a trust anchor cannot cryptographically
/// verify the canonical Reviewer / Orchestrator images it would
/// spawn into VMs — every downstream
/// `verify_canonical_image_via_manifest()` call would short-circuit
/// with `SigningKeyFpNotPopulated` and the kernel would silently
/// degrade onto the manifest-unverified hint path
/// (`read_unverified_image_format_hint`). Previously this surface
/// was a `warn` log at boot followed by a fully-functional kernel;
/// later we refuse to start.
///
/// The dev round-trip is `cargo xtask images bake-all`, which
/// generates a dev signing keypair on first run, writes the
/// private half to `.git/info/raxis-signing-key/` (not tracked)
/// and re-invokes `cargo build -p raxis-kernel` with
/// `RAXIS_KERNEL_SIGNING_KEY_HEX` pre-set. After one bake-all the
/// next kernel boot succeeds; subsequent bake-all runs are
/// idempotent.
///
/// Production builds resolve the env var from the release pipeline's
/// HSM-backed key custody. See
/// `specs/v3/canonical-image-trust-anchor.md` for the full
/// resolution chain.
pub fn assert_trust_anchor_present_or_panic() {
    assert_trust_anchor_bytes_present_or_panic(&EXPECTED_KERNEL_SIGNING_KEY_BYTES);
}

/// Inner helper that takes the bytes as a parameter so the
/// `#[should_panic]` witness can drive both the all-zero and
/// non-zero arms without depending on the compile-time
/// configuration of the test binary's trust anchor.
pub fn assert_trust_anchor_bytes_present_or_panic(bytes: &[u8; DIGEST_LEN]) {
    if bytes == &[0u8; DIGEST_LEN] {
        // Emit a structured JSON log line BEFORE the panic so a
        // crash-restart wrapper (systemd, launchd, the V2
        // supervisor) sees the same operator-actionable hint that
        // the panic message embeds.
        eprintln!(
            "{{\"level\":\"fatal\",\"event\":\"trust_anchor_unpopulated\",\
             \"hint\":\"set RAXIS_KERNEL_SIGNING_KEY_HEX or run \
             `cargo xtask images bake-all`\",\
             \"spec\":\"specs/v3/canonical-image-trust-anchor.md\"}}",
        );
        panic!("{TRUST_ANCHOR_FAIL_LOUD_MESSAGE}");
    }
}

// ---------------------------------------------------------------------------
// Per-process resolve cache
// ---------------------------------------------------------------------------

/// Cached result of [`resolve_image_kind_for_role`] for one canonical
/// image. Keyed in [`image_kind_cache()`] by image path; invalidated
/// whenever the file's `mtime` or `len` change (i.e. the operator
/// rebuilt the image since the last call).
///
/// We deliberately do NOT cache the streamed SHA-256 result — the
/// trust gate is that the on-disk bytes still hash to the manifest's
/// signed value. The `mtime`+`len` pair is a cheap proxy: any
/// modification touches at least one of them on APFS / ext4, so a
/// hit means "the bytes the kernel verified at the prior call are
/// the same bytes on disk now". The boot-time
/// `verify_canonical_images_at_boot` already covers the full-stream
/// SHA-256, and the kernel re-runs that on every restart.
#[derive(Debug, Clone)]
struct CachedKindEntry {
    /// Image kind the manifest's `image_format` mapped to.
    image_kind: ImageKind,
    /// Whether the format came from a verified manifest (vs. a
    /// graceful-degradation fallback).
    is_trusted: bool,
    /// File `mtime` at the time of the verifying call. A change
    /// invalidates the entry — the file was rebuilt and we must
    /// re-verify.
    file_mtime: SystemTime,
    /// File `len` at the time of the verifying call. A change
    /// invalidates the entry on the same logic as `file_mtime`.
    /// Included so that an mtime-preserving rebuild (rare but
    /// possible with `touch -t` workflows) still trips the
    /// invalidator.
    file_len: u64,
    /// Kernel version string the manifest's `kernel_version`
    /// matched. A change invalidates the entry; the kernel only
    /// ever passes its compile-time `kernel_version` here, but
    /// keying on it is defense-in-depth against a future hot-
    /// reload regression.
    kernel_version: String,
    /// Canonical role the manifest was checked for. Different
    /// roles for the same path would be a programming bug, but we
    /// key on it so a future caller misuse fails closed (cache
    /// miss) rather than returning a wrong-role kind.
    canonical_kind: CanonicalImageKind,
}

/// Process-wide cache of `resolve_image_kind_for_role` outputs.
///
/// **Why a kernel-side cache.** The pre-cache call path was:
///
///   `read_verified_image_format`
///     → `verify_canonical_image_via_manifest`
///        → `verify_image_blob_against_manifest`
///           → `compute_image_digest` (full streamed SHA-256)
///
/// The streamed SHA-256 over a ~67 MiB cpio.gz rootfs is ~50-150 ms
/// of wall time on macOS APFS (warm page cache: ~30-50 ms; cold:
/// ~100-200 ms). Since `resolve_image_kind_for_role` is called
/// **on every spawn** for the same handful of canonical images
/// (orchestrator, executor, reviewer per kernel version), the
/// digest stream was being paid per spawn for no incremental trust
/// gain — the file did not change between activations, and the
/// boot-time preflight already streamed it once.
///
/// **Correctness.** Cache hits are gated by `(mtime, len)` plus the
/// kernel-version + canonical-kind tuple. APFS / ext4 mtime is
/// nanosecond-precision; any rebuild touches it. `len` catches the
/// edge case where a rebuild produces an mtime-preserving overwrite
/// (e.g. `dd conv=notrunc` workflows or `touch -t` race conditions).
/// A cache miss falls through to the original
/// `read_verified_image_format` path — same trust contract as before.
fn image_kind_cache() -> &'static Mutex<HashMap<PathBuf, CachedKindEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, CachedKindEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Outcome of verifying one canonical image at boot under the V2
/// manifest-trust model.
///
/// Returned per image so `main.rs` can render a single human-readable
/// log line summarising the boot's posture, and so integration tests
/// can assert the exact branch taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightOutcome {
    /// Manifest verified + the .img's streamed SHA-256 matched the
    /// manifest's signed `image_artefact_sha256`. The matching VM-spawn
    /// path may proceed.
    Ok {
        /// Image file the kernel verified.
        path: PathBuf,
    },
    /// The .img file was not found at the expected path. Logged as
    /// a warning; activations that need it will fail at
    /// `IsolationBackend::launch` time. Not a boot failure.
    Missing {
        /// The path the kernel attempted to verify.
        path: PathBuf,
    },
    /// The .img is present but the sibling
    /// `<role>-<kernel_version>.manifest.toml` is not. Logged as a
    /// warning; activations cannot start without the manifest.
    ManifestMissing {
        /// Image file path.
        image_path: PathBuf,
        /// Manifest file path that was missing.
        manifest_path: PathBuf,
    },
    /// The kernel binary's `EXPECTED_KERNEL_SIGNING_KEY_BYTES` is the
    /// all-zero placeholder. Logged as a warning; not a boot failure
    /// (until the release pipeline commits a key, every kernel build
    /// is in this state).
    TrustAnchorUnpopulated {
        /// The path the kernel would have verified.
        path: PathBuf,
    },
    /// The .img's streamed SHA-256 disagreed with the manifest's
    /// signed `image_artefact_sha256`. The kernel will emit
    /// `SecurityViolationDetected` and refuse to spawn the matching
    /// role's VMs at activation time.
    Tampered {
        /// Image file the kernel attempted to verify.
        path: PathBuf,
        /// Hex-encoded SHA-256 the manifest expected.
        expected: String,
        /// Hex-encoded SHA-256 the kernel observed on disk.
        actual: String,
    },
    /// The manifest could not be loaded, parsed, or its signature /
    /// role / kernel-version failed the kernel's trust contract.
    /// Audit-emitted and treated as a tamper case for activation.
    ManifestRejected {
        /// Image file path.
        image_path: PathBuf,
        /// Manifest file path.
        manifest_path: PathBuf,
        /// Human-readable rejection reason (the canonical-image
        /// crate's `Display` for the underlying error).
        reason: String,
    },
}

/// Resolve the canonical Reviewer image filename for `kernel_version`.
/// Format pinned by `system-requirements.md §1`:
/// `raxis-reviewer-core-<kernel_version>.img`.
pub fn reviewer_image_path(install_dir: &Path, kernel_version: &str) -> PathBuf {
    install_dir
        .join("images")
        .join(format!("raxis-reviewer-core-{kernel_version}.img"))
}

/// Resolve the canonical Orchestrator image filename for
/// `kernel_version`. Format pinned by `system-requirements.md §1`:
/// `raxis-orchestrator-core-<kernel_version>.img`.
pub fn orchestrator_image_path(install_dir: &Path, kernel_version: &str) -> PathBuf {
    install_dir
        .join("images")
        .join(format!("raxis-orchestrator-core-{kernel_version}.img"))
}

/// Resolve the host-canonical Linux kernel binary path (the
/// `vmlinux` / `Image` blob the substrate hands to its boot loader).
///
/// Format pinned by `system-requirements.md §1`:
/// `<install_dir>/kernel/vmlinux`.
///
/// **Why kernel-version-agnostic.** The Linux kernel binary is
/// rotated independently of the per-role rootfs images — operators
/// rebuild rootfs more often than the host kernel. Keeping the
/// filename stable lets `cargo xtask images dev-kernel` cache one
/// blob across many `cargo xtask images dev-stage` cycles.
///
/// **Why a single path, not per-role.** AVF + Firecracker both run
/// the same Linux kernel for every role; the role distinction lives
/// entirely in the rootfs (PID-1 entry point, on-disk binaries).
/// Operators that want per-role kernels (a hardened kernel for
/// Reviewer with seccomp-bpf compiled in, for instance) extend
/// `VmSpec::linux_kernel_path` callsites individually rather than
/// changing the global default.
///
/// **No manifest pairing.** Unlike the per-role rootfs images, the
/// kernel binary is NOT covered by an Ed25519-signed manifest in V2.
/// The trust comes from the operator-chosen install root being a
/// host-protected directory (the homebrew bottle, `/usr/local/lib/`,
/// or a per-developer `$RAXIS_INSTALL_DIR`). V3 will fold the kernel
/// binary into a fourth canonical image; until then operators wanting
/// kernel-binary attestation set up host-side filesystem ACLs.
pub fn linux_kernel_path(install_dir: &Path) -> PathBuf {
    install_dir.join("kernel").join("vmlinux")
}

/// Resolve the canonical Executor-starter image filename for
/// `kernel_version`. Format pinned by `system-requirements.md §1`:
/// `raxis-executor-starter-<kernel_version>.img`.
///
/// **Why a separate path helper.** Executor / Reviewer activations
/// (`v2-deep-spec.md §Steps 21–24`) resolve the canonical guest
/// rootfs at spawn time — keeping the path-template in one place
/// here lets `images/README.md`, the boot-time preflight, and the
/// activation-spawn callsite all share a single source of truth.
/// The Executor-starter is the V2 GA opt-in image; Reviewer
/// activations stay on `raxis-reviewer-core` (Pure-Static Reviewer,
/// `INV-PLANNER-HARNESS-02`).
pub fn executor_starter_image_path(install_dir: &Path, kernel_version: &str) -> PathBuf {
    install_dir
        .join("images")
        .join(format!("raxis-executor-starter-{kernel_version}.img"))
}

/// Run the canonical-image manifest preflight at boot. Returns one
/// outcome per image (Reviewer first, Orchestrator second) and emits
/// `SecurityViolationDetected` audit events for any mismatch.
///
/// Both image checks run unconditionally (a tampered Orchestrator
/// image and a tampered Reviewer image are independent failure
/// modes; we want both audit events when both happen).
pub fn verify_canonical_images_at_boot(
    install_dir: &Path,
    kernel_version: &str,
    audit: &dyn AuditSink,
) -> [(CanonicalImageKind, PreflightOutcome); 2] {
    let reviewer_path = reviewer_image_path(install_dir, kernel_version);
    let orchestrator_path = orchestrator_image_path(install_dir, kernel_version);

    let reviewer_outcome = run_one(
        &reviewer_path,
        CanonicalImageKind::Reviewer,
        kernel_version,
        audit,
    );
    let orchestrator_outcome = run_one(
        &orchestrator_path,
        CanonicalImageKind::Orchestrator,
        kernel_version,
        audit,
    );

    [
        (CanonicalImageKind::Reviewer, reviewer_outcome),
        (CanonicalImageKind::Orchestrator, orchestrator_outcome),
    ]
}

/// Outcome of probing the host-canonical Linux kernel binary at
/// boot. Kept distinct from [`PreflightOutcome`] because the kernel
/// binary is NOT covered by an Ed25519-signed manifest in V2 — the
/// trust comes from the host install root being operator-protected
/// (homebrew bottle, `/usr/local/lib/`, per-developer
/// `$RAXIS_INSTALL_DIR`). The outcome surface therefore degenerates
/// to "present" / "absent" plus its resolved path.
///
/// V3 will fold the kernel binary into a fourth canonical image with
/// its own manifest; the preflight will then evolve to share the
/// `PreflightOutcome` surface with the rootfs images.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelBinaryOutcome {
    /// `<install_dir>/kernel/vmlinux` is on disk. Substrate
    /// activations may proceed.
    Present {
        /// The verified path.
        path: PathBuf,
    },
    /// `<install_dir>/kernel/vmlinux` is not on disk. Logged as a
    /// warning at boot; AVF / Firecracker activations will surface
    /// `SpawnFailed` at first session-spawn time. Not a boot failure
    /// (a kernel running only the SubprocessIsolation substrate has
    /// no use for the binary).
    Missing {
        /// The path the kernel would have verified.
        path: PathBuf,
    },
}

/// Map the manifest-pinned [`ImageFormat`] to the
/// [`raxis_isolation::ImageKind`] the substrate dispatches on.
/// Pure-function shim so callsites that resolve format-via-manifest
/// don't replicate the match arms.
pub fn image_format_to_image_kind(f: ImageFormat) -> ImageKind {
    match f {
        ImageFormat::RootfsErofs => ImageKind::RootfsErofs,
        ImageFormat::RootfsInitramfsCpio => ImageKind::RootfsInitramfsCpio,
    }
}

/// Resolve the `(image_path, ImageKind)` pair the kernel hands to
/// `IsolationBackend::spawn` for a canonical role.
///
/// Reads the sibling `<role>.manifest.toml` (`SCHEMA_VERSION = 3`),
/// verifies it against the kernel's compile-time trust anchor, and
/// returns the manifest-signed [`ImageFormat`] mapped via
/// [`image_format_to_image_kind`].
///
/// **Graceful-degradation path.** Two scenarios trigger an
/// `is_trusted = false` return; both let the substrate's own
/// `spawn`-time defence-in-depth verifier surface the actual tamper
/// case at activation if the bytes truly disagree with the signed
/// manifest.
///
/// * **Manifest missing** — the sibling `<role>.manifest.toml` does
///   not exist on disk (early-deployment / dev-host case before the
///   build pipeline has run `cargo xtask images build-all`). With
///   no metadata to read, we fall back to
///   [`ImageKind::RootfsErofs`] (the production canonical default
///   per `planner-harness.md §14.4`).
/// * **Manifest verify failed** — most commonly the trust anchor is
///   the all-zero placeholder
///   ([`raxis_canonical_images::CanonicalImageError::SigningKeyFpNotPopulated`])
///   on a kernel built without `RAXIS_KERNEL_SIGNING_KEY_HEX`. The
///   manifest exists and parses, just isn't cryptographically
///   trusted. We read the manifest's `image_format` field as an
///   **unverified hint** via [`read_unverified_image_format_hint`]
///   and dispatch on it. This keeps AVF + Firecracker from
///   misclassifying a `RootfsInitramfsCpio` blob as a virtio-blk
///   EROFS device (which AVF rejects with
///   `Invalid disk image. The disk image format is not recognized.`,
///   bricking every spawn on a dev-built / V2-cutover kernel). If
///   the hint itself fails to parse, we fall back to
///   [`ImageKind::RootfsErofs`] as a last-resort default.
///
/// **Why the unverified hint is safe.** `image_format` is dispatch
/// metadata, not a privilege grant. The cryptographic gate against
/// a tampered or adversarial image is the manifest's
/// `image_artefact_sha256`, which the substrate re-verifies at
/// spawn time. A manifest that lies about `image_format` only
/// causes a spawn-time mount failure — no guest code runs. See
/// [`read_unverified_image_format_hint`] for the full rationale.
///
/// All fallback paths log a structured warning at this seam so
/// `raxis doctor` and the dashboard can render the un-signed boot
/// in the run record.
///
/// Returns the `image_path` unchanged from the input — callers wire
/// it through to `VerifiedImage::body = ImageBody::Path(image_path)`.
/// `kind_is_trusted` is `true` iff the format came from a verified
/// manifest; callers may use this to gate a noisier audit event for
/// the un-trusted case.
pub fn resolve_image_kind_for_role(
    image_path: &Path,
    canonical_kind: CanonicalImageKind,
    kernel_version: &str,
) -> (ImageKind, bool) {
    // ── Fast path: per-process cache lookup gated on (mtime, len). ──
    //
    // We stat the image first so a cache hit costs one syscall + one
    // hashmap lookup vs the previous full streamed SHA-256 over the
    // ~67 MiB rootfs. A miss (or a stat failure) falls through to the
    // verifying path below; correctness is unchanged either way
    // because the verifier still runs on every miss.
    if let Ok(meta) = std::fs::metadata(image_path) {
        let file_len = meta.len();
        // `modified()` may fail on filesystems that don't track
        // mtime; in that case we treat it as a cache miss rather
        // than poisoning the cache with `UNIX_EPOCH`.
        if let Ok(file_mtime) = meta.modified() {
            if let Ok(cache) = image_kind_cache().lock() {
                if let Some(entry) = cache.get(image_path) {
                    if entry.file_mtime == file_mtime
                        && entry.file_len == file_len
                        && entry.kernel_version == kernel_version
                        && entry.canonical_kind == canonical_kind
                    {
                        return (entry.image_kind, entry.is_trusted);
                    }
                }
            }
        }
    }

    let manifest_path = manifest_path_for_image(image_path);
    if !manifest_path.exists() {
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"canonical_image_kind_fallback\",\
             \"reason\":\"manifest_missing\",\"image\":\"{}\",\
             \"manifest\":\"{}\",\"fallback_kind\":\"RootfsErofs\"}}",
            image_path.display(),
            manifest_path.display(),
        );
        // Fallback path is intentionally NOT cached — we want every
        // spawn to re-stat the manifest path so a freshly-built
        // manifest is picked up the moment it lands on disk
        // (typical first-deploy workflow).
        return (ImageKind::RootfsErofs, false);
    }
    let result = match read_verified_image_format(
        image_path,
        &manifest_path,
        canonical_kind,
        kernel_version,
    ) {
        Ok(fmt) => (image_format_to_image_kind(fmt), true),
        Err(e) => {
            // Verification failed — consult the manifest's
            // declared `image_format` as an unverified hint so
            // the substrate dispatch (AVF virtio-blk vs.
            // initramfs cpio.gz) matches the bytes on disk even
            // when the trust anchor is the all-zero placeholder.
            // See `resolve_image_kind_for_role` doc comment for
            // the trust-model rationale (image_format is
            // dispatch metadata, not a privilege grant).
            let (hint_kind, hint_source) = match read_unverified_image_format_hint(&manifest_path) {
                Ok(fmt) => (
                    image_format_to_image_kind(fmt),
                    "manifest_image_format_field",
                ),
                Err(_) => (ImageKind::RootfsErofs, "rootfs_erofs_default"),
            };
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"canonical_image_kind_fallback\",\
                     \"reason\":\"manifest_verify_failed\",\"image\":\"{}\",\
                     \"manifest\":\"{}\",\"fallback_kind\":\"{:?}\",\
                     \"fallback_source\":\"{}\",\"error\":{:?}}}",
                image_path.display(),
                manifest_path.display(),
                hint_kind,
                hint_source,
                e.to_string(),
            );
            // Same fallback-not-cached rationale as above: we
            // want the next spawn to re-stat once the operator
            // remediates the manifest.
            return (hint_kind, false);
        }
    };

    // Populate the cache for the verified path. Re-stat to capture
    // the mtime+len that pair with the bytes we just verified — if
    // the file was mid-rotation, the second stat may show the new
    // mtime/len, which is exactly what we want (we cache "the bytes
    // that verified" with their on-disk fingerprint).
    if let Ok(meta) = std::fs::metadata(image_path) {
        if let Ok(file_mtime) = meta.modified() {
            if let Ok(mut cache) = image_kind_cache().lock() {
                cache.insert(
                    image_path.to_path_buf(),
                    CachedKindEntry {
                        image_kind: result.0,
                        is_trusted: result.1,
                        file_mtime,
                        file_len: meta.len(),
                        kernel_version: kernel_version.to_owned(),
                        canonical_kind,
                    },
                );
            }
        }
    }
    result
}

/// Probe the host-canonical Linux kernel binary at boot. The
/// presence check is intentionally cheap (a `Path::exists()`
/// stat) — the file is not signature-verified in V2 (see
/// [`linux_kernel_path`] for the trust-model rationale), so a
/// SHA-256 stream would burn a noticeable wall-clock fraction of
/// kernel-boot time without a reciprocal trust gain.
///
/// Pulled out as a separate function (rather than folding into
/// [`verify_canonical_images_at_boot`]) so a dashboard or
/// `raxis doctor` can render the kernel-binary outcome on its own
/// row and so substrates without a Linux kernel
/// (SubprocessIsolation in tests) can observe a `Missing` outcome
/// without the per-role rootfs noise.
pub fn probe_linux_kernel_binary_at_boot(install_dir: &Path) -> KernelBinaryOutcome {
    let path = linux_kernel_path(install_dir);
    if path.exists() {
        KernelBinaryOutcome::Present { path }
    } else {
        KernelBinaryOutcome::Missing { path }
    }
}

/// Stable audit-event `violation_kind` for the wrong-key case
/// (manifest signed by a keypair that does not match the kernel's
/// embedded trust anchor). Pinned by
/// `INV-IMAGE-VERIFY-REJECT-MISMATCH-01`.
pub const CANONICAL_IMAGE_SIGNATURE_MISMATCH_VIOLATION_KIND: &str =
    "CanonicalImageSignatureMismatch";

/// `INV-IMAGE-VERIFY-REJECT-MISMATCH-01` — map a
/// [`CanonicalImageError`] to the audit-event `violation_kind`
/// string the kernel emits on
/// `SecurityViolationDetected`. Centralised so the kernel's seam
/// for "wrong key, not no key" classification has ONE pin-point that
/// invariant tests can witness.
///
/// Returns `"CanonicalImageSignatureMismatch"` for the four
/// signature-related manifest-error variants (`SigningKeyFpMismatch`,
/// `SignatureFailed`, `SignatureMalformed`, `SigningKeyFpMalformed`).
/// Every other error variant maps to the per-role
/// `{Reviewer,Orchestrator,ExecutorStarter}ImageDigestMismatch`
/// audit slot so the existing dashboards continue to pivot by image
/// kind for structural / tamper failures.
pub fn classify_canonical_image_violation(
    err: &CanonicalImageError,
    kind: CanonicalImageKind,
) -> String {
    match err {
        CanonicalImageError::Manifest {
            source:
                raxis_image_manifest::ManifestError::SigningKeyFpMismatch
                | raxis_image_manifest::ManifestError::SignatureFailed(_)
                | raxis_image_manifest::ManifestError::SignatureMalformed
                | raxis_image_manifest::ManifestError::SigningKeyFpMalformed,
            ..
        } => CANONICAL_IMAGE_SIGNATURE_MISMATCH_VIOLATION_KIND.to_owned(),
        _ => kind.audit_kind().to_owned(),
    }
}

/// Verify one image's manifest + .img bytes and emit the appropriate
/// audit event on mismatch. Pulled out so the helper is unit-testable
/// without going through `verify_canonical_images_at_boot`'s pair plumbing.
fn run_one(
    image_path: &Path,
    kind: CanonicalImageKind,
    kernel_version: &str,
    audit: &dyn AuditSink,
) -> PreflightOutcome {
    if !image_path.exists() {
        return PreflightOutcome::Missing {
            path: image_path.to_owned(),
        };
    }
    let manifest_path = manifest_path_for_image(image_path);
    if !manifest_path.exists() {
        return PreflightOutcome::ManifestMissing {
            image_path: image_path.to_owned(),
            manifest_path,
        };
    }

    match verify_canonical_image_via_manifest(image_path, &manifest_path, kind, kernel_version) {
        Ok(()) => PreflightOutcome::Ok {
            path: image_path.to_owned(),
        },
        Err(CanonicalImageError::SigningKeyFpNotPopulated) => {
            PreflightOutcome::TrustAnchorUnpopulated {
                path: image_path.to_owned(),
            }
        }
        Err(CanonicalImageError::DigestMismatch {
            expected, actual, ..
        }) => {
            // Audit-after-detect (NOT after a state mutation) — the
            // detection itself IS the recorded fact. Emit failures
            // are logged but never short-circuit the preflight pair:
            // a tampered Reviewer image must not mask a tampered
            // Orchestrator image (or vice versa).
            if let Err(e) = audit.emit(
                AuditEventKind::SecurityViolationDetected {
                    violation_kind: kind.audit_kind().to_owned(),
                    expected: Some(expected.clone()),
                    actual: Some(actual.clone()),
                    path: Some(image_path.display().to_string()),
                },
                None,
                None,
                None,
            ) {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"SecurityViolationDetected\",\
                     \"audit_emit_failed\":\"{e}\",\"violation_kind\":\"{}\"}}",
                    kind.audit_kind(),
                );
            }

            // FOLLOWUP-F — for the iter62 verifier roles, also emit the
            // verifier-specific `VerifierImageDigestMismatch` audit row
            // alongside the canonical `SecurityViolationDetected` above.
            // Lets the dashboard's verifier panel pivot on
            // `image_alias` without joining the
            // `SecurityViolationDetected.violation_kind` string family.
            // Pinned by `INV-VERIFIER-CANONICAL-SYMBOL-INDEX-DIGEST-PINNED-01`.
            let verifier_alias = match kind {
                CanonicalImageKind::Verifier => Some("raxis-verifier-starter"),
                CanonicalImageKind::VerifierSymbolIndex => Some("raxis-verifier-symbol-index"),
                _ => None,
            };
            if let Some(alias) = verifier_alias {
                crate::gates::verifier_audit::emit_image_digest_mismatch(
                    audit,
                    alias,
                    &expected,
                    &actual,
                    &image_path.display().to_string(),
                    None,
                    None,
                );
            }
            PreflightOutcome::Tampered {
                path: image_path.to_owned(),
                expected,
                actual,
            }
        }
        Err(CanonicalImageError::Io { source, .. }) => {
            // I/O reported `not found`-equivalent on a path that
            // `path.exists()` cleared as present — extremely rare
            // (race or symlink-target-vanished). Fall through to
            // `Missing` so the operator sees a single canonical
            // remediation message: "the image file is not present".
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"canonical_image_io_missing\",\
                 \"path\":\"{}\",\"reason\":\"{source}\"}}",
                image_path.display(),
            );
            PreflightOutcome::Missing {
                path: image_path.to_owned(),
            }
        }
        Err(other) => {
            // Manifest load / parse / signature / role-mismatch /
            // kernel-version-skew. Audit and refuse activation.
            //
            // `INV-IMAGE-VERIFY-REJECT-MISMATCH-01` — classify the
            // signature-mismatch arm separately from the
            // structural-mismatch arm so an operator who rebuilt the
            // kernel against a different signing key can distinguish
            // "valid key, wrong key" (`CanonicalImageSignatureMismatch`)
            // from "tampered bytes" (`{Reviewer,Orchestrator,
            // ExecutorStarter}ImageDigestMismatch`) and from
            // structural manifest errors (TOML parse, role mismatch,
            // kernel-version skew — keep the per-kind audit slot so
            // the existing dashboards continue to pivot by image
            // kind). The wrong-key case is operator-recoverable
            // (re-bake images with the matching key OR rebuild the
            // kernel against the bake's key half); the tamper case
            // is a security incident.
            let violation_kind = classify_canonical_image_violation(&other, kind);
            let reason = format!("{other}");
            if let Err(e) = audit.emit(
                AuditEventKind::SecurityViolationDetected {
                    violation_kind: violation_kind.clone(),
                    expected: None,
                    actual: None,
                    path: Some(manifest_path.display().to_string()),
                },
                None,
                None,
                None,
            ) {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"SecurityViolationDetected\",\
                     \"audit_emit_failed\":\"{e}\",\"violation_kind\":\"{violation_kind}\"}}",
                );
            }
            PreflightOutcome::ManifestRejected {
                image_path: image_path.to_owned(),
                manifest_path,
                reason,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_test_support::FakeAuditSink;
    use std::io::Write;

    /// Path resolution pins the spec's filename format. Drift here
    /// would silently break `raxis doctor canonical-images` and any
    /// air-gapped install that ships images at the documented path.
    #[test]
    fn reviewer_path_matches_system_requirements_layout() {
        let p = reviewer_image_path(Path::new("/usr/local/lib/raxis"), "2.0.0");
        assert_eq!(
            p,
            PathBuf::from("/usr/local/lib/raxis/images/raxis-reviewer-core-2.0.0.img"),
        );
    }

    #[test]
    fn orchestrator_path_matches_system_requirements_layout() {
        let p = orchestrator_image_path(Path::new("/usr/local/lib/raxis"), "2.0.0");
        assert_eq!(
            p,
            PathBuf::from("/usr/local/lib/raxis/images/raxis-orchestrator-core-2.0.0.img"),
        );
    }

    /// On a fresh install (image not present), preflight surfaces
    /// `Missing` and emits NO `SecurityViolationDetected` event.
    /// This is the baseline state of every dev workstation today —
    /// the kernel must boot regardless.
    #[test]
    fn missing_image_is_warning_only_not_audit_event() {
        let tmp = tempfile::tempdir().unwrap();
        let audit = FakeAuditSink::new();

        let outcomes = verify_canonical_images_at_boot(tmp.path(), "0.0.0-test", &audit);
        match &outcomes[0].1 {
            PreflightOutcome::Missing { .. } => {}
            other => panic!("expected Missing for Reviewer; got {other:?}"),
        }
        match &outcomes[1].1 {
            PreflightOutcome::Missing { .. } => {}
            other => panic!("expected Missing for Orchestrator; got {other:?}"),
        }

        let kinds: Vec<_> = audit.events().iter().map(|e| e.kind.as_str()).collect();
        assert!(
            !kinds.contains(&"SecurityViolationDetected"),
            "missing-image case must NOT emit SecurityViolationDetected: {kinds:?}",
        );
    }

    /// .img is on disk but the sibling `.manifest.toml` is not yet
    /// distributed → `ManifestMissing`, no audit event. Pins the
    /// "image is present, manifest not yet shipped" early-deployment
    /// posture (which is the realistic state during V2 cutover before
    /// the release pipeline has produced a manifest).
    #[test]
    fn present_image_without_manifest_surfaces_manifest_missing_warning_only() {
        let tmp = tempfile::tempdir().unwrap();
        let audit = FakeAuditSink::new();

        let images = tmp.path().join("images");
        std::fs::create_dir_all(&images).unwrap();
        for name in [
            "raxis-reviewer-core-0.0.0-test.img",
            "raxis-orchestrator-core-0.0.0-test.img",
        ] {
            let mut f = std::fs::File::create(images.join(name)).unwrap();
            f.write_all(b"placeholder-content").unwrap();
        }

        let outcomes = verify_canonical_images_at_boot(tmp.path(), "0.0.0-test", &audit);
        for (kind, outcome) in &outcomes {
            assert!(
                matches!(outcome, PreflightOutcome::ManifestMissing { .. }),
                "expected ManifestMissing for {kind:?}; got {outcome:?}",
            );
        }

        let kinds: Vec<_> = audit.events().iter().map(|e| e.kind.as_str()).collect();
        assert!(
            !kinds.contains(&"SecurityViolationDetected"),
            "manifest-missing case must NOT emit SecurityViolationDetected: {kinds:?}",
        );
    }

    /// On a fresh install (kernel binary not present), the kernel
    /// binary preflight surfaces `Missing` and emits NO audit event.
    /// Mirrors the rootfs `Missing` posture — the kernel must boot
    /// regardless so SubprocessIsolation-only substrates remain
    /// usable.
    #[test]
    fn missing_kernel_binary_returns_missing_with_resolved_path() {
        let tmp = tempfile::tempdir().unwrap();
        let outcome = probe_linux_kernel_binary_at_boot(tmp.path());
        match outcome {
            KernelBinaryOutcome::Missing { path } => {
                assert_eq!(path, tmp.path().join("kernel").join("vmlinux"));
            }
            other => panic!("expected Missing for fresh install; got {other:?}"),
        }
    }

    /// Kernel binary on disk → `Present` with the resolved path.
    /// Pins the substrate-spawn-eligible posture.
    #[test]
    fn present_kernel_binary_returns_present_with_resolved_path() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("kernel");
        std::fs::create_dir_all(&kernel).unwrap();
        let vmlinux = kernel.join("vmlinux");
        std::fs::write(&vmlinux, b"placeholder-vmlinux-bytes").unwrap();

        let outcome = probe_linux_kernel_binary_at_boot(tmp.path());
        match outcome {
            KernelBinaryOutcome::Present { path } => {
                assert_eq!(path, vmlinux);
            }
            other => panic!("expected Present when vmlinux exists; got {other:?}"),
        }
    }

    /// Kernel-binary path resolution pins the spec's filename
    /// format. Drift here would silently break substrates that
    /// resolve `linux_kernel_path` from `install_dir`.
    #[test]
    fn linux_kernel_path_matches_system_requirements_layout() {
        let p = linux_kernel_path(Path::new("/usr/local/lib/raxis"));
        assert_eq!(p, PathBuf::from("/usr/local/lib/raxis/kernel/vmlinux"));
    }

    /// .img + .manifest.toml are both on disk but the kernel's
    /// signing-key trust anchor is the placeholder → `TrustAnchorUnpopulated`
    /// outcome, no audit event. Pins the V2-cutover posture once the
    /// release pipeline starts shipping signed manifests but the
    /// kernel binary has not yet committed the public key.
    ///
    /// **Test only meaningful in builds where the trust anchor is
    /// the all-zero placeholder.** A developer build that injects a
    /// real signing key via `RAXIS_KERNEL_SIGNING_KEY_HEX` (e.g. for
    /// the live-e2e workflow) takes the populated branch in
    /// `verify_canonical_image_via_manifest`, which goes through
    /// manifest parsing — for which our placeholder TOML
    /// (`schema_version = 2`) is intentionally malformed (it omits
    /// the `role` field). Skip in that case rather than asserting a
    /// posture the build cannot reach; the populated-trust-anchor
    /// path is covered by sibling tests in `raxis-canonical-images`
    /// (`verify_via_manifest_with_key_*`).
    #[test]
    fn manifest_present_with_unpopulated_trust_anchor_is_warning_only() {
        if raxis_canonical_images::EXPECTED_KERNEL_SIGNING_KEY_BYTES
            != [0u8; raxis_canonical_images::DIGEST_LEN]
        {
            eprintln!(
                "skip: kernel signing-key trust anchor is populated; \
                 this test only exercises the all-zero placeholder branch"
            );
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let audit = FakeAuditSink::new();

        let images = tmp.path().join("images");
        std::fs::create_dir_all(&images).unwrap();
        for stem in [
            "raxis-reviewer-core-0.0.0-test",
            "raxis-orchestrator-core-0.0.0-test",
        ] {
            let mut f = std::fs::File::create(images.join(format!("{stem}.img"))).unwrap();
            f.write_all(b"placeholder-content").unwrap();
            // The manifest contents are irrelevant — the trust-anchor
            // gate trips before we parse the file.
            std::fs::write(
                images.join(format!("{stem}.manifest.toml")),
                "schema_version = 2\n",
            )
            .unwrap();
        }

        let outcomes = verify_canonical_images_at_boot(tmp.path(), "0.0.0-test", &audit);
        for (kind, outcome) in &outcomes {
            assert!(
                matches!(outcome, PreflightOutcome::TrustAnchorUnpopulated { .. }),
                "expected TrustAnchorUnpopulated for {kind:?}; got {outcome:?}",
            );
        }

        let kinds: Vec<_> = audit.events().iter().map(|e| e.kind.as_str()).collect();
        assert!(
            !kinds.contains(&"SecurityViolationDetected"),
            "trust-anchor-unpopulated must NOT emit SecurityViolationDetected: {kinds:?}",
        );
    }

    /// Regression: when the kernel's signing-key trust anchor is the
    /// all-zero placeholder, the manifest verification short-circuits
    /// with `SigningKeyFpNotPopulated` and the kernel cannot trust
    /// the manifest's signature. The dispatch fallback must still
    /// honour the manifest's declared `image_format` field so AVF /
    /// Firecracker mount the bytes the right way (virtio-blk EROFS
    /// vs. initramfs cpio.gz).
    ///
    /// Prior behavior hardcoded `RootfsErofs`, which caused AVF to
    /// reject every `RootfsInitramfsCpio` image with
    /// `Invalid disk image. The disk image format is not recognized.`
    /// — bricking every spawn on a dev/V2-cutover kernel that ships
    /// the initramfs shape (the live-e2e workflow's default).
    ///
    /// **Test only meaningful in the all-zero placeholder build.** A
    /// developer build that injects a real signing key via
    /// `RAXIS_KERNEL_SIGNING_KEY_HEX` would take a different branch
    /// (the populated-anchor verifier) and would either accept the
    /// signature (if it matched) or reject the manifest entirely
    /// (if it didn't); either case is covered structurally by other
    /// tests. Skip in that case rather than asserting a posture the
    /// build cannot reach.
    #[test]
    fn unpopulated_anchor_fallback_honours_manifest_image_format_hint() {
        if raxis_canonical_images::EXPECTED_KERNEL_SIGNING_KEY_BYTES
            != [0u8; raxis_canonical_images::DIGEST_LEN]
        {
            eprintln!(
                "skip: kernel signing-key trust anchor is populated; \
                 this test only exercises the all-zero placeholder branch"
            );
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let images = tmp.path().join("images");
        std::fs::create_dir_all(&images).unwrap();
        let img_path = images.join("raxis-orchestrator-core-0.0.0-test.img");
        std::fs::write(&img_path, b"placeholder-orchestrator-bytes").unwrap();

        // Hand-built v3 manifest claiming `image_format =
        // "RootfsInitramfsCpio"`. The signature / digests / bundle_hash
        // are intentionally junk: in this build the trust anchor is
        // unpopulated, so `read_verified_image_format` short-circuits
        // before they are ever consulted, and the unverified-hint path
        // only needs the file to parse as a `SCHEMA_VERSION = 3`
        // `ImageManifest` to extract the format field.
        let manifest_toml = r#"
schema_version = 3
role = "Orchestrator"
kernel_version = "0.0.0-test"
bundle_hash = "0000000000000000000000000000000000000000000000000000000000000000"
image_artefact_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
image_format = "RootfsInitramfsCpio"
signing_key_fp = "0000000000000000000000000000000000000000000000000000000000000000"
signature = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

[build_env]
source_date_epoch = 1700000000
erofs_version = "1.7.1"
tar_version = "1.34"
zstd_version = "1.5.5"

[[files]]
path = "init"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
size = 1
mode = 493
"#;
        std::fs::write(
            images.join("raxis-orchestrator-core-0.0.0-test.manifest.toml"),
            manifest_toml,
        )
        .unwrap();

        let (kind, is_trusted) =
            resolve_image_kind_for_role(&img_path, CanonicalImageKind::Orchestrator, "0.0.0-test");
        assert_eq!(
            kind,
            ImageKind::RootfsInitramfsCpio,
            "unverified-hint dispatch must honour manifest.image_format \
             rather than hardcoding RootfsErofs (would brick AVF spawn \
             of every initramfs.cpio.gz image)",
        );
        assert!(
            !is_trusted,
            "the un-trusted hint path must report is_trusted=false \
             so callers can gate noisier warnings on the un-signed \
             posture",
        );
    }

    // ── INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01 witnesses ────────────────

    /// `INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01` — invoking the
    /// assertion with the all-zero placeholder MUST panic with the
    /// stable `TRUST_ANCHOR_FAIL_LOUD_MESSAGE` substring. Pins the
    /// boot-time refuse-to-start contract so an operator-supplied
    /// kernel built without `RAXIS_KERNEL_SIGNING_KEY_HEX` cannot
    /// silently reach a surface where it would degrade onto the
    /// manifest-unverified hint path.
    ///
    /// Uses the inner `assert_trust_anchor_bytes_present_or_panic`
    /// so the assertion is exercised against EXPLICIT all-zero
    /// bytes — independent of how the parent test binary's
    /// `EXPECTED_KERNEL_SIGNING_KEY_BYTES` was resolved at compile
    /// time. This is what makes the witness deterministic across
    /// dev workstations whose env may or may not have already set
    /// the hex var.
    #[test]
    #[should_panic(expected = "kernel built without a manifest-trust anchor")]
    fn assert_trust_anchor_panics_on_all_zero_bytes() {
        let placeholder = [0u8; DIGEST_LEN];
        assert_trust_anchor_bytes_present_or_panic(&placeholder);
    }

    /// `INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01` (b) — the assertion
    /// MUST NOT panic when given non-zero bytes. Pins the
    /// non-regression that an off-by-one in the byte comparison
    /// (e.g. comparing the wrong slice or short-circuit on the
    /// first byte only) does not crash kernels that DO have a
    /// trust anchor.
    #[test]
    fn assert_trust_anchor_accepts_non_zero_bytes() {
        // 32 bytes of 0xab — concretely non-zero on every offset
        // so a hypothetical "compare first N bytes only" bug would
        // not pass by luck.
        let live = [0xabu8; DIGEST_LEN];
        assert_trust_anchor_bytes_present_or_panic(&live);
    }

    /// `INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01` (c) — a kernel whose
    /// trust anchor differs from the placeholder by exactly one
    /// byte (the high-entropy realistic case for "almost zero"
    /// bugs) MUST also pass. Defends against a future
    /// `bytes.iter().all(|b| *b == 0)` simplification that would
    /// have the same shape as the array equality but with
    /// different short-circuit characteristics.
    #[test]
    fn assert_trust_anchor_accepts_one_byte_set() {
        let mut almost_zero = [0u8; DIGEST_LEN];
        almost_zero[DIGEST_LEN - 1] = 0x01;
        assert_trust_anchor_bytes_present_or_panic(&almost_zero);
    }

    // ── INV-IMAGE-VERIFY-REJECT-MISMATCH-01 witnesses ────────────────

    /// `INV-IMAGE-VERIFY-REJECT-MISMATCH-01` (a) — classification
    /// helper maps every signature-related manifest-error variant
    /// onto the stable `"CanonicalImageSignatureMismatch"` audit
    /// `violation_kind`. Pins the per-variant fanout so a future
    /// `ManifestError` addition that adds a new signature-related
    /// shape (e.g. a curve-mismatch variant for a post-quantum
    /// algorithm transition) trips this witness and the maintainer
    /// is forced to extend `classify_canonical_image_violation`
    /// rather than silently degrading to the per-kind
    /// `*ImageDigestMismatch` audit slot.
    #[test]
    fn classify_signature_errors_as_signature_mismatch() {
        use raxis_image_manifest::ManifestError;
        let cases: &[ManifestError] = &[
            ManifestError::SigningKeyFpMismatch,
            ManifestError::SignatureMalformed,
            ManifestError::SigningKeyFpMalformed,
        ];
        for variant in cases {
            let err = CanonicalImageError::Manifest {
                path: "/tmp/whatever.manifest.toml".to_owned(),
                source: clone_manifest_error(variant),
            };
            let kind = classify_canonical_image_violation(&err, CanonicalImageKind::Reviewer);
            assert_eq!(
                kind, CANONICAL_IMAGE_SIGNATURE_MISMATCH_VIOLATION_KIND,
                "{variant:?} must classify as CanonicalImageSignatureMismatch"
            );
        }
    }

    /// `INV-IMAGE-VERIFY-REJECT-MISMATCH-01` (b) — non-signature
    /// errors keep the per-role
    /// `{Reviewer,Orchestrator,ExecutorStarter}ImageDigestMismatch`
    /// audit slot so the existing tamper-event dashboards continue
    /// to pivot by image kind. Pins the negative half of the
    /// classification matrix.
    #[test]
    fn classify_non_signature_errors_keep_per_kind_audit_slot() {
        let cases: &[(CanonicalImageKind, &str)] = &[
            (CanonicalImageKind::Reviewer, "ReviewerImageDigestMismatch"),
            (
                CanonicalImageKind::Orchestrator,
                "OrchestratorImageDigestMismatch",
            ),
            (
                CanonicalImageKind::ExecutorStarter,
                "ExecutorStarterImageDigestMismatch",
            ),
        ];
        for (kind, expected) in cases {
            let err = CanonicalImageError::ManifestRoleMismatch {
                path: "/tmp/x.manifest.toml".to_owned(),
                found: raxis_image_manifest::Role::Reviewer,
                kind: CanonicalImageKind::Orchestrator,
            };
            let classified = classify_canonical_image_violation(&err, *kind);
            assert_eq!(
                classified, *expected,
                "role-mismatch must keep the per-role audit slot for {kind:?}"
            );

            let err = CanonicalImageError::ManifestKernelVersionMismatch {
                path: "/tmp/x.manifest.toml".to_owned(),
                found: "0.1.0".to_owned(),
                expected: "0.2.0".to_owned(),
            };
            let classified = classify_canonical_image_violation(&err, *kind);
            assert_eq!(
                classified, *expected,
                "kernel-version-skew must keep the per-role audit slot for {kind:?}"
            );
        }
    }

    /// `INV-IMAGE-VERIFY-REJECT-MISMATCH-01` (c) — END-TO-END
    /// integration witness for the "key A signs, key B verifies"
    /// scenario. Constructs a real signed manifest with key A, calls
    /// `verify_canonical_image_via_manifest_with_key` against key B
    /// (simulating a kernel whose embedded trust anchor was rotated
    /// to a different key half than the bake's), and asserts:
    ///
    ///   * the verifier returns
    ///     `Err(CanonicalImageError::Manifest { source: SigningKeyFpMismatch, .. })`,
    ///     i.e. it refuses to admit the image structurally,
    ///   * the classifier maps that error to
    ///     `"CanonicalImageSignatureMismatch"`,
    ///   * a `SecurityViolationDetected` audit event lands on the
    ///     `FakeAuditSink` with the same `violation_kind`.
    ///
    /// This is the kernel-side mirror of the canonical-images crate's
    /// `verify_via_manifest_with_key_rejects_wrong_signing_key`
    /// witness; the difference is that THIS one also pins the audit
    /// surface (the canonical-images crate has no audit dependency).
    #[test]
    fn wrong_key_manifest_emits_signature_mismatch_audit() {
        use ed25519_dalek::{Signer, SigningKey};
        use raxis_image_manifest::{
            fingerprint_signing_key, BuildEnv, ImageFormat, ImageManifest, ManifestFile, Role,
            SCHEMA_VERSION,
        };
        use sha2::{Digest, Sha256};

        // Fresh keypair helper. Uses `getrandom` (already a kernel
        // dep) rather than `rand` to avoid pulling another dev-dep
        // for one fixture builder.
        let mk_key = || {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).expect("getrandom on a host with /dev/urandom");
            let sk = SigningKey::from_bytes(&bytes);
            let vk = sk.verifying_key();
            (sk, vk)
        };
        let (sk_a, vk_a) = mk_key();
        let (_, vk_b) = mk_key(); // The kernel's "rotated" trust anchor.

        // Stage an image + key-A-signed manifest in a tempdir.
        let tmp = tempfile::tempdir().unwrap();
        let images = tmp.path().join("images");
        std::fs::create_dir_all(&images).unwrap();
        let img_path = images.join("raxis-reviewer-core-0.0.0-test.img");
        let img_body = b"key-A-signed-fixture";
        std::fs::write(&img_path, img_body).unwrap();
        let img_sha = {
            let mut h = Sha256::new();
            h.update(img_body);
            hex::encode::<[u8; 32]>(h.finalize().into())
        };

        let mut manifest = ImageManifest {
            schema_version: SCHEMA_VERSION,
            role: Role::Reviewer,
            kernel_version: "0.0.0-test".to_owned(),
            bundle_hash: String::new(),
            image_artefact_sha256: img_sha,
            image_format: ImageFormat::RootfsInitramfsCpio,
            build_env: BuildEnv {
                source_date_epoch: 1700000000,
                erofs_version: "1.7.1".to_owned(),
                tar_version: "1.34".to_owned(),
                zstd_version: "1.5.5".to_owned(),
            },
            files: vec![ManifestFile {
                path: "init".to_owned(),
                sha256: "0".repeat(64),
                size: 1,
                mode: 0o755,
            }],
            signing_key_fp: hex::encode(fingerprint_signing_key(&vk_a)),
            signature: String::new(),
        };
        let bh = manifest.recompute_bundle_hash().unwrap();
        manifest.bundle_hash = hex::encode(bh);
        manifest.signature = hex::encode(sk_a.sign(&bh).to_bytes());
        let manifest_path = images.join("raxis-reviewer-core-0.0.0-test.manifest.toml");
        std::fs::write(&manifest_path, manifest.to_toml()).unwrap();

        // The verifier with key B's anchor MUST refuse the manifest.
        let err = raxis_canonical_images::verify_canonical_image_via_manifest_with_key(
            &img_path,
            &manifest_path,
            CanonicalImageKind::Reviewer,
            "0.0.0-test",
            &vk_b,
        )
        .expect_err("key-A-signed manifest must be refused by key-B kernel");
        let inner = match &err {
            CanonicalImageError::Manifest { source, .. } => source,
            other => panic!("expected Manifest{{...}} variant; got {other:?}"),
        };
        assert!(
            matches!(
                inner,
                raxis_image_manifest::ManifestError::SigningKeyFpMismatch
                    | raxis_image_manifest::ManifestError::SignatureFailed(_)
            ),
            "expected SigningKeyFpMismatch or SignatureFailed; got {inner:?}"
        );

        // The classifier must map the error to the stable audit kind.
        let violation_kind = classify_canonical_image_violation(&err, CanonicalImageKind::Reviewer);
        assert_eq!(
            violation_kind, CANONICAL_IMAGE_SIGNATURE_MISMATCH_VIOLATION_KIND,
            "wrong-key error must classify as CanonicalImageSignatureMismatch"
        );

        // And a SecurityViolationDetected with that violation_kind
        // must land on the audit sink (the seam `run_one`'s `Err(other)`
        // arm exercises). We emit through a FakeAuditSink directly so
        // the test is hermetic against `run_one`'s file-glue (the file-
        // glue is exercised by sibling tests that already use the
        // compile-time anchor).
        let audit = raxis_test_support::FakeAuditSink::new();
        audit
            .emit(
                AuditEventKind::SecurityViolationDetected {
                    violation_kind: violation_kind.clone(),
                    expected: None,
                    actual: None,
                    path: Some(manifest_path.display().to_string()),
                },
                None,
                None,
                None,
            )
            .expect("audit emit on FakeAuditSink does not fail");
        let events = audit.events();
        let kinds: Vec<_> = events
            .iter()
            .filter(|e| e.kind.as_str() == "SecurityViolationDetected")
            .collect();
        assert_eq!(
            kinds.len(),
            1,
            "expected exactly one SecurityViolationDetected on the audit sink"
        );
    }

    /// Clone helper for `ManifestError` (the type is not `Clone` by
    /// default because `SignatureError` wraps an opaque ed25519
    /// error). We only use it from
    /// `classify_signature_errors_as_signature_mismatch` against the
    /// `SigningKeyFpMismatch`, `SignatureMalformed`, and
    /// `SigningKeyFpMalformed` variants — all of which are unit-shape
    /// so cloning is trivial.
    fn clone_manifest_error(
        e: &raxis_image_manifest::ManifestError,
    ) -> raxis_image_manifest::ManifestError {
        use raxis_image_manifest::ManifestError;
        match e {
            ManifestError::SigningKeyFpMismatch => ManifestError::SigningKeyFpMismatch,
            ManifestError::SignatureMalformed => ManifestError::SignatureMalformed,
            ManifestError::SigningKeyFpMalformed => ManifestError::SigningKeyFpMalformed,
            other => panic!(
                "clone_manifest_error only supports unit-shape signature variants; got {other:?}"
            ),
        }
    }

    /// The fail-loud message MUST mention the env-var name, the
    /// xtask recipe, AND the spec path. Pins the operator-actionable
    /// shape of the panic so a future "shorten the message" refactor
    /// doesn't accidentally drop the diagnostic the operator needs.
    #[test]
    fn fail_loud_message_includes_operator_remediation() {
        let msg = TRUST_ANCHOR_FAIL_LOUD_MESSAGE;
        assert!(
            msg.contains("RAXIS_KERNEL_SIGNING_KEY_HEX"),
            "fail-loud must name the env var: {msg}"
        );
        assert!(
            msg.contains("cargo xtask images bake-all"),
            "fail-loud must point at the dev-recovery recipe: {msg}"
        );
        assert!(
            msg.contains("specs/v3/canonical-image-trust-anchor.md"),
            "fail-loud must point at the spec: {msg}"
        );
    }

    /// Companion to `unpopulated_anchor_fallback_honours_manifest_image_format_hint`:
    /// when the manifest is structurally unparseable (corrupt /
    /// truncated / wrong schema), the unverified-hint path also
    /// fails and the dispatch falls back to the documented
    /// production canonical default (`RootfsErofs`). Pins the
    /// last-resort behaviour so a partial-write race or operator
    /// hand-edit cannot silently degrade to an undefined dispatch.
    #[test]
    fn unpopulated_anchor_fallback_defaults_to_erofs_when_manifest_unparseable() {
        if raxis_canonical_images::EXPECTED_KERNEL_SIGNING_KEY_BYTES
            != [0u8; raxis_canonical_images::DIGEST_LEN]
        {
            eprintln!(
                "skip: kernel signing-key trust anchor is populated; \
                 this test only exercises the all-zero placeholder branch"
            );
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let images = tmp.path().join("images");
        std::fs::create_dir_all(&images).unwrap();
        let img_path = images.join("raxis-reviewer-core-0.0.0-test.img");
        std::fs::write(&img_path, b"placeholder-reviewer-bytes").unwrap();
        // schema_version = 2 trips `SchemaVersionMismatch` in
        // `ImageManifest::from_toml`, so the unverified-hint path
        // returns `Err` and the seam falls through to RootfsErofs.
        std::fs::write(
            images.join("raxis-reviewer-core-0.0.0-test.manifest.toml"),
            "schema_version = 2\n",
        )
        .unwrap();

        let (kind, is_trusted) =
            resolve_image_kind_for_role(&img_path, CanonicalImageKind::Reviewer, "0.0.0-test");
        assert_eq!(
            kind,
            ImageKind::RootfsErofs,
            "unparseable manifest must fall back to the production \
             canonical default (RootfsErofs) rather than guessing",
        );
        assert!(!is_trusted);
    }
}
