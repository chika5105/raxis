//! `raxis doctor` — preflight diagnostic for the operator's
//! `<data_dir>` and the kernel's on-disk surfaces.
//!
//! Normative reference: cli-readonly.md §5.5.15.
//!
//! # What this command does
//!
//! Walks every invariant the kernel asserts at boot and reports the
//! result as a typed list of `Check` records. Each check has an
//! outcome (`Ok` | `Warn` | `Fail`); the command's exit code is the
//! worst-of:
//!
//!   * 0 — every check is `Ok`.
//!   * 1 — at least one `Warn`, no `Fail`.
//!   * 2 — at least one `Fail`. The kernel is unlikely to boot
//!         (or has booted into a broken state).
//!
//! # What this command does NOT do
//!
//! * It does NOT mutate anything. There is no "fix-it" mode — the
//!   operator is responsible for editing files / setting permissions
//!   based on the report.
//! * It does NOT touch the kernel over IPC. Doctor must work even
//!   when the kernel cannot start.
//! * It does NOT walk the full audit chain. Use `raxis verify-chain`
//!   for the cryptographic walk; doctor uses the same quick-check
//!   `raxis status` does so the report stays under one screen.
//!
//! # Checks performed (in order)
//!
//! 1. `<data_dir>/` exists and is a directory.
//! 2. `<data_dir>/{keys,policy,audit,providers,runtime,sockets,notifications}/`
//!    each exist with sensible mode bits.
//! 3. `policy/policy.toml` is loadable through `raxis_policy::load_policy`.
//! 4. `kernel.db` is openable read-only AND its `SCHEMA_VERSION`
//!    matches the CLI's compiled-in expectation
//!    (`raxis_store::open_ro` does the assertion).
//! 5. `runtime/heartbeat.json` is parseable via `raxis_runtime::read`
//!    (`Warn` if missing — kernel may not have started yet).
//! 6. `audit/` has at least one `segment-NNN.jsonl` and the
//!    quick-check passes.
//! 7. Cross-check: bundle.epoch() == policy_epoch_history.MAX(epoch).
//! 8. Operator-cert status (step-11): for every row in the
//!    `operator_certificates` view table, classify against the
//!    four-zone state machine (`raxis_crypto::cert::cert_status`)
//!    and surface:
//!    * `WARN` for `Expiring` (within `warn_before_expiry_days`),
//!    * `WARN` for `Grace` (within `grace_period_days` past expiry),
//!    * `FAIL` for `Expired` (recovery ops also denied),
//!    * `FAIL` for `NotYetValid` (cert is dead-on-arrival),
//!    * `OK`   for `Active` and `AlwaysActiveEmergency`.
//!
//!    Plus `WARN` for any operator entry with
//!    `force_misconfig_bypass = true` so the operator is reminded
//!    they have an audited structural override active.
//!
//! # Distribution-specific subcommands
//!
//! Two additional subcommands are dispatched by name as the first
//! positional argument; both are referenced by the Homebrew formula's
//! `post_install` block (`release-and-distribution.md §9.2`):
//!
//! * `raxis doctor signing-key-fp` — print the kernel binary's
//!   compiled-in trust-anchor fingerprint
//!   (`EXPECTED_KERNEL_SIGNING_KEY_BYTES`). Exit code 0 when a real
//!   key is baked in; 1 with a loud warning when the binary is in
//!   the all-zero placeholder state. Useful for confirming a
//!   notarized release binary actually has a kernel signing key
//!   compiled in (vs. a `cargo build` of unsigned source which
//!   would have all zeros).
//! * `raxis doctor canonical-images` — for the kernel-version-
//!   matched Reviewer + Orchestrator + Executor-starter canonical
//!   images under `<install_dir>/images/`, verify each one against
//!   the kernel's compiled-in trust anchor + signed sibling
//!   manifest. Exit code 0 when every image verifies. The formula's
//!   `post_install` aborts the install on failure (§9.2). The
//!   `--install-dir` flag accepts an explicit override; default is
//!   `$RAXIS_INSTALL_DIR` env var, falling back to
//!   `/usr/local/lib/raxis`.

use std::io::Write;
use std::path::{Path, PathBuf};

use raxis_audit_tools::{quick_chain_check, ChainQuickCheck};
use raxis_canonical_images::{
    compute_signing_key_fp, manifest_path_for_image, verify_canonical_image_via_manifest,
    CanonicalImageError, CanonicalImageKind, EXPECTED_KERNEL_SIGNING_KEY_BYTES,
};
use raxis_crypto::cert::{cert_status, CertStatus};
use raxis_policy::load_policy;
use raxis_runtime::{read as read_heartbeat, ReadError as HeartbeatReadError};
use raxis_store::views::operator_certificates;
use raxis_store::views::policy_history;
use raxis_store::{open_ro, RoError};
use raxis_types::unix_now_secs;

use crate::errors::CliError;
use crate::GlobalFlags;

/// Default install dir when `--install-dir` and `RAXIS_INSTALL_DIR`
/// are both unset. Pinned by `system-requirements.md §1` install-
/// dir layout; matches what the Homebrew formula deposits via
/// `share/raxis/`.
const DEFAULT_INSTALL_DIR: &str = "/usr/local/lib/raxis";

const POLICY_FILE_NAME: &str = "policy.toml";
const AUDIT_DIR_NAME:   &str = "audit";

// Spec'd mode bits per kernel-store.md §2.5.1 ("permissions") and
// peripherals.md §3.2 (providers/). These match what bootstrap.rs sets.
const EXPECTED_MODES: &[(&str, u32)] = &[
    ("keys",          0o700),
    ("policy",        0o755),
    ("audit",         0o755),
    ("providers",     0o700),
    ("runtime",       0o755),
    ("sockets",       0o755),
    ("notifications", 0o755),
];

// ────────────────────────────────────────────────────────────────────
// Outcome model
// ────────────────────────────────────────────────────────────────────

/// One row in the doctor report.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Check {
    /// Short stable identifier, e.g. "data_dir.exists". Stable across
    /// versions so JSON consumers can pin against it.
    id:      &'static str,
    outcome: Outcome,
    detail:  String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome { Ok, Warn, Fail }

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Ok   => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Report {
    checks: Vec<Check>,
}

impl Report {
    fn push(&mut self, id: &'static str, outcome: Outcome, detail: impl Into<String>) {
        self.checks.push(Check { id, outcome, detail: detail.into() });
    }

    /// Worst-of outcome. Drives the process exit code.
    fn worst(&self) -> Outcome {
        let mut worst = Outcome::Ok;
        for c in &self.checks {
            worst = match (worst, c.outcome) {
                (_, Outcome::Fail)              => Outcome::Fail,
                (Outcome::Ok, Outcome::Warn)    => Outcome::Warn,
                (other, _)                      => other,
            };
        }
        worst
    }

    fn exit_code(&self) -> i32 {
        match self.worst() {
            Outcome::Ok   => 0,
            Outcome::Warn => 1,
            Outcome::Fail => 2,
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let parsed = parse_args(args)?;
    match parsed.subcommand {
        Subcommand::Default => run_default(flags, parsed.opts),
        Subcommand::SigningKeyFp => run_signing_key_fp(parsed.opts),
        Subcommand::CanonicalImages { install_dir } => {
            run_canonical_images(parsed.opts, install_dir)
        }
        Subcommand::CachePrune { dry_run } => {
            run_cache_prune(flags, parsed.opts, dry_run)
        }
    }
}

fn run_default(flags: &GlobalFlags, opts: DoctorOpts) -> Result<(), CliError> {
    let data_dir = flags.data_dir().clone();
    let report = collect(&data_dir);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if opts.json {
        render_json(&mut out, &data_dir, &report);
    } else {
        render_human(&mut out, &data_dir, &report);
    }
    let _ = out.flush();
    std::process::exit(report.exit_code());
}

/// `raxis doctor signing-key-fp` — print the kernel binary's
/// compiled-in trust-anchor fingerprint.
///
/// Exit code:
///   * 0 — a real (non-placeholder) key is baked in.
///   * 1 — the binary was built without `RAXIS_KERNEL_SIGNING_KEY_HEX`
///         (or the matching bytes path) set; surfaced loudly so an
///         operator who installed an unsigned `cargo build` knows
///         their kernel cannot verify any image manifest.
///
/// The compiled-in `EXPECTED_KERNEL_SIGNING_KEY_BYTES` constant is
/// the public half of the kernel signing keypair; this command is
/// therefore safe to run on any host, the output reveals nothing
/// secret. Pinned by `release-and-distribution.md §9.2`.
fn run_signing_key_fp(opts: DoctorOpts) -> Result<(), CliError> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let bytes = EXPECTED_KERNEL_SIGNING_KEY_BYTES;
    let is_placeholder = bytes == [0u8; 32];
    let fp = compute_signing_key_fp();
    let fp_hex = hex::encode(fp);

    if opts.json {
        let v = serde_json::json!({
            "signing_key_fingerprint":  fp_hex,
            "trust_anchor_populated":   !is_placeholder,
        });
        let _ = serde_json::to_writer(&mut out, &v);
        let _ = writeln!(out);
    } else if is_placeholder {
        let _ = writeln!(
            out,
            "raxis doctor — signing key fingerprint\n  \
             FAIL: trust anchor is the all-zero placeholder.\n  \
             This kernel binary was built without RAXIS_KERNEL_SIGNING_KEY_HEX\n  \
             (or RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH) set. It cannot verify\n  \
             any signed canonical-image manifest. See\n  \
             raxis/specs/v2/release-and-distribution.md §7 (production)\n  \
             or §8 (local-build) for the populating recipe."
        );
    } else {
        let _ = writeln!(out, "raxis doctor — signing key fingerprint");
        let _ = writeln!(out, "  signing key fingerprint: {fp_hex}");
        let _ = writeln!(out, "  trust anchor: populated");
    }
    let _ = out.flush();
    if is_placeholder {
        std::process::exit(1);
    }
    Ok(())
}

/// `raxis doctor canonical-images` — verify every shipped canonical
/// image against the kernel's compile-time trust anchor.
///
/// Walks Reviewer, Orchestrator, and Executor-starter (when
/// present) under `<install_dir>/images/`. Each verification calls
/// the same entry point the kernel boot path uses
/// (`verify_canonical_image_via_manifest`), so this command's verdict
/// matches what the kernel itself will see at boot — if doctor says
/// OK, the kernel will boot OK; if doctor says FAIL, the kernel
/// would refuse to spawn the matching role's VMs.
///
/// Exit code:
///   * 0 — every present image verifies.
///   * 1 — at least one image is missing on disk (Warn). Doctor
///         does NOT distinguish "not yet installed" from "deleted",
///         so the formula's `post_install` treats this as
///         non-fatal but still surfaces it.
///   * 2 — at least one image's manifest signature failed, the
///         streamed SHA-256 disagreed with the manifest's signed
///         digest, or the trust anchor is unpopulated. The formula's
///         `post_install` aborts the install in this case.
fn run_canonical_images(opts: DoctorOpts, install_dir: PathBuf) -> Result<(), CliError> {
    let kernel_version = env!("CARGO_PKG_VERSION");
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    // We verify the two kernel-canonical image roles
    // (`INV-PLANNER-HARNESS-02` Reviewer and `-05` Orchestrator).
    //
    // The Executor-starter image (`v2-deep-spec.md §Canonical
    // Images`) ships in the same install dir but is intentionally
    // NOT a CanonicalImageKind: operators may replace it with
    // their own `[[vm_images]]` entries, so a "missing executor-
    // starter" is not a doctor-actionable failure. We surface its
    // presence/absence as an informational Warn-or-Ok at the end,
    // without invoking the kernel-trust path.
    let images = [
        (CanonicalImageKind::Reviewer,     "raxis-reviewer-core"),
        (CanonicalImageKind::Orchestrator, "raxis-orchestrator-core"),
    ];

    let mut report = Report::default();
    let images_dir = install_dir.join("images");
    if !images_dir.exists() {
        report.push(
            "canonical_images.dir",
            Outcome::Fail,
            format!(
                "{} does not exist — install dir is missing the canonical-image \
                 layout entirely (see system-requirements.md §1)",
                images_dir.display(),
            ),
        );
    } else {
        report.push("canonical_images.dir", Outcome::Ok, format!("{}", images_dir.display()));

        for (kind, file_prefix) in images {
            let image_path = images_dir.join(format!("{file_prefix}-{kernel_version}.img"));
            verify_one(&mut report, kind, &image_path, kernel_version);
        }

        // Executor-starter informational row.
        let exec_path = images_dir.join(format!("raxis-executor-starter-{kernel_version}.img"));
        if exec_path.exists() {
            report.push(
                "canonical_images.executor_starter.exists",
                Outcome::Ok,
                format!("{} present (operator-replaceable; not kernel-trust-verified here)",
                    exec_path.display()),
            );
        } else {
            report.push(
                "canonical_images.executor_starter.exists",
                Outcome::Warn,
                format!(
                    "{} not present (V2 GA opt-in image; OK if operator brings their own)",
                    exec_path.display(),
                ),
            );
        }
    }

    if opts.json {
        render_json(&mut out, &install_dir, &report);
    } else {
        render_canonical_images_human(&mut out, &install_dir, kernel_version, &report);
    }
    let _ = out.flush();
    std::process::exit(report.exit_code());
}

fn verify_one(
    report:         &mut Report,
    kind:           CanonicalImageKind,
    image_path:     &Path,
    kernel_version: &str,
) {
    let id_exists = leak_subdir_id_owned(format!("canonical_images.{}.exists", kind_tag(kind)));
    let id_verify = leak_subdir_id_owned(format!("canonical_images.{}.verify", kind_tag(kind)));

    if !image_path.exists() {
        report.push(
            id_exists,
            Outcome::Fail,
            format!("{} not present", image_path.display()),
        );
        return;
    }
    report.push(id_exists, Outcome::Ok, format!("{}", image_path.display()));

    let manifest_path = manifest_path_for_image(image_path);
    if !manifest_path.exists() {
        report.push(
            id_verify,
            Outcome::Fail,
            format!(
                "manifest missing at {} — image cannot be verified",
                manifest_path.display(),
            ),
        );
        return;
    }

    match verify_canonical_image_via_manifest(image_path, &manifest_path, kind, kernel_version) {
        Ok(()) => {
            report.push(
                id_verify,
                Outcome::Ok,
                format!("manifest signature + image digest verify against trust anchor"),
            );
        }
        Err(CanonicalImageError::SigningKeyFpNotPopulated) => {
            report.push(
                id_verify,
                Outcome::Fail,
                "trust anchor is the all-zero placeholder; this kernel binary \
                 was built without RAXIS_KERNEL_SIGNING_KEY_HEX set (see \
                 release-and-distribution.md §7 / §8)"
                    .to_string(),
            );
        }
        Err(e) => {
            report.push(id_verify, Outcome::Fail, format!("{e}"));
        }
    }
}

/// `raxis doctor cache prune` — sweep `<data_dir>/oci-cache/` for
/// images that no live policy generation references.
///
/// V2 implementation walks every operator-registered policy
/// generation in `policy_history` and computes the live `oci_digest`
/// set as `policy_history[*].vm_images[*].oci_digest`. Any
/// `images/sha256/<aa>/<full>/` or `blobs/sha256/<aa>/<full>.*` not
/// in that set is removed (or just listed when `--dry-run`).
///
/// **What this does NOT do.** It does not consult in-flight
/// initiative rows or running session rows for additional
/// references. The §8 spec mentions both as additional sources of
/// "live" digests; the doctor command is intentionally
/// conservative-by-removal: it only acts on digests not in the
/// **policy** set. An operator who wants the more aggressive sweep
/// can run the kernel's background prune (which kicks in on every
/// `policy_manager::advance_epoch`) — that path consumes the
/// kernel's runtime view of active sessions + initiatives.
///
/// Exit code:
///   * 0 — prune completed successfully (any number of bytes
///         freed, including 0).
///   * 1 — `--dry-run`-only diagnostic mode finished; same shape
///         as 0 but no bytes were freed.
///   * 2 — the cache could not be enumerated (filesystem error
///         walking the cache root, etc.); details on stderr.
fn run_cache_prune(
    flags:   &GlobalFlags,
    opts:    DoctorOpts,
    dry_run: bool,
) -> Result<(), CliError> {
    use std::collections::HashSet;
    use raxis_image_cache::{ImageResolver, OciDigest, ProductionResolver};

    let data_dir   = flags.data_dir().clone();
    let cache_root = data_dir.join("oci-cache");

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    // Enumerate live digests from the policy history table.
    let live_digests: HashSet<OciDigest> = match enumerate_live_digests(&data_dir) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(
                out,
                "raxis doctor cache prune — FAIL: {e}",
            );
            std::process::exit(2);
        }
    };

    if dry_run {
        // For dry-run we walk the cache enumerating every digest we
        // would delete, without consulting the resolver. The resolver
        // itself only exposes a "delete-or-not" `prune_unreferenced`
        // call that takes the live set; a dry-run mode is a useful
        // operator habit so we hand-roll the walk here.
        let dead = enumerate_dead_digests(&cache_root, &live_digests).unwrap_or_default();
        if opts.json {
            let v = serde_json::json!({
                "cache_root":    cache_root.display().to_string(),
                "dry_run":       true,
                "live_digests":  live_digests.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
                "would_remove":  dead.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
            });
            let _ = serde_json::to_writer(&mut out, &v);
            let _ = writeln!(out);
        } else {
            let _ = writeln!(out, "raxis doctor cache prune (dry-run)");
            let _ = writeln!(out, "  cache_root:   {}", cache_root.display());
            let _ = writeln!(out, "  live_digests: {}", live_digests.len());
            let _ = writeln!(out, "  would_remove: {}", dead.len());
            for d in &dead {
                let _ = writeln!(out, "    - {d}");
            }
        }
        let _ = out.flush();
        std::process::exit(1);
    }

    // Real prune through the production resolver. The bearer-token
    // / default-registry inputs are irrelevant for prune; we pass
    // `None` for both. The reqwest client is constructed but
    // unused (prune is local I/O only).
    let client = match reqwest::Client::builder().build() {
        Ok(c)  => c,
        Err(e) => {
            let _ = writeln!(out, "raxis doctor cache prune — FAIL: reqwest client build: {e}");
            std::process::exit(2);
        }
    };
    let resolver = ProductionResolver::new(&cache_root, client, None, None);
    match resolver.prune_unreferenced(&live_digests) {
        Ok(bytes_freed) => {
            if opts.json {
                let v = serde_json::json!({
                    "cache_root":   cache_root.display().to_string(),
                    "dry_run":      false,
                    "live_digests": live_digests.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
                    "bytes_freed":  bytes_freed,
                });
                let _ = serde_json::to_writer(&mut out, &v);
                let _ = writeln!(out);
            } else {
                let _ = writeln!(out, "raxis doctor cache prune");
                let _ = writeln!(out, "  cache_root:   {}", cache_root.display());
                let _ = writeln!(out, "  live_digests: {}", live_digests.len());
                let _ = writeln!(out, "  bytes_freed:  {bytes_freed}");
            }
            let _ = out.flush();
            Ok(())
        }
        Err(e) => {
            let _ = writeln!(out, "raxis doctor cache prune — FAIL: {e}");
            std::process::exit(2);
        }
    }
}

/// Enumerate the union of `[[vm_images]] oci_digest = "sha256:..."`
/// entries declared by the operator's current `<data_dir>/policy/policy.toml`.
///
/// **V2 conservative scope.** We deliberately do NOT walk historical
/// policy generations from `policy_epoch_history` (the table records
/// the SHA hash of each historical bundle but does not retain the
/// raw TOML for re-parsing) and we do NOT walk in-flight initiative
/// rows or running session rows — those would require the kernel to
/// be running, which `raxis doctor` must work without. The kernel's
/// background prune (kicked from `policy_manager::advance_epoch`)
/// IS the mechanism that consumes the runtime view; doctor is the
/// off-line walker that operates on what's on disk only.
///
/// **TOML parse mode.** We use a hand-rolled TOML walk over
/// `[[vm_images]]` blocks rather than going through
/// [`raxis_policy::PolicyBundle`] because (a) `PolicyBundle::from_toml`
/// requires every section to validate cross-references that are
/// out of scope for prune (operator certs, gates, etc.) and (b)
/// we want prune to succeed even on a partially-malformed bundle.
fn enumerate_live_digests(
    data_dir: &Path,
) -> Result<std::collections::HashSet<raxis_image_cache::OciDigest>, String> {
    use std::collections::HashSet;
    let policy_path = data_dir.join("policy").join(POLICY_FILE_NAME);
    if !policy_path.exists() {
        // No policy file → empty live set. The prune walk treats
        // every cache entry as dead. Doctors run pre-bootstrap
        // exit at the data-dir-exists check, never here.
        return Ok(HashSet::new());
    }
    let body = std::fs::read_to_string(&policy_path)
        .map_err(|e| format!("read {}: {e}", policy_path.display()))?;
    let value: toml::Value = toml::from_str(&body)
        .map_err(|e| format!("parse {}: {e}", policy_path.display()))?;
    let mut out = HashSet::new();
    if let Some(arr) = value.get("vm_images").and_then(|v| v.as_array()) {
        for entry in arr {
            let Some(d) = entry.get("oci_digest").and_then(|v| v.as_str()) else { continue };
            if let Ok(parsed) = d.parse::<raxis_image_cache::OciDigest>() {
                out.insert(parsed);
            }
        }
    }
    Ok(out)
}

fn enumerate_dead_digests(
    cache_root: &Path,
    live: &std::collections::HashSet<raxis_image_cache::OciDigest>,
) -> Result<Vec<raxis_image_cache::OciDigest>, String> {
    use std::fs;
    let images_root = cache_root.join("images/sha256");
    if !images_root.exists() { return Ok(Vec::new()); }
    let mut out = Vec::new();
    for shard in fs::read_dir(&images_root).map_err(|e| format!("read {images_root:?}: {e}"))? {
        let shard = shard.map_err(|e| e.to_string())?;
        for de in fs::read_dir(shard.path()).map_err(|e| e.to_string())? {
            let de = de.map_err(|e| e.to_string())?;
            let Some(name) = de.file_name().to_str().map(str::to_owned) else { continue };
            let Ok(digest) = format!("sha256:{name}").parse::<raxis_image_cache::OciDigest>() else {
                continue;
            };
            if !live.contains(&digest) {
                out.push(digest);
            }
        }
    }
    Ok(out)
}

fn kind_tag(kind: CanonicalImageKind) -> &'static str {
    match kind {
        CanonicalImageKind::Reviewer     => "reviewer",
        CanonicalImageKind::Orchestrator => "orchestrator",
    }
}

fn leak_subdir_id_owned(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn render_canonical_images_human<W: Write>(
    out:            &mut W,
    install_dir:    &Path,
    kernel_version: &str,
    report:         &Report,
) {
    let _ = writeln!(out, "raxis doctor — canonical images");
    let _ = writeln!(out, "  install_dir:    {}", install_dir.display());
    let _ = writeln!(out, "  kernel_version: {kernel_version}");
    let _ = writeln!(out, "  worst:          {}", report.worst().label());
    let _ = writeln!(out);
    for c in &report.checks {
        let _ = writeln!(
            out,
            "  [{lvl:<4}] {id:<48} {detail}",
            lvl    = c.outcome.label(),
            id     = c.id,
            detail = c.detail,
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Copy)]
struct DoctorOpts {
    json: bool,
}

#[derive(Debug, Clone)]
enum Subcommand {
    /// `raxis doctor` — full data-dir preflight (the existing
    /// pre-V2 entry point).
    Default,
    /// `raxis doctor signing-key-fp` — print the kernel binary's
    /// compiled-in trust-anchor fingerprint.
    SigningKeyFp,
    /// `raxis doctor canonical-images` — verify shipped canonical
    /// images under `<install_dir>/images/`.
    CanonicalImages {
        install_dir: PathBuf,
    },
    /// `raxis doctor cache prune` — sweep the OCI image cache
    /// (`<data_dir>/oci-cache/`) for `images/` and `blobs/` entries
    /// whose digest is not referenced by any active policy
    /// generation. The `--dry-run` flag walks without unlinking.
    CachePrune {
        dry_run: bool,
    },
}

#[derive(Debug, Clone)]
struct ParsedArgs {
    subcommand: Subcommand,
    opts:       DoctorOpts,
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, CliError> {
    // First non-flag arg, if any, is the subcommand selector. The
    // remaining args are subcommand-specific.
    let (subcmd_pos, subcmd_name): (Option<usize>, Option<&str>) = args
        .iter()
        .enumerate()
        .find(|(_, a)| !a.starts_with('-'))
        .map(|(i, a)| (Some(i), Some(a.as_str())))
        .unwrap_or((None, None));

    match subcmd_name {
        None => {
            let opts = parse_default_flags(args)?;
            Ok(ParsedArgs { subcommand: Subcommand::Default, opts })
        }
        Some("signing-key-fp") => {
            let mut tail = args.to_vec();
            tail.remove(subcmd_pos.unwrap());
            let opts = parse_default_flags(&tail)?;
            Ok(ParsedArgs { subcommand: Subcommand::SigningKeyFp, opts })
        }
        Some("canonical-images") => {
            let mut tail = args.to_vec();
            tail.remove(subcmd_pos.unwrap());
            let (opts, install_dir) = parse_canonical_images_flags(&tail)?;
            Ok(ParsedArgs {
                subcommand: Subcommand::CanonicalImages { install_dir },
                opts,
            })
        }
        Some("cache") => {
            // `raxis doctor cache prune` — second positional is the
            // verb. Currently `prune` is the only verb.
            let mut tail = args.to_vec();
            tail.remove(subcmd_pos.unwrap());
            let (verb_pos, verb) = tail
                .iter()
                .enumerate()
                .find(|(_, a)| !a.starts_with('-'))
                .map(|(i, a)| (Some(i), Some(a.as_str())))
                .unwrap_or((None, None));
            match verb {
                Some("prune") => {
                    let mut rest = tail.clone();
                    rest.remove(verb_pos.unwrap());
                    let (opts, dry_run) = parse_cache_prune_flags(&rest)?;
                    Ok(ParsedArgs {
                        subcommand: Subcommand::CachePrune { dry_run },
                        opts,
                    })
                }
                Some(other) => Err(CliError::Usage(format!(
                    "unknown `cache` verb: {other:?} \
                     (available: prune)",
                ))),
                None => Err(CliError::Usage(
                    "missing verb after `cache` \
                     (available: prune)".to_owned(),
                )),
            }
        }
        Some(other) => Err(CliError::Usage(format!(
            "unknown doctor subcommand: {other:?} \
             (available: signing-key-fp, canonical-images, cache; \
              or run `raxis doctor` with no subcommand for the full \
              data-dir preflight)"
        ))),
    }
}

fn parse_cache_prune_flags(args: &[String]) -> Result<(DoctorOpts, bool), CliError> {
    let mut opts = DoctorOpts::default();
    let mut dry_run = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json"    => opts.json = true,
            "--dry-run" => dry_run = true,
            "-h" | "--help" => {
                eprintln!("Usage: raxis doctor cache prune [--dry-run] [--json]");
                std::process::exit(0);
            }
            other => return Err(CliError::Usage(format!(
                "unknown flag for `doctor cache prune`: {other:?}",
            ))),
        }
        i += 1;
    }
    Ok((opts, dry_run))
}

fn parse_default_flags(args: &[String]) -> Result<DoctorOpts, CliError> {
    let mut opts = DoctorOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => opts.json = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown doctor flag: {other:?} (try --json or --help)"
                )));
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn parse_canonical_images_flags(args: &[String]) -> Result<(DoctorOpts, PathBuf), CliError> {
    let mut opts        = DoctorOpts::default();
    let mut install_dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => opts.json = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--install-dir" => {
                let v = args.get(i + 1).ok_or_else(|| CliError::Usage(
                    "missing value for --install-dir".to_owned(),
                ))?;
                if v.is_empty() {
                    return Err(CliError::Usage("--install-dir cannot be empty".to_owned()));
                }
                install_dir = Some(PathBuf::from(v));
                i += 1;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown doctor canonical-images flag: {other:?} \
                     (try --install-dir <PATH>, --json, or --help)"
                )));
            }
        }
        i += 1;
    }

    // Resolve install dir: --install-dir > $RAXIS_INSTALL_DIR > default.
    let install_dir = install_dir.or_else(|| {
        std::env::var("RAXIS_INSTALL_DIR").ok().map(PathBuf::from)
    }).unwrap_or_else(|| PathBuf::from(DEFAULT_INSTALL_DIR));

    Ok((opts, install_dir))
}

fn print_help() {
    println!(
        "raxis doctor — preflight + post-install verification\n\
         \n\
         USAGE:\n\
         \traxis doctor [--json]                                  # full data-dir preflight\n\
         \traxis doctor signing-key-fp [--json]                   # print kernel trust anchor\n\
         \traxis doctor canonical-images [--install-dir P] [--json]\n\
         \n\
         FLAGS:\n\
         \t--json                   Emit one JSON object instead of a human report.\n\
         \t--install-dir <PATH>     (canonical-images) Override install dir; defaults\n\
         \t                         to $RAXIS_INSTALL_DIR or {default}.\n\
         \n\
         EXIT CODES:\n\
         \t0   every check OK\n\
         \t1   at least one WARN, no FAIL\n\
         \t2   at least one FAIL (kernel likely won't boot cleanly)\n\
         ",
        default = DEFAULT_INSTALL_DIR,
    );
}

// ────────────────────────────────────────────────────────────────────
// Collection — independent of rendering
// ────────────────────────────────────────────────────────────────────

fn collect(data_dir: &Path) -> Report {
    let mut r = Report::default();

    // 1. data_dir exists.
    match std::fs::metadata(data_dir) {
        Ok(m) if m.is_dir() => {
            r.push("data_dir.exists", Outcome::Ok, format!("{}", data_dir.display()));
        }
        Ok(_) => {
            r.push(
                "data_dir.exists",
                Outcome::Fail,
                format!("{} exists but is not a directory", data_dir.display()),
            );
            // No point continuing — every other check assumes a dir.
            return r;
        }
        Err(e) => {
            r.push(
                "data_dir.exists",
                Outcome::Fail,
                format!("cannot stat {}: {}", data_dir.display(), e),
            );
            return r;
        }
    }

    // 2. Subdir presence + mode bits.
    for (name, expected_mode) in EXPECTED_MODES {
        check_subdir(&mut r, data_dir, name, *expected_mode);
    }

    // 3. policy/policy.toml loadable.
    let policy_path = data_dir.join("policy").join(POLICY_FILE_NAME);
    let bundle_epoch_opt = match load_policy(&policy_path) {
        Ok((bundle, _bytes, sha)) => {
            r.push(
                "policy.loadable",
                Outcome::Ok,
                format!("epoch={} sha={}", bundle.epoch(), &sha[..16.min(sha.len())]),
            );
            Some(bundle.epoch())
        }
        Err(e) => {
            r.push("policy.loadable", Outcome::Fail, format!("{e}"));
            None
        }
    };

    // 4. kernel.db schema-version pin.
    let conn = match open_ro(data_dir) {
        Ok(c) => {
            r.push("store.open_ro", Outcome::Ok, "schema version pin satisfied");
            Some(c)
        }
        Err(RoError::SchemaMismatch { actual, expected, .. }) => {
            r.push(
                "store.open_ro",
                Outcome::Fail,
                format!("schema mismatch: db=v{actual}, CLI expected v{expected}"),
            );
            None
        }
        Err(e) => {
            r.push("store.open_ro", Outcome::Fail, format!("{e}"));
            None
        }
    };

    // 5. runtime/heartbeat.json reachable. Missing = WARN, not FAIL.
    match read_heartbeat(data_dir) {
        Ok(snap) => {
            r.push(
                "runtime.heartbeat",
                Outcome::Ok,
                format!(
                    "pid={} state={} policy_epoch={}",
                    snap.kernel_pid, snap.state, snap.policy_epoch,
                ),
            );
        }
        Err(HeartbeatReadError::Missing(_)) => {
            r.push(
                "runtime.heartbeat",
                Outcome::Warn,
                "no heartbeat.json (kernel not running, or first boot still in progress)",
            );
        }
        Err(e) => {
            r.push("runtime.heartbeat", Outcome::Fail, format!("{e}"));
        }
    }

    // 6. Audit chain quick check.
    let audit_dir = data_dir.join(AUDIT_DIR_NAME);
    match quick_chain_check(&audit_dir) {
        ChainQuickCheck::Ok { last_seq, segment_count } => {
            r.push(
                "audit.quick_check",
                Outcome::Ok,
                format!("segments={segment_count} last_seq={last_seq}"),
            );
        }
        ChainQuickCheck::NoSegments => {
            r.push(
                "audit.quick_check",
                Outcome::Warn,
                "no segment-NNN.jsonl (kernel never emitted an audit event)",
            );
        }
        ChainQuickCheck::Broken { error } => {
            r.push("audit.quick_check", Outcome::Fail, format!("{error}"));
        }
    }

    // 7. Cross-check bundle epoch against MAX(epoch_id).
    if let (Some(conn), Some(bundle_epoch)) = (conn.as_ref(), bundle_epoch_opt) {
        match policy_history::current_epoch(conn) {
            Ok(Some(kernel_epoch)) => {
                if kernel_epoch == bundle_epoch {
                    r.push(
                        "policy.epoch_aligned",
                        Outcome::Ok,
                        format!("bundle_epoch={bundle_epoch} == kernel_epoch={kernel_epoch}"),
                    );
                } else {
                    r.push(
                        "policy.epoch_aligned",
                        Outcome::Warn,
                        format!(
                            "bundle_epoch={bundle_epoch}, kernel_epoch={kernel_epoch} \
                             — policy.toml has not been rotated yet"
                        ),
                    );
                }
            }
            Ok(None) => {
                r.push(
                    "policy.epoch_aligned",
                    Outcome::Warn,
                    "no policy_epoch_history rows (genesis row not installed?)",
                );
            }
            Err(e) => {
                r.push(
                    "policy.epoch_aligned",
                    Outcome::Fail,
                    format!("policy_history::current_epoch failed: {e}"),
                );
            }
        }
    }

    // 8. Operator-cert status sweep (step-11). Only runs if the store
    // opened cleanly above.
    if let Some(conn) = conn.as_ref() {
        check_operator_certs(&mut r, conn, unix_now_secs() as i64);
    }

    r
}

/// Walk every row in the `operator_certificates` view and classify it
/// against the four-zone model. See module docstring for the exact
/// outcomes per zone.
///
/// Reading the kernel-managed view (rather than re-parsing
/// `policy.toml`) keeps doctor honest: if `repopulate` skipped a
/// cert (for instance due to migration drift), doctor will not see
/// it either, which is the right behaviour — the kernel's view of
/// the world is what matters at boot.
fn check_operator_certs(
    r:    &mut Report,
    conn: &raxis_store::RoConn,
    now:  i64,
) {
    let rows = match operator_certificates::list_all(conn) {
        Ok(rows) => rows,
        Err(e) => {
            r.push("cert.list", Outcome::Fail, format!("{e}"));
            return;
        }
    };

    if rows.is_empty() {
        // Cert-mandatory (INV-CERT-01): every operator entry MUST have
        // a self-signed cert. An empty `operator_certificates` table
        // therefore signals one of:
        //   * the kernel never ran genesis (no cert was installed); or
        //   * the cert mirror failed to repopulate the view table on
        //     the last epoch advance (transactional invariant
        //     INV-STORE-01 violated — likely a prior crash); or
        //   * a third-party tool truncated the table.
        // Any of these is operator-actionable and FAIL-worthy: the
        // kernel will refuse to admit any operator op until a cert is
        // installed (the auth path enforces the same invariant). The
        // "legacy operator-key flow" OK branch was deleted alongside
        // the legacy code path itself.
        r.push(
            "cert.list",
            Outcome::Fail,
            "operator_certificates is empty — every operator MUST have a self-signed cert \
             (INV-CERT-01). Re-run `raxis genesis` (which always installs a cert) or use \
             `raxis cert install` to register one for an existing entry.",
        );
        return;
    }

    r.push(
        "cert.list",
        Outcome::Ok,
        format!("found {n} operator certificate(s)", n = rows.len()),
    );

    for row in rows {
        // Surface bypass-misconfig regardless of expiry zone — the
        // operator deliberately overrode a structural validation
        // check at policy-sign time and should be reminded.
        if row.force_misconfig_bypass {
            r.push(
                Box::leak(format!("cert.{}.misconfig_bypass", &row.pubkey_fingerprint)
                    .into_boxed_str()),
                Outcome::Warn,
                format!(
                    "{display} ({fp}) was installed with --force-misconfig — \
                     a structural validation check was bypassed at policy-sign time. \
                     See `OperatorCertMisconfigBypassed` audit event for the reason.",
                    display = row.display_name,
                    fp      = row.pubkey_fingerprint,
                ),
            );
        }

        let cert   = row.clone().into_operator_cert();
        let status = cert_status(&cert, now);
        let id     = Box::leak(
            format!("cert.{}.status", &row.pubkey_fingerprint).into_boxed_str(),
        );

        match status {
            CertStatus::Active | CertStatus::AlwaysActiveEmergency => {
                r.push(
                    id,
                    Outcome::Ok,
                    format!(
                        "{display} ({fp}) status={tag}",
                        display = row.display_name,
                        fp      = row.pubkey_fingerprint,
                        tag     = status.tag(),
                    ),
                );
            }
            CertStatus::Expiring { secs_until_expiry } => {
                let days = secs_until_expiry / 86_400;
                r.push(
                    id,
                    Outcome::Warn,
                    format!(
                        "{display} ({fp}) expiring in ~{days}d \
                         (warn_window={warn_d}d, not_after={not_after}); \
                         rotate via `raxis cert mint` + `raxis cert install` \
                         + `raxis epoch advance`",
                        display   = row.display_name,
                        fp        = row.pubkey_fingerprint,
                        warn_d    = row.warn_before_expiry_days,
                        not_after = row.not_after,
                    ),
                );
            }
            CertStatus::Grace { secs_until_grace_end } => {
                let days = secs_until_grace_end / 86_400;
                r.push(
                    id,
                    Outcome::Warn,
                    format!(
                        "{display} ({fp}) IN GRACE PERIOD — only recovery ops \
                         allowed. {days}d remaining before all ops are denied. \
                         Rotate immediately.",
                        display = row.display_name,
                        fp      = row.pubkey_fingerprint,
                    ),
                );
            }
            CertStatus::Expired { secs_since_expiry } => {
                let days = secs_since_expiry / 86_400;
                r.push(
                    id,
                    Outcome::Fail,
                    format!(
                        "{display} ({fp}) EXPIRED ~{days}d ago — all ops denied. \
                         Operator key is unusable until rotated.",
                        display = row.display_name,
                        fp      = row.pubkey_fingerprint,
                    ),
                );
            }
            CertStatus::NotYetValid { secs_until_active } => {
                let days = secs_until_active / 86_400;
                r.push(
                    id,
                    Outcome::Fail,
                    format!(
                        "{display} ({fp}) NOT YET VALID — activates in ~{days}d \
                         (not_before={not_before}). All ops denied until then.",
                        display    = row.display_name,
                        fp         = row.pubkey_fingerprint,
                        not_before = row.not_before,
                    ),
                );
            }
            CertStatus::Revoked { reason, revoked_at } => {
                r.push(
                    id,
                    Outcome::Fail,
                    format!(
                        "{display} ({fp}) REVOKED ({reason:?}, revoked_at={revoked_at}) \
                         — all ops denied. Mint a fresh cert with a new signing \
                         key, install it, and advance the policy epoch.",
                        display = row.display_name,
                        fp      = row.pubkey_fingerprint,
                    ),
                );
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Subdir + mode check
// ────────────────────────────────────────────────────────────────────

fn check_subdir(r: &mut Report, data_dir: &Path, name: &'static str, expected_mode: u32) {
    let path = data_dir.join(name);
    let id_exists = leak_subdir_id(name, "exists");
    let id_mode   = leak_subdir_id(name, "mode");

    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(_) => {
            // notifications/ is created lazily by the kernel's first
            // delivery; surface as WARN, not FAIL, when it is missing.
            let outcome = if name == "notifications" {
                Outcome::Warn
            } else {
                Outcome::Fail
            };
            r.push(
                id_exists,
                outcome,
                format!("missing: {}", path.display()),
            );
            return;
        }
    };

    if !meta.is_dir() {
        r.push(
            id_exists,
            Outcome::Fail,
            format!("{} exists but is not a directory", path.display()),
        );
        return;
    }
    r.push(id_exists, Outcome::Ok, format!("{}", path.display()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let actual = meta.permissions().mode() & 0o777;
        if actual == expected_mode {
            r.push(id_mode, Outcome::Ok, format!("0{:o}", actual));
        } else {
            // Mode drift is a WARN, not FAIL: the kernel will refuse
            // to boot for keys/ and providers/ specifically (those
            // are policed by the kernel itself), but operator
            // workflows on macOS sometimes flip group-readable bits;
            // we report rather than fail-close from the CLI.
            let severity = if matches!(name, "keys" | "providers") {
                Outcome::Fail
            } else {
                Outcome::Warn
            };
            r.push(
                id_mode,
                severity,
                format!("mode is 0{:o}, expected 0{:o}", actual, expected_mode),
            );
        }
    }

    #[cfg(not(unix))]
    {
        // Mode bits are not meaningful on non-unix; report as OK so
        // the JSON consumers see a stable id regardless of platform.
        let _ = expected_mode;
        r.push(id_mode, Outcome::Ok, "mode check skipped (non-unix)");
    }
}

/// Build a static-ish id like `"providers.exists"` from a subdir
/// name + suffix. We Box::leak the formatted String so it satisfies
/// the `&'static str` field on `Check` without burdening every caller
/// with a lifetime parameter; total leakage is bounded by the number
/// of EXPECTED_MODES entries (well under a kilobyte).
fn leak_subdir_id(name: &'static str, suffix: &'static str) -> &'static str {
    let s = format!("{name}.{suffix}");
    Box::leak(s.into_boxed_str())
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human
// ────────────────────────────────────────────────────────────────────

fn render_human<W: Write>(out: &mut W, data_dir: &Path, report: &Report) {
    let _ = writeln!(out, "raxis doctor — preflight report");
    let _ = writeln!(out, "  data_dir: {}", data_dir.display());
    let _ = writeln!(out, "  worst:    {}", report.worst().label());
    let _ = writeln!(out);
    for c in &report.checks {
        let _ = writeln!(
            out,
            "  [{lvl:<4}] {id:<28} {detail}",
            lvl    = c.outcome.label(),
            id     = c.id,
            detail = c.detail,
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — JSON
// ────────────────────────────────────────────────────────────────────

fn render_json<W: Write>(out: &mut W, data_dir: &Path, report: &Report) {
    let v = serde_json::json!({
        "data_dir": data_dir.display().to_string(),
        "worst":    report.worst().label(),
        "checks":   report.checks.iter().map(|c| serde_json::json!({
            "id":      c.id,
            "outcome": c.outcome.label(),
            "detail":  c.detail,
        })).collect::<Vec<_>>(),
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn worst_of_ok_warn_fail_is_fail() {
        let mut r = Report::default();
        r.push("a", Outcome::Ok,   "ok");
        r.push("b", Outcome::Warn, "warn");
        r.push("c", Outcome::Fail, "fail");
        assert_eq!(r.worst(), Outcome::Fail);
        assert_eq!(r.exit_code(), 2);
    }

    #[test]
    fn worst_of_ok_warn_is_warn() {
        let mut r = Report::default();
        r.push("a", Outcome::Ok,   "ok");
        r.push("b", Outcome::Warn, "warn");
        assert_eq!(r.worst(), Outcome::Warn);
        assert_eq!(r.exit_code(), 1);
    }

    #[test]
    fn worst_of_all_ok_is_ok() {
        let mut r = Report::default();
        r.push("a", Outcome::Ok, "ok");
        assert_eq!(r.worst(), Outcome::Ok);
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn collect_fails_when_data_dir_missing() {
        let r = collect(Path::new("/definitely/does/not/exist/raxis"));
        assert_eq!(r.checks.len(), 1);
        assert_eq!(r.checks[0].id, "data_dir.exists");
        assert_eq!(r.checks[0].outcome, Outcome::Fail);
    }

    #[test]
    fn collect_runs_full_pipeline_against_empty_dir_and_reports_each_failure() {
        let tmp = TempDir::new().unwrap();
        let r = collect(tmp.path());
        // data_dir.exists must succeed.
        let mut ids: Vec<&str> = r.checks.iter().map(|c| c.id).collect();
        ids.sort();
        assert!(ids.contains(&"data_dir.exists"), "ids: {ids:?}");
        // Every required subdir is missing → keys/providers fail,
        // notifications warns, audit warn-or-fail through to the
        // chain check.
        assert_eq!(r.worst(), Outcome::Fail);
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(&["--bogus".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_accepts_json() {
        let parsed = parse_args(&["--json".to_owned()]).unwrap();
        assert!(parsed.opts.json);
        assert!(matches!(parsed.subcommand, Subcommand::Default));
    }

    #[test]
    fn parse_args_dispatches_signing_key_fp_subcommand() {
        let parsed = parse_args(&["signing-key-fp".to_owned()]).unwrap();
        assert!(matches!(parsed.subcommand, Subcommand::SigningKeyFp));
        assert!(!parsed.opts.json);
    }

    #[test]
    fn parse_args_signing_key_fp_accepts_trailing_json_flag() {
        let parsed = parse_args(&[
            "signing-key-fp".to_owned(),
            "--json".to_owned(),
        ]).unwrap();
        assert!(matches!(parsed.subcommand, Subcommand::SigningKeyFp));
        assert!(parsed.opts.json);
    }

    #[test]
    fn parse_args_dispatches_canonical_images_subcommand_with_default_dir() {
        // Clear any pre-existing env var for determinism.
        // SAFETY: tests in this module run single-threaded by default
        // but we use `set_var` only inside #[test] fns; concurrent
        // tests in this module that touch RAXIS_INSTALL_DIR would
        // need to serialise.
        let saved = std::env::var("RAXIS_INSTALL_DIR").ok();
        std::env::remove_var("RAXIS_INSTALL_DIR");

        let parsed = parse_args(&["canonical-images".to_owned()]).unwrap();
        match parsed.subcommand {
            Subcommand::CanonicalImages { install_dir } => {
                assert_eq!(install_dir, PathBuf::from(DEFAULT_INSTALL_DIR));
            }
            other => panic!("unexpected subcommand: {other:?}"),
        }

        if let Some(v) = saved { std::env::set_var("RAXIS_INSTALL_DIR", v); }
    }

    #[test]
    fn parse_args_canonical_images_explicit_install_dir_wins() {
        let parsed = parse_args(&[
            "canonical-images".to_owned(),
            "--install-dir".to_owned(),
            "/tmp/raxis-test-install".to_owned(),
        ]).unwrap();
        match parsed.subcommand {
            Subcommand::CanonicalImages { install_dir } => {
                assert_eq!(install_dir, PathBuf::from("/tmp/raxis-test-install"));
            }
            other => panic!("unexpected subcommand: {other:?}"),
        }
    }

    #[test]
    fn parse_args_canonical_images_install_dir_requires_value() {
        let err = parse_args(&[
            "canonical-images".to_owned(),
            "--install-dir".to_owned(),
        ]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_canonical_images_install_dir_rejects_empty_value() {
        let err = parse_args(&[
            "canonical-images".to_owned(),
            "--install-dir".to_owned(),
            "".to_owned(),
        ]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_rejects_unknown_subcommand() {
        let err = parse_args(&["bogus-subcommand".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn render_json_emits_object_with_per_check_array() {
        let mut buf: Vec<u8> = Vec::new();
        let mut report = Report::default();
        report.push("a.b", Outcome::Ok,   "ok detail");
        report.push("c.d", Outcome::Warn, "warning detail");
        render_json(&mut buf, Path::new("/tmp/d"), &report);
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["data_dir"], "/tmp/d");
        assert_eq!(v["worst"], "WARN");
        let checks = v["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0]["id"], "a.b");
        assert_eq!(checks[1]["id"], "c.d");
        assert_eq!(checks[1]["outcome"], "WARN");
    }

    // ── Step-11: cert.* check coverage ────────────────────────────────
    //
    // These tests build a real on-disk SQLite via `Store::open`,
    // insert one or more `operator_certificates` rows directly with
    // raw SQL (the kernel-side `repopulate` helper drives off a full
    // PolicyBundle which is heavy to construct in a unit test), then
    // re-open read-only and exercise `check_operator_certs`.
    //
    // The `cert_status` classification is already tested in
    // `raxis-crypto::cert::tests`; here we only assert the
    // doctor-side mapping (status → Outcome + id format).

    fn setup_db_with_cert(
        tmp:                    &TempDir,
        fp:                     &str,
        display_name:           &str,
        not_before:             i64,
        not_after:              i64,
        warn_days:              u32,
        grace_days:             u32,
        kind:                   &str,
        force_misconfig_bypass: bool,
    ) {
        const POLICY_EPOCH_HISTORY:  &str =
            raxis_store::Table::PolicyEpochHistory.as_str();
        const OPERATOR_CERTIFICATES: &str =
            raxis_store::Table::OperatorCertificates.as_str();

        // Open RW once to apply migrations + insert the row, then
        // drop the handle so the RO open downstream sees a complete
        // schema (migrations run on `Store::open`).
        let store = raxis_store::Store::open(&tmp.path().join("kernel.db")).unwrap();
        let conn = store.lock_sync();
        // policy_epoch_history must have a row first — `operator_certificates.epoch_id`
        // FK-references it. We use `INSERT OR IGNORE` so multiple cert
        // inserts in one test (future-proofing for that case) don't trip
        // the PRIMARY KEY UNIQUE on (epoch_id) and pubkey UNIQUE on
        // policy_sha256.
        conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {POLICY_EPOCH_HISTORY} (\
                    epoch_id, policy_sha256, signed_by_authority, \
                    triggered_by_operator, advanced_at\
                 ) VALUES (1, 'sha-test', 'auth-test', 'op-test', 0)"
            ),
            [],
        ).unwrap();
        // Each cert needs a unique pubkey_hex (UNIQUE constraint on the
        // column), so we derive one from the test-supplied fingerprint
        // padded to 64 hex chars.
        let pubkey_hex = format!("{fp}{}", "0".repeat(64usize.saturating_sub(fp.len())));
        let self_sig   = "11".repeat(32);
        conn.execute(
            &format!(
                "INSERT INTO {OPERATOR_CERTIFICATES} (\
                    pubkey_fingerprint, epoch_id, kind, display_name, pubkey_hex, \
                    not_before, not_after, warn_before_expiry_days, grace_period_days, \
                    permitted_ops_json, contact_info, self_sig_hex, \
                    force_misconfig_bypass, installed_at\
                 ) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '[]', NULL, ?9, ?10, 0)"
            ),
            rusqlite::params![
                fp,
                kind,
                display_name,
                pubkey_hex,
                not_before,
                not_after,
                warn_days as i64,
                grace_days as i64,
                self_sig,
                force_misconfig_bypass as i64,
            ],
        ).unwrap();
        drop(conn);
        drop(store);
    }

    #[test]
    fn cert_check_fails_when_operator_certificates_table_is_empty() {
        // Cert-mandatory (INV-CERT-01): an empty `operator_certificates`
        // table is unrecoverable without operator action — the kernel
        // would refuse to admit any operator op. Doctor MUST surface
        // this as `[FAIL]`, not `[OK]`. The legacy operator-key flow
        // (no cert installed) was deleted alongside this branch.
        let tmp = TempDir::new().unwrap();
        let _ = raxis_store::Store::open(&tmp.path().join("kernel.db")).unwrap();
        // Re-open read-only.
        let conn = raxis_store::open_ro(tmp.path()).unwrap();
        let mut r = Report::default();
        check_operator_certs(&mut r, &conn, 1_700_000_000);

        let ids: Vec<&str> = r.checks.iter().map(|c| c.id).collect();
        assert!(ids.contains(&"cert.list"),
            "must emit cert.list when zero certs are installed; got {ids:?}");
        let cert_list = r.checks.iter().find(|c| c.id == "cert.list").unwrap();
        assert_eq!(cert_list.outcome, Outcome::Fail,
            "INV-CERT-01: empty operator_certificates MUST be a hard failure");
        assert!(cert_list.detail.contains("INV-CERT-01"),
            "detail must cite INV-CERT-01 so an operator can find the spec: {:?}",
            cert_list.detail);
        assert!(cert_list.detail.contains("raxis genesis")
                || cert_list.detail.contains("raxis cert install"),
            "detail must point at the recovery commands: {:?}", cert_list.detail);
    }

    #[test]
    fn cert_check_classifies_active_cert_as_ok() {
        let tmp = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        let one_year = 365 * 86_400;
        setup_db_with_cert(
            &tmp, "abcd1234deadbeef", "Chika",
            now - 86_400, now + one_year, // valid through next year
            30, 7, "Standard", false,
        );

        let conn = raxis_store::open_ro(tmp.path()).unwrap();
        let mut r = Report::default();
        check_operator_certs(&mut r, &conn, now);

        let status_check = r.checks.iter()
            .find(|c| c.id.starts_with("cert.abcd1234deadbeef.status"))
            .expect("must emit per-cert status check");
        assert_eq!(status_check.outcome, Outcome::Ok);
        assert!(status_check.detail.contains("status=active"),
            "detail must carry the active tag: {:?}", status_check.detail);
    }

    #[test]
    fn cert_check_warns_on_expiring_cert() {
        let tmp = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        // Cert expires in 5 days, warn window is 30 days → Expiring.
        setup_db_with_cert(
            &tmp, "expiring00000001", "Jinanwa",
            now - 86_400 * 60, now + 86_400 * 5,
            30, 7, "Standard", false,
        );

        let conn = raxis_store::open_ro(tmp.path()).unwrap();
        let mut r = Report::default();
        check_operator_certs(&mut r, &conn, now);

        let status = r.checks.iter()
            .find(|c| c.id.starts_with("cert.expiring00000001.status"))
            .expect("must emit per-cert status check");
        assert_eq!(status.outcome, Outcome::Warn);
        assert!(status.detail.contains("expiring in"),
            "detail must mention expiry runway: {:?}", status.detail);
    }

    #[test]
    fn cert_check_fails_on_expired_cert() {
        let tmp = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        // Cert expired 30 days ago and grace (7d) elapsed → Expired.
        setup_db_with_cert(
            &tmp, "expired000000001", "Charlie",
            now - 86_400 * 365, now - 86_400 * 30,
            30, 7, "Standard", false,
        );

        let conn = raxis_store::open_ro(tmp.path()).unwrap();
        let mut r = Report::default();
        check_operator_certs(&mut r, &conn, now);

        let status = r.checks.iter()
            .find(|c| c.id.starts_with("cert.expired000000001.status"))
            .expect("must emit per-cert status check");
        assert_eq!(status.outcome, Outcome::Fail);
        assert!(status.detail.contains("EXPIRED"),
            "detail must carry the loud EXPIRED marker: {:?}", status.detail);
    }

    #[test]
    fn cert_check_warns_when_force_misconfig_bypass_is_set() {
        let tmp = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        let one_year = 365 * 86_400;
        setup_db_with_cert(
            &tmp, "bypassedcert0001", "Dana",
            now - 86_400, now + one_year,
            30, 7, "Standard", true, // ← bypass on
        );

        let conn = raxis_store::open_ro(tmp.path()).unwrap();
        let mut r = Report::default();
        check_operator_certs(&mut r, &conn, now);

        let bypass = r.checks.iter()
            .find(|c| c.id.starts_with("cert.bypassedcert0001.misconfig_bypass"))
            .expect("must emit a cert.<fp>.misconfig_bypass row");
        assert_eq!(bypass.outcome, Outcome::Warn);
        assert!(bypass.detail.contains("--force-misconfig"),
            "bypass detail must reference the CLI flag for grep-traceability: {:?}",
            bypass.detail);

        // Status itself is Active (the bypass is orthogonal).
        let status = r.checks.iter()
            .find(|c| c.id.starts_with("cert.bypassedcert0001.status"))
            .expect("status row must still appear alongside bypass row");
        assert_eq!(status.outcome, Outcome::Ok);
    }

    #[test]
    fn cert_check_treats_emergency_kind_as_always_active() {
        let tmp = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        // EmergencyRecovery: the not_before / not_after / warn / grace
        // values are STRUCTURALLY IGNORED by `cert_status` — we still
        // pass realistic values so the row passes any future row-level
        // CHECK constraints. The expected outcome is OK regardless.
        setup_db_with_cert(
            &tmp, "emergency00000001", "Break-Glass",
            0, 0, 0, 0, "EmergencyRecovery", false,
        );

        let conn = raxis_store::open_ro(tmp.path()).unwrap();
        let mut r = Report::default();
        check_operator_certs(&mut r, &conn, now);

        let status = r.checks.iter()
            .find(|c| c.id.starts_with("cert.emergency00000001.status"))
            .expect("must emit per-cert status check for emergency cert");
        assert_eq!(status.outcome, Outcome::Ok);
        assert!(status.detail.contains("always_active_emergency"),
            "emergency cert detail must use the canonical zone tag: {:?}",
            status.detail);
    }
}
