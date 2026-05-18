//! `cargo xtask images bake` — one operator-facing command that
//! preflights host inputs, stages the Linux guest kernel, bakes any
//! required role rootfs, cross-compiles the guest PID-1 binaries, and
//! writes signed initramfs blobs for AVF / Firecracker microVM boot.
//!
//! Normative references:
//!
//! * `raxis/specs/v2/planner-harness.md §14.4 — Image-build pipeline`
//!   — the production EROFS pipeline. This module is the dev-host
//!   companion that emits the same signed-manifest shape but with
//!   `image_format = RootfsInitramfsCpio` instead.
//! * The `mkfs.erofs`-on-macOS blocker is the reason this dev-host
//!   pipeline emits initramfs cpio.gz images instead of EROFS blobs.
//! * `raxis/crates/initramfs-builder/` — the cpio.gz writer the
//!   pack/sign step drives.
//!
//! ## Pipeline
//!
//! ```text
//! cargo xtask images bake [--role <ROLE>]... [--kernel-from-file <PATH>]
//!   → preflight signing key, vmlinux, guest .config, Containerfiles
//!   → bake OCI rootfs for roles that need OS tooling
//!   → cross-compile the guest binary and overlay it into rootfs
//!   → pack cpio.gz, sign manifest.toml, write bake.json cache record
//! ```
//!
//! ## Why `dev-stage` shells out to `cargo` for the cross-compile
//!
//! Cross-compiling a workspace member from xtask with the Cargo
//! library API requires linking against `cargo` as a build dependency
//! — adding ~600 transitive crates to a build-tooling binary that
//! exists to be small. Shelling out keeps xtask's Cargo.toml under 10
//! deps and uses the same toolchain resolution the developer would
//! get from `cargo build --target <TRIPLE>`. The trade-off is that
//! `dev-stage` requires the developer to have the target installed
//! (`rustup target add aarch64-unknown-linux-musl`) and a musl linker
//! on `$PATH` (`brew install filosottile/musl-cross/musl-cross` on
//! macOS); we surface a clear remediation hint when either is absent.
//!
//! ## Why the dev-host pipeline ships a separate manifest
//!
//! `image-builder`'s `assemble_manifest` already takes
//! `BuildInputs.image_format` as an input. `build-all` constructs a
//! `BuildInputs` with `image_format = RootfsInitramfsCpio` and feeds
//! that through the same signing path the production EROFS pipeline
//! uses. The kernel verifies BOTH shapes via the same
//! `read_verified_image_format` helper added in
//! `crates/canonical-images`, so dev-built images and prod-built
//! images cannot be confused at boot.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::guest_kernel_config::{
    resolve_and_validate_kernel_config, stage_kernel_config, KernelConfigSource,
};
use crate::trust_anchor;

/// Workspace-relative path to the per-role staging dir. Mirrors the
/// `images/<role>/rootfs/` layout `raxis-image-builder` already
/// expects.
const STAGING_PARENT: &str = "images";

/// Default install dir if neither `--install-dir` nor
/// `RAXIS_INSTALL_DIR` is set. Mirrors `dev_kernel.rs`.
const DEFAULT_DEV_INSTALL_DIR: &str = "/usr/local/lib/raxis";

/// One canonical role this pipeline knows how to stage.
///
/// === iter62 verifier-runtime: production verifier roles ===
///
/// `Verifier` and `VerifierSymbolIndex` extend the bake pipeline to
/// produce the two new V2 verifier images:
///
///   * `Verifier` ⇒ `images/verifier-starter/` (general verifier;
///     ships the `raxis-verifier` PID 1 alongside ripgrep / ctags /
///     jq for the common gate types — operator-publishable-
///     equivalent, alias `raxis-verifier-starter` is reserved per
///     `RESERVED_GENERAL_VERIFIER_VM_IMAGE_NAME`).
///   * `VerifierSymbolIndex` ⇒ `images/verifier-symbol-index/`
///     (kernel-canonical symbol-index verifier carrying the diff-
///     scoped + parallel ctags speed path from D7; the alias
///     `raxis-verifier-symbol-index` is reserved per
///     `RESERVED_SYMBOL_INDEX_VM_IMAGE_NAME`).
///
/// Both flip `needs_rootfs_bake` to `true` because each image ships
/// a small Linux tooling layer on top of the binary (busybox /
/// universal-ctags / ripgrep). The cross-compile pulls a single
/// workspace crate (`raxis-verifier`) for both; the per-image
/// subdir owns the Containerfile that decides which utilities land
/// in the rootfs. Cf. `xtask/src/linux_microvm.rs::Role` which
/// mirrors this taxonomy at the dispatch / argv-parse seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Role {
    Orchestrator,
    Reviewer,
    ExecutorStarter,
    // === iter62 verifier-runtime ===
    Verifier,
    VerifierSymbolIndex,
}

impl Role {
    /// Does this role's rootfs come from a `Containerfile`-driven OCI
    /// bake (`bake-rootfs`), or is it binary-only (just the staged
    /// planner PID-1 binary)? Orchestrator + Reviewer are deliberately
    /// binary-only per `INV-PLANNER-HARNESS-02` minimalism;
    /// `executor-starter` and both verifier images need the
    /// OS-tooling-rich Containerfile bake — the verifier ships the
    /// runtime alongside the binary.
    ///
    /// This single helper is the only place the dispatch lives so a
    /// future role that flips between the two shapes stays a one-line
    /// edit. The harness's `role_needs_rootfs_bake` mirrors this
    /// taxonomy and is kept in lockstep by
    /// `INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01`'s witness test.
    fn needs_rootfs_bake(self) -> bool {
        matches!(
            self,
            Role::ExecutorStarter | Role::Verifier | Role::VerifierSymbolIndex,
        )
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "orchestrator" => Ok(Role::Orchestrator),
            "reviewer" => Ok(Role::Reviewer),
            "executor-starter" => Ok(Role::ExecutorStarter),
            // === iter62 verifier-runtime ===
            "verifier-starter" => Ok(Role::Verifier),
            "verifier-symbol-index" => Ok(Role::VerifierSymbolIndex),
            other => bail!(
                "unsupported --role {other:?}; expected one of: \
                 orchestrator, reviewer, executor-starter, \
                 verifier-starter, verifier-symbol-index"
            ),
        }
    }

    fn all() -> &'static [Role] {
        &[
            Role::Orchestrator,
            Role::Reviewer,
            Role::ExecutorStarter,
            // === iter62 verifier-runtime ===
            Role::Verifier,
            Role::VerifierSymbolIndex,
        ]
    }

    fn workspace_crate(self) -> &'static str {
        match self {
            Role::Orchestrator => "raxis-planner-orchestrator",
            Role::Reviewer => "raxis-planner-reviewer",
            Role::ExecutorStarter => "raxis-planner-executor",
            // === iter62 verifier-runtime ===
            //
            // Both verifier images stage the SAME workspace crate
            // (`raxis-verifier`) — the per-image Containerfile in
            // `images/<images_subdir>/` decides which auxiliary
            // tools land in the rootfs. Cross-compiling once would
            // be a future optimisation; the per-role dev-stage call
            // is idempotent and the cargo cache makes the second
            // call cheap.
            Role::Verifier => "raxis-verifier",
            Role::VerifierSymbolIndex => "raxis-verifier",
        }
    }

    /// Filename of the produced binary (matches the `[[bin]] name`
    /// in each planner crate's Cargo.toml).
    fn binary_name(self) -> &'static str {
        match self {
            Role::Orchestrator => "raxis-orchestrator",
            Role::Reviewer => "raxis-reviewer",
            Role::ExecutorStarter => "raxis-executor",
            // === iter62 verifier-runtime ===
            Role::Verifier => "raxis-verifier",
            Role::VerifierSymbolIndex => "raxis-verifier",
        }
    }

    fn images_subdir(self) -> &'static str {
        match self {
            Role::Orchestrator => "orchestrator-core",
            Role::Reviewer => "reviewer-core",
            Role::ExecutorStarter => "executor-starter",
            // === iter62 verifier-runtime ===
            Role::Verifier => "verifier-starter",
            Role::VerifierSymbolIndex => "verifier-symbol-index",
        }
    }

    /// Filename stem for the produced `.img` / `.manifest.toml`
    /// blobs, matching `image-manifest::Role::artefact_stem`.
    fn artefact_stem(self) -> &'static str {
        match self {
            Role::Orchestrator => "raxis-orchestrator-core",
            Role::Reviewer => "raxis-reviewer-core",
            Role::ExecutorStarter => "raxis-executor-starter",
            // === iter62 verifier-runtime ===
            Role::Verifier => "raxis-verifier-starter",
            Role::VerifierSymbolIndex => "raxis-verifier-symbol-index",
        }
    }

    fn manifest_role(self) -> raxis_image_manifest::Role {
        match self {
            Role::Orchestrator => raxis_image_manifest::Role::Orchestrator,
            Role::Reviewer => raxis_image_manifest::Role::Reviewer,
            Role::ExecutorStarter => raxis_image_manifest::Role::ExecutorStarter,
            // === iter62 verifier-runtime ===
            //
            // Both verifier-bake roles fold into the same
            // `image-manifest::Role` variant for their respective
            // canonical shapes (`Verifier` vs `VerifierSymbolIndex`),
            // so an operator inspecting the on-disk manifest sees
            // a clear role tag that names the image's identity, not
            // just "verifier".
            Role::Verifier => raxis_image_manifest::Role::Verifier,
            Role::VerifierSymbolIndex => raxis_image_manifest::Role::VerifierSymbolIndex,
        }
    }
}

/// Default cross-compile target. `--target` overrides; otherwise we
/// pick the musl triple matching the host arch since AVF and
/// Firecracker on macOS Apple Silicon both run aarch64 guests, and
/// Linux x86_64 hosts run x86_64 guests.
fn default_target_triple() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-musl"
    } else {
        "x86_64-unknown-linux-musl"
    }
}

// ---------------------------------------------------------------------------
// dev-stage
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct DevStageArgs {
    role: Role,
    target: String,
    workspace_root: PathBuf,
    cargo: String,
    /// When true, skip the post-stage stub-detection guard. Default
    /// `false`: dev-stage refuses to claim success when the role's
    /// staging tree is missing OS tooling that the canonical
    /// Containerfile promises (e.g. `bin/bash` for executor-starter).
    /// Set this only when intentionally building a binary-only
    /// debug image (e.g. while iterating on planner-core without
    /// re-running the docker bake).
    allow_stub: bool,
    /// 64-char lowercase hex public-half to inject as
    /// `RAXIS_KERNEL_SIGNING_KEY_HEX` into the cross-compile cargo
    /// subprocess. `None` for in-process callers (test fixtures)
    /// that do not need the trust-anchor injection; populated by
    /// `run_dev_stage` (operator-invoked) and `bake_one_role_full`
    /// (umbrella bake driver). The
    /// `INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01` audit-sweep
    /// witness pins that every cargo invocation in the bake pipeline
    /// has this set; see `dev_stage` for the per-`Command::env(...)`
    /// thread.
    kernel_signing_key_hex: Option<String>,
}

impl DevStageArgs {
    fn parse(argv: &[String]) -> Result<Self> {
        let mut role: Option<Role> = None;
        let mut target: Option<String> = None;
        let mut allow_stub: bool = false;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--role" => {
                    i += 1;
                    role = Some(Role::parse(
                        argv.get(i).context("--role requires a value")?,
                    )?);
                }
                "--target" => {
                    i += 1;
                    target = Some(argv.get(i).context("--target requires a triple")?.clone());
                }
                "--allow-stub" => {
                    allow_stub = true;
                }
                "-h" | "--help" => {
                    eprintln!(
                        "usage: cargo xtask images dev-stage --role <ROLE> \
                         [--target <TRIPLE>] [--allow-stub]\n  \
                         --role        orchestrator | reviewer | executor-starter\n  \
                         --target      default: {default}\n  \
                         --allow-stub  skip the post-stage stub-detection guard \
                                       (refuses success when the role's staging \
                                       tree lacks Containerfile-promised tooling \
                                       like bin/bash on executor-starter; pass \
                                       this only when intentionally building a \
                                       binary-only debug image)\n",
                        default = default_target_triple(),
                    );
                    std::process::exit(0);
                }
                other => bail!("unknown dev-stage arg: {other}"),
            }
            i += 1;
        }

        let role = role.context("--role is required")?;
        let target = target.unwrap_or_else(|| default_target_triple().to_owned());
        let workspace_root = workspace_root_from_cwd()?;
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());

        Ok(Self {
            role,
            target,
            workspace_root,
            cargo,
            allow_stub,
            // Argv-parse alone does NOT resolve the dev signing
            // key — `run_dev_stage` is the entry point that
            // resolves and injects. Leaving this `None` here
            // keeps `DevStageArgs::parse` test-friendly (existing
            // witnesses construct args without a populated
            // workspace's `.git/info/raxis-signing-key/`).
            kernel_signing_key_hex: None,
        })
    }
}

/// Per-role inventory of OS-level binaries the canonical Containerfile
/// promises. If `dev-stage` runs without a prior `bake-rootfs`, the
/// staging tree contains only the planner binary and these files are
/// missing — the symptom is the iter-12 `BashTool: ENOENT` storm.
///
/// The list is **role-required** (not nice-to-have): every entry maps
/// to a planner-tool spawn or runtime requirement that would ENOENT
/// at the first invocation if absent.
///
/// * `bin/bash` — `BashTool` spawn (`tokio::process::Command::new("bash")`).
/// * `usr/bin/python3` — required by the executor's "LLM writes a
///   `psycopg2` script and pipes it through `bash -c 'python3 -c "..."'`"
///   canonical pattern. Without python the credential-proxy round-trip
///   tests can never run.
/// * `usr/bin/git` — `GitCommitTool` spawn.
///
/// Orchestrator and Reviewer are intentionally binary-only today
/// (`INV-PLANNER-HARNESS-02 — minimalism`); their `required_binaries`
/// list is empty so the guard always passes for those roles.
fn required_os_binaries(role: Role) -> &'static [&'static str] {
    match role {
        Role::ExecutorStarter => &["bin/bash", "usr/bin/python3", "usr/bin/git"],
        Role::Orchestrator | Role::Reviewer => &[],
        // === iter62 verifier-runtime ===
        //
        // `verifier-starter` carries `bash` (for `RAXIS_VERIFIER_COMMAND
        // → sh -lc <command>` execution), `ripgrep` (D7 symbol-index
        // fast path), `jq` (gate-side JSON inspection), and
        // `universal-ctags` (the canonical-verifier symbol-index
        // path; Containerfile installs ctags binary at /usr/bin/ctags).
        // The `verifier-symbol-index` image is smaller — just the
        // verifier + ctags + busybox-static — so its required-binary
        // set is narrower. The list pins paths the kernel-side
        // `assert_no_stub_after_stage` check inspects after the bake;
        // every entry MUST be present at the listed rootfs path or
        // the bake fails closed.
        Role::Verifier => &["bin/bash", "usr/bin/jq", "usr/bin/rg", "usr/bin/ctags"],
        Role::VerifierSymbolIndex => &["bin/busybox", "usr/bin/ctags"],
    }
}

fn assert_no_stub_after_stage(role: Role, staging_root: &Path) -> Result<()> {
    let required = required_os_binaries(role);
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|rel| {
            let p = staging_root.join(rel);
            // Treat both regular files AND symlinks-to-files as
            // satisfied; OS rootfs trees use both shapes
            // (`/usr/bin/python3 -> python3.11`).
            !p.exists() && p.symlink_metadata().is_err()
        })
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    bail!(
        "dev-stage refuses to declare success: the {role:?} staging tree at \n  \
         {staging}\n\
         is a stub — missing {n} Containerfile-promised binar{plural}:\n{lines}\n\
         \n\
         Run the bake first:\n  \
         cargo xtask images bake --role {role_arg}\n\
         Pass --allow-stub to dev-stage if you are \
         intentionally building a binary-only debug image (NOT for live-e2e).",
        role = role.workspace_crate(),
        staging = staging_root.display(),
        n = missing.len(),
        plural = if missing.len() == 1 { "y" } else { "ies" },
        role_arg = role.images_subdir(),
        lines = missing
            .iter()
            .map(|m| format!("  - {m}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// Entry point for `cargo xtask images dev-stage`.
///
/// Resolves the dev signing key public half via the canonical
/// search order (`trust_anchor::resolve_signing_key_pk_hex`) BEFORE
/// invoking `dev_stage`, so the cross-compile cargo subprocess
/// (`cargo build -p raxis-planner-<role>`) inherits
/// `RAXIS_KERNEL_SIGNING_KEY_HEX` via per-`Command` `.env(...)`. A
/// transitively-built `raxis-canonical-images`'s build script then
/// embeds the populated trust anchor into any planner binary that
/// links it, AND a sibling `cargo build -p raxis-kernel` invoked
/// from the same xtask seam sees the same anchor.
/// INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01.
pub fn run_dev_stage(argv: &[String]) -> Result<()> {
    let mut args = DevStageArgs::parse(argv)?;
    let resolved = trust_anchor::resolve_signing_key_pk_hex(&args.workspace_root)
        .map_err(anyhow::Error::new)
        .context(
            "resolve dev signing key for dev-stage cargo subprocess \
             (INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01)",
        )?;
    args.kernel_signing_key_hex = Some(resolved.pk_hex);
    dev_stage(&args)
}

fn dev_stage(args: &DevStageArgs) -> Result<()> {
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"dev_stage_begin\",\
         \"role\":{:?},\"target\":{:?},\"workspace_root\":{:?}}}",
        args.role.workspace_crate(),
        args.target,
        args.workspace_root.display().to_string(),
    );

    // Cross-compile: `cargo build -p <crate> --release --target <triple>`.
    //
    // Per-`Command` `.env(...)` injection of
    // `RAXIS_KERNEL_SIGNING_KEY_HEX` is the load-bearing
    // INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01 step. Without
    // it the planner crate's transitively-built
    // `raxis-canonical-images` build script falls through to the
    // placeholder arm (or auto-mints a per-clone key that may
    // disagree with the one the umbrella bake driver signs images
    // with). We deliberately do NOT mutate process-level
    // `std::env` here — the per-`Command` scope keeps the
    // injection contained to exactly the children that need it.
    //
    // AUDIT-MARKER:bake-cargo-spawn — the spec-audit witness
    // `inv_image_bake_kernel_trust_anchor_populated_01_every_cargo_spawn_pairs_with_marker_and_helper`
    // scans for this token AND the `apply_trust_anchor_env` call
    // immediately below; both MUST be present at every cargo
    // subprocess site in this file.
    let mut cmd = Command::new(&args.cargo);
    cmd.current_dir(&args.workspace_root).args([
        "build",
        "-p",
        args.role.workspace_crate(),
        "--release",
        "--target",
        &args.target,
    ]);
    apply_trust_anchor_env(&mut cmd, args.kernel_signing_key_hex.as_deref());
    let status = cmd
        .status()
        .context("failed to spawn cargo for cross-compile; is the toolchain on $PATH?")?;
    if !status.success() {
        bail!(
            "cross-compile failed (exit {}). Likely causes:\n  \
             1. target {} not installed:  rustup target add {target}\n  \
             2. musl linker missing:       brew install filosottile/musl-cross/musl-cross  (macOS)\n  \
             3. .cargo/config.toml lacks  [target.{target}.linker]  (run `rustup show` to inspect)",
            status,
            args.target,
            target = args.target,
        );
    }

    // Locate the built binary.
    let built = args
        .workspace_root
        .join("target")
        .join(&args.target)
        .join("release")
        .join(args.role.binary_name());
    if !built.exists() {
        bail!(
            "expected cross-compiled binary not found at {} after `cargo build` \
             succeeded. Did the planner crate's [[bin]] name change?",
            built.display(),
        );
    }

    // Stage into images/<role>/rootfs/. The Containerfile-built rootfs
    // already contains a `/init` symlink pointing at
    // `/usr/local/bin/raxis-planner-<role>` (planner-harness.md §14.4
    // canonical layout). When `init` is a symlink, naïve `fs::copy`
    // follows it and writes to whatever absolute path the symlink
    // resolves to ON THE HOST — i.e. /usr/local/bin/ — instead of
    // updating the in-rootfs binary that the cpio writer will
    // actually pack. We therefore:
    //   1. Always write the freshly cross-compiled binary into the
    //      canonical /usr/local/bin path INSIDE the rootfs.
    //   2. Ensure /init exists as a symlink pointing at that path.
    // This keeps the dev pipeline's on-disk layout byte-identical to
    // the production EROFS layout and guarantees the new binary
    // actually ships in the cpio.gz.
    use std::os::unix::fs::{symlink, PermissionsExt};

    let staging_root = args
        .workspace_root
        .join(STAGING_PARENT)
        .join(args.role.images_subdir())
        .join("rootfs");
    fs::create_dir_all(&staging_root)
        .with_context(|| format!("create {}", staging_root.display()))?;

    let canonical_rel = format!("usr/local/bin/{}", args.role.binary_name());
    let canonical_abs = staging_root.join(&canonical_rel);
    if let Some(parent) = canonical_abs.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    // Replace the existing binary atomically: remove the stale file
    // (or symlink) first so `fs::copy` writes a fresh inode rather
    // than following a host-absolute symlink.
    if canonical_abs.exists() || canonical_abs.symlink_metadata().is_ok() {
        fs::remove_file(&canonical_abs)
            .with_context(|| format!("remove stale {}", canonical_abs.display()))?;
    }
    fs::copy(&built, &canonical_abs)
        .with_context(|| format!("copy {} -> {}", built.display(), canonical_abs.display()))?;
    let mut perms = fs::metadata(&canonical_abs)
        .with_context(|| format!("stat {}", canonical_abs.display()))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&canonical_abs, perms)
        .with_context(|| format!("chmod {}", canonical_abs.display()))?;

    // Ensure `/init` exists as a symlink to /usr/local/bin/<binary>.
    // We always recreate it so a stale regular-file `/init` (left by
    // an earlier pre-fix dev-stage run) cannot end up packed instead
    // of the canonical-layout binary.
    let init_link = staging_root.join("init");
    if init_link.exists() || init_link.symlink_metadata().is_ok() {
        fs::remove_file(&init_link)
            .with_context(|| format!("remove stale {}", init_link.display()))?;
    }
    let init_target = format!("/{canonical_rel}");
    symlink(&init_target, &init_link)
        .with_context(|| format!("symlink {} -> {}", init_link.display(), init_target,))?;
    let dest = canonical_abs;

    // Stub guard — assert the staging tree contains the role's
    // canonical Containerfile-promised binaries before declaring
    // success. Skipped when --allow-stub is set or when the role's
    // required-binary list is empty (orch / reviewer today). Without
    // this guard, a missing `bake-rootfs` invocation surfaces as the
    // iter-12 `BashTool: ENOENT` storm at runtime instead of an
    // immediate, actionable build-time failure.
    if !args.allow_stub {
        if let Err(e) = assert_no_stub_after_stage(args.role, &staging_root) {
            // Emit the structured event BEFORE returning so audit-grep
            // and CI logs both record the stub detection.
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"dev_stage_stub_detected\",\
                 \"role\":{:?},\"staging_root\":{:?}}}",
                args.role.workspace_crate(),
                staging_root.display().to_string(),
            );
            return Err(e);
        }
    }

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"dev_stage_ok\",\
         \"role\":{:?},\"binary\":{:?},\"staged_at\":{:?},\
         \"stub_guard\":{:?}}}",
        args.role.workspace_crate(),
        built.display().to_string(),
        dest.display().to_string(),
        if args.allow_stub { "skipped" } else { "passed" },
    );

    Ok(())
}

/// Inject `RAXIS_KERNEL_SIGNING_KEY_HEX` into `cmd`'s child env
/// when a resolved value is available. Single chokepoint so every
/// cargo subprocess in the bake pipeline goes through the same
/// `.env(...)` call — the audit-sweep witness
/// `inv_image_bake_kernel_trust_anchor_populated_01_every_cargo_spawn_pairs_with_marker_and_helper`
/// pins that this helper is called at every site.
///
/// We do NOT silently fall back to an unset env when `pk_hex` is
/// `None`: the call sites are expected to have resolved a value via
/// `trust_anchor::resolve_signing_key_pk_hex` before constructing
/// the command. The `Option` exists so test fixtures that
/// construct `DevStageArgs` / `BuildAllArgs` in-process without
/// touching the resolver can still drive the rest of the pipeline.
fn apply_trust_anchor_env(cmd: &mut Command, pk_hex: Option<&str>) {
    if let Some(hex) = pk_hex {
        cmd.env(trust_anchor::RAXIS_KERNEL_SIGNING_KEY_HEX, hex);
    }
}

// ---------------------------------------------------------------------------
// Stale-cache guard (INV-IMAGE-BAKE-NO-STALE-CACHE-01)
// ---------------------------------------------------------------------------

/// Verdict from comparing the staged planner binary's mtime to the
/// newest mtime under the role's planner source tree
/// (`crates/planner-<role>/src/**` ∪ `crates/planner-core/src/**`).
///
/// `Fresh`   — staged binary is at least as new as every source file;
///             `build-all` can pack the cpio without re-staging.
/// `Stale`   — at least one source file is newer than the staged
///             binary; `build-all` must auto-rebake (or fail closed
///             under `--no-auto-stage`).
/// `Missing` — no staged binary at all; either dev-stage never ran or
///             the role's binary was deleted. Treated identically to
///             `Stale` (auto-rebake or fail closed).
///
/// Canonical home: `specs/v2/planner-harness.md §14.4` (image-build
/// pipeline) + the witness invariant
/// `INV-IMAGE-BAKE-NO-STALE-CACHE-01` in `specs/invariants.md §10.5`.
#[derive(Debug)]
enum FreshnessVerdict {
    /// Staged binary's mtime ≥ newest source mtime.
    Fresh {
        staged_mtime: std::time::SystemTime,
        source_mtime: std::time::SystemTime,
        staged_path: PathBuf,
        newest_source: PathBuf,
    },
    /// A source file is newer than the staged binary.
    Stale {
        staged_mtime: std::time::SystemTime,
        source_mtime: std::time::SystemTime,
        staged_path: PathBuf,
        newest_source: PathBuf,
    },
    /// No staged binary file exists at the canonical staging path.
    Missing {
        staged_path: PathBuf,
        newest_source: Option<PathBuf>,
    },
}

/// Per-role planner source dirs whose contents invalidate the staged
/// binary. These two cover the dominant freshness-failure shapes: a
/// change in the role's main.rs / role-specific code (`planner-<role>`)
/// or a change in the shared driver / env / sidecar plumbing
/// (`planner-core`). Other transitive deps (`types`, `ksb`, …) are
/// rarer change points; an operator who edits one of those and wants
/// the guard to trigger can `touch` the role's main.rs or run
/// `cargo xtask images dev-stage --role <ROLE>` explicitly.
///
/// Returned paths are workspace-absolute; they may not exist (e.g.,
/// a partial worktree). Missing dirs are treated as "no source files
/// to consider", consistent with the iter54 baseline.
fn planner_source_dirs(role: Role, workspace_root: &Path) -> [PathBuf; 2] {
    let role_dir = match role {
        Role::Orchestrator => "planner-orchestrator",
        Role::Reviewer => "planner-reviewer",
        Role::ExecutorStarter => "planner-executor",
        // === iter62 verifier-runtime ===
        //
        // Both verifier roles stage the same workspace crate
        // (`raxis-verifier`).
        Role::Verifier | Role::VerifierSymbolIndex => "verifier",
    };
    // The second slot is the cross-role dependency that ALL planner
    // roles re-link against (`planner-core`). For the verifier roles
    // this slot is intentionally elided — the verifier binary does
    // NOT link `planner-core` (verified by reading `crates/verifier/
    // Cargo.toml`: deps are `raxis-types` only), so a `planner-core`
    // source-tree mtime bump is NOT a real freshness signal for the
    // verifier-staged binary. Prior versions included `planner-core`
    // here "for symmetry"; the freshness check then tripped
    // `INV-IMAGE-BAKE-NO-STALE-CACHE-01 VIOLATED` on every dev-loop
    // bake that edited any `planner-core` source file (including the
    // orchestrator-only `driver.rs`), because cargo's incremental
    // cache restores the unchanged `target/.../raxis-verifier`
    // binary at its original compile-time mtime (older than the
    // freshly-edited planner-core source). The symmetric slot was
    // load-bearing for the planner roles ONLY; the verifier slot is
    // a no-op duplicate that gets walked twice. Empty-PathBuf in
    // that slot is silently skipped by `newest_mtime_in_tree` (per
    // its `if !root.exists()` early-return contract), preserving
    // the symmetric two-slot return shape without re-walking the
    // verifier source tree.
    let second_slot = match role {
        Role::Orchestrator | Role::Reviewer | Role::ExecutorStarter => workspace_root
            .join("crates")
            .join("planner-core")
            .join("src"),
        Role::Verifier | Role::VerifierSymbolIndex => PathBuf::new(),
    };
    [
        workspace_root.join("crates").join(role_dir).join("src"),
        second_slot,
    ]
}

/// Walk `root` recursively (following non-link directories only) and
/// return the newest `mtime` found plus the path that produced it. If
/// `root` does not exist or contains no regular files, returns
/// `Ok(None)`.
///
/// The walk follows `walkdir`'s default — depth-first, no
/// `follow_links` — which matches the initramfs builder's tree walk
/// in `pack_initramfs` and the planner crate's on-disk layout. Errors
/// during the walk (permission, broken symlink, …) are surfaced as
/// `Err` so the freshness guard fail-closes rather than silently
/// returning `Fresh` on an incomplete walk.
fn newest_mtime_in_tree(root: &Path) -> Result<Option<(std::time::SystemTime, PathBuf)>> {
    if !root.exists() {
        return Ok(None);
    }
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.with_context(|| format!("walk source tree under {}", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let m = entry
            .metadata()
            .with_context(|| format!("stat {}", entry.path().display()))?
            .modified()
            .with_context(|| format!("read mtime of {}", entry.path().display()))?;
        match best {
            None => best = Some((m, entry.path().to_owned())),
            Some((cur, _)) if m > cur => {
                best = Some((m, entry.path().to_owned()));
            }
            _ => {}
        }
    }
    Ok(best)
}

/// Classify the staging tree's planner binary against the role's
/// planner source tree mtimes. Pure-data: no filesystem mutation, no
/// subprocess invocations. The caller (`handle_staged_binary_freshness`)
/// turns the verdict into either an auto-rebake or a fail-closed
/// remediation message.
fn check_staged_binary_freshness(role: Role, workspace_root: &Path) -> Result<FreshnessVerdict> {
    let staged_path = workspace_root
        .join(STAGING_PARENT)
        .join(role.images_subdir())
        .join("rootfs")
        .join("usr")
        .join("local")
        .join("bin")
        .join(role.binary_name());

    let source_dirs = planner_source_dirs(role, workspace_root);
    let mut newest_source: Option<(std::time::SystemTime, PathBuf)> = None;
    for dir in &source_dirs {
        if let Some((mtime, path)) = newest_mtime_in_tree(dir)? {
            match &newest_source {
                None => newest_source = Some((mtime, path)),
                Some((cur, _)) if mtime > *cur => {
                    newest_source = Some((mtime, path));
                }
                _ => {}
            }
        }
    }

    if !staged_path.exists() {
        return Ok(FreshnessVerdict::Missing {
            staged_path,
            newest_source: newest_source.map(|(_, p)| p),
        });
    }

    let staged_mtime = fs::metadata(&staged_path)
        .with_context(|| format!("stat {}", staged_path.display()))?
        .modified()
        .with_context(|| format!("read mtime of {}", staged_path.display()))?;

    let (source_mtime, newest_source_path) = match newest_source {
        Some(pair) => pair,
        // No source tree to compare against (e.g., the planner-core
        // crate dir is missing from this worktree). Treat as fresh —
        // there is nothing to invalidate the staged binary.
        None => {
            return Ok(FreshnessVerdict::Fresh {
                staged_mtime,
                source_mtime: staged_mtime,
                staged_path,
                newest_source: PathBuf::new(),
            });
        }
    };

    if source_mtime > staged_mtime {
        Ok(FreshnessVerdict::Stale {
            staged_mtime,
            source_mtime,
            staged_path,
            newest_source: newest_source_path,
        })
    } else {
        Ok(FreshnessVerdict::Fresh {
            staged_mtime,
            source_mtime,
            staged_path,
            newest_source: newest_source_path,
        })
    }
}

/// `build_one_role`-side wrapper: classify staleness, then either
/// invoke `dev_stage` to auto-refresh (default) or bail with an
/// `INV-IMAGE-BAKE-NO-STALE-CACHE-01 VIOLATED` remediation message
/// when `--no-auto-stage` is set. Emits structured audit log lines on
/// every branch so a build log replay always answers "did the guard
/// fire on this role, and which way".
fn handle_staged_binary_freshness(role: Role, args: &BuildAllArgs) -> Result<()> {
    let verdict = check_staged_binary_freshness(role, &args.workspace_root)?;
    match &verdict {
        FreshnessVerdict::Fresh {
            staged_mtime,
            source_mtime,
            staged_path,
            newest_source,
        } => {
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"build_all_freshness_check_fresh\",\
                 \"role\":{:?},\"staged_path\":{:?},\"staged_mtime_unix\":{},\
                 \"newest_source\":{:?},\"source_mtime_unix\":{}}}",
                role.workspace_crate(),
                staged_path.display().to_string(),
                mtime_to_unix(*staged_mtime),
                newest_source.display().to_string(),
                mtime_to_unix(*source_mtime),
            );
            Ok(())
        }
        FreshnessVerdict::Stale {
            staged_mtime,
            source_mtime,
            staged_path,
            newest_source,
        } => {
            let reason = format!(
                "staged planner binary {} (mtime {}) is older than source \
                 file {} (mtime {})",
                staged_path.display(),
                mtime_to_unix(*staged_mtime),
                newest_source.display(),
                mtime_to_unix(*source_mtime),
            );
            if args.no_auto_stage {
                bail!(
                    "INV-IMAGE-BAKE-NO-STALE-CACHE-01 VIOLATED for role {role:?}: \
                     {reason}.\n\n\
                     `build-all` was invoked with `--no-auto-stage` (the \
                     hermetic-CI flow), so it refuses to silently pack a stale \
                     binary into the signed cpio.gz. Remediation: re-run \
                     `cargo xtask images dev-stage --role {arg}` (which \
                     cross-compiles `{krate}` and overlays the fresh binary \
                     into `images/{subdir}/rootfs/usr/local/bin/{bin}`), then \
                     re-run this `build-all` invocation. \n\n\
                     Alternative: drop `--no-auto-stage` and let `build-all` \
                     auto-rebake the role for you (default behaviour).",
                    role = role,
                    arg = role.images_subdir(),
                    krate = role.workspace_crate(),
                    subdir = role.images_subdir(),
                    bin = role.binary_name(),
                );
            }
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"build_all_auto_stage_invoked\",\
                 \"role\":{:?},\"reason\":\"stale_staged_binary\",\
                 \"staged_path\":{:?},\"staged_mtime_unix\":{},\
                 \"newest_source\":{:?},\"source_mtime_unix\":{}}}",
                role.workspace_crate(),
                staged_path.display().to_string(),
                mtime_to_unix(*staged_mtime),
                newest_source.display().to_string(),
                mtime_to_unix(*source_mtime),
            );
            invoke_auto_stage(role, args)?;
            Ok(())
        }
        FreshnessVerdict::Missing {
            staged_path,
            newest_source,
        } => {
            if args.no_auto_stage {
                bail!(
                    "INV-IMAGE-BAKE-NO-STALE-CACHE-01 VIOLATED for role {role:?}: \
                     no staged planner binary at {staged}. \n\n\
                     `build-all` was invoked with `--no-auto-stage`, so it \
                     refuses to silently pack a rootfs missing the role's \
                     planner binary. Remediation: run \
                     `cargo xtask images dev-stage --role {arg}` first.",
                    role = role,
                    staged = staged_path.display(),
                    arg = role.images_subdir(),
                );
            }
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"build_all_auto_stage_invoked\",\
                 \"role\":{:?},\"reason\":\"missing_staged_binary\",\
                 \"staged_path\":{:?},\"newest_source\":{:?}}}",
                role.workspace_crate(),
                staged_path.display().to_string(),
                newest_source
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(none)".to_owned()),
            );
            invoke_auto_stage(role, args)?;
            Ok(())
        }
    }
}

/// Internal helper: synthesise a `DevStageArgs` from a `BuildAllArgs`
/// context and run the cross-compile + overlay step for one role.
/// Used by `handle_staged_binary_freshness` to satisfy
/// `INV-IMAGE-BAKE-NO-STALE-CACHE-01` when the staged binary is stale
/// or missing. The auto-staged path uses `default_target_triple()`
/// and `allow_stub = false` so a partial bake-rootfs surfaces as the
/// same stub-detection error an operator would see from running
/// `dev-stage` directly. The cargo binary is resolved the same way
/// `DevStageArgs::parse` does (env `CARGO`, falling back to "cargo").
fn invoke_auto_stage(role: Role, args: &BuildAllArgs) -> Result<()> {
    let dev_stage_args = DevStageArgs {
        role,
        target: default_target_triple().to_owned(),
        workspace_root: args.workspace_root.clone(),
        cargo: std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()),
        allow_stub: false,
        // Propagate the umbrella driver's resolved trust anchor
        // into the auto-stage cargo subprocess.
        // INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01.
        kernel_signing_key_hex: args.kernel_signing_key_hex.clone(),
    };
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"build_all_auto_stage_begin\",\
         \"role\":{:?},\"target\":{:?}}}",
        role.workspace_crate(),
        dev_stage_args.target,
    );
    dev_stage(&dev_stage_args).with_context(|| {
        format!(
            "auto-rebake for role {role:?} failed under \
             INV-IMAGE-BAKE-NO-STALE-CACHE-01 (pass --no-auto-stage to \
             surface this as a fail-closed remediation message instead)",
        )
    })?;
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"build_all_auto_stage_ok\",\
         \"role\":{:?}}}",
        role.workspace_crate(),
    );
    Ok(())
}

/// Format a `SystemTime` as Unix seconds-since-epoch for structured
/// log lines. Pre-epoch times (clock skew, replayed fixtures) clamp
/// to `0`; the freshness comparison itself uses the raw
/// `SystemTime` so the clamp here is cosmetic-only.
fn mtime_to_unix(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// build-all
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BuildAllArgs {
    /// `None` = build every role for which `images/<role>/rootfs/`
    /// is non-empty.
    role: Option<Role>,
    install_dir: PathBuf,
    workspace_root: PathBuf,
    /// Path to the Ed25519 signing-key hex file. Defaults to
    /// `$HOME/.config/raxis/keys/raxis-dev-signing.key.hex`
    /// (`release-and-distribution.md §8.1`). The build-all
    /// step requires this exists; mint one with
    /// `cargo xtask dev-keys init` if absent.
    signing_key: PathBuf,
    /// When true, skip the stale-cache auto-rebake guard. Default
    /// `false`: build-all auto-invokes `dev-stage` for any role
    /// whose staged planner binary is older than its `crates/
    /// planner-<role>/src/**` or `crates/planner-core/src/**`
    /// source tree (see `INV-IMAGE-BAKE-NO-STALE-CACHE-01`). With
    /// this flag, build-all instead **fails closed** when the
    /// staged binary is stale, telling the operator to run
    /// `dev-stage` manually. Reserved for hermetic CI lanes that
    /// already ran `dev-stage` as a separate audit-tracked step.
    no_auto_stage: bool,
    /// Resolved dev signing key public half, threaded into the
    /// `invoke_auto_stage` cargo subprocess via per-`Command`
    /// `.env(...)`. Populated by `run_build_all` (operator-invoked)
    /// and by the umbrella `bake_one_role_full` driver. Test
    /// fixtures may leave this `None` — the auto-stage path then
    /// runs without the env injection, matching the earlier
    /// behaviour. INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01.
    kernel_signing_key_hex: Option<String>,
}

impl BuildAllArgs {
    fn parse(argv: &[String]) -> Result<Self> {
        let mut role: Option<Role> = None;
        let mut install_dir: Option<PathBuf> = None;
        let mut signing_key: Option<PathBuf> = None;
        let mut no_auto_stage: bool = false;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--role" => {
                    i += 1;
                    role = Some(Role::parse(
                        argv.get(i).context("--role requires a value")?,
                    )?);
                }
                "--install-dir" => {
                    i += 1;
                    install_dir = Some(PathBuf::from(
                        argv.get(i).context("--install-dir requires a path")?,
                    ));
                }
                "--signing-key" => {
                    i += 1;
                    signing_key = Some(PathBuf::from(
                        argv.get(i).context("--signing-key requires a path")?,
                    ));
                }
                "--no-auto-stage" => {
                    no_auto_stage = true;
                }
                "-h" | "--help" => {
                    eprintln!(
                        "usage: cargo xtask images build-all [--role <ROLE>] \
                         [--install-dir <PATH>] [--signing-key <PATH>] \
                         [--no-auto-stage]\n\
                         \n\
                         Pack staged rootfs trees into signed initramfs cpio.gz \
                         blobs and lay them out at <install_dir>/images/.\n\
                         \n\
                         By default, build-all detects staged planner binaries \
                         older than their `crates/planner-<role>/src/**` or \
                         `crates/planner-core/src/**` source tree and auto-runs \
                         `dev-stage` to refresh them before packing — pass \
                         --no-auto-stage to opt out and instead fail closed on \
                         stale binaries (hermetic-CI flow, where dev-stage was \
                         already run as a separate audit-tracked step). See \
                         `INV-IMAGE-BAKE-NO-STALE-CACHE-01`.\n"
                    );
                    std::process::exit(0);
                }
                other => bail!("unknown build-all arg: {other}"),
            }
            i += 1;
        }

        let install_dir = install_dir
            .or_else(|| std::env::var_os("RAXIS_INSTALL_DIR").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DEV_INSTALL_DIR));
        let signing_key = signing_key
            .or_else(default_signing_key_path)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "could not resolve --signing-key (HOME unset?). Pass --signing-key \
                 <PATH> or run `cargo xtask dev-keys init` first."
                )
            })?;
        let workspace_root = workspace_root_from_cwd()?;

        Ok(Self {
            role,
            install_dir,
            signing_key,
            workspace_root,
            no_auto_stage,
            // Argv-parse alone does NOT resolve the trust anchor;
            // `run_build_all` is the entry point that resolves and
            // injects. Test fixtures that construct
            // `BuildAllArgs` directly can leave this `None`.
            kernel_signing_key_hex: None,
        })
    }
}

fn default_signing_key_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("raxis")
            .join("keys")
            .join("raxis-dev-signing.key.hex"),
    )
}

/// Entry point for `cargo xtask images build-all`.
///
/// Resolves the dev signing key BEFORE invoking `build_all` so
/// any auto-stage triggered by the stale-cache guard
/// (`INV-IMAGE-BAKE-NO-STALE-CACHE-01`) spawns `cargo build` with
/// the trust anchor injected
/// (`INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01`).
pub fn run_build_all(argv: &[String]) -> Result<()> {
    let mut args = BuildAllArgs::parse(argv)?;
    let resolved = trust_anchor::resolve_signing_key_pk_hex(&args.workspace_root)
        .map_err(anyhow::Error::new)
        .context(
            "resolve dev signing key for build-all auto-stage cargo \
             subprocess (INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01)",
        )?;
    args.kernel_signing_key_hex = Some(resolved.pk_hex);
    build_all(&args)
}

fn build_all(args: &BuildAllArgs) -> Result<()> {
    if !args.signing_key.exists() {
        bail!(
            "signing key not found at {}. Run `cargo xtask dev-keys init` first \
             (release-and-distribution.md §8.1).",
            args.signing_key.display(),
        );
    }

    let signing_key = load_signing_key(&args.signing_key)?;

    let roles_to_build: Vec<Role> = match args.role {
        Some(r) => vec![r],
        None => Role::all()
            .iter()
            .copied()
            .filter(|r| {
                let staging = args
                    .workspace_root
                    .join(STAGING_PARENT)
                    .join(r.images_subdir())
                    .join("rootfs");
                staging.exists()
                    && std::fs::read_dir(&staging)
                        .map(|mut d| d.next().is_some())
                        .unwrap_or(false)
            })
            .collect(),
    };

    if roles_to_build.is_empty() {
        bail!(
            "no roles to build. Either pass --role <ROLE> explicitly or run \
             `cargo xtask images dev-stage --role <ROLE>` first to populate \
             images/<role>-core/rootfs/."
        );
    }

    let images_dir = args.install_dir.join("images");
    fs::create_dir_all(&images_dir).with_context(|| format!("create {}", images_dir.display()))?;

    for role in roles_to_build {
        build_one_role(role, args, &signing_key, &images_dir)?;
    }
    Ok(())
}

fn build_one_role(
    role: Role,
    args: &BuildAllArgs,
    signing_key: &ed25519_dalek::SigningKey,
    images_dir: &Path,
) -> Result<()> {
    use raxis_image_builder::{assemble_manifest, enumerate_rootfs, BuildInputs};
    use raxis_image_manifest::{fingerprint_signing_key, ImageFormat};

    let images_subdir = args
        .workspace_root
        .join(STAGING_PARENT)
        .join(role.images_subdir());
    let rootfs_dir = images_subdir.join("rootfs");
    let inputs_path = images_subdir.join("manifest.toml");

    if !rootfs_dir.exists() {
        bail!(
            "rootfs staging dir {} does not exist; run `cargo xtask images dev-stage \
             --role {role:?}` first",
            rootfs_dir.display(),
        );
    }
    if !inputs_path.exists() {
        bail!(
            "build-inputs file {} does not exist (the in-tree fixture)",
            inputs_path.display(),
        );
    }

    // Read BuildInputs and force image_format = RootfsInitramfsCpio.
    // The in-tree manifest.toml currently encodes the production EROFS
    // pipeline's parameters (erofs_version, tar_version) — those stay
    // accurate for the production build path. The dev pipeline ignores
    // them at signing time except for the canonical bundle_hash input.
    let inputs_toml = fs::read_to_string(&inputs_path)
        .with_context(|| format!("read {}", inputs_path.display()))?;
    let mut inputs: BuildInputs =
        toml::from_str(&inputs_toml).with_context(|| format!("parse {}", inputs_path.display()))?;
    inputs.image_format = ImageFormat::RootfsInitramfsCpio;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"build_all_role_begin\",\
         \"role\":{:?},\"rootfs_dir\":{:?}}}",
        role.workspace_crate(),
        rootfs_dir.display().to_string(),
    );

    // Stale-cache guard (INV-IMAGE-BAKE-NO-STALE-CACHE-01).
    //
    // Iter53's root cause: the canonical reviewer image's
    // `/init`-target binary (`/usr/local/bin/raxis-reviewer`) was a
    // May-12 build that pre-dated the May-13 landing of the
    // `RAXIS_PLANNER_TASK_PROMPT_PATH` sidecar codepath in
    // `crates/planner-core/src/driver.rs::read_task_prompt`. The
    // operator had run `cargo xtask images dev-stage` for orchestrator
    // and executor-starter after the sidecar lands but not for
    // reviewer; `build-all` then packed the May-12 stale binary into
    // a fresh cpio.gz and signed it. The kernel stamped
    // `RAXIS_PLANNER_TASK_PROMPT_PATH` (intentionally clearing the
    // inline `RAXIS_PLANNER_TASK_PROMPT` to avoid AVF cmdline
    // truncation; see `kernel/src/session_spawn_orchestrator.rs`),
    // the guest planner saw an empty prompt, dropped into
    // `DriverOutcome::Scaffold`, and called `park_on_signal()` —
    // never opening the vsock listener the host was trying to
    // connect to. The visible symptom 30 s later was
    // `vsock CONNECT 1024: ... Connection reset by peer` and
    // `ActivateSubTaskSpawnFailed { agent_kind: "Reviewer" }`.
    //
    // The guard below catches that exact regression at the BUILD
    // layer rather than the BOOT layer: it compares the staged
    // binary's mtime to the newest mtime under
    // `crates/planner-<role>/src/**` and `crates/planner-core/src/**`
    // and either auto-invokes `dev-stage` (default) or fails closed
    // with an actionable remediation message when `--no-auto-stage`
    // is set.
    handle_staged_binary_freshness(role, args)?;

    // Assemble the cpio.gz bytes with the initramfs-builder.
    let cpio_gz = pack_initramfs(&rootfs_dir, inputs.source_date_epoch)?;

    // Write the .img blob to <install_dir>/images/<stem>-<kver>.img.
    let img_path = images_dir.join(format!(
        "{stem}-{kver}.img",
        stem = role.artefact_stem(),
        kver = inputs.kernel_version,
    ));
    fs::write(&img_path, &cpio_gz).with_context(|| format!("write {}", img_path.display()))?;

    // Compute the .img digest for the manifest.
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&cpio_gz);
    let img_sha256_hex = hex::encode(hasher.finalize());

    // Assert the parsed BuildInputs role agrees with the role we're
    // building — catches a stale manifest.toml fixture.
    if inputs.role != role.manifest_role() {
        bail!(
            "build-inputs role {:?} disagrees with --role {role:?} (expected {:?})",
            inputs.role,
            role.manifest_role(),
        );
    }

    // Walk the staging tree and turn it into ManifestFile entries.
    let files = enumerate_rootfs(&rootfs_dir)?;
    let signing_fp_hex = hex::encode(fingerprint_signing_key(&signing_key.verifying_key()));
    let mut m = assemble_manifest(&inputs, files, signing_fp_hex, img_sha256_hex)?;

    // Sign + write the .manifest.toml sibling.
    raxis_image_builder::sign_manifest(&mut m, signing_key)?;

    let manifest_path = images_dir.join(format!(
        "{stem}-{kver}.manifest.toml",
        stem = role.artefact_stem(),
        kver = inputs.kernel_version,
    ));
    fs::write(&manifest_path, m.to_toml())
        .with_context(|| format!("write {}", manifest_path.display()))?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"build_all_role_ok\",\
         \"role\":{:?},\"img\":{:?},\"manifest\":{:?},\
         \"image_size_bytes\":{},\"image_sha256\":{:?}}}",
        role.workspace_crate(),
        img_path.display().to_string(),
        manifest_path.display().to_string(),
        cpio_gz.len(),
        m.image_artefact_sha256,
    );

    Ok(())
}

fn pack_initramfs(rootfs_dir: &Path, source_date_epoch: u64) -> Result<Vec<u8>> {
    use raxis_initramfs_builder::InitramfsBuilder;

    let mut b = InitramfsBuilder::new().with_source_date_epoch(source_date_epoch);
    b.add_tree_from_disk(rootfs_dir, "")
        .with_context(|| format!("walk staging tree {}", rootfs_dir.display()))?;
    let bytes = b.finalise_to_cpio_gz().context("finalise cpio.gz")?;
    Ok(bytes)
}

fn load_signing_key(p: &Path) -> Result<ed25519_dalek::SigningKey> {
    use ed25519_dalek::SigningKey;

    let s = fs::read_to_string(p).with_context(|| format!("read signing key {}", p.display()))?;
    let s = s.trim();
    if s.len() != 64 {
        bail!(
            "signing key at {} is {} chars; expected 64 lowercase hex",
            p.display(),
            s.len(),
        );
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(s, &mut bytes)
        .with_context(|| format!("hex-decode signing key at {}", p.display()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn workspace_root_from_cwd() -> Result<PathBuf> {
    let mut cwd: PathBuf = std::env::current_dir().context("cannot read CWD")?;
    loop {
        let candidate = cwd.join("Cargo.toml");
        if candidate.exists() {
            let s = std::fs::read_to_string(&candidate)
                .with_context(|| format!("read {}", candidate.display()))?;
            if s.contains("[workspace]") {
                return Ok(cwd);
            }
        }
        if !cwd.pop() {
            bail!(
                "could not find workspace root (no Cargo.toml with \
                 [workspace] in any ancestor of CWD)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// `cargo xtask images bake` — auto-generated dev signing keypair
// (INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01)
// ---------------------------------------------------------------------------
//
// Previously a fresh clone could not run `cargo xtask images bake`
// without first running BOTH `cargo xtask dev-keys init` (to mint a
// keypair under `$HOME/.config/raxis/keys/`) AND manually exporting
// `RAXIS_KERNEL_SIGNING_KEY_HEX` into the shell so the kernel's
// fail-loud trust anchor (`crates/canonical-images/build.rs`) could
// bake the public key in. The friction was real — operators hit it
// once, set up the env var, then forgot the seam exists.
//
// The helper below moves the keypair into the per-clone, untracked
// `.git/info/raxis-signing-key/` directory and ensures it's present
// (mode 0700 dir, 0600 sk.hex, 0644 pk.hex) on every `bake` run. It
// is idempotent: present-and-readable → return; missing → generate.
// The umbrella `bake` driver then exports the public half into
// `RAXIS_KERNEL_SIGNING_KEY_HEX` for every cargo subprocess it spawns
// (dev-stage's `cargo build -p raxis-planner-<role>` chain), so a
// concurrent `cargo build -p raxis-kernel` invoked from the same
// shell sees the trust anchor without manual export.
//
// `.git/info/` is the canonical "per-clone, never tracked" home for
// repository-local state (`man gitrepository-layout`); using it
// removes the gitignore step entirely (git itself refuses to stage
// anything under `.git/`).

// As of iter62 (`INV-IMAGE-TRUST-ANCHOR-DEV-FALLBACK-01`) the
// keypair-mint logic lives in `crates/dev-signing-key/` so the
// kernel-side `crates/canonical-images/build.rs` and this xtask
// driver write the SAME `.git/info/raxis-signing-key/{sk,pk}.hex`
// artefact. Both halves now land at mode 0600 (uniform, iter62
// hardening); the parent dir is 0700.
const GIT_INFO_KEY_SK_FILENAME: &str = raxis_dev_signing_key::SK_FILENAME;

pub(crate) use raxis_dev_signing_key::{ensure_dev_signing_keypair, git_info_signing_key_dir};

// ---------------------------------------------------------------------------
// bake-rootfs (retired CLI subcommand; helper is still consumed by the
// umbrella `bake` driver)
//
// `cargo xtask images bake-rootfs --role <ROLE> [--builder <B>] [--platform
// <PLAT>]` — execute the per-role `images/<role>/Containerfile` against
// docker (or podman / buildah, in that fallback order), export the
// resulting OCI image's filesystem, and unpack it into
// `images/<role>/rootfs/`. The subsequent `dev-stage` overlays the
// freshly cross-compiled planner binary on top, and `build-all` packs
// the merged tree into the signed cpio.gz initramfs.
//
// The Containerfile IS the source of truth for the rootfs content;
// this subcommand is the per-release pipeline `images/README.md` says
// "populates `rootfs/`". Before this existed, the `dev-stage` step
// alone produced a binary-only initramfs (no /bin/bash, no python3,
// no git) — every `BashTool` invocation inside the executor VM
// returned ENOENT. See `iter12-artifacts/kernel.stderr.log` for the
// failure mode this fixes.
// ---------------------------------------------------------------------------

/// Container builders we know how to drive. Detection order is
/// `Docker → Podman → Buildah`; an explicit `--builder` overrides the
/// auto-detection. Each variant pairs with a fixed CLI shape so the
/// `bake_one_role` driver does not branch in three places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Builder {
    Docker,
    Podman,
    Buildah,
}

impl Builder {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "docker" => Ok(Builder::Docker),
            "podman" => Ok(Builder::Podman),
            "buildah" => Ok(Builder::Buildah),
            other => bail!(
                "unsupported --builder {other:?}; expected one of: \
                 docker, podman, buildah"
            ),
        }
    }

    fn binary(self) -> &'static str {
        match self {
            Builder::Docker => "docker",
            Builder::Podman => "podman",
            Builder::Buildah => "buildah",
        }
    }

    /// Auto-detect a usable builder by probing `$PATH`. Walks the
    /// fallback order `docker → podman → buildah`; returns the first
    /// binary that resolves. A clear remediation hint is surfaced if
    /// none are present.
    fn auto_detect() -> Result<Self> {
        for candidate in [Builder::Docker, Builder::Podman, Builder::Buildah] {
            if which(candidate.binary()).is_some() {
                return Ok(candidate);
            }
        }
        bail!(
            "no container builder found on $PATH. Install one of:\n  \
             - docker      (recommended on macOS / Linux dev hosts)\n  \
             - podman      (rootless, recommended on Linux servers)\n  \
             - buildah     (Linux-only, daemonless OCI builder)\n\
             Then re-run `cargo xtask images bake --role <ROLE>`."
        )
    }
}

/// `which`-style binary probe. Walks `$PATH` directories and returns
/// the first executable resolution. Inlined here to avoid pulling
/// the `which` crate into xtask for one short helper.
fn which(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        let Ok(meta) = std::fs::metadata(&candidate) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        if meta.permissions().mode() & 0o111 != 0 {
            return Some(candidate);
        }
    }
    None
}

/// Map a Rust target triple to an OCI / Docker `--platform` string.
/// Mirrors `default_target_triple` so the produced rootfs matches the
/// guest VM's architecture. AVF on Apple Silicon runs aarch64 guests,
/// AVF on Intel macOS runs x86_64; Firecracker on Linux mirrors the
/// host arch.
fn oci_platform_for_target_triple(triple: &str) -> Result<&'static str> {
    if triple.starts_with("aarch64-") {
        Ok("linux/arm64")
    } else if triple.starts_with("x86_64-") {
        Ok("linux/amd64")
    } else {
        bail!(
            "no OCI platform mapping for target triple {triple:?}; \
             expected aarch64-* or x86_64-* (the AVF / Firecracker \
             guests this pipeline targets). Pass --platform <PLAT> \
             explicitly to override."
        )
    }
}

fn bake_one_role(
    role: Role,
    builder: Builder,
    platform: &str,
    workspace_root: &Path,
    keep: bool,
) -> Result<()> {
    let images_subdir = workspace_root
        .join(STAGING_PARENT)
        .join(role.images_subdir());
    let containerfile = images_subdir.join("Containerfile");
    if !containerfile.exists() {
        bail!(
            "Containerfile not found at {}; expected the per-role recipe \
             to live next to manifest.toml under images/<role>/.",
            containerfile.display(),
        );
    }
    let rootfs_dir = images_subdir.join("rootfs");

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"bake_rootfs_begin\",\
         \"role\":{:?},\"builder\":{:?},\"platform\":{:?},\
         \"containerfile\":{:?}}}",
        role.workspace_crate(),
        builder.binary(),
        platform,
        containerfile.display().to_string(),
    );

    // ── Step 1: docker build (or podman / buildah build). ─────────────
    //
    // `--pull` ensures the FROM base layer is refreshed against the
    // upstream registry — without it, an older locally-cached
    // debian:bookworm-slim could ship a security regression silently.
    // `-t` tags the built image so we have a stable reference for the
    // subsequent `create` step. The tag carries a kernel-version
    // suffix once the bake pipeline grows multi-version support; for
    // now a fixed `:dev` is enough since each role bakes one image.
    let tag = format!("raxis-rootfs-{}:dev", role.images_subdir());
    let build_status = Command::new(builder.binary())
        .args([
            "build",
            "--platform",
            platform,
            "--pull",
            "-t",
            &tag,
            "-f",
            &containerfile.display().to_string(),
            &images_subdir.display().to_string(),
        ])
        .status()
        .with_context(|| {
            format!(
                "spawn `{builder} build` for role {role:?}",
                builder = builder.binary(),
            )
        })?;
    if !build_status.success() {
        bail!(
            "{builder} build failed (exit {status}). Inspect the build log \
             above; common causes: (1) Dockerfile syntax error, (2) apt-get \
             upstream outage, (3) a host/container architecture mismatch \
             (pick a matching host or run with a builder that supports \
             the target platform).",
            builder = builder.binary(),
            status = build_status,
        );
    }

    // ── Step 2: create a throwaway container so we can `export` its
    //    filesystem. `docker export` writes a tar stream to stdout;
    //    `podman` and `buildah` use the same shape. We always remove
    //    the container in Step 4 even on failure paths so a panic
    //    here does not leak named containers.
    let create_out = Command::new(builder.binary())
        .args(["create", "--platform", platform, &tag])
        .output()
        .with_context(|| {
            format!(
                "spawn `{builder} create` for tag {tag}",
                builder = builder.binary(),
            )
        })?;
    if !create_out.status.success() {
        bail!(
            "{builder} create failed (exit {status}):\n--- stderr ---\n{stderr}",
            builder = builder.binary(),
            status = create_out.status,
            stderr = String::from_utf8_lossy(&create_out.stderr),
        );
    }
    let container_id = String::from_utf8_lossy(&create_out.stdout)
        .trim()
        .to_owned();
    if container_id.is_empty() {
        bail!(
            "{builder} create returned empty container id",
            builder = builder.binary()
        );
    }

    // ── Step 3: `<builder> export <container_id>` → tar stream → tar -x.
    //
    // We pipe directly into a `tar -xf -` child to avoid materialising
    // a multi-GB temporary tarball on disk. `--no-same-owner` so the
    // extracted tree is owned by the invoking user (otherwise tar
    // tries to chown to UID 0, which fails on macOS without root).
    // `--no-same-permissions` keeps file modes from the archive but
    // strips the SUID/SGID bits — the cpio packer writes new mode
    // bits per the manifest anyway so this is a no-op for the on-disk
    // image but protects against accidental SUID inheritance during
    // dev-host extraction.
    if rootfs_dir.exists() && !keep {
        fs::remove_dir_all(&rootfs_dir)
            .with_context(|| format!("clean stale {}", rootfs_dir.display()))?;
    }
    fs::create_dir_all(&rootfs_dir).with_context(|| format!("create {}", rootfs_dir.display()))?;

    let extract_result = run_export_pipeline(builder, &container_id, &rootfs_dir);

    // ── Step 4: always remove the throwaway container. We swallow
    //    rm errors so a successful extract is not masked by a failed
    //    teardown; the dangling container is harmless and the next
    //    bake will overwrite the tag.
    let _ = Command::new(builder.binary())
        .args(["rm", "-f", &container_id])
        .status();

    extract_result?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"bake_rootfs_ok\",\
         \"role\":{:?},\"rootfs_dir\":{:?}}}",
        role.workspace_crate(),
        rootfs_dir.display().to_string(),
    );

    Ok(())
}

/// Run `<builder> export <container_id> | tar -xf - -C <rootfs_dir>`
/// without buffering a multi-GB tarball on disk. We use `Stdio::piped`
/// on the builder side and feed the read end into tar's stdin; both
/// children are reaped before we return.
fn run_export_pipeline(builder: Builder, container_id: &str, rootfs_dir: &Path) -> Result<()> {
    use std::process::Stdio;

    let mut export = Command::new(builder.binary())
        .args(["export", container_id])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "spawn `{builder} export {container_id}`",
                builder = builder.binary(),
            )
        })?;
    let export_stdout = export.stdout.take().expect("export stdout piped");

    let mut tar = Command::new("tar")
        .args([
            "-xf",
            "-",
            "--no-same-owner",
            "-C",
            &rootfs_dir.display().to_string(),
        ])
        .stdin(Stdio::from(export_stdout))
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn `tar -xf -`; tar(1) must be on $PATH")?;

    let tar_status = tar.wait().context("wait tar")?;
    let export_output = export.wait_with_output().context("wait export")?;

    if !export_output.status.success() {
        bail!(
            "{builder} export failed (exit {status}):\n--- stderr ---\n{stderr}",
            builder = builder.binary(),
            status = export_output.status,
            stderr = String::from_utf8_lossy(&export_output.stderr),
        );
    }
    if !tar_status.success() {
        bail!(
            "tar -x failed (exit {tar_status}); rootfs may be partially extracted at {}",
            rootfs_dir.display()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// bake — single-command end-to-end pipeline + preflight + manifest.json
//
// `cargo xtask images bake [--role <ROLE>]... [--install-dir <PATH>]
//                          [--signing-key <PATH>] [--kernel-from-file <PATH>]
//                          [--kernel-config <PATH>] [--skip-bake-rootfs] [--force]`
//
// Wraps the existing three-step pipeline (`bake-rootfs → dev-stage →
// build-all`) with:
//
//  * A **host-tool preflight** that runs BEFORE any artefact is
//    produced. Verifies the container builder (when any selected
//    role needs an OCI bake), the Rust musl cross-target + linker,
//    the signing key, the Linux guest-kernel binary (`vmlinux`), and
//    the kernel .config needed to prove built-in nftables support.
//    Fails closed with a clear remediation when any input is missing
//    — never lets the bake proceed half-staffed.
//    (`INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01`.)
//
//  * **`vmlinux` auto-staging.** Resolves the canonical Linux
//    kernel binary path (`<install_dir>/kernel/vmlinux`) at the
//    bake layer rather than leaving it to the harness's
//    `ensure_canonical_kernel_binary_staged` workaround. Resolution
//    order: explicit `--kernel-from-file`, then env override
//    `RAXIS_DEV_KERNEL_SOURCE`, then a pre-existing file at the
//    canonical path. `--force` is required to overwrite an existing
//    kernel binary that doesn't match the requested source.
//    (`INV-IMAGE-BAKE-VMLINUX-STAGED-01`.)
//
//  * **Guest-kernel config validation.** Resolves `--kernel-config`,
//    a sidecar `vmlinux.config`, or an embedded `IKCONFIG` blob and
//    rejects kernels that lack built-in nftables NAT/REDIRECT support
//    for Path A3's `iptables-nft` chain.
//    (`INV-GUEST-KERNEL-A3-NFTABLES-01`.)
//
//  * A per-role **integrity manifest** at
//    `<install_dir>/images/<artefact_stem>-<kver>.bake.json`. Records
//    the SHA-256 of every input (Containerfile, in-tree
//    `manifest.toml`, staged planner binary, signing-key
//    fingerprint, vmlinux) and every output (`.img`,
//    `.manifest.toml`). On re-run the bake hashes the inputs first
//    and skips any role whose input + output SHAs match the prior
//    manifest — re-running the bake on an unchanged tree is a fast
//    no-op. (`INV-IMAGE-BAKE-MANIFEST-INTEGRITY-01` and the
//    no-stale-cache witness in `INV-IMAGE-BAKE-NO-STALE-CACHE-01`.)
//
//  * A **Containerfile-graph acyclicity check** that parses every
//    in-tree `Containerfile` (one per role) and asserts no `FROM`
//    line names another in-tree role's bake tag. This prevents the
//    pre-migration `images/<role>/Containerfile.dev` shape (which
//    chained one role's image into another's base) from ever
//    re-entering the tree under a different filename.
//    (`INV-IMAGE-BAKE-NO-CIRCULAR-CONTAINERFILE-01`.)
//
// The existing `dev-stage`, `bake-rootfs`, and `build-all`
// subcommands keep their semantics; `bake` is a strict superset
// that runs them in the canonical order. Operators on a fresh
// checkout run one command (`cargo xtask images bake`) instead of
// the four they had to chain by hand before (`dev-kernel` plus the
// three per-role pipeline steps).
//
// Normative reference: `specs/v2/canonical-images.md §7` and
// `specs/invariants.md §10.5 INV-IMAGE-BAKE-*`.
// ---------------------------------------------------------------------------

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

/// Schema version embedded in every `*.bake.json` integrity manifest.
///
/// Bumping requires either (a) backwards-compatible additions
/// (`#[serde(default)]`) so old manifests still round-trip into the
/// new struct shape, or (b) a migration step that consumers run
/// before reading manifests stamped with the prior version. Either
/// way the version field is the trigger for that decision tree.
const BAKE_MANIFEST_SCHEMA_VERSION: u32 = 2;

/// Workspace-relative path to the per-role staging directory's
/// Containerfile. Used by the acyclicity check and by `preflight`
/// to assert each role's recipe exists before we attempt the
/// container build. Mirrors `bake_one_role`'s `containerfile`
/// resolution.
fn containerfile_path(workspace_root: &Path, role: Role) -> PathBuf {
    workspace_root
        .join(STAGING_PARENT)
        .join(role.images_subdir())
        .join("Containerfile")
}

/// Workspace-relative path to the per-role in-tree
/// `manifest.toml` — the pinned `BuildInputs` fixture
/// (kernel_version, source_date_epoch, ...).
fn inputs_manifest_path(workspace_root: &Path, role: Role) -> PathBuf {
    workspace_root
        .join(STAGING_PARENT)
        .join(role.images_subdir())
        .join("manifest.toml")
}

/// Compute the SHA-256 of a file's contents and return the
/// lowercase hex digest. Errors propagate the path so the caller
/// can include "which file" in its diagnostic.
fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

fn should_fingerprint_source_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if matches!(name, "Cargo.toml" | "Cargo.lock" | "build.rs") {
        return true;
    }
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("rs" | "toml")
    )
}

fn add_source_tree(files: &mut BTreeSet<PathBuf>, root: &Path) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.with_context(|| format!("walk source tree under {}", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if should_fingerprint_source_file(path) {
            files.insert(path.to_owned());
        }
    }
    Ok(())
}

fn add_source_file(files: &mut BTreeSet<PathBuf>, path: PathBuf) {
    if path.exists() && path.is_file() && should_fingerprint_source_file(&path) {
        files.insert(path);
    }
}

fn role_source_fingerprint_files(role: Role, workspace_root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = BTreeSet::new();

    add_source_file(&mut files, workspace_root.join("Cargo.toml"));
    add_source_file(&mut files, workspace_root.join("Cargo.lock"));
    add_source_tree(&mut files, &workspace_root.join("xtask").join("src"))?;

    for crate_dir in [
        "canonical-images",
        "image-builder",
        "image-manifest",
        "initramfs-builder",
        "ipc",
        "types",
    ] {
        add_source_tree(&mut files, &workspace_root.join("crates").join(crate_dir))?;
    }

    match role {
        Role::Orchestrator | Role::Reviewer | Role::ExecutorStarter => {
            for crate_dir in ["planner-core", "ksb"] {
                add_source_tree(&mut files, &workspace_root.join("crates").join(crate_dir))?;
            }
            let role_dir = match role {
                Role::Orchestrator => "planner-orchestrator",
                Role::Reviewer => "planner-reviewer",
                Role::ExecutorStarter => "planner-executor",
                Role::Verifier | Role::VerifierSymbolIndex => unreachable!(),
            };
            add_source_tree(&mut files, &workspace_root.join("crates").join(role_dir))?;
            if role == Role::ExecutorStarter {
                add_source_tree(&mut files, &workspace_root.join("tproxy"))?;
            }
        }
        Role::Verifier | Role::VerifierSymbolIndex => {
            add_source_tree(&mut files, &workspace_root.join("crates").join("verifier"))?;
        }
    }

    Ok(files.into_iter().collect())
}

fn role_source_tree_sha256(role: Role, workspace_root: &Path) -> Result<String> {
    let files = role_source_fingerprint_files(role, workspace_root)?;
    let mut h = Sha256::new();
    for path in files {
        let rel = path.strip_prefix(workspace_root).unwrap_or(path.as_path());
        h.update(rel.to_string_lossy().as_bytes());
        h.update([0]);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read {} for bake source fingerprint", path.display()))?;
        h.update(bytes);
        h.update([0]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Inputs covered by the per-role integrity manifest. Recorded in
/// `bake.json` so a re-run can shortcut to a no-op when none of the
/// observable inputs has changed.
///
/// The hash set is **deliberately minimal**. Everything that
/// influences the resulting `.img` byte stream IS hashed; nothing
/// else is. Adding a field requires updating both the writer
/// (`bake_one_role_full`) and the comparison shortcut
/// (`bake_should_skip`) so a silent "I added a field but didn't
/// gate on it" mismatch is structurally unreachable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BakeInputs {
    /// SHA-256 of the per-role `Containerfile` (the OCI recipe).
    /// `None` for binary-only roles where the file MAY be absent
    /// from a stripped checkout (though all three tracked roles
    /// currently ship one).
    containerfile_sha256: Option<String>,
    /// SHA-256 of the per-role `manifest.toml` (`BuildInputs`
    /// fixture: kernel_version, source_date_epoch, ...).
    inputs_manifest_sha256: String,
    /// SHA-256 of the staged planner binary at
    /// `images/<role>/rootfs/usr/local/bin/<binary>`. `None` when
    /// no binary has been staged yet (i.e. dev-stage has not run);
    /// the bake driver always (re)stages before recording so this
    /// is `Some(...)` in every emitted manifest.
    staged_binary_sha256: Option<String>,
    /// SHA-256 over the role's Rust source inputs plus build tooling.
    ///
    /// This is intentionally independent of `staged_binary_sha256`.
    /// The no-op shortcut runs before `dev-stage`; without this
    /// fingerprint, edited source plus an old staged binary can look
    /// "clean" because the old binary hash still matches the previous
    /// bake manifest.
    #[serde(default)]
    source_tree_sha256: String,
    /// First 16 hex chars of the Ed25519 signing-key fingerprint.
    /// Recorded so a key rotation invalidates the cache (the
    /// downstream `.manifest.toml` carries the full fingerprint).
    signing_key_fp_prefix: String,
    /// SHA-256 of `<install_dir>/kernel/vmlinux` (the canonical
    /// guest-kernel binary the substrate boots). `None` when
    /// vmlinux is absent — the preflight rejects that state before
    /// we reach the bake step, so a manifest with `vmlinux_sha256
    /// = None` should never appear on disk under the default
    /// invocation.
    vmlinux_sha256: Option<String>,
}

/// Outputs covered by the per-role integrity manifest. Recorded in
/// `bake.json` so an operator (or downstream tooling) can verify
/// the on-disk artefacts match what the bake claimed it produced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BakeOutputs {
    /// SHA-256 of the produced cpio.gz blob at
    /// `<install_dir>/images/<stem>-<kver>.img`.
    img_sha256: String,
    /// On-disk size in bytes of the produced `.img` blob.
    img_size_bytes: u64,
    /// SHA-256 of the produced TOML-encoded image manifest at
    /// `<install_dir>/images/<stem>-<kver>.manifest.toml`.
    manifest_toml_sha256: String,
    /// On-disk size in bytes of the produced `.manifest.toml`.
    manifest_toml_size_bytes: u64,
}

/// Host-context fields recorded in the integrity manifest. Pure
/// metadata; not consulted by the no-op shortcut (a bake on a
/// different host should not invalidate the cache as long as the
/// observable inputs match).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BakeHostInfo {
    /// `cfg!(target_os)` string when the bake ran ("macos" /
    /// "linux" / ...).
    os: String,
    /// `cfg!(target_arch)` string ("aarch64" / "x86_64").
    arch: String,
    /// Cross-compile target triple the bake used.
    target_triple: String,
    /// Container builder used to bake the rootfs, when relevant
    /// (`docker` / `podman` / `buildah`). `None` for binary-only
    /// roles that don't invoke the OCI builder.
    container_builder: Option<String>,
}

/// On-disk shape of `<install_dir>/images/<stem>-<kver>.bake.json`.
///
/// Read by the no-op shortcut, written atomically by the bake
/// driver. The same struct is also written as
/// `<install_dir>/images/<stem>-<kver>.bake.json.tmp` then renamed
/// so a partial write cannot corrupt the cache state.
///
/// **Schema discipline.** A new field MUST be `#[serde(default)]`
/// so a pre-existing on-disk manifest from an earlier xtask version
/// still deserialises (rather than tripping the no-op shortcut
/// into a forced rebake). Field removals require a schema-version
/// bump.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BakeManifest {
    schema_version: u32,
    role: String,
    artefact_stem: String,
    kernel_version: String,
    /// UNIX seconds-since-epoch when the bake completed. Cosmetic;
    /// the no-op shortcut does not consult this.
    built_at_unix: u64,
    host: BakeHostInfo,
    inputs: BakeInputs,
    outputs: BakeOutputs,
}

impl BakeManifest {
    /// Path the per-role manifest lives at — sibling of the `.img`
    /// and `.manifest.toml` it summarises. Pinning the layout in
    /// one helper keeps every reader / writer in lockstep.
    fn path(install_dir: &Path, role: Role, kernel_version: &str) -> PathBuf {
        install_dir.join("images").join(format!(
            "{stem}-{kver}.bake.json",
            stem = role.artefact_stem(),
            kver = kernel_version,
        ))
    }

    /// Read a prior manifest from disk, returning `None` if the
    /// file is absent or fails to parse (the no-op shortcut treats
    /// "no manifest" and "corrupt manifest" identically — the
    /// safe answer in both cases is to rebake).
    fn read_from(path: &Path) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        let parsed: BakeManifest = serde_json::from_slice(&bytes).ok()?;
        if parsed.schema_version != BAKE_MANIFEST_SCHEMA_VERSION {
            // A future-version manifest is treated as "unknown" so
            // an older xtask never trusts a newer manifest's
            // shortcut decision; we rebake under our own rules.
            return None;
        }
        Some(parsed)
    }

    /// Serialise to pretty JSON and write atomically. The pretty
    /// shape (2-space indent) is intentional — the file is meant
    /// to be operator-readable, and `bake.json` files are small
    /// (under 1 KiB even with future field growth).
    fn write_atomic(&self, dest: &Path) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(self).context("encode bake manifest")?;
        bytes.push(b'\n');
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {} (for bake manifest)", parent.display()))?;
        }
        let tmp = dest.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes).with_context(|| format!("write {} (tmp)", tmp.display()))?;
        std::fs::rename(&tmp, dest)
            .with_context(|| format!("rename {} -> {}", tmp.display(), dest.display()))?;
        Ok(())
    }
}

/// Read the per-role `BuildInputs` (and extract its `kernel_version`)
/// without committing to a full bake. Used by the preflight to plan
/// per-role manifest paths and by the no-op shortcut to compute
/// where the prior `bake.json` would live.
fn read_kernel_version_for(workspace_root: &Path, role: Role) -> Result<String> {
    let inputs_path = inputs_manifest_path(workspace_root, role);
    let s = std::fs::read_to_string(&inputs_path).with_context(|| {
        format!(
            "read {}: per-role manifest.toml is required to resolve \
             kernel_version for bake-output paths",
            inputs_path.display(),
        )
    })?;
    let parsed: raxis_image_builder::BuildInputs =
        toml::from_str(&s).with_context(|| format!("parse {}", inputs_path.display()))?;
    Ok(parsed.kernel_version)
}

/// Compute the current input inventory for one role. Reads the
/// Containerfile, the in-tree `manifest.toml`, the staged planner
/// binary (if any), and the canonical vmlinux.
///
/// Errors only on inputs the bake step is going to need anyway
/// (`manifest.toml`, `vmlinux`). The Containerfile is `Option<Sha>`
/// because a future role might be binary-only and ship without
/// one; the staged-binary entry is `Option<Sha>` because dev-stage
/// may not have run yet. The bake driver re-stages the binary
/// before passing the inventory to `BakeManifest::write_atomic`,
/// so a final manifest never carries `staged_binary_sha256 =
/// None`.
fn compute_bake_inputs(
    role: Role,
    workspace_root: &Path,
    install_dir: &Path,
    signing_key_fp_prefix: &str,
) -> Result<BakeInputs> {
    let containerfile = containerfile_path(workspace_root, role);
    let containerfile_sha256 = if containerfile.exists() {
        Some(sha256_file(&containerfile)?)
    } else {
        None
    };

    let inputs_manifest_sha256 = sha256_file(&inputs_manifest_path(workspace_root, role))?;

    let staged_binary = workspace_root
        .join(STAGING_PARENT)
        .join(role.images_subdir())
        .join("rootfs")
        .join("usr")
        .join("local")
        .join("bin")
        .join(role.binary_name());
    let staged_binary_sha256 = if staged_binary.exists() {
        Some(sha256_file(&staged_binary)?)
    } else {
        None
    };
    let source_tree_sha256 = role_source_tree_sha256(role, workspace_root)?;

    let vmlinux = install_dir.join("kernel").join("vmlinux");
    let vmlinux_sha256 = if vmlinux.exists() {
        Some(sha256_file(&vmlinux)?)
    } else {
        None
    };

    Ok(BakeInputs {
        containerfile_sha256,
        inputs_manifest_sha256,
        staged_binary_sha256,
        source_tree_sha256,
        signing_key_fp_prefix: signing_key_fp_prefix.to_owned(),
        vmlinux_sha256,
    })
}

/// Decide whether the prior `bake.json` lets us short-circuit one
/// role's bake. Returns `Some(prior_manifest)` to skip with a log
/// line, or `None` to proceed with the full bake.
///
/// The shortcut fires only when:
///
///  1. A prior manifest exists at the expected path.
///  2. The prior manifest's `inputs` matches the just-computed
///     inputs **byte-for-byte** (including the vmlinux SHA — a
///     guest-kernel rotation re-bakes everything because the
///     manifest binds image to kernel pair).
///  3. The `.img` and `.manifest.toml` outputs still exist on disk
///     and their SHA-256s match what the prior manifest recorded.
///
/// If ANY of those checks fails the shortcut bails. There's no
/// "partial" no-op — either every input is unchanged AND every
/// output is intact, or we rebake.
fn bake_should_skip(
    install_dir: &Path,
    role: Role,
    kernel_version: &str,
    current_inputs: &BakeInputs,
) -> Result<Option<BakeManifest>> {
    let manifest_path = BakeManifest::path(install_dir, role, kernel_version);
    let Some(prior) = BakeManifest::read_from(&manifest_path) else {
        return Ok(None);
    };
    if &prior.inputs != current_inputs {
        return Ok(None);
    }
    let img = install_dir.join("images").join(format!(
        "{stem}-{kver}.img",
        stem = role.artefact_stem(),
        kver = kernel_version,
    ));
    let manifest_toml = install_dir.join("images").join(format!(
        "{stem}-{kver}.manifest.toml",
        stem = role.artefact_stem(),
        kver = kernel_version,
    ));
    if !img.exists() || !manifest_toml.exists() {
        return Ok(None);
    }
    let img_sha = sha256_file(&img)?;
    if img_sha != prior.outputs.img_sha256 {
        return Ok(None);
    }
    let mtoml_sha = sha256_file(&manifest_toml)?;
    if mtoml_sha != prior.outputs.manifest_toml_sha256 {
        return Ok(None);
    }
    Ok(Some(prior))
}

// ---------------------------------------------------------------------------
// Containerfile graph acyclicity (INV-IMAGE-BAKE-NO-CIRCULAR-CONTAINERFILE-01)
// ---------------------------------------------------------------------------

/// Per-role bake tag the OCI build step emits, in the form
/// `raxis-rootfs-<images-subdir>:dev`. Mirrors `bake_one_role`'s
/// `tag` construction so the acyclicity check inspects the same
/// names the actual `<builder> build` would use as a `FROM`
/// argument.
fn role_bake_tag(role: Role) -> String {
    format!("raxis-rootfs-{}:dev", role.images_subdir())
}

/// Tokens that, when found as the immediate operand of `FROM`,
/// indicate the in-tree Containerfile chains another in-tree
/// role's bake output as its base layer. Returning `Some(role)`
/// means the parsed `FROM` operand matches one of `Role::all()`'s
/// bake tags.
fn from_token_names_in_tree_role(token: &str) -> Option<Role> {
    let normalised = token.trim_end_matches(|c: char| c == '\n' || c.is_whitespace());
    for r in Role::all() {
        if normalised == role_bake_tag(*r) {
            return Some(*r);
        }
    }
    None
}

/// Parse every in-tree Containerfile and assert no role's recipe
/// pulls another role's bake tag as a `FROM` base. The check is
/// **conservative**: it accepts any `FROM` operand that does NOT
/// match one of `role_bake_tag(...)` (`debian:bookworm-slim`,
/// `scratch`, multi-stage `AS <name>` references, registry URLs,
/// etc.). The only rejection shape is a `FROM` that explicitly
/// names another in-tree role's tag, which is the historical
/// `Containerfile.dev` failure mode (untracked diff in the
/// pre-migration aegis-ai checkout; cleaned out by the
/// `chika5105/raxis` migration sweep but kept in the spec as a
/// regression guard).
///
/// Returns `Ok(())` on a clean graph; bails with the offending
/// (role, from_token, role_pulled_in) triple otherwise so the
/// remediation message names the exact problem line.
fn check_containerfile_graph_acyclic(workspace_root: &Path) -> Result<()> {
    for r in Role::all() {
        let path = containerfile_path(workspace_root, *r);
        if !path.exists() {
            continue;
        }
        let body = std::fs::read_to_string(&path)
            .with_context(|| format!("read {} (Containerfile graph check)", path.display()))?;
        for (lineno, raw_line) in body.lines().enumerate() {
            let line = raw_line.trim_start();
            // Comments and blank lines never define a base image.
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Match `FROM <image>` (case-insensitive — Containerfile
            // grammar treats directives as case-insensitive). We
            // accept `FROM`, `from`, `From`, etc.
            let lower = line.to_ascii_lowercase();
            if !lower.starts_with("from ") && !lower.starts_with("from\t") {
                continue;
            }
            // After `FROM`, the operand is the next whitespace-
            // separated token. We strip the optional `--platform=`
            // flag the Containerfile grammar allows so a
            // `FROM --platform=$BUILDPLATFORM scratch` line
            // resolves to the `scratch` operand for this check.
            let rest = &line[4..].trim_start();
            let mut tokens = rest.split_whitespace();
            let Some(mut operand) = tokens.next() else {
                continue;
            };
            while operand.starts_with("--") {
                operand = match tokens.next() {
                    Some(t) => t,
                    None => break,
                };
            }
            if let Some(target) = from_token_names_in_tree_role(operand) {
                bail!(
                    "INV-IMAGE-BAKE-NO-CIRCULAR-CONTAINERFILE-01 VIOLATED: \
                     {} line {} declares `FROM {}`, which is the bake \
                     tag the in-tree pipeline produces for role {:?}. \
                     This is the pre-migration `Containerfile.dev` \
                     shape — one role's image chained as another \
                     role's base layer — and produces a build-order \
                     cycle that surfaces as a confusing `image not \
                     found` failure on a fresh checkout (the upstream \
                     role's tag does not exist until you bake it). \n\n\
                     Remediation: replace the `FROM` operand with a \
                     concrete upstream image (`debian:bookworm-slim`, \
                     `scratch`, …) and copy in the upstream binaries \
                     via `COPY --from=<stage>` from the upstream \
                     Containerfile if needed.",
                    path.display(),
                    lineno + 1,
                    operand,
                    target,
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// vmlinux staging (INV-IMAGE-BAKE-VMLINUX-STAGED-01)
// ---------------------------------------------------------------------------

/// Source of truth resolution for the Linux guest-kernel binary
/// the bake should stage into `<install_dir>/kernel/vmlinux`.
///
/// Order, with the **first present** source winning:
///
/// 1. Explicit `--kernel-from-file <PATH>` on the bake CLI.
/// 2. `RAXIS_DEV_KERNEL_SOURCE` env var.
/// 3. An already-staged file at `<install_dir>/kernel/vmlinux`
///    (the bake reuses it).
/// 4. The canonical host install at
///    `/usr/local/lib/raxis/kernel/vmlinux` (the same path the
///    `cargo xtask images dev-kernel` flow targets per
///    `system-requirements.md §11`).
///
/// Returns the path the bake should copy (or `None` if the target
/// already-staged path is in use and matches the canonical
/// location — i.e. nothing to copy). Bails with a remediation
/// message naming the `dev-kernel` flow when none of the four
/// sources resolves.
#[derive(Debug, Clone, PartialEq, Eq)]
enum VmlinuxResolution {
    /// `<install_dir>/kernel/vmlinux` already exists and we will
    /// NOT overwrite it. The bake records its SHA in the manifest.
    AlreadyStaged { path: PathBuf },
    /// Source resolves to a path we MUST copy into the canonical
    /// staging location.
    CopyFrom { source: PathBuf },
}

fn resolve_vmlinux_source(
    install_dir: &Path,
    explicit_from: Option<&Path>,
    force_overwrite: bool,
) -> Result<VmlinuxResolution> {
    let staged = install_dir.join("kernel").join("vmlinux");

    // 1 + 2: explicit / env override. Both win over an
    // already-staged file IFF `--force` is set; without force,
    // any in-place file takes precedence so a successful prior
    // `dev-kernel` run is not re-overwritten by a stale env var.
    let explicit_env = std::env::var_os("RAXIS_DEV_KERNEL_SOURCE").map(PathBuf::from);
    let override_source = explicit_from.map(PathBuf::from).or(explicit_env);

    if let Some(src) = override_source.as_ref() {
        let src_meta = std::fs::metadata(src).with_context(|| {
            format!(
                "stat {} (resolved from --kernel-from-file / RAXIS_DEV_KERNEL_SOURCE)",
                src.display(),
            )
        })?;
        if !src_meta.is_file() || src_meta.len() == 0 {
            bail!(
                "INV-IMAGE-BAKE-VMLINUX-STAGED-01: explicit kernel source {} \
                 is not a non-empty file (size={}, is_file={}). The bake \
                 refuses to stage a stub or a directory as vmlinux.",
                src.display(),
                src_meta.len(),
                src_meta.is_file(),
            );
        }
        // If the source IS the same canonical path that's already
        // staged (e.g. the operator passed `--kernel-from-file
        // /usr/local/lib/raxis/kernel/vmlinux` which happens to be
        // the install dir's staged path), don't copy onto itself.
        if let Ok(staged_canon) = staged.canonicalize() {
            if let Ok(src_canon) = src.canonicalize() {
                if staged_canon == src_canon {
                    return Ok(VmlinuxResolution::AlreadyStaged { path: staged });
                }
            }
        }
        if staged.exists() && !force_overwrite {
            // Honour --force semantics: refuse to overwrite a
            // working kernel unless explicitly asked. The
            // operator's intent matters here — a fresh
            // `--kernel-from-file` after a successful boot run
            // should NOT silently invalidate the staged binary
            // without a deliberate `--force`.
            return Ok(VmlinuxResolution::AlreadyStaged { path: staged });
        }
        return Ok(VmlinuxResolution::CopyFrom {
            source: src.clone(),
        });
    }

    // 3: already staged at the install dir (the common no-op case
    // when the operator already ran `dev-kernel` or a previous
    // bake).
    if let Ok(meta) = std::fs::metadata(&staged) {
        if meta.is_file() && meta.len() > 0 {
            return Ok(VmlinuxResolution::AlreadyStaged { path: staged });
        }
    }

    // 4: canonical host install (the path `dev-kernel` defaults
    // to). Used by operators who keep one global kernel and run
    // bakes against per-developer install dirs.
    let canonical = PathBuf::from("/usr/local/lib/raxis/kernel/vmlinux");
    if canonical.exists() && canonical != staged {
        return Ok(VmlinuxResolution::CopyFrom { source: canonical });
    }

    bail!(
        "INV-IMAGE-BAKE-VMLINUX-STAGED-01 VIOLATED: no Linux guest-kernel \
         binary (`vmlinux`) found at any of:\n  \
         - --kernel-from-file <PATH>            (CLI flag)\n  \
         - $RAXIS_DEV_KERNEL_SOURCE             (env override)\n  \
         - {staged}\n  \
         - /usr/local/lib/raxis/kernel/vmlinux  (canonical install)\n\n\
         AVF and Firecracker substrates resolve their boot kernel from \n  \
         <install_dir>/kernel/vmlinux\n\
         per `canonical_images_preflight::linux_kernel_path`. Without it, \
         the first session-spawn surfaces `AVF VM start failed: Invalid \
         virtual machine configuration. The boot loader is invalid.` two \
         seconds into the run.\n\n\
         Remediation: stage a kernel via `cargo xtask images dev-kernel \
         --from-file <PATH>` and re-run bake; or pass \
         `--kernel-from-file <PATH>` directly to `cargo xtask images bake`.",
        staged = staged.display(),
    )
}

/// Apply a resolved `VmlinuxResolution`: copy if needed, leave
/// alone otherwise. Returns the SHA-256 of the bytes on disk after
/// the operation (so the caller can fold it into the per-role
/// integrity manifest without re-reading the file). Atomically
/// stages via a temp-file rename so a partial copy never replaces
/// a working kernel.
fn apply_vmlinux_resolution(
    install_dir: &Path,
    resolution: &VmlinuxResolution,
    explicit_config: Option<&Path>,
) -> Result<String> {
    let (kernel_path, config_lookup_path) = match resolution {
        VmlinuxResolution::AlreadyStaged { path } => (path.clone(), path.clone()),
        VmlinuxResolution::CopyFrom { source } => {
            let dest_dir = install_dir.join("kernel");
            std::fs::create_dir_all(&dest_dir)
                .with_context(|| format!("create {}", dest_dir.display()))?;
            let dest = dest_dir.join("vmlinux");
            let tmp = dest_dir.join(".vmlinux.tmp");
            std::fs::copy(source, &tmp).with_context(|| {
                format!("copy vmlinux: {} -> {}", source.display(), tmp.display(),)
            })?;
            std::fs::rename(&tmp, &dest).with_context(|| {
                format!("atomic rename {} -> {}", tmp.display(), dest.display(),)
            })?;
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"bake_vmlinux_staged\",\
                 \"source\":{:?},\"dest\":{:?}}}",
                source.display().to_string(),
                dest.display().to_string(),
            );
            (dest, source.clone())
        }
    };
    let config = resolve_and_validate_kernel_config(&config_lookup_path, explicit_config)?;
    let config_path = stage_kernel_config(install_dir, &config)?;
    let config_source = match &config.source {
        KernelConfigSource::Explicit(path) => format!("explicit:{}", path.display()),
        KernelConfigSource::Sidecar(path) => format!("sidecar:{}", path.display()),
        KernelConfigSource::EmbeddedIkconfig => "embedded:IKCONFIG".to_owned(),
    };
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"bake_vmlinux_config_validated\",\
         \"kernel_path\":{:?},\"config_path\":{:?},\"config_source\":{:?}}}",
        kernel_path.display().to_string(),
        config_path.display().to_string(),
        config_source,
    );
    sha256_file(&kernel_path)
}

// ---------------------------------------------------------------------------
// Host-tool preflight (INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01)
// ---------------------------------------------------------------------------

/// Outcome from preflight: every input that the bake needs has been
/// resolved AND probed for availability. The bake driver consumes
/// this struct and never re-resolves any of these — preflight is
/// the single point where missing-input failures surface.
#[derive(Debug)]
struct PreflightOutcome {
    /// Container builder for roles that need an OCI bake. `None`
    /// when the selected roles are all binary-only.
    container_builder: Option<Builder>,
    /// Cross-compile target triple all roles will build against.
    target_triple: String,
    /// Resolved vmlinux source (or "already staged"). The bake
    /// driver passes this to `apply_vmlinux_resolution`.
    vmlinux: VmlinuxResolution,
    /// First 16 hex chars of the signing-key fingerprint, recorded
    /// in the integrity manifest.
    signing_key_fp_prefix: String,
}

/// Preflight every input the bake will need before producing ANY
/// artefact. Fails closed with a remediation message naming the
/// missing piece. Pure-read: never mutates the filesystem.
///
/// The function takes ownership of the parsed bake args so it can
/// emit role-specific remediation (e.g., "container builder is
/// only required because role `executor-starter` needs it").
fn preflight_bake_inputs(
    workspace_root: &Path,
    install_dir: &Path,
    signing_key: &Path,
    roles: &[Role],
    explicit_builder: Option<Builder>,
    explicit_kernel: Option<&Path>,
    explicit_kernel_config: Option<&Path>,
    force_overwrite: bool,
) -> Result<PreflightOutcome> {
    // 1. Containerfile graph acyclicity — runs first because it's
    //    pure-read and a cycle means no bake can ever succeed.
    check_containerfile_graph_acyclic(workspace_root)?;

    // 2. Per-role `manifest.toml` and `Containerfile` existence.
    //    The bake step would error on these later anyway; surfacing
    //    them here gives the operator one clean diagnostic instead
    //    of a partial bake followed by a confusing per-role error.
    for r in roles {
        let containerfile = containerfile_path(workspace_root, *r);
        let inputs = inputs_manifest_path(workspace_root, *r);
        if r.needs_rootfs_bake() && !containerfile.exists() {
            bail!(
                "INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01: role {:?} \
                 requires an OCI rootfs bake but its Containerfile is \
                 missing at {}. The bake refuses to proceed without \
                 the per-role recipe.",
                r,
                containerfile.display(),
            );
        }
        if !inputs.exists() {
            bail!(
                "INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01: role {:?} is \
                 missing its in-tree manifest.toml at {}. This fixture \
                 pins kernel_version / source_date_epoch / ... and is \
                 required for the build-all signing step.",
                r,
                inputs.display(),
            );
        }
    }

    // 3. Signing key presence + non-empty + parseable.
    if !signing_key.exists() {
        bail!(
            "INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01: signing key not \
             found at {}. Run `cargo xtask dev-keys init` first \
             (release-and-distribution.md §8.1), or pass --signing-key \
             <PATH> to point at a pre-existing key.",
            signing_key.display(),
        );
    }
    let signing_key_bytes = load_signing_key(signing_key)?;
    let fp_hex = hex::encode(raxis_image_manifest::fingerprint_signing_key(
        &signing_key_bytes.verifying_key(),
    ));
    let signing_key_fp_prefix = fp_hex.chars().take(16).collect::<String>();

    // 4. Container builder resolution (only when any role needs
    //    an OCI bake). Detects daemon-not-running for `docker`
    //    explicitly so we don't wait for the `build` subprocess to
    //    surface that as a confusing exit-1 deep in the bake step.
    let any_needs_bake = roles.iter().any(|r| r.needs_rootfs_bake());
    let container_builder = if any_needs_bake {
        let builder = match explicit_builder {
            Some(b) => b,
            None => Builder::auto_detect()?,
        };
        verify_builder_daemon(builder)?;
        Some(builder)
    } else {
        None
    };

    // 5. Rust musl cross-target sanity. We don't fail closed on a
    //    missing target here (the dev-stage step surfaces a clear
    //    `rustup target add` remediation) but we DO assert the
    //    matching musl linker exists when on macOS — that's the
    //    `brew install musl-cross` hint operators hit most often.
    let target_triple = default_target_triple().to_owned();
    #[cfg(target_os = "macos")]
    {
        if target_triple.contains("musl") {
            let prefix = if target_triple.starts_with("aarch64-") {
                "aarch64-linux-musl-gcc"
            } else {
                "x86_64-linux-musl-gcc"
            };
            if which(prefix).is_none() {
                bail!(
                    "INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01: musl \
                     linker `{prefix}` not found on $PATH. Install via:\n  \
                     brew install filosottile/musl-cross/musl-cross\n\
                     (or pin a different target via --target). Bake \
                     refuses to proceed because dev-stage would fail \
                     mid-flight with a less helpful error from cargo."
                );
            }
        }
    }

    // 6. vmlinux resolution — fails closed if no source resolves.
    let vmlinux = resolve_vmlinux_source(install_dir, explicit_kernel, force_overwrite)?;
    let kernel_path = match &vmlinux {
        VmlinuxResolution::AlreadyStaged { path } => path.as_path(),
        VmlinuxResolution::CopyFrom { source } => source.as_path(),
    };
    let _kernel_config = resolve_and_validate_kernel_config(kernel_path, explicit_kernel_config)?;

    Ok(PreflightOutcome {
        container_builder,
        target_triple,
        vmlinux,
        signing_key_fp_prefix,
    })
}

/// Probe the resolved container builder for an active daemon /
/// usable socket. `docker info` is the universally-supported probe
/// — both rootful and rootless daemons answer it; `podman` accepts
/// it as a compatibility shim; `buildah` is daemon-less so the
/// probe degenerates to "the binary exists" (already verified by
/// `Builder::auto_detect`).
///
/// On daemon-not-running, surfaces a clear remediation message
/// naming the offending socket. The most common shape on a fresh
/// macOS dev host is "Docker CLI installed via Homebrew but
/// Docker Desktop is not running" — the remediation explicitly
/// names that.
fn verify_builder_daemon(builder: Builder) -> Result<()> {
    match builder {
        Builder::Buildah => Ok(()), // daemon-less; binary check sufficed.
        Builder::Docker | Builder::Podman => {
            let out = std::process::Command::new(builder.binary())
                .arg("info")
                .output()
                .with_context(|| {
                    format!(
                        "spawn `{builder} info` (daemon probe)",
                        builder = builder.binary(),
                    )
                })?;
            if out.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Docker Desktop's daemon-down stderr contains a
            // "Cannot connect to the Docker daemon" line; podman's
            // analogous message names the socket. Surface either
            // verbatim alongside our remediation hint.
            let hint = match builder {
                Builder::Docker => "Start Docker Desktop (macOS: open /Applications/Docker.app)",
                Builder::Podman => "Start the podman machine (`podman machine start`)",
                Builder::Buildah => unreachable!(),
            };
            bail!(
                "INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01: `{} info` \
                 reports the container daemon is not reachable \
                 (exit {}). The bake refuses to proceed because the \
                 subsequent `build` would fail with a less helpful \
                 error mid-pipeline.\n\n\
                 Remediation: {}\n\n\
                 Daemon probe output:\n--- stderr ---\n{}\n\
                 --- stdout (tail) ---\n{}",
                builder.binary(),
                out.status,
                hint,
                stderr.trim(),
                stdout
                    .lines()
                    .rev()
                    .take(4)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// `cargo xtask images bake` entry point + arg parser
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BakeArgs {
    /// Empty = bake every role. Non-empty = bake the named roles
    /// only.
    roles: Vec<Role>,
    install_dir: PathBuf,
    signing_key: PathBuf,
    workspace_root: PathBuf,
    explicit_builder: Option<Builder>,
    explicit_kernel: Option<PathBuf>,
    explicit_kernel_config: Option<PathBuf>,
    /// When true, overwrite an existing
    /// `<install_dir>/kernel/vmlinux` with the explicit-source
    /// kernel even if the staged copy already exists. The bake
    /// itself still uses the prior-manifest no-op shortcut for
    /// rootfs images; `--force` only flips the vmlinux replacement
    /// behaviour.
    force: bool,
    /// When true, bake refuses to short-circuit even when the prior
    /// `bake.json` says nothing changed. Used by CI to assert the
    /// pipeline reproduces from scratch.
    no_cache: bool,
}

impl BakeArgs {
    fn parse(argv: &[String]) -> Result<Self> {
        let mut roles: Vec<Role> = Vec::new();
        let mut install_dir: Option<PathBuf> = None;
        let mut signing_key: Option<PathBuf> = None;
        let mut explicit_builder: Option<Builder> = None;
        let mut explicit_kernel: Option<PathBuf> = None;
        let mut explicit_kernel_config: Option<PathBuf> = None;
        let mut force: bool = false;
        let mut no_cache: bool = false;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--role" => {
                    i += 1;
                    let r = Role::parse(argv.get(i).context("--role requires a value")?)?;
                    if !roles.contains(&r) {
                        roles.push(r);
                    }
                }
                "--install-dir" => {
                    i += 1;
                    install_dir = Some(PathBuf::from(
                        argv.get(i).context("--install-dir requires a path")?,
                    ));
                }
                "--signing-key" => {
                    i += 1;
                    signing_key = Some(PathBuf::from(
                        argv.get(i).context("--signing-key requires a path")?,
                    ));
                }
                "--builder" => {
                    i += 1;
                    explicit_builder = Some(Builder::parse(
                        argv.get(i).context("--builder requires a value")?,
                    )?);
                }
                "--kernel-from-file" => {
                    i += 1;
                    explicit_kernel = Some(PathBuf::from(
                        argv.get(i).context("--kernel-from-file requires a path")?,
                    ));
                }
                "--kernel-config" => {
                    i += 1;
                    explicit_kernel_config = Some(PathBuf::from(
                        argv.get(i).context("--kernel-config requires a path")?,
                    ));
                }
                "--force" => force = true,
                "--no-cache" => no_cache = true,
                "-h" | "--help" => {
                    print_bake_help();
                    std::process::exit(0);
                }
                other => bail!("unknown bake arg: {other}"),
            }
            i += 1;
        }

        if roles.is_empty() {
            roles.extend(Role::all().iter().copied());
        }

        let install_dir = install_dir
            .or_else(|| std::env::var_os("RAXIS_INSTALL_DIR").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DEV_INSTALL_DIR));
        // INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01 — when the operator
        // does not pass --signing-key explicitly, default to the
        // per-clone, autogen-on-first-run keypair at
        // `.git/info/raxis-signing-key/sk.hex`. The umbrella
        // `run_bake_inner` calls `ensure_dev_signing_keypair` on
        // every invocation so this path is guaranteed to exist by
        // the time `build_all` reads it. The legacy home-dir path
        // (`$HOME/.config/raxis/keys/raxis-dev-signing.key.hex`,
        // minted by `cargo xtask dev-keys init`) is still respected
        // when explicitly passed via `--signing-key`.
        let workspace_root = workspace_root_from_cwd()?;
        let signing_key = signing_key.unwrap_or_else(|| {
            git_info_signing_key_dir(&workspace_root).join(GIT_INFO_KEY_SK_FILENAME)
        });

        Ok(Self {
            roles,
            install_dir,
            signing_key,
            workspace_root,
            explicit_builder,
            explicit_kernel,
            explicit_kernel_config,
            force,
            no_cache,
        })
    }
}

fn print_bake_help() {
    eprintln!(
        "usage: cargo xtask images bake [--role <ROLE>]... \n         \
         [--install-dir <PATH>] [--signing-key <PATH>] \n         \
         [--builder docker|podman|buildah] [--kernel-from-file <PATH>] \n         \
         [--kernel-config <PATH>] \n         \
         [--force] [--no-cache]\n\
         \n\
         Single-command end-to-end image-bake pipeline. Preflights inputs,\n\
         builds any required role rootfs, cross-compiles the guest PID-1\n\
         binaries, packs signed initramfs images, and stages the Linux guest-kernel\n\
         binary at <install_dir>/kernel/vmlinux so the substrate can boot\n\
         from a fresh install dir on first try.\n\
         \n\
         Defaults:\n  \
         --role             every canonical role (orchestrator, reviewer,\n                     \
                            executor-starter, verifier-starter,\n                     \
                            verifier-symbol-index)\n  \
         --install-dir      $RAXIS_INSTALL_DIR (or {default_install})\n  \
         --signing-key      <workspace>/.git/info/raxis-signing-key/sk.hex\n                     \
                            (autogen on first run; per-clone, untracked.\n                     \
                            INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01)\n  \
         --builder          auto-detect (docker → podman → buildah)\n  \
         --kernel-from-file resolution order: --kernel-from-file → \n                     \
                            $RAXIS_DEV_KERNEL_SOURCE → \n                     \
                            <install_dir>/kernel/vmlinux (already-staged) → \n                     \
                            /usr/local/lib/raxis/kernel/vmlinux\n\
         --kernel-config   optional Linux .config for the selected vmlinux;\n                     \
                            otherwise bake looks for a sidecar vmlinux.config\n                     \
                            or embedded CONFIG_IKCONFIG.\n\
         \n\
         Per-role outputs:\n  \
         <install_dir>/images/raxis-<role>-<kver>.img\n  \
         <install_dir>/images/raxis-<role>-<kver>.manifest.toml   (signed)\n  \
         <install_dir>/images/raxis-<role>-<kver>.bake.json       (integrity manifest)\n  \
         <install_dir>/kernel/vmlinux                              (guest kernel)\n\
         \n\
         Re-running `bake` on an unchanged tree is a fast no-op only when\n\
         source fingerprints, inputs, and outputs all match the prior\n\
         bake.json. Pass --no-cache to force a full rebake.\n\
         \n\
         Dev signing key (INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01 +\n  \
         INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01, iter66):\n  \
         On first run, `bake` mints an Ed25519 keypair under\n  \
         <workspace>/.git/info/raxis-signing-key/{{sk.hex,pk.hex}} (mode\n  \
         0700/0600/0600). On every run the public half is resolved via\n  \
         the canonical search order\n  \
         (`trust_anchor::resolve_signing_key_pk_hex`):\n  \
         (1) RAXIS_KERNEL_SIGNING_KEY_HEX, (2) RAXIS_KERNEL_SIGNING_KEY_PATH,\n  \
         (3) <workspace>/.git/info/raxis-signing-key/pk.hex, (4) the\n  \
         nested <workspace>/raxis/.git/info/... variant — and injected\n  \
         into every spawned cargo subprocess via per-`Command` `.env(...)`.\n  \
         A later `cargo build -p raxis-kernel` from the same workspace\n  \
         also sees the matching trust anchor through the per-clone\n  \
         pk.hex file. The\n  \
         CI / release pipeline path is unchanged: those workflows pre-set\n  \
         RAXIS_KERNEL_SIGNING_KEY_HEX from a secret, which arm 1 picks\n  \
         up over the per-clone dev key. To audit the host daemon's embedded\n  \
         trust anchor after rebuilding `raxis-kernel`, run:\n  \
         cargo xtask images verify-trust-anchor --kernel <path-to-raxis-kernel>\n",
        default_install = DEFAULT_DEV_INSTALL_DIR,
    );
}

/// Entry point for `cargo xtask images bake`.
pub fn run_bake(argv: &[String]) -> Result<()> {
    let args = BakeArgs::parse(argv)?;
    run_bake_inner(&args)
}

fn run_bake_inner(args: &BakeArgs) -> Result<()> {
    let roles_json: Vec<&str> = args.roles.iter().map(|r| r.workspace_crate()).collect();
    let begin_payload = serde_json::json!({
        "level": "info",
        "event": "bake_begin",
        "roles": roles_json,
        "install_dir": args.install_dir.display().to_string(),
        "workspace_root": args.workspace_root.display().to_string(),
    });
    eprintln!("{begin_payload}");

    // 0. Ensure the per-clone dev signing keypair under
    //    `.git/info/raxis-signing-key/` exists (autogen on first
    //    run). INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01.
    let keypair = ensure_dev_signing_keypair(&args.workspace_root)?;
    if keypair.generated_now {
        eprintln!(
            "generated new dev signing key at {}",
            keypair.pk_path.display()
        );
    } else {
        eprintln!("using dev signing key from {}", keypair.pk_path.display());
    }

    // 0b. Re-resolve the trust-anchor pk_hex through the canonical
    //     `trust_anchor::resolve_signing_key_pk_hex` helper. The
    //     just-minted keypair will normally satisfy the arm-3
    //     (canonical `.git/info/`) check; we route through the
    //     helper anyway so an outer `RAXIS_KERNEL_SIGNING_KEY_HEX` /
    //     `RAXIS_KERNEL_SIGNING_KEY_PATH` env (CI / release
    //     pipeline) wins over the just-minted dev key. The
    //     resolved value is then threaded into every cargo
    //     subprocess via per-`Command` `.env(...)` rather than
    //     mutating process-level `std::env` — concurrent xtask
    //     invocations no longer race on the variable.
    //     INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01.
    let resolved_anchor = trust_anchor::resolve_signing_key_pk_hex(&args.workspace_root)
        .map_err(anyhow::Error::new)
        .context(
            "resolve dev signing key for bake cargo subprocesses \
             (INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01)",
        )?;
    eprintln!(
        "{}",
        serde_json::json!({
            "level": "info",
            "event": "bake_trust_anchor_resolved",
            "source": resolved_anchor.source.as_str(),
            "source_path": resolved_anchor
                .source_path
                .as_ref()
                .map(|p| p.display().to_string()),
            "pk_hex_prefix": &resolved_anchor.pk_hex[..16.min(resolved_anchor.pk_hex.len())],
        })
    );
    let pk_hex_for_children = resolved_anchor.pk_hex.clone();

    // 1. Preflight (pure-read; fails closed before any mutation).
    let outcome = preflight_bake_inputs(
        &args.workspace_root,
        &args.install_dir,
        &args.signing_key,
        &args.roles,
        args.explicit_builder,
        args.explicit_kernel.as_deref(),
        args.explicit_kernel_config.as_deref(),
        args.force,
    )?;

    // 2. Stage vmlinux into the canonical install location BEFORE
    //    per-role bakes. This way every per-role manifest can
    //    record the vmlinux SHA in its `inputs` block, binding
    //    image to guest-kernel pair.
    let vmlinux_sha = apply_vmlinux_resolution(
        &args.install_dir,
        &outcome.vmlinux,
        args.explicit_kernel_config.as_deref(),
    )?;

    // 3. Ensure the install-dir's images/ subdir exists. The
    //    `build-all` step would create it, but doing it here keeps
    //    the per-role error messages cleaner (existence-check
    //    failures from inside `bake_one_role` surface at the
    //    OCI-builder layer; doing this up front means a missing
    //    install-dir surfaces as a single, clean error).
    let images_dir = args.install_dir.join("images");
    std::fs::create_dir_all(&images_dir)
        .with_context(|| format!("create {} (per-role outputs)", images_dir.display()))?;

    // The signing key is re-loaded by the per-role `build_all`
    // invocation from `args.signing_key` so we don't pass the
    // parsed key down — keeping the per-role driver decoupled from
    // the umbrella `bake` driver's load order.

    // 4. Per-role bake.
    for role in &args.roles {
        bake_one_role_full(*role, args, &outcome, &vmlinux_sha, &pk_hex_for_children)?;
    }

    // Post-bake trust-anchor verification is intentionally NOT
    // performed against `<install_dir>/kernel/vmlinux`: that file is
    // the Linux *guest* kernel that boots inside the microVM, not the
    // `raxis-kernel` *host daemon* binary. The trust anchor
    // (`EXPECTED_KERNEL_SIGNING_KEY_BYTES`) only ever lands in the
    // host daemon — injected at compile time by
    // `crates/canonical-images/build.rs` from
    // `RAXIS_KERNEL_SIGNING_KEY_HEX`. The bake already threaded that
    // env var through every cargo subprocess it spawned via
    // `apply_trust_anchor_env`; operators still rebuild the host
    // daemon separately with `cargo build --release -p raxis-kernel`
    // (or their release pipeline). Operators wanting an explicit
    // audit of the host daemon's embedded fingerprint should run
    // `cargo xtask images verify-trust-anchor
    //     --kernel "$(command -v raxis-kernel)"`
    // and not infer host-daemon health from the guest vmlinux.

    let roles_json: Vec<&str> = args.roles.iter().map(|r| r.workspace_crate()).collect();
    let payload = serde_json::json!({
        "level": "info",
        "event": "bake_ok",
        "roles": roles_json,
    });
    eprintln!("{payload}");
    Ok(())
}

/// Top-level driver for one role: decide whether to short-circuit
/// via the prior `bake.json`, otherwise run the canonical
/// `bake-rootfs → dev-stage → build-all` flow and emit a fresh
/// integrity manifest.
///
/// `kernel_signing_key_hex` is the resolved 64-char public-half
/// the umbrella `run_bake_inner` computed via
/// `trust_anchor::resolve_signing_key_pk_hex`. It is threaded
/// through to every cargo subprocess the per-role driver spawns
/// (today: `dev_stage`'s cross-compile, plus `build_all`'s
/// auto-stage path). INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01.
fn bake_one_role_full(
    role: Role,
    args: &BakeArgs,
    outcome: &PreflightOutcome,
    vmlinux_sha: &str,
    kernel_signing_key_hex: &str,
) -> Result<()> {
    let kernel_version = read_kernel_version_for(&args.workspace_root, role)?;

    let inputs_now = compute_bake_inputs(
        role,
        &args.workspace_root,
        &args.install_dir,
        &outcome.signing_key_fp_prefix,
    )?;

    // No-op shortcut: prior manifest agrees AND outputs intact.
    if !args.no_cache {
        if let Some(prior) =
            bake_should_skip(&args.install_dir, role, &kernel_version, &inputs_now)?
        {
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"bake_role_no_op\",\
                 \"role\":{:?},\"reason\":\"inputs_unchanged_outputs_intact\",\
                 \"img_sha256\":{:?}}}",
                role.workspace_crate(),
                prior.outputs.img_sha256,
            );
            return Ok(());
        }
    }

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"bake_role_begin\",\
         \"role\":{:?},\"kernel_version\":{:?}}}",
        role.workspace_crate(),
        kernel_version,
    );

    // ── Step 1: bake-rootfs (only for roles that need an OCI bake).
    if role.needs_rootfs_bake() {
        let builder = outcome.container_builder.expect(
            "preflight ensures container_builder.is_some() whenever any \
             selected role needs a rootfs bake",
        );
        let platform = oci_platform_for_target_triple(&outcome.target_triple)?.to_owned();
        bake_one_role(role, builder, &platform, &args.workspace_root, false)?;
    }

    // ── Step 2: dev-stage. For binary-only roles we pass
    //    `--allow-stub` to skip the stub guard (their staging tree
    //    is intentionally just the planner binary).
    let dev_stage_args = DevStageArgs {
        role,
        target: outcome.target_triple.clone(),
        workspace_root: args.workspace_root.clone(),
        cargo: std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()),
        allow_stub: !role.needs_rootfs_bake(),
        // Thread the umbrella driver's resolved trust anchor
        // into the cross-compile cargo subprocess.
        // INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01.
        kernel_signing_key_hex: Some(kernel_signing_key_hex.to_owned()),
    };
    dev_stage(&dev_stage_args)
        .with_context(|| format!("dev-stage for role {role:?} (bake driver)"))?;

    // ── Step 3: build-all (pack + sign).
    let build_args = BuildAllArgs {
        role: Some(role),
        install_dir: args.install_dir.clone(),
        workspace_root: args.workspace_root.clone(),
        signing_key: args.signing_key.clone(),
        no_auto_stage: true, // we already ran dev-stage above
        // Plumb the trust anchor through so the (rarely-fired)
        // auto-stage path inside `build_all` also injects it.
        kernel_signing_key_hex: Some(kernel_signing_key_hex.to_owned()),
    };
    build_all(&build_args)?;

    // ── Step 4: record the integrity manifest. Re-compute inputs
    //    AFTER dev-stage so the staged-binary SHA reflects the
    //    freshly-built binary.
    let inputs_after = compute_bake_inputs(
        role,
        &args.workspace_root,
        &args.install_dir,
        &outcome.signing_key_fp_prefix,
    )?;
    let img_path = args.install_dir.join("images").join(format!(
        "{stem}-{kver}.img",
        stem = role.artefact_stem(),
        kver = kernel_version,
    ));
    let manifest_toml_path = args.install_dir.join("images").join(format!(
        "{stem}-{kver}.manifest.toml",
        stem = role.artefact_stem(),
        kver = kernel_version,
    ));
    let img_sha = sha256_file(&img_path)?;
    let img_size = std::fs::metadata(&img_path)?.len();
    let mtoml_sha = sha256_file(&manifest_toml_path)?;
    let mtoml_size = std::fs::metadata(&manifest_toml_path)?.len();

    let manifest = BakeManifest {
        schema_version: BAKE_MANIFEST_SCHEMA_VERSION,
        role: role.workspace_crate().to_owned(),
        artefact_stem: role.artefact_stem().to_owned(),
        kernel_version: kernel_version.clone(),
        built_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        host: BakeHostInfo {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            target_triple: outcome.target_triple.clone(),
            container_builder: outcome.container_builder.map(|b| b.binary().to_owned()),
        },
        inputs: BakeInputs {
            vmlinux_sha256: Some(vmlinux_sha.to_owned()),
            ..inputs_after
        },
        outputs: BakeOutputs {
            img_sha256: img_sha.clone(),
            img_size_bytes: img_size,
            manifest_toml_sha256: mtoml_sha,
            manifest_toml_size_bytes: mtoml_size,
        },
    };

    let dest = BakeManifest::path(&args.install_dir, role, &kernel_version);
    manifest.write_atomic(&dest)?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"bake_role_ok\",\
         \"role\":{:?},\"img_sha256\":{:?},\"bake_manifest\":{:?}}}",
        role.workspace_crate(),
        img_sha,
        dest.display().to_string(),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// `cargo xtask images verify-trust-anchor` — read-only diagnostic
// that confirms a built raxis-kernel binary embeds the expected
// signing-key fingerprint as `EXPECTED_KERNEL_SIGNING_KEY_BYTES`.
// ---------------------------------------------------------------------------

/// Parsed argv for `cargo xtask images verify-trust-anchor`.
#[derive(Debug)]
struct VerifyTrustAnchorArgs {
    /// Path to the host `raxis-kernel` binary to verify.
    kernel_path: PathBuf,
    /// 64-char lowercase hex of the public key the kernel binary
    /// is expected to embed as `EXPECTED_KERNEL_SIGNING_KEY_BYTES`.
    /// Defaults to `trust_anchor::resolve_signing_key_pk_hex` so an
    /// operator running the bake then this verifier sees the same
    /// resolution arms documented in
    /// `INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01`.
    expected_pk_hex: String,
}

impl VerifyTrustAnchorArgs {
    fn parse(argv: &[String]) -> Result<Self> {
        let mut kernel_path: Option<PathBuf> = None;
        let mut expected_pk_hex: Option<String> = None;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--kernel" => {
                    i += 1;
                    kernel_path = Some(PathBuf::from(
                        argv.get(i).context("--kernel requires a path")?,
                    ));
                }
                "--expected-pk-hex" => {
                    i += 1;
                    expected_pk_hex = Some(
                        argv.get(i)
                            .context("--expected-pk-hex requires a 64-char hex value")?
                            .clone(),
                    );
                }
                "-h" | "--help" => {
                    eprintln!(
                        "usage: cargo xtask images verify-trust-anchor \
                         [--kernel <PATH>] [--expected-pk-hex <HEX>]\n\
                         \n\
                         Reads the built host raxis-kernel binary and asserts its \
                         compile-time trust anchor matches the resolved \
                         pk_hex. --kernel defaults to RAXIS_KERNEL_BINARY, \
                         target/release/raxis-kernel, target/debug/raxis-kernel, \
                         then raxis-kernel on $PATH. --expected-pk-hex defaults \
                         to trust_anchor::resolve_signing_key_pk_hex.\n\
                         \n\
                         Exit codes:\n  \
                         0  trust anchor populated; fingerprint embedded\n  \
                         1  fingerprint missing OR placeholder embedded\n\
                         \n\
                         See INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01\n"
                    );
                    std::process::exit(0);
                }
                "--install-dir" => bail!(
                    "--install-dir no longer applies to verify-trust-anchor. \
                     The trust anchor lives in the host `raxis-kernel` binary, \
                     not <install-dir>/kernel/vmlinux. Pass --kernel <path>."
                ),
                other => bail!("unknown verify-trust-anchor arg: {other}"),
            }
            i += 1;
        }

        let workspace_root = workspace_root_from_cwd()?;
        let kernel_path = match kernel_path {
            Some(p) => p,
            None => default_host_kernel_binary(&workspace_root)?,
        };

        let expected_pk_hex = match expected_pk_hex {
            Some(h) => h.trim().to_owned(),
            None => {
                let resolved = trust_anchor::resolve_signing_key_pk_hex(&workspace_root)
                    .map_err(anyhow::Error::new)
                    .context(
                        "resolve dev signing key for verify-trust-anchor \
                         (pass --expected-pk-hex <HEX> to bypass the \
                         resolution chain)",
                    )?;
                resolved.pk_hex
            }
        };

        Ok(Self {
            kernel_path,
            expected_pk_hex,
        })
    }
}

fn default_host_kernel_binary(workspace_root: &Path) -> Result<PathBuf> {
    let env_override = std::env::var_os("RAXIS_KERNEL_BINARY")
        .filter(|raw| !raw.is_empty())
        .map(PathBuf::from);
    default_host_kernel_binary_from(workspace_root, env_override)
}

fn default_host_kernel_binary_from(
    workspace_root: &Path,
    env_override: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(path) = env_override {
        return Ok(path);
    }
    for rel in ["target/release/raxis-kernel", "target/debug/raxis-kernel"] {
        let candidate = workspace_root.join(rel);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    if let Some(path) = which("raxis-kernel") {
        return Ok(path);
    }

    let fallback = PathBuf::from("/usr/local/bin/raxis-kernel");
    if fallback.is_file() {
        return Ok(fallback);
    }

    bail!(
        "could not locate a host `raxis-kernel` binary to verify. \
         Build it first (`cargo build --release -p raxis-kernel`) or \
         pass --kernel <path>. Note: <install-dir>/kernel/vmlinux is \
         the Linux guest kernel and does not contain \
         EXPECTED_KERNEL_SIGNING_KEY_BYTES."
    )
}

/// Entry point for `cargo xtask images verify-trust-anchor`.
pub fn run_verify_trust_anchor(argv: &[String]) -> Result<()> {
    let args = VerifyTrustAnchorArgs::parse(argv)?;
    trust_anchor::verify_kernel_binary_at_path(&args.kernel_path, &args.expected_pk_hex)?;
    eprintln!(
        "{}",
        serde_json::json!({
            "level": "info",
            "event": "verify_trust_anchor_ok",
            "kernel": args.kernel_path.display().to_string(),
            "pk_hex_prefix": &args.expected_pk_hex
                [..16.min(args.expected_pk_hex.len())],
        })
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_guest_kernel_config() -> &'static str {
        "CONFIG_NETFILTER=y\n\
         CONFIG_NETFILTER_NETLINK=y\n\
         CONFIG_NF_TABLES=y\n\
         CONFIG_NF_TABLES_INET=y\n\
         CONFIG_NF_CONNTRACK=y\n\
         CONFIG_NF_NAT=y\n\
         CONFIG_NFT_NAT=y\n\
         CONFIG_NFT_REDIR=y\n\
         CONFIG_NFT_CHAIN_NAT=y\n"
    }

    fn write_test_vmlinux(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::write(path.with_extension("config"), valid_guest_kernel_config()).unwrap();
    }

    #[test]
    fn role_parse_accepts_documented_aliases_and_rejects_unknown() {
        assert_eq!(Role::parse("orchestrator").unwrap(), Role::Orchestrator);
        assert_eq!(Role::parse("reviewer").unwrap(), Role::Reviewer);
        assert_eq!(
            Role::parse("executor-starter").unwrap(),
            Role::ExecutorStarter
        );
        // === iter62 verifier-runtime ===
        assert_eq!(Role::parse("verifier-starter").unwrap(), Role::Verifier);
        assert_eq!(
            Role::parse("verifier-symbol-index").unwrap(),
            Role::VerifierSymbolIndex,
        );
        assert!(Role::parse("Reviewer").is_err());
        assert!(Role::parse("orchestrators").is_err());
        assert!(Role::parse("verifier").is_err());
    }

    // === iter62 verifier-runtime ===
    //
    // Pin the bake-shape dispatch and the verifier-specific
    // workspace-crate routing so the per-role surfaces stay in
    // lockstep with `image-manifest::Role` and `crates/verifier/`'s
    // workspace name. A regression in any of these would surface as
    // a confusing "Cargo cannot find package" error far downstream
    // of the actual divergence.
    #[test]
    fn verifier_roles_need_rootfs_bake() {
        assert!(
            Role::Verifier.needs_rootfs_bake(),
            "verifier-starter ships ripgrep / ctags / jq alongside the binary; \
             rootfs bake is required",
        );
        assert!(
            Role::VerifierSymbolIndex.needs_rootfs_bake(),
            "verifier-symbol-index ships ctags + busybox; rootfs bake is required",
        );
    }

    #[test]
    fn verifier_roles_share_workspace_crate_and_binary_name() {
        // Both verifier images stage the SAME workspace crate
        // (`raxis-verifier`) and produce the SAME binary name
        // (`raxis-verifier`). Only the Containerfile-driven rootfs
        // layout differs (`images/verifier-starter/` vs
        // `images/verifier-symbol-index/`).
        assert_eq!(Role::Verifier.workspace_crate(), "raxis-verifier");
        assert_eq!(
            Role::VerifierSymbolIndex.workspace_crate(),
            "raxis-verifier"
        );
        assert_eq!(Role::Verifier.binary_name(), "raxis-verifier");
        assert_eq!(Role::VerifierSymbolIndex.binary_name(), "raxis-verifier");
    }

    #[test]
    fn verifier_roles_have_distinct_images_subdirs_and_artefact_stems() {
        // Distinct subdirs so the kernel-canonical symbol-index image
        // has its own digest-pinning slot in `raxis-canonical-images`
        // and operators inspecting `images/` see two separate trees.
        assert_eq!(Role::Verifier.images_subdir(), "verifier-starter");
        assert_eq!(
            Role::VerifierSymbolIndex.images_subdir(),
            "verifier-symbol-index"
        );
        assert_eq!(Role::Verifier.artefact_stem(), "raxis-verifier-starter");
        assert_eq!(
            Role::VerifierSymbolIndex.artefact_stem(),
            "raxis-verifier-symbol-index"
        );
    }

    #[test]
    fn role_all_includes_both_verifier_variants() {
        let all = Role::all();
        assert!(all.contains(&Role::Verifier));
        assert!(all.contains(&Role::VerifierSymbolIndex));
        assert_eq!(all.len(), 5, "role taxonomy is closed at 5 variants");
    }

    #[test]
    fn role_metadata_table_matches_image_manifest_artefact_stems() {
        for r in Role::all() {
            assert_eq!(
                r.artefact_stem(),
                r.manifest_role().artefact_stem(),
                "role {r:?} stem must match image-manifest crate's mapping",
            );
        }
    }

    #[test]
    fn dev_stage_args_default_target_matches_host_arch() {
        let argv = vec!["--role".to_owned(), "orchestrator".to_owned()];
        let args = DevStageArgs::parse(&argv).expect("parse");
        assert_eq!(args.target, default_target_triple());
    }

    #[test]
    fn build_all_args_default_install_dir_is_documented_layout() {
        let prev_install = std::env::var_os("RAXIS_INSTALL_DIR");
        let prev_home = std::env::var_os("HOME");
        // SAFETY: single-threaded test; restored at end.
        unsafe {
            std::env::remove_var("RAXIS_INSTALL_DIR");
            std::env::set_var("HOME", "/tmp/nonexistent-home-for-test");
        }
        let argv = vec![];
        let args = BuildAllArgs::parse(&argv).expect("parse");
        assert_eq!(args.install_dir, PathBuf::from(DEFAULT_DEV_INSTALL_DIR));
        // SAFETY: see above.
        unsafe {
            match prev_install {
                Some(v) => std::env::set_var("RAXIS_INSTALL_DIR", v),
                None => std::env::remove_var("RAXIS_INSTALL_DIR"),
            }
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn pack_initramfs_round_trips_a_one_file_tree() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("init"), b"#!/bin/sh\necho hi\n").unwrap();
        let bytes = pack_initramfs(tmp.path(), 1).unwrap();
        // gzip magic.
        assert_eq!(&bytes[0..2], &[0x1f, 0x8b]);
    }

    #[test]
    fn load_signing_key_rejects_short_input() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"deadbeef").unwrap();
        let err = load_signing_key(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("expected 64"), "got: {err}");
    }

    #[test]
    fn builder_parse_accepts_documented_aliases_only() {
        assert_eq!(Builder::parse("docker").unwrap(), Builder::Docker);
        assert_eq!(Builder::parse("podman").unwrap(), Builder::Podman);
        assert_eq!(Builder::parse("buildah").unwrap(), Builder::Buildah);
        assert!(Builder::parse("Docker").is_err());
        assert!(Builder::parse("kaniko").is_err());
    }

    #[test]
    fn oci_platform_for_target_triple_covers_supported_arches() {
        assert_eq!(
            oci_platform_for_target_triple("aarch64-unknown-linux-musl").unwrap(),
            "linux/arm64"
        );
        assert_eq!(
            oci_platform_for_target_triple("x86_64-unknown-linux-musl").unwrap(),
            "linux/amd64"
        );
        assert_eq!(
            oci_platform_for_target_triple("aarch64-apple-darwin").unwrap(),
            "linux/arm64"
        );
        assert!(oci_platform_for_target_triple("riscv64-unknown-linux-musl").is_err());
    }

    // `bake_rootfs_args_*` tests pinned the retired `bake-rootfs`
    // subcommand argv parser. The umbrella `bake` command's argv
    // parser (`BakeArgs::parse_*`) exercises the same role-resolution
    // logic.

    #[test]
    fn stub_guard_passes_when_role_has_no_required_binaries() {
        // Orchestrator + Reviewer ship binary-only today
        // (INV-PLANNER-HARNESS-02 minimalism), so the guard is a
        // no-op. This pins that contract: a future change that adds
        // entries to `required_os_binaries(Role::Reviewer)` MUST
        // also amend the spec.
        let tmp = tempfile::tempdir().unwrap();
        assert!(assert_no_stub_after_stage(Role::Orchestrator, tmp.path()).is_ok());
        assert!(assert_no_stub_after_stage(Role::Reviewer, tmp.path()).is_ok());
    }

    #[test]
    fn stub_guard_rejects_executor_starter_with_empty_rootfs() {
        let tmp = tempfile::tempdir().unwrap();
        let err = assert_no_stub_after_stage(Role::ExecutorStarter, tmp.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("bin/bash"),
            "remediation must name bash:    {err}"
        );
        assert!(
            err.contains("usr/bin/python3"),
            "remediation must name python3: {err}"
        );
        assert!(
            err.contains("usr/bin/git"),
            "remediation must name git:     {err}"
        );
        assert!(
            err.contains("images bake --role executor-starter"),
            "remediation must point at bake: {err}"
        );
        assert!(
            err.contains("--allow-stub"),
            "remediation must mention escape hatch: {err}"
        );
    }

    #[test]
    fn stub_guard_passes_for_executor_starter_when_required_binaries_present() {
        let tmp = tempfile::tempdir().unwrap();
        for rel in required_os_binaries(Role::ExecutorStarter) {
            let p = tmp.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"#!/bin/sh\nexit 0\n").unwrap();
        }
        assert!(assert_no_stub_after_stage(Role::ExecutorStarter, tmp.path()).is_ok());
    }

    #[test]
    fn stub_guard_passes_for_executor_starter_when_required_binaries_are_symlinks() {
        // Real Linux rootfs trees use symlinks heavily
        // (`/usr/bin/python3 -> python3.11`). Pin that the guard
        // accepts symlinks even when the target does not resolve.
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        for rel in required_os_binaries(Role::ExecutorStarter) {
            let p = tmp.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            symlink("/dev/null", &p).unwrap();
        }
        assert!(assert_no_stub_after_stage(Role::ExecutorStarter, tmp.path()).is_ok());
    }

    #[test]
    fn dev_stage_args_default_allow_stub_is_false() {
        let argv = vec!["--role".to_owned(), "orchestrator".to_owned()];
        let args = DevStageArgs::parse(&argv).expect("parse");
        assert!(!args.allow_stub);
    }

    #[test]
    fn dev_stage_args_allow_stub_flag_parses() {
        let argv = vec![
            "--role".to_owned(),
            "executor-starter".to_owned(),
            "--allow-stub".to_owned(),
        ];
        let args = DevStageArgs::parse(&argv).expect("parse");
        assert!(args.allow_stub);
    }

    #[test]
    fn which_finds_a_known_unix_binary_or_skips() {
        // `sh` is universally present on macOS / Linux dev hosts; if it
        // isn't, the test environment is too exotic to make claims about.
        match which("sh") {
            Some(p) => assert!(p.is_absolute(), "which(sh) returned {}", p.display()),
            None => eprintln!("skipped: no sh on $PATH (exotic test env)"),
        }
        // A binary that should never resolve.
        assert!(which("definitely-not-a-real-binary-xyz-9999").is_none());
    }

    // -----------------------------------------------------------------
    // INV-IMAGE-BAKE-NO-STALE-CACHE-01 — stale-cache guard witnesses
    // -----------------------------------------------------------------

    /// Build a minimal three-file scaffold that mirrors the layout the
    /// freshness guard inspects:
    ///   <workspace>/crates/planner-<role>/src/main.rs
    ///   <workspace>/crates/planner-core/src/driver.rs
    ///   <workspace>/images/<role>/rootfs/usr/local/bin/<binary>
    /// Returns the workspace tempdir (held until drop) plus the
    /// per-role source-file and staged-binary paths so individual
    /// witnesses can `touch` selected files to drive the mtime
    /// comparison without depending on the real workspace tree.
    fn build_freshness_scaffold(role: Role) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let workspace = tmp.path();
        let role_subdir = match role {
            Role::Orchestrator => "planner-orchestrator",
            Role::Reviewer => "planner-reviewer",
            Role::ExecutorStarter => "planner-executor",
            // The freshness-guard scaffold pins the planner-role
            // src layout (`crates/planner-<role>/src/main.rs`); the
            // iter62 verifier roles live at `crates/verifier` and
            // do not participate in the planner-side freshness
            // taxonomy. No existing witness drives this scaffold
            // with a verifier role; refuse loudly if a future test
            // tries to.
            Role::Verifier | Role::VerifierSymbolIndex => unreachable!(
                "build_freshness_scaffold does not model the verifier roles; \
                 they live at crates/verifier and have a different \
                 freshness contract"
            ),
        };
        let role_src = workspace.join("crates").join(role_subdir).join("src");
        let core_src = workspace.join("crates").join("planner-core").join("src");
        std::fs::create_dir_all(&role_src).unwrap();
        std::fs::create_dir_all(&core_src).unwrap();
        let role_main = role_src.join("main.rs");
        let core_driver = core_src.join("driver.rs");
        std::fs::write(&role_main, b"// role main\n").unwrap();
        std::fs::write(&core_driver, b"// shared driver\n").unwrap();

        let staged = workspace
            .join("images")
            .join(role.images_subdir())
            .join("rootfs")
            .join("usr")
            .join("local")
            .join("bin")
            .join(role.binary_name());
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();

        (tmp, role_main, core_driver, staged)
    }

    /// Set a path's mtime to `(now - delta_secs)`. Used to inject
    /// deterministic ordering between source and staged-binary
    /// mtimes without relying on filesystem timestamp resolution
    /// (which is 1 s or worse on macOS HFS+ / 1 µs on APFS).
    fn set_mtime_secs_ago(p: &Path, delta_secs: u64) {
        use std::time::{Duration, SystemTime};
        let when = SystemTime::now()
            .checked_sub(Duration::from_secs(delta_secs))
            .expect("delta fits in SystemTime");
        let ft = filetime::FileTime::from_system_time(when);
        filetime::set_file_mtime(p, ft).expect("set mtime");
    }

    #[test]
    fn inv_image_bake_no_stale_cache_01_planner_source_dirs_per_role() {
        // Map each role to (planner-<role>, planner-core). Pins the
        // contract that adding a new role REQUIRES adding the new
        // crate's src/ to this list — a silent omission would let a
        // future role's binary go stale without the guard firing.
        let root = PathBuf::from("/ws");
        assert_eq!(
            planner_source_dirs(Role::Orchestrator, &root),
            [
                root.join("crates/planner-orchestrator/src"),
                root.join("crates/planner-core/src")
            ],
        );
        assert_eq!(
            planner_source_dirs(Role::Reviewer, &root),
            [
                root.join("crates/planner-reviewer/src"),
                root.join("crates/planner-core/src")
            ],
        );
        assert_eq!(
            planner_source_dirs(Role::ExecutorStarter, &root),
            [
                root.join("crates/planner-executor/src"),
                root.join("crates/planner-core/src")
            ],
        );
    }

    #[test]
    fn inv_image_bake_no_stale_cache_01_newest_mtime_walks_files_recursively() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let nested = root.join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(root.join("top.rs"), b"top\n").unwrap();
        std::fs::write(root.join("a/mid.rs"), b"mid\n").unwrap();
        std::fs::write(nested.join("deep.rs"), b"deep\n").unwrap();
        set_mtime_secs_ago(&root.join("top.rs"), 1000);
        set_mtime_secs_ago(&root.join("a/mid.rs"), 500);
        set_mtime_secs_ago(&nested.join("deep.rs"), 10);

        let (mtime, path) = newest_mtime_in_tree(root).unwrap().unwrap();
        assert_eq!(path, nested.join("deep.rs"));
        let _ = mtime;
    }

    #[test]
    fn inv_image_bake_no_stale_cache_01_newest_mtime_returns_none_for_missing_root() {
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("definitely-not-here");
        assert!(newest_mtime_in_tree(&absent).unwrap().is_none());
    }

    #[test]
    fn inv_image_bake_no_stale_cache_01_verdict_fresh_when_staged_newer_than_source() {
        let (tmp, role_main, core_driver, staged) = build_freshness_scaffold(Role::Reviewer);
        std::fs::write(&staged, b"fresh binary").unwrap();
        // Sources older than staged → Fresh.
        set_mtime_secs_ago(&role_main, 1000);
        set_mtime_secs_ago(&core_driver, 1500);
        set_mtime_secs_ago(&staged, 10);

        let verdict = check_staged_binary_freshness(Role::Reviewer, tmp.path()).unwrap();
        match verdict {
            FreshnessVerdict::Fresh { .. } => {}
            other => panic!("expected Fresh, got {other:?}"),
        }
    }

    #[test]
    fn inv_image_bake_no_stale_cache_01_verdict_stale_when_planner_core_newer() {
        // Iter53 reproduction shape: the reviewer binary was staged
        // earlier, and `planner-core` got a later edit (the
        // RAXIS_PLANNER_TASK_PROMPT_PATH sidecar) that the guard
        // must detect even though planner-reviewer/src itself didn't
        // change.
        let (tmp, role_main, core_driver, staged) = build_freshness_scaffold(Role::Reviewer);
        std::fs::write(&staged, b"stale binary").unwrap();
        set_mtime_secs_ago(&role_main, 1500);
        set_mtime_secs_ago(&staged, 1000);
        set_mtime_secs_ago(&core_driver, 10);

        let verdict = check_staged_binary_freshness(Role::Reviewer, tmp.path()).unwrap();
        match verdict {
            FreshnessVerdict::Stale { newest_source, .. } => {
                assert_eq!(
                    newest_source, core_driver,
                    "the newest source must be the planner-core file \
                     that drove the staleness — that's the iter53 \
                     fingerprint the operator needs to see",
                );
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn inv_image_bake_no_stale_cache_01_verdict_stale_when_role_src_newer() {
        let (tmp, role_main, core_driver, staged) = build_freshness_scaffold(Role::Orchestrator);
        std::fs::write(&staged, b"stale orch binary").unwrap();
        set_mtime_secs_ago(&core_driver, 1500);
        set_mtime_secs_ago(&staged, 1000);
        set_mtime_secs_ago(&role_main, 10);

        let verdict = check_staged_binary_freshness(Role::Orchestrator, tmp.path()).unwrap();
        match verdict {
            FreshnessVerdict::Stale { newest_source, .. } => {
                assert_eq!(newest_source, role_main);
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn inv_image_bake_no_stale_cache_01_verdict_missing_when_no_staged_binary() {
        let (tmp, _role_main, _core_driver, staged) = build_freshness_scaffold(Role::Reviewer);
        // Do not create `staged` — the role's binary was never staged.
        assert!(!staged.exists());

        let verdict = check_staged_binary_freshness(Role::Reviewer, tmp.path()).unwrap();
        match verdict {
            FreshnessVerdict::Missing { newest_source, .. } => {
                assert!(
                    newest_source.is_some(),
                    "newest_source must surface even when staged is missing"
                );
            }
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn inv_image_bake_no_stale_cache_01_verdict_fresh_when_no_source_tree() {
        // A worktree pruned to images/* without crates/* (e.g., a
        // release tarball that only ships the staged tree) MUST NOT
        // trip the guard — there is nothing to compare against, so
        // packing is allowed. Pin this contract.
        let tmp = tempfile::tempdir().unwrap();
        let staged = tmp
            .path()
            .join("images")
            .join(Role::Reviewer.images_subdir())
            .join("rootfs")
            .join("usr")
            .join("local")
            .join("bin")
            .join(Role::Reviewer.binary_name());
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::write(&staged, b"binary").unwrap();
        let verdict = check_staged_binary_freshness(Role::Reviewer, tmp.path()).unwrap();
        match verdict {
            FreshnessVerdict::Fresh { .. } => {}
            other => panic!("expected Fresh (no source tree), got {other:?}"),
        }
    }

    #[test]
    fn build_all_args_default_no_auto_stage_is_false() {
        let prev_install = std::env::var_os("RAXIS_INSTALL_DIR");
        let prev_home = std::env::var_os("HOME");
        // SAFETY: single-threaded test; restored at end.
        unsafe {
            std::env::remove_var("RAXIS_INSTALL_DIR");
            std::env::set_var("HOME", "/tmp/nonexistent-home-for-test");
        }
        let argv = vec![];
        let args = BuildAllArgs::parse(&argv).expect("parse");
        assert!(
            !args.no_auto_stage,
            "default must be auto-stage = ON (iter53 reproduction shape)"
        );
        // SAFETY: see above.
        unsafe {
            match prev_install {
                Some(v) => std::env::set_var("RAXIS_INSTALL_DIR", v),
                None => std::env::remove_var("RAXIS_INSTALL_DIR"),
            }
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn build_all_args_no_auto_stage_flag_parses() {
        let prev_install = std::env::var_os("RAXIS_INSTALL_DIR");
        let prev_home = std::env::var_os("HOME");
        // SAFETY: single-threaded test; restored at end.
        unsafe {
            std::env::remove_var("RAXIS_INSTALL_DIR");
            std::env::set_var("HOME", "/tmp/nonexistent-home-for-test");
        }
        let argv = vec!["--no-auto-stage".to_owned()];
        let args = BuildAllArgs::parse(&argv).expect("parse");
        assert!(args.no_auto_stage);
        // SAFETY: see above.
        unsafe {
            match prev_install {
                Some(v) => std::env::set_var("RAXIS_INSTALL_DIR", v),
                None => std::env::remove_var("RAXIS_INSTALL_DIR"),
            }
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn inv_image_bake_no_stale_cache_01_no_auto_stage_bails_on_stale_with_remediation() {
        let (tmp, _role_main, core_driver, staged) = build_freshness_scaffold(Role::Reviewer);
        std::fs::write(&staged, b"stale").unwrap();
        set_mtime_secs_ago(&staged, 1000);
        set_mtime_secs_ago(&core_driver, 10);

        let args = BuildAllArgs {
            role: Some(Role::Reviewer),
            install_dir: tmp.path().join("install"),
            workspace_root: tmp.path().to_owned(),
            signing_key: tmp.path().join("key.hex"),
            no_auto_stage: true,
            kernel_signing_key_hex: None,
        };
        let err = handle_staged_binary_freshness(Role::Reviewer, &args)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("INV-IMAGE-BAKE-NO-STALE-CACHE-01 VIOLATED"),
            "remediation must cite the invariant token: {err}",
        );
        assert!(
            err.contains("dev-stage --role reviewer-core"),
            "remediation must name the dev-stage command: {err}",
        );
        assert!(
            err.contains("--no-auto-stage"),
            "remediation must explain the opt-out: {err}",
        );
    }

    #[test]
    fn inv_image_bake_no_stale_cache_01_no_auto_stage_bails_on_missing_with_remediation() {
        let (tmp, _role_main, _core_driver, staged) = build_freshness_scaffold(Role::Reviewer);
        assert!(!staged.exists());

        let args = BuildAllArgs {
            role: Some(Role::Reviewer),
            install_dir: tmp.path().join("install"),
            workspace_root: tmp.path().to_owned(),
            signing_key: tmp.path().join("key.hex"),
            no_auto_stage: true,
            kernel_signing_key_hex: None,
        };
        let err = handle_staged_binary_freshness(Role::Reviewer, &args)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("INV-IMAGE-BAKE-NO-STALE-CACHE-01 VIOLATED"),
            "remediation must cite the invariant token: {err}",
        );
        assert!(
            err.contains("dev-stage --role reviewer-core"),
            "remediation must name the dev-stage command: {err}",
        );
    }

    #[test]
    fn inv_image_bake_no_stale_cache_01_fresh_returns_ok_without_subprocess() {
        // When the staged binary is fresh, `handle_staged_binary_freshness`
        // returns Ok without invoking dev_stage (which would shell out
        // to `cargo build` and fail under a tempdir workspace). The
        // test asserts the function returns within milliseconds and
        // does not bail — a smoke test for the no-op happy path.
        let (tmp, role_main, core_driver, staged) = build_freshness_scaffold(Role::Reviewer);
        std::fs::write(&staged, b"fresh").unwrap();
        set_mtime_secs_ago(&role_main, 2000);
        set_mtime_secs_ago(&core_driver, 1500);
        set_mtime_secs_ago(&staged, 10);

        let args = BuildAllArgs {
            role: Some(Role::Reviewer),
            install_dir: tmp.path().join("install"),
            workspace_root: tmp.path().to_owned(),
            signing_key: tmp.path().join("key.hex"),
            no_auto_stage: false,
            kernel_signing_key_hex: None,
        };
        handle_staged_binary_freshness(Role::Reviewer, &args).expect("fresh binary must not error");
    }

    // -----------------------------------------------------------------
    // INV-IMAGE-BAKE-NO-CIRCULAR-CONTAINERFILE-01 witnesses
    // -----------------------------------------------------------------

    /// Build a workspace scaffold containing per-role
    /// `images/<subdir>/Containerfile` files with operator-supplied
    /// `FROM` directives. Returns the tempdir handle (held until
    /// drop) plus the workspace root path.
    fn build_containerfile_graph_scaffold(
        per_role_from: &[(Role, &str)],
    ) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path().to_owned();
        for (role, from_line) in per_role_from {
            let dir = workspace.join(STAGING_PARENT).join(role.images_subdir());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("Containerfile"),
                format!("# scaffold\n{from_line}\nRUN true\n"),
            )
            .unwrap();
        }
        (tmp, workspace)
    }

    #[test]
    fn inv_image_bake_no_circular_containerfile_01_accepts_external_bases() {
        // Real in-tree shape: every Containerfile names an upstream
        // image (`debian:bookworm-slim`, `scratch`). The acyclicity
        // check must accept those without complaint.
        let (_tmp, ws) = build_containerfile_graph_scaffold(&[
            (Role::Orchestrator, "FROM debian:bookworm-slim AS base"),
            (Role::Reviewer, "FROM scratch"),
            (Role::ExecutorStarter, "FROM debian:bookworm-slim"),
        ]);
        check_containerfile_graph_acyclic(&ws).expect("clean graph must pass");
    }

    #[test]
    fn inv_image_bake_no_circular_containerfile_01_rejects_in_tree_role_base() {
        // The historical `Containerfile.dev` shape: one role's
        // bake tag (`raxis-rootfs-orchestrator-core:dev`) used as
        // another role's `FROM` base. The acyclicity check must
        // reject this with the invariant token + line number.
        let (_tmp, ws) = build_containerfile_graph_scaffold(&[
            (Role::Orchestrator, "FROM debian:bookworm-slim"),
            (Role::Reviewer, "FROM raxis-rootfs-orchestrator-core:dev"),
            (Role::ExecutorStarter, "FROM debian:bookworm-slim"),
        ]);
        let err = check_containerfile_graph_acyclic(&ws)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("INV-IMAGE-BAKE-NO-CIRCULAR-CONTAINERFILE-01 VIOLATED"),
            "remediation must cite the invariant: {err}",
        );
        assert!(
            err.contains("raxis-rootfs-orchestrator-core:dev"),
            "remediation must name the offending FROM operand: {err}",
        );
        assert!(
            err.contains("line 2"),
            "remediation must include the line number: {err}",
        );
    }

    #[test]
    fn inv_image_bake_no_circular_containerfile_01_ignores_comments_and_case() {
        // A commented-out `FROM raxis-rootfs-*:dev` line MUST NOT
        // trip the check; an uppercase `FROM` directive MUST be
        // recognised (Containerfile grammar is case-insensitive).
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().to_owned();
        let dir = ws.join(STAGING_PARENT).join(Role::Reviewer.images_subdir());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("Containerfile"),
            "# FROM raxis-rootfs-orchestrator-core:dev  (commented out)\n\
             from debian:bookworm-slim\n\
             RUN true\n",
        )
        .unwrap();
        check_containerfile_graph_acyclic(&ws).expect("comment must be ignored");

        std::fs::write(
            dir.join("Containerfile"),
            "FROM raxis-rootfs-orchestrator-core:dev\n",
        )
        .unwrap();
        let err = check_containerfile_graph_acyclic(&ws)
            .unwrap_err()
            .to_string();
        assert!(err.contains("VIOLATED"), "uppercase FROM must trip: {err}");
    }

    #[test]
    fn inv_image_bake_no_circular_containerfile_01_skips_missing_files() {
        // A worktree pruned to e.g. just the reviewer Containerfile
        // MUST NOT trip the check for the other two roles. Pin
        // this contract.
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().to_owned();
        let dir = ws.join(STAGING_PARENT).join(Role::Reviewer.images_subdir());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Containerfile"), "FROM scratch\n").unwrap();
        check_containerfile_graph_acyclic(&ws).expect("partial worktree must pass");
    }

    #[test]
    fn inv_image_bake_no_circular_containerfile_01_handles_platform_flag() {
        // `FROM --platform=$BUILDPLATFORM <image>` is a valid
        // grammar; the acyclicity check must skip the `--platform`
        // flag and inspect the actual operand.
        let (_tmp, ws) = build_containerfile_graph_scaffold(&[(
            Role::Orchestrator,
            "FROM --platform=linux/arm64 raxis-rootfs-reviewer-core:dev",
        )]);
        let err = check_containerfile_graph_acyclic(&ws)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("raxis-rootfs-reviewer-core:dev"),
            "remediation must surface the operand past --platform: {err}",
        );
    }

    // -----------------------------------------------------------------
    // INV-IMAGE-BAKE-VMLINUX-STAGED-01 witnesses
    // -----------------------------------------------------------------

    #[test]
    fn inv_image_bake_vmlinux_staged_01_returns_copy_from_for_explicit_source() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("explicit.bin");
        std::fs::write(&src, b"DUMMY KERNEL").unwrap();
        let install = tmp.path().join("install");
        let res = resolve_vmlinux_source(&install, Some(&src), false).unwrap();
        match res {
            VmlinuxResolution::CopyFrom { source } => assert_eq!(source, src),
            other => panic!("expected CopyFrom, got {other:?}"),
        }
    }

    #[test]
    fn inv_image_bake_vmlinux_staged_01_already_staged_when_in_place() {
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().to_owned();
        let kdir = install.join("kernel");
        std::fs::create_dir_all(&kdir).unwrap();
        std::fs::write(kdir.join("vmlinux"), b"STAGED").unwrap();
        let res = resolve_vmlinux_source(&install, None, false).unwrap();
        assert!(matches!(res, VmlinuxResolution::AlreadyStaged { .. }));
    }

    #[test]
    fn inv_image_bake_vmlinux_staged_01_explicit_does_not_overwrite_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().to_owned();
        let kdir = install.join("kernel");
        std::fs::create_dir_all(&kdir).unwrap();
        std::fs::write(kdir.join("vmlinux"), b"STAGED").unwrap();
        let src = tmp.path().join("explicit.bin");
        std::fs::write(&src, b"DIFFERENT").unwrap();
        let res = resolve_vmlinux_source(&install, Some(&src), false).unwrap();
        assert!(
            matches!(res, VmlinuxResolution::AlreadyStaged { .. }),
            "without --force, a present staged binary must win",
        );
        // With --force the explicit source wins.
        let res_forced = resolve_vmlinux_source(&install, Some(&src), true).unwrap();
        assert!(matches!(res_forced, VmlinuxResolution::CopyFrom { .. }));
    }

    #[test]
    fn inv_image_bake_vmlinux_staged_01_bails_with_remediation_when_no_source() {
        // No --kernel-from-file, no env, no canonical /usr/local,
        // no already-staged file. The bail message must cite the
        // invariant token AND the dev-kernel command.
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().join("install");
        // Clear env so the fallback to RAXIS_DEV_KERNEL_SOURCE
        // doesn't accidentally hit a path leaked in by the parent
        // test invocation. SAFETY: single-threaded test.
        let prev = std::env::var_os("RAXIS_DEV_KERNEL_SOURCE");
        unsafe { std::env::remove_var("RAXIS_DEV_KERNEL_SOURCE") };
        let res = resolve_vmlinux_source(&install, None, false);
        if let Some(v) = prev {
            unsafe { std::env::set_var("RAXIS_DEV_KERNEL_SOURCE", v) };
        }
        // Skip the assertion when the host happens to have a
        // canonical kernel at `/usr/local/lib/raxis/kernel/vmlinux`
        // (the test env this PR was authored on does). The
        // function's documented order means "canonical install
        // wins over bail" so a real-world bail surface is only
        // reachable when both the install dir AND `/usr/local`
        // are empty.
        if PathBuf::from("/usr/local/lib/raxis/kernel/vmlinux").exists() {
            assert!(
                matches!(res, Ok(VmlinuxResolution::CopyFrom { .. })),
                "with canonical install present, must resolve to CopyFrom"
            );
            return;
        }
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("INV-IMAGE-BAKE-VMLINUX-STAGED-01 VIOLATED"),
            "remediation must cite the invariant: {err}",
        );
        assert!(
            err.contains("cargo xtask images dev-kernel"),
            "remediation must name dev-kernel: {err}",
        );
    }

    #[test]
    fn inv_image_bake_vmlinux_staged_01_rejects_empty_explicit_source() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("empty.bin");
        std::fs::write(&src, b"").unwrap();
        let install = tmp.path().join("install");
        let err = resolve_vmlinux_source(&install, Some(&src), false)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("is not a non-empty file"),
            "empty source must be rejected: {err}",
        );
    }

    #[test]
    fn inv_image_bake_vmlinux_staged_01_apply_copy_writes_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().join("install");
        let src = tmp.path().join("k.bin");
        write_test_vmlinux(&src, b"BYTES");
        let sha = apply_vmlinux_resolution(
            &install,
            &VmlinuxResolution::CopyFrom {
                source: src.clone(),
            },
            None,
        )
        .unwrap();
        // SHA matches manual computation.
        assert_eq!(sha, sha256_file(&src).unwrap());
        // The dest exists and matches src bytes.
        let dest = install.join("kernel").join("vmlinux");
        assert_eq!(std::fs::read(&dest).unwrap(), b"BYTES");
        // No leftover .vmlinux.tmp.
        assert!(!install.join("kernel").join(".vmlinux.tmp").exists());
    }

    // -----------------------------------------------------------------
    // INV-IMAGE-BAKE-MANIFEST-INTEGRITY-01 witnesses
    // -----------------------------------------------------------------

    /// Helper: synthesise a minimal scaffold the bake driver
    /// consumes: `<workspace>/images/<subdir>/manifest.toml` and
    /// `<workspace>/images/<subdir>/rootfs/usr/local/bin/<binary>`.
    fn build_bake_inputs_scaffold(
        role: Role,
        kernel_version: &str,
    ) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().to_owned();
        let images_subdir = ws.join(STAGING_PARENT).join(role.images_subdir());
        std::fs::create_dir_all(&images_subdir).unwrap();
        let manifest_toml = format!(
            "role = {role:?}\n\
             kernel_version = \"{kver}\"\n\
             source_date_epoch = 0\n\
             erofs_version = \"1.6.0\"\n\
             tar_version = \"1.34\"\n\
             zstd_version = \"1.5.5\"\n",
            role = role.manifest_role(),
            kver = kernel_version,
        );
        std::fs::write(images_subdir.join("manifest.toml"), manifest_toml).unwrap();
        let bin_dir = images_subdir
            .join("rootfs")
            .join("usr")
            .join("local")
            .join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(bin_dir.join(role.binary_name()), b"PLANNER BINARY BYTES").unwrap();
        let install = ws.join("install");
        std::fs::create_dir_all(install.join("kernel")).unwrap();
        write_test_vmlinux(&install.join("kernel").join("vmlinux"), b"FAKE KERNEL");
        (tmp, ws, install)
    }

    #[test]
    fn inv_image_bake_manifest_integrity_01_inputs_round_trip_through_compute() {
        let (_tmp, ws, install) = build_bake_inputs_scaffold(Role::Reviewer, "0.1.0");
        let fp = "deadbeefdeadbeef";
        let inputs = compute_bake_inputs(Role::Reviewer, &ws, &install, fp).unwrap();
        assert_eq!(inputs.signing_key_fp_prefix, fp);
        assert!(inputs.vmlinux_sha256.is_some(), "vmlinux MUST be hashed");
        assert!(
            inputs.staged_binary_sha256.is_some(),
            "staged binary MUST be hashed when present"
        );
        // The Containerfile is absent in this scaffold; the
        // optional field MUST be None.
        assert!(inputs.containerfile_sha256.is_none());
    }

    #[test]
    fn inv_image_bake_manifest_integrity_01_compute_detects_planner_binary_change() {
        let (_tmp, ws, install) = build_bake_inputs_scaffold(Role::Reviewer, "0.1.0");
        let before = compute_bake_inputs(Role::Reviewer, &ws, &install, "fp").unwrap();
        let binary = ws
            .join(STAGING_PARENT)
            .join(Role::Reviewer.images_subdir())
            .join("rootfs")
            .join("usr")
            .join("local")
            .join("bin")
            .join(Role::Reviewer.binary_name());
        std::fs::write(&binary, b"DIFFERENT PLANNER BINARY").unwrap();
        let after = compute_bake_inputs(Role::Reviewer, &ws, &install, "fp").unwrap();
        assert_ne!(
            before.staged_binary_sha256, after.staged_binary_sha256,
            "a binary rewrite MUST change the recorded SHA",
        );
    }

    #[test]
    fn inv_image_bake_manifest_integrity_01_compute_detects_source_change() {
        let (_tmp, ws, install) = build_bake_inputs_scaffold(Role::Reviewer, "0.1.0");
        let role_src = ws.join("crates").join("planner-reviewer").join("src");
        std::fs::create_dir_all(&role_src).unwrap();
        let main_rs = role_src.join("main.rs");
        std::fs::write(&main_rs, b"fn main() {}\n").unwrap();

        let before = compute_bake_inputs(Role::Reviewer, &ws, &install, "fp").unwrap();
        std::fs::write(&main_rs, b"fn main() { println!(\"changed\"); }\n").unwrap();
        let after = compute_bake_inputs(Role::Reviewer, &ws, &install, "fp").unwrap();

        assert_ne!(
            before.source_tree_sha256, after.source_tree_sha256,
            "source edits MUST invalidate the bake no-op cache even when \
             the old staged binary is still present",
        );
    }

    #[test]
    fn inv_image_bake_manifest_integrity_01_compute_detects_vmlinux_change() {
        let (_tmp, ws, install) = build_bake_inputs_scaffold(Role::Reviewer, "0.1.0");
        let before = compute_bake_inputs(Role::Reviewer, &ws, &install, "fp").unwrap();
        std::fs::write(
            install.join("kernel").join("vmlinux"),
            b"DIFFERENT KERNEL BYTES",
        )
        .unwrap();
        let after = compute_bake_inputs(Role::Reviewer, &ws, &install, "fp").unwrap();
        assert_ne!(before.vmlinux_sha256, after.vmlinux_sha256);
    }

    #[test]
    fn inv_image_bake_manifest_integrity_01_compute_detects_signing_key_rotation() {
        let (_tmp, ws, install) = build_bake_inputs_scaffold(Role::Reviewer, "0.1.0");
        let before = compute_bake_inputs(Role::Reviewer, &ws, &install, "fp-old").unwrap();
        let after = compute_bake_inputs(Role::Reviewer, &ws, &install, "fp-new").unwrap();
        assert_ne!(
            before.signing_key_fp_prefix, after.signing_key_fp_prefix,
            "a key rotation MUST surface as a recorded-input change",
        );
    }

    #[test]
    fn inv_image_bake_manifest_integrity_01_no_op_shortcut_skips_unchanged_role() {
        let (_tmp, ws, install) = build_bake_inputs_scaffold(Role::Reviewer, "0.1.0");

        // Synthesise a prior bake.json + matching .img / .manifest.toml.
        let img_path = install.join("images").join(format!(
            "{stem}-{kver}.img",
            stem = Role::Reviewer.artefact_stem(),
            kver = "0.1.0",
        ));
        let mtoml_path = install.join("images").join(format!(
            "{stem}-{kver}.manifest.toml",
            stem = Role::Reviewer.artefact_stem(),
            kver = "0.1.0",
        ));
        std::fs::create_dir_all(img_path.parent().unwrap()).unwrap();
        std::fs::write(&img_path, b"IMG BYTES").unwrap();
        std::fs::write(&mtoml_path, b"MANIFEST BYTES").unwrap();
        let inputs_now = compute_bake_inputs(Role::Reviewer, &ws, &install, "fp").unwrap();
        let img_sha = sha256_file(&img_path).unwrap();
        let mtoml_sha = sha256_file(&mtoml_path).unwrap();
        let manifest = BakeManifest {
            schema_version: BAKE_MANIFEST_SCHEMA_VERSION,
            role: Role::Reviewer.workspace_crate().to_owned(),
            artefact_stem: Role::Reviewer.artefact_stem().to_owned(),
            kernel_version: "0.1.0".to_owned(),
            built_at_unix: 1,
            host: BakeHostInfo {
                os: "test".to_owned(),
                arch: "test".to_owned(),
                target_triple: "test".to_owned(),
                container_builder: None,
            },
            inputs: inputs_now.clone(),
            outputs: BakeOutputs {
                img_sha256: img_sha.clone(),
                img_size_bytes: std::fs::metadata(&img_path).unwrap().len(),
                manifest_toml_sha256: mtoml_sha,
                manifest_toml_size_bytes: std::fs::metadata(&mtoml_path).unwrap().len(),
            },
        };
        manifest
            .write_atomic(&BakeManifest::path(&install, Role::Reviewer, "0.1.0"))
            .unwrap();

        // Now the shortcut must fire (Some).
        let verdict = bake_should_skip(&install, Role::Reviewer, "0.1.0", &inputs_now).unwrap();
        assert!(verdict.is_some(), "unchanged tree MUST be a no-op");

        // Mutate the binary; the shortcut must bail.
        let binary = ws
            .join(STAGING_PARENT)
            .join(Role::Reviewer.images_subdir())
            .join("rootfs")
            .join("usr")
            .join("local")
            .join("bin")
            .join(Role::Reviewer.binary_name());
        std::fs::write(&binary, b"NEW PLANNER").unwrap();
        let inputs_after = compute_bake_inputs(Role::Reviewer, &ws, &install, "fp").unwrap();
        let verdict = bake_should_skip(&install, Role::Reviewer, "0.1.0", &inputs_after).unwrap();
        assert!(verdict.is_none(), "binary change MUST invalidate the cache");
    }

    #[test]
    fn inv_image_bake_manifest_integrity_01_no_op_shortcut_rejects_tampered_img() {
        let (_tmp, ws, install) = build_bake_inputs_scaffold(Role::Reviewer, "0.1.0");
        let img_path = install.join("images").join(format!(
            "{stem}-{kver}.img",
            stem = Role::Reviewer.artefact_stem(),
            kver = "0.1.0",
        ));
        let mtoml_path = install.join("images").join(format!(
            "{stem}-{kver}.manifest.toml",
            stem = Role::Reviewer.artefact_stem(),
            kver = "0.1.0",
        ));
        std::fs::create_dir_all(img_path.parent().unwrap()).unwrap();
        std::fs::write(&img_path, b"IMG BYTES").unwrap();
        std::fs::write(&mtoml_path, b"MANIFEST BYTES").unwrap();
        let inputs_now = compute_bake_inputs(Role::Reviewer, &ws, &install, "fp").unwrap();
        let manifest = BakeManifest {
            schema_version: BAKE_MANIFEST_SCHEMA_VERSION,
            role: Role::Reviewer.workspace_crate().to_owned(),
            artefact_stem: Role::Reviewer.artefact_stem().to_owned(),
            kernel_version: "0.1.0".to_owned(),
            built_at_unix: 1,
            host: BakeHostInfo {
                os: "test".to_owned(),
                arch: "test".to_owned(),
                target_triple: "test".to_owned(),
                container_builder: None,
            },
            inputs: inputs_now.clone(),
            outputs: BakeOutputs {
                img_sha256: sha256_file(&img_path).unwrap(),
                img_size_bytes: std::fs::metadata(&img_path).unwrap().len(),
                manifest_toml_sha256: sha256_file(&mtoml_path).unwrap(),
                manifest_toml_size_bytes: std::fs::metadata(&mtoml_path).unwrap().len(),
            },
        };
        manifest
            .write_atomic(&BakeManifest::path(&install, Role::Reviewer, "0.1.0"))
            .unwrap();

        // Tamper the on-disk .img — the recorded SHA in the
        // bake.json now disagrees with disk. Shortcut MUST bail.
        std::fs::write(&img_path, b"TAMPERED").unwrap();
        let verdict = bake_should_skip(&install, Role::Reviewer, "0.1.0", &inputs_now).unwrap();
        assert!(
            verdict.is_none(),
            "tampered .img must NOT pass the integrity check"
        );
    }

    #[test]
    fn inv_image_bake_manifest_integrity_01_manifest_round_trips_through_json() {
        let inputs = BakeInputs {
            containerfile_sha256: Some("aa".repeat(32)),
            inputs_manifest_sha256: "bb".repeat(32),
            staged_binary_sha256: Some("cc".repeat(32)),
            source_tree_sha256: "11".repeat(32),
            signing_key_fp_prefix: "deadbeef00112233".to_owned(),
            vmlinux_sha256: Some("dd".repeat(32)),
        };
        let outputs = BakeOutputs {
            img_sha256: "ee".repeat(32),
            img_size_bytes: 42,
            manifest_toml_sha256: "ff".repeat(32),
            manifest_toml_size_bytes: 7,
        };
        let manifest = BakeManifest {
            schema_version: BAKE_MANIFEST_SCHEMA_VERSION,
            role: "raxis-planner-reviewer".to_owned(),
            artefact_stem: "raxis-reviewer-core".to_owned(),
            kernel_version: "0.1.0".to_owned(),
            built_at_unix: 1_700_000_000,
            host: BakeHostInfo {
                os: "macos".to_owned(),
                arch: "aarch64".to_owned(),
                target_triple: "aarch64-unknown-linux-musl".to_owned(),
                container_builder: Some("docker".to_owned()),
            },
            inputs: inputs.clone(),
            outputs: outputs.clone(),
        };
        let json = serde_json::to_vec_pretty(&manifest).unwrap();
        let back: BakeManifest = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.inputs, inputs);
        assert_eq!(back.outputs, outputs);
        assert_eq!(back.schema_version, BAKE_MANIFEST_SCHEMA_VERSION);
    }

    #[test]
    fn inv_image_bake_manifest_integrity_01_unknown_schema_version_treated_as_missing() {
        // A future-version manifest must be treated as "unknown"
        // so a stale xtask cannot trust a newer manifest's
        // shortcut decision. Pin this contract.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("future.bake.json");
        let json = serde_json::json!({
            "schema_version": 999,
            "role": "x",
            "artefact_stem": "x",
            "kernel_version": "x",
            "built_at_unix": 0,
            "host": { "os": "x", "arch": "x", "target_triple": "x", "container_builder": null },
            "inputs": {
                "containerfile_sha256": null,
                "inputs_manifest_sha256": "00",
                "staged_binary_sha256": null,
                "signing_key_fp_prefix": "",
                "vmlinux_sha256": null,
            },
            "outputs": {
                "img_sha256": "00",
                "img_size_bytes": 0,
                "manifest_toml_sha256": "00",
                "manifest_toml_size_bytes": 0,
            },
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
        assert!(
            BakeManifest::read_from(&path).is_none(),
            "future schema version must read as None"
        );
    }

    // -----------------------------------------------------------------
    // INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01 witnesses
    // -----------------------------------------------------------------

    #[test]
    fn inv_image_bake_preflight_fail_closed_01_missing_signing_key_bails() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().to_owned();
        // Make every per-role manifest.toml + Containerfile exist
        // so the preflight reaches the signing-key check.
        for r in Role::all() {
            let dir = ws.join(STAGING_PARENT).join(r.images_subdir());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("manifest.toml"),
                format!(
                    "role = {role:?}\nkernel_version=\"0.1.0\"\n\
                 source_date_epoch=0\nerofs_version=\"x\"\n\
                 tar_version=\"x\"\nzstd_version=\"x\"\n",
                    role = r.manifest_role(),
                ),
            )
            .unwrap();
            std::fs::write(dir.join("Containerfile"), "FROM scratch\n").unwrap();
        }
        let install = tmp.path().join("install");
        std::fs::create_dir_all(install.join("kernel")).unwrap();
        std::fs::write(install.join("kernel").join("vmlinux"), b"k").unwrap();
        let signing_key = tmp.path().join("nope.hex");
        let err = preflight_bake_inputs(
            &ws,
            &install,
            &signing_key,
            &[Role::Reviewer], // binary-only avoids the daemon probe
            None,
            None,
            None,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01"),
            "remediation must cite the invariant: {err}"
        );
        assert!(
            err.contains("dev-keys init"),
            "remediation must mention dev-keys init: {err}"
        );
    }

    #[test]
    fn inv_image_bake_preflight_fail_closed_01_missing_inputs_manifest_bails() {
        // Set up signing key + vmlinux + an empty workspace (no
        // per-role manifest.toml). The preflight must surface
        // the missing per-role fixture with the invariant token.
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().to_owned();
        let install = tmp.path().join("install");
        std::fs::create_dir_all(install.join("kernel")).unwrap();
        std::fs::write(install.join("kernel").join("vmlinux"), b"k").unwrap();
        let key_hex = tmp.path().join("k.hex");
        std::fs::write(&key_hex, "11".repeat(32)).unwrap();
        let err = preflight_bake_inputs(
            &ws,
            &install,
            &key_hex,
            &[Role::Reviewer],
            None,
            None,
            None,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01"),
            "remediation must cite the invariant: {err}"
        );
        assert!(
            err.contains("manifest.toml"),
            "remediation must name the missing fixture: {err}"
        );
    }

    #[test]
    fn inv_image_bake_preflight_fail_closed_01_binary_only_skips_builder_probe() {
        // When the selected roles are all binary-only
        // (`Role::Reviewer`, `Role::Orchestrator`), the preflight
        // must NOT require a container builder — a fresh macOS
        // dev box without docker/podman/buildah can still bake
        // the two canonical binary-only roles.
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().to_owned();
        for r in &[Role::Reviewer, Role::Orchestrator] {
            let dir = ws.join(STAGING_PARENT).join(r.images_subdir());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("manifest.toml"),
                format!(
                    "role = {role:?}\nkernel_version=\"0.1.0\"\n\
                 source_date_epoch=0\nerofs_version=\"x\"\n\
                 tar_version=\"x\"\nzstd_version=\"x\"\n",
                    role = r.manifest_role(),
                ),
            )
            .unwrap();
            std::fs::write(dir.join("Containerfile"), "FROM scratch\n").unwrap();
        }
        let install = tmp.path().join("install");
        std::fs::create_dir_all(install.join("kernel")).unwrap();
        write_test_vmlinux(&install.join("kernel").join("vmlinux"), b"k");
        let key_hex = tmp.path().join("k.hex");
        std::fs::write(&key_hex, "11".repeat(32)).unwrap();
        let outcome = preflight_bake_inputs(
            &ws,
            &install,
            &key_hex,
            &[Role::Reviewer, Role::Orchestrator],
            None,
            None,
            None,
            false,
        )
        .expect("binary-only preflight must pass without a builder");
        assert!(
            outcome.container_builder.is_none(),
            "no role needs a builder; preflight must NOT resolve one"
        );
    }

    #[test]
    fn inv_image_bake_preflight_fail_closed_01_role_needs_rootfs_bake_taxonomy() {
        // Pin which roles need the OCI bake. A future change to
        // this table MUST update the harness's
        // `role_needs_rootfs_bake` in lockstep — they MUST agree
        // because the harness auto-bake mirrors the bake driver.
        assert!(
            !Role::Orchestrator.needs_rootfs_bake(),
            "Orchestrator is binary-only by spec"
        );
        assert!(
            !Role::Reviewer.needs_rootfs_bake(),
            "Reviewer is binary-only by spec"
        );
        assert!(
            Role::ExecutorStarter.needs_rootfs_bake(),
            "ExecutorStarter needs OS tooling via Containerfile bake"
        );
    }

    // -----------------------------------------------------------------
    // INV-IMAGE-CPIO-MULTI-ARCHIVE-PRESERVED-01 witnesses
    // -----------------------------------------------------------------

    #[test]
    fn inv_image_cpio_multi_archive_preserved_01_pack_emits_exactly_one_trailer() {
        // The `pack_initramfs` helper walks a directory and emits
        // a single cpio archive terminated by exactly one `TRAILER!!!`
        // entry. Pin this byte-stream contract so a future
        // optimisation (e.g. multi-archive concatenation for early
        // initrd support) doesn't silently truncate the per-role
        // rootfs by adding a second TRAILER mid-stream.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("init"), b"#!/bin/sh\n").unwrap();
        std::fs::write(tmp.path().join("etc-x"), b"x").unwrap();
        let cpio_gz = pack_initramfs(tmp.path(), 1).unwrap();

        // gunzip and count occurrences of the trailer's
        // `TRAILER!!!` literal in the raw cpio.
        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut decoded = Vec::new();
        GzDecoder::new(&cpio_gz[..])
            .read_to_end(&mut decoded)
            .unwrap();
        let trailer_count = decoded.windows(10).filter(|w| *w == b"TRAILER!!!").count();
        assert_eq!(
            trailer_count, 1,
            "exactly one TRAILER!!! must appear in the cpio stream \
             (multi-archive concatenation would emit more)"
        );
    }

    #[test]
    fn inv_image_cpio_multi_archive_preserved_01_concat_two_streams_is_a_valid_initramfs() {
        // The Linux kernel's `init/initramfs.c` documents that a
        // multi-archive initramfs is two or more cpio.gz streams
        // concatenated byte-for-byte (early-initrd shape). Pin
        // that two independently-built `pack_initramfs` outputs
        // can be concatenated and the resulting bytes still
        // satisfy the "one TRAILER per archive" invariant — i.e.
        // each archive's TRAILER survives the concat.
        let tmp_a = tempfile::tempdir().unwrap();
        std::fs::write(tmp_a.path().join("a.txt"), b"a").unwrap();
        let a = pack_initramfs(tmp_a.path(), 1).unwrap();
        let tmp_b = tempfile::tempdir().unwrap();
        std::fs::write(tmp_b.path().join("b.txt"), b"b").unwrap();
        let b = pack_initramfs(tmp_b.path(), 1).unwrap();

        let mut concatenated = Vec::with_capacity(a.len() + b.len());
        concatenated.extend_from_slice(&a);
        concatenated.extend_from_slice(&b);

        // The Linux kernel's gunzip is multi-member-aware (it
        // reads `gzip` member after `gzip` member until EOF; each
        // member's body feeds the cpio unpacker). We mirror that
        // with `MultiGzDecoder` here, which consumes every member
        // in the concatenated stream. Each member's body MUST
        // carry its own `TRAILER!!!`; the kernel uses those to
        // separate archives.
        use flate2::read::MultiGzDecoder;
        use std::io::Read;
        let mut decoded = Vec::new();
        MultiGzDecoder::new(&concatenated[..])
            .read_to_end(&mut decoded)
            .unwrap();
        let trailer_count = decoded.windows(10).filter(|w| *w == b"TRAILER!!!").count();
        assert_eq!(
            trailer_count, 2,
            "concatenated multi-archive cpio MUST preserve BOTH \
             trailers byte-for-byte (the Linux kernel's initramfs \
             unpacker reads them as separate archives)"
        );

        // Byte-level concat invariant: the prefix of the
        // concatenated stream MUST be exactly archive A's bytes
        // (no archive-B bytes leaked in, no archive-A bytes
        // truncated). This is what makes "multi-archive cpio
        // inputs survive the bake step byte-for-byte" mechanical.
        assert_eq!(
            &concatenated[..a.len()],
            a.as_slice(),
            "archive A bytes must survive the concat byte-for-byte"
        );
        assert_eq!(
            &concatenated[a.len()..],
            b.as_slice(),
            "archive B bytes must survive the concat byte-for-byte"
        );
    }

    // -----------------------------------------------------------------
    // INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01 — autogen keypair witnesses
    // -----------------------------------------------------------------

    /// Build a tempdir scaffold with a `.git/info/` subdir so the
    /// autogen helper has somewhere to write. We do NOT init a real
    /// git repo — the helper only needs the directory hierarchy to
    /// exist for `create_dir_all` to land the keypair inside it,
    /// matching the per-clone "this is a git checkout" assumption.
    fn make_workspace_with_git_info() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git").join("info")).unwrap();
        tmp
    }

    #[test]
    fn inv_image_dev_signing_key_autogen_01_first_run_mints_keypair_under_dot_git_info() {
        let tmp = make_workspace_with_git_info();
        let kp = ensure_dev_signing_keypair(tmp.path()).expect("first-run autogen");
        assert!(kp.generated_now, "first-run must report generated_now=true");
        assert!(kp.sk_path.exists(), "sk.hex must exist after first run");
        assert!(kp.pk_path.exists(), "pk.hex must exist after first run");
        assert_eq!(
            kp.pk_path,
            tmp.path()
                .join(".git")
                .join("info")
                .join("raxis-signing-key")
                .join("pk.hex"),
            "pk path must land under .git/info/raxis-signing-key/",
        );
        assert_eq!(
            kp.pk_hex.len(),
            64,
            "pk_hex must be 64 lowercase hex chars (Ed25519 verifying key)",
        );
        assert!(
            kp.pk_hex
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "pk_hex must be lowercase hex only",
        );
    }

    #[test]
    fn inv_image_dev_signing_key_autogen_01_second_run_reuses_existing_pair_byte_for_byte() {
        let tmp = make_workspace_with_git_info();
        let first = ensure_dev_signing_keypair(tmp.path()).expect("first run");
        assert!(first.generated_now);
        let first_sk = std::fs::read_to_string(&first.sk_path).unwrap();
        let first_pk = std::fs::read_to_string(&first.pk_path).unwrap();

        let second = ensure_dev_signing_keypair(tmp.path()).expect("second run");
        assert!(
            !second.generated_now,
            "second run on a populated tree must NOT regenerate",
        );
        assert_eq!(
            std::fs::read_to_string(&second.sk_path).unwrap(),
            first_sk,
            "sk.hex must survive the second run byte-for-byte",
        );
        assert_eq!(
            std::fs::read_to_string(&second.pk_path).unwrap(),
            first_pk,
            "pk.hex must survive the second run byte-for-byte",
        );
        assert_eq!(
            second.pk_hex.trim(),
            first.pk_hex.trim(),
            "pk_hex returned across runs must agree",
        );
    }

    #[test]
    fn inv_image_dev_signing_key_autogen_01_first_run_files_have_secure_modes() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tmp = make_workspace_with_git_info();
            let kp = ensure_dev_signing_keypair(tmp.path()).expect("first run");
            let sk_mode = std::fs::metadata(&kp.sk_path).unwrap().permissions().mode() & 0o777;
            let pk_mode = std::fs::metadata(&kp.pk_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(sk_mode, 0o600, "sk.hex MUST be 0600 (private half)");
            // iter62 hardening (uniform-perms): pk.hex is now 0600
            // alongside sk.hex. INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01
            // pins both halves at 0600 so a `chmod -R` audit on the
            // dir sees one mode instead of two.
            assert_eq!(
                pk_mode, 0o600,
                "pk.hex MUST be 0600 (uniform with sk.hex per iter62; \
                 widening it back to 0644 must update INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01)",
            );
            let dir_mode = std::fs::metadata(kp.sk_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                dir_mode, 0o700,
                "raxis-signing-key/ dir MUST be 0700 (no other users may                  read the private half through the parent dir)",
            );
        }
    }

    #[test]
    fn inv_image_dev_signing_key_autogen_01_pk_hex_round_trips_to_signing_key() {
        // The pk.hex file MUST be the verifying-key half of the
        // sk.hex file; otherwise the kernel's trust anchor (baked
        // from RAXIS_KERNEL_SIGNING_KEY_HEX) and the image-builder's
        // signing key (loaded from sk.hex) disagree, and every
        // signature the bake produces fails verification at boot.
        use ed25519_dalek::SigningKey;
        let tmp = make_workspace_with_git_info();
        let kp = ensure_dev_signing_keypair(tmp.path()).expect("first run");
        let sk_hex = std::fs::read_to_string(&kp.sk_path).unwrap();
        let sk_bytes = hex::decode(sk_hex.trim()).unwrap();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&sk_bytes);
        let signing_key = SigningKey::from_bytes(&seed);
        let derived_pk = hex::encode(signing_key.verifying_key().to_bytes());
        assert_eq!(
            derived_pk,
            kp.pk_hex.trim(),
            "pk.hex on disk MUST equal the verifying-key derived from              sk.hex; otherwise the kernel trust anchor disagrees with              the image signature.",
        );
    }

    #[test]
    fn inv_image_dev_signing_key_autogen_01_corrupt_pk_hex_fails_loud_with_remediation() {
        let tmp = make_workspace_with_git_info();
        let _ = ensure_dev_signing_keypair(tmp.path()).expect("seed");
        let pk_path = tmp
            .path()
            .join(".git")
            .join("info")
            .join("raxis-signing-key")
            .join("pk.hex");
        // Corrupt the pk.hex file so validation trips.
        std::fs::write(
            &pk_path,
            b"not-hex
",
        )
        .unwrap();
        let err = ensure_dev_signing_keypair(tmp.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("pk.hex"),
            "remediation MUST cite the file: {err}",
        );
        assert!(
            err.contains("delete") && err.contains("re-run"),
            "remediation MUST tell the operator how to recover: {err}",
        );
    }

    #[test]
    fn inv_image_dev_signing_key_autogen_01_git_info_dir_path_is_per_clone_local() {
        // Pin the literal path the helper writes to — operators
        // grepping for `raxis-signing-key` should always land here
        // and `.git/info/` is git's documented "per-clone, never
        // tracked" directory (`man gitrepository-layout`). A future
        // refactor that moves the keypair somewhere shareable
        // (e.g. `target/`) MUST update this witness.
        let ws = std::path::PathBuf::from("/ws");
        let dir = git_info_signing_key_dir(&ws);
        assert_eq!(
            dir,
            std::path::PathBuf::from("/ws/.git/info/raxis-signing-key")
        );
    }

    /// Iter62 chmod-at-write witness for the xtask seam. Pairs with
    /// the equivalent witness inside `crates/dev-signing-key`'s test
    /// module. INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01 pins both write
    /// sites at 0600 for both halves.
    #[cfg(unix)]
    #[test]
    fn inv_image_dev_signing_key_autogen_01_xtask_seam_chmod_lands_at_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = make_workspace_with_git_info();
        let kp = ensure_dev_signing_keypair(tmp.path()).expect("first run");
        let sk_meta = std::fs::metadata(&kp.sk_path).expect("sk.hex on disk");
        let pk_meta = std::fs::metadata(&kp.pk_path).expect("pk.hex on disk");
        assert_eq!(
            sk_meta.permissions().mode() & 0o777,
            0o600,
            "sk.hex MUST be 0600 at the xtask write site (iter62)",
        );
        assert_eq!(
            pk_meta.permissions().mode() & 0o777,
            0o600,
            "pk.hex MUST be 0600 at the xtask write site (iter62, uniform-perms hardening)",
        );
    }

    // -----------------------------------------------------------------
    // INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01 — iter66
    // witnesses for the bake's per-`Command` env injection + the
    // post-build trust-anchor verification step.
    // -----------------------------------------------------------------

    /// The audit-sweep witness: walks the on-disk text of
    /// `xtask/src/images.rs` and pins that every cargo-spawn site
    /// is preceded by the canonical `AUDIT-MARKER:bake-cargo-spawn`
    /// comment AND followed by an `apply_trust_anchor_env(&mut cmd,`
    /// call. A future refactor that re-introduces a bare cargo
    /// invocation without either piece trips this witness and the
    /// spec. The marker is a deliberate contract: explicit
    /// comment-level opt-in beats grep-and-pray.
    #[test]
    fn inv_image_bake_kernel_trust_anchor_populated_01_every_cargo_spawn_pairs_with_marker_and_helper(
    ) {
        let src = include_str!("images.rs");
        let audit_marker = "AUDIT-MARKER:bake-cargo-spawn";
        let helper_call = "apply_trust_anchor_env(&mut cmd,";

        let marker_count = src.matches(audit_marker).count();
        let helper_call_count = src.matches(helper_call).count();

        // The audit marker is referenced in: (a) every cargo-spawn
        // site preceding the `Command::new(...)`, AND (b) this
        // witness comment. We expect strictly more than 1 (the
        // doc-comment alone yields 1; the spawn-site preamble
        // yields the rest). The helper-call literal is similarly
        // referenced at every spawn site PLUS this witness; we pin
        // a lower bound of 2 (current bake-cargo-spawn site + this
        // witness's reference). A future second cargo-spawn site
        // must increment both counters in lockstep.
        //
        // Why count both pieces: the marker comment alone is too
        // easy to copy-paste without wiring the helper; the
        // helper-call alone could be added speculatively without
        // the marker. Requiring BOTH ensures the contract is
        // self-documenting at every spawn site.
        assert!(
            marker_count >= 2,
            "expected ≥2 occurrences of `{audit_marker}` (1 doc-comment + ≥1 spawn site); \
             got {marker_count}. INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01.",
        );
        assert!(
            helper_call_count >= 2,
            "expected ≥2 occurrences of `{helper_call}` (1 doc-comment + ≥1 spawn site); \
             got {helper_call_count}. INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01.",
        );

        // The spawn-site count of each MUST agree: every marker is
        // a contract for a paired helper call, and every helper
        // call is documented by a marker. Drift between the two
        // means a spawn site introduced the marker without wiring
        // the helper (or vice versa).
        let marker_at_spawn_sites = marker_count - 1; // strip the doc-comment self-reference
        let helper_at_spawn_sites = helper_call_count - 1;
        assert_eq!(
            marker_at_spawn_sites, helper_at_spawn_sites,
            "marker count at spawn sites ({marker_at_spawn_sites}) MUST equal helper-call \
             count ({helper_at_spawn_sites}). Every cargo spawn site MUST carry both. \
             INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01.",
        );
    }

    /// Companion to the source-audit witness above: confirms the
    /// helper itself routes through `.env(...)` with the canonical
    /// env-var name from `trust_anchor::RAXIS_KERNEL_SIGNING_KEY_HEX`.
    /// A drift between the helper's chosen env var and the kernel
    /// build script's resolution chain would silently dis-arm the
    /// trust anchor.
    #[test]
    fn inv_image_bake_kernel_trust_anchor_populated_01_helper_env_var_matches_build_script() {
        assert_eq!(
            trust_anchor::RAXIS_KERNEL_SIGNING_KEY_HEX,
            "RAXIS_KERNEL_SIGNING_KEY_HEX",
            "the env-var name MUST stay aligned with \
             crates/canonical-images/build.rs::TRUST_ANCHOR_HEX_VAR; \
             a rename here would let a kernel build's resolution chain \
             miss the injection.",
        );
    }

    /// Witness for the post-build verification step: a synthetic
    /// kernel-shaped fixture whose `.rodata` carries only the
    /// placeholder bytes is rejected by `verify_kernel_binary_at_path`
    /// with the `INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01
    /// VIOLATED` token, and a sibling fixture carrying the expected
    /// fingerprint is accepted.
    #[test]
    fn inv_image_bake_kernel_trust_anchor_populated_01_verify_step_rejects_placeholder_and_accepts_fingerprint(
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let kernel_dir = tmp.path().join("install").join("kernel");
        std::fs::create_dir_all(&kernel_dir).unwrap();
        let kernel_path = kernel_dir.join("vmlinux");

        let pk_hex: String = "ab".repeat(32);
        let pk_bytes = trust_anchor::decode_pk_hex_bytes(&pk_hex).unwrap();

        // Case 1: placeholder embedded, fingerprint absent → reject.
        let mut placeholder_binary: Vec<u8> = (0..1024u32).map(|i| (i % 251 + 1) as u8).collect();
        placeholder_binary.extend_from_slice(&[0u8; 32]);
        placeholder_binary.extend((0..1024u32).map(|i| (i % 241 + 1) as u8));
        std::fs::write(&kernel_path, &placeholder_binary).unwrap();
        let err = trust_anchor::verify_kernel_binary_at_path(&kernel_path, &pk_hex)
            .expect_err("placeholder binary MUST be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01 VIOLATED"),
            "rejection MUST cite the invariant: {msg}",
        );

        // Case 2: fingerprint embedded → accept.
        let mut populated_binary: Vec<u8> = (0..1024u32).map(|i| (i % 251 + 1) as u8).collect();
        populated_binary.extend_from_slice(&pk_bytes);
        populated_binary.extend((0..1024u32).map(|i| (i % 241 + 1) as u8));
        std::fs::write(&kernel_path, &populated_binary).unwrap();
        trust_anchor::verify_kernel_binary_at_path(&kernel_path, &pk_hex)
            .expect("populated binary MUST be accepted");
    }

    /// Witness for the verify-trust-anchor argv parser: defaults
    /// fall back to `<install_dir>/kernel/vmlinux` AND
    /// `resolve_signing_key_pk_hex` when neither flag is supplied,
    /// and explicit flags override both.
    #[test]
    fn inv_image_bake_kernel_trust_anchor_populated_01_verify_argv_explicit_flags_override_defaults(
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let kernel_path = tmp.path().join("custom-vmlinux");
        std::fs::write(&kernel_path, b"placeholder-bytes").unwrap();
        let pk_hex: String = "cd".repeat(32);

        let argv = vec![
            "--kernel".to_owned(),
            kernel_path.display().to_string(),
            "--expected-pk-hex".to_owned(),
            pk_hex.clone(),
        ];
        let parsed = VerifyTrustAnchorArgs::parse(&argv).expect("parse");
        assert_eq!(parsed.kernel_path, kernel_path);
        assert_eq!(parsed.expected_pk_hex, pk_hex);
    }

    #[test]
    fn verify_trust_anchor_default_kernel_targets_host_binary_not_guest_vmlinux() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path();
        let guest_vmlinux = workspace.join("install/kernel/vmlinux");
        std::fs::create_dir_all(guest_vmlinux.parent().unwrap()).unwrap();
        std::fs::write(&guest_vmlinux, b"guest kernel").unwrap();

        let release_kernel = workspace.join("target/release/raxis-kernel");
        std::fs::create_dir_all(release_kernel.parent().unwrap()).unwrap();
        std::fs::write(&release_kernel, b"host daemon").unwrap();

        let resolved = default_host_kernel_binary_from(workspace, None).unwrap();
        assert_eq!(resolved, release_kernel);
        assert_ne!(resolved, guest_vmlinux);
    }

    #[test]
    fn verify_trust_anchor_default_kernel_honors_explicit_env_override() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path();
        let env_kernel = workspace.join("custom/raxis-kernel");
        let resolved =
            default_host_kernel_binary_from(workspace, Some(env_kernel.clone())).unwrap();
        assert_eq!(resolved, env_kernel);
    }

    /// Witness that `bake_one_role_full`'s signature carries the
    /// resolved `kernel_signing_key_hex` so the per-role driver can
    /// thread it into both the `dev_stage` cargo subprocess AND
    /// `build_all`'s auto-stage path. We pin this through a
    /// compile-time check (the function symbol exists with the
    /// expected arity) rather than a runtime spawn — the umbrella
    /// driver's threading is exercised end-to-end by the bake
    /// integration harness in the parent worker repo.
    #[test]
    fn inv_image_bake_kernel_trust_anchor_populated_01_bake_one_role_full_threads_signing_key() {
        // Compile-time witness: take a function pointer with the
        // exact signature we expect. If a future refactor drops
        // the `kernel_signing_key_hex` parameter (or moves it
        // into a struct without keeping a top-level seam),
        // this test stops compiling and the spec must be
        // updated in lockstep.
        let _: fn(Role, &BakeArgs, &PreflightOutcome, &str, &str) -> Result<()> =
            bake_one_role_full;
    }

    /// Witness that `apply_trust_anchor_env` injects the canonical
    /// env-var name into a `Command`'s child env, and skips the
    /// injection when `pk_hex` is `None` (test-fixture path).
    #[test]
    fn inv_image_bake_kernel_trust_anchor_populated_01_apply_trust_anchor_env_threads_pk_hex() {
        let pk_hex: String = "ef".repeat(32);

        // With Some: child env carries the var.
        let mut cmd_with = Command::new("true");
        apply_trust_anchor_env(&mut cmd_with, Some(&pk_hex));
        let envs: Vec<_> = cmd_with
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|s| s.to_string_lossy().into_owned()),
                )
            })
            .collect();
        let found = envs
            .iter()
            .find(|(k, _)| k == "RAXIS_KERNEL_SIGNING_KEY_HEX");
        assert!(found.is_some(), "env var must be set; got {envs:?}");
        assert_eq!(found.unwrap().1.as_deref(), Some(pk_hex.as_str()));

        // With None: helper is a no-op.
        let mut cmd_without = Command::new("true");
        apply_trust_anchor_env(&mut cmd_without, None);
        let envs_without: Vec<_> = cmd_without.get_envs().collect();
        assert!(
            envs_without
                .iter()
                .all(|(k, _)| k.to_string_lossy() != "RAXIS_KERNEL_SIGNING_KEY_HEX"),
            "helper must NOT set the var when pk_hex is None; got {envs_without:?}",
        );
    }
}
