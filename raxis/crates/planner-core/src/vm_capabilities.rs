//! `vm_capabilities` — in-guest VM capability discovery
//! (`INV-EXEC-DISCOVERY-01`).
//!
//! ## Why this module exists
//!
//! Per `planner-harness.md §10.6`, the executor LLM runs inside a
//! digest-pinned canonical rootfs (Node 20 LTS, Python 3.11 with
//! pinned DB clients, Rust stable, Go 1.22, bash, git, gh, jq,
//! ripgrep, fd, build-essential, …) OR an operator-pinned BYO image
//! whose contents we cannot enumerate at kernel build time
//! (`canonical-images.md §INV-OPERATOR-CUSTOM-IMAGE-01`). Either
//! way, the LLM cannot do trial-and-error `pip install` /
//! `npm install` of packages: egress is gated by the kernel's
//! allowlist (most tasks have NO outbound net) and the credential
//! proxies only forward DB / cloud traffic, not package mirrors. If
//! the LLM doesn't know what's already baked in, it will either
//! write a script importing a missing module and fail at runtime
//! OR try to install a package and burn a turn on a tproxy denial.
//!
//! This module gives the planner-harness one **in-guest
//! introspection** path that probes the VM's binaries, language
//! runtimes, pre-installed packages, env vars, and workdir state,
//! and returns a typed [`CapabilityManifest`] the dispatch loop can:
//!
//! 1. Render into the executor / reviewer / orchestrator system
//!    prompt as a one-shot capability hint
//!    ([`build_capability_hint`]).
//! 2. Expose to the LLM as the structured `vm_capabilities` tool
//!    so the model can ask "is `numpy` available?" without grepping
//!    free-text shell output (`tools_vm_capabilities.rs`).
//!
//! Both surfaces consume the SAME [`CapabilityManifest`] computed
//! by [`probe_capabilities`], so the in-prompt summary and the
//! tool output can never disagree about what the VM has.
//!
//! ## Caching
//!
//! Every probe is bounded to sub-second on a warm VM: we do NOT
//! recursively walk the filesystem (workdir-language detection
//! peeks at the workdir's *top-level entries* only) and we do not
//! shell out for binaries we did not specifically need a version
//! string for. The result is cached for the lifetime of the
//! planner-harness process via [`cached_capabilities`] —
//! the planner-executor is one-shot per session, so per-process
//! caching == per-session caching.
//!
//! ## Determinism
//!
//! Per `INV-EXEC-DISCOVERY-01`, the manifest MUST be deterministic
//! for a given image digest + session env: same image + same
//! credential-proxy env stamping => same manifest bytes. We achieve
//! that by:
//!
//! * Emitting binaries in lexical order (we walk PATH dirs in
//!   declared order, then sort the discovered names).
//! * Emitting Python / Node packages in lexical order (we
//!   `BTreeSet`-collect names before serializing).
//! * Filtering env vars with a closed denylist
//!   ([`is_kernel_private_env`]) so a kernel-side env-stamp
//!   reorder does not change the surface — only the names matter,
//!   not the iteration order.
//!
//! Determinism makes prompt caching at the provider layer
//! observable: an unchanged manifest produces an unchanged system
//! prompt, which the provider's prefix cache can hit.
//!
//! ## Kernel-private env redaction
//!
//! The env section of the manifest MUST NOT leak the
//! `RAXIS_VSOCK_LOOPBACK_PLAN` payload, `RAXIS_SESSION_TOKEN`, the
//! `RAXIS_PLANNER_KSB` JSON, the sidecar HMAC secret, or any name
//! containing a credential-shaped substring (`SECRET`, `PASSWORD`,
//! `API_KEY`, `PRIVATE_KEY`, `_TOKEN`). The closed predicate
//! [`is_kernel_private_env`] is the chokepoint; every probe that
//! collects env vars routes through it.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One probed binary (PATH entry + optional version string).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryEntry {
    /// File-name as it appears on PATH (e.g. `python3`, `node`).
    pub name: String,
    /// Absolute path the first PATH-walk hit resolved to.
    pub path: String,
    /// Best-effort version string (`5.2.15`, `1.79.0`, …). `None`
    /// means we did not invoke the binary — either the name was
    /// not in our well-known toolchain table or the version probe
    /// failed. We do NOT shell out to every binary on PATH because
    /// the goal is sub-second introspection on a warm VM.
    pub version: Option<String>,
}

/// One Python package discovered in the interpreter's site-packages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PythonPackage {
    /// Distribution name (canonical PyPI form, e.g.
    /// `psycopg2-binary`).
    pub name: String,
    /// Version string from the `dist-info/METADATA` `Version:` line.
    pub version: String,
    /// `true` if `python3 -c "import <module>"` round-tripped on
    /// the VM. Only populated when the caller passed an explicit
    /// `python_package` filter; otherwise `None` (importability is
    /// expensive — one subprocess per package — and the
    /// dist-info metadata is the cheap ground truth).
    pub importable: Option<bool>,
}

/// Python runtime + package set probed from the canonical
/// interpreter on PATH (`python3` if present, falling back to
/// `python`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PythonRuntime {
    /// Path to the interpreter (`/usr/bin/python3`).
    pub interpreter: String,
    /// Version string (`3.11.2`).
    pub version: String,
    /// Site-packages root the manifest scanned for installed
    /// distributions.
    pub site_packages: String,
    /// Packages discovered in `site-packages` (lex-sorted by name).
    pub packages: Vec<PythonPackage>,
}

/// One Node global package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodePackage {
    /// npm package name (e.g. `npm`, `yarn`).
    pub name: String,
    /// Version string from `npm list -g --json --depth=0` (or
    /// `package.json` fallback).
    pub version: String,
}

/// Node runtime + global package set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRuntime {
    /// Path to the interpreter (`/usr/bin/node`).
    pub interpreter: String,
    /// Version string (`20.18.0`).
    pub version: String,
    /// Globally-installed packages (lex-sorted by name).
    pub global_packages: Vec<NodePackage>,
}

/// Rust toolchain probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustToolchain {
    /// `rustc --version` (e.g. `1.79.0`). `None` ⇒ rustc not on PATH.
    pub rustc: Option<String>,
    /// `cargo --version` (e.g. `1.79.0`). `None` ⇒ cargo not on PATH.
    pub cargo: Option<String>,
}

/// Go toolchain probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoToolchain {
    /// `go version` (e.g. `1.22.0`). `None` ⇒ go not on PATH.
    pub go: Option<String>,
}

/// Filesystem / workdir snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemSnapshot {
    /// Working directory as observed at probe time
    /// (`std::env::current_dir`).
    pub workdir: String,
    /// Languages we detected by inspecting the workdir's TOP-LEVEL
    /// entries only (`Cargo.toml` ⇒ rust, `package.json` ⇒ node,
    /// `pyproject.toml` / `setup.py` / `requirements.txt` ⇒ python,
    /// `go.mod` ⇒ go). No recursive walk — the goal is hint, not
    /// authoritative tagging.
    pub workdir_languages_detected: Vec<String>,
    /// `true` if the workdir contains a `.git/` directory.
    pub git_initialized: bool,
    /// `git rev-parse HEAD` if the workdir is a git repo, else
    /// `None`.
    pub head_commit: Option<String>,
}

/// Image role tag — which planner-harness role this manifest was
/// probed inside. The value is informational; the kernel
/// authoritative role binding is whichever binary was spawned
/// (`/usr/local/bin/raxis-{executor,reviewer,orchestrator}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageRole {
    /// Executor binary spawned this manifest.
    Executor,
    /// Reviewer binary.
    Reviewer,
    /// Orchestrator binary.
    Orchestrator,
    /// Operator-published BYO Executor image
    /// (`canonical-images.md §3`). The role binary is still the
    /// executor; the tag exists so the LLM knows the contents are
    /// not the kernel-bundled defaults.
    Byo,
    /// We could not classify the image. Used by tests / non-VM
    /// hosts where the introspection runs but the role context is
    /// absent.
    Unknown,
}

/// **The manifest the LLM sees.** Returned by both the
/// system-prompt assembler ([`build_capability_hint`]) and the
/// `vm_capabilities` tool, so the in-prompt hint and the tool
/// output never disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    /// Which planner role this manifest was probed in.
    pub image_role: ImageRole,
    /// SHA-256 image digest (`sha256:<64-hex>`) when the kernel
    /// stamped one via the `RAXIS_VM_IMAGE_DIGEST` env at spawn,
    /// else `None`. Inert metadata for the LLM; the kernel-side
    /// digest verification is what binds the contents.
    pub image_digest: Option<String>,
    /// Binaries discovered on PATH (lex-sorted).
    pub binaries: Vec<BinaryEntry>,
    /// Python runtime + packages. `None` ⇒ no python interpreter
    /// on PATH.
    pub python: Option<PythonRuntime>,
    /// Node runtime + global packages. `None` ⇒ no node on PATH.
    pub node: Option<NodeRuntime>,
    /// Rust toolchain (always emitted; per-tool `Option<String>`
    /// reflects per-tool absence).
    pub rust: RustToolchain,
    /// Go toolchain (always emitted).
    pub go: GoToolchain,
    /// Env var name → value, after kernel-private redaction.
    pub env: BTreeMap<String, String>,
    /// Workdir / git state.
    pub filesystem: FilesystemSnapshot,
}

// ---------------------------------------------------------------------------
// Categories + filter
// ---------------------------------------------------------------------------

/// Subset of the manifest the caller wants to see. The
/// `vm_capabilities` tool accepts a `categories: [...]` array;
/// this enum is its typed projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityCategory {
    /// Binary table.
    Binaries,
    /// Python runtime + package set.
    Python,
    /// Node runtime + global package set.
    Node,
    /// Rust toolchain (`rustc` / `cargo`).
    Rust,
    /// Go toolchain.
    Go,
    /// Env vars (redacted).
    Env,
    /// Filesystem / workdir snapshot.
    Filesystem,
    /// Everything (default).
    All,
}

impl CapabilityCategory {
    /// Map the wire string the LLM sends (`"binaries"`, etc.) to
    /// the typed variant. Returns `None` for unknown values so the
    /// tool surface can produce a structured error message.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "binaries" => Some(Self::Binaries),
            "python" => Some(Self::Python),
            "node" => Some(Self::Node),
            "rust" => Some(Self::Rust),
            "go" => Some(Self::Go),
            "env" => Some(Self::Env),
            "filesystem" => Some(Self::Filesystem),
            "all" => Some(Self::All),
            _ => None,
        }
    }
}

/// Optional filters the LLM can apply on top of a category.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CapabilityFilter {
    /// Substring match against [`BinaryEntry::name`]. ASCII
    /// `to_lowercase` on both sides so "RIPGREP" matches `rg`?
    /// No — only literal substring of the name; the LLM should
    /// know the binary name.
    pub binary_name: Option<String>,
    /// Single Python package name to surface (and probe
    /// importability for).
    pub python_package: Option<String>,
    /// Single Node global-package name to surface.
    pub node_package: Option<String>,
    /// Single env var name to surface (subject to kernel-private
    /// redaction).
    pub env_var: Option<String>,
}

/// Apply categories + filter to a base manifest, producing a new
/// manifest containing only the requested fields. Always returns
/// a manifest (never errors); empty subsections become empty.
///
/// `categories` empty ⇒ same as `[All]`.
pub fn project_manifest(
    base: &CapabilityManifest,
    categories: &[CapabilityCategory],
    filter: &CapabilityFilter,
) -> CapabilityManifest {
    let want_all = categories.is_empty()
        || categories
            .iter()
            .any(|c| matches!(c, CapabilityCategory::All));
    let want = |c: CapabilityCategory| -> bool { want_all || categories.iter().any(|x| *x == c) };

    let binaries = if want(CapabilityCategory::Binaries) {
        match filter.binary_name.as_deref() {
            Some(needle) => base
                .binaries
                .iter()
                .filter(|b| b.name.contains(needle))
                .cloned()
                .collect(),
            None => base.binaries.clone(),
        }
    } else {
        Vec::new()
    };

    let python = if want(CapabilityCategory::Python) {
        match (&base.python, filter.python_package.as_deref()) {
            (Some(py), Some(pkg)) => {
                // Find the requested package; probe importability if
                // the interpreter is callable.
                let mut filtered = py.clone();
                let importable = python_importable(&py.interpreter, pkg);
                filtered.packages = py
                    .packages
                    .iter()
                    .filter(|p| p.name == pkg)
                    .cloned()
                    .map(|mut p| {
                        p.importable = Some(importable);
                        p
                    })
                    .collect();
                if filtered.packages.is_empty() {
                    // Package not in dist-info but the LLM asked
                    // about it — still surface the importability
                    // probe so a failure is visible.
                    filtered.packages.push(PythonPackage {
                        name: pkg.to_owned(),
                        version: String::new(),
                        importable: Some(importable),
                    });
                }
                Some(filtered)
            }
            (Some(py), None) => Some(py.clone()),
            (None, _) => None,
        }
    } else {
        None
    };

    let node = if want(CapabilityCategory::Node) {
        match (&base.node, filter.node_package.as_deref()) {
            (Some(n), Some(pkg)) => {
                let mut filtered = n.clone();
                filtered.global_packages = n
                    .global_packages
                    .iter()
                    .filter(|p| p.name == pkg)
                    .cloned()
                    .collect();
                Some(filtered)
            }
            (Some(n), None) => Some(n.clone()),
            (None, _) => None,
        }
    } else {
        None
    };

    let rust = if want(CapabilityCategory::Rust) {
        base.rust.clone()
    } else {
        RustToolchain {
            rustc: None,
            cargo: None,
        }
    };

    let go = if want(CapabilityCategory::Go) {
        base.go.clone()
    } else {
        GoToolchain { go: None }
    };

    let env = if want(CapabilityCategory::Env) {
        match filter.env_var.as_deref() {
            Some(name) => {
                let mut out = BTreeMap::new();
                if let Some(v) = base.env.get(name) {
                    out.insert(name.to_owned(), v.clone());
                }
                out
            }
            None => base.env.clone(),
        }
    } else {
        BTreeMap::new()
    };

    let filesystem = if want(CapabilityCategory::Filesystem) {
        base.filesystem.clone()
    } else {
        FilesystemSnapshot {
            workdir: String::new(),
            workdir_languages_detected: Vec::new(),
            git_initialized: false,
            head_commit: None,
        }
    };

    CapabilityManifest {
        image_role: base.image_role.clone(),
        image_digest: base.image_digest.clone(),
        binaries,
        python,
        node,
        rust,
        go,
        env,
        filesystem,
    }
}

// ---------------------------------------------------------------------------
// Env redaction — INV-EXEC-DISCOVERY-01 kernel-private chokepoint
// ---------------------------------------------------------------------------

/// `true` ⇒ the env var name is kernel-private and MUST NOT appear
/// in the manifest's `env` section. Closed predicate so a future
/// kernel-side env stamp that adds a new sensitive var has one
/// place to extend.
///
/// Two layers:
///
/// 1. **Explicit name list.** The kernel's own session-spawn env
///    (`RAXIS_SESSION_TOKEN`, `RAXIS_VSOCK_LOOPBACK_PLAN`, the KSB
///    snapshot, the task prompt, sidecar HMAC).
///
/// 2. **Pattern denylist.** Anything whose name (case-insensitively)
///    contains `SECRET`, `PASSWORD`, `PASSWD`, `API_KEY`, `APIKEY`,
///    `PRIVATE_KEY`, or ends in `_TOKEN`. Matches operator-declared
///    secret-shaped env vars (`STRIPE_API_KEY`, `GITHUB_TOKEN`,
///    `DATABASE_PASSWORD`, …) without enumeration.
pub fn is_kernel_private_env(name: &str) -> bool {
    if matches!(
        name,
        "RAXIS_SESSION_TOKEN"
            | "RAXIS_VSOCK_LOOPBACK_PLAN"
            | "RAXIS_PLANNER_KSB"
            | "RAXIS_PLANNER_KSB_PATH"
            | "RAXIS_PLANNER_TASK_PROMPT"
            | "RAXIS_PLANNER_TASK_PROMPT_PATH"
            | "RAXIS_PLANNER_SIDECAR_HMAC_SECRET"
            | "RAXIS_PLANNER_SIDECAR_PROVIDER_ID"
            | "RAXIS_PLANNER_SIDECAR_ENDPOINT"
    ) {
        return true;
    }
    let upper = name.to_ascii_uppercase();
    upper.contains("SECRET")
        || upper.contains("PASSWORD")
        || upper.contains("PASSWD")
        || upper.contains("API_KEY")
        || upper.contains("APIKEY")
        || upper.contains("PRIVATE_KEY")
        || upper.ends_with("_TOKEN")
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

/// Run every probe synchronously and return a fresh
/// [`CapabilityManifest`]. Bounded sub-second on a warm VM; the
/// only subprocess invocations are the small per-toolchain version
/// probes (`bash --version`, `python3 --version`, `node --version`,
/// `npm --version`, `rustc --version`, `cargo --version`,
/// `go version`, `git --version`, `git rev-parse HEAD`,
/// `npm list -g --json --depth=0`).
///
/// `env_reader` is the env-reader closure (matches the
/// `BootEnv::from_env_fn` shape so unit tests can hermetically
/// stub the process env). `cwd` is the workdir to inspect for
/// the `filesystem` section.
///
/// The `image_role` field is filled from `RAXIS_PLANNER_ROLE`
/// when present (kernel stamps it for every spawn), else
/// [`ImageRole::Unknown`] — non-VM hosts (CI, dev workstation)
/// hit the `Unknown` branch.
pub fn probe_capabilities<F>(env_reader: &F, cwd: &Path) -> CapabilityManifest
where
    F: Fn(&str) -> Option<String>,
{
    let path_var = env_reader("PATH").unwrap_or_default();
    let binaries = probe_binaries(&path_var);
    let python = probe_python(&binaries);
    let node = probe_node(&binaries);
    let rust = probe_rust(&binaries);
    let go = probe_go(&binaries);
    let env = probe_env(env_reader);
    let filesystem = probe_filesystem(cwd);
    let image_role = match env_reader("RAXIS_PLANNER_ROLE").as_deref() {
        Some("executor") => ImageRole::Executor,
        Some("reviewer") => ImageRole::Reviewer,
        Some("orchestrator") => ImageRole::Orchestrator,
        Some("byo") => ImageRole::Byo,
        _ => ImageRole::Unknown,
    };
    let image_digest = env_reader("RAXIS_VM_IMAGE_DIGEST").filter(|s| !s.is_empty());

    CapabilityManifest {
        image_role,
        image_digest,
        binaries,
        python,
        node,
        rust,
        go,
        env,
        filesystem,
    }
}

/// Cached process-wide accessor. The first call probes; subsequent
/// calls return the same `Arc<CapabilityManifest>`. Per
/// `INV-EXEC-DISCOVERY-01`, the manifest is deterministic for a
/// given (image, env) pair and the planner-harness is one-shot per
/// session, so per-process == per-session caching is correct.
pub fn cached_capabilities() -> Arc<CapabilityManifest> {
    static CACHE: OnceLock<Arc<CapabilityManifest>> = OnceLock::new();
    Arc::clone(CACHE.get_or_init(|| {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        Arc::new(probe_capabilities(&|k| std::env::var(k).ok(), &cwd))
    }))
}

// ---------------------------------------------------------------------------
// Per-section probes (private)
// ---------------------------------------------------------------------------

/// Walk every directory in `PATH` (declared order, first-wins) and
/// collect executable file entries. Adds a best-effort version
/// string for the well-known toolchain set. Other binaries surface
/// with `version: None` to keep the probe sub-second (one
/// subprocess per binary would scale with the rootfs, not the
/// manifest's payload).
fn probe_binaries(path_var: &str) -> Vec<BinaryEntry> {
    let mut seen: BTreeMap<String, BinaryEntry> = BTreeMap::new();
    for dir in path_var.split(':').filter(|s| !s.is_empty()) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            // Skip if we already saw this name in an earlier PATH
            // dir (PATH precedence).
            if seen.contains_key(&name) {
                continue;
            }
            // Best-effort executable check: stat the entry; if
            // metadata fails or the file is a directory, skip.
            // We do NOT enforce the executable bit on Unix because
            // BYO images may surface scripts via wrappers; the
            // model can resolve that. The cheap check is "it's a
            // regular file in a PATH dir".
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                continue;
            }
            let path = format!("{dir}/{name}");
            seen.insert(
                name.clone(),
                BinaryEntry {
                    name,
                    path,
                    version: None,
                },
            );
        }
    }

    // Best-effort version probes for the well-known toolchain set.
    // Each probe spawns one subprocess; we cap the table at a
    // small list so the worst-case probe time stays sub-second.
    for name in WELL_KNOWN_VERSION_PROBES {
        if let Some(entry) = seen.get_mut(*name) {
            entry.version = best_effort_version(name, &entry.path);
        }
    }

    seen.into_values().collect()
}

/// Names whose `--version` output we extract for the manifest.
/// Order is alphabetical (we re-sort on emit anyway). Curated to
/// cover the canonical executor starter image plus the operator
/// most-likely BYO additions.
const WELL_KNOWN_VERSION_PROBES: &[&str] = &[
    "bash", "cargo", "clang", "curl", "fd", "gcc", "git", "gh", "go", "gofmt", "grep", "jq",
    "make", "node", "npm", "npx", "pip", "pip3", "pnpm", "python", "python3", "ripgrep", "rg",
    "ruby", "rustc", "sed", "wget", "yarn",
];

/// Run `<bin> --version` (or `<bin> version` for `go`) with a
/// 2-second hard timeout, return the first stripped output line
/// or `None` on failure / timeout.
fn best_effort_version(name: &str, path: &str) -> Option<String> {
    use std::process::{Command, Stdio};
    let arg = if name == "go" { "version" } else { "--version" };
    let mut cmd = Command::new(path);
    cmd.arg(arg)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Spawn + wait with a bounded budget. We use the std blocking
    // API rather than tokio because the probe runs at session
    // boot before the dispatch loop's tokio runtime is engaged.
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return None,
    };
    let out = match wait_with_timeout(child, Duration::from_secs(2)) {
        Some(o) => o,
        None => return None,
    };
    let raw = if !out.stdout.is_empty() {
        String::from_utf8_lossy(&out.stdout).into_owned()
    } else {
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    raw.lines()
        .next()
        .map(|l| l.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Spawn-and-wait with a wall-clock budget. Returns `None` if the
/// child outlives the budget (in which case we leak the child
/// PID — the planner-harness process is one-shot and will exit
/// shortly anyway, so the leak is bounded). Mirrors the bounded
/// timeout pattern the `BashTool` uses but keeps the std API
/// because this runs before the tokio runtime is set up.
fn wait_with_timeout(
    mut child: std::process::Child,
    budget: Duration,
) -> Option<std::process::Output> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                return child.wait_with_output().ok();
            }
            Ok(None) => {
                if start.elapsed() > budget {
                    let _ = child.kill();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }
}

/// Detect Python interpreter, version, site-packages root, and
/// installed distributions. Prefer `python3` over `python`. We do
/// NOT shell out to `pip list` — reading dist-info directly is
/// faster and avoids the "pip not installed" failure mode.
fn probe_python(binaries: &[BinaryEntry]) -> Option<PythonRuntime> {
    let interp = binaries
        .iter()
        .find(|b| b.name == "python3")
        .or_else(|| binaries.iter().find(|b| b.name == "python"))?;
    let version = interp
        .version
        .clone()
        .unwrap_or_else(|| best_effort_version(&interp.name, &interp.path).unwrap_or_default());
    // Strip the `Python ` prefix that `python3 --version` emits.
    let version = version
        .strip_prefix("Python ")
        .unwrap_or(&version)
        .to_owned();

    // Resolve site-packages by asking the interpreter directly. This
    // is the only authoritative source — the on-disk path varies
    // across distros (`/usr/lib/python3/dist-packages`,
    // `/usr/lib/python3.11/site-packages`, virtualenv targets, …).
    let site_packages = match python_site_packages(&interp.path) {
        Some(p) => p,
        None => {
            return Some(PythonRuntime {
                interpreter: interp.path.clone(),
                version,
                site_packages: String::new(),
                packages: Vec::new(),
            })
        }
    };

    let packages = read_python_packages(&site_packages);
    Some(PythonRuntime {
        interpreter: interp.path.clone(),
        version,
        site_packages,
        packages,
    })
}

/// Ask the interpreter for the first site-packages path on its
/// `sys.path`. Two-second budget; on failure return `None` so the
/// caller emits an empty `packages: []`.
fn python_site_packages(interpreter: &str) -> Option<String> {
    use std::process::{Command, Stdio};
    let child = Command::new(interpreter)
        .arg("-c")
        .arg(
            "import sys, sysconfig; \
             p = sysconfig.get_paths().get('purelib') or \
                 sysconfig.get_paths().get('platlib'); \
             print(p or '', end='')",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let out = wait_with_timeout(child, Duration::from_secs(2))?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Walk the site-packages root looking for `*.dist-info/METADATA`
/// (PEP 427) and `*.egg-info/PKG-INFO` (legacy). Extract `Name:`
/// and `Version:`. Lex-sorted by name on emit.
fn read_python_packages(site_packages: &str) -> Vec<PythonPackage> {
    let mut packages: BTreeMap<String, PythonPackage> = BTreeMap::new();
    let entries = match std::fs::read_dir(site_packages) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let metadata_path = if name.ends_with(".dist-info") {
            entry.path().join("METADATA")
        } else if name.ends_with(".egg-info") {
            entry.path().join("PKG-INFO")
        } else {
            continue;
        };
        let body = match std::fs::read_to_string(&metadata_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut pkg_name: Option<String> = None;
        let mut pkg_version: Option<String> = None;
        for line in body.lines() {
            // PEP 566: only the headers above the first blank
            // line are the metadata. Stop scanning at the gap.
            if line.is_empty() {
                break;
            }
            if let Some(v) = line.strip_prefix("Name:") {
                pkg_name = Some(v.trim().to_owned());
            } else if let Some(v) = line.strip_prefix("Version:") {
                pkg_version = Some(v.trim().to_owned());
            }
            if pkg_name.is_some() && pkg_version.is_some() {
                break;
            }
        }
        if let (Some(n), Some(v)) = (pkg_name, pkg_version) {
            packages.insert(
                n.clone(),
                PythonPackage {
                    name: n,
                    version: v,
                    importable: None,
                },
            );
        }
    }
    packages.into_values().collect()
}

/// Attempt `python3 -c "import <pkg>"` with a 5-second budget;
/// `true` ⇒ exit 0. Used by the per-tool filter when the LLM asks
/// "is `numpy` actually importable?".
fn python_importable(interpreter: &str, package: &str) -> bool {
    use std::process::{Command, Stdio};
    let probe = format!("import {package}");
    let child = match Command::new(interpreter)
        .arg("-c")
        .arg(&probe)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    match wait_with_timeout(child, Duration::from_secs(5)) {
        Some(o) => o.status.success(),
        None => false,
    }
}

/// Detect Node interpreter and global packages. Spawns
/// `npm list -g --json --depth=0` with a bounded budget; if `npm`
/// is absent or the call fails, returns `node` alone with an
/// empty `global_packages` set.
fn probe_node(binaries: &[BinaryEntry]) -> Option<NodeRuntime> {
    let node = binaries.iter().find(|b| b.name == "node")?;
    let version = node
        .version
        .clone()
        .unwrap_or_else(|| best_effort_version("node", &node.path).unwrap_or_default());
    let version = version.trim_start_matches('v').to_owned();
    let global_packages = match binaries.iter().find(|b| b.name == "npm") {
        Some(npm) => npm_list_global(&npm.path).unwrap_or_default(),
        None => Vec::new(),
    };
    Some(NodeRuntime {
        interpreter: node.path.clone(),
        version,
        global_packages,
    })
}

/// Run `npm list -g --json --depth=0` and parse the
/// `dependencies: { name: { version: ... } }` object.
fn npm_list_global(npm_path: &str) -> Option<Vec<NodePackage>> {
    use std::process::{Command, Stdio};
    let child = Command::new(npm_path)
        .args(["list", "-g", "--json", "--depth=0"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let out = wait_with_timeout(child, Duration::from_secs(5))?;
    let body = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let deps = v.get("dependencies")?.as_object()?;
    let mut packages: BTreeSet<(String, String)> = BTreeSet::new();
    for (name, meta) in deps {
        let version = meta
            .get("version")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_owned();
        packages.insert((name.clone(), version));
    }
    Some(
        packages
            .into_iter()
            .map(|(name, version)| NodePackage { name, version })
            .collect(),
    )
}

fn probe_rust(binaries: &[BinaryEntry]) -> RustToolchain {
    let rustc = binaries
        .iter()
        .find(|b| b.name == "rustc")
        .and_then(|b| b.version.clone());
    let cargo = binaries
        .iter()
        .find(|b| b.name == "cargo")
        .and_then(|b| b.version.clone());
    RustToolchain { rustc, cargo }
}

fn probe_go(binaries: &[BinaryEntry]) -> GoToolchain {
    let go = binaries
        .iter()
        .find(|b| b.name == "go")
        .and_then(|b| b.version.clone());
    GoToolchain { go }
}

/// Collect env vars surviving [`is_kernel_private_env`].
fn probe_env<F>(env_reader: &F) -> BTreeMap<String, String>
where
    F: Fn(&str) -> Option<String>,
{
    // We only have an env-reader closure (not the full process env
    // map) so we cannot enumerate; fall back to `std::env::vars`
    // when the closure is wrapping the live process. Hermetic unit
    // tests pass a stubbed env via [`probe_env_with_iter`].
    let mut out = BTreeMap::new();
    for (k, v) in std::env::vars() {
        if is_kernel_private_env(&k) {
            continue;
        }
        out.insert(k, v);
    }
    // Cross-check against the closure: if a name we collected from
    // `vars()` has a different value via the closure (rare; the
    // closure may be a hermetic stub), prefer the closure's value
    // so test stubs are authoritative.
    let names: Vec<String> = out.keys().cloned().collect();
    for k in names {
        if let Some(v) = env_reader(&k) {
            out.insert(k, v);
        }
    }
    out
}

/// Test-only constructor that does NOT touch `std::env::vars()`.
/// Used by hermetic unit tests to feed a synthetic env.
#[doc(hidden)]
pub fn probe_env_with_iter<I>(iter: I) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut out = BTreeMap::new();
    for (k, v) in iter {
        if is_kernel_private_env(&k) {
            continue;
        }
        out.insert(k, v);
    }
    out
}

fn probe_filesystem(cwd: &Path) -> FilesystemSnapshot {
    let workdir = cwd.to_string_lossy().into_owned();
    let git_initialized = cwd.join(".git").is_dir();
    let head_commit = if git_initialized {
        git_head_sha(cwd)
    } else {
        None
    };
    let mut langs: BTreeSet<&'static str> = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir(cwd) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            match name.as_str() {
                "Cargo.toml" => {
                    langs.insert("rust");
                }
                "package.json" => {
                    langs.insert("node");
                }
                "pyproject.toml" => {
                    langs.insert("python");
                }
                "setup.py" => {
                    langs.insert("python");
                }
                "requirements.txt" => {
                    langs.insert("python");
                }
                "go.mod" => {
                    langs.insert("go");
                }
                "Gemfile" => {
                    langs.insert("ruby");
                }
                "pom.xml" => {
                    langs.insert("java");
                }
                "build.gradle" | "build.gradle.kts" => {
                    langs.insert("java");
                }
                _ => {}
            }
        }
    }
    FilesystemSnapshot {
        workdir,
        workdir_languages_detected: langs.into_iter().map(str::to_owned).collect(),
        git_initialized,
        head_commit,
    }
}

fn git_head_sha(cwd: &Path) -> Option<String> {
    use std::process::{Command, Stdio};
    let child = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let out = wait_with_timeout(child, Duration::from_secs(2))?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(s)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// System-prompt hint
// ---------------------------------------------------------------------------

/// Render the manifest into a one-paragraph system-prompt hint the
/// LLM sees on its first turn. Keep this short (≤ ~1.5 KiB on a
/// canonical executor manifest); the structured `vm_capabilities`
/// tool is the recourse for finer queries.
///
/// The hint advertises:
///
/// * Image role / digest (when stamped).
/// * Available language runtimes + versions.
/// * The TOP curated subset of pre-installed Python / Node packages.
/// * The curated subset of available CLI binaries (excluding
///   commodities like `cat`, `echo`, `test`).
/// * Credential-proxy env var names (NEVER values — values may be
///   loopback URLs but the names alone are what the LLM needs to
///   wire its scripts).
/// * Workdir + git state.
/// * The "no outbound network — `pip install` will fail" warning.
pub fn build_capability_hint(m: &CapabilityManifest) -> String {
    let mut s = String::with_capacity(2048);
    s.push_str("## VM Environment\n\n");

    let role = match m.image_role {
        ImageRole::Executor => "executor",
        ImageRole::Reviewer => "reviewer",
        ImageRole::Orchestrator => "orchestrator",
        ImageRole::Byo => "byo (operator-published)",
        ImageRole::Unknown => "unknown",
    };
    s.push_str(&format!("Image role: {role}"));
    if let Some(digest) = &m.image_digest {
        s.push_str(&format!(" (digest {digest})"));
    }
    s.push('\n');

    // Languages + versions.
    let mut langs: Vec<String> = Vec::new();
    if let Some(py) = &m.python {
        if !py.version.is_empty() {
            langs.push(format!("Python {} ({})", py.version, py.interpreter));
        } else {
            langs.push(format!("Python ({})", py.interpreter));
        }
    }
    if let Some(node) = &m.node {
        if !node.version.is_empty() {
            langs.push(format!("Node {}", node.version));
        } else {
            langs.push("Node".to_owned());
        }
    }
    if let Some(rustc) = &m.rust.rustc {
        langs.push(format!("Rust ({rustc})"));
    }
    if let Some(go) = &m.go.go {
        langs.push(format!("Go ({go})"));
    }
    if !langs.is_empty() {
        s.push_str(&format!("Languages: {}\n", langs.join(", ")));
    } else {
        s.push_str("Languages: (none detected)\n");
    }

    // Python packages — TOP curated subset (DB clients first).
    if let Some(py) = &m.python {
        let curated = curated_subset(
            &py.packages
                .iter()
                .map(|p| (p.name.as_str(), p.version.as_str()))
                .collect::<Vec<_>>(),
            CURATED_PYTHON,
        );
        s.push_str(&format!(
            "Pre-installed Python packages: {}\n",
            if curated.is_empty() {
                format!(
                    "(none of common DB/util set; full count {})",
                    py.packages.len()
                )
            } else if py.packages.len() > curated.len() {
                format!(
                    "{} (+ {} others; query `vm_capabilities` for full list)",
                    curated.join(", "),
                    py.packages.len() - curated.len(),
                )
            } else {
                curated.join(", ")
            }
        ));
    }

    // Node global packages.
    if let Some(node) = &m.node {
        if node.global_packages.is_empty() {
            s.push_str(
                "Pre-installed Node packages: (none — `npm install` BLOCKED by egress unless allowed)\n",
            );
        } else {
            let listed: Vec<String> = node
                .global_packages
                .iter()
                .map(|p| format!("{} {}", p.name, p.version))
                .collect();
            s.push_str(&format!(
                "Pre-installed Node packages: {}\n",
                listed.join(", ")
            ));
        }
    }

    // CLI binaries — curated set.
    let avail_binaries = curated_subset(
        &m.binaries
            .iter()
            .map(|b| (b.name.as_str(), b.version.as_deref().unwrap_or("")))
            .collect::<Vec<_>>(),
        CURATED_BINARIES,
    );
    if !avail_binaries.is_empty() {
        s.push_str(&format!(
            "Available binaries: {}\n",
            avail_binaries
                .iter()
                .map(|kv| {
                    // strip the version suffix on the binary line —
                    // saves prompt budget and the LLM rarely needs
                    // it inline.
                    kv.split_once(' ')
                        .map(|(name, _)| name.to_owned())
                        .unwrap_or_else(|| kv.clone())
                })
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }

    // Credential-proxy env vars — NAMES only (values may carry
    // loopback URLs but the LLM only needs the names to wire its
    // scripts; the env section of the structured tool returns
    // values).
    let cred_env: Vec<&String> = m
        .env
        .keys()
        .filter(|k| looks_like_credential_proxy(k))
        .collect();
    if !cred_env.is_empty() {
        s.push_str(&format!(
            "Credential-proxy env vars: {}\n",
            cred_env
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }

    // Workdir.
    let fs = &m.filesystem;
    s.push_str(&format!(
        "Workdir: {} ({}{}{})\n",
        fs.workdir,
        if fs.git_initialized {
            "git-initialized"
        } else {
            "no .git"
        },
        if fs.workdir_languages_detected.is_empty() {
            String::new()
        } else {
            format!(", languages: {}", fs.workdir_languages_detected.join("/"),)
        },
        match &fs.head_commit {
            Some(sha) => format!(", head {}", &sha[..sha.len().min(12)]),
            None => String::new(),
        },
    ));

    s.push('\n');
    s.push_str(
        "No outbound network — `pip install` / `npm install` / `cargo install` / \
         `go get` will fail (egress is gated by the kernel allowlist; package \
         mirrors are not proxied). Use the pre-installed packages above. For \
         finer queries call the `vm_capabilities` tool (e.g. to check whether \
         `numpy` is available, pass `{ \"filter\": { \"python_package\": \
         \"numpy\" } }`).",
    );
    s
}

/// Names whose presence we surface in the system-prompt hint's
/// "Pre-installed Python packages" line. Curated to match the
/// canonical executor starter image's pinned DB clients
/// (planner-harness.md §10.6) plus a few utility libs.
const CURATED_PYTHON: &[&str] = &[
    "psycopg2",
    "psycopg2-binary",
    "psycopg",
    "pymongo",
    "redis",
    "PyMySQL",
    "pymssql",
    "requests",
    "boto3",
    "google-cloud-core",
    "azure-identity",
    "numpy",
    "pandas",
    "pyyaml",
];

/// Names whose presence we surface in the system-prompt hint's
/// "Available binaries" line. Curated to match the canonical
/// starter manifest plus the operator-most-used additions.
const CURATED_BINARIES: &[&str] = &[
    "bash", "git", "gh", "jq", "yq", "rg", "ripgrep", "fd", "curl", "wget", "make", "gcc", "g++",
    "clang", "ld", "ar", "node", "npm", "npx", "yarn", "pnpm", "python3", "pip3", "cargo", "rustc",
    "go", "gofmt", "diff", "patch", "awk", "sed", "grep", "sort", "find", "xargs",
];

/// Pull the curated subset out of a (name, version) sequence,
/// preserving the curation order so the rendered hint is stable.
fn curated_subset(pool: &[(&str, &str)], curated: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for want in curated {
        if let Some((name, version)) = pool.iter().find(|(n, _)| *n == *want) {
            if version.is_empty() {
                out.push((*name).to_owned());
            } else {
                out.push(format!("{name} {version}"));
            }
        }
    }
    out
}

/// Heuristic for credential-proxy env var names. Matches the
/// operator-declared `mount_as` shape from `plan-credentials.md`
/// (`DATABASE_URL`, `USERS_DATABASE_URL`, `MONGO_URL`, `REDIS_URL`,
/// `SMTP_URL`, `*_HOST`, `*_PORT`, etc.) without requiring a
/// closed enumeration — operators name them freely.
fn looks_like_credential_proxy(name: &str) -> bool {
    // Skip the well-known shell + Unix vars that happen to end in
    // `_URL` (none, but be conservative).
    name.ends_with("_URL")
        || name.ends_with("_HOST")
        || name.ends_with("_DSN")
        || name.ends_with("_ENDPOINT")
        || name == "DATABASE_URL"
        || name == "MONGO_URL"
        || name == "REDIS_URL"
        || name == "SMTP_URL"
        || name == "MYSQL_URL"
        || name == "MSSQL_URL"
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_manifest() -> CapabilityManifest {
        CapabilityManifest {
            image_role: ImageRole::Unknown,
            image_digest: None,
            binaries: Vec::new(),
            python: None,
            node: None,
            rust: RustToolchain {
                rustc: None,
                cargo: None,
            },
            go: GoToolchain { go: None },
            env: BTreeMap::new(),
            filesystem: FilesystemSnapshot {
                workdir: "/workspace/repo".to_owned(),
                workdir_languages_detected: Vec::new(),
                git_initialized: false,
                head_commit: None,
            },
        }
    }

    // ── env redaction ────────────────────────────────────────────

    #[test]
    fn redacts_kernel_private_session_token() {
        assert!(is_kernel_private_env("RAXIS_SESSION_TOKEN"));
    }

    #[test]
    fn redacts_kernel_private_loopback_plan() {
        assert!(is_kernel_private_env("RAXIS_VSOCK_LOOPBACK_PLAN"));
    }

    #[test]
    fn redacts_kernel_private_ksb_and_task_prompt() {
        assert!(is_kernel_private_env("RAXIS_PLANNER_KSB"));
        assert!(is_kernel_private_env("RAXIS_PLANNER_TASK_PROMPT"));
    }

    #[test]
    fn redacts_pattern_secret_token_password() {
        assert!(is_kernel_private_env("STRIPE_API_KEY"));
        assert!(is_kernel_private_env("GITHUB_TOKEN"));
        assert!(is_kernel_private_env("DATABASE_PASSWORD"));
        assert!(is_kernel_private_env("PRIVATE_KEY"));
        assert!(is_kernel_private_env("MY_SECRET_VALUE"));
        assert!(is_kernel_private_env("APIKEY_FOO"));
    }

    #[test]
    fn does_not_redact_credential_proxy_urls() {
        // Credential-proxy mounts use `*_URL` names — these are
        // loopback URLs without secret values; they MUST surface.
        assert!(!is_kernel_private_env("DATABASE_URL"));
        assert!(!is_kernel_private_env("MONGO_URL"));
        assert!(!is_kernel_private_env("REDIS_URL"));
        assert!(!is_kernel_private_env("SMTP_URL"));
        assert!(!is_kernel_private_env("USERS_DATABASE_URL"));
        // Standard Unix vars MUST survive.
        assert!(!is_kernel_private_env("PATH"));
        assert!(!is_kernel_private_env("HOME"));
        assert!(!is_kernel_private_env("LANG"));
    }

    #[test]
    fn probe_env_with_iter_redacts_loopback_plan() {
        let env = probe_env_with_iter([
            ("PATH".to_owned(), "/usr/bin".to_owned()),
            (
                "RAXIS_VSOCK_LOOPBACK_PLAN".to_owned(),
                "<base64-payload>".to_owned(),
            ),
            ("RAXIS_SESSION_TOKEN".to_owned(), "secret-token".to_owned()),
            (
                "DATABASE_URL".to_owned(),
                "postgres://raxis@127.0.0.1:54121/db".to_owned(),
            ),
            ("STRIPE_API_KEY".to_owned(), "sk_live_xxx".to_owned()),
        ]);
        // INV-EXEC-DISCOVERY-01: RAXIS_VSOCK_LOOPBACK_PLAN value
        // MUST NOT appear in the manifest's env section.
        assert!(
            !env.contains_key("RAXIS_VSOCK_LOOPBACK_PLAN"),
            "RAXIS_VSOCK_LOOPBACK_PLAN must be redacted"
        );
        assert!(
            !env.contains_key("RAXIS_SESSION_TOKEN"),
            "RAXIS_SESSION_TOKEN must be redacted"
        );
        assert!(
            !env.contains_key("STRIPE_API_KEY"),
            "STRIPE_API_KEY must be redacted (pattern denylist)"
        );
        // Credential proxy URL must survive.
        assert_eq!(
            env.get("DATABASE_URL").map(String::as_str),
            Some("postgres://raxis@127.0.0.1:54121/db"),
        );
        assert!(env.contains_key("PATH"));
    }

    // ── system-prompt hint ───────────────────────────────────────

    #[test]
    fn capability_hint_includes_python_node_rust_go_versions() {
        let mut m = empty_manifest();
        m.python = Some(PythonRuntime {
            interpreter: "/usr/bin/python3".to_owned(),
            version: "3.11.2".to_owned(),
            site_packages: "/usr/lib/python3.11/dist-packages".to_owned(),
            packages: vec![
                PythonPackage {
                    name: "psycopg2-binary".to_owned(),
                    version: "2.9.10".to_owned(),
                    importable: None,
                },
                PythonPackage {
                    name: "pymongo".to_owned(),
                    version: "4.10.1".to_owned(),
                    importable: None,
                },
                PythonPackage {
                    name: "redis".to_owned(),
                    version: "5.2.1".to_owned(),
                    importable: None,
                },
                PythonPackage {
                    name: "PyMySQL".to_owned(),
                    version: "1.1.1".to_owned(),
                    importable: None,
                },
                PythonPackage {
                    name: "pymssql".to_owned(),
                    version: "2.3.2".to_owned(),
                    importable: None,
                },
            ],
        });
        m.node = Some(NodeRuntime {
            interpreter: "/usr/bin/node".to_owned(),
            version: "20.18.0".to_owned(),
            global_packages: vec![NodePackage {
                name: "npm".to_owned(),
                version: "10.8.0".to_owned(),
            }],
        });
        m.rust.rustc = Some("1.79.0".to_owned());
        m.go.go = Some("go1.22.0 linux/amd64".to_owned());
        m.env.insert(
            "DATABASE_URL".to_owned(),
            "postgres://raxis@127.0.0.1:54121/db".to_owned(),
        );
        m.env.insert(
            "MONGO_URL".to_owned(),
            "mongodb://127.0.0.1:54122/db".to_owned(),
        );
        let hint = build_capability_hint(&m);
        // Languages summary present.
        assert!(hint.contains("Python 3.11.2"), "{hint}");
        assert!(hint.contains("Node 20.18.0"), "{hint}");
        assert!(hint.contains("Rust"), "{hint}");
        assert!(hint.contains("Go"), "{hint}");
        // Curated DB-client subset present.
        assert!(
            hint.contains("psycopg2-binary 2.9.10"),
            "expected psycopg2-binary in hint:\n{hint}"
        );
        assert!(hint.contains("pymongo 4.10.1"));
        assert!(hint.contains("redis 5.2.1"));
        assert!(hint.contains("PyMySQL 1.1.1"));
        assert!(hint.contains("pymssql 2.3.2"));
        // Credential-proxy env names present (without values
        // dumped inline).
        assert!(hint.contains("DATABASE_URL"));
        assert!(hint.contains("MONGO_URL"));
        // The egress warning MUST be present so the LLM doesn't
        // try `pip install`.
        assert!(hint.contains("No outbound network"));
        assert!(hint.contains("pip install"));
    }

    #[test]
    fn capability_hint_redacts_kernel_private_env_in_cred_summary() {
        let mut m = empty_manifest();
        m.env.insert(
            "RAXIS_VSOCK_LOOPBACK_PLAN".to_owned(),
            "<base64-payload>".to_owned(),
        );
        m.env.insert(
            "DATABASE_URL".to_owned(),
            "postgres://raxis@127.0.0.1:54121/db".to_owned(),
        );
        let hint = build_capability_hint(&m);
        // Even though `m.env` carries the kernel-private value
        // (a misuse the build_capability_hint code itself does NOT
        // re-filter), the cred-proxy section MUST select on the
        // looks-like-credential-proxy heuristic which excludes
        // RAXIS_*. The value MUST NOT appear in the rendered hint.
        assert!(
            !hint.contains("<base64-payload>"),
            "RAXIS_VSOCK_LOOPBACK_PLAN value leaked into hint:\n{hint}"
        );
        assert!(
            !hint.contains("RAXIS_VSOCK_LOOPBACK_PLAN"),
            "RAXIS_VSOCK_LOOPBACK_PLAN name leaked into cred summary:\n{hint}"
        );
        // Real credential-proxy var still present.
        assert!(hint.contains("DATABASE_URL"));
    }

    // ── projection ────────────────────────────────────────────────

    #[test]
    fn project_manifest_filters_to_binaries_only() {
        let mut m = empty_manifest();
        m.binaries.push(BinaryEntry {
            name: "git".to_owned(),
            path: "/usr/bin/git".to_owned(),
            version: Some("2.43.0".to_owned()),
        });
        m.binaries.push(BinaryEntry {
            name: "ripgrep".to_owned(),
            path: "/usr/bin/ripgrep".to_owned(),
            version: None,
        });
        m.python = Some(PythonRuntime {
            interpreter: "/usr/bin/python3".to_owned(),
            version: "3.11".to_owned(),
            site_packages: "/x".to_owned(),
            packages: vec![],
        });
        let p = project_manifest(
            &m,
            &[CapabilityCategory::Binaries],
            &CapabilityFilter::default(),
        );
        assert_eq!(p.binaries.len(), 2);
        assert!(
            p.python.is_none(),
            "python section MUST be omitted when not requested"
        );
    }

    #[test]
    fn project_manifest_binary_name_filter_is_substring() {
        let mut m = empty_manifest();
        m.binaries.extend([
            BinaryEntry {
                name: "git".to_owned(),
                path: "/usr/bin/git".to_owned(),
                version: None,
            },
            BinaryEntry {
                name: "gh".to_owned(),
                path: "/usr/bin/gh".to_owned(),
                version: None,
            },
            BinaryEntry {
                name: "node".to_owned(),
                path: "/usr/bin/node".to_owned(),
                version: None,
            },
        ]);
        let p = project_manifest(
            &m,
            &[CapabilityCategory::Binaries],
            &CapabilityFilter {
                binary_name: Some("g".to_owned()),
                ..Default::default()
            },
        );
        let names: BTreeSet<&str> = p.binaries.iter().map(|b| b.name.as_str()).collect();
        assert!(names.contains("git"));
        assert!(names.contains("gh"));
        assert!(!names.contains("node"));
    }

    #[test]
    fn project_manifest_env_var_filter_returns_single_value() {
        let mut m = empty_manifest();
        m.env
            .insert("DATABASE_URL".to_owned(), "postgres://x".to_owned());
        m.env
            .insert("MONGO_URL".to_owned(), "mongodb://y".to_owned());
        let p = project_manifest(
            &m,
            &[CapabilityCategory::Env],
            &CapabilityFilter {
                env_var: Some("DATABASE_URL".to_owned()),
                ..Default::default()
            },
        );
        assert_eq!(p.env.len(), 1);
        assert_eq!(
            p.env.get("DATABASE_URL").map(String::as_str),
            Some("postgres://x")
        );
    }

    #[test]
    fn project_manifest_all_returns_full_manifest() {
        let mut m = empty_manifest();
        m.binaries.push(BinaryEntry {
            name: "bash".to_owned(),
            path: "/bin/bash".to_owned(),
            version: Some("5.2".to_owned()),
        });
        m.env.insert("PATH".to_owned(), "/usr/bin".to_owned());
        let p = project_manifest(&m, &[CapabilityCategory::All], &CapabilityFilter::default());
        assert_eq!(p, m);
    }

    #[test]
    fn project_manifest_empty_categories_means_all() {
        let mut m = empty_manifest();
        m.binaries.push(BinaryEntry {
            name: "bash".to_owned(),
            path: "/bin/bash".to_owned(),
            version: None,
        });
        let p = project_manifest(&m, &[], &CapabilityFilter::default());
        assert_eq!(p.binaries.len(), 1);
    }

    // ── live probe (best-effort, host-dependent) ─────────────────

    /// Smoke: probe against the live process env. CI runs on Linux
    /// with Python+Node, so the manifest should contain at least
    /// `bash` (every supported host has it) and a non-empty PATH-
    /// derived binary table. We do NOT pin specific binaries
    /// because dev workstations vary.
    #[test]
    fn probe_capabilities_live_returns_a_manifest() {
        let cwd = std::env::current_dir().unwrap();
        let m = probe_capabilities(&|k| std::env::var(k).ok(), &cwd);
        // PATH-derived binary table is non-empty on every supported
        // host (CI Linux + dev macOS).
        assert!(
            !m.binaries.is_empty(),
            "binary table empty — PATH probe failed?"
        );
        // Workdir snapshot has a non-empty path.
        assert!(!m.filesystem.workdir.is_empty());
    }

    /// `cached_capabilities` returns the same `Arc` on repeated
    /// calls (per `INV-EXEC-DISCOVERY-01` per-session caching).
    #[test]
    fn cached_capabilities_is_per_process_stable() {
        let a = cached_capabilities();
        let b = cached_capabilities();
        assert!(
            Arc::ptr_eq(&a, &b),
            "cached_capabilities must return the same Arc per process"
        );
    }

    // ── projection edge cases ────────────────────────────────────

    #[test]
    fn project_manifest_python_package_filter_probes_importability_when_absent() {
        let mut m = empty_manifest();
        m.python = Some(PythonRuntime {
            interpreter: "/nonexistent/python3".to_owned(),
            version: "3.11".to_owned(),
            site_packages: "/x".to_owned(),
            packages: vec![],
        });
        // Filter to a package that's not in dist-info → still
        // surfaces the importability probe (which fails because
        // the interpreter path is bogus).
        let p = project_manifest(
            &m,
            &[CapabilityCategory::Python],
            &CapabilityFilter {
                python_package: Some("nonexistent_pkg".to_owned()),
                ..Default::default()
            },
        );
        let py = p.python.unwrap();
        assert_eq!(py.packages.len(), 1);
        assert_eq!(py.packages[0].name, "nonexistent_pkg");
        assert_eq!(py.packages[0].importable, Some(false));
    }
}
