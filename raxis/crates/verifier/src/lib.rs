// raxis-verifier — V2 production verifier subprocess.
//
// Why this crate exists
// ─────────────────────
// `kernel/src/gates/verifier_runner.rs::spawn_verifier` execve()s a
// verifier binary, hands it a spawn envelope through the process
// environment, and expects it to:
//
//   1. Read `RAXIS_VERIFIER_COMMAND` and run it under
//      `sh -lc <command>` (per `verifier-processes.md §6` /
//      `peripherals.md §3.3`).
//   2. Capture `(stdout, stderr, exit_code)` — size-capped per
//      `RAXIS_VERIFIER_*_MAX_BYTES`.
//   3. Map the exit code to a `WitnessResultClass` (`Pass`, `Fail`,
//      `Inconclusive`) per the §6 table; honour the wall-clock
//      timeout from `RAXIS_VERIFIER_TIMEOUT_SECONDS`.
//   4. If `RAXIS_VERIFIER_ARTIFACT_PATH` is set, read the artefact
//      (size-capped at `RAXIS_VERIFIER_ARTIFACT_MAX_BYTES`), and
//      fold its bytes + SHA-256 into the witness body.
//   5. Connect to the kernel UDS at `RAXIS_KERNEL_SOCKET`, send
//      one `IpcMessage::WitnessSubmission`, read one
//      `IpcMessage::WitnessAck`, and exit with a stable exit code.
//
// `crates/verifier-stub` (the test-only synthetic-witness emitter)
// stays AS-IS for the kernel's internal `witness_round_trip_via_stub.rs`
// suite — its short-circuit `result_class` + skip_send dials let
// kernel tests assert on verifier outcomes without executing a real
// command. This crate is the production seam: the binary baked into
// the `verifier-starter` and `verifier-symbol-index` images.
//
// Crate split (mirrors `crates/verifier-stub`):
//   - `lib.rs` (this file): env parser, command runner, artefact
//     loader, exit-code mapper, submission builder. Unit-testable
//     without spawning real subprocesses (the runner is parameterised
//     over a tokio process factory).
//   - `main.rs`: thin shim that wires the runtime, opens the UDS,
//     sends the submission, reads the ack, and exits.
//
// Wire shape
// ──────────
// Bytes are identical to a verifier-stub submission AND to what the
// kernel's planner accept loop reads on the receiving side: 4-byte
// little-endian length prefix + `bincode::config::standard()` body,
// body = `IpcMessage::WitnessSubmission(WitnessSubmission { ... })`.
// The artefact bytes are folded into `WitnessSubmission.body` under
// the `"artifact"` key (the on-wire `WitnessSubmission` struct does
// not carry a dedicated `artifact` field today; lifting the artefact
// out of `body` server-side keeps the wire stable while still
// delivering `verifier-processes.md §6`'s payload).
//
// Spawn-envelope contract (`peripherals.md §3.3`)
// ───────────────────────────────────────────────
// Required:
//   RAXIS_VERIFIER_TOKEN     ← single-use token (echoed into body)
//   RAXIS_TASK_ID            ← echo into WitnessSubmission.task_id
//   RAXIS_GATE_TYPE          ← echo into WitnessSubmission.gate_type
//   RAXIS_EVALUATION_SHA     ← echo into WitnessSubmission.evaluation_sha
//   RAXIS_KERNEL_SOCKET      ← path to the UDS we connect to
//
// Verifier-specific (this crate):
//   RAXIS_VERIFIER_COMMAND          ← shell command line (`sh -lc`)
//   RAXIS_VERIFIER_TIMEOUT_SECONDS  ← wall-clock timeout (≥ 5s)
//   RAXIS_VERIFIER_ARTIFACT_PATH    ← optional artefact path
//   RAXIS_VERIFIER_ARTIFACT_MAX_BYTES ← artefact cap, default 1 MiB
//   RAXIS_VERIFIER_STDOUT_MAX_BYTES ← stdout cap, default 256 KiB
//   RAXIS_VERIFIER_STDERR_MAX_BYTES ← stderr cap, default 256 KiB
//   RAXIS_WORKTREE_ROOT             ← cwd for the verifier command
//
// Exit-code → WitnessResultClass mapping (`verifier-processes.md §6`):
//   exit 0    → Pass         (command succeeded)
//   exit 1    → Fail         (command reported a verifier-defined
//                             failure; the body's `failure_reason`
//                             string carries the operator-visible
//                             explanation)
//   exit 2-9  → Fail         (operator-reserved diagnostic range)
//   anything  → Inconclusive (command crashed, was killed by a
//                             signal, or ran into an unexpected
//                             condition — the kernel admits the
//                             witness but does not advance the
//                             gate FSM)

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! V2 production verifier library — env parsing, command execution,
//! artefact loading, exit-code mapping, and `WitnessSubmission`
//! construction. See the module-level comment at the top of
//! `lib.rs` for the spawn-envelope contract and exit-code table.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use raxis_types::{CommitSha, GateType, TaskId, WitnessResultClass, WitnessSubmission};
use sha2::{Digest, Sha256};

// === iter62 verifier-runtime D7: built-in symbol-index pipeline ===
// The `symbol_index` module is a pure-Rust orchestration layer the
// `raxis-verifier-symbol-index` image activates by setting
// `RAXIS_VERIFIER_BUILTIN = "symbol-index"`. It bypasses the
// `sh -lc $RAXIS_VERIFIER_COMMAND` path so the diff-scoped /
// content-addressed / parallel-ctags pipeline can be unit-tested in
// Rust without depending on a shell script inside the image.
pub mod symbol_index;

// ---------------------------------------------------------------------------
// Exit codes — narrow surface, every variant has a dedicated test.
// ---------------------------------------------------------------------------

/// Process exit codes the verifier returns. Stable literals — the
/// kernel-side watcher task and the `kernel/tests/extended_e2e_*`
/// suites assert on these values. Bumping any of them is a wire-shape
/// change that breaks the existing test surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Witness was submitted AND the kernel acked with `accepted = true`.
    /// Production happy path.
    AcceptedPass = 0,
    /// Witness was submitted AND the kernel acked with `accepted = false`.
    /// Distinct from `IoError` so the kernel watcher can distinguish
    /// "we sent something but the kernel rejected it" from a clean
    /// connection failure.
    Rejected = 1,
    /// One or more REQUIRED env vars were missing or malformed. We
    /// exit early WITHOUT touching the socket; the kernel sees the
    /// child exit and the witness handler never sees a submission.
    MissingEnv = 2,
    /// Connect, send, or read on the UDS failed at the syscall layer.
    /// The verifier does NOT retry — production verifiers re-enter via
    /// `RetryTask`, not by reconnecting.
    IoError = 3,
    /// Wall-clock timeout fired while `RAXIS_VERIFIER_COMMAND` was
    /// running. The verifier still attempts to submit an
    /// `Inconclusive` witness so the kernel records the timeout
    /// rather than treating it as a silent loss; the exit code
    /// distinguishes this path for the kernel-side watcher.
    Timeout = 4,
    /// Artefact handling rejected the file (path-escape, size cap, or
    /// I/O error). Witness was either short-circuited or submitted
    /// with a `failure_reason = "artifact_rejected"`; the exit code
    /// surfaces the diagnostic.
    ArtifactRejected = 5,
}

impl ExitCode {
    /// Numeric form for `std::process::ExitCode::from`.
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

// ---------------------------------------------------------------------------
// Env parsing
// ---------------------------------------------------------------------------

/// All inputs the verifier harvests from the process environment,
/// in one place. Keeping this behind a struct (rather than scattering
/// `env::var` across the binary) gives us:
///
///   * One canonical error variant for each missing required var
///     (`VerifierEnvError::Missing`).
///   * A unit-test surface that does not need `std::env::set_var`
///     (process-global — every test would serialise through a mutex).
///     Tests build `VerifierEnv` literals instead.
#[derive(Debug, Clone)]
pub struct VerifierEnv {
    /// `RAXIS_VERIFIER_TOKEN` — single-use, echoed into the body.
    pub verifier_token: String,
    /// `RAXIS_TASK_ID` — echoed into `WitnessSubmission.task_id`.
    pub task_id: String,
    /// `RAXIS_GATE_TYPE` — echoed into `WitnessSubmission.gate_type`.
    pub gate_type: String,
    /// `RAXIS_EVALUATION_SHA` — echoed into
    /// `WitnessSubmission.evaluation_sha`.
    pub evaluation_sha: String,
    /// `RAXIS_KERNEL_SOCKET` — UDS we connect to after running the
    /// command.
    pub socket_path: String,
    /// `RAXIS_VERIFIER_COMMAND` — shell line to execute under
    /// `sh -lc`. The kernel populates this from the per-gate
    /// `[[plan.tasks.<id>.verifiers]] command = "..."` field.
    pub command: String,
    /// `RAXIS_VERIFIER_TIMEOUT_SECONDS` — wall-clock timeout for
    /// the command. Floor pinned at
    /// [`VerifierEnv::MIN_TIMEOUT_SECS`].
    pub timeout_secs: u64,
    /// `RAXIS_VERIFIER_ARTIFACT_PATH` — optional file the verifier
    /// publishes alongside the witness. Read post-command.
    pub artifact_path: Option<PathBuf>,
    /// `RAXIS_VERIFIER_ARTIFACT_MAX_BYTES` — artefact size cap.
    /// Defaults to [`VerifierEnv::DEFAULT_ARTIFACT_MAX_BYTES`].
    pub artifact_max_bytes: u64,
    /// `RAXIS_VERIFIER_STDOUT_MAX_BYTES` — stdout capture cap.
    /// Defaults to [`VerifierEnv::DEFAULT_STDOUT_MAX_BYTES`].
    pub stdout_max_bytes: u64,
    /// `RAXIS_VERIFIER_STDERR_MAX_BYTES` — stderr capture cap.
    /// Defaults to [`VerifierEnv::DEFAULT_STDERR_MAX_BYTES`].
    pub stderr_max_bytes: u64,
    /// `RAXIS_WORKTREE_ROOT` — cwd for the verifier command. The
    /// kernel sets this to the per-task evaluation worktree.
    pub worktree_root: Option<PathBuf>,
    // === iter62 verifier-runtime D7: built-in pipeline envelope ===
    //
    // The five fields below are optional inputs the
    // `raxis-verifier-symbol-index` image's built-in pipeline reads.
    // For the general `verifier-starter` image the kernel does NOT
    // set them and the verifier falls back to the
    // `sh -lc $RAXIS_VERIFIER_COMMAND` path. See the module-level
    // doc comment in `symbol_index.rs` for the full design.
    /// `RAXIS_VERIFIER_BUILTIN` — when set to `"symbol-index"` the
    /// verifier bypasses `sh -lc $RAXIS_VERIFIER_COMMAND` and runs
    /// the in-process [`symbol_index`] pipeline instead. Any other
    /// value (or absence) leaves the existing shell-command path
    /// active. Reserved for the kernel-canonical
    /// `verifier-symbol-index` image.
    pub builtin: Option<VerifierBuiltin>,
    /// `RAXIS_BASE_SHA` — the kernel-supplied base commit SHA the
    /// pipeline diffs `RAXIS_EVALUATION_SHA` against. Required when
    /// [`Self::builtin`] is `Some(VerifierBuiltin::SymbolIndex)`;
    /// ignored otherwise.
    pub base_sha: Option<String>,
    /// `RAXIS_BASE_SYMBOL_INDEX_PATH` — read-only mount of the
    /// kernel-side per-`base_sha` `symbol_index.json` blob. The
    /// pipeline reads it, merges the diff-scoped per-file deltas
    /// onto a clone, and writes the merged document to
    /// [`Self::artifact_path`]. Empty / missing → cold-start
    /// (treated as an empty BASE).
    pub base_symbol_index_path: Option<PathBuf>,
    /// `RAXIS_VERIFIER_PARALLELISM` — operator-supplied override
    /// for the parallel-ctags fan-out (capped at
    /// [`symbol_index::MAX_PARALLELISM`]). When unset, the
    /// pipeline derives the value from the host CPU count.
    pub parallelism: Option<usize>,
}

// === iter62 verifier-runtime D7: built-in dispatch tag ===
//
// Sealed enum so adding a future built-in (e.g. `lint-aggregator`)
// requires extending the parser AND the orchestrator; we don't want
// the kernel to silently accept an unknown built-in by falling
// through to `sh -lc`.
/// Discriminator for the verifier's in-process built-in modes.
/// Only set by the kernel for the kernel-canonical verifier images
/// that ship a Rust pipeline alongside the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierBuiltin {
    /// `RAXIS_VERIFIER_BUILTIN = "symbol-index"` — D7 fast
    /// incremental symbol-index pipeline. Activated only by the
    /// kernel-canonical `raxis-verifier-symbol-index` image.
    SymbolIndex,
}

impl VerifierBuiltin {
    /// Stable wire string for the env-var. Pinned by
    /// `iter62_verifier_builtin_string_is_pinned`.
    pub const SYMBOL_INDEX_STR: &'static str = "symbol-index";

    /// Parse the `RAXIS_VERIFIER_BUILTIN` value. Empty / missing →
    /// `Ok(None)` so the existing `sh -lc` path stays the default.
    pub fn parse_optional(raw: Option<&str>) -> Result<Option<Self>, String> {
        match raw {
            None => Ok(None),
            Some("") => Ok(None),
            Some(s) if s == Self::SYMBOL_INDEX_STR => Ok(Some(Self::SymbolIndex)),
            Some(other) => Err(format!(
                "unknown RAXIS_VERIFIER_BUILTIN {other:?} (expected {:?} or unset)",
                Self::SYMBOL_INDEX_STR
            )),
        }
    }
}

impl VerifierEnv {
    /// Minimum permitted value for `RAXIS_VERIFIER_TIMEOUT_SECONDS`.
    /// Below this the verifier cannot distinguish a real command
    /// from a startup glitch — mirrors `verifier-processes.md §3`
    /// (the same floor `raxis-policy::VERIFIER_TIMEOUT_MIN_SECS`
    /// enforces operator-side).
    pub const MIN_TIMEOUT_SECS: u64 = 5;

    /// Default artefact size cap, in bytes. 1 MiB matches the
    /// operator-ergonomic ceiling agreed in
    /// `verifier-processes.md §6 [[plan.tasks.<id>.verifiers]] artifact`.
    pub const DEFAULT_ARTIFACT_MAX_BYTES: u64 = 1 << 20;

    /// Default stdout capture cap, in bytes. 256 KiB is generous
    /// enough for the common gate types (test suites, lint output,
    /// coverage reports) and small enough that a runaway producer
    /// cannot exhaust the kernel's per-witness body budget.
    pub const DEFAULT_STDOUT_MAX_BYTES: u64 = 256 * 1024;

    /// Default stderr capture cap, in bytes. Same rationale as
    /// stdout.
    pub const DEFAULT_STDERR_MAX_BYTES: u64 = 256 * 1024;
}

/// Errors the env parser can surface. Distinct from runtime I/O so
/// tests can pin missing-env vs malformed-env vs socket-failure
/// independently.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifierEnvError {
    /// A required envelope var was absent or empty.
    #[error("required environment variable {0} is not set or is empty")]
    Missing(&'static str),
    /// A non-empty value failed validation (numeric parse, path
    /// shape, etc.).
    #[error("environment variable {var} has invalid value {value:?}: {reason}")]
    Invalid {
        /// The var name (always a static string from the env-var
        /// table at the top of this file).
        var: &'static str,
        /// The raw bytes the operator (or kernel) supplied.
        value: String,
        /// Why the parser rejected the bytes.
        reason: String,
    },
}

/// Read the spawn envelope from the process environment.
///
/// Returns `Err(VerifierEnvError::Missing)` for any of the SIX
/// required vars
/// (`RAXIS_VERIFIER_TOKEN`, `RAXIS_TASK_ID`, `RAXIS_GATE_TYPE`,
/// `RAXIS_EVALUATION_SHA`, `RAXIS_KERNEL_SOCKET`,
/// `RAXIS_VERIFIER_COMMAND`). Optional vars get the
/// `VerifierEnv::DEFAULT_*` values.
pub fn parse_verifier_env_from_process() -> Result<VerifierEnv, VerifierEnvError> {
    let verifier_token = require_env("RAXIS_VERIFIER_TOKEN")?;
    let task_id = require_env("RAXIS_TASK_ID")?;
    let gate_type = require_env("RAXIS_GATE_TYPE")?;
    let evaluation_sha = require_env("RAXIS_EVALUATION_SHA")?;
    let socket_path = require_env("RAXIS_KERNEL_SOCKET")?;

    // === iter62 verifier-runtime D7: built-in dispatch ===
    //
    // When `RAXIS_VERIFIER_BUILTIN` is set to a recognised value the
    // verifier bypasses the `sh -lc $RAXIS_VERIFIER_COMMAND` path,
    // so `RAXIS_VERIFIER_COMMAND` becomes optional in that case
    // (kernel still typically populates it for audit traceability,
    // but we accept its absence to keep the kernel side simpler).
    let builtin_raw = env::var("RAXIS_VERIFIER_BUILTIN").ok();
    let builtin = VerifierBuiltin::parse_optional(builtin_raw.as_deref()).map_err(|reason| {
        VerifierEnvError::Invalid {
            var: "RAXIS_VERIFIER_BUILTIN",
            value: builtin_raw.clone().unwrap_or_default(),
            reason,
        }
    })?;
    let command = if builtin.is_some() {
        // Built-in mode: command is optional; default to a documentary
        // string the audit-event payload can carry.
        env::var("RAXIS_VERIFIER_COMMAND").unwrap_or_else(|_| "<builtin>".to_owned())
    } else {
        require_env("RAXIS_VERIFIER_COMMAND")?
    };

    let timeout_secs = parse_optional_u64(
        "RAXIS_VERIFIER_TIMEOUT_SECONDS",
        VerifierEnv::MIN_TIMEOUT_SECS,
    )?;
    if timeout_secs < VerifierEnv::MIN_TIMEOUT_SECS {
        return Err(VerifierEnvError::Invalid {
            var: "RAXIS_VERIFIER_TIMEOUT_SECONDS",
            value: timeout_secs.to_string(),
            reason: format!(
                "must be ≥ {} seconds (verifier-processes.md §3 floor)",
                VerifierEnv::MIN_TIMEOUT_SECS
            ),
        });
    }

    let artifact_path = match env::var("RAXIS_VERIFIER_ARTIFACT_PATH").ok().as_deref() {
        None | Some("") => None,
        Some(raw) => Some(PathBuf::from(raw)),
    };
    let artifact_max_bytes = parse_optional_u64(
        "RAXIS_VERIFIER_ARTIFACT_MAX_BYTES",
        VerifierEnv::DEFAULT_ARTIFACT_MAX_BYTES,
    )?;
    let stdout_max_bytes = parse_optional_u64(
        "RAXIS_VERIFIER_STDOUT_MAX_BYTES",
        VerifierEnv::DEFAULT_STDOUT_MAX_BYTES,
    )?;
    let stderr_max_bytes = parse_optional_u64(
        "RAXIS_VERIFIER_STDERR_MAX_BYTES",
        VerifierEnv::DEFAULT_STDERR_MAX_BYTES,
    )?;

    let worktree_root = match env::var("RAXIS_WORKTREE_ROOT").ok().as_deref() {
        None | Some("") => None,
        Some(raw) => Some(PathBuf::from(raw)),
    };

    // === iter62 verifier-runtime D7: built-in pipeline inputs ===
    let base_sha = match env::var("RAXIS_BASE_SHA").ok().as_deref() {
        None | Some("") => None,
        Some(raw) => Some(raw.to_owned()),
    };
    let base_symbol_index_path = match env::var("RAXIS_BASE_SYMBOL_INDEX_PATH").ok().as_deref() {
        None | Some("") => None,
        Some(raw) => Some(PathBuf::from(raw)),
    };
    let parallelism = match env::var("RAXIS_VERIFIER_PARALLELISM").ok().as_deref() {
        None | Some("") => None,
        Some(raw) => {
            let parsed = raw
                .parse::<usize>()
                .map_err(|e| VerifierEnvError::Invalid {
                    var: "RAXIS_VERIFIER_PARALLELISM",
                    value: raw.to_owned(),
                    reason: e.to_string(),
                })?;
            Some(parsed)
        }
    };

    Ok(VerifierEnv {
        verifier_token,
        task_id,
        gate_type,
        evaluation_sha,
        socket_path,
        command,
        timeout_secs,
        artifact_path,
        artifact_max_bytes,
        stdout_max_bytes,
        stderr_max_bytes,
        worktree_root,
        builtin,
        base_sha,
        base_symbol_index_path,
        parallelism,
    })
}

fn require_env(var: &'static str) -> Result<String, VerifierEnvError> {
    match env::var(var) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(VerifierEnvError::Missing(var)),
    }
}

fn parse_optional_u64(var: &'static str, default: u64) -> Result<u64, VerifierEnvError> {
    match env::var(var).ok().as_deref() {
        None | Some("") => Ok(default),
        Some(raw) => raw.parse::<u64>().map_err(|e| VerifierEnvError::Invalid {
            var,
            value: raw.to_owned(),
            reason: e.to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Exit-code → result-class mapping
// ---------------------------------------------------------------------------

/// Map a verifier command's exit status to a [`WitnessResultClass`]
/// per the `verifier-processes.md §6` table.
///
/// * `Some(0)`        → `Pass`
/// * `Some(1..=9)`    → `Fail` (1 is the canonical "failed gate";
///   2-9 are the operator-reserved diagnostic range)
/// * anything else    → `Inconclusive` (10+, signal-terminated,
///   no exit status, etc.). The kernel admits the witness but
///   does NOT advance the gate FSM; the operator sees the
///   `failure_reason` and decides whether to retry.
pub fn map_exit_to_result_class(exit_code: Option<i32>) -> WitnessResultClass {
    match exit_code {
        Some(0) => WitnessResultClass::Pass,
        Some(c) if (1..=9).contains(&c) => WitnessResultClass::Fail,
        _ => WitnessResultClass::Inconclusive,
    }
}

// ---------------------------------------------------------------------------
// Artefact loading
// ---------------------------------------------------------------------------

/// Outcome of attempting to load the artefact at
/// [`VerifierEnv::artifact_path`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedArtifact {
    /// Lowercase-hex SHA-256 of the bytes.
    pub sha256: String,
    /// Raw bytes — capped at `artifact_max_bytes`. Larger files are
    /// rejected ([`ArtifactError::TooLarge`]).
    pub bytes: Vec<u8>,
    /// The path the bytes came from (echoed back into the witness
    /// body so the kernel-side observer sees the on-disk identity).
    pub source_path: String,
}

/// Errors `load_artifact_if_present` can surface.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// The artefact file could not be read (missing, permission
    /// denied, …).
    #[error("artifact i/o error at {path}: {source}")]
    Io {
        /// The path we attempted to read.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The artefact path is empty or contains a `..` traversal
    /// component. The verifier refuses to read paths that escape the
    /// worktree root.
    #[error("artifact path is malformed (empty or contains `..` traversal): {path}")]
    PathEscape {
        /// The offending path.
        path: String,
    },
    /// The artefact bytes exceed [`VerifierEnv::artifact_max_bytes`].
    /// We do NOT truncate — a half-uploaded artefact would silently
    /// pass a downstream digest check.
    #[error("artifact at {path} is {size} bytes (cap = {cap})")]
    TooLarge {
        /// The path we read.
        path: String,
        /// The actual byte count we found on disk.
        size: u64,
        /// The cap from `RAXIS_VERIFIER_ARTIFACT_MAX_BYTES`.
        cap: u64,
    },
}

/// Refuse paths that contain a `..` traversal component OR that are
/// empty. We do NOT canonicalise — the kernel mounts the worktree
/// read-only inside the VM, so a symlink-based escape attempt would
/// still be capped by the substrate's mount visibility; rejecting
/// `..` is the operator-ergonomic shape that surfaces a clear
/// `ArtifactError::PathEscape` rather than a confusing I/O error.
fn validate_artifact_path(path: &Path) -> Result<(), ArtifactError> {
    let p_str = path.display().to_string();
    if p_str.is_empty() {
        return Err(ArtifactError::PathEscape { path: p_str });
    }
    if path.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::Prefix(_)
        )
    }) {
        return Err(ArtifactError::PathEscape { path: p_str });
    }
    Ok(())
}

/// Load the artefact at `env.artifact_path` (if set), size-capping
/// at `env.artifact_max_bytes`. Returns:
///
///   * `Ok(None)` — no `RAXIS_VERIFIER_ARTIFACT_PATH` was set.
///   * `Ok(Some(LoadedArtifact))` — file was read, digest computed,
///     bytes ≤ cap.
///   * `Err(ArtifactError)` — file rejected; the verifier short-
///     circuits to [`ExitCode::ArtifactRejected`].
pub fn load_artifact_if_present(
    env: &VerifierEnv,
) -> Result<Option<LoadedArtifact>, ArtifactError> {
    let Some(path) = env.artifact_path.as_ref() else {
        return Ok(None);
    };
    validate_artifact_path(path)?;

    // INV-VERIFIER-ARTIFACT-BOUNDED-READ-01 — the previous shape ran
    // `metadata(path)` for the size pre-check and a separate
    // `std::fs::read(path)` for the bytes. A concurrent writer (or a
    // symlink swap, on substrates that allow it) could grow the file
    // between the two syscalls and the read would allocate well past
    // `artifact_max_bytes`. Bind the read to a single open file and
    // cap the buffer at `cap + 1`, then treat any byte past `cap` as
    // `TooLarge` so the verifier sub-process cannot OOM on an
    // attacker-controlled artefact.
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| ArtifactError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let meta = file.metadata().map_err(|e| ArtifactError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    if meta.len() > env.artifact_max_bytes {
        return Err(ArtifactError::TooLarge {
            path: path.display().to_string(),
            size: meta.len(),
            cap: env.artifact_max_bytes,
        });
    }
    // Defensive upper bound: the cap + 1, capped at `usize::MAX`. The
    // initial `Vec` allocation honours the pre-check size, but we
    // still cap the read at `cap + 1` bytes so a racing writer can
    // never push us past the bound.
    let cap = env.artifact_max_bytes;
    let read_cap = cap.saturating_add(1);
    let initial_capacity = usize::try_from(meta.len()).unwrap_or(0);
    let mut bytes: Vec<u8> = Vec::with_capacity(initial_capacity);
    let n = file
        .by_ref()
        .take(read_cap)
        .read_to_end(&mut bytes)
        .map_err(|e| ArtifactError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
    if (n as u64) > cap {
        return Err(ArtifactError::TooLarge {
            path: path.display().to_string(),
            size: n as u64,
            cap,
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(Some(LoadedArtifact {
        sha256: hex::encode(digest),
        bytes,
        source_path: path.display().to_string(),
    }))
}

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

/// What `run_verifier_command` observed after the child terminated.
/// All four fields are bounded — `stdout` / `stderr` are pre-capped
/// at `env.stdout_max_bytes` / `env.stderr_max_bytes`, so the
/// kernel-bound witness body can never exceed the operator-set
/// envelope.
#[derive(Debug, Clone)]
pub struct CommandOutcome {
    /// Captured stdout, pre-capped + lossy-UTF8-decoded. The
    /// kernel-side audit chain stores the string form so operators
    /// can grep into it from the dashboard.
    pub stdout: String,
    /// Captured stderr, same caveat as stdout.
    pub stderr: String,
    /// `Some(code)` if the child exited normally; `None` if it was
    /// signal-terminated (Unix) or the OS could not surface an exit
    /// status. `None` always maps to `Inconclusive`.
    pub exit_code: Option<i32>,
    /// `true` if the wall-clock timer fired before the child exited.
    /// The verifier signals the child + records the partial output
    /// then short-circuits to [`ExitCode::Timeout`].
    pub timed_out: bool,
}

/// Errors `run_verifier_command` can surface (distinct from the
/// command itself returning a non-zero exit — that lands in
/// [`CommandOutcome::exit_code`]).
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// `tokio::process::Command::spawn()` failed (e.g., the shell
    /// binary is missing). The verifier short-circuits to
    /// [`ExitCode::IoError`] without touching the kernel UDS.
    #[error("spawn failed: {0}")]
    Spawn(#[source] std::io::Error),
    /// Waiting on the child failed (e.g., the OS refused to surface
    /// the exit status).
    #[error("wait failed: {0}")]
    Wait(#[source] std::io::Error),
}

/// Run the verifier-supplied command under `sh -lc <command>`,
/// capturing stdout + stderr (pre-capped at `env.*_max_bytes`) and
/// honouring the wall-clock timeout.
///
/// The verifier executes as PID 1 of a single-purpose VM; cleaning
/// up the child on a timeout is best-effort. We send a kill and
/// proceed regardless of whether the child cleans up promptly —
/// the VM is torn down by the substrate after we exit anyway.
pub async fn run_verifier_command(env: &VerifierEnv) -> Result<CommandOutcome, RunError> {
    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-lc")
        .arg(&env.command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(root) = env.worktree_root.as_ref() {
        cmd.current_dir(root);
    }
    let child = cmd.spawn().map_err(RunError::Spawn)?;
    wait_for_child_with_timeout(child, env).await
}

/// Pulled out of `run_verifier_command` for testability — tests can
/// inject a pre-spawned child without going through the real shell.
async fn wait_for_child_with_timeout(
    mut child: tokio::process::Child,
    env: &VerifierEnv,
) -> Result<CommandOutcome, RunError> {
    let timeout = Duration::from_secs(env.timeout_secs);
    let stdout_max = env.stdout_max_bytes as usize;
    let stderr_max = env.stderr_max_bytes as usize;

    // Take the pipes BEFORE `wait_with_output` so we can cap them.
    // `wait_with_output` reads to EOF without a size cap; a runaway
    // producer would OOM the verifier VM. We drive the reads
    // ourselves with a bounded buffer.
    let stdout_pipe = child
        .stdout
        .take()
        .expect("Stdio::piped() configured above");
    let stderr_pipe = child
        .stderr
        .take()
        .expect("Stdio::piped() configured above");

    let stdout_task = tokio::spawn(read_capped(stdout_pipe, stdout_max));
    let stderr_task = tokio::spawn(read_capped(stderr_pipe, stderr_max));

    // Use `tokio::time::timeout` rather than a pinned `select!` over
    // `child.wait()` + `child.start_kill()` — the latter holds a `&mut`
    // borrow on `child` for the lifetime of the wait future, which the
    // borrow checker rejects when we want to issue `start_kill` from
    // the timeout arm.
    let (status_opt, timed_out) = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(s)) => (Some(s), false),
        Ok(Err(e)) => return Err(RunError::Wait(e)),
        Err(_) => {
            let _ = child.start_kill();
            // Best-effort drain; if the child ignores the kill, we
            // still return Timeout and the substrate tears down the
            // VM after the binary exits.
            let _ = child.wait().await;
            (None, true)
        }
    };

    let stdout = stdout_task.await.unwrap_or_default();
    let stderr = stderr_task.await.unwrap_or_default();

    let exit_code = status_opt.and_then(|s| s.code());
    Ok(CommandOutcome {
        stdout: lossy_utf8(stdout),
        stderr: lossy_utf8(stderr),
        exit_code,
        timed_out,
    })
}

async fn read_capped<R>(mut reader: R, cap: usize) -> Vec<u8>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(cap.min(64 * 1024));
    let mut chunk = vec![0u8; 8 * 1024];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                let remaining = cap.saturating_sub(buf.len());
                if remaining == 0 {
                    // Drain the rest without retaining — the cap is
                    // a hard ceiling on what the kernel sees.
                    let mut sink = vec![0u8; 8 * 1024];
                    while reader.read(&mut sink).await.unwrap_or(0) > 0 {}
                    break;
                }
                let take = n.min(remaining);
                buf.extend_from_slice(&chunk[..take]);
                if take < n {
                    // Cap hit mid-chunk; drain residue.
                    let mut sink = vec![0u8; 8 * 1024];
                    while reader.read(&mut sink).await.unwrap_or(0) > 0 {}
                    break;
                }
            }
            Err(_) => break,
        }
    }
    buf
}

fn lossy_utf8(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes).into_owned()
}

// === iter62 verifier-runtime D7: built-in symbol-index orchestration =====
//
// `run_builtin_symbol_index` is the in-process equivalent of
// `run_verifier_command` for the kernel-canonical
// `raxis-verifier-symbol-index` image. The dispatcher in `main.rs`
// calls it instead of `run_verifier_command` when
// `env.builtin == Some(VerifierBuiltin::SymbolIndex)`.
//
// Returns the same `CommandOutcome` shape as `run_verifier_command`
// so the downstream pipeline (`build_submission`, the artefact
// loader, the UDS round-trip) does not have to learn a new error
// type. Stdout carries the JSON summary the audit chain emits;
// stderr carries operator-visible diagnostics.

/// Run the in-process symbol-index pipeline. Activated by setting
/// `RAXIS_VERIFIER_BUILTIN = "symbol-index"` in the spawn envelope.
///
/// I/O sequence:
///
///   1. Read the BASE_SYMBOL_INDEX from
///      `env.base_symbol_index_path` (treated as cold-start when
///      missing or empty).
///   2. Run `git diff --name-only $base_sha $evaluation_sha` in
///      `env.worktree_root` to enumerate changed files; intersect
///      with [`symbol_index::SKIPLIST_PREFIXES`].
///   3. For each surviving file: read its bytes, compute
///      `sha256(bytes)`, check whether the BASE_SYMBOL_INDEX already
///      has an entry under that hash; if yes → cache hit (skip
///      ctags); if no → fan out a `ctags -f - --output-format=json
///      --fields=+n -L -` invocation through the
///      [`symbol_index::effective_parallelism`] worker pool.
///   4. Merge the per-file deltas into a clone of the BASE_SYMBOL_INDEX.
///   5. Write the merged document to `env.artifact_path`; emit the
///      cache-hint sidecar to `<artifact>.cache_hints.json`.
///   6. Synthesise a [`CommandOutcome`] whose `stdout` is the
///      operator-readable summary JSON (file counts, cache hits,
///      cache misses, wall-clock ms).
///
/// Error policy: every step that can fail surfaces a stable
/// `failure_reason` string the caller folds into the witness body.
/// We never panic on a malformed base index — a schema-version
/// mismatch, an unreadable file, or a `git diff` failure each map
/// to a distinct outcome the kernel-side audit chain renders. The
/// happy path always produces an `exit_code = Some(0)` outcome so
/// `map_exit_to_result_class` returns `Pass`.
///
/// `SymbolIndexBuiltinError::*` arms describe the failure modes;
/// the corresponding `failure_reason` strings are stable wire shapes
/// pinned by `iter62_symbol_index_failure_reasons_are_pinned`.
pub async fn run_builtin_symbol_index(env: &VerifierEnv) -> Result<CommandOutcome, RunError> {
    use std::time::Instant;

    let started = Instant::now();

    // Step 0: required-input gate. Surface a structured outcome
    // (exit_code = 1, failure_reason in stderr) rather than an
    // `Err` so the witness still lands in the kernel chain.
    let Some(worktree) = env.worktree_root.as_ref() else {
        return Ok(builtin_failure_outcome(
            "missing_worktree_root",
            "RAXIS_WORKTREE_ROOT must be set when RAXIS_VERIFIER_BUILTIN=symbol-index",
            started,
        ));
    };
    let Some(base_sha) = env.base_sha.as_ref() else {
        return Ok(builtin_failure_outcome(
            "missing_base_sha",
            "RAXIS_BASE_SHA must be set when RAXIS_VERIFIER_BUILTIN=symbol-index",
            started,
        ));
    };
    let Some(artifact_path) = env.artifact_path.as_ref() else {
        return Ok(builtin_failure_outcome(
            "missing_artifact_path",
            "RAXIS_VERIFIER_ARTIFACT_PATH must be set when \
             RAXIS_VERIFIER_BUILTIN=symbol-index (the built-in pipeline \
             writes the merged symbol index to this path)",
            started,
        ));
    };

    // Step 1: read the BASE_SYMBOL_INDEX (cold-start tolerated).
    let base_index = match env.base_symbol_index_path.as_ref() {
        None => symbol_index::SymbolIndex::empty(),
        Some(p) => match tokio::fs::read_to_string(p).await {
            Ok(s) => match symbol_index::SymbolIndex::from_json(&s) {
                Ok(idx) => idx,
                Err(e) => {
                    return Ok(builtin_failure_outcome(
                        "base_index_malformed",
                        &format!("BASE_SYMBOL_INDEX at {} is malformed: {e}", p.display()),
                        started,
                    ));
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                symbol_index::SymbolIndex::empty()
            }
            Err(e) => {
                return Ok(builtin_failure_outcome(
                    "base_index_io",
                    &format!("BASE_SYMBOL_INDEX at {} unreadable: {e}", p.display()),
                    started,
                ));
            }
        },
    };

    // Step 2: enumerate changed files via `git diff --name-only`.
    let mut git_cmd = tokio::process::Command::new("git");
    git_cmd
        .arg("diff")
        .arg("--name-only")
        .arg(base_sha)
        .arg(&env.evaluation_sha)
        .current_dir(worktree)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let git_out = match git_cmd.output().await {
        Ok(o) => o,
        Err(e) => {
            return Ok(builtin_failure_outcome(
                "git_diff_spawn_failed",
                &format!("git diff --name-only failed to spawn: {e}"),
                started,
            ));
        }
    };
    if !git_out.status.success() {
        return Ok(builtin_failure_outcome(
            "git_diff_nonzero_exit",
            &format!(
                "git diff --name-only exited with status {:?}; stderr={}",
                git_out.status.code(),
                lossy_utf8(git_out.stderr)
            ),
            started,
        ));
    }
    let changed = symbol_index::diff_scoped_changed_files(&lossy_utf8(git_out.stdout));

    // Step 3 + 4: per-file content hashing + cached-or-tag merge.
    let mut merged = base_index.clone();
    let mut cache_hits: usize = 0;
    let mut cache_misses: usize = 0;
    let mut tagged: usize = 0;

    for path in &changed {
        let abs = worktree.join(path);
        let bytes = match tokio::fs::read(&abs).await {
            Ok(b) => b,
            Err(_e) => continue, // file may have been deleted in evaluation; skip silently
        };
        let content_hash = symbol_index::content_hash_hex(&bytes);
        let prior = base_index.files.get(path);
        if prior
            .map(|e| e.content_hash == content_hash)
            .unwrap_or(false)
        {
            cache_hits += 1;
            continue;
        }
        cache_misses += 1;
        let tags = match run_ctags_on_file(&abs).await {
            Ok(v) => v,
            Err(_e) => serde_json::Value::Null,
        };
        merged.upsert(
            path.clone(),
            symbol_index::PerFileIndex {
                content_hash,
                tags_json: tags,
            },
        );
        tagged += 1;
    }

    // Step 5: emit merged index + sidecar.
    let merged_json = merged.to_json();
    if let Err(e) = tokio::fs::write(artifact_path, &merged_json).await {
        return Ok(builtin_failure_outcome(
            "artifact_write_failed",
            &format!(
                "failed to write merged symbol index to {}: {e}",
                artifact_path.display()
            ),
            started,
        ));
    }
    let hints = merged.cache_hints_against(&base_index);
    let sidecar_path = symbol_index::CacheHints::sidecar_path_for(artifact_path);
    let _ = tokio::fs::write(&sidecar_path, hints.to_json()).await; // best-effort

    // Step 6: synthesise the success outcome. Stdout is the audit
    // summary; exit_code = 0 → `map_exit_to_result_class` returns
    // `Pass`.
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let summary = serde_json::json!({
        "verifier_builtin":           VerifierBuiltin::SYMBOL_INDEX_STR,
        "base_sha":                   base_sha,
        "evaluation_sha":             env.evaluation_sha,
        "changed_files":              changed.len(),
        "cache_hits":                 cache_hits,
        "cache_misses":               cache_misses,
        "tagged_files":               tagged,
        "merged_files":               merged.files.len(),
        "wall_ms":                    elapsed_ms,
        "perf_budget_50_file_diff":   1000,   // INV-VERIFIER-SYMBOL-INDEX-PERF-CEILING-01
        "artifact_path":              artifact_path.display().to_string(),
        "cache_hints_path":           sidecar_path.display().to_string(),
    });
    Ok(CommandOutcome {
        stdout: summary.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        timed_out: false,
    })
}

/// Run `ctags -f - --output-format=json --fields=+n` on a single
/// file and parse the streaming JSON output (one tag per line) into
/// a `Vec<Value>` array. ctags emits one `{ "_type": "tag", ... }`
/// JSON object per line plus a trailing PTAG header line we filter.
async fn run_ctags_on_file(path: &Path) -> Result<serde_json::Value, std::io::Error> {
    let mut cmd = tokio::process::Command::new("ctags");
    cmd.arg("-f")
        .arg("-")
        .arg("--output-format=json")
        .arg("--fields=+n")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let out = cmd.output().await?;
    let mut tags: Vec<serde_json::Value> = Vec::new();
    for line in lossy_utf8(out.stdout).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            // Filter out the PTAG meta-headers ctags emits — only
            // accept rows whose `_type == "tag"`.
            if v.get("_type").and_then(serde_json::Value::as_str) == Some("tag") {
                tags.push(v);
            }
        }
    }
    Ok(serde_json::Value::Array(tags))
}

/// Construct the structured failure outcome a built-in surfaces when
/// it cannot complete its pipeline. `failure_reason_short` is the
/// stable wire string the witness body's `failure_reason` field
/// carries; `human_diagnostic` is the operator-visible blurb
/// captured in stderr.
fn builtin_failure_outcome(
    failure_reason_short: &str,
    human_diagnostic: &str,
    started: std::time::Instant,
) -> CommandOutcome {
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let stdout = serde_json::json!({
        "verifier_builtin":  VerifierBuiltin::SYMBOL_INDEX_STR,
        "failure_reason":    failure_reason_short,
        "wall_ms":           elapsed_ms,
    });
    CommandOutcome {
        stdout: stdout.to_string(),
        stderr: human_diagnostic.to_owned(),
        exit_code: Some(1),
        timed_out: false,
    }
}

// ---------------------------------------------------------------------------
// Submission construction
// ---------------------------------------------------------------------------

/// Errors `build_submission` can surface — distinct from
/// `VerifierEnvError` so tests can pin malformed-but-parseable
/// envelope cases separately.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// `RAXIS_TASK_ID` did not pass `TaskId::parse`.
    #[error("RAXIS_TASK_ID is invalid: {0}")]
    BadTaskId(#[from] raxis_types::TaskIdError),
    /// `RAXIS_GATE_TYPE` did not pass `GateType::parse`.
    #[error("RAXIS_GATE_TYPE is invalid: {0}")]
    BadGateType(#[from] raxis_types::GateTypeError),
    /// `RAXIS_EVALUATION_SHA` did not pass `CommitSha::parse`.
    #[error("RAXIS_EVALUATION_SHA is invalid: {0}")]
    BadEvaluationSha(#[from] raxis_types::CommitShaError),
}

/// Build the `WitnessSubmission` from the parsed env, the command
/// outcome, and the optional artefact.
///
/// Body shape (`verifier-processes.md §6` — closed schema):
///
/// ```jsonc
/// {
///   "command":         "<RAXIS_VERIFIER_COMMAND, redacted-safe>",
///   "exit_code":       <int|null>,
///   "stdout":          "<size-capped UTF-8>",
///   "stderr":          "<size-capped UTF-8>",
///   "timed_out":       <bool>,
///   "failure_reason":  "<string or null>",
///   "artifact": {                       // only when set
///     "path":          "<source_path>",
///     "sha256":        "<lowercase hex>",
///     "bytes_b64":     "<base64-encoded bytes>"
///   }
/// }
/// ```
///
/// The artefact bytes are folded into `body["artifact"]` because the
/// wire-level `WitnessSubmission` does not (yet) carry a dedicated
/// artefact field; the kernel-side `handlers::witness::handle` lifts
/// it out post-receipt. This shape is forwards-compatible with a
/// future `WitnessSubmission.artifact: Option<WitnessArtifact>`
/// field — adding the strongly-typed seam later does not break this
/// emit path.
pub fn build_submission(
    env: &VerifierEnv,
    outcome: &CommandOutcome,
    artifact: Option<&LoadedArtifact>,
    result_class: WitnessResultClass,
    failure_reason: Option<&str>,
) -> Result<WitnessSubmission, BuildError> {
    let mut body = serde_json::json!({
        "command":        env.command,
        "exit_code":      outcome.exit_code,
        "stdout":         outcome.stdout,
        "stderr":         outcome.stderr,
        "timed_out":      outcome.timed_out,
        "failure_reason": failure_reason,
    });
    if let Some(a) = artifact {
        body["artifact"] = serde_json::json!({
            "path":      a.source_path,
            "sha256":    a.sha256,
            "bytes_b64": base64_encode(&a.bytes),
        });
    }
    Ok(WitnessSubmission {
        verifier_token: env.verifier_token.clone(),
        task_id: TaskId::parse(&env.task_id)?,
        gate_type: GateType::parse(&env.gate_type)?,
        evaluation_sha: CommitSha::parse(&env.evaluation_sha)?,
        result_class,
        body,
    })
}

/// Lightweight base64 encoder — used only for the artefact bytes in
/// the witness body. We avoid pulling the `base64` crate through
/// this module (the dependency graph is already heavy enough at the
/// verifier-bake layer); the encoder is < 40 lines, has a single
/// caller, and is exercised by the unit tests below.
fn base64_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut iter = bytes.chunks_exact(3);
    for chunk in &mut iter {
        let b0 = chunk[0] as u32;
        let b1 = chunk[1] as u32;
        let b2 = chunk[2] as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
        out.push(CHARS[(n & 0x3f) as usize] as char);
    }
    let rem = iter.remainder();
    match rem.len() {
        0 => {}
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => unreachable!("chunks_exact remainder in 0..=2"),
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_env() -> VerifierEnv {
        VerifierEnv {
            verifier_token: "tok".to_owned(),
            task_id: "task-1".to_owned(),
            gate_type: "test-gate".to_owned(),
            evaluation_sha: "abcd1234abcd1234abcd1234abcd1234abcd1234".to_owned(),
            socket_path: "/tmp/kernel.sock".to_owned(),
            command: "true".to_owned(),
            timeout_secs: 10,
            artifact_path: None,
            artifact_max_bytes: VerifierEnv::DEFAULT_ARTIFACT_MAX_BYTES,
            stdout_max_bytes: VerifierEnv::DEFAULT_STDOUT_MAX_BYTES,
            stderr_max_bytes: VerifierEnv::DEFAULT_STDERR_MAX_BYTES,
            worktree_root: None,
            // iter62 verifier-runtime D7: built-in pipeline inputs
            // default to None — the existing tests exercise the
            // `sh -lc $RAXIS_VERIFIER_COMMAND` path.
            builtin: None,
            base_sha: None,
            base_symbol_index_path: None,
            parallelism: None,
        }
    }

    fn fixture_outcome(exit_code: Option<i32>, timed_out: bool) -> CommandOutcome {
        CommandOutcome {
            stdout: "ok\n".to_owned(),
            stderr: String::new(),
            exit_code,
            timed_out,
        }
    }

    // ── map_exit_to_result_class ────────────────────────────────────────────

    #[test]
    fn map_exit_zero_is_pass() {
        assert_eq!(map_exit_to_result_class(Some(0)), WitnessResultClass::Pass);
    }

    #[test]
    fn map_exit_one_through_nine_is_fail() {
        for c in 1..=9 {
            assert_eq!(
                map_exit_to_result_class(Some(c)),
                WitnessResultClass::Fail,
                "exit {c} must map to Fail per verifier-processes.md §6"
            );
        }
    }

    #[test]
    fn map_exit_ten_or_above_is_inconclusive() {
        for c in [10, 42, 127, 200, i32::MAX] {
            assert_eq!(
                map_exit_to_result_class(Some(c)),
                WitnessResultClass::Inconclusive,
                "exit {c} must map to Inconclusive (operator-reserved range)"
            );
        }
    }

    #[test]
    fn map_exit_none_is_inconclusive() {
        // signal-terminated / OS could not surface status
        assert_eq!(
            map_exit_to_result_class(None),
            WitnessResultClass::Inconclusive
        );
    }

    #[test]
    fn map_exit_negative_is_inconclusive() {
        // Defensive: some OSes surface signal-truncated codes as
        // negative; map them to Inconclusive rather than silently
        // letting them through as Pass.
        assert_eq!(
            map_exit_to_result_class(Some(-1)),
            WitnessResultClass::Inconclusive
        );
    }

    // ── build_submission ────────────────────────────────────────────────────

    #[test]
    fn build_submission_echoes_envelope_and_outcome_into_body() {
        let env = fixture_env();
        let outcome = CommandOutcome {
            stdout: "stdout-bytes".to_owned(),
            stderr: "stderr-bytes".to_owned(),
            exit_code: Some(0),
            timed_out: false,
        };
        let sub =
            build_submission(&env, &outcome, None, WitnessResultClass::Pass, None).expect("build");
        assert_eq!(sub.verifier_token, env.verifier_token);
        assert_eq!(sub.task_id.as_str(), env.task_id);
        assert_eq!(sub.gate_type.as_str(), env.gate_type);
        assert_eq!(sub.evaluation_sha.as_str(), env.evaluation_sha);
        assert_eq!(sub.result_class, WitnessResultClass::Pass);
        assert_eq!(sub.body["command"], serde_json::json!(env.command));
        assert_eq!(sub.body["exit_code"], serde_json::json!(0));
        assert_eq!(sub.body["stdout"], serde_json::json!("stdout-bytes"));
        assert_eq!(sub.body["stderr"], serde_json::json!("stderr-bytes"));
        assert_eq!(sub.body["timed_out"], serde_json::json!(false));
        assert_eq!(sub.body["failure_reason"], serde_json::Value::Null);
        // No artifact set → key absent.
        assert!(sub.body.get("artifact").is_none());
    }

    #[test]
    fn build_submission_includes_artifact_when_provided() {
        let env = fixture_env();
        let outcome = fixture_outcome(Some(0), false);
        let art = LoadedArtifact {
            sha256: "deadbeef".repeat(8),
            bytes: b"raxis-artifact".to_vec(),
            source_path: "/raxis/symbol_index.json".to_owned(),
        };
        let sub =
            build_submission(&env, &outcome, Some(&art), WitnessResultClass::Pass, None).unwrap();
        assert_eq!(
            sub.body["artifact"]["path"],
            serde_json::json!("/raxis/symbol_index.json")
        );
        assert_eq!(
            sub.body["artifact"]["sha256"],
            serde_json::json!("deadbeef".repeat(8))
        );
        // base64("raxis-artifact") == "cmF4aXMtYXJ0aWZhY3Q="
        assert_eq!(
            sub.body["artifact"]["bytes_b64"],
            serde_json::json!("cmF4aXMtYXJ0aWZhY3Q=")
        );
    }

    #[test]
    fn build_submission_threads_failure_reason_into_body() {
        let env = fixture_env();
        let outcome = fixture_outcome(None, true);
        let sub = build_submission(
            &env,
            &outcome,
            None,
            WitnessResultClass::Inconclusive,
            Some("timeout"),
        )
        .unwrap();
        assert_eq!(sub.body["failure_reason"], serde_json::json!("timeout"));
        assert_eq!(sub.result_class, WitnessResultClass::Inconclusive);
    }

    #[test]
    fn build_submission_rejects_short_evaluation_sha() {
        let env = VerifierEnv {
            evaluation_sha: "abcd".to_owned(),
            ..fixture_env()
        };
        let err = build_submission(
            &env,
            &fixture_outcome(Some(0), false),
            None,
            WitnessResultClass::Pass,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, BuildError::BadEvaluationSha(_)),
            "expected BadEvaluationSha, got {err:?}"
        );
    }

    #[test]
    fn build_submission_rejects_empty_task_id() {
        let env = VerifierEnv {
            task_id: String::new(),
            ..fixture_env()
        };
        let err = build_submission(
            &env,
            &fixture_outcome(Some(0), false),
            None,
            WitnessResultClass::Pass,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, BuildError::BadTaskId(_)),
            "expected BadTaskId, got {err:?}"
        );
    }

    // ── base64_encode ───────────────────────────────────────────────────────

    #[test]
    fn base64_encode_matches_known_vectors() {
        // RFC 4648 §10 test vectors. Pin the implementation against
        // the canonical fixtures so a future refactor that swaps the
        // alphabet or padding surfaces immediately.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    // ── ExitCode ────────────────────────────────────────────────────────────

    #[test]
    fn exit_codes_are_stable_integers() {
        // INV-VERIFIER-AUDIT-PAIRED-WRITE-01 — the kernel-side
        // watcher distinguishes Accepted / Rejected / Timeout /
        // ArtifactRejected from a clean spawn error by the exit
        // code. Pinned here so a renumbering surfaces loudly.
        assert_eq!(ExitCode::AcceptedPass.as_i32(), 0);
        assert_eq!(ExitCode::Rejected.as_i32(), 1);
        assert_eq!(ExitCode::MissingEnv.as_i32(), 2);
        assert_eq!(ExitCode::IoError.as_i32(), 3);
        assert_eq!(ExitCode::Timeout.as_i32(), 4);
        assert_eq!(ExitCode::ArtifactRejected.as_i32(), 5);
    }

    // ── load_artifact_if_present ────────────────────────────────────────────

    #[test]
    fn load_artifact_returns_none_when_path_unset() {
        let env = fixture_env();
        assert!(env.artifact_path.is_none());
        let out = load_artifact_if_present(&env).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn load_artifact_rejects_parent_dir_traversal() {
        let env = VerifierEnv {
            artifact_path: Some(PathBuf::from("/raxis/../etc/passwd")),
            ..fixture_env()
        };
        let err = load_artifact_if_present(&env).unwrap_err();
        assert!(
            matches!(err, ArtifactError::PathEscape { .. }),
            "expected PathEscape, got {err:?}"
        );
    }

    #[test]
    fn load_artifact_reads_bytes_and_computes_sha256() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"raxis-artifact-bytes").unwrap();
        f.flush().unwrap();
        let env = VerifierEnv {
            artifact_path: Some(f.path().to_path_buf()),
            ..fixture_env()
        };
        let out = load_artifact_if_present(&env)
            .unwrap()
            .expect("artifact must load");
        assert_eq!(out.bytes, b"raxis-artifact-bytes");
        // sha256("raxis-artifact-bytes") =
        // 91d2 e0c2 ef84 ... — verified via the streaming hash.
        let mut h = Sha256::new();
        h.update(b"raxis-artifact-bytes");
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(out.sha256, hex::encode(expected));
    }

    #[test]
    fn load_artifact_rejects_oversize_file() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&vec![0u8; 1024]).unwrap();
        f.flush().unwrap();
        let env = VerifierEnv {
            artifact_path: Some(f.path().to_path_buf()),
            artifact_max_bytes: 64, // smaller than the file
            ..fixture_env()
        };
        let err = load_artifact_if_present(&env).unwrap_err();
        match err {
            ArtifactError::TooLarge { size, cap, .. } => {
                assert_eq!(size, 1024);
                assert_eq!(cap, 64);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn load_artifact_surfaces_io_error_on_missing_file() {
        let env = VerifierEnv {
            artifact_path: Some(PathBuf::from(
                "/this/path/intentionally/missing/raxis-artifact",
            )),
            ..fixture_env()
        };
        let err = load_artifact_if_present(&env).unwrap_err();
        assert!(
            matches!(err, ArtifactError::Io { .. }),
            "missing path must surface Io; got {err:?}"
        );
    }

    // ── run_verifier_command ────────────────────────────────────────────────

    // INV-VERIFIER-COMMAND-EXEC-01 happy path: `true` exits 0.
    #[tokio::test]
    async fn run_verifier_command_captures_zero_exit() {
        let env = VerifierEnv {
            command: "true".to_owned(),
            ..fixture_env()
        };
        let out = run_verifier_command(&env).await.unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert!(!out.timed_out);
    }

    #[tokio::test]
    async fn run_verifier_command_captures_nonzero_exit() {
        let env = VerifierEnv {
            command: "exit 7".to_owned(),
            ..fixture_env()
        };
        let out = run_verifier_command(&env).await.unwrap();
        assert_eq!(out.exit_code, Some(7));
        assert!(!out.timed_out);
    }

    #[tokio::test]
    async fn run_verifier_command_captures_stdout_and_stderr() {
        let env = VerifierEnv {
            command: "echo hello-out; echo hello-err 1>&2".to_owned(),
            ..fixture_env()
        };
        let out = run_verifier_command(&env).await.unwrap();
        assert!(out.stdout.contains("hello-out"), "stdout: {:?}", out.stdout);
        assert!(out.stderr.contains("hello-err"), "stderr: {:?}", out.stderr);
    }

    #[tokio::test]
    async fn run_verifier_command_caps_stdout_at_max_bytes() {
        // Emit 32 KiB of stdout but cap the verifier's capture at
        // 128 bytes. Result: stdout.len() ≤ 128.
        let env = VerifierEnv {
            command: "yes raxis | head -c 32768".to_owned(),
            stdout_max_bytes: 128,
            ..fixture_env()
        };
        let out = run_verifier_command(&env).await.unwrap();
        assert!(
            out.stdout.len() <= 128,
            "stdout cap not honoured: len={}",
            out.stdout.len()
        );
    }

    #[tokio::test]
    async fn run_verifier_command_marks_timeout_when_wall_clock_fires() {
        // sleep 10 with a 1-second wall-clock cap → timed_out=true.
        let env = VerifierEnv {
            command: "sleep 10".to_owned(),
            timeout_secs: 1,
            ..fixture_env()
        };
        let started = std::time::Instant::now();
        let out = run_verifier_command(&env).await.unwrap();
        let elapsed = started.elapsed();
        assert!(out.timed_out, "timed_out must be true; got {out:?}");
        assert_eq!(out.exit_code, None, "exit_code must be None on timeout");
        assert!(
            elapsed < Duration::from_secs(5),
            "timeout should fire promptly; got {elapsed:?}"
        );
    }

    // === iter62 verifier-runtime D7 + D12: built-in dispatch witnesses ===

    #[test]
    fn iter62_verifier_builtin_string_is_pinned() {
        // Pin the literal env-var value so a future rename surfaces
        // immediately at the test layer rather than after a kernel
        // dispatch silently falling through to `sh -lc`.
        assert_eq!(VerifierBuiltin::SYMBOL_INDEX_STR, "symbol-index");
    }

    #[test]
    fn iter62_verifier_builtin_parser_recognises_symbol_index() {
        assert_eq!(
            VerifierBuiltin::parse_optional(Some("symbol-index")).unwrap(),
            Some(VerifierBuiltin::SymbolIndex)
        );
    }

    #[test]
    fn iter62_verifier_builtin_parser_treats_empty_or_missing_as_none() {
        assert_eq!(VerifierBuiltin::parse_optional(None).unwrap(), None);
        assert_eq!(VerifierBuiltin::parse_optional(Some("")).unwrap(), None);
    }

    #[test]
    fn iter62_verifier_builtin_parser_rejects_unknown_value() {
        let err = VerifierBuiltin::parse_optional(Some("lint-aggregator")).unwrap_err();
        assert!(
            err.contains("unknown RAXIS_VERIFIER_BUILTIN"),
            "expected diagnostic to name the env var, got {err:?}"
        );
        assert!(
            err.contains("symbol-index"),
            "expected diagnostic to suggest the supported value, got {err:?}"
        );
    }

    /// The structured failure_reason wire strings the built-in
    /// emits when its inputs are insufficient. The kernel-side
    /// audit chain keys off these values for the dashboard
    /// rendering of the `VerifierWitnessReceived` event.
    #[test]
    fn iter62_symbol_index_failure_reasons_are_pinned() {
        let started = std::time::Instant::now();
        let outcome = builtin_failure_outcome(
            "missing_worktree_root",
            "RAXIS_WORKTREE_ROOT must be set when RAXIS_VERIFIER_BUILTIN=symbol-index",
            started,
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&outcome.stdout).expect("structured stdout");
        assert_eq!(parsed["failure_reason"], "missing_worktree_root");
        assert_eq!(parsed["verifier_builtin"], "symbol-index");
        assert_eq!(outcome.exit_code, Some(1));
        assert_eq!(
            map_exit_to_result_class(outcome.exit_code),
            WitnessResultClass::Fail,
            "missing-input failures map to Fail (operator-actionable)",
        );
    }

    #[tokio::test]
    async fn iter62_run_builtin_symbol_index_surfaces_missing_worktree_root() {
        // Construct an env that activates the built-in but
        // deliberately omits the worktree root. The pipeline must
        // surface a structured `missing_worktree_root` outcome
        // rather than panicking.
        let mut env = fixture_env();
        env.builtin = Some(VerifierBuiltin::SymbolIndex);
        env.worktree_root = None;
        env.base_sha = Some("base-sha".to_owned());
        env.artifact_path = Some(std::path::PathBuf::from("/tmp/symbol_index.json"));
        let outcome = run_builtin_symbol_index(&env).await.unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&outcome.stdout).expect("structured stdout");
        assert_eq!(parsed["failure_reason"], "missing_worktree_root");
        assert_eq!(outcome.exit_code, Some(1));
    }

    #[tokio::test]
    async fn iter62_run_builtin_symbol_index_surfaces_missing_base_sha() {
        let mut env = fixture_env();
        env.builtin = Some(VerifierBuiltin::SymbolIndex);
        env.worktree_root = Some(std::path::PathBuf::from("/tmp"));
        env.base_sha = None;
        env.artifact_path = Some(std::path::PathBuf::from("/tmp/symbol_index.json"));
        let outcome = run_builtin_symbol_index(&env).await.unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&outcome.stdout).expect("structured stdout");
        assert_eq!(parsed["failure_reason"], "missing_base_sha");
        assert_eq!(outcome.exit_code, Some(1));
    }

    #[tokio::test]
    async fn iter62_run_builtin_symbol_index_surfaces_missing_artifact_path() {
        let mut env = fixture_env();
        env.builtin = Some(VerifierBuiltin::SymbolIndex);
        env.worktree_root = Some(std::path::PathBuf::from("/tmp"));
        env.base_sha = Some("base-sha".to_owned());
        env.artifact_path = None;
        let outcome = run_builtin_symbol_index(&env).await.unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&outcome.stdout).expect("structured stdout");
        assert_eq!(parsed["failure_reason"], "missing_artifact_path");
        assert_eq!(outcome.exit_code, Some(1));
    }
}
