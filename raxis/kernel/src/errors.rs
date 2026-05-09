// raxis-kernel::errors — BOOT_ERR_* exit codes and KernelError enum.
//
// Normative reference: kernel-core.md §2.2 `src/errors.rs`.
//
// Every subsystem that can fail at startup or runtime uses these types.
// Placing them at the crate root makes them accessible everywhere without
// re-export chains.
//
// Exit code table (from the startup sequence table in §2.2):
//   10 BOOT_ERR_POLICY_INVALID   — policy.toml failed to load or verify
//   11 BOOT_ERR_KEY_REGISTRY     — key registry init failed
//   12 BOOT_ERR_STORE_SCHEMA     — store schema version mismatch or migration
//   13 BOOT_ERR_AUDIT_CHAIN      — audit chain broken at startup verify
//   14 BOOT_ERR_SOCKET_BIND      — UDS listener bind failed
//   15 BOOT_ERR_BOOTSTRAP_FAILED — genesis state machine failed
//   16 BOOT_ERR_AUDIT_WRITE      — KernelStarted event write failed (fatal)
//   17 BOOT_ERR_VCS_ROOT         — worktree root validation failed

use thiserror::Error;

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

pub const BOOT_ERR_POLICY_INVALID: i32 = 10;
pub const BOOT_ERR_KEY_REGISTRY: i32 = 11;
pub const BOOT_ERR_STORE_SCHEMA: i32 = 12;
pub const BOOT_ERR_AUDIT_CHAIN: i32 = 13;
pub const BOOT_ERR_SOCKET_BIND: i32 = 14;
pub const BOOT_ERR_BOOTSTRAP_FAILED: i32 = 15;
pub const BOOT_ERR_AUDIT_WRITE: i32 = 16;
pub const BOOT_ERR_VCS_ROOT: i32 = 17;
/// V2_GAPS §D2 — kernel refuses to boot when the FD limit is below
/// `[host_capacity] required_min_fd_limit` (host-capacity.md §12.1).
pub const BOOT_ERR_HOST_CAPACITY: i32 = 18;

// ---------------------------------------------------------------------------
// KernelError
// ---------------------------------------------------------------------------

/// Runtime error enum for all kernel failure modes. Each variant maps to a
/// `BOOT_ERR_*` exit code. `Display` produces a structured message suitable
/// for `exit_with_code` to write as a JSON line to stderr.
#[derive(Debug, Error)]
pub enum KernelError {
    /// Step 3 failure: policy.toml failed to load, parse, or verify.
    #[error("BOOT_ERR_POLICY_INVALID: {reason}")]
    PolicyInvalid { reason: String },

    /// Step 4 failure: key registry could not be initialised from the policy.
    #[error("BOOT_ERR_KEY_REGISTRY: {reason}")]
    KeyRegistry { reason: String },

    /// Step 5 failure: store schema version mismatch or migration failed.
    #[error("BOOT_ERR_STORE_SCHEMA: {reason}")]
    StoreSchema { reason: String },

    /// Step 6 (chain) failure: audit chain is broken or missing.
    /// This is a fatal, non-recoverable error — operating would worsen the problem.
    #[error("BOOT_ERR_AUDIT_CHAIN: {reason}")]
    AuditChainBroken { reason: String },

    /// Step 7 failure: UDS listener bind failed.
    #[error("BOOT_ERR_SOCKET_BIND: {reason}")]
    SocketBind { reason: String },

    /// Step 2 path: genesis state machine failed.
    #[error("BOOT_ERR_BOOTSTRAP_FAILED: {reason}")]
    BootstrapFailed { reason: String },

    /// Step 8 failure: could not write KernelStarted audit event.
    #[error("BOOT_ERR_AUDIT_WRITE: {reason}")]
    AuditWrite { reason: String },

    /// VCS worktree root validation failure.
    #[error("BOOT_ERR_VCS_ROOT: {reason}")]
    VcsRoot { reason: String },

    /// V2_GAPS §D2 — host-capacity boot-time invariant violation
    /// (`required_min_fd_limit` floor not met). The kernel refuses
    /// to boot rather than start with insufficient FDs and OOM
    /// later under per-VM growth.
    #[error("BOOT_ERR_HOST_CAPACITY: {reason}")]
    HostCapacity { reason: String },

    /// Generic I/O error (wraps std::io::Error variants not covered above).
    #[error("kernel I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl KernelError {
    /// The process exit code for this error.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::PolicyInvalid { .. } => BOOT_ERR_POLICY_INVALID,
            Self::KeyRegistry { .. } => BOOT_ERR_KEY_REGISTRY,
            Self::StoreSchema { .. } => BOOT_ERR_STORE_SCHEMA,
            Self::AuditChainBroken { .. } => BOOT_ERR_AUDIT_CHAIN,
            Self::SocketBind { .. } => BOOT_ERR_SOCKET_BIND,
            Self::BootstrapFailed { .. } => BOOT_ERR_BOOTSTRAP_FAILED,
            Self::AuditWrite { .. } => BOOT_ERR_AUDIT_WRITE,
            Self::VcsRoot { .. } => BOOT_ERR_VCS_ROOT,
            Self::HostCapacity { .. } => BOOT_ERR_HOST_CAPACITY,
            Self::Io(_) => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// exit_with_code
// ---------------------------------------------------------------------------

/// Log `err` as a structured JSON line to stderr and exit with its code.
///
/// The `-> !` ensures the compiler knows this function never returns.
/// Called from `main.rs` when any startup step fails.
pub fn exit_with_code(err: KernelError) -> ! {
    // Write a structured JSON line to stderr for operator tooling to parse.
    let code = err.exit_code();
    eprintln!(
        "{{\"level\":\"error\",\"exit_code\":{code},\"message\":\"{}\"}}",
        err
    );
    std::process::exit(code);
}
