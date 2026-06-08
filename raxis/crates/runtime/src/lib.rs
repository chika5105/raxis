//! Shared runtime hint types written by the kernel and read by the
//! CLI, lying under `<data_dir>/runtime/`.
//!
//! Normative reference: `cli-readonly.md` §5.2 (heartbeat) and any
//! future hint files (gateway PID, planned for v1.x).
//!
//! # Why this crate exists
//!
//! Both the `raxis-kernel` binary (writer) and the `raxis` CLI binary
//! (reader) need to agree on the byte-exact JSON shape of every file
//! under `runtime/`. A workspace-shared crate with the structs +
//! constants + atomic-write/read helpers is the smallest correct
//! scope; pulling them through `raxis-store` would conflate
//! durable kernel state (the SQLite database) with NON-durable
//! liveness hints, which the CLI is allowed to find missing or stale
//! without that being a correctness failure.
//!
//! # Hard rules — apply to every public item in this crate
//!
//! 1. **Forward-compat:** structs derive `serde(default)` per field
//!    (or are flagged with `#[serde(default)]` collectively) so a
//!    kernel ahead of the CLI never breaks the CLI parser. New fields
//!    are ADDED, never repurposed.
//! 2. **Atomic writes only:** every file under `runtime/` is written
//!    via tempfile + `rename(2)` so a concurrent reader either sees
//!    the previous record or the new one — never a torn file.
//! 3. **Best-effort:** a missing or stale file is the CLI's signal
//!    that the kernel is down or wedged. The kernel must never make
//!    a control-plane decision based on what it wrote here; the
//!    audit chain is the source of truth.

pub mod heartbeat;
pub mod install;

pub use heartbeat::{
    read, unix_now_secs, write_atomic, KernelLifecycleState, ReadError, Snapshot, HEARTBEAT_FILE,
    HEARTBEAT_INTERVAL, HEARTBEAT_SCHEMA_VERSION, HEARTBEAT_STALE_AFTER, RUNTIME_DIR,
    STORE_SCHEMA_VERSION,
};
pub use install::{
    current_install_origin, data_dir_from_env_or_install_default, homebrew_data_dir_from_exe_path,
    homebrew_prefix_from_exe_path, InstallOrigin, HOMEBREW_DATA_DIR_SUFFIX, RAXIS_DATA_DIR_ENV,
};
