//! Kernel-side runtime hints — the `<data_dir>/runtime/` surface.
//!
//! Normative reference: `cli-readonly.md` §5.2 ("the kernel-side
//! heartbeat file").
//!
//! # What lives here
//!
//! The `runtime/` directory is the operator-visible *liveness hint*
//! channel — explicitly **not** part of the audit chain (see
//! cli-readonly.md §5.2.4). The kernel emits one file today
//! (`heartbeat.json`) but the directory is named generically because
//! v2 is expected to add a small number of additional sibling files
//! (e.g. `gateway.json` for the active gateway PID + token prefix once
//! `peripherals.md` §3.2 supervisor metadata graduates from stderr).
//!
//! # What does NOT live here
//!
//! Anything durable. The audit chain (`<data_dir>/audit/segment-*.jsonl`)
//! and `kernel.db` are the two sources of truth; if a future requirement
//! ever wants to read the heartbeat file from inside the kernel, that
//! is a design smell — the answer is to make the kernel publish to the
//! audit chain instead. The kernel never reads its own
//! `runtime/heartbeat.json`.

pub mod heartbeat;

pub use heartbeat::{
    run_loop as heartbeat_loop, write_atomic, KernelLifecycleState, Snapshot, HEARTBEAT_FILE,
    HEARTBEAT_INTERVAL, RUNTIME_DIR,
};
