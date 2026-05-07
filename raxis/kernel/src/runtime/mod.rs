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
//! (e.g. `gateway.json` for the active gateway PID + token prefix
//! once `peripherals.md` §3.2 supervisor metadata graduates from
//! stderr).
//!
//! # What does NOT live here
//!
//! Anything durable. The audit chain (`<data_dir>/audit/segment-*.jsonl`)
//! and `kernel.db` are the two sources of truth; if a future
//! requirement ever wants to read the heartbeat file from inside the
//! kernel, that is a design smell — the answer is to make the kernel
//! publish to the audit chain instead. The kernel never reads its own
//! `runtime/heartbeat.json`.
//!
//! # Crate-split rationale
//!
//! The wire shape (`Snapshot`, `KernelLifecycleState`, atomic write,
//! read, the cadence/staleness constants) lives in the workspace
//! crate `raxis-runtime` so the CLI binary can deserialize what the
//! kernel writes without depending on the kernel binary. This module
//! owns ONLY the live-data collection (`collect`) and the `tokio`
//! `select!` loop (`run_loop`) — both of which need access to
//! kernel-internal state (the verifier runner, the policy `ArcSwap`).

pub mod heartbeat;
pub mod nonce_sweeper;

pub use heartbeat::run_loop as heartbeat_loop;
pub use nonce_sweeper::run_loop as nonce_sweeper_loop;
