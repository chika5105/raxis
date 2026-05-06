// raxis-kernel::ipc — IPC listener, auth, and dispatch subsystem.
//
// Normative reference: kernel-core.md §2.2 (handlers/), §2.3 (operator.rs),
// and peripherals.md §3 (wire codec, socket layout).
//
// Three UDS sockets:
//   <data_dir>/sockets/operator.sock  — operator CLI connections
//   <data_dir>/sockets/planner.sock   — planner subprocess connections
//   <data_dir>/sockets/gateway.sock   — gateway connections (v1 stub)
//
// All sockets use the raxis-ipc length-prefixed framing with bincode
// `config::standard()`.

pub mod context;
pub mod auth;
pub mod cid_blocklist;
pub mod log;
pub mod server;
pub mod operator;

// V2 Step 15 — pre-auth CID blocklist. Re-exported here because the
// accept layer consults it BEFORE any authenticated session lookup
// (cf. `ipc::auth`, which runs AFTER the connection is established).
// See `cid_blocklist.rs` and `v2-deep-spec.md §Step 15` for design.
pub use cid_blocklist::{
    BlocklistInsertError, CidBlocklist,
    VMADDR_CID_ANY, VMADDR_CID_HOST, VMADDR_CID_LOCAL,
};
