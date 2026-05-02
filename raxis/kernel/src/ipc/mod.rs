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
pub mod server;
pub mod operator;
