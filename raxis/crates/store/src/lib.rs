// raxis-store — SQLite-backed persistent kernel state.
//
// Normative reference: specs/v1/kernel-store.md §2.5.1
//
// This crate owns the single `kernel.db` SQLite connection and all
// schema migrations. It exposes a `Store` handle (Arc<Mutex<Connection>>)
// that all kernel subsystems use for reads and writes.
//
// Crate rules (philosophy.md §1.5):
//   - No async I/O: rusqlite is synchronous; callers use tokio::sync::Mutex.
//   - No IPC, no subprocess logic, no key material.
//   - The mutex must be held for the entire duration of any transaction.

pub mod db;
pub mod migration;
pub mod table;

pub use db::{Store, StoreError};
pub use table::Table;
