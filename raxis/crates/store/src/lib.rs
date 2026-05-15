// raxis-store — SQLite-backed persistent kernel state.
//
// Normative reference: specs/v1/kernel-store.md §2.5.1
//
// This crate owns the single `kernel.db` SQLite connection and all
// schema migrations. It exposes:
//
//   - `Store`           — the kernel's read+write handle
//                          (Arc<Mutex<Connection>>); see `db.rs`.
//   - `ro::open`         — the CLI's read-only handle; see `ro.rs`,
//                          backed by `OpenFlags::SQLITE_OPEN_READ_ONLY`.
//   - `Table`            — typed table-name enum (INV-STORE-03).
//   - `SCHEMA_VERSION`   — current kernel.db schema version; bumped
//                          alongside every new migration. Compared by
//                          `ro::assert_compatible_schema` so the CLI
//                          fails-closed against a kernel.db it does
//                          not understand (cli-readonly.md §5.3).
//
// Crate rules (philosophy.md §1.5):
//   - No async I/O: rusqlite is synchronous; callers use tokio::sync::Mutex.
//   - No IPC, no subprocess logic, no key material.
//   - The mutex must be held for the entire duration of any transaction.

pub mod circuit_store;
pub mod db;
pub mod genesis;
pub mod migration;
pub mod observability;
pub mod plan_bundles;
pub mod ro;
pub mod table;
pub mod views;

pub use circuit_store::{CircuitRowSqlite, CircuitTransition, SqliteCircuitStore};
pub use db::{Store, StoreError};
pub use genesis::install_genesis_policy_epoch_row;
pub use migration::SCHEMA_VERSION;
pub use plan_bundles::{
    insert_artifacts, insert_bundle, nonce_status_in_tx, record_nonce, sweep_expired_nonces,
    NonceStatus, PlanBundleStoreError,
};
pub use ro::{assert_compatible_schema, open as open_ro, RoConn, RoError, KERNEL_DB_FILE};
pub use table::Table;
