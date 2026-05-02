// raxis-kernel::ipc::context — HandlerContext shared state for IPC handlers.
//
// Normative reference: kernel-core.md §2.2 `src/handlers/context.rs`.
//
// HandlerContext is the dependency-injected read-only (or Arc-shared) context
// passed to every IPC handler. It is constructed once in main.rs after all
// startup steps complete and cloned (via Arc) into each connection task.

use std::sync::Arc;

use raxis_policy::PolicyBundle;
use raxis_store::Store;

use crate::authority::keys::KeyRegistry;

/// Shared, read-only context for all IPC handlers.
///
/// All fields are `Arc`-wrapped so each connection task gets a cheap clone.
/// The `store` is behind `Store` which itself contains a `tokio::sync::Mutex`.
pub struct HandlerContext {
    /// Validated policy bundle. Replaced atomically (via `ArcSwap` in v2;
    /// in v1 we use `Arc<PolicyBundle>` since epoch advance is rare and
    /// requires kernel restart in v1).
    pub policy: Arc<PolicyBundle>,
    /// Kernel key registry — authority + quality keypairs + verifier token key.
    pub registry: Arc<KeyRegistry>,
    /// SQLite state store (WAL mode, synchronous=FULL, foreign_keys=ON).
    pub store: Arc<Store>,
    /// Absolute path to the kernel data directory (e.g. `~/.raxis`).
    pub data_dir: std::path::PathBuf,
}

impl HandlerContext {
    pub fn new(
        policy: Arc<PolicyBundle>,
        registry: Arc<KeyRegistry>,
        store: Arc<Store>,
        data_dir: std::path::PathBuf,
    ) -> Self {
        Self { policy, registry, store, data_dir }
    }
}
