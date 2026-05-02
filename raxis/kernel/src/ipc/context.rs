// raxis-kernel::ipc::context — HandlerContext shared state for IPC handlers.
//
// Normative reference: kernel-core.md §2.2 `src/handlers/context.rs`.
//
// HandlerContext is the dependency-injected read-only (or Arc-shared) context
// passed to every IPC handler. It is constructed once in main.rs after all
// startup steps complete and cloned (via Arc) into each connection task.
//
// Fields added vs the minimal v1 starter:
//   witness_dir — absolute path to <data_dir>/witness/ blob store. Required
//                 by handlers/witness.rs per spec §2.3 witness.rs: "blob bytes
//                 and WitnessIndexCtx are mandatory".

use std::path::PathBuf;
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
    pub data_dir: PathBuf,
    /// Absolute path to the witness blob store (`<data_dir>/witness/`).
    ///
    /// Spec §2.3 witness.rs: all witness blob writes go through
    /// `witness_index::write(record, blob, &ctx.witness_dir, store)`.
    /// The directory is created at bootstrap time and always exists by
    /// the time the IPC server starts (startup step 5, store open).
    pub witness_dir: PathBuf,
}

impl HandlerContext {
    pub fn new(
        policy: Arc<PolicyBundle>,
        registry: Arc<KeyRegistry>,
        store: Arc<Store>,
        data_dir: PathBuf,
    ) -> Self {
        let witness_dir = data_dir.join("witness");
        Self { policy, registry, store, data_dir, witness_dir }
    }

    /// Construct with an explicit witness_dir (useful in tests that use a
    /// non-standard layout or a temporary directory).
    pub fn with_witness_dir(mut self, witness_dir: PathBuf) -> Self {
        self.witness_dir = witness_dir;
        self
    }
}
