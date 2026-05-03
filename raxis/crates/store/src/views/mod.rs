//! Typed read-only query catalog (cli-readonly.md §5.4).
//!
//! # Scope
//!
//! Every read the operator CLI performs against `kernel.db` lives here,
//! NOT inline in the CLI binary. The kernel's own production code is
//! welcome to use these functions too — `recovery.rs` and
//! `lifecycle::repopulate_plan_registry` already do similar reads, and
//! new kernel-side reads SHOULD migrate here over time so a schema
//! migration changes a column in exactly one place.
//!
//! # Hard rules
//!
//! 1. **No raw SQL ever escapes this module.** Every public function
//!    returns owned `Vec<T>` or owned struct types. The CLI never sees
//!    a `rusqlite::Statement` or row iterator.
//! 2. **Every function takes `&RoConn`.** The type system makes a
//!    write-attempt impossible.
//! 3. **Every function opens its own short-lived snapshot.** The
//!    discipline from §5.4.3: a `BEGIN DEFERRED ... COMMIT` (no-op for
//!    reads) per call, materialised result, return. We do NOT return
//!    iterators that would hold a WAL snapshot open across UI ticks.
//! 4. **All identifiers come from typed sources** — the
//!    [`crate::Table`] enum for table names, and the kernel's typed
//!    state enums (re-exported below) for state values. INV-STORE-03
//!    applies inside views/ same as everywhere else.
//!
//! # Module layout
//!
//! ```text
//! views/
//! ├── mod.rs            // this file: re-exports + integer helpers
//! ├── kernel_meta.rs    // schema_version, current policy_epoch
//! ├── tasks.rs          // task counts, lookup, ready/blocked sets
//! ├── initiatives.rs    // initiative counts, lookup
//! ├── sessions.rs       // active session counts + list
//! ├── escalations.rs    // pending counts + list with filters
//! └── policy_history.rs // policy_epoch_history rows
//! ```
//!
//! Future modules (added as the CLI surface needs them; tracked in
//! cli-readonly.md §5.4.1):
//!
//!   * `budget.rs`        — lane_budget_reservations + per-lane pressure
//!   * `witnesses.rs`     — witness_records joins
//!   * `verifier_tokens.rs` — outstanding tokens
//!   * `delegations.rs`   — delegations by session × capability
//!
//! These are deferred not because they are difficult, but because the
//! CLI commands that consume them (`raxis budget`, `raxis witnesses`,
//! `raxis verifiers`) are scheduled for Phase B2 sub-commits — adding
//! the view + the command together keeps the diff reviewable.
//!
//! # Redaction (§5.4.2)
//!
//! The spec defines a `Redactable<T>` enum for path-list fields with
//! `--reveal-paths` audit emission. v1 publishes the underlying values
//! unwrapped because (a) the only path-bearing reads currently exposed
//! are kernel-internal (`task_exported_path_snapshots`,
//! `signed_plan_artifacts.plan_bytes`) and not yet wired to a CLI
//! `inspect` surface, and (b) cli-readonly.md §5.4.2 requires the
//! reveal path to write a `PathReadAccessed` audit event — which means
//! redaction depends on Phase B2 (the `inspect` command), not on this
//! foundation crate. Tracked as TODO in `tasks::full_inspection`.

pub mod escalations;
pub mod initiatives;
pub mod kernel_meta;
pub mod policy_history;
pub mod sessions;
pub mod tasks;
pub mod witnesses;

// Re-export the most common return shapes so CLI binders don't have to
// chase three sub-paths for one table.
pub use escalations::{EscalationRow, EscalationStatusFilter};
pub use initiatives::{InitiativeRow, InitiativeStateCounts};
pub use kernel_meta::{KernelMeta, KernelMetaError};
pub use policy_history::PolicyEpochRow;
pub use sessions::{SessionRow, SessionStateCounts};
pub use tasks::{
    BlockingEdgeRow, DagEdgeRow, EdgeDirection, ReadyTaskRow, TaskRow, TaskStateCounts,
};
pub use witnesses::WitnessRow;
