//! Shared scaffolding for kernel-level integration tests.
//!
//! Files in `tests/<name>.rs` are each compiled as a SEPARATE integration test
//! binary by Cargo. To share helpers between them without duplicating code,
//! Cargo conventionally accepts modules under `tests/common/` (or
//! `tests/<name>/common.rs`); they are compiled only when an integration
//! test file declares `mod common;` at the crate root.
//!
//! Right now only `mock_planner_end_to_end.rs` opts in. The longer-standing
//! `kernel_signal_shutdown.rs` keeps its own inlined copy of the harness so
//! we can land the new integration test without churning a known-good file.
//! Migrating that file is a separate, easily-reverted change tracked as
//! follow-up work.

pub mod browser;
pub mod cpio_inspect;
pub mod dashboard;
pub mod keep_alive;
pub mod kernel_harness;
pub mod tier3_artifacts;
