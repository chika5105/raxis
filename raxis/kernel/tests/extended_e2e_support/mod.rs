//! Shared scaffolding for `extended_e2e_concurrent_lifecycle.rs`.
//!
//! Spec: [`raxis/specs/v2/e2e-extended-scenario.md`].
//!
//! Each integration test file under `kernel/tests/*.rs` is a separate
//! integration test binary, so `mod extended_e2e_support;` only
//! pulls these helpers into the extended-scenario binary. The
//! existing `tests/common/` harness is reused alongside this module
//! via `mod common;`.

#![allow(dead_code)]

pub mod audit_chain;
pub mod concurrency;
pub mod crash_recovery;
pub mod injection;
pub mod kernel_driver;
pub mod multi_initiative;
pub mod path_allowlist;
pub mod plan;
pub mod plan_realistic;
pub mod prompts;
pub mod reviewer_substantive_disagreement;
pub mod secrets;
pub mod seeds;
pub mod witnesses;
