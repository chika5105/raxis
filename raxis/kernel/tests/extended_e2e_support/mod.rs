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
pub mod injection;
pub mod plan;
pub mod prompts;
pub mod seeds;
pub mod witnesses;
