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
pub mod byo_image;
pub mod concurrency;
pub mod crash_recovery;
pub mod credential_substitution_evidence;
pub mod dep_fetch_evidence;
pub mod docker_stack;
pub mod harness_timeout;
pub mod health_probe;
pub mod injection;
pub mod kernel_driver;
pub mod multi_initiative;
pub mod otel_pusher;
pub mod path_allowlist;
pub mod plan;
pub mod plan_realistic;
pub mod prompts;
pub mod reviewer_substantive_disagreement;
pub mod seeds;
pub mod service_evidence;
pub mod transparent_proxy_evidence;
pub mod witnesses;
