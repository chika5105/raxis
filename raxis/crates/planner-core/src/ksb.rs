//! Re-export of the [`raxis_ksb`] crate.
//!
//! V2 `v2_extended_gaps.md §2.4` extracted the schema + renderer
//! into the standalone `raxis-ksb` crate so the kernel (which
//! assembles + serializes the snapshot at session-spawn time) and
//! the planner-core driver (which deserializes + renders it from
//! the env at dispatch time) cannot drift on the wire shape.
//!
//! This module is kept for source-compatibility with existing
//! `crate::ksb::*` import paths inside `raxis-planner-core`.

pub use raxis_ksb::*;
