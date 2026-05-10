//! Per-endpoint handlers for the operator dashboard HTTP API.
//!
//! Module layout mirrors the spec §4.3 endpoint table:
//!
//! * [`auth`] — challenge / verify / logout.
//! * [`health`] — kernel health snapshot.
//! * [`initiatives`] — initiative list + detail + DAG.
//! * [`tasks`] — task detail + structured outputs.
//! * [`sessions`] — session list + detail (stream is wired
//!   later in P4).
//! * [`escalations`] — pending escalation list.
//! * [`audit`] — paginated audit chain.
//! * [`inbox`] — operator inbox.
//! * [`notifications`] — notification list + mark-read.
//! * [`policy`] — policy snapshot view.

pub mod audit;
pub mod auth;
pub mod escalations;
pub mod git;
pub mod health;
pub mod inbox;
pub mod initiatives;
pub mod notifications;
pub mod policy;
pub mod sessions;
pub mod tasks;
