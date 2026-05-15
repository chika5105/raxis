//! `raxis-image-cache` — **OCI digest resolver + on-disk cache.**
//!
//! Normative reference: `raxis/specs/v2/image-cache.md`.
//!
//! ## What this crate does (V2 skeleton iteration)
//!
//! Turns an [`OciDigest`] (the policy-/plan-pinned commitment from
//! `[[vm_images]] oci_digest = "sha256:..."`) into a [`ResolvedImage`]
//! whose [`ResolvedImage::rootfs_image_path`] is the absolute path
//! the isolation backend (`raxis-isolation-apple-vz`,
//! `raxis-isolation-firecracker`) hands to its
//! `IsolationBackend::spawn(image_path = ...)` API.
//!
//! ## What this crate ships in V2
//!
//! * [`OciDigest`] — typed wrapper with `FromStr` validation
//!   (`sha256:<64 lowercase hex>`).
//! * [`RegistryRef`] — `(host, repository)` pair the kernel
//!   passes as a hint.
//! * [`ImageResolver`] — the async trait the kernel session-spawn
//!   path consumes.
//! * [`ResolvedImage`] — the trait return type.
//! * [`ImageResolverError`] — full failure-mode taxonomy from
//!   `image-cache.md §9` (every variant carries enough info for
//!   the audit-record mapping).
//! * [`CacheLayout`] — pure path-derivation helper for the on-disk
//!   layout in `image-cache.md §4`. Has no I/O; the kernel uses
//!   it to address pre-staged blobs without depending on a registry
//!   client.
//! * [`PrePopulatedResolver`] — `cfg(test)`-friendly impl that
//!   resolves only digests already present in the cache; surfaces
//!   `RegistryUnreachable` for any miss. Re-hashes on every call
//!   because it has no §6 phase-3 verification step.
//! * [`ProductionResolver`] — registry-pull-backed impl that
//!   wires `pull.rs` (phases 1–4) and `extract.rs` (phase 5)
//!   together with the §7 in-memory mutex map keyed by digest.
//!   Talks the OCI distribution-spec v2 wire format
//!   (`GET /v2/<repo>/blobs/sha256:<hex>`); supports a single
//!   shared bearer token for authenticated registries.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod cache_layout;
mod digest;
mod error;
mod extract;
mod pre_populated;
mod production;
mod pull;
mod registry;
mod resolved_image;
mod resolver;

pub use cache_layout::CacheLayout;
pub use digest::OciDigest;
pub use error::ImageResolverError;
pub use pre_populated::PrePopulatedResolver;
pub use production::ProductionResolver;
pub use pull::build_blob_url;
pub use registry::RegistryRef;
pub use resolved_image::ResolvedImage;
pub use resolver::ImageResolver;

/// SHA-256 length in bytes — public so callers that surface the
/// value (audit payloads, `raxis doctor` output) do not redefine
/// the magic number.
pub const SHA256_LEN_BYTES: usize = 32;

/// SHA-256 length when rendered as lowercase hex (no `0x` prefix).
pub const SHA256_LEN_HEX: usize = SHA256_LEN_BYTES * 2;
