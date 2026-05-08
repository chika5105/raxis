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
//! ## What this crate does NOT yet do (deferred to next iteration)
//!
//! The skeleton iteration deliberately omits the registry-pull side
//! of the spec (`image-cache.md §6` "pull-and-verify pipeline") and
//! the in-process mutex-map concurrency (`§7`). Both land in the
//! follow-up iteration. The skeleton ships:
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
//!   `RegistryUnreachable` for any miss. This is what
//!   `raxis-kernel`'s integration tests will wire into
//!   `HandlerContext::image_resolver` until the production
//!   resolver lands.
//!
//! Together these are enough to wire the kernel-side trait
//! consumer (`HandlerContext`) and write the integration tests for
//! `session-spawn → isolation-backend` against deterministic
//! pre-populated cache state, **without** committing to a registry
//! client this iteration.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod cache_layout;
mod digest;
mod error;
mod pre_populated;
mod registry;
mod resolver;
mod resolved_image;

pub use cache_layout::CacheLayout;
pub use digest::OciDigest;
pub use error::ImageResolverError;
pub use pre_populated::PrePopulatedResolver;
pub use registry::RegistryRef;
pub use resolved_image::ResolvedImage;
pub use resolver::ImageResolver;

/// SHA-256 length in bytes — public so callers that surface the
/// value (audit payloads, `raxis doctor` output) do not redefine
/// the magic number.
pub const SHA256_LEN_BYTES: usize = 32;

/// SHA-256 length when rendered as lowercase hex (no `0x` prefix).
pub const SHA256_LEN_HEX: usize = SHA256_LEN_BYTES * 2;
