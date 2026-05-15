# RAXIS V2 — VM Image Cache and OCI Resolver Specification

> **Status:** V2 Draft. This spec is the canonical home for the
> resolver layer between the kernel's policy- and plan-pinned
> `oci_digest` references and the `image_path: &Path` argument the
> isolation backends (`raxis-isolation-apple-vz`,
> `raxis-isolation-firecracker`) expect.
>
> **Cross-references:**
>
> - [`v2-deep-spec.md §17`](v2-deep-spec.md) (Step 17 — `approve_plan` shift-left
>   validation) — `[[vm_images]]` admit-list handling, `oci_digest`
>   recording on the initiative row, kernel provisioning flow at
>   session activation (the seed text for §3 below).
> - [`planner-harness.md §10.4–§10.7`](planner-harness.md) — the three RAXIS-canonical
>   images that bypass this resolver (they are kernel-version-locked
>   on-disk artefacts, never pulled).
> - [`policy-plan-authority.md §4`](policy-plan-authority.md) — `[[vm_images]] role_restriction`
>   admit list and `oci_digest` field semantics.
> - [`release-and-distribution.md §10`](release-and-distribution.md) — operator-published images
>   are out of scope for the RAXIS release pipeline; they are
>   exclusively this resolver's concern.
> - [`system-requirements.md §1`](system-requirements.md) — install-dir layout that this spec
>   extends with an `oci-cache/` subdirectory.

---

## §1 — Why a standalone spec

The kernel's `[[vm_images]]` admission story is fully specified in
existing docs: every operator-defined VM image is pinned by SHA-256
`oci_digest`, the policy bundle declares the admit list, and
`approve_plan` Check 8 records the resolved digest on the initiative
row before any VM boots. That much is normative.

What is NOT specified anywhere is **the layer that turns an
`oci_digest` into bytes on disk a microVM can boot.** The spec has
elided this with phrases like "Check local OCI cache: image with
this digest already present? Yes → use cached layers; No → pull from
registry, verify digest, cache" without ever saying:

* what local-cache layout (path scheme, subdir per digest, etc.),
* what registry transport (HTTPS+OCI, skopeo invocation, internal
  Rust client),
* how digest verification differs for ORAS / EROFS-blob registries,
* whether pulls are concurrent-safe (two sessions racing on the same
  digest),
* what the GC story is when an old `oci_digest` is no longer
  referenced by any policy generation,
* how transient failures (registry 5xx, partial writes) are
  recovered,
* and how the resolver feeds an `image_path: &Path` back to the
  isolation backend.

This spec is normative for all of those decisions. It is the reason
no `raxis-image-cache` / `raxis-oci-pull` crate has been authored
yet — the upstream contract was unwritten.

---

## §2 — Scope and non-scope

In scope:

- The on-disk cache layout under `$RAXIS_DATA_DIR/oci-cache/`.
- The trait surface (`ImageResolver`) the kernel session-spawn path
  consumes; the production implementation backed by an OCI registry
  client; the test impls (`PrePopulatedResolver`).
- The pull-and-verify pipeline: registry → on-disk staging → atomic
  rename into the cache → SHA-256 verification gate.
- Concurrency control across multiple sessions racing on the same
  digest (no double-pulls, no partial-cache reads).
- GC: `raxis doctor cache prune` and the kernel's policy-epoch-bump
  background sweep.
- Failure-mode taxonomy and the kernel's `FAIL_*` mappings.

Out of scope:

- The three RAXIS-canonical images (`raxis-reviewer-core`,
  `raxis-orchestrator-core`, `raxis-executor-starter`). Those are
  delivered by the release pipeline ([`release-and-distribution.md`](release-and-distribution.md))
  to a kernel-version-locked path under `$RAXIS_INSTALL_DIR/images/`
  and are NOT routed through this resolver.
- The OCI image-builder side (operators use their own toolchain —
  Buildah, Docker, Podman, Nix); RAXIS only consumes their output.
- Multi-arch manifest selection. V2 ships single-arch images only;
  the resolver returns an error if the manifest declares more than
  one platform.
- TLS pinning for upstream registries — operators MUST configure
  their registry to use a CA the host already trusts; the kernel
  does NOT carry a registry-CA pin field in V2.

---

## §3 — The seed text from [`v2-deep-spec.md`](v2-deep-spec.md)

[`v2-deep-spec.md §Distribution`](v2-deep-spec.md) already specifies the high-level
flow at session activation:

```text
1. Read task.vm_image → resolve oci_digest (recorded at approve_plan time)
2. Check local OCI cache: image with this digest already present?
   Yes → use cached layers
   No  → pull from registry, verify digest, cache
3. Boot AVF microVM with the OCI image as root filesystem
4. Mount VirtioFS (rw): /workspace → $RAXIS_DATA_DIR/worktrees/<session_uuid>/
5. Mount VirtioFS (ro): /raxis    → session config directory
6. raxis-planner starts as PID 1; reads /raxis/session.env + /raxis/system_prompt.txt
```

This spec turns step 2 — "Check local OCI cache… Yes / No" — into
a concrete subsystem, leaving steps 1, 3–6 unchanged.

---

## §4 — On-disk cache layout

```text
$RAXIS_DATA_DIR/oci-cache/
├── blobs/
│   └── sha256/
│       ├── ab/abcd1234…ef.tar.zst       (compressed image blob)
│       ├── ab/abcd1234…ef.json          (parsed image manifest)
│       └── ab/abcd1234…ef.staging       (in-flight pull; absent on stable cache)
├── images/
│   └── sha256/
│       └── ab/abcd1234…ef/
│           ├── rootfs.img               (extracted EROFS / squashfs blob; what the isolation backend boots)
│           ├── manifest.json            (the OCI image manifest, copied for self-containment)
│           └── config.json              (the OCI config — env vars, cmd, entrypoint)
└── locks/
    └── pulls/
        └── ab/abcd1234…ef.lockfile      (advisory file lock; acquired by exclusive pull, released when blob lands)
```

Three orthogonal directories:

* `blobs/sha256/<aa>/<full>.*` — raw artefacts as-pulled. The first
  two hex chars are the shard prefix (matches the OCI `sha256:`
  layout convention; keeps each directory under ~256 entries even
  for a long-running cache).
* `images/sha256/<aa>/<full>/` — the **extracted** image, ready for
  the isolation backend. `rootfs.img` is what
  `IsolationBackend::spawn(image_path = …/rootfs.img)` consumes.
* `locks/pulls/<aa>/<full>.lockfile` — `flock(2)`-based mutual
  exclusion across processes. The kernel (single binary, multiple
  sessions) does NOT depend on file locking for in-process
  serialisation; the file lock exists so a second `raxis doctor`
  / `raxis cli` invocation cannot race against a kernel-side pull.

The split between `blobs/` and `images/` is deliberate: a tampered
extraction can be re-derived from `blobs/` without re-pulling, and
GC can prune `images/` faster than `blobs/` (extraction is cheap
relative to network).

---

## §5 — Trait surface

```rust
/// Resolver from a policy- / plan-pinned `oci_digest` to a path
/// the isolation backend can hand to its `spawn(image_path = …)`
/// API.
///
/// Implementations are expected to be:
///   * concurrency-safe (multiple sessions resolving the same
///     digest concurrently must not duplicate-pull);
///   * digest-verifying (the returned path's SHA-256 MUST equal
///     the `oci_digest` argument byte-for-byte);
///   * cancellation-safe (a `tokio::select!`-driven cancel must
///     leave on-disk state consistent — no partially-extracted
///     `images/<digest>/` directories visible to a follow-up call).
#[async_trait]
pub trait ImageResolver: Send + Sync {
    /// Resolve `oci_digest` (e.g. `"sha256:abcd1234…"`) to a path
    /// the isolation backend can boot. Pulls from the configured
    /// registry on cache miss.
    async fn resolve(
        &self,
        oci_digest: &OciDigest,
        registry_hint: Option<&RegistryRef>,
    ) -> Result<ResolvedImage, ImageResolverError>;

    /// Best-effort GC. Idempotent; must not panic on a missing
    /// cache. Returns the number of bytes freed.
    fn prune_unreferenced(
        &self,
        live_digests: &HashSet<OciDigest>,
    ) -> Result<u64, ImageResolverError>;
}

pub struct ResolvedImage {
    /// Absolute path to the EROFS / squashfs rootfs blob the
    /// isolation backend boots. Stable across the lifetime of the
    /// `oci_digest` (cache writes are atomic-rename).
    pub rootfs_image_path: PathBuf,

    /// Path to the OCI config.json. Used by the kernel session-
    /// spawn path to read `Env`, `Entrypoint`, and `Cmd`.
    pub oci_config_path: PathBuf,

    /// The byte-equality-verified digest. Echoed back so the
    /// kernel can carry it into audit events without a second
    /// `compute_image_digest` pass.
    pub verified_digest: OciDigest,
}
```

`OciDigest` is a typed wrapper around `sha256:<64 hex chars>` with
`FromStr` validation; `RegistryRef` is `(host, repository)` with
optional auth credentials sourced from operator policy (NOT from
plan).

The `registry_hint` parameter is advisory — production
implementations may consult per-image registry overrides in
`policy.toml` `[[vm_images]] registry = "ghcr.io/operator/foo"` and
ignore the hint, or fall back to the hint when the policy entry is
silent. The kernel session-spawn path passes the policy entry's
registry field (when present) as the hint.

---

## §6 — Pull-and-verify pipeline

The production resolver implementation handles a cache miss in
five phases:

1. **Lock.** `flock(2)`-acquire `locks/pulls/<aa>/<digest>.lockfile`
   with `LOCK_EX | LOCK_NB`. On `EWOULDBLOCK` — another process is
   pulling the same digest — fall through to phase 2 with a
   blocking `LOCK_SH`; the eventual `flock` return is the signal
   that the other process landed the blob.
2. **Stage.** Stream the OCI registry's blob to
   `blobs/sha256/<aa>/<digest>.staging`. The transport is HTTPS via
   `reqwest`; auth tokens (operator-policy `[[vm_images.auth]]`)
   are attached as `Authorization: Bearer …` headers and never
   logged. The streaming write hashes-as-it-goes via `sha2::Sha256`.
3. **Verify.** On stream end, finalise the SHA-256. If it does not
   match the requested `oci_digest`, the staging file is removed
   and `ImageResolverError::DigestMismatch { expected, actual }`
   is surfaced. The kernel maps this to
   `FAIL_OCI_IMAGE_DIGEST_MISMATCH`.
4. **Atomic rename.** `rename(2)` `…/<digest>.staging` →
   `…/<digest>.tar.zst`. Atomic on every supported filesystem
   (ext4, APFS, XFS, btrfs, ZFS); the cache is never observed in a
   partial state.
5. **Extract.** Untar / unzstd the blob into
   `images/sha256/<aa>/<digest>/`. The OCI manifest declares the
   rootfs filesystem layout; for `mediaType: application/vnd.raxis.image.rootfs.v1+erofs`
   the extracted bytes are an EROFS blob written verbatim to
   `rootfs.img`. (Other media types are reserved for future
   verifier-image subsets and are rejected with
   `ImageResolverError::UnsupportedMediaType` in V2.)

The lock is released on either successful completion or any error
in phases 2–5; a partial extraction (process killed between phases
4 and 5) is detected on the next call by re-checking the
`images/<digest>/rootfs.img` existence and re-running phase 5 from
the still-cached blob.

---

## §7 — Concurrency

The lock-file convention in §6 phase 1 covers the inter-process
case. Inside the kernel binary itself, `ImageResolver` impls hold
an in-memory `tokio::sync::Mutex` keyed by digest so two concurrent
session-spawn calls coalesce on a single pull future. The mutex
map is bounded; eviction is LRU at 256 entries (the maximum
reasonable concurrent-pull count is low single digits — operators
with thousands of unique digests per minute are out of scope).

A second-arrival caller observes the cache hit immediately after
the first caller's atomic rename in §6 phase 4; phase 5 is
idempotent so no fairness issue arises if the second caller wins
the in-memory mutex first.

---

## §8 — GC

Two GC paths:

**Foreground.** `raxis doctor cache prune` walks every active
policy generation's `[[vm_images]] oci_digest` set, every
in-flight initiative's recorded `oci_digest`, every running
session's resolved image, and removes any `blobs/` /
`images/` entry NOT in the union. Output is a structured table of
`{digest, bytes_freed, reason}`.

**Background.** On every `policy_manager::advance_epoch` the
kernel schedules a low-priority `prune_unreferenced` call against
the new live-digest set. This is best-effort; failures log but do
not block the epoch advance. Implementation-side this is a 30-line
`tokio::spawn(async move { … })` keyed on
`policy_manager::on_epoch_advance` (an existing hook).

Neither path touches the three RAXIS-canonical images (they live
under `$RAXIS_INSTALL_DIR/`, not `$RAXIS_DATA_DIR/oci-cache/`).

---

## §9 — Failure-mode taxonomy

| `ImageResolverError`                     | Kernel `FAIL_*`                                 | When                                                |
| ---------------------------------------- | ----------------------------------------------- | --------------------------------------------------- |
| `DigestMismatch { expected, actual }`    | `FAIL_OCI_IMAGE_DIGEST_MISMATCH`                | Phase 3 of §6                                       |
| `RegistryUnreachable { host, source }`   | `FAIL_OCI_IMAGE_PULL_NETWORK`                   | Phase 2 of §6                                       |
| `RegistryAuthRejected`                   | `FAIL_OCI_IMAGE_AUTH`                           | Phase 2 (registry returned 401/403)                 |
| `RegistryNotFound`                       | `FAIL_OCI_IMAGE_NOT_FOUND`                      | Phase 2 (registry returned 404)                     |
| `RegistryServerError { status }`         | `FAIL_OCI_IMAGE_PULL_TRANSIENT`                 | Phase 2 (5xx; kernel retries up to 3× with backoff) |
| `UnsupportedMediaType { media_type }`    | `FAIL_OCI_IMAGE_UNSUPPORTED`                    | Phase 5 of §6                                       |
| `CacheCorrupted { path, source }`        | `FAIL_OCI_IMAGE_CACHE_CORRUPT`                  | Cache hit but on-disk verification re-failed        |
| `Io { path, source }`                    | `FAIL_OCI_IMAGE_CACHE_IO`                       | Filesystem error during any phase                   |

Every error variant carries enough information for the audit
record (`SecurityViolationDetected` for the `DigestMismatch` case,
`SessionSpawnFailed { reason: … }` for the others) to be
actionable without re-running the failing pull.

The `FAIL_OCI_IMAGE_PULL_TRANSIENT` 3× retry is the only place
the kernel implements automatic retry on this path — every other
error is a hard fail. Retrying a `DigestMismatch` would mask a
registry-side compromise; retrying an `AuthRejected` would
hammer a misconfigured operator credential.

---

## §10 — `policy.toml` integration

V2 extends `[[vm_images]]` with two new optional fields:

```toml
[[vm_images]]
name        = "raxis/rust:1.87"
oci_digest  = "sha256:a1b2c3d4..."
registry    = "ghcr.io/operator/raxis-rust"   # NEW: optional registry override
auth        = "operator-ghcr"                 # NEW: optional credential alias

[[vm_image_credentials]]                      # NEW: registry credentials by alias
alias       = "operator-ghcr"
mount_as    = "OCI_AUTH_GHCR"
proxy_type  = "static-bearer"
```

The credential mechanism reuses the operator-policy credential
plane already specified in [`credential-proxy.md`](credential-proxy.md): an OCI-pull is
just an HTTP request, and `static-bearer` is a degenerate
credential type with no proxy-side rewriting.

`approve_plan` validation rejects `[[vm_images]]` rows whose
`auth` alias does not resolve to a `[[vm_image_credentials]]` entry
in the same policy generation; this is shift-left of a runtime
"registry rejected our token" failure.

---

## §11 — Implementation roadmap

| File / dir                                            | Action  | Status   | Purpose                                                                                                  |
| ----------------------------------------------------- | ------- | -------- | -------------------------------------------------------------------------------------------------------- |
| `raxis/crates/image-cache/Cargo.toml`                 | NEW     | LANDED   | Crate manifest                                                                                           |
| `raxis/crates/image-cache/src/lib.rs`                 | NEW     | LANDED   | Module wiring + public re-exports                                                                        |
| `raxis/crates/image-cache/src/digest.rs`              | NEW     | LANDED   | `OciDigest` typed wrapper + `OciDigestParseError`                                                        |
| `raxis/crates/image-cache/src/registry.rs`            | NEW     | LANDED   | `RegistryRef` value type                                                                                 |
| `raxis/crates/image-cache/src/error.rs`               | NEW     | LANDED   | Full `ImageResolverError` taxonomy per §9                                                                |
| `raxis/crates/image-cache/src/resolved_image.rs`      | NEW     | LANDED   | `ResolvedImage` return type                                                                              |
| `raxis/crates/image-cache/src/resolver.rs`            | NEW     | LANDED   | `ImageResolver` async trait per §5                                                                       |
| `raxis/crates/image-cache/src/cache_layout.rs`        | NEW     | LANDED   | On-disk path scheme (§4); pure derivation, no I/O                                                        |
| `raxis/crates/image-cache/src/pre_populated.rs`       | NEW     | LANDED   | `PrePopulatedResolver` impl (resolve = lookup + verify; prune = real walk-and-unlink); kernel-test target |
| `raxis/crates/image-cache/src/pull.rs`                | NEW     | LANDED   | Production registry-pull pipeline (§6); reqwest + sha2 + tokio                                           |
| `raxis/crates/image-cache/src/extract.rs`             | NEW     | LANDED   | OCI-layer extraction; EROFS-mediatype dispatch                                                           |
| `raxis/crates/image-cache/src/production.rs`          | NEW     | LANDED   | `ProductionResolver` impl + in-memory mutex map (§7)                                                     |
| `raxis/kernel/src/session_spawn_orchestrator.rs`      | MODIFY  | DEFERRED | Replace direct `image_path` resolution with a call to `ctx.image_resolver.resolve(...)`                  |
| `raxis/kernel/src/ipc/context.rs`                     | MODIFY  | LANDED   | `image_resolver: Arc<dyn ImageResolver>` field + `with_image_resolver` swap; default = `PrePopulatedResolver` rooted at `<data_dir>/oci-cache/` |
| `raxis/cli/src/commands/doctor.rs`                    | MODIFY  | LANDED   | `raxis doctor cache prune [--dry-run] [--json]` subcommand exercising `prune_unreferenced` (§8 foreground) |
| [`raxis/specs/v2/image-cache.md`](image-cache.md)                       | THIS    | LANDED   | (you are here)                                                                                           |

The crate now ships the full V2 surface (LANDED rows): trait + on-disk
layout + failure-mode taxonomy + `PrePopulatedResolver` (offline /
test-friendly, re-hashes per call) + `ProductionResolver` (registry-
backed, talks the OCI distribution-spec v2 wire format
`GET /v2/<repo>/blobs/sha256:<hex>`, hashes-as-it-streams, atomic-renames
into the cache, and re-verifies post-extract). 38 unit tests pin
the contracts: digest parsing (canonical form, wrong algorithm,
length errors, lowercase enforcement, hex-charset enforcement,
serde round-trip, hash-equality), registry-ref construction (empty
host / repository), cache-layout path derivation (shard prefix,
extracted-dir layout, lockfile suffix, distinct-digest separation),
the `PrePopulatedResolver` (cache hit, cache miss → registry-
unreachable, on-disk digest mismatch, GC of dead digests, GC
idempotency, missing cache root), the URL builder (OCI-distribution
v2 conformance), the extractor (rootfs.img copy, synthesised
sidecars, intermediate-dir creation), and the `ProductionResolver`
end-to-end against a `hyper`-based fixture (200 → ResolvedImage,
401 → AuthRejected, 404 → NotFound, 503 → RegistryServerError,
body-vs-claimed digest mismatch, no-hint → NoRegistryHint, warm-
cache no-network resolve, prune across `images/` and `blobs/`).

The DEFERRED rows are the kernel-side plumbing: wire
`Arc<dyn ImageResolver>` into `HandlerContext`, replace the direct
`image_path` resolution in `session_spawn_orchestrator.rs` with a
`ctx.image_resolver.resolve(...)` call, and surface the
`prune_unreferenced` foreground GC through a new
`raxis doctor cache prune` subcommand. Those land as their own
follow-up so the resolver swap can be reviewed independently of
the new `ProductionResolver` implementation.
