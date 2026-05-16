# iter65 — follow-ups queued from the stateful-kernel audit sweep

## Stateful-kernel audit findings

The pattern that produced the iter64 root cause (Bug 0):
"in-memory map shadow-tracks state that already lives in the DB;
the in-memory copy diverges; the cap/check/policy reads the
wrong value." The iter65 sweep walked every
`Mutex<HashMap<...>>` / `RwLock<HashMap<...>>` / `OnceCell<...>`
/ `Lazy<...>` site in the kernel and supporting crates and
classified each. Sites are listed by file path; classification
is one of:

* **OK** — not a violation. Either the mapping has no
  DB-persisted equivalent (process-wide IPC plumbing,
  short-lived runtime tokens, transient performance projections
  that are invalidated on every read or carry a TTL), or the
  cache is downstream of an immutable artifact that the kernel
  re-reads at every consult site.
* **FIXED-IN-THIS-PR** — was a violation; fixed in iter65.
* **FOLLOWUP-QUEUED** — possible violation that warrants a
  separate look but is not in the iter65 scope.

| Site | Class | Reasoning |
|------|-------|-----------|
| `crates/session-spawn/src/lib.rs::SessionSpawnService.sessions` | **FIXED-IN-THIS-PR** (Bug 0) | The map is no longer the source of truth for `active_count()`; that now reads from `sessions` table. The map remains as a per-session runtime-handle store (substrate handle, credential proxy, egress allowlist) — it carries values not derivable from the DB row, and the cap decision no longer reads it. `INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01`. |
| `kernel/src/session_activity.rs::SessionActivityTracker.inner` | **OK** | Transient kernel-internal projection of the most recent IntentRequest outcome on the IPC stream. Not persisted to DB by design — the SessionActivity is an observation of the IPC wire shape, not a fact about kernel state. The map IS the source of truth for the kernel-observed last-intent attribution. No drift class. |
| `kernel/src/push/mod.rs::KernelPushDispatcher.sessions` | **OK** | Process-wide `broadcast::Sender` registry per session. The sender handles are runtime IPC plumbing — they cannot be reconstructed from DB state. Subscribers re-attach on session re-attach; no policy decision reads the sender count. |
| `kernel/src/push/initiative_bus.rs::channels` | **OK** | Same shape as `KernelPushDispatcher` — per-initiative broadcast channels, runtime pub/sub plumbing, not DB state. |
| `kernel/src/notifications/handler/sidecar.rs::by_id` | **OK** | Per-process sidecar-handler registry; the row holds `Arc<SidecarChannelState>` runtime handles (subprocess, mpsc::Sender). Not DB-derivable. |
| `kernel/src/handlers/tproxy_admit.rs::TunnelRegistry.by_id` | **OK** | Single-use tunnel registry: tokens are minted on admission and consumed by the tunnel listener within seconds. Tokens never persist to DB (they live in-process for security — leaving them in SQLite would broaden the attack surface). No drift class because there is no DB row to drift against. |
| `kernel/src/elastic.rs::Tracker.inner` | **OK** | Per-role utilisation samples for autoscaling. Bounded ring buffer (VecDeque), in-process by design (the autoscaler reads the last N samples; persisting to SQLite would be a write-amplification anti-pattern). No DB equivalent. |
| `kernel/src/canonical_images_preflight.rs::image_kind_cache` | **OK** | TTL-bounded performance cache for image-format detection. Each entry stores a hash + classification; on a hit the cache short-circuits a re-read of the image bytes. The kernel re-resolves the canonical image path on every spawn so a stale entry is at most a one-spawn miss. |
| `kernel/src/initiatives/plan_registry.rs::PlanRegistry` | **OK** | Process-wide projection of the immutable `signed_plan_artifacts` row. `repopulate_from_store` loads the registry on every kernel boot from the signed artifact bytes; no drift class because the artifact is content-addressable. |
| `crates/image-cache/src/production.rs::Production.pulls` | **OK** | Per-pull dedupe locks (`Arc<Mutex<()>>`); no DB state. |
| `crates/egress-admission/src/stall_tracker.rs::StallTracker.state` | **OK** | Transient stall-detection windows (per-host token buckets). In-process by design; no DB equivalent. |
| `crates/dashboard-kernel/src/{task_llm_capture,stream_capture,session_capture}.rs` | **OK** | Read-side dashboard capture buffers. The dashboard is a pure projection over the kernel store; these caches buffer transient streaming wire fragments before they land in the audit chain. No drift class because the captures are always replayed from the chain on dashboard restart. |
| `crates/credential-proxy-cloud-shared/src/cache.rs::TokenCache` | **OK** | TTL-bounded token cache with safety window (`cache_safety_window_seconds`). The upstream IAM token has a strict expiry; this cache short-circuits re-fetching but never drives a policy decision past the TTL. |
| `crates/planner-core/src/circuit.rs::entries` | **OK** | Planner-side circuit-breaker state. Lives in the planner process, not the kernel; the planner is allowed in-process state because each VM is short-lived. |
| `kernel/src/handlers/escalation.rs` LineageRateLimits | **OK** | Already DB-backed (`lineage_rate_limits` table). The "escalation rate limiter" the user asked about for `EscalationRateLimitExceeded` reads + writes the SQLite table inside the same transaction as the rejection emit. |

### Summary

- **Violations found:** 1 (the iter64 root cause, `SessionSpawnService.sessions`).
- **Violations fixed in this PR:** 1 (Bug 0).
- **Followups queued for a future PR:** 0.

The iter65 sweep was thorough; no additional kernel-as-cache
violations surfaced beyond Bug 0. The `Mutex<HashMap>` /
`RwLock<HashMap>` shapes that DO exist in the kernel are either
runtime IPC plumbing (push dispatcher, broadcast channels,
process registries), bounded performance caches with TTL or
content-addressable invalidation (image kind cache, plan
registry, token caches), or in-memory observations of streaming
wire shapes that have no DB equivalent (session activity,
utilisation samples, stall tracker).

If a future iter regression surfaces a new violation, file it
into a fresh `iter*-followups.md` with the same
classification grid. The pattern to look for: a
`Mutex<HashMap<K, V>>` whose key K is also a primary key in the
SQLite schema AND whose value V is read for a cap / admission /
dispatch / signature decision AND whose write is not
atomically paired with the matching DB write.
