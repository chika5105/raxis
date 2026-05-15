# RAXIS V2 — Elastic VM Scaling

> **Status:** V2 Specified
> **Cross-references:**
> - `specs/v2/host-capacity.md` — per-role baseline budgets (`[isolation]`)
>   that this spec scales above / below.
> - `specs/v2/v2-deep-spec.md §Step 12` — `max_crash_retries`
>   (operator ceiling on VM-crash retry; orthogonal to the
>   transient/permanent retry policy added here).
> - `specs/v2/extensibility-traits.md §3.5` — substrate `Backend::spawn`
>   contract + `IsolationError` variant set this spec classifies.
> - `specs/v2/audit-paired-writes.md §4.1` — `SessionVmSpawned` /
>   `SessionVmExited` paired-writes contract this spec extends.
> - `specs/invariants.md` — INV-CAPACITY-01..06 (host caps),
>   INV-PLAN-POLICY-PRECEDENCE-01 (plan/policy authority).

---

## 1. Problem statement

A RAXIS VM can fail to boot for two completely different reasons:

1. **Transient infrastructure noise.** The hypervisor scheduler missed
   a VSock boot grace, the `KernelStateBlock` (KSB) sidecar took an
   extra `flush()` for the per-initiative DAG snapshot, the boot
   loader briefly hit an O_DIRECT contention on the rootfs blob, or
   a noisy-neighbour AVF VM evicted the new VM from physical memory
   before `start()`'s completion handler fired. None of these
   conditions are reproducible — a second `Backend::spawn(...)` call
   moments later succeeds. The kernel today **fails the activation
   permanently** in every one of these cases, leaving the operator
   to retry by hand.

2. **Permanent configuration / signature failure.** The canonical image
   has the wrong digest. The plan declared a `vm_image` whose
   signature is unforgeable. The operator certificate has expired.
   The host disk is full. None of these will succeed on retry; a
   retry loop here is a denial-of-service against the substrate
   bookkeeping (each attempt re-allocates the per-session worktree
   anchor, mints a fresh CSPRNG token, and writes a `SessionVmSpawned`
   audit row that never matches its `SessionVmExited` partner).

**The kernel must distinguish these two outcome classes mechanically,
retry only the transient one, and emit operator-visible audit so an
operator post-mortem can see exactly what happened.**

The second concern is dynamic resource shaping. Today every spawn of a
given role uses the operator-declared `[isolation]` baseline budget
verbatim. If the Executor agent is mid-build and the host has
abundant headroom, the kernel cannot grant it more memory or vCPUs.
If the Reviewer's previous N sessions all idled at <30% memory
utilisation, the kernel cannot bias the next spawn smaller. The
operator either over-provisions (wastes capacity) or under-provisions
(causes timeouts and OOM-driven crash retries). **The kernel must be
allowed to scale capacity dynamically, but only within
operator-signed ceilings, and never increase capacity when the
operator has explicitly declared `elastic = false`.**

---

## 2. Schema additions

### 2.1 `policy.toml` `[elastic]`

```toml
[elastic]
# Master switch. When `false`, the kernel never increases capacity
# beyond the configured baseline (the per-role `[isolation]`
# budgets). Transient retries and downscale-on-next-spawn remain
# active — `elastic` gates only upward scaling. Default `true`.
enabled                                = true

# Operator-signed ceilings for any single per-session VM. The kernel
# clamps every dynamic-scale-up event to these values; a plan that
# declares `max_vcpus` / `max_memory_mb` larger than these values is
# rejected at admission with `FAIL_ELASTIC_PLAN_EXCEEDS_POLICY`.
max_vcpus_per_session                  = 8
max_memory_mb_per_session              = 16384

# Sliding-window rate limit on substrate-visible scaling events
# (scale-up + scale-down combined). When exceeded, scale events are
# deferred (audit `SessionVmScaleDeferred { reason: RateLimit }`),
# never silently dropped. INV-ELASTIC-04.
max_concurrent_scaling_events_per_minute = 6

# Transient-retry tunables. The classification table in §3.1 decides
# what counts as transient; these knobs decide how many times and
# how long to back off.
transient_retry_max_attempts           = 3
transient_retry_initial_backoff_ms     = 250
transient_retry_max_backoff_ms         = 4000
```

All fields are **optional**. Every default lands at validate time:
omitting `[elastic]` entirely yields `enabled = true`, the operator
ceilings shown above, the rate-limit, and the retry knobs. The
defaults are chosen to be **non-breaking for existing deployments**:
a kernel that runs without an explicit `[elastic]` block today
keeps booting after this spec lands and behaves identically modulo
the new transient-retry loop (which can only IMPROVE liveness).

The validator enforces these structural rules at policy load:

* `max_vcpus_per_session ≥ max(orchestrator_vcpu_count,
  executor_vcpu_count, reviewer_vcpu_count)` (else
  `FAIL_ELASTIC_CEILING_BELOW_BASELINE`). The ceiling cannot be
  smaller than the baseline; that combination is structurally
  inconsistent and would force every spawn to fail closed.
* `max_memory_mb_per_session ≥ max(orchestrator_mem_mib,
  executor_mem_mib, reviewer_mem_mib)` (same reason).
* `transient_retry_max_attempts ≤ 10` — a hard ceiling beyond which
  retry loops are operator-pathological. INV-ELASTIC-06.
* `transient_retry_initial_backoff_ms ≤ transient_retry_max_backoff_ms`.
* `max_concurrent_scaling_events_per_minute ≤ 60` — operator
  dashboards become illegible above one event per second.

### 2.2 `plan.toml` per-task and per-initiative `elastic`

```toml
[plan.initiative]
description = "..."
elastic     = true                     # initiative-level default; optional

[[tasks]]
task_id            = "rate_limit_implementer"
session_agent_type = "Executor"
clone_strategy     = "blobless"
path_allowlist     = ["src/auth/"]
description        = "Implement rate limiting"

# V2 elastic-vm-scaling additions (all optional):
elastic            = false             # this task uses fixed baseline
min_vcpus          = 2
max_vcpus          = 4
min_memory_mb      = 1024
max_memory_mb      = 8192
```

Resolution precedence (per `INV-PLAN-POLICY-PRECEDENCE-01` —
**plan-narrows-policy**):

| Effective `elastic` | Plan task | Plan initiative | Policy `[elastic] enabled` |
|---|---|---|---|
| `false` | declared `false` (any policy) | (any) | (any) |
| `false` | omitted | declared `false` | (any) |
| `false` | omitted | omitted | `false` |
| `true`  | declared `true` | (any) | `true` |
| `true`  | omitted | declared `true` | `true` |
| `true`  | omitted | omitted | `true` |
| **REJECTED** | declared `true` | (any) | `false` |
| **REJECTED** | (any) | declared `true` | `false` |

**INV-ELASTIC-01 (plan narrows policy).** A plan MAY disable elastic
when policy enables (the task's workload is known-bounded). A plan
MAY NOT enable elastic when policy disables — admission rejects
with `FAIL_ELASTIC_PLAN_EXCEEDS_POLICY`. A plan MAY declare
`max_vcpus` / `max_memory_mb` smaller than the policy ceiling
(narrowing). A plan MAY NOT declare `max_vcpus` / `max_memory_mb`
larger than the policy ceiling — admission rejects with
`FAIL_ELASTIC_PLAN_EXCEEDS_POLICY`.

**Reviewer tasks** MAY NOT declare any of the elastic fields
(`elastic`, `min_vcpus`, `max_vcpus`, `min_memory_mb`,
`max_memory_mb`). The Reviewer image is kernel-canonical and pinned
to a small budget by `INV-PLANNER-HARNESS-02`; allowing a plan
to scale a Reviewer would let a compromised plan starve the
operator's review surface. The validator rejects with
`FAIL_REVIEWER_ELASTIC_NOT_ALLOWED`.

`min_vcpus` / `min_memory_mb` are floor-knobs: a downscale event
never crosses below them. Their default is the operator's
`[isolation]` baseline.

### 2.3 Defaults for omitted plan fields

When the plan omits the elastic fields, the kernel resolves them as
follows:

| Field | Default |
|---|---|
| `elastic` (task) | inherit from `plan.initiative.elastic` |
| `elastic` (initiative) | inherit from `policy.[elastic].enabled` |
| `min_vcpus` | role baseline from `policy.[isolation]` |
| `max_vcpus` | `policy.[elastic].max_vcpus_per_session` |
| `min_memory_mb` | role baseline from `policy.[isolation]` |
| `max_memory_mb` | `policy.[elastic].max_memory_mb_per_session` |

The resolved values are persisted in the `PlanRegistry` so the
spawn path observes them as a single struct rather than chasing the
plan TOML at every spawn boundary.

---

## 3. State machine

### 3.1 Spawn outcome classification

`Backend::spawn` returns one of three classifications:

* **`Success`** — `Result::Ok(Box<dyn Session>)`.
* **`TransientFailure(reason)`** — the kernel must retry, subject to
  `transient_retry_max_attempts` and exponential backoff.
* **`PermanentFailure(reason)`** — the kernel MUST NOT retry; emit
  `SessionVmFailedFinal` and surface the activation-handler error.

The classification table is the **contract**: there is no
"retry-on-any-error" fallthrough. Adding a new `IsolationError`
variant requires an explicit row here.

| `IsolationError` variant | Class | Rationale |
|---|---|---|
| `SpawnFailed("vsock_boot_grace_exceeded: ...")` | Transient | Hypervisor scheduler missed the boot grace; common under noisy-neighbour AVF VMs. Retry typically succeeds. |
| `SpawnFailed("vmm_api_busy: ...")` | Transient | Firecracker/AVF API socket busy during a concurrent spawn burst. |
| `SpawnFailed("hypervisor_resource: ...")` | Transient | Substrate-internal resource (e.g. hypervisor memory pool fragmentation) requested but currently unavailable; backoff lets the host quiesce. |
| `SpawnFailed("ksb_delivery_failed: ...")` | Transient | KSB virtiofs sidecar mount race; retry re-provisions the meta dir cleanly. |
| `SpawnFailed("image_digest_mismatch")` | Permanent | The on-disk canonical image bytes do not match the signed manifest — operator must re-install. |
| `SpawnFailed("policy_violation: ...")` | Permanent | Spawn rejected by an admission gate; retrying yields the same rejection. |
| `SpawnFailed("config_invalid: ...")` | Permanent | `VmSpec` failed substrate translate (e.g. memory below substrate floor); retrying yields the same translate failure. |
| `SpawnFailed("out_of_disk_space: ...")` | Permanent | The disk-watchdog tripped (per [`host-capacity.md §7`](host-capacity.md)); retrying makes the disk pressure worse. |
| `SignatureMismatch` | Permanent | Same as image-digest mismatch; substrate's defence-in-depth check tripped. |
| `BackendInternal("kernel_module_unloaded: ...")` | Permanent | Operator must restore the substrate; retry would loop indefinitely. |
| `BackendInternal(_)` (other) | Permanent | Default for unknown backend-internal failures — fail closed. |
| `ResourceLimit(_)` | Transient | cgroup quota / FD cap reached transiently; backoff lets the host recover. |
| `TransportFault(_)` | Permanent | Ring-buffer corruption / VSock host-call boundary panic — never observed pre-spawn (the IPC transport is established last) and indicates a substrate bug rather than a noisy environment. |
| `PeerClosed` | Permanent | Same as `TransportFault` — observed only post-spawn. |

The classification is implemented in
`crates/isolation-apple-vz/src/lib.rs` (and reused by the
Firecracker substrate via the same trait method) so substrate-
specific shapes can refine the tag string while the kernel sees
a uniform `SpawnOutcomeClass`.

### 3.2 Transient-retry flow

```text
spawn_executor_for_task(...)
  ├─ attempt 0:  service.spawn_session(req)                ─┐
  │     ↳ Ok(handle)  → return handle                       │
  │     ↳ Err(e)      → classify(e)                         │
  │         ↳ Permanent → emit SessionVmFailedFinal,         │
  │                       return Err(activation rejected)   │
  │         ↳ Transient → emit SessionVmRespawnAttempted     │
  │                       sleep(backoff)                     │
  ├─ attempt 1: …                                            │
  │   …                                                      │
  └─ attempt N (= max_attempts):                              │
        ↳ Ok(handle) → return handle                          │
        ↳ Err(e)     → emit SessionVmFailedFinal              │
                       (with retry_history),                  │
                       return Err(activation rejected)        │
```

Backoff is exponential: `attempt_n_delay = min(initial *
2^(n-1), max_backoff)` with a small randomised jitter (±10%) to
spread out simultaneous re-spawns from a host-wide noisy-neighbour
event. Backoff sleeps are tokio-async (the spawn path is already
async) so they do not block the dispatch worker.

Per attempt, a `SessionVmRespawnAttempted` audit event is emitted
**before** the next `Backend::spawn` call. Each event carries
`attempt_number`, `previous_failure_reason`, and `backoff_ms`. The
final `SessionVmFailedFinal` event carries the full
`retry_history: Vec<{attempt, reason, classification}>` so an
operator post-mortem can replay the sequence.

### 3.3 Permanent-failure flow

```text
spawn_executor_for_task(...)
  ├─ attempt 0: service.spawn_session(req)
  │     ↳ Err(e) → classify(e)
  │         ↳ Permanent → emit SessionVmFailedFinal
  │                       (retry_history = []),
  │                       return Err(activation rejected)
  └─ no further attempts (INV-ELASTIC-02)
```

`SessionVmFailedFinal` is emitted exactly once per activation; it
pairs with a `SessionVmSpawned` only on the rare success-after-retry
path. The [`audit-paired-writes.md §4.1`](audit-paired-writes.md) linter is updated to treat
`SessionVmFailedFinal` as a terminal-class event that does NOT
require a `SessionVmExited` partner (the VM never reached the
"booted" milestone).

---

## 4. Dynamic resource adjustment

### 4.1 Scale-up triggers

The kernel observes the following per-session signals and converts
them into a `RespawnWithLargerResources` event when `elastic = true`:

| Signal | Source | Threshold |
|---|---|---|
| Inference token-burn rate | `InferenceCompleted` audit events / KSB | > 80% of `[budget.token_caps] max_total_tokens_per_session` within the first half of the wallclock budget |
| IPC backpressure | per-session `pending_pushes` queue depth | > 75% of `[kernel-push-protocol.md §10]` cap, sustained ≥ 30 s |
| Memory pressure | guest-reported RSS via the dispatch-loop's heartbeat | RSS > 80% of allotted `mem_mib` for ≥ 60 s |
| Tool execution timeouts | `IntentRejected { code: "TOOL_TIMEOUT" }` | ≥ 3 timeouts within 5 minutes for the same session |

Any single signal can trigger; multiple signals firing together
short-circuit to a larger jump (`vcpus *= 2` and `memory_mb *= 2`
instead of the single-signal `vcpus *= 2` and `memory_mb *= 1.5`).

### 4.2 Scale-up event flow

```text
ScalingDecisionEngine::tick()
  ├─ for each active session:
  │     ├─ collect signals (RSS, queue depth, timeout count, ...)
  │     ├─ if no trigger → continue
  │     ├─ if rate-limited (§5) →
  │     │     emit SessionVmScaleDeferred { reason: RateLimit }
  │     │     continue
  │     ├─ compute new VmSpec via build_scaled_vm_spec(...)
  │     │     (clamps to baseline when elastic = false — INV-ELASTIC-05)
  │     ├─ schedule_drain_and_respawn(session_id, new_spec)
  │     │     ├─ drain: wait for in-flight intents to complete
  │     │     │        (bounded by drain_grace_secs = 30)
  │     │     ├─ terminate_session(grace = 5s)
  │     │     ├─ emit SessionVmExited { ... }
  │     │     ├─ emit SessionVmScaleEvent { direction: Up, ... }
  │     │     ├─ spawn_session(req with new_spec) (uses §3.2 retry loop!)
  │     │     └─ emit SessionVmSpawned { ... }
  │     └─ continue
  └─ end
```

The audit emit order — `SessionVmExited` → `SessionVmScaleEvent` →
`SessionVmSpawned` — keeps the paired-writes linter happy: each
spawn pairs with an exit, and the scale event sits between them so
audit replay can attribute the new spawn to the scaling decision
(write-then-emit per `INV-ELASTIC-03`).

### 4.3 `build_scaled_vm_spec` clamping (INV-ELASTIC-05 enforcement)

```rust
fn build_scaled_vm_spec(
    baseline:   &VmSpec,
    direction:  ScaleDirection,
    multiplier: ScaleMultiplier,
    bounds:     &ElasticBounds,
    elastic:    bool,
) -> VmSpec {
    debug_assert!(
        !(direction == ScaleDirection::Up && !elastic),
        "INV-ELASTIC-05: scale-up requested for elastic=false session",
    );

    let new_vcpus = match direction {
        ScaleDirection::Up if elastic => {
            (baseline.vcpu_count * multiplier.vcpu_factor)
                .min(bounds.max_vcpus)
        }
        ScaleDirection::Up => {
            // Mechanical floor: NEVER raise vcpus when elastic = false.
            // Defence-in-depth — a debug_assert above already tripped.
            baseline.vcpu_count
        }
        ScaleDirection::Down => {
            (baseline.vcpu_count * multiplier.vcpu_factor)
                .max(bounds.min_vcpus)
        }
    };
    let new_memory_mb = ... /* same shape */;

    VmSpec { vcpu_count: new_vcpus, mem_mib: new_memory_mb, ..baseline.clone() }
}
```

The `debug_assert!` catches caller bugs in dev/test builds; the
runtime fallthrough (`baseline.vcpu_count` when `elastic = false`)
makes the production binary fail-safe even if a future refactor
removes the call-site check. **The function is the single
mechanical chokepoint** — every scale-up flows through it, so
INV-ELASTIC-05 cannot be bypassed by call-site discipline.

### 4.4 Scale-down policy

Scale-down is **only at session boundaries**. There is no live
in-place downsize — virtio-blk + virtiofs require the substrate to
re-attach the worktree mounts at boot, and AVF/Firecracker do not
support hot-removing vCPUs from a running guest cleanly.

The kernel maintains a per-role rolling window of the last N
sessions' resource utilisation (default N = 5). When ALL N
sessions reported ≤ 30% peak memory utilisation AND ≤ 50% peak
vCPU utilisation, the kernel biases the next spawn of that role
smaller:

* `vcpus = max(baseline.vcpu_count - 1, min_vcpus)`
* `memory_mb = max(baseline.mem_mib * 0.75, min_memory_mb)`

Audit `SessionVmScaleEvent { direction: Down, ... }`. **Scale-down is
allowed even when `elastic = false`** — it never raises capacity, so
the spec's "never increases capacity" rule is preserved.

---

## 5. Rate-limit enforcement

`max_concurrent_scaling_events_per_minute` is enforced at policy
admission (the `ScalingDecisionEngine`). The kernel maintains a
sliding 60-second window of `(timestamp, session_id)` pairs; on
each new scaling decision:

```text
if window.count_within(60.seconds) >= policy.max_per_minute {
    emit SessionVmScaleDeferred { session_id, reason: RateLimit, ... }
    return Skipped;
}
```

Deferred events are **soft** — the next tick of the decision engine
re-evaluates whether the signal still warrants scaling. INV-ELASTIC-04
forbids hard-failing on rate-limit overflow.

---

## 6. `elastic = false` semantics

When `elastic = false` (resolved per §2.2 precedence):

| Behaviour | Active when `elastic = false`? |
|---|---|
| Transient retry loop (§3.2) | **Yes** — transient retries are environmental noise insurance, not capacity scaling. |
| Permanent failure → fail (§3.3) | **Yes** |
| Scale-up event emission | **No** — `SessionVmScaleEvent { direction: Up }` is mechanically forbidden. |
| Scale-down on next-spawn (§4.4) | **Yes** — scale-down never increases capacity. |
| `RespawnWithLargerResources` admission | **No** — `ScalingDecisionEngine` short-circuits before computing the new spec. |
| Rate-limit accounting | N/A — no scale events to rate-limit. |

`elastic` therefore gates **exactly one mechanism**: upward
capacity scaling at the substrate boundary. Everything else
(retries, downscaling, audit) is unconditional.

---

## 7. Invariants

* **INV-ELASTIC-01.** Plan-level elastic CANNOT exceed policy-level.
  A plan-task `elastic = true` paired with `policy.[elastic] enabled
  = false` is rejected at admission with
  `FAIL_ELASTIC_PLAN_EXCEEDS_POLICY`. A plan `max_vcpus` /
  `max_memory_mb` greater than the policy ceiling is rejected with
  the same code.

* **INV-ELASTIC-02.** Permanent failures are NEVER retried. The
  classification table in §3.1 is the closed contract; the retry
  loop short-circuits on `Permanent` and emits
  `SessionVmFailedFinal` with `retry_history = []`.

* **INV-ELASTIC-03.** Scale-up emits an audit event in the same
  transaction as the new spawn. Audit emit order is
  `SessionVmExited` → `SessionVmScaleEvent { Up }` →
  `SessionVmSpawned`; the substrate boundary is crossed only after
  the scale event has been written.

* **INV-ELASTIC-04.** Rate-limit overflow is a soft event
  (`SessionVmScaleDeferred`), never a hard failure. The next
  scheduling tick re-evaluates the signal.

* **INV-ELASTIC-05.** When `elastic = false`, no
  `SessionVmScaleEvent { direction: Up }` may ever be emitted. The
  rule is enforced mechanically by `build_scaled_vm_spec` (the
  single chokepoint that constructs the new `VmSpec`) — call-site
  discipline is not load-bearing.

* **INV-ELASTIC-06.** `transient_retry_max_attempts` is a hard
  ceiling. Exceeding it surfaces as `SessionVmFailedFinal`, never
  as an infinite-retry loop. The policy validator rejects values >
  10 to keep the bound legible.

* **INV-ELASTIC-07.** All transient-classification rules are
  documented in this spec (§3.1). No implicit fallthrough to
  "retry on any error" exists; new `IsolationError` variants
  REQUIRE an explicit classification entry before they may be
  surfaced through `Backend::spawn`. The `IsolationError` →
  classification function is exhaustively matched (compiler
  enforces).

---

## 8. Audit shape

### 8.1 `SessionVmRespawnAttempted`

```jsonc
{
  "kind": "SessionVmRespawnAttempted",
  "session_id":              "...",
  "task_id":                 "..." | null,
  "initiative_id":           "...",
  "attempt_number":          1,            // 0-indexed; 0 = first retry
  "previous_failure_reason": "vsock_boot_grace_exceeded: ...",
  "previous_failure_class":  "Transient",
  "backoff_ms":              250
}
```

### 8.2 `SessionVmFailedFinal`

```jsonc
{
  "kind": "SessionVmFailedFinal",
  "session_id":     "...",
  "task_id":        "..." | null,
  "initiative_id":  "...",
  "final_reason":   "image_digest_mismatch",
  "final_class":    "Permanent" | "Transient",   // Transient only after retry exhaustion
  "retry_history": [
    { "attempt": 0, "reason": "vsock_boot_grace_exceeded", "class": "Transient" },
    { "attempt": 1, "reason": "vsock_boot_grace_exceeded", "class": "Transient" },
    { "attempt": 2, "reason": "vsock_boot_grace_exceeded", "class": "Transient" }
  ]
}
```

### 8.3 `SessionVmScaleEvent`

```jsonc
{
  "kind": "SessionVmScaleEvent",
  "session_id":     "...",
  "initiative_id":  "...",
  "direction":      "Up" | "Down",
  "trigger":        "MemoryPressure" | "TokenBurnRate" | "IpcBackpressure" |
                    "ToolTimeouts" | "PostSessionLowUtilisation",
  "previous_vcpus":     2,
  "new_vcpus":          4,
  "previous_memory_mb": 4096,
  "new_memory_mb":      6144,
  "elastic_effective":  true
}
```

### 8.4 `SessionVmScaleDeferred`

```jsonc
{
  "kind": "SessionVmScaleDeferred",
  "session_id":      "...",
  "initiative_id":   "...",
  "reason":          "RateLimit" | "ElasticDisabled" | "PlanCeilingReached",
  "deferred_at_ms":  1714500000000
}
```

`SessionVmScaleDeferred` is a single-class observability event (no
SQL row mutates), listed in the [`audit-paired-writes.md §4.3`](audit-paired-writes.md)
single-class roster.

---

## 9. Trade-offs considered

### Plan-overrides-policy vs policy-only

* **Pro plan-overrides-policy (chosen).** Heterogeneous workloads
  inside a single initiative — e.g. one Executor that compiles
  Rust and one that runs Python tests — have radically different
  resource shapes; forcing them to share the policy default wastes
  capacity for the lighter task. The plan is the operator-signed
  granular surface.
* **Con.** A plan author can mistakenly disable elastic on a task
  that needed it; the kernel cannot recover that capacity at
  runtime because plans are immutable. **Mitigation:** the policy
  default is `enabled = true`, so plan authors who omit the field
  inherit the elastic behaviour automatically; explicit
  `elastic = false` is opt-in.
* **Why not policy-only.** Policy is per-deployment and changes
  only at epoch advance; pinning every workload to policy defaults
  forces over-provisioning for the worst-case workload. Plans are
  the natural per-workload knob.

### Upper-bound vs unbounded scaling

* **Pro upper-bound (chosen).** Without an operator-signed ceiling,
  a malicious or hallucinating plan could request unbounded
  resources and drive the host to OOM. The ceiling is the only
  defence between the authority chain and the host kernel's
  page-cache.
* **Con.** The ceiling can become a bottleneck if the operator
  pre-sized it conservatively. **Mitigation:** the ceiling lives
  in policy; epoch-rotating it raises the bound for every active
  initiative simultaneously.

### In-place resize vs respawn-with-larger

* **Pro respawn-with-larger (chosen).** AVF and Firecracker both
  support hot-add of vCPUs / memory in principle, but the kernel's
  per-session state (worktree anchor, KSB sidecar, audit-paired-
  writes pending row) is bound to the original VM lifetime by the
  [`audit-paired-writes.md §4.1`](audit-paired-writes.md) contract. A respawn cleanly
  traverses the `SessionVmExited` → `SessionVmScaleEvent` →
  `SessionVmSpawned` triple, keeping the audit chain monotonic.
* **Con.** A respawn drops the in-flight model context. **Mitigation:**
  the KSB sidecar carries the per-session conversation state; the
  re-spawned VM resumes from the same KSB snapshot (this is
  already the case for crash-respawn under `max_crash_retries`).
* **Why not in-place.** In-place hot-add would force the
  paired-writes linter to evolve into a multi-class state machine
  ("the same spawn event has multiple resource shapes over its
  life"), which we considered and rejected as too complex for the
  forensic-replay model.
