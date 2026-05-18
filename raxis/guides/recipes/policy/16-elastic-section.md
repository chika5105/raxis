# `[elastic]` — bounded scaling + transient-failure retry

> **Topic:** Policy reference | **Time to read:** ~5 min | **Complexity:** ⭐⭐⭐ Advanced

The `[elastic]` block governs two related kernel-side mechanisms:

1. **Bounded retry on transient VM-spawn failure** — the kernel
   wraps every `IsolationBackend::spawn` call in an exponential-
   backoff loop driven by `transient_retry_*` settings. Retries
   stop the moment a permanent failure is detected
   (`INV-ELASTIC-02`) or when `transient_retry_max_attempts` is
   exhausted (`INV-ELASTIC-06`). See `specs/v2/elastic-vm-scaling.md
   §3` for the classification table.

2. **Dynamic resource adjustment** — when `enabled = true`, the
   kernel may respawn a session with `vcpus *= 2` and
   `memory_mb *= 1.5` after observing scale-up signals (memory
   pressure, IPC backpressure, tool-timeout burst, inference
   token-burn rate). It may also bias the **next** spawn smaller
   when a role's recent sessions consistently under-used their
   budget. Both directions emit `SessionVmScaleEvent` audit
   events. See `specs/v2/elastic-vm-scaling.md §4`.

The block is **optional** — omitting it from `policy.toml` keeps
elastic enabled at the V2 GA defaults.

---

## Field reference

| Field | Type | Default | Effect |
|---|---|---|---|
| `enabled` | `bool` | `true` | Master switch for **upward** scaling. When `false`, the kernel never raises capacity above the configured baseline (`INV-ELASTIC-05`). Down-bias and transient-retry remain active. |
| `max_vcpus_per_session` | `u32` | `8` | Hard ceiling on `vcpu_count` for any session, including post-scale-up. `≥` the largest `[isolation]` role baseline (`FAIL_ELASTIC_CEILING_BELOW_BASELINE`). |
| `max_memory_mb_per_session` | `u32` | `16384` (16 GiB) | Hard ceiling on `mem_mib` for any session. Same `≥ baseline` rule. |
| `max_concurrent_scaling_events_per_minute` | `u32` | `6` | Sliding-60-second admission cap on `SessionVmScaleEvent` emissions. Overflow ⇒ `SessionVmScaleDeferred { reason: "RateLimit" }` (`INV-ELASTIC-04` — soft event). |
| `transient_retry_max_attempts` | `u32` | `3` | Hard ceiling on retry attempts after a transient `IsolationError` (`INV-ELASTIC-06`). Beyond this, the kernel emits `SessionVmFailedFinal` and stops. |
| `transient_retry_initial_backoff_ms` | `u32` | `250` | First retry's backoff. Subsequent retries follow `min(initial * 2^(attempt-1), max)`. |
| `transient_retry_max_backoff_ms` | `u32` | `4000` | Ceiling on the per-retry backoff. MUST be `≥ transient_retry_initial_backoff_ms`. |

> **Plan narrows policy.** Per-task `elastic`, `min_vcpus`,
> `max_vcpus`, `min_memory_mb`, `max_memory_mb` may appear under
> `[[tasks]]`, but the plan can only **narrow** the policy
> ceilings — never expand them. A plan declaring `max_vcpus = 32`
> against a policy ceiling of `8` is rejected at admission with
> `FAIL_ELASTIC_PLAN_EXCEEDS_POLICY` (`INV-ELASTIC-01`).

---

## Example — restrictive elastic (production-conservative)

```toml
[elastic]
enabled                                = true
max_vcpus_per_session                  = 4
max_memory_mb_per_session              = 4096
max_concurrent_scaling_events_per_minute = 3
transient_retry_max_attempts           = 2
transient_retry_initial_backoff_ms     = 500
transient_retry_max_backoff_ms         = 2000
```

* Cap any single VM at 4 vCPUs / 4 GiB even after scale-up.
* Allow up to three scaling events per minute across all
  sessions; bursts above that are deferred + audited.
* Retry transient spawn failures up to twice with 500 ms / 1 s
  backoffs.

---

## Example — elastic disabled (regulatory pin)

```toml
[elastic]
enabled                                = false
# The remaining fields still apply to transient-retry; only
# upward scaling is forbidden when `enabled = false`.
transient_retry_max_attempts           = 5
transient_retry_initial_backoff_ms     = 100
transient_retry_max_backoff_ms         = 1000
```

* No `SessionVmScaleEvent { direction: "Up" }` will ever fire.
* Down-bias still applies (`§6` — never raises capacity).
* Transient retries are still enforced — they're environmental
  noise insurance, not capacity scaling.

---

## How elastic interacts with `[isolation]`

The `[elastic]` ceilings MUST be `≥` the largest `[isolation]`
role baseline:

```toml
# Required invariant:
max_vcpus_per_session     >= max(orchestrator_vcpu_count, executor_vcpu_count, reviewer_vcpu_count)
max_memory_mb_per_session >= max(orchestrator_mem_mib, executor_mem_mib, reviewer_mem_mib)
```

If a baseline is above the elastic ceiling, the policy load
fails with `FAIL_ELASTIC_CEILING_BELOW_BASELINE` — there would
be no admissible scale-up window.

---

## Audit events you'll see

| Event | When |
|---|---|
| `SessionVmRespawnAttempted { attempt, max_attempts, failure_class, previous_reason, backoff_ms }` | Each transient-retry attempt before the spawn loop succeeds or exhausts. |
| `SessionVmFailedFinal { total_attempts, failure_class, final_reason }` | Spawn lineage gave up — either retries exhausted (`failure_class = "Transient"`) or a permanent failure short-circuited (`failure_class = "Permanent"`). |
| `SessionVmScaleEvent { direction, prev_vcpus, new_vcpus, prev_memory_mb, new_memory_mb, reason }` | Admitted scaling decision. `direction = "Up"` requires `enabled = true`; `direction = "Down"` is allowed always. |
| `SessionVmScaleDeferred { direction, reason }` | Rate-limit or other soft deferral. Today's only `reason` is `"RateLimit"`. |

---

## Common errors

| Symptom | Fix |
|---|---|
| `FAIL_ELASTIC_INVALID: max_vcpus_per_session must be ≥ 1` | Raise the value or omit the field to fall through to default. |
| `FAIL_ELASTIC_CEILING_BELOW_BASELINE` | Either raise `max_vcpus_per_session` / `max_memory_mb_per_session` or lower the matching `[isolation]` role baseline. |
| `FAIL_ELASTIC_PLAN_EXCEEDS_POLICY` | The submitted plan declared a per-task `max_vcpus` or `max_memory_mb` higher than the policy ceiling. Tighten the plan. |
| `FAIL_REVIEWER_ELASTIC_NOT_ALLOWED` | Remove `min_vcpus` / `max_vcpus` / `min_memory_mb` / `max_memory_mb` from any Reviewer task; the Reviewer image's resource budget is kernel-canonical. |

---

## Related docs

* `specs/v2/elastic-vm-scaling.md` — full design (state machine,
  invariants, audit shapes).
* `guides/recipes/plan/03-tasks-block.md` — per-task elastic
  fields.
* `guides/recipes/elastic-vm-scaling.md` — worked example with
  expected audit events.
