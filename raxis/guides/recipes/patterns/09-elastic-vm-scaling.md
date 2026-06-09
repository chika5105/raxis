# Pattern: elastic VM scaling (transient retry + dynamic resize)

> **Topic:** Plan + policy patterns | **Time to read:** ~6 min | **Complexity:** ⭐⭐⭐ Advanced

The kernel's elastic-VM subsystem does **two** things that are
often confused:

1. **Bounded retry on transient VM-spawn failure** — environmental
   noise (vsock timeout, KSB delivery hiccup, hypervisor transient
   resource exhaustion) gets a small budget of exponential-backoff
   retries before the kernel gives up. This applies *whether or
   not* `enabled = true` (`INV-ELASTIC-02` keeps permanent
   failures un-retried; transient retry is environmental insurance,
   not capacity scaling).
2. **Dynamic resource adjustment** — when scale-up signals fire
   (memory pressure, IPC backpressure, tool-timeout burst,
   inference token-burn rate), the kernel may **respawn** a session
   with `vcpus *= 2` and `memory_mb *= 1.5` (capped by the policy
   ceilings). It can also *bias the next spawn smaller* when a
   role's recent sessions consistently under-used their budget.

Setting `[elastic].enabled = false` (or `elastic = false` on a
specific task) disables only the **upward** scaling — transient
retry and down-bias remain active. This lets a regulated
deployment pin baseline VM sizes without losing transient-failure
recovery.

---

## When to use this pattern

* **A long-running Executor task occasionally OOMs** with
  `IsolationError::HypervisorTransientResource` or hits memory
  pressure mid-tool-execution. Elastic respawn-with-larger
  rescues the task without operator intervention.
* **An Orchestrator running a wide DAG saturates its IPC ring**
  during fan-in and the kernel observes IPC backpressure. Scale
  the Orchestrator vCPUs up by one factor.
* **A role whose recent sessions ran under 30% RSS / 25% vCPU
  for the last three sessions** is wasting host budget. Bias
  the *next* spawn smaller and pocket the headroom.

If your concern is *retry on bad agent output* (Reviewer
rejection, crash-after-spawn), see
[`patterns/04-retry-on-failure`](04-retry-on-failure.md). Elastic
is about VM-substrate health, not agent verdicts.

---

## Policy side

```toml
# policy.toml

[elastic]
enabled                                = true
max_vcpus_per_session                  = 8
max_memory_mb_per_session              = 16384
max_concurrent_scaling_events_per_minute = 6
transient_retry_max_attempts           = 3
transient_retry_initial_backoff_ms     = 250
transient_retry_max_backoff_ms         = 4000
```

* The kernel will retry up to **3** transient spawn failures with
  250 ms / 500 ms / 1 s backoffs (capped at 4 s).
* Up to **6** scaling decisions will be admitted per rolling 60-
  second window. Burst beyond that ⇒ `SessionVmScaleDeferred`.
* `vcpus` may grow to 8 and `memory_mb` to 16 GiB even after
  scale-up.

> **Hard rule.** Both ceilings MUST be `≥` the largest
> `[isolation]` role baseline, or policy load fails with
> `FAIL_ELASTIC_CEILING_BELOW_BASELINE`.

---

## Plan side

### Task that opts out of upward scaling

```toml
[plan.initiative]
description = "Cross-cutting type-system refactor"

[workspace]
name        = "ts-refactor"
lane_id     = "default"
repository  = "main"
target_ref  = "refs/heads/main"

[[tasks]]
task_name              = "compile-types"
session_agent_type   = "Executor"
clone_strategy       = "blobless"
path_allowlist       = ["crates/types/"]
predecessors         = []
description        = "Compile Types"
prompt             = """Recompile every dependent type. Should not need extra cores."""

# Pin baseline regardless of scale-up signals.
elastic              = false
```

The kernel still:

* Retries transient spawn failures up to the policy budget.
* Bias the *next* spawn smaller if this session ends with
  under-30% peak RSS and under-25% peak vCPU.

The kernel will **never** emit `SessionVmScaleEvent { direction: "Up" }`
for this task (`INV-ELASTIC-05`).

### Task that narrows the policy ceiling

```toml
[[tasks]]
task_name              = "wide-fanout-merge"
session_agent_type   = "Executor"
clone_strategy       = "sparse"
path_allowlist       = ["src/", "tests/"]
predecessors         = ["compile-types"]
description        = "Wide Fanout Merge"
prompt             = """Apply the merge across N files, expects bursty memory."""

# Plan can NARROW — never widen — the policy.
min_vcpus            = 4
max_vcpus            = 6           # ≤ policy.elastic.max_vcpus_per_session = 8
min_memory_mb        = 4096
max_memory_mb        = 12288       # ≤ policy.elastic.max_memory_mb_per_session = 16384
```

Submitting with `max_vcpus = 16` (above the policy ceiling)
fails admission with `FAIL_ELASTIC_PLAN_EXCEEDS_POLICY`
(`INV-ELASTIC-01`).

> **Reviewer tasks must NOT declare any of `min_vcpus` /
> `max_vcpus` / `min_memory_mb` / `max_memory_mb`.** The
> Reviewer image's resource budget is kernel-canonical;
> declaring them fails admission with
> `FAIL_REVIEWER_ELASTIC_NOT_ALLOWED`.

---

## Audit timeline you'll see

A "happy path" elastic-up scenario on a task spawning at the
default 2 vCPUs / 2048 MiB and observing memory pressure:

```text
SessionVmSpawned       { session_id: S1, vcpus: 2, memory_mb: 2048 }
…
SessionVmScaleEvent    { session_id: S1, direction: "Up",
                          prev_vcpus: 2, new_vcpus: 4,
                          prev_memory_mb: 2048, new_memory_mb: 3072,
                          reason: "MemoryPressure" }
SessionVmExited        { session_id: S1, reason: "ScaledUp" }
SessionVmSpawned       { session_id: S2, vcpus: 4, memory_mb: 3072 }
…
SessionVmExited        { session_id: S2, reason: "Completed" }
```

A flaky-substrate transient-retry scenario:

```text
SessionVmRespawnAttempted { attempt: 1, max_attempts: 3,
                             failure_class: "Transient",
                             previous_reason: "HypervisorTransientResource",
                             backoff_ms: 250 }
SessionVmRespawnAttempted { attempt: 2, max_attempts: 3,
                             failure_class: "Transient",
                             previous_reason: "HypervisorTransientResource",
                             backoff_ms: 500 }
SessionVmSpawned          { session_id: S1, vcpus: 2, memory_mb: 2048 }
```

A permanent-failure scenario (no retries):

```text
SessionVmFailedFinal      { total_attempts: 1,
                             failure_class: "Permanent",
                             final_reason: "ImageDigestMismatch" }
```

A rate-limit overflow scenario (sixth scaling decision in a
60-second window when the cap is 6):

```text
SessionVmScaleEvent       { direction: "Up", … }    # admitted
SessionVmScaleEvent       { direction: "Up", … }    # admitted
SessionVmScaleEvent       { direction: "Up", … }    # admitted
SessionVmScaleEvent       { direction: "Up", … }    # admitted
SessionVmScaleEvent       { direction: "Up", … }    # admitted
SessionVmScaleEvent       { direction: "Up", … }    # admitted
SessionVmScaleDeferred    { direction: "Up", reason: "RateLimit" }   # 7th
```

The deferral is **soft** (`INV-ELASTIC-04`) — the seventh
candidate is recorded as deferred, not failed; the next session
that triggers a scale signal will be re-evaluated against the
sliding window.

---

## Verification (how you'd inspect this in the field)

```bash
# Show the resolved policy (defaults are filled in).
raxis policy show --section elastic

# Watch elastic events live.
raxis log tail --filter 'kind in {SessionVmRespawnAttempted,
                                  SessionVmFailedFinal,
                                  SessionVmScaleEvent,
                                  SessionVmScaleDeferred}'

# Show scale-up history for one session.
raxis explain --session-id <SID> --include scale-events
```

---

## Common errors

| Symptom | Fix |
|---|---|
| `FAIL_ELASTIC_PLAN_EXCEEDS_POLICY` | Plan declared a `max_vcpus` / `max_memory_mb` above the policy ceiling. Tighten the plan; never edit the signed policy at submission time. |
| `FAIL_REVIEWER_ELASTIC_NOT_ALLOWED` | Remove all `min_vcpus` / `max_vcpus` / `min_memory_mb` / `max_memory_mb` from any Reviewer task. |
| `FAIL_ELASTIC_CEILING_BELOW_BASELINE` | The policy `[elastic]` ceiling is below the largest `[isolation]` role baseline. Raise the elastic ceiling or lower the matching baseline. |
| `SessionVmFailedFinal { failure_class: "Transient" }` | Retries exhausted. Investigate the substrate (vsock health, hypervisor disk space, FD limit). Tune `transient_retry_*` only after fixing the root cause. |
| `SessionVmFailedFinal { failure_class: "Permanent" }` | The kernel correctly refused to retry — usually `ImageDigestMismatch`, `PolicyViolation`, or `ConfigInvalid`. Fix the policy / image and resubmit. |
| Frequent `SessionVmScaleDeferred { reason: "RateLimit" }` | Either raise `max_concurrent_scaling_events_per_minute` (operator decision) or investigate why so many sessions need to scale at once (likely an under-provisioned baseline). |

---

## Reference

| Topic | Source |
|---|---|
| Spec (normative) | [`specs/v2/elastic-vm-scaling.md`](../../../specs/v2/elastic-vm-scaling.md) |
| Policy schema | [`guides/recipes/policy/16-elastic-section.md`](../policy/16-elastic-section.md) |
| Plan field reference | [`guides/recipes/plan/03-tasks-block.md`](../plan/03-tasks-block.md) |
| Kernel implementation | `raxis/kernel/src/elastic.rs`, `raxis/kernel/src/session_spawn_orchestrator.rs` |
| Audit event kinds | `raxis/crates/audit/src/event.rs` |
| Isolation classification | `raxis/crates/isolation/src/lib.rs` (`IsolationFailureClass`) |

---

## Related patterns

* [`patterns/04-retry-on-failure`](04-retry-on-failure.md) —
  agent-verdict retries (`RetrySubTask`), distinct from VM-spawn
  retries.
* [`patterns/08-budget-bounded-cohort`](08-budget-bounded-cohort.md)
  — when the right answer is to throttle concurrency rather
  than scale individual sessions.
