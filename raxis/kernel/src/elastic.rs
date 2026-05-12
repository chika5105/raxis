//! Kernel-side dynamic resource adjustment — the chokepoint that
//! turns scaling signals into [`raxis_isolation::VmSpec`] mutations.
//!
//! Normative reference: `specs/v2/elastic-vm-scaling.md §4`.
//!
//! # Why a dedicated module
//!
//! INV-ELASTIC-05 requires that **upward capacity scaling is
//! mechanically forbidden when `elastic = false`**. Per
//! `elastic-vm-scaling.md §4.3` ("the function is the single
//! mechanical chokepoint"), every scale-up flows through
//! [`build_scaled_vm_spec`]. Splitting it into its own module:
//!
//! * Keeps the chokepoint review-discoverable (one file, one set of
//!   tests).
//! * Lets the operator-visible decision API ([`decide_scale_up`])
//!   compose the chokepoint with the elastic-config gates (policy
//!   `enabled`, plan `elastic`, plan ceilings) without duplicating
//!   the clamping logic.
//! * Provides a stable seam for future rate-limit (c8) and
//!   scale-down (c7) wiring.
//!
//! # What this module does NOT do
//!
//! * **Does not own signal collection.** The actual observation of
//!   RSS, IPC backpressure, and tool-execution timeouts (`§4.1`)
//!   lives outside this module. Observers feed [`ScaleSignal`]
//!   values into [`decide_scale_up`]; this module is purely the
//!   decision + clamping layer.
//! * **Does not own the drain-and-respawn orchestration.** The
//!   actual respawn-with-larger flow (`§4.2`) is performed by
//!   `session_spawn_orchestrator::respawn_with_larger_resources`
//!   which calls into this module for the new `VmSpec` and for the
//!   audit emission, then delegates to the bounded-retry helper
//!   for the new spawn.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use parking_lot::Mutex;
use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_isolation::VmSpec;
use raxis_policy::ElasticConfig;

// ---------------------------------------------------------------------------
// ScaleDirection / ScaleSignal / ScaleMultiplier
// ---------------------------------------------------------------------------

/// Direction of a scaling decision. The audit projection uses the
/// `as_str()` form (`"Up"` / `"Down"`); dashboards key on the exact
/// PascalCase string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScaleDirection {
    /// Capacity increase. Gated by `elastic = true` (INV-ELASTIC-05).
    Up,
    /// Capacity decrease. Allowed even when `elastic = false`
    /// (`elastic-vm-scaling.md §6` — never raises capacity).
    Down,
}

impl ScaleDirection {
    /// Stable PascalCase string for the audit projection.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Up   => "Up",
            Self::Down => "Down",
        }
    }
}

/// Operator-visible signals that can trigger an upward scaling
/// decision per `elastic-vm-scaling.md §4.1`.
///
/// Multiple signals firing for the same session collapse into a
/// single decision per scheduling tick — the multiplier is
/// computed via [`ScaleMultiplier::for_signals`] so a multi-signal
/// trigger jumps further than a single-signal trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScaleSignal {
    /// Token-burn rate exceeded the §4.1 threshold.
    InferenceBurnRate,
    /// IPC `pending_pushes` queue depth sustained ≥ 75% of the
    /// kernel-push-protocol cap for ≥ 30 s.
    IpcBackpressure,
    /// Guest-reported RSS sustained > 80% of `mem_mib` for ≥ 60 s.
    MemoryPressure,
    /// ≥ 3 tool-execution timeouts within 5 minutes.
    ToolTimeoutBurst,
}

impl ScaleSignal {
    /// Stable string projection for audit / structured-log output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InferenceBurnRate => "InferenceBurnRate",
            Self::IpcBackpressure   => "IpcBackpressure",
            Self::MemoryPressure    => "MemoryPressure",
            Self::ToolTimeoutBurst  => "ToolTimeoutBurst",
        }
    }
}

/// Multiplier the scaling decision applies to vCPUs and memory.
///
/// Per `elastic-vm-scaling.md §4.1`, a single-signal trigger uses
/// `vcpus *= 2` and `memory_mb *= 1.5`; a multi-signal trigger uses
/// `vcpus *= 2` and `memory_mb *= 2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScaleMultiplier {
    /// vCPU multiplier. `2` for both single-signal and multi-signal
    /// scale-up; future tuning may distinguish.
    pub vcpu_factor:   u32,
    /// Memory multiplier numerator (denominator is fixed at 2). A
    /// value of `3` ⇒ memory `*= 1.5`; `4` ⇒ memory `*= 2.0`.
    /// Encoded as a fraction so we can express `*= 1.5` without
    /// dragging floating-point into the kernel.
    pub mem_num:       u32,
    /// Memory multiplier denominator. Fixed at `2` to keep the
    /// arithmetic exact for the §4.1 single-signal `*= 1.5` case.
    pub mem_den:       u32,
}

impl ScaleMultiplier {
    /// Single-signal scale-up: `vcpus *= 2`, `memory_mb *= 1.5`.
    pub const SINGLE_SIGNAL: Self = Self { vcpu_factor: 2, mem_num: 3, mem_den: 2 };
    /// Multi-signal scale-up: `vcpus *= 2`, `memory_mb *= 2`.
    pub const MULTI_SIGNAL:  Self = Self { vcpu_factor: 2, mem_num: 4, mem_den: 2 };
    /// Scale-down on next-spawn (`§4.4`): `vcpus -= 1`,
    /// `memory_mb *= 0.75`. We encode the vCPU rule via a special
    /// sentinel — `vcpu_factor = 0` means "subtract one" — because
    /// the multiplier struct cannot encode subtraction directly
    /// without invalidating the scale-up arithmetic. The
    /// [`build_scaled_vm_spec`] function recognises this sentinel
    /// when `direction = Down`.
    pub const NEXT_SPAWN_DOWN: Self = Self { vcpu_factor: 0, mem_num: 3, mem_den: 4 };

    /// Pick the multiplier matching the firing-signal count.
    #[must_use]
    pub fn for_signal_count(n: usize) -> Self {
        if n >= 2 { Self::MULTI_SIGNAL } else { Self::SINGLE_SIGNAL }
    }
}

// ---------------------------------------------------------------------------
// ElasticBounds — resolved bounds used by the chokepoint
// ---------------------------------------------------------------------------

/// Bounds enforced on every scaling decision. Combines the
/// operator-policy ceilings with any per-task plan overrides.
///
/// Plan overrides can only NARROW the policy ceiling
/// (INV-ELASTIC-01); the resolution to a single `ElasticBounds`
/// is performed by [`ElasticBounds::resolve`] and rejects
/// over-broad plan values defensively (the plan validator
/// already enforces the rule, but the chokepoint re-checks so
/// upstream regressions cannot silently bypass it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElasticBounds {
    /// Minimum vCPU count for any spec produced by the chokepoint.
    /// Sourced from plan `min_vcpus` when present, else `1`.
    pub min_vcpus:     u32,
    /// Maximum vCPU count for any spec produced by the chokepoint.
    /// `min(policy.[elastic].max_vcpus_per_session, plan.max_vcpus)`.
    pub max_vcpus:     u32,
    /// Minimum memory MiB. Sourced from plan `min_memory_mb` when
    /// present, else the policy `[isolation]` minimum is honoured by
    /// the substrate; this struct just clamps to `min_memory_mb`.
    pub min_memory_mb: u32,
    /// Maximum memory MiB.
    /// `min(policy.[elastic].max_memory_mb_per_session,
    ///      plan.max_memory_mb)`.
    pub max_memory_mb: u32,
}

/// Per-task plan-level elastic overrides. Field-by-field optional
/// because the plan TOML's `[[plan.tasks]]` block declares each
/// override independently (`elastic-vm-scaling.md §2`).
#[derive(Debug, Clone, Copy, Default)]
pub struct PlanElasticOverrides {
    /// `[[plan.tasks]] elastic = false` ⇒ `Some(false)`. Plan-level
    /// `false` always wins (plan narrows policy per INV-ELASTIC-01).
    pub elastic:        Option<bool>,
    /// `[[plan.tasks]] min_vcpus = N`.
    pub min_vcpus:      Option<u32>,
    /// `[[plan.tasks]] max_vcpus = N`. Validated `≤
    /// policy.[elastic].max_vcpus_per_session` at admission.
    pub max_vcpus:      Option<u32>,
    /// `[[plan.tasks]] min_memory_mb = N`.
    pub min_memory_mb:  Option<u32>,
    /// `[[plan.tasks]] max_memory_mb = N`. Validated `≤
    /// policy.[elastic].max_memory_mb_per_session` at admission.
    pub max_memory_mb:  Option<u32>,
}

impl ElasticBounds {
    /// Resolve bounds from the live policy bundle + the per-task
    /// plan overrides.
    ///
    /// **INV-ELASTIC-01 defence-in-depth.** If the plan declares a
    /// `max_*` higher than the policy ceiling, the resolver clamps
    /// to the policy ceiling rather than honouring the plan value.
    /// The plan validator (`initiatives::lifecycle::
    /// validate_elastic_against_policy`) already rejects this case
    /// at admission with `FAIL_ELASTIC_PLAN_EXCEEDS_POLICY`; the
    /// re-clamp here is a fail-safe for any future regression that
    /// lets a non-conforming plan reach the spawn boundary.
    #[must_use]
    pub fn resolve(elastic: &ElasticConfig, plan: &PlanElasticOverrides) -> Self {
        let max_vcpus = plan.max_vcpus
            .unwrap_or(elastic.max_vcpus_per_session)
            .min(elastic.max_vcpus_per_session);
        let max_memory_mb = plan.max_memory_mb
            .unwrap_or(elastic.max_memory_mb_per_session)
            .min(elastic.max_memory_mb_per_session);
        let min_vcpus     = plan.min_vcpus.unwrap_or(1).max(1);
        let min_memory_mb = plan.min_memory_mb.unwrap_or(0);
        Self {
            min_vcpus:     min_vcpus.min(max_vcpus),
            max_vcpus,
            min_memory_mb: min_memory_mb.min(max_memory_mb),
            max_memory_mb,
        }
    }
}

// ---------------------------------------------------------------------------
// ScaleDecision — the chokepoint's output
// ---------------------------------------------------------------------------

/// Outcome of a scaling decision.
///
/// `Apply` carries the new `VmSpec` the caller should respawn with
/// AND the old/new vcpu / memory pair the caller stamps into the
/// `SessionVmScaleEvent` audit. `Skip` carries a stable PascalCase
/// reason tag suitable for structured logging.
#[derive(Debug, Clone)]
pub enum ScaleDecision {
    /// The decision was admitted. Caller should respawn with
    /// `new_spec` and emit `SessionVmScaleEvent` via
    /// [`emit_scale_event_audit`] (or the matching helper for the
    /// rate-limit-deferred case in c8).
    Apply {
        /// New `VmSpec` post-clamping. Already enforces
        /// INV-ELASTIC-05 at the chokepoint.
        new_spec:        VmSpec,
        /// Echo of `prev_spec.vcpu_count` for the audit event.
        prev_vcpus:      u32,
        /// Echo of `new_spec.vcpu_count`.
        new_vcpus:       u32,
        /// Echo of `prev_spec.mem_mib`.
        prev_memory_mb:  u32,
        /// Echo of `new_spec.mem_mib`.
        new_memory_mb:   u32,
        /// Direction (`Up` or `Down`) the caller stamps into the
        /// audit event.
        direction:       ScaleDirection,
        /// Reason tag — for scale-up this is the dominant signal
        /// kind (or `"MultiSignal"` when multiple fired); for
        /// scale-down this is `"NextSpawnUnderUtilised"`.
        reason:          String,
    },
    /// The decision was rejected before reaching the chokepoint.
    /// Stable PascalCase reason — closed set:
    ///
    ///   * `"ElasticDisabledPolicy"` — `policy.[elastic].enabled = false`.
    ///   * `"ElasticDisabledPlan"`   — `plan.[[tasks]] elastic = false`.
    ///   * `"NoSignal"`              — no signals fired this tick.
    ///   * `"AtCeiling"`             — already at `bounds.max_*`.
    ///
    /// Rate-limited deferral is reported via the c8
    /// `SessionVmScaleDeferred` audit event, not via this variant.
    Skip {
        /// Reason tag (closed set documented above).
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// build_scaled_vm_spec — the §4.3 chokepoint
// ---------------------------------------------------------------------------

/// Compute a new [`VmSpec`] from `baseline` according to
/// `direction`, `multiplier`, and `bounds`.
///
/// **INV-ELASTIC-05 mechanical enforcement.** When `elastic = false`
/// AND `direction = ScaleDirection::Up`:
///
///   * `debug_assert!` trips in dev/test builds (call-site bug).
///   * The runtime fallthrough returns `baseline.clone()` verbatim
///     (no vCPU bump, no memory bump). A future refactor that
///     accidentally removes the call-site `elastic` gate cannot
///     produce a scaled-up spec — the function returns the
///     baseline.
///
/// **Scale-down (INV-ELASTIC-06 unaffected).** Down-scaling is
/// allowed regardless of `elastic` per `elastic-vm-scaling.md §6`;
/// the function clamps `new_vcpus` to `max(.., bounds.min_vcpus)`
/// and `new_memory_mb` to `max(.., bounds.min_memory_mb)`.
///
/// Other `VmSpec` fields (`egress_tier`, `cgroup_quota`,
/// `boot_args`, `entrypoint_argv`, `session_token`, `vsock_cid`,
/// `virtio_fs_mounts`, `linux_kernel_path`, `env`,
/// `guest_console_log`) are inherited verbatim from `baseline`.
/// The session token in particular MUST remain identical so the
/// kernel ↔ guest auth contract survives the respawn.
#[must_use]
pub fn build_scaled_vm_spec(
    baseline:   &VmSpec,
    direction:  ScaleDirection,
    multiplier: ScaleMultiplier,
    bounds:     &ElasticBounds,
    elastic:    bool,
) -> VmSpec {
    debug_assert!(
        !(direction == ScaleDirection::Up && !elastic),
        "INV-ELASTIC-05: build_scaled_vm_spec called with direction = Up \
         and elastic = false; the call site failed to gate. Production \
         falls through to the baseline-clamp path; dev/test trips here.",
    );

    let new_vcpus = match direction {
        ScaleDirection::Up if elastic => {
            baseline.vcpu_count
                .saturating_mul(multiplier.vcpu_factor)
                .min(bounds.max_vcpus)
                .max(bounds.min_vcpus)
        }
        ScaleDirection::Up => {
            // INV-ELASTIC-05 runtime fallthrough.
            baseline.vcpu_count
        }
        ScaleDirection::Down => {
            // The vcpu_factor = 0 sentinel encodes "subtract one"
            // for the §4.4 next-spawn down-bias; otherwise treat
            // vcpu_factor as a divisor (so vcpus = baseline / 2 etc.
            // is expressible if a future tuning needs it). For the
            // shipped down-policy the sentinel is the only path.
            let raw = if multiplier.vcpu_factor == 0 {
                baseline.vcpu_count.saturating_sub(1)
            } else {
                baseline.vcpu_count / multiplier.vcpu_factor.max(1)
            };
            raw.max(bounds.min_vcpus).min(bounds.max_vcpus)
        }
    };

    let new_memory_mb = match direction {
        ScaleDirection::Up if elastic => {
            mul_frac_clamped(
                baseline.mem_mib,
                multiplier.mem_num,
                multiplier.mem_den,
            )
            .min(bounds.max_memory_mb)
            .max(bounds.min_memory_mb)
        }
        ScaleDirection::Up => baseline.mem_mib,
        ScaleDirection::Down => {
            mul_frac_clamped(
                baseline.mem_mib,
                multiplier.mem_num,
                multiplier.mem_den,
            )
            .max(bounds.min_memory_mb)
            .min(bounds.max_memory_mb)
        }
    };

    let mut spec = baseline.clone();
    spec.vcpu_count = new_vcpus;
    spec.mem_mib    = new_memory_mb;
    spec
}

/// `value * num / den` with saturating arithmetic. Used by
/// [`build_scaled_vm_spec`] to express `mem_mib *= 1.5` (`num=3,
/// den=2`) and `mem_mib *= 0.75` (`num=3, den=4`) without
/// floating-point.
#[inline]
fn mul_frac_clamped(value: u32, num: u32, den: u32) -> u32 {
    let den = den.max(1);
    let scaled: u64 = (value as u64).saturating_mul(num as u64);
    u32::try_from(scaled / den as u64).unwrap_or(u32::MAX)
}

// ---------------------------------------------------------------------------
// decide_scale_up — composition of the gates + the chokepoint
// ---------------------------------------------------------------------------

/// Top-level scale-up decision per `elastic-vm-scaling.md §4.2`.
///
/// Composition (in order):
///   1. **Plan elastic gate.** `plan.elastic = Some(false)` ⇒
///      `Skip("ElasticDisabledPlan")` (INV-ELASTIC-01).
///   2. **Policy elastic gate.** `policy.[elastic].enabled = false`
///      ⇒ `Skip("ElasticDisabledPolicy")` (INV-ELASTIC-05).
///   3. **No-signal gate.** `signals.is_empty()` ⇒
///      `Skip("NoSignal")`.
///   4. **At-ceiling gate.** Already at `bounds.max_*` on both
///      axes ⇒ `Skip("AtCeiling")`.
///   5. **Chokepoint.** [`build_scaled_vm_spec`] computes the new
///      spec; the result is wrapped in `Apply { ... }` with the
///      reason set to the dominant signal (or `"MultiSignal"`).
///
/// Rate-limit accounting (c8) is performed by the caller AFTER
/// this function returns `Apply` — the caller emits
/// `SessionVmScaleDeferred` and skips the respawn instead of
/// admitting the new spec. Centralising the rate-limit downstream
/// keeps this function a pure decision (no shared state).
#[must_use]
pub fn decide_scale_up(
    baseline: &VmSpec,
    signals:  &[ScaleSignal],
    elastic:  &ElasticConfig,
    plan:     &PlanElasticOverrides,
) -> ScaleDecision {
    if matches!(plan.elastic, Some(false)) {
        return ScaleDecision::Skip { reason: "ElasticDisabledPlan".to_owned() };
    }
    if !elastic.enabled {
        return ScaleDecision::Skip { reason: "ElasticDisabledPolicy".to_owned() };
    }
    if signals.is_empty() {
        return ScaleDecision::Skip { reason: "NoSignal".to_owned() };
    }

    let bounds = ElasticBounds::resolve(elastic, plan);
    if baseline.vcpu_count >= bounds.max_vcpus
        && baseline.mem_mib >= bounds.max_memory_mb
    {
        return ScaleDecision::Skip { reason: "AtCeiling".to_owned() };
    }

    let multiplier = ScaleMultiplier::for_signal_count(signals.len());
    let new_spec   = build_scaled_vm_spec(
        baseline,
        ScaleDirection::Up,
        multiplier,
        &bounds,
        true, // elastic admitted by gate above
    );

    // If the chokepoint produced a spec identical to the baseline
    // (already-at-ceiling on every axis after multiplier
    // application), surface that as `AtCeiling` rather than
    // emitting a no-op `SessionVmScaleEvent`.
    if new_spec.vcpu_count == baseline.vcpu_count
        && new_spec.mem_mib == baseline.mem_mib
    {
        return ScaleDecision::Skip { reason: "AtCeiling".to_owned() };
    }

    let reason = if signals.len() >= 2 {
        "MultiSignal".to_owned()
    } else {
        signals[0].as_str().to_owned()
    };

    let prev_vcpus     = baseline.vcpu_count;
    let prev_memory_mb = baseline.mem_mib;
    let new_vcpus      = new_spec.vcpu_count;
    let new_memory_mb  = new_spec.mem_mib;
    ScaleDecision::Apply {
        new_spec,
        prev_vcpus,
        new_vcpus,
        prev_memory_mb,
        new_memory_mb,
        direction: ScaleDirection::Up,
        reason,
    }
}

// ---------------------------------------------------------------------------
// Scale-down history — `ScaleDownHistory` tracker
// ---------------------------------------------------------------------------

/// Stable identifier for the resource-budget role the tracker keys
/// utilisation samples by. The mapping `(install role) → RoleKey`
/// is intentionally narrow — the kernel has exactly three classes
/// of long-running VMs that consume operator-tunable resource
/// budgets per `host-capacity.md §4.1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoleKey {
    /// Canonical Orchestrator session
    /// (`OrchestratorSpawnContext::vcpu_count` /
    /// `mem_mib`).
    Orchestrator,
    /// Executor sessions
    /// (`ExecutorSpawnContext::executor_vcpu_count` /
    /// `executor_mem_mib`).
    Executor,
    /// Reviewer sessions
    /// (`ExecutorSpawnContext::reviewer_vcpu_count` /
    /// `reviewer_mem_mib`).
    Reviewer,
}

impl RoleKey {
    /// Stable string projection — used for structured-log output
    /// only (the audit event projects role through the
    /// session-agent-type field, not through the `RoleKey`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Orchestrator => "Orchestrator",
            Self::Executor     => "Executor",
            Self::Reviewer     => "Reviewer",
        }
    }
}

/// One session's peak resource utilisation as measured by the
/// substrate's heartbeat / per-tick sampler. The kernel records a
/// fresh `UtilisationSample` for every session that completes
/// successfully (terminations on permanent failure are excluded —
/// they don't carry meaningful utilisation history).
///
/// Percentages are rounded to whole percent (`u8`) so the tracker's
/// rolling window stays compact even under heavy session churn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtilisationSample {
    /// Peak resident-set-size during the session, as a percent of
    /// the allotted `mem_mib`. Sourced from the dispatch loop's
    /// heartbeat (when present) or the VMM's RSS read on
    /// `terminate_session`.
    pub peak_memory_pct: u8,
    /// Peak vCPU saturation during the session, as a percent.
    pub peak_vcpu_pct:   u8,
}

/// Defaults for the §4.4 down-bias triggers. Constants live here
/// (rather than in `policy.toml`) because the scale-down rule is
/// a kernel-internal heuristic, not an operator-tuneable; bumping
/// the threshold is a kernel change, not a policy bump.
pub mod scale_down_thresholds {
    /// Window size N — the tracker keeps the most recent N
    /// utilisation samples per role and biases the next spawn
    /// smaller only when ALL N are under the thresholds.
    pub const WINDOW_SIZE: usize = 5;
    /// Memory utilisation must be `≤ MEMORY_PCT` for every sample
    /// in the window to bias smaller. Per
    /// `elastic-vm-scaling.md §4.4`.
    pub const MEMORY_PCT:  u8 = 30;
    /// vCPU utilisation must be `≤ VCPU_PCT` for every sample.
    pub const VCPU_PCT:    u8 = 50;
}

/// Per-role rolling window of recent utilisation samples.
///
/// Construct ONE instance at kernel boot, share it across every
/// spawn path (`OrchestratorSpawnContext`, `ExecutorSpawnContext`)
/// via `Arc::clone`. Recording (`record_sample`) is `&self` and
/// thread-safe; the tracker holds a `parking_lot::Mutex` over the
/// per-role queues internally so concurrent terminations in a
/// busy initiative do not need external coordination.
///
/// **Correctness note.** The tracker is per-process; restart
/// resets the windows. This is by design — the §4.4 heuristic is
/// behavioural feedback, not a hard policy contract; throwing
/// away the window across restarts is a benign loss of one tick
/// of capacity tuning. Persisting the window into SQLite would
/// invite stale-data drift across operator-driven kernel
/// rolls and is explicitly out of scope.
pub struct ScaleDownHistory {
    inner: Mutex<HashMap<RoleKey, VecDeque<UtilisationSample>>>,
    window_size: usize,
}

impl ScaleDownHistory {
    /// Construct a fresh tracker with the §4.4 default window
    /// size (`scale_down_thresholds::WINDOW_SIZE = 5`).
    #[must_use]
    pub fn new() -> Self {
        Self::with_window_size(scale_down_thresholds::WINDOW_SIZE)
    }

    /// Construct a tracker with a custom window size. Used by
    /// unit tests to drive shorter windows.
    #[must_use]
    pub fn with_window_size(window_size: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            window_size: window_size.max(1),
        }
    }

    /// Append `sample` to the rolling window for `role`. The
    /// oldest sample is evicted when the window is full
    /// (FIFO). Idempotent at the per-call level — the caller is
    /// expected to dedupe on session_id BEFORE calling so a
    /// double-record on a flaky observer does not skew the
    /// window.
    pub fn record_sample(&self, role: RoleKey, sample: UtilisationSample) {
        let mut guard = self.inner.lock();
        let queue = guard.entry(role).or_insert_with(|| {
            VecDeque::with_capacity(self.window_size)
        });
        if queue.len() >= self.window_size {
            queue.pop_front();
        }
        queue.push_back(sample);
    }

    /// Snapshot the current samples for `role`. Returns an empty
    /// `Vec` when no samples have landed yet. Used by tests + by
    /// `decide_scale_down` to evaluate the §4.4 trigger.
    #[must_use]
    pub fn samples(&self, role: RoleKey) -> Vec<UtilisationSample> {
        self.inner
            .lock()
            .get(&role)
            .map(|q| q.iter().copied().collect())
            .unwrap_or_default()
    }

    /// `true` when the rolling window for `role` is full AND every
    /// sample is below the §4.4 thresholds. Returns `false` when
    /// the window is not yet full — the kernel will not bias
    /// smaller until it has seen at least N consecutive
    /// well-behaved sessions, so a freshly-restarted kernel
    /// always spawns at the operator-configured baseline.
    #[must_use]
    pub fn should_downscale(&self, role: RoleKey) -> bool {
        let guard = self.inner.lock();
        let Some(queue) = guard.get(&role) else { return false; };
        if queue.len() < self.window_size {
            return false;
        }
        queue.iter().all(|s| {
            s.peak_memory_pct <= scale_down_thresholds::MEMORY_PCT
                && s.peak_vcpu_pct <= scale_down_thresholds::VCPU_PCT
        })
    }

    /// Reset the window for `role`. Used by callers after a
    /// successful down-bias has been applied so the next round of
    /// samples starts from a clean slate (otherwise a single
    /// down-biased session would never accrue enough history to
    /// down-bias again, but the previous samples would persist
    /// indefinitely).
    pub fn clear(&self, role: RoleKey) {
        self.inner.lock().remove(&role);
    }
}

impl Default for ScaleDownHistory {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// decide_scale_down — §4.4 next-spawn down-bias decision
// ---------------------------------------------------------------------------

/// Decide whether the kernel should bias the next spawn for
/// `role` smaller than `baseline`.
///
/// **`elastic = false` is intentionally ignored.** Per
/// `elastic-vm-scaling.md §6`, scale-down is allowed regardless of
/// the elastic flag because it never raises capacity — the
/// "never increase capacity beyond baseline" rule is preserved.
/// The function therefore does NOT consult `elastic.enabled` or
/// `plan.elastic`.
///
/// Returns `Apply { direction = Down, ... }` when:
///
///   * `history.should_downscale(role)` is `true` AND
///   * The chokepoint produced a spec strictly smaller than
///     `baseline` (otherwise the bias would be a no-op).
///
/// Otherwise returns `Skip { reason }` with one of:
///
///   * `"InsufficientHistory"` — fewer than N samples yet.
///   * `"AboveThresholds"` — at least one recent sample blew
///     past the memory or vCPU threshold.
///   * `"AtFloor"` — already at the bounds floor; nothing to bias.
#[must_use]
pub fn decide_scale_down(
    baseline: &VmSpec,
    elastic:  &ElasticConfig,
    plan:     &PlanElasticOverrides,
    history:  &ScaleDownHistory,
    role:     RoleKey,
) -> ScaleDecision {
    if !history.should_downscale(role) {
        // Distinguish "not enough samples" from "samples blew
        // through the thresholds" so structured logs are useful.
        let samples = history.samples(role);
        let reason = if samples.len() < scale_down_thresholds::WINDOW_SIZE {
            "InsufficientHistory"
        } else {
            "AboveThresholds"
        };
        return ScaleDecision::Skip { reason: reason.to_owned() };
    }

    let bounds = ElasticBounds::resolve(elastic, plan);
    if baseline.vcpu_count <= bounds.min_vcpus
        && baseline.mem_mib <= bounds.min_memory_mb
    {
        return ScaleDecision::Skip { reason: "AtFloor".to_owned() };
    }

    let new_spec = build_scaled_vm_spec(
        baseline,
        ScaleDirection::Down,
        ScaleMultiplier::NEXT_SPAWN_DOWN,
        &bounds,
        // `elastic` is irrelevant for Down (the chokepoint only
        // gates Up); pass `true` so the function takes the
        // arithmetic path, not the baseline-fallthrough.
        true,
    );

    if new_spec.vcpu_count == baseline.vcpu_count
        && new_spec.mem_mib == baseline.mem_mib
    {
        return ScaleDecision::Skip { reason: "AtFloor".to_owned() };
    }

    let prev_vcpus     = baseline.vcpu_count;
    let prev_memory_mb = baseline.mem_mib;
    let new_vcpus      = new_spec.vcpu_count;
    let new_memory_mb  = new_spec.mem_mib;
    ScaleDecision::Apply {
        new_spec,
        prev_vcpus,
        new_vcpus,
        prev_memory_mb,
        new_memory_mb,
        direction: ScaleDirection::Down,
        reason:    "NextSpawnUnderUtilised".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// emit_scale_event_audit — INV-ELASTIC-03 helper
// ---------------------------------------------------------------------------

/// Emit `SessionVmScaleEvent` for an admitted [`ScaleDecision::Apply`].
///
/// **INV-ELASTIC-03.** Callers MUST emit this AFTER the new
/// `SessionVmSpawned` lands (write-then-emit). The helper does not
/// itself sequence audit emissions — it is a thin wrapper around
/// `AuditSink::emit` that constructs the event with the correct
/// field shape so call sites cannot misformat the wire payload.
///
/// Returns `Ok(())` on successful emission; audit-disk failures
/// surface as `AuditWriterError` so the caller can log + treat as
/// non-fatal (the new VM is already running; the loss of the scale
/// event is dashboard-visible but does not invalidate the spawn).
pub fn emit_scale_event_audit(
    audit:           &Arc<dyn AuditSink>,
    session_id:      &str,
    task_id:         Option<&str>,
    initiative_id:   &str,
    direction:       ScaleDirection,
    prev_vcpus:      u32,
    new_vcpus:       u32,
    prev_memory_mb:  u32,
    new_memory_mb:   u32,
    reason:          &str,
) -> Result<(), raxis_audit_tools::AuditWriterError> {
    audit.emit(
        AuditEventKind::SessionVmScaleEvent {
            session_id:    session_id.to_owned(),
            task_id:       task_id.map(str::to_owned),
            initiative_id: initiative_id.to_owned(),
            direction:     direction.as_str().to_owned(),
            prev_vcpus,
            new_vcpus,
            prev_memory_mb,
            new_memory_mb,
            reason:        reason.to_owned(),
        },
        Some(session_id),
        task_id,
        Some(initiative_id),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_isolation::{EgressTier, SessionToken};

    fn baseline_vmspec(vcpu: u32, mem: u32) -> VmSpec {
        VmSpec {
            vcpu_count:        vcpu,
            mem_mib:           mem,
            egress_tier:       EgressTier::Tier1Tproxy,
            cgroup_quota:      None,
            boot_args:         Vec::new(),
            entrypoint_argv:   Vec::new(),
            session_token:     SessionToken("token".into()),
            vsock_cid:         None,
            virtio_fs_mounts:  Vec::new(),
            linux_kernel_path: std::path::PathBuf::new(),
            env:               std::collections::BTreeMap::new(),
            guest_console_log: None,
        }
    }

    fn elastic_default() -> ElasticConfig {
        ElasticConfig {
            enabled:                                  true,
            max_vcpus_per_session:                    8,
            max_memory_mb_per_session:                16 * 1024,
            max_concurrent_scaling_events_per_minute: 6,
            transient_retry_max_attempts:             3,
            transient_retry_initial_backoff_ms:       250,
            transient_retry_max_backoff_ms:           4_000,
        }
    }

    // -----------------------------------------------------------------
    // build_scaled_vm_spec — INV-ELASTIC-05 chokepoint pinning
    // -----------------------------------------------------------------

    #[test]
    fn scale_up_when_elastic_true_doubles_vcpus_and_mem15x() {
        let base = baseline_vmspec(2, 1024);
        let bounds = ElasticBounds {
            min_vcpus:     1,
            max_vcpus:     8,
            min_memory_mb: 256,
            max_memory_mb: 16_384,
        };
        let spec = build_scaled_vm_spec(
            &base,
            ScaleDirection::Up,
            ScaleMultiplier::SINGLE_SIGNAL,
            &bounds,
            true,
        );
        assert_eq!(spec.vcpu_count, 4);
        assert_eq!(spec.mem_mib,    1_536); // 1024 * 1.5
    }

    #[test]
    fn scale_up_clamps_to_policy_ceiling() {
        let base = baseline_vmspec(6, 12_000);
        let bounds = ElasticBounds {
            min_vcpus:     1,
            max_vcpus:     8,
            min_memory_mb: 256,
            max_memory_mb: 16_384,
        };
        let spec = build_scaled_vm_spec(
            &base,
            ScaleDirection::Up,
            ScaleMultiplier::SINGLE_SIGNAL,
            &bounds,
            true,
        );
        assert_eq!(spec.vcpu_count, 8);       // 6*2 = 12, clamped to 8
        assert_eq!(spec.mem_mib,    16_384);  // 12000*1.5 = 18000, clamped
    }

    #[test]
    fn scale_up_with_elastic_false_returns_baseline() {
        // INV-ELASTIC-05: production fallthrough returns baseline
        // verbatim even if a (broken) caller passes Up + elastic=false.
        let base = baseline_vmspec(2, 1024);
        let bounds = ElasticBounds {
            min_vcpus:     1,
            max_vcpus:     8,
            min_memory_mb: 256,
            max_memory_mb: 16_384,
        };
        // We can't test the debug_assert path in release-mode tests
        // (the `panic` would also fail the test); instead we pin the
        // production fallthrough by flipping a cfg-guarded flag.
        // The runtime path returns the baseline verbatim.
        if !cfg!(debug_assertions) {
            let spec = build_scaled_vm_spec(
                &base,
                ScaleDirection::Up,
                ScaleMultiplier::SINGLE_SIGNAL,
                &bounds,
                false,
            );
            assert_eq!(spec.vcpu_count, base.vcpu_count);
            assert_eq!(spec.mem_mib,    base.mem_mib);
        }
    }

    #[test]
    fn scale_down_subtracts_one_vcpu_and_drops_mem_to_75pct() {
        let base = baseline_vmspec(4, 2_048);
        let bounds = ElasticBounds {
            min_vcpus:     1,
            max_vcpus:     8,
            min_memory_mb: 256,
            max_memory_mb: 16_384,
        };
        let spec = build_scaled_vm_spec(
            &base,
            ScaleDirection::Down,
            ScaleMultiplier::NEXT_SPAWN_DOWN,
            &bounds,
            true,
        );
        assert_eq!(spec.vcpu_count, 3);     // 4 - 1
        assert_eq!(spec.mem_mib,    1_536); // 2048 * 0.75
    }

    #[test]
    fn scale_down_respects_min_floor() {
        let base = baseline_vmspec(1, 256);
        let bounds = ElasticBounds {
            min_vcpus:     1,
            max_vcpus:     8,
            min_memory_mb: 256,
            max_memory_mb: 16_384,
        };
        let spec = build_scaled_vm_spec(
            &base,
            ScaleDirection::Down,
            ScaleMultiplier::NEXT_SPAWN_DOWN,
            &bounds,
            true,
        );
        // 1 - 1 = 0, clamped to min_vcpus = 1
        assert_eq!(spec.vcpu_count, 1);
        // 256 * 0.75 = 192, clamped to min_memory_mb = 256
        assert_eq!(spec.mem_mib, 256);
    }

    // -----------------------------------------------------------------
    // decide_scale_up — gate composition
    // -----------------------------------------------------------------

    #[test]
    fn decide_scale_up_admits_single_signal() {
        let base    = baseline_vmspec(2, 1024);
        let elastic = elastic_default();
        let plan    = PlanElasticOverrides::default();
        let signals = [ScaleSignal::MemoryPressure];
        let dec = decide_scale_up(&base, &signals, &elastic, &plan);
        match dec {
            ScaleDecision::Apply {
                new_spec, prev_vcpus, new_vcpus,
                prev_memory_mb, new_memory_mb,
                direction, reason,
            } => {
                assert_eq!(direction, ScaleDirection::Up);
                assert_eq!(prev_vcpus, 2);
                assert_eq!(new_vcpus, 4);
                assert_eq!(prev_memory_mb, 1_024);
                assert_eq!(new_memory_mb, 1_536);
                assert_eq!(new_spec.vcpu_count, 4);
                assert_eq!(reason, "MemoryPressure");
            }
            ScaleDecision::Skip { reason } => panic!("expected Apply, got Skip({reason})"),
        }
    }

    #[test]
    fn decide_scale_up_multi_signal_uses_2x_memory() {
        let base    = baseline_vmspec(2, 1024);
        let elastic = elastic_default();
        let plan    = PlanElasticOverrides::default();
        let signals = [
            ScaleSignal::MemoryPressure,
            ScaleSignal::IpcBackpressure,
        ];
        match decide_scale_up(&base, &signals, &elastic, &plan) {
            ScaleDecision::Apply { new_spec, reason, .. } => {
                assert_eq!(new_spec.vcpu_count, 4);
                assert_eq!(new_spec.mem_mib,    2_048); // 1024 * 2
                assert_eq!(reason, "MultiSignal");
            }
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn decide_scale_up_skips_when_policy_disabled() {
        let base    = baseline_vmspec(2, 1024);
        let mut elastic = elastic_default();
        elastic.enabled = false;
        let plan    = PlanElasticOverrides::default();
        let signals = [ScaleSignal::MemoryPressure];
        match decide_scale_up(&base, &signals, &elastic, &plan) {
            ScaleDecision::Skip { reason } => assert_eq!(reason, "ElasticDisabledPolicy"),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn decide_scale_up_skips_when_plan_disabled_even_if_policy_enabled() {
        let base    = baseline_vmspec(2, 1024);
        let elastic = elastic_default();
        let plan    = PlanElasticOverrides {
            elastic: Some(false),
            ..PlanElasticOverrides::default()
        };
        let signals = [ScaleSignal::MemoryPressure];
        match decide_scale_up(&base, &signals, &elastic, &plan) {
            ScaleDecision::Skip { reason } => assert_eq!(reason, "ElasticDisabledPlan"),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn decide_scale_up_skips_when_no_signal() {
        let base    = baseline_vmspec(2, 1024);
        let elastic = elastic_default();
        let plan    = PlanElasticOverrides::default();
        let signals: [ScaleSignal; 0] = [];
        match decide_scale_up(&base, &signals, &elastic, &plan) {
            ScaleDecision::Skip { reason } => assert_eq!(reason, "NoSignal"),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn decide_scale_up_skips_at_ceiling() {
        let base    = baseline_vmspec(8, 16_384);
        let elastic = elastic_default();
        let plan    = PlanElasticOverrides::default();
        let signals = [ScaleSignal::MemoryPressure];
        match decide_scale_up(&base, &signals, &elastic, &plan) {
            ScaleDecision::Skip { reason } => assert_eq!(reason, "AtCeiling"),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn decide_scale_up_clamps_to_plan_max_when_narrower_than_policy() {
        // Plan says max_vcpus = 4 (≤ policy 8). After 2*2 = 4, we're
        // at the plan ceiling on vCPU axis but memory still has
        // headroom — Apply with 4 vcpus, 1.5x memory.
        let base    = baseline_vmspec(2, 1024);
        let elastic = elastic_default();
        let plan    = PlanElasticOverrides {
            max_vcpus: Some(4),
            ..PlanElasticOverrides::default()
        };
        let signals = [ScaleSignal::IpcBackpressure];
        match decide_scale_up(&base, &signals, &elastic, &plan) {
            ScaleDecision::Apply { new_spec, .. } => {
                assert_eq!(new_spec.vcpu_count, 4);
                assert_eq!(new_spec.mem_mib,    1_536);
            }
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // ElasticBounds::resolve — INV-ELASTIC-01 defence-in-depth
    // -----------------------------------------------------------------

    #[test]
    fn bounds_resolve_clamps_plan_max_to_policy_ceiling() {
        // Plan says max_vcpus = 16 but policy allows only 8.
        // Resolver clamps to 8 (defence-in-depth).
        let elastic = elastic_default();
        let plan    = PlanElasticOverrides {
            max_vcpus: Some(16),
            ..PlanElasticOverrides::default()
        };
        let bounds = ElasticBounds::resolve(&elastic, &plan);
        assert_eq!(bounds.max_vcpus, 8);
    }

    #[test]
    fn bounds_resolve_honours_plan_max_when_narrower() {
        let elastic = elastic_default();
        let plan    = PlanElasticOverrides {
            max_vcpus:     Some(4),
            max_memory_mb: Some(2_048),
            ..PlanElasticOverrides::default()
        };
        let bounds = ElasticBounds::resolve(&elastic, &plan);
        assert_eq!(bounds.max_vcpus,     4);
        assert_eq!(bounds.max_memory_mb, 2_048);
    }

    // -----------------------------------------------------------------
    // ScaleMultiplier projection
    // -----------------------------------------------------------------

    #[test]
    fn multiplier_for_signal_count_picks_single_or_multi() {
        assert_eq!(ScaleMultiplier::for_signal_count(0), ScaleMultiplier::SINGLE_SIGNAL);
        assert_eq!(ScaleMultiplier::for_signal_count(1), ScaleMultiplier::SINGLE_SIGNAL);
        assert_eq!(ScaleMultiplier::for_signal_count(2), ScaleMultiplier::MULTI_SIGNAL);
        assert_eq!(ScaleMultiplier::for_signal_count(99), ScaleMultiplier::MULTI_SIGNAL);
    }

    #[test]
    fn scale_direction_as_str_round_trip() {
        assert_eq!(ScaleDirection::Up.as_str(),   "Up");
        assert_eq!(ScaleDirection::Down.as_str(), "Down");
    }

    #[test]
    fn scale_signal_as_str_round_trip() {
        assert_eq!(ScaleSignal::InferenceBurnRate.as_str(), "InferenceBurnRate");
        assert_eq!(ScaleSignal::IpcBackpressure.as_str(),   "IpcBackpressure");
        assert_eq!(ScaleSignal::MemoryPressure.as_str(),    "MemoryPressure");
        assert_eq!(ScaleSignal::ToolTimeoutBurst.as_str(),  "ToolTimeoutBurst");
    }

    // -----------------------------------------------------------------
    // ScaleDownHistory + decide_scale_down — §4.4 down-bias pinning
    // -----------------------------------------------------------------

    #[test]
    fn history_empty_does_not_downscale() {
        let h = ScaleDownHistory::new();
        assert!(!h.should_downscale(RoleKey::Executor));
    }

    #[test]
    fn history_partial_window_does_not_downscale() {
        let h = ScaleDownHistory::new();
        for _ in 0..(scale_down_thresholds::WINDOW_SIZE - 1) {
            h.record_sample(
                RoleKey::Executor,
                UtilisationSample { peak_memory_pct: 10, peak_vcpu_pct: 10 },
            );
        }
        // Window not yet full → no downscale, even though all
        // samples are well under threshold.
        assert!(!h.should_downscale(RoleKey::Executor));
    }

    #[test]
    fn history_full_window_under_threshold_downscales() {
        let h = ScaleDownHistory::new();
        for _ in 0..scale_down_thresholds::WINDOW_SIZE {
            h.record_sample(
                RoleKey::Executor,
                UtilisationSample { peak_memory_pct: 20, peak_vcpu_pct: 30 },
            );
        }
        assert!(h.should_downscale(RoleKey::Executor));
    }

    #[test]
    fn history_one_blown_sample_blocks_downscale() {
        let h = ScaleDownHistory::new();
        for _ in 0..(scale_down_thresholds::WINDOW_SIZE - 1) {
            h.record_sample(
                RoleKey::Executor,
                UtilisationSample { peak_memory_pct: 20, peak_vcpu_pct: 30 },
            );
        }
        h.record_sample(
            RoleKey::Executor,
            // Memory at the threshold is fine; just over kicks us out.
            UtilisationSample { peak_memory_pct: 50, peak_vcpu_pct: 30 },
        );
        assert!(!h.should_downscale(RoleKey::Executor));
    }

    #[test]
    fn history_evicts_oldest_when_window_full() {
        let h = ScaleDownHistory::with_window_size(3);
        for pct in [80, 80, 80] {
            h.record_sample(
                RoleKey::Executor,
                UtilisationSample { peak_memory_pct: pct, peak_vcpu_pct: 30 },
            );
        }
        // Now push three under-threshold samples; the over-threshold
        // history must evict.
        for _ in 0..3 {
            h.record_sample(
                RoleKey::Executor,
                UtilisationSample { peak_memory_pct: 20, peak_vcpu_pct: 30 },
            );
        }
        assert!(h.should_downscale(RoleKey::Executor));
    }

    #[test]
    fn history_keys_per_role_independently() {
        let h = ScaleDownHistory::new();
        for _ in 0..scale_down_thresholds::WINDOW_SIZE {
            h.record_sample(
                RoleKey::Executor,
                UtilisationSample { peak_memory_pct: 20, peak_vcpu_pct: 30 },
            );
        }
        // Reviewer has no history; must NOT downscale even though
        // Executor would.
        assert!(h.should_downscale(RoleKey::Executor));
        assert!(!h.should_downscale(RoleKey::Reviewer));
    }

    #[test]
    fn decide_scale_down_admits_when_history_says_yes() {
        let history = ScaleDownHistory::new();
        for _ in 0..scale_down_thresholds::WINDOW_SIZE {
            history.record_sample(
                RoleKey::Executor,
                UtilisationSample { peak_memory_pct: 20, peak_vcpu_pct: 30 },
            );
        }
        let base    = baseline_vmspec(2, 1024);
        let elastic = elastic_default();
        let plan    = PlanElasticOverrides::default();
        match decide_scale_down(&base, &elastic, &plan, &history, RoleKey::Executor) {
            ScaleDecision::Apply {
                new_vcpus, new_memory_mb, direction, reason, ..
            } => {
                assert_eq!(direction, ScaleDirection::Down);
                assert_eq!(new_vcpus, 1);     // 2 - 1
                assert_eq!(new_memory_mb, 768); // 1024 * 0.75
                assert_eq!(reason, "NextSpawnUnderUtilised");
            }
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn decide_scale_down_skips_when_no_history() {
        let history = ScaleDownHistory::new();
        let base    = baseline_vmspec(2, 1024);
        let elastic = elastic_default();
        let plan    = PlanElasticOverrides::default();
        match decide_scale_down(&base, &elastic, &plan, &history, RoleKey::Executor) {
            ScaleDecision::Skip { reason } => assert_eq!(reason, "InsufficientHistory"),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn decide_scale_down_skips_when_blown_recent_sample() {
        let history = ScaleDownHistory::new();
        for i in 0..scale_down_thresholds::WINDOW_SIZE {
            // Last sample blows the threshold.
            let mem = if i + 1 == scale_down_thresholds::WINDOW_SIZE { 90 } else { 20 };
            history.record_sample(
                RoleKey::Executor,
                UtilisationSample { peak_memory_pct: mem, peak_vcpu_pct: 30 },
            );
        }
        let base    = baseline_vmspec(2, 1024);
        let elastic = elastic_default();
        let plan    = PlanElasticOverrides::default();
        match decide_scale_down(&base, &elastic, &plan, &history, RoleKey::Executor) {
            ScaleDecision::Skip { reason } => assert_eq!(reason, "AboveThresholds"),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn decide_scale_down_skips_at_floor() {
        let history = ScaleDownHistory::new();
        for _ in 0..scale_down_thresholds::WINDOW_SIZE {
            history.record_sample(
                RoleKey::Executor,
                UtilisationSample { peak_memory_pct: 20, peak_vcpu_pct: 30 },
            );
        }
        // Already at the floor (1 vcpu, 0 memory after applying
        // bounds.min_memory_mb default 0 — we pin a custom plan
        // override to say "min memory = 1024" so the floor is
        // visible).
        let base    = baseline_vmspec(1, 1024);
        let elastic = elastic_default();
        let plan    = PlanElasticOverrides {
            min_memory_mb: Some(1024),
            ..PlanElasticOverrides::default()
        };
        match decide_scale_down(&base, &elastic, &plan, &history, RoleKey::Executor) {
            ScaleDecision::Skip { reason } => assert_eq!(reason, "AtFloor"),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn decide_scale_down_admits_even_when_elastic_disabled() {
        // INV-ELASTIC-05 is about UPWARD scaling. Down-bias is
        // unaffected by the elastic flag because it never raises
        // capacity (`elastic-vm-scaling.md §6`).
        let history = ScaleDownHistory::new();
        for _ in 0..scale_down_thresholds::WINDOW_SIZE {
            history.record_sample(
                RoleKey::Executor,
                UtilisationSample { peak_memory_pct: 20, peak_vcpu_pct: 30 },
            );
        }
        let base    = baseline_vmspec(2, 1024);
        let mut elastic = elastic_default();
        elastic.enabled = false;
        let plan    = PlanElasticOverrides::default();
        match decide_scale_down(&base, &elastic, &plan, &history, RoleKey::Executor) {
            ScaleDecision::Apply { direction: ScaleDirection::Down, .. } => {}
            other => panic!("expected Apply Down, got {other:?}"),
        }
    }

    #[test]
    fn history_clear_resets_role() {
        let h = ScaleDownHistory::new();
        for _ in 0..scale_down_thresholds::WINDOW_SIZE {
            h.record_sample(
                RoleKey::Executor,
                UtilisationSample { peak_memory_pct: 20, peak_vcpu_pct: 30 },
            );
        }
        assert!(h.should_downscale(RoleKey::Executor));
        h.clear(RoleKey::Executor);
        assert!(!h.should_downscale(RoleKey::Executor));
    }

    #[test]
    fn role_key_as_str_round_trip() {
        assert_eq!(RoleKey::Orchestrator.as_str(), "Orchestrator");
        assert_eq!(RoleKey::Executor.as_str(),     "Executor");
        assert_eq!(RoleKey::Reviewer.as_str(),     "Reviewer");
    }
}
