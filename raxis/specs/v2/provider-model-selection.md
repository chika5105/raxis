# RAXIS V2 — Provider and Model Selection

> **Status.** Normative for V2. This spec is the canonical home for
> per-role inference model selection, the `[provider_aliases_defaults]`
> policy schema, and the operator-facing decision framework for picking
> chains.
>
> **Cross-references.**
> - `provider-failure-handling.md` — alias-chain resolution, circuit
>   breaker, retry policy, audit trail (the *mechanism*; this spec is
>   the *guidance + defaulting layer* on top)
> - `policy-plan-authority.md §4 [orchestrator]` — Orchestrator's
>   policy-pinned alias selection
> - `policy-plan-authority.md §4 [provider_aliases_defaults]` — the
>   defaultable per-role alias chains consumed by `plan prepare`
> - `operator-ergonomics.md §5 plan prepare`, `§16 setup wizard` —
>   integration points for ergonomic defaulting
> - `v1/peripherals.md §3 raxis-gateway` — gateway as the credential
>   boundary; `<data_dir>/providers/` storage location
> - `environment-access-control.md §5b.4` — reserved
>   `override_reviewer_alias` field for V2.x per-environment overrides
> - `invariants.md INV-02A`, `INV-02B`, `INV-PROVIDER-01` — the
>   mediation and credential-isolation guarantees this spec rests on
> - `extensibility-traits.md §7` — `InferenceRouter` trait; the
>   resolved `(provider_id, model_id)` this spec produces is consumed
>   by an `InferenceRouter` impl (V2 default = `HttpsGatewayRouter`).
>   Operators on a `LocalVllmRouter` deployment configure
>   `[provider_aliases_defaults]` exactly the same way — the policy
>   schema is unchanged across routers; only the boot-site router
>   selection differs.

---

## §1 — Why this spec exists

A new operator who has just walked through `raxis-cli setup wizard` has
provider API keys configured and a working policy bundle, but they
still face four authoring decisions before their first plan submission:

1. Which model to use for the **Orchestrator** (kernel-managed; one
   choice per deployment).
2. Which model to use for the **Reviewer** (per-plan; chosen via the
   `reviewer` alias).
3. Which model to use for each **Executor** task (per-task via
   profile).
4. Whether to put any of these on a **fallback chain** for resilience
   against provider outages.

The V1 / pre-this-spec defaults (`[orchestrator] provider_alias =
"fast_low_cost"`, no policy-shipped Reviewer alias chain, no
defaulting machinery) push every one of these decisions onto the
operator's first day. Worse, the suggested defaults themselves embed
opinions that don't survive workload analysis — "low cost" is the
wrong default for the Orchestrator, whose total token volume is
modest and whose decisions affect the whole DAG.

This spec replaces all four ad-hoc defaults with a single coherent
defaulting layer:

- **Policy-level `[provider_aliases_defaults]`** ships role-canonical
  alias chains that `raxis-cli plan prepare` fills into `plan.toml`
  when the operator omits them.
- **`raxis-cli setup wizard`** generates these defaults at install
  time based on which provider credentials the operator entered, with
  automatic cross-provider diversification when ≥ 2 providers are
  configured.
- **The Orchestrator default alias** is renamed
  `orchestrator_default` and its chain is updated to a mid-tier
  reasoning model with cross-provider fallback.

The result: a fresh-install operator gets a sensible per-role model
configuration without authoring a single line of `[provider_aliases]`
TOML, and the alias names that show up in their `plan.toml` after
`plan prepare` are self-documenting (`reviewer`, `executor`,
`orchestrator_default`) rather than embedding a stale opinion.

---

## §2 — Scope and Non-Scope

### In scope

- The decision framework operators should use to pick per-role models
  (§3 workload profiles, §4 recommended defaults, §5 diversification,
  §6 deviation triggers).
- The `[provider_aliases_defaults]` policy schema and its `plan
  prepare` consumption pattern (§7).
- The end-to-end resolution chain from "operator picks an alias name"
  to "gateway makes the outbound API call" (§8).
- The two-credential-system architectural property and how it shapes
  the diversification recommendation (§8.1).
- The `setup wizard` auto-generation logic for one-provider and
  multi-provider deployments (§9).
- New failure codes specific to this surface and their semantics (§10).
- Implementation checklist (§11).

### Out of scope (explicit)

- **Alias resolution algorithm and circuit-breaker behavior.** Those
  live in `provider-failure-handling.md` §4–§5 and are unchanged by
  this spec.
- **Per-environment Reviewer model overrides.** Reserved for V2.x via
  `[environments.<label>] override_reviewer_alias`
  (`environment-access-control.md §5b.4`); this spec only documents
  the trajectory.
- **Custom provider plugins.** Adding a new provider to RAXIS (a
  hypothetical `[[providers]] kind = "custom"`) is gateway work
  governed by `v1/peripherals.md §3` and is unaffected by this spec.
- **Model-quality benchmarking.** This spec recommends model tiers
  ("mid-tier reasoning", "long-context reading") rather than naming
  specific frontier models, because operator-environment latency,
  cost, and capability tradeoffs vary too much for a one-true
  recommendation. Specific model names appear in examples but are
  illustrative, not normative.

---

## §3 — Per-role workload profiles

Each role's model selection is a different optimization problem
because the workloads have different shapes. The recommended defaults
in §4 are derived from these profiles.

### 3.1 Orchestrator

| Property | Profile |
|---|---|
| **Token volume per initiative** | **Low.** The Orchestrator's NNSP (`ORCHESTRATOR_NNSP_BYTES`) is short and kernel-locked; per-burst reasoning is mostly DAG bookkeeping. Typical session: 100k–500k tokens for a 5-task initiative. |
| **Burst frequency** | **Moderate.** One reasoning burst per sub-task transition, plus occasional semantic merge resolution per `kernel-mechanics-prompt.md §3.2`. |
| **Hardest reasoning task** | Semantic merge conflict resolution (3-way merges where the ancestor and both branches disagree on the same lines), and escalation routing when multiple sub-tasks have escalations pending simultaneously. Both are short-context, judgment-heavy. |
| **Failure cost** | **High and broad.** A wrong escalation routing decision sends a security-class escalation to the wrong queue. A bad merge sequencing decision strands every downstream task. The Orchestrator decides on behalf of the entire initiative. |
| **Latency sensitivity** | **Noticeable.** Every task transition waits on the Orchestrator's burst. A 30-second Orchestrator turn × 20 task transitions = 10 minutes of pure latency overhead per initiative. |
| **Cost sensitivity** | **Low.** Token volume is small enough that per-token rate barely moves the per-initiative cost. Reliability and reasoning quality dominate the value. |

**Implication.** The Orchestrator wants a **mid-tier reasoning model
with a thinking budget**, on a **fast inference path**. The historical
"cheap and fast" framing was wrong on both axes — the per-initiative
cost saving from picking a haiku-tier model is dwarfed by the cost of
one botched merge sequencing decision causing a re-run of the
initiative.

### 3.2 Reviewer

| Property | Profile |
|---|---|
| **Token volume per session** | **High.** The Reviewer reads the whole diff, all verifier witnesses (potentially several MB of structured output), the symbol index, and any prior review submissions in the round. Typical session: 500k–2M input tokens. |
| **Burst frequency** | **One large session per review round**, often 2–4 rounds per task per `INV-CONVERGENCE-01`. |
| **Hardest reasoning task** | Spotting subtle bugs the verifiers didn't catch (off-by-one logic errors, missing edge cases, inconsistent invariant maintenance across files). Long-context comprehension and careful judgment matter more than raw "smartness." |
| **Failure cost** | **High in a different shape.** A rubber-stamp Reviewer is *worse* than no Reviewer (false confidence). A Reviewer that hallucinates issues triggers wasted re-review rounds, eating into `INV-CONVERGENCE-01`'s round cap and ultimately escalating to operator. |
| **Latency sensitivity** | **Low.** Operators expect reviews to take time. A 5-minute review session is fine; a 30-second review session that misses bugs is not. |
| **Cost sensitivity** | **High.** Tokens × rounds × tasks per initiative add up quickly. A Reviewer at 2M input tokens per session × 3 rounds × 10 tasks = 60M tokens per initiative. The per-token rate of the chosen model is the dominant cost lever. |

**Implication.** The Reviewer wants a **high-tier reasoning model
with a long context window**. Cost-conscious deployments should
upgrade selectively (production-bound tasks get a bigger Reviewer;
beta-bound tasks get a cheaper one — see §6 and the V2.x
`override_reviewer_alias` reserved field).

### 3.3 Executor

| Property | Profile |
|---|---|
| **Token volume per session** | **Variable.** Depends entirely on what the agent is doing. A simple bug-fix task: 100k–500k tokens. A large refactor: 5M+ tokens. |
| **Burst frequency** | **Many short bursts.** Each tool invocation is a burst. A typical Executor session has 50–500 turns. |
| **Hardest reasoning task** | Tool-using code generation: deciding which file to edit, what to change, how to verify. Domain expertise matters — e.g., "writes good React" or "writes good Rust" is a model-by-model property. |
| **Failure cost** | **Moderate per-task.** The Reviewer catches most Executor mistakes; verifiers catch the rest. Bad Executor output triggers re-review rounds (counts against `INV-CONVERGENCE-01`) but doesn't compromise the system. |
| **Latency sensitivity** | **High.** Many small turns; each turn's latency is felt directly by the operator watching `initiative watch`. |
| **Cost sensitivity** | **High.** Often the dominant cost component of an initiative. |

**Implication.** The Executor wants a **mid-tier reasoning model
optimized for code**. Per-task profile overrides are common — a
"frontend" profile may pick a different model than a "systems"
profile.

### 3.4 Why the defaults aren't symmetric

Naively, you might pick "use the same model for everything because
it's simpler." The workload analysis says: don't.

- The **Orchestrator** is low-volume and high-leverage. Spend more per
  token; total spend is small.
- The **Reviewer** is high-volume and high-leverage. Spend on
  context-handling and reasoning quality; cost is proportionate to
  the value of catching bugs.
- The **Executor** is high-volume and moderate-leverage (caught by
  Reviewer + verifiers). Cost-optimize within a "good enough at code"
  band.

Picking the same model across all three either over-pays for
Executor work (use Opus for routine code edits → expensive) or
under-pays for Orchestrator decisions (use Haiku for merge sequencing
→ mistakes are silent and expensive downstream).

---

## §4 — Recommended defaults

The defaults below are what `raxis-cli setup wizard` ships and what
`[provider_aliases_defaults]` resolves to in the absence of operator
override. Specific model names are illustrative — operators on
different deployments may prefer different concrete models, and the
RAXIS release notes will track the recommended chains as the
provider model lineup evolves.

### 4.1 Single-provider deployment (Anthropic-only example)

```toml
# policy.toml — generated by `raxis-cli setup wizard` when only an
# Anthropic API key was entered.

[orchestrator]
provider_alias = "orchestrator_default"   # default name; renamed from V1 "fast_low_cost"

[provider_aliases.orchestrator_default]
chain = ["anthropic:claude-4.6-sonnet-medium-thinking"]
fallback_behavior = "attempt_in_order"

[provider_aliases_defaults.reviewer]
chain = ["anthropic:claude-opus-4.7-thinking-medium"]
fallback_behavior = "attempt_in_order"

[provider_aliases_defaults.executor]
chain = ["anthropic:claude-4.6-sonnet-medium-thinking"]
fallback_behavior = "attempt_in_order"
```

Rationale per §3: Sonnet-tier with thinking budget for Orchestrator
and Executor; Opus-tier with thinking budget for Reviewer.
Single-provider deployment means single-element chains — there is no
fallback because there is no other provider to fall back to. If
Anthropic has an outage, the initiative pauses with
`InferenceFailureProviderUnavailable` per
`provider-failure-handling.md §6.4`, and the operator gets an
`InitiativePaused` push notification.

### 4.2 Two-provider deployment (Anthropic + OpenAI; recommended)

```toml
# policy.toml — generated by `raxis-cli setup wizard` when both
# Anthropic and OpenAI API keys were entered, with default
# auto-diversification.

[orchestrator]
provider_alias = "orchestrator_default"

[provider_aliases.orchestrator_default]
chain = [
    "anthropic:claude-4.6-sonnet-medium-thinking",   # primary
    "openai:gpt-5.5-medium",                         # cross-provider fallback
]
fallback_behavior = "attempt_in_order"

[provider_aliases_defaults.reviewer]
chain = [
    "openai:gpt-5.3-codex",                          # primary on a DIFFERENT provider
    "anthropic:claude-opus-4.7-thinking-medium",     # fallback
]
fallback_behavior = "attempt_in_order"

[provider_aliases_defaults.executor]
chain = [
    "anthropic:claude-4.6-sonnet-medium-thinking",
    "openai:gpt-5.5-medium",
]
fallback_behavior = "attempt_in_order"
```

**Why the Reviewer's primary differs from the Orchestrator's
primary:** auto-diversification (§5). When a single provider has a
regional outage, the Orchestrator's primary stays up (different
provider) AND the Reviewer's primary stays up (different provider).
The fallback chains protect against the cross-case where one
provider's outage takes out the role's primary. Either way the
initiative survives a single-provider incident.

### 4.3 Three-or-more-provider deployment (Anthropic + OpenAI + Google)

```toml
# policy.toml — generated by `raxis-cli setup wizard` when three or
# more provider credentials were entered.

[orchestrator]
provider_alias = "orchestrator_default"

[provider_aliases.orchestrator_default]
chain = [
    "anthropic:claude-4.6-sonnet-medium-thinking",
    "openai:gpt-5.5-medium",
    "google:gemini-2.5-pro",
]
fallback_behavior = "attempt_in_order"

[provider_aliases_defaults.reviewer]
chain = [
    "openai:gpt-5.3-codex",
    "anthropic:claude-opus-4.7-thinking-medium",
    "google:gemini-2.5-pro",
]
fallback_behavior = "attempt_in_order"

[provider_aliases_defaults.executor]
chain = [
    "anthropic:claude-4.6-sonnet-medium-thinking",
    "openai:gpt-5.5-medium",
    "google:gemini-2.5-flash",
]
fallback_behavior = "attempt_in_order"
```

Three-element chains protect against simultaneous two-provider
outages (rare but documented for high-availability deployments). The
Orchestrator and Executor share Gemini-Pro fallback at tier-3 because
both can use a frontier model in a pinch; the Executor specifically
uses Gemini-Flash at tier-3 instead of Gemini-Pro for the per-token
cost difference (Executor is high-volume).

---

## §5 — Auto-diversification

When `setup wizard` configures more than one provider, the recommended
defaults assign each role's primary to a different provider. This is
the canonical pattern for protecting an initiative against a
single-provider outage.

### 5.1 Why diversification across roles, not within

A naive "diversify within a single role's chain" would be:

```toml
# DON'T do this:
[provider_aliases.orchestrator_default]
chain = [
    "anthropic:claude-4.6-sonnet-medium-thinking",
    "openai:gpt-5.5-medium",
]
[provider_aliases_defaults.reviewer]
chain = [
    "anthropic:claude-opus-4.7-thinking-medium",
    "openai:gpt-5.3-codex",
]
[provider_aliases_defaults.executor]
chain = [
    "anthropic:claude-4.6-sonnet-medium-thinking",
    "openai:gpt-5.5-medium",
]
```

Every role's primary is on Anthropic. When Anthropic has an outage,
**every** role fails over simultaneously, all three roles run their
fallback's first inference call against OpenAI at the same moment,
and OpenAI gets a thundering-herd burst. The diversification works
intra-role (each role still has a working fallback) but does nothing
for the system as a whole.

The cross-role auto-diversification pattern (§4.2):

```toml
[provider_aliases.orchestrator_default]
chain = ["anthropic:...", "openai:..."]    # primary: Anthropic

[provider_aliases_defaults.reviewer]
chain = ["openai:...", "anthropic:..."]    # primary: OpenAI

[provider_aliases_defaults.executor]
chain = ["anthropic:...", "openai:..."]    # primary: Anthropic
```

When Anthropic is down: the Orchestrator and Executor fail over to
OpenAI, but the Reviewer is still on its OpenAI primary (no failover
needed). When OpenAI is down: the Reviewer fails over to Anthropic,
and the Orchestrator/Executor are still on their Anthropic primary.
**Steady-state load is split across providers**, and an outage
shifts only some of the load rather than all of it.

### 5.2 Wizard logic

```rust
fn auto_diversify(configured_providers: &[ProviderId]) -> AliasDefaults {
    match configured_providers.len() {
        0 => panic!("setup wizard requires at least one provider"),
        1 => {
            // Single provider: single-element chains everywhere.
            // §4.1 layout.
        }
        2 => {
            // Two providers: cross-role diversification.
            // Orchestrator primary on providers[0]; Reviewer primary
            // on providers[1]; Executor primary on providers[0].
            // (Exec follows Orch since Exec is high-volume; keeps
            // a single provider taking the bulk of the request load
            // when both are healthy.)
            // §4.2 layout.
        }
        n => {
            // Three or more: same as 2-provider with all unused
            // providers appended as tier-3+ fallback in each chain.
            // §4.3 layout.
        }
    }
}
```

**Why Executor follows Orchestrator and not Reviewer:** the Executor
is high-volume; if the wizard split it onto Reviewer's provider, both
high-volume roles (Executor + Reviewer) would steady-state on the
same provider, defeating load-distribution. Putting Executor with
Orchestrator keeps the bulk of the inference traffic on one provider
in the steady state, and shifts to the other provider when the
primary fails.

### 5.3 Operator override

The wizard's diversification is a default. Operators may disable it
at wizard time with `--no-diversify` or override per-role after the
fact by editing the generated `policy.toml`. The diversification
exists because most operators don't know to ask for it; operators who
do know can override.

---

## §6 — When to deviate from the defaults

The defaults are tuned for the median deployment. Concrete situations
where operators should adjust:

### 6.1 Production-environment work where bugs are expensive

**Action.** Upgrade Reviewer to thinking-tier high (e.g.,
`anthropic:claude-opus-4.7-thinking-high` instead of -medium). For
deployments with the V2.x `[environments.production]
override_reviewer_alias` knob (`environment-access-control.md
§5b.4`), the upgrade is per-environment; otherwise it's deployment-wide.

Also consider `[orchestrator] all_merges_require_approval = true` so
a human approves every prod merge regardless of model — defense in
depth for the highest-leverage decision.

### 6.2 Large-DAG initiatives (≥ 50 tasks) with parallel branches

**Action.** Upgrade Orchestrator to a thinking-tier model (e.g.,
`anthropic:claude-opus-4.7-thinking-medium`). Merge-sequencing
reasoning load grows non-linearly with the number of parallel
branches.

### 6.3 Cost-bounded experiments and dev environments

**Action.** Drop Reviewer to a mid-tier model (e.g.,
`anthropic:claude-4.6-sonnet-medium-thinking` instead of Opus-tier).
Combine with `[plan.tasks.<id>.review] symbol_index = "not_needed"`
per `planner-harness.md` to keep token volume small.

**Don't drop the Orchestrator below mid-tier.** The cost saving is
small and the failure mode (botched merge sequencing) is silent.
Cheap-tier models routinely pick the wrong merge order on
non-trivial DAGs.

### 6.4 Air-gapped or single-provider deployment

**Action.** Use single-element chains for all roles (the §4.1
single-provider layout). Pin specific model versions to minimize
provider-side surprise (e.g., `anthropic:claude-4.6-sonnet@20260301`
syntax if your provider supports it). Lose the fallback benefit;
gain reproducibility.

### 6.5 Latency-sensitive deployments

**Action.** Drop Orchestrator's thinking budget (e.g.,
`anthropic:claude-4.6-sonnet-low-thinking` or just
`anthropic:claude-4.6-sonnet`). Each Orchestrator burst becomes
faster at the cost of slightly less reasoning depth. Acceptable when
DAGs are simple (≤ 10 tasks, no parallelism).

### 6.6 Profile-specific Executor models

**Action.** Define per-profile aliases in `plan.toml` for tasks with
specialized needs. A "frontend" profile might use a model trained on
React; a "systems" profile might use a model strong on Rust:

```toml
[provider_aliases.frontend_dev]
chain = ["openai:gpt-5.5-medium"]

[provider_aliases.systems_dev]
chain = ["anthropic:claude-opus-4.7-thinking-medium"]

[[profiles.frontend]]
inherits_from = "Executor"
provider_alias = "frontend_dev"

[[profiles.systems]]
inherits_from = "Executor"
provider_alias = "systems_dev"
```

`plan prepare` does NOT default the Executor alias when the task's
profile already declares a `provider_alias`; the operator's
profile-level choice wins.

---

## §7 — `[provider_aliases_defaults]` policy schema

The defaulting machinery for per-role aliases. Lives in `policy.toml`;
consumed by `raxis-cli plan prepare` per `operator-ergonomics.md §4`.

### 7.1 Schema

```toml
# policy.toml — V2 schema for [provider_aliases_defaults]

[provider_aliases_defaults.reviewer]
chain             = ["openai:gpt-5.3-codex", "anthropic:claude-opus-4.7-thinking-medium"]
fallback_behavior = "attempt_in_order"   # currently the only valid value; reserved for future strategies

[provider_aliases_defaults.executor]
chain             = ["anthropic:claude-4.6-sonnet-medium-thinking", "openai:gpt-5.5-medium"]
fallback_behavior = "attempt_in_order"
```

| Field | Type | Default | Purpose |
|---|---|---|---|
| `[provider_aliases_defaults.<role>] chain` | `Vec<ProviderModelKey>` | (none; absence disables defaulting for that role) | The fallback chain `plan prepare` fills into `plan.toml [provider_aliases.<role>]` when the operator's plan omits the section. |
| `[provider_aliases_defaults.<role>] fallback_behavior` | string | `"attempt_in_order"` | Same semantics as `plan.toml [provider_aliases.<name>] fallback_behavior` per `provider-failure-handling.md §3.2`. |
| `[provider_aliases_defaults.<role>] session_affinity` | bool | `false` for `executor`, `true` for `reviewer` (rationale below) | Whether `plan prepare` adds `session_affinity = <value>` to the materialized `plan.toml [provider_aliases.<role>]`. See `provider-failure-handling.md §4.1.1` for cross-call pinning semantics. The Reviewer default is `true` because Reviewer sessions accumulate review history across rounds and benefit measurably from reasoning-style and prompt-prefix-cache stability; the Executor default is `false` because Executor work is typically a single short transcript per task and the modest per-call resolution preserves the §12.1 "no session-state in routing" property by default. Operators MAY override per-plan. |

**Recognized roles.** V2 ships defaults for two role names:
- `reviewer` — used by Reviewer-rooted profiles.
- `executor` — used by Executor-rooted profiles whose own
  `provider_alias` is absent.

Other names are accepted by the parser but produce a
`WARN_PROVIDER_ALIAS_DEFAULT_UNKNOWN_ROLE` because they have no
defaulting consumer in V2; operators reading the warning know they
can remove the orphan section.

The Orchestrator role is **NOT** in this schema because the
Orchestrator's alias lives in `[orchestrator] provider_alias`
(operator-pinned via policy, never via plan, per
`policy-plan-authority.md §4 [orchestrator]`). It has its own
authoring path; defaulting it through this mechanism would create
two paths to the same target and invite drift.

### 7.2 Validation at policy load

For each `[provider_aliases_defaults.<role>]` declared:

1. Every model in `chain` MUST appear in `policy.toml [providers]
   permitted_models` (per `INV-PROVIDER-01`,
   `provider-failure-handling.md §10`).
   - Otherwise: `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_REFERENCES_NONPERMITTED_MODEL { role, missing_models }`.
2. For every distinct provider referenced in `chain`, at least one
   `[[providers.credentials]]` entry MUST exist with that
   `provider_id`.
   - Otherwise: `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_MISSING_CREDENTIAL { role, missing_provider }`.
   - Rationale: a chain entry whose provider has no configured
     credential will never resolve at inference time
     (`provider-failure-handling.md §4.1` `credentials_authorized`
     check); declaring it as a default just delays the failure to a
     confusing place.
3. `chain` MUST be non-empty. Otherwise: `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_EMPTY_CHAIN`.
4. `fallback_behavior` MUST be `"attempt_in_order"` (the only V2
   value). Otherwise: `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_UNKNOWN_FALLBACK_BEHAVIOR`.

These validations make every defaultable alias usable by definition
— `plan prepare` cannot fill in a default the kernel would later
reject at admission.

### 7.3 `plan prepare` consumption

Per `operator-ergonomics.md §5`:

```text
For each [provider_aliases_defaults.<role>] in policy:
    Does plan.toml declare [provider_aliases.<role>]?
        Yes → leave alone (operator-explicit).
        No  → add to plan.toml:
                [provider_aliases.<role>]
                chain             = <policy default>     # @raxis-default v0.4.0
                fallback_behavior = "attempt_in_order"   # @raxis-default v0.4.0
```

Idempotency rule (`operator-ergonomics.md §4.4`): a previously-defaulted
alias whose policy default has not changed leaves the file untouched
on re-prepare. A drifted default fails with
`FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED` unless `--upgrade-defaults`
is passed.

### 7.4 Interaction with profile-level `provider_alias`

The defaulting mechanism is **alias-name-keyed**, not
profile-keyed. Profiles that declare their own `provider_alias` (e.g.,
`[[profiles.frontend]] provider_alias = "frontend_dev"`) reference
that alias, NOT the role-canonical `executor` alias. So
`plan prepare`'s defaulting of `executor` does not conflict with
specialized profiles — they go through their own alias.

A profile that omits `provider_alias` falls back to the
role-canonical name (`executor` for Executor-rooted profiles,
`reviewer` for Reviewer-rooted profiles), which is the alias `plan
prepare` defaults. So the common case (operator declares no profile
overrides) is fully handled by the defaults.

---

## §8 — End-to-end resolution chain

Every alias chain entry resolves through the same sequence to an
outbound HTTPS call. Operators should understand this chain because
it's where the two-credential-system architecture (§8.1) becomes
visible and where INV-02A / INV-02B / INV-PROVIDER-01 are enforced
mechanically.

### 8.1 The two credential systems (architectural property)

> **Critical separation.** RAXIS deliberately maintains **two
> orthogonal credential systems** with different on-disk locations,
> different read-eligibility, and different threat models. This
> separation is what makes both credential systems' invariants
> tractable.

| Property | **Provider credentials** | **Operator credentials** |
|---|---|---|
| Used for | Inference calls to LLM providers (Anthropic, OpenAI, Google) | Resources inside agent VMs (kubeconfig, AWS keys, registry tokens) |
| On-disk path | `<data_dir>/providers/<provider>.toml` (chmod 0600, kernel-OS-user) — or content-addressed in the gateway's immutable artifact store, keyed by the `key_ref` field | `<data_dir>/credentials/<name>.env` (chmod 0600, kernel-OS-user) |
| Read by | The **gateway subprocess** at startup, from a per-provider config file or artifact-store handle | The **kernel** at VM boot, for env-var injection per `[[plan.tasks.<id>.credentials]]` |
| Enters any agent VM? | **Never.** The gateway makes the outbound HTTPS call; the VM never sees the API key. | Yes, as env vars per task (e.g., `KUBECONFIG=<bytes from kubeconfig.env>`) |
| Declared in policy via | `[[providers.credentials]] provider_id key_ref` | `[[permitted_credentials]] name environment` |
| Subject to environment binding (`INV-ENV-01`)? | No (these are kernel/gateway authority, not task-level authority) | Yes |
| Subject to `INV-02A` (kernel-priced inference) | **Yes — these ARE the keys that pay providers** | No (no payment role) |
| Rotation governed by | `key-revocation.md` provider-key path | `key-revocation.md` plan-signing-key path (different scope) |
| Held in process memory by | Gateway subprocess only | Kernel briefly at injection; agent VM for the lifetime of the task |

Operators sometimes ask "why two systems?" — the threats they
defend against are different:

- **Provider credentials must never enter a VM**, because the
  planner could leak them into a model context (the agent has
  read access to its own env vars; writing them into a prompt
  exfiltrates them to whichever model the next inference targets).
  The gateway is the authority boundary: it holds the keys, makes
  the outbound calls, and the planner never sees the bytes.
- **Operator credentials must never reach the gateway**, because the
  gateway is a network-egress process; an exploited gateway should
  not have cluster-admin keys. Operator credentials live in a
  separate store the gateway has no path to.

This spec's chains and aliases govern **System 1 only** — the
provider-credential side. The model selection knobs (`provider_alias`,
`[provider_aliases]`, `[provider_aliases_defaults]`) are entirely
about which gateway-managed key gets used for which inference call.
None of them touch System 2.

### 8.2 The full resolution path

```yaml
Step 1 — Operator declares the alias chain.
  Plan.toml or policy.toml:
    [provider_aliases.reviewer]
    chain = ["anthropic:claude-opus-4.7-thinking-medium",
             "openai:gpt-5.5-medium"]

Step 2 — Planner submits an inference request.
  Inside the Reviewer VM, the planner harness emits:
    InferenceRequest { model: "alias:reviewer", input: <bytes>, ... }
  This crosses the planner→kernel IPC. The planner does NOT know
  which concrete model will be picked; the kernel decides.

Step 3 — Kernel resolves the alias.
  resolve_alias("reviewer") walks the chain in order:
    For each chain entry "anthropic:claude-opus-4.7-thinking-medium":
      a. Is the model in policy.toml [providers] permitted_models?
         (INV-PROVIDER-01)
         No  → reject the alias chain at admission (caught earlier
               by approve_plan; this is a defense-in-depth re-check).
         Yes → continue.
      b. credentials_authorized("anthropic")? — i.e., does
         policy.toml have at least one [[providers.credentials]]
         entry with provider_id = "anthropic"?
         No  → skip this chain entry; try next.
         Yes → continue.
      c. Circuit breaker for this specific model in CLOSED state?
         (provider-failure-handling.md §5)
         No (open or half-open without quota)
             → skip this chain entry; try next.
         Yes → dispatch this attempt.
    If chain is exhausted → InferenceFailureProviderUnavailable
      (provider-failure-handling.md §6.4); the agent's session
      pauses with InitiativePaused per kernel-push-protocol.md.

Step 4 — Kernel dispatches to the gateway.
  Kernel sends FetchRequest {
    fetch_kind: "Inference",
    resolved_model: "anthropic:claude-opus-4.7-thinking-medium",
    body: <provider-specific request bytes>,
    ...
  } over the gateway UDS.
  The kernel does NOT have the provider API key in process memory;
  it's just naming the model and handing the bytes to the gateway.

Step 5 — Gateway picks a credential and makes the call.
  Gateway looks up [[providers.credentials]] entries with
  provider_id = "anthropic":
    - If multiple entries exist (e.g., key rotation): pick by
      operator-defined priority field, or round-robin.
    - Load the actual key bytes from the immutable artifact store
      keyed by the entry's key_ref.
  Gateway constructs the outbound HTTPS request:
    POST https://api.anthropic.com/v1/messages
    Authorization: Bearer <key bytes>
    Content-Type: application/json
    Body: <provider-specific request>
  Gateway parses response, returns to kernel as FetchResponse.

Step 6 — Kernel decorates and returns to planner.
  Kernel emits InferenceCompleted audit event with
  actual_model_used, total_attempts, tokens consumed,
  provider-side latency, etc.
  Kernel returns InferenceResponse {
    content: <model output>,
    actual_model_used: "anthropic:claude-opus-4.7-thinking-medium",
    total_attempts: 1,
  } to the planner.
  The planner sees which concrete model answered; this is its only
  view into the chain (no fallback decisions, no breaker state).
```

### 8.3 Where each authority constraint applies

| Constraint | Enforced at | Reference |
|---|---|---|
| Planner cannot bypass the kernel for inference | Step 2 (no IPC type for "raw provider call") | `INV-02A`, `paradigm.md` R-2 |
| Planner cannot inject its own provider key | Step 5 (gateway is the only key holder) | `INV-02A`, this spec §8.1 |
| Plan cannot reference an unpermitted model | Step 3a + earlier `approve_plan` check | `INV-PROVIDER-01`, `provider-failure-handling.md §10` |
| Chain element with no credential is silently skipped | Step 3b | `provider-failure-handling.md §4.1` |
| Outage in one provider doesn't take down the initiative | Step 3c (circuit breaker) + chain fallback | `provider-failure-handling.md §5–§6` |
| Audit chain records which concrete model answered | Step 6 | `INV-04`, `provider-failure-handling.md §3.1` |

The whole chain is mechanical and deterministic given inputs. The
operator's only authoring decisions are which API keys to
provision (System 1, §9 setup wizard automates), which permitted
models to whitelist (`policy.toml [providers] permitted_models`),
and which alias chains to declare (§4 defaults handle most cases).

---

## §9 — `setup wizard` integration

The `raxis-cli setup wizard` (`operator-ergonomics.md §16`) is the
canonical first-run path that gets all of this configured without
the operator hand-authoring TOML. This section specifies the
provider-and-model phases of the wizard.

### 9.1 Phase 2 — Provider credential entry

```text
═════════════════════════════════════════════════════════════════
  Provider credentials
═════════════════════════════════════════════════════════════════

  RAXIS uses LLM provider APIs (Anthropic, OpenAI, Google) for
  agent inference. You need at least one provider configured.
  Configuring two or more enables automatic cross-provider failover
  for resilience against provider outages.

  Add provider credentials? (recommended: 2)

    [1] Anthropic   API key (sk-ant-...): [press enter to skip]
    [2] OpenAI      API key (sk-...):     [press enter to skip]
    [3] Google      API key (AIza...):    [press enter to skip]
    [4] Add custom provider via [[providers]] schema (advanced)

  Auto-diversify across providers when 2+ are configured? [Y/n] _
```

**On submission, for each entered key:**

1. **Smoke-test the credential.** Call the provider's `models.list`
   (or equivalent lightest-weight authenticated endpoint) to verify
   the key is valid. Reject and re-prompt on `401`.
2. **Write the key to disk.** `<data_dir>/providers/<provider>.toml`
   (chmod 0600, owner: kernel OS user). The file format is the
   gateway's existing per-provider config, with the API key in the
   appropriate field.
3. **Compute the artifact-store key_ref.** SHA-256 of the key bytes
   (or operator-supplied label suffix); see `v1/peripherals.md §3`
   for the artifact store conventions.
4. **Append to in-progress `policy.toml`:**
   ```toml
   [[providers.credentials]]
   provider_id = "anthropic"
   key_ref     = "anthropic-prod-2026-q1"
   ```

The on-disk path AND the policy entries are both surfaced to the
operator in the wizard's final summary so they know exactly what was
created.

### 9.2 Phase 3 — Permitted models

```text
═════════════════════════════════════════════════════════════════
  Permitted models
═════════════════════════════════════════════════════════════════

  Which models can plans request? RAXIS will only dispatch
  inference to models you explicitly permit (INV-PROVIDER-01).

  Recommended set (covers the §4 default chains):

    [✓] anthropic:claude-4.6-sonnet-medium-thinking
    [✓] anthropic:claude-opus-4.7-thinking-medium
    [✓] openai:gpt-5.5-medium
    [✓] openai:gpt-5.3-codex
    [ ] google:gemini-2.5-pro     (selected if Google configured)
    [ ] google:gemini-2.5-flash   (selected if Google configured)
    [+] Add more...

  Use the recommended set? [Y/n/customize] _
```

The recommended set is the union of every model that appears in
the §4 default chains for the operator's configured-provider count.
If the operator added a custom provider, that provider's models must
be added explicitly.

The selected set lands in `policy.toml`:

```toml
[providers]
permitted_models = [
    "anthropic:claude-4.6-sonnet-medium-thinking",
    "anthropic:claude-opus-4.7-thinking-medium",
    "openai:gpt-5.5-medium",
    "openai:gpt-5.3-codex",
]
```

### 9.3 Phase 4 — Alias chain generation

This phase is **fully automatic** when the operator accepted the
diversification default in phase 2. The wizard runs the §5.2
`auto_diversify` algorithm against the configured providers and
writes the resulting chains to `policy.toml`.

```text
═════════════════════════════════════════════════════════════════
  Per-role inference chains (auto-generated)
═════════════════════════════════════════════════════════════════

  Based on your 2 configured providers (Anthropic + OpenAI), the
  wizard generated cross-provider diversified chains:

  Orchestrator (policy-pinned)
    primary:  anthropic:claude-4.6-sonnet-medium-thinking
    fallback: openai:gpt-5.5-medium

  Reviewer (defaulted into every plan via plan prepare)
    primary:  openai:gpt-5.3-codex                    [DIFFERENT provider for diversification]
    fallback: anthropic:claude-opus-4.7-thinking-medium

  Executor (defaulted into every plan via plan prepare)
    primary:  anthropic:claude-4.6-sonnet-medium-thinking
    fallback: openai:gpt-5.5-medium

  Why the cross-provider primary on Reviewer: when Anthropic has
  an outage, the Reviewer keeps running on its OpenAI primary; the
  Orchestrator/Executor fail over to OpenAI fallback. This spreads
  steady-state load AND degrades gracefully under partial outage.

  Customize chains? [N/y] _
```

The operator can press through with `N` and proceed to the smoke
test (phase 5 / `operator-ergonomics.md §16.3`). The whole sequence
takes under two minutes for an operator who already has API keys in
hand.

### 9.4 Single-provider variant

When only one provider is configured, phase 4 generates the §4.1
single-element chains:

```text
═════════════════════════════════════════════════════════════════
  Per-role inference chains (single-provider)
═════════════════════════════════════════════════════════════════

  Based on your 1 configured provider (Anthropic):

  Orchestrator (policy-pinned)
    only:     anthropic:claude-4.6-sonnet-medium-thinking

  Reviewer (defaulted into every plan via plan prepare)
    only:     anthropic:claude-opus-4.7-thinking-medium

  Executor (defaulted into every plan via plan prepare)
    only:     anthropic:claude-4.6-sonnet-medium-thinking

  Note: with one provider configured, there is no fallback chain.
  An Anthropic outage will pause your initiative until the provider
  recovers. Configure a second provider to enable cross-provider
  failover.

  Continue? [Y/n] _
```

### 9.5 Re-running the wizard for a provider addition

```bash
$ raxis-cli setup wizard --add-provider openai
```

This re-runs phase 2 to add a new credential, then re-runs phase 4
to regenerate the alias chains incorporating the new provider. The
operator's existing customizations (manually-edited
`[provider_aliases]` blocks) are preserved unless they pass
`--reset-chains`.

---

## §10 — Failure codes

| Code | Phase | Trigger |
|---|---|---|
| `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_REFERENCES_NONPERMITTED_MODEL { role, missing_models }` | Policy load | A `[provider_aliases_defaults.<role>] chain` entry references a model not in `[providers] permitted_models`. The kernel refuses to load the policy until either the model is added to `permitted_models` or the chain is corrected. |
| `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_MISSING_CREDENTIAL { role, missing_provider }` | Policy load | A `[provider_aliases_defaults.<role>] chain` entry references a provider with no `[[providers.credentials]]` entry. The chain element would be silently skipped at every alias resolution; the kernel surfaces this as a load-time error rather than a confusing runtime degradation. |
| `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_EMPTY_CHAIN { role }` | Policy load | A declared `[provider_aliases_defaults.<role>]` has an empty `chain`. Equivalent to "no defaulting for this role" but expressed in a way that's almost certainly an authoring mistake. |
| `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_UNKNOWN_FALLBACK_BEHAVIOR { role, value }` | Policy load | `fallback_behavior` is not `"attempt_in_order"`. Reserved for future strategies; only one value is valid in V2. |
| `WARN_PROVIDER_ALIAS_DEFAULT_UNKNOWN_ROLE { role }` | Policy load | `[provider_aliases_defaults.<role>]` declares a role name other than `executor` or `reviewer`. The default has no consumer in V2 and is silently ignored; the warning lets operators clean up orphan sections. |
| `FAIL_POLICY_ORCHESTRATOR_PROVIDER_ALIAS_UNRESOLVED { alias }` | Policy load | (Existing — referenced here for completeness.) `[orchestrator] provider_alias` doesn't resolve to a `[provider_aliases.<alias>]` entry. The default name in V2 is `orchestrator_default` (renamed from the V1 `fast_low_cost`); see `policy-plan-authority.md §4 [orchestrator]`. |
| `WARN_PROVIDER_ALIAS_PRIMARY_NO_FAILOVER { alias }` | Policy load | An alias chain has length 1 in a deployment that has 2+ configured providers. Suggests the operator may have missed the diversification benefit; non-fatal; auditors can spot single-provider exposure. |

All `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_*` codes prevent the policy
from loading. This means a misconfigured `[provider_aliases_defaults]`
cannot break in-flight initiatives — the new policy is rejected;
the previous policy stays active until the operator fixes and
re-pushes.

---

## §11 — Implementation Checklist

### Kernel side

- [ ] Parse `[provider_aliases_defaults.<role>]` blocks per §7.1; default to absent (no defaulting).
- [ ] Validation chain at policy load per §7.2:
      - `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_REFERENCES_NONPERMITTED_MODEL`
      - `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_MISSING_CREDENTIAL`
      - `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_EMPTY_CHAIN`
      - `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_UNKNOWN_FALLBACK_BEHAVIOR`
      - `WARN_PROVIDER_ALIAS_DEFAULT_UNKNOWN_ROLE`
      - `WARN_PROVIDER_ALIAS_PRIMARY_NO_FAILOVER`
- [ ] Rename the V1 `[orchestrator] provider_alias` default value from `"fast_low_cost"` to `"orchestrator_default"` (and update the policy migration path so V1 policies that use the old name still load with a deprecation warning).
- [ ] Update `OperatorRequest::ProposeDefaults` handler (`operator-ergonomics.md §5.3`) to consume `[provider_aliases_defaults.<role>]` and fill `[provider_aliases.<role>]` entries into the augmented plan when absent, per §7.3.
- [ ] All §10 codes registered in `raxis-types::PlannerErrorCode`.

### CLI side

- [ ] `raxis-cli setup wizard` phases 2 / 3 / 4 per §9, including:
      - Per-key smoke test against the provider's lightest authenticated endpoint.
      - On-disk write to `<data_dir>/providers/<provider>.toml` (chmod 0600).
      - Auto-population of `[[providers.credentials]]` with the SHA-256-derived `key_ref`.
      - Auto-population of `[providers] permitted_models` with the §4 recommended set for the configured provider count.
      - Auto-generation of `[orchestrator] provider_alias` + chain and `[provider_aliases_defaults.{reviewer, executor}]` per §5.2 `auto_diversify`.
      - `--no-diversify` and `--reset-chains` flags per §5.3 / §9.5.
- [ ] `raxis-cli setup wizard --add-provider <id>` re-runs phases 2 + 4 only.
- [ ] `raxis-cli plan prepare` consumes `[provider_aliases_defaults]` per §7.3; idempotent re-runs per `operator-ergonomics.md §4.4`.
- [ ] `raxis-cli plan explain` (`operator-ergonomics.md §9`) renders per-task resolved alias and the alias's chain (so operators can see "task X uses chain Y" in plain English).

### Tests

- [ ] **Single-provider wizard.** Run wizard with only Anthropic key entered → policy generated matches §4.1 exactly; smoke test passes.
- [ ] **Two-provider wizard.** Run wizard with Anthropic + OpenAI → policy matches §4.2; Reviewer primary is on the SECOND-entered provider per cross-role diversification.
- [ ] **Three-provider wizard.** Run wizard with Anthropic + OpenAI + Google → policy matches §4.3.
- [ ] **`--no-diversify` wizard.** Run wizard with two providers and `--no-diversify` → all roles' primaries on the FIRST-entered provider; second provider only as fallback.
- [ ] **`--add-provider` re-run.** Existing single-provider deployment; run `--add-provider openai` → chains regenerate to two-provider layout; `[[providers.credentials]]` entries gain the new one.
- [ ] **Provider key smoke test failure.** Wizard rejects an invalid Anthropic key and re-prompts.
- [ ] **Defaulting on plan submission.** Plan with no `[provider_aliases.reviewer]` → `plan prepare` fills it from policy default; bundle bytes include the filled chain.
- [ ] **Defaulting idempotency.** Re-running `plan prepare` on an already-prepared plan → no-op when policy default is unchanged.
- [ ] **Defaulting drift.** Bump `[provider_aliases_defaults.reviewer]` chain in policy; re-run `plan prepare` on a previously-prepared plan → `FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED { fields: ["provider_aliases.reviewer.chain"] }`.
- [ ] **Profile override.** Profile declares its own `provider_alias` → `plan prepare` does NOT default `[provider_aliases.executor]` for tasks using that profile (per §7.4).
- [ ] **Policy validation: unpermitted model in default.** `[provider_aliases_defaults.reviewer] chain = ["unpermitted:model"]` → `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_REFERENCES_NONPERMITTED_MODEL`.
- [ ] **Policy validation: missing credential in default.** Default chain references "google:gemini-2.5-pro" but no `[[providers.credentials]] provider_id = "google"` exists → `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_MISSING_CREDENTIAL`.
- [ ] **Policy validation: empty chain.** `[provider_aliases_defaults.reviewer] chain = []` → `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_EMPTY_CHAIN`.
- [ ] **Policy validation: unknown role.** `[provider_aliases_defaults.summarizer] chain = [...]` → `WARN_PROVIDER_ALIAS_DEFAULT_UNKNOWN_ROLE`; policy still loads.
- [ ] **Single-provider warning.** Two-provider deployment with `[provider_aliases_defaults.reviewer] chain = ["only:one_model"]` (length 1) → `WARN_PROVIDER_ALIAS_PRIMARY_NO_FAILOVER`.
- [ ] **V1 alias-name compatibility.** Policy with `[orchestrator] provider_alias = "fast_low_cost"` (the V1 default name) still loads but emits a one-line `WARN_ORCHESTRATOR_DEFAULT_ALIAS_RENAMED` recommending rename to `orchestrator_default`.
- [ ] **Cross-spec: setup wizard end-to-end smoke.** Wizard from clean `$RAXIS_DATA_DIR` → operator-key generation → 2-provider entry → permitted-models acceptance → alias-chain generation → first plan submission via `plan init → plan prepare → submit plan`. Total wall-clock under 5 minutes on a fresh host.

---

## §12 — Cross-Spec Impacts

| Spec | Change |
|---|---|
| `policy-plan-authority.md` | New `[provider_aliases_defaults]` section in §4. Rename `[orchestrator] provider_alias` default value from `"fast_low_cost"` to `"orchestrator_default"`; update recommended chain. New `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_*` and `WARN_PROVIDER_ALIAS_*` codes in §3b failure catalog. |
| `operator-ergonomics.md` | `§4.2` defaultable-fields table gains `[provider_aliases.reviewer]` and `[provider_aliases.executor]`. `§16.3` setup wizard rewritten to incorporate phases 2–4 per this spec's §9. `§20` failure catalog cross-references the new codes. |
| `provider-failure-handling.md` | No structural change. `§3.2` (plan declares aliases) gains a brief cross-reference noting that the typical authoring path now goes through `plan prepare` defaulting from `policy.toml [provider_aliases_defaults]`. |
| `environment-access-control.md` | `§5b.4` reserved-fields list gains `override_reviewer_alias` for V2.x per-environment Reviewer model overrides. |
| `paradigm.md` | `§5.1` gains a brief paragraph documenting the two-credential-system architectural property as an implementation pattern that satisfies R-2. |
| `v1/peripherals.md` | No change. The `<data_dir>/providers/` storage convention is already canonical there; this spec just cross-references it. |
| `key-revocation.md` | No change. Provider-key rotation already covered there; this spec's chains are the consumers. |
| `setup-wizard` (within `operator-ergonomics.md`) | Existing phases 1–6 reorganized to insert the §9 provider/model phases; downstream tests unchanged. |
