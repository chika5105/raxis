# RAXIS Policy Configuration — End-to-End Explained

> **Audience.** Operators authoring `policy.toml`, security
> reviewers checking that an organisation's policy enforces the
> expected ceilings, and contributors changing `RawPolicy` /
> `PolicyBundle` in `crates/policy/src/bundle.rs`.
>
> **Authority.** The structural source of truth is
> `crates/policy/src/bundle.rs::RawPolicy` (the deserialised
> shape) and `PolicyBundle` (the validated runtime shape). Spec
> documents to consult: `specs/v1/kernel-store.md` §2.5.5/2.5.6
> (operators + gates), `specs/v2/policy-plan-authority.md` (which
> field belongs in policy vs plan), `specs/v2/custom-tools.md`,
> `specs/v3/otel-observability.md` (V3 telemetry section),
> `specs/v2/credential-proxy.md` §12 (credential schema fields).
>
> **Paradigm anchor.** `policy.toml` is the implementation of
> **R-7 — Operator-bound authority** at the policy layer:
> every privilege the kernel hands out is rooted in an
> Ed25519-signed TOML file controlled by the operator, and
> `arc_swap` makes hot reloads atomic so an in-flight intent
> cannot straddle epochs.

---

## What is policy.toml?

`policy.toml` is the **single source of truth** for what an AI agent can and cannot do. The operator writes it, signs it, and the kernel enforces it. The agent never sees or modifies the policy.

Where there is a tension between `policy.toml` and `plan.toml`,
**policy wins** — `INV-PLAN-POLICY-PRECEDENCE-01` (see
`specs/v2/policy-plan-authority.md`) defines the precedence:
*locked* fields (e.g. `target_ref`) cannot be overridden from
plan, *floor* fields (e.g. `max_custom_tool_timeout_seconds`) cap
plan-side requests, and *defaults-with-override* fields let plan
narrow but not widen.

---

## Policy sections overview

The canonical section list comes straight from
`crates/policy/src/bundle.rs::RawPolicy`:

```toml
# ┌────────────────────────────────────────────────────────────┐
# │                     policy.toml                            │
# ├────────────────────────────────────────────────────────────┤
# │ [sessions]              — TTL & concurrency caps           │
# │ [budget]                — admission cost + LLM token caps  │
# │ [operators]             — Ed25519 signing keys + permitted │
# │ [[gates]]               — verifier binaries per claim type │
# │ [[lanes]]               — budget lane definitions          │
# │ [claim_requirements]    — path → required claim types      │
# │ [egress]                — fetch proxy allow-list           │
# │ [[providers]]           — LLM provider catalogue (optional)│
# │ [delegations]           — role ceilings + max TTL          │
# │ [gateway]               — gateway proxy config (optional)  │
# └────────────────────────────────────────────────────────────┘
```

**`[[custom_tools]]` does NOT live in `policy.toml`.** Earlier
drafts of this guide put it here; it actually lives in
`plan.toml` (see `specs/v2/custom-tools.md` §3 — declared inline
in `plan.toml`, hard-capped by `policy.toml`'s
`max_custom_tool_timeout_seconds` / `max_concurrent_custom_tool_invocations`
fields).

---

## Section-by-Section

### `[operators]` — Who Can Operate

```toml
[[operators.entries]]
fingerprint = "abc123..."
pubkey = "ed25519-pubkey-hex"
display_name = "Alice"
permitted_ops = ["grant_delegation", "approve_escalation", "revoke_session"]
cert = "-----BEGIN RAXIS OPERATOR CERT-----\n..."
```

Every operator has an Ed25519 keypair. Their public key is embedded in the policy. Their private key stays on their machine. The kernel verifies every operator action (delegation grants, escalation approvals, break-glass activations) against this key.

**INV-CERT-01:** Every operator entry must include a self-signed certificate. The policy loader rejects any entry without one.

### `[sessions]` — Session Limits

```toml
[sessions]
max_session_ttl_secs = 86400        # 24 hours max
max_delegation_ttl_secs = 3600      # 1 hour max per delegation
max_concurrent_sessions = 8         # no more than 8 agents at once
```

### `[[lanes]]` — Budget Lanes

```toml
[[lanes]]
lane_id = "feature-work"
max_concurrent_tasks = 4
max_cost_per_epoch = 1000
priority = 10
```

See [05-lanes-and-budgets.md](05-lanes-and-budgets.md) for details.

### `[claim_requirements]` — Proof Gates

```toml
[claim_requirements]
default_action = "deny"

[[claim_requirements.rules]]
path_glob = "migrations/**"
claim_types = ["TestSuite"]
```

See [01-claims-and-gates.md](01-claims-and-gates.md) for details.

### `[[gates]]` — Verifier Configuration

```toml
[[gates]]
gate_type = "TestSuite"
verifier_command = "/usr/local/bin/run-tests.sh"
max_wall_seconds = 120
max_memory_bytes = 536870912
network_allowed = false
```

Each gate maps a `claim_type` to a deterministic verifier binary.

### `[egress]` — Outbound Network Access

```toml
[egress]
domains  = ["github.com", "registry.npmjs.org"]
patterns = ["*.githubusercontent.com"]
max_fetches_per_window = 100

# V2 default-include for inference providers (default: true).
# When true, the kernel auto-grants the canonical FQDN of every
# [[providers]] entry below (Anthropic ⇒ api.anthropic.com,
# OpenAI ⇒ api.openai.com, Gemini ⇒
# generativelanguage.googleapis.com, Bedrock ⇒
# bedrock-runtime.<region>.amazonaws.com, http_sidecar ⇒ host of
# sidecar_endpoint). Set to false ONLY if you intend to list every
# provider FQDN by hand under `domains`.
implicit_provider_grants = true

# Optional opt-out — drop the implicit grant for one or more
# provider ids. Each id MUST appear in [[providers]]; unknown ids
# are rejected at policy load. Use this when you need to hard-deny
# a single provider while still benefitting from defaulting on the
# others.
deny_provider = []
```

The agent can only make HTTP fetches to the *effective* allowlist
— the union of the explicit `domains` / `patterns` above with the
implicit provider FQDNs derived from `[[providers]]` (minus any in
`deny_provider`). Everything else is blocked by the kernel's
egress chokepoints (`raxis-tproxy` for Tier-1 VMs and the
kernel-mediated fetch path for Reviewers). Each implicit grant
emits one `DefaultProviderEgressApplied` audit event at kernel
boot and after every `RotateEpoch` so operators can audit exactly
what was granted by default. See
`specs/v2/reviewer-egress-defaults-decision.md` for the full
rationale and `specs/v2/vm-network-isolation.md §4.1` for how the
effective allowlist is consumed by the transparent proxy.

### `[[providers]]` — LLM Providers

```toml
[[providers]]
provider_id = "anthropic-prod"
kind = "Anthropic"
credentials_file = "anthropic.toml"
inference_timeout_ms = 30000

[providers.pricing]
input_tokens_per_dollar = 200000
output_tokens_per_dollar = 50000
```

### `[delegations]` — Role ceilings

```toml
[delegations]
max_delegation_ttl_secs = 3600

[delegations.role_ceilings]
"executor-junior" = ["WriteCode", "RunTests"]
"executor-senior" = ["WriteCode", "RunTests", "WriteSecrets"]
"orchestrator"    = ["WriteCode", "RunTests"]
```

Operator delegation grants are clamped to the role's ceiling at
grant time (INV-DELEG-03). See concept 04 for the lifecycle.

### `[budget]` — Global cost limits

```toml
[budget]
max_cost_per_task = 100        # USD cents — per-task LLM cost ceiling
cost_per_touched_path = 2      # admission cost per file touched
base_cost_single_commit = 10   # base admission cost for SingleCommit
```

---

## Policy Loading & Epoch Advancement

The kernel loads policy from disk and watches for changes:

1. **Initial load:** `load_policy(&path)` parses the TOML, validates all invariants, builds a `PolicyBundle`
2. **Hot reload:** When the file changes, the kernel re-parses and atomically swaps the policy via `arc_swap::ArcSwap<PolicyBundle>`
3. **Epoch advance:** All active delegations are marked `StaleOnNextUse` (one grace use)
4. **In-flight protection:** `evaluate_claims` pins a single policy snapshot for the duration of a gate evaluation (INV-POLICY-01)

---

## Policy signing

The operator signs the policy with their Ed25519 key. The kernel
verifies the signature at load time and again at every epoch
advance (`policy_manager::advance_epoch` Phase 0). The CLI
surface (verified against `cli/src/main.rs:319-360` and
`cli/src/commands/policy.rs`):

```bash
raxis policy sign --policy policy.toml --operator-key operator.key
```

This produces `policy.toml.sig` (raw 64-byte Ed25519 signature
in hex) alongside the policy file. The kernel verifies the
signature against the operator pubkey embedded in the *previous*
epoch's policy bundle — meaning a fresh deployment must seed the
chain via `raxis genesis` (which writes the bootstrap operator
entry).

An unsigned or mis-signed policy is rejected at load time with
`PolicyAdvanceRejected` audit event. The agent can never trick
the kernel into loading a different policy because the planner
binary doesn't link the policy crate.

---

## Edge Cases

### 1. Policy has syntax errors

`load_policy` returns `Err(PolicyError::ParseFailed)`. The kernel refuses to start. Existing running sessions continue under the old policy epoch.

### 2. Policy removes a lane that has running tasks

The tasks continue under the old lane configuration until they complete. New task admissions for the removed lane are rejected.

### 3. Policy tightens claim requirements

Existing delegations are marked `StaleOnNextUse`. The agent gets one more use, then must get a new delegation from the operator under the new policy.

### 4. Operator public key is rotated

The new policy includes the new key. The old key is removed. Any delegations signed with the old key expire naturally (TTL).

---

## Key source files

| File | Role |
|---|---|
| `crates/policy/src/bundle.rs` | `RawPolicy` (deserialise) → `PolicyBundle` (validate). All section structs live here |
| `crates/policy/src/loader.rs` | `load_policy(path)` entry point — TOML parse, signature verify, bundle build |
| `crates/policy/src/lib.rs`    | Re-exports `load_policy`, `PolicyBundle`, error types |
| `crates/policy/src/error.rs`  | `PolicyError` taxonomy |
| `kernel/src/policy_manager.rs` | Hot reload + `advance_epoch` (Phase 0/1/2/3, INV-POLICY-01) |
| `kernel/src/authority/dispatch_matrix.rs` | V2 static `(IntentKind, SessionAgentType)` matrix — also lives outside policy because it's structural |
| `crates/genesis-tools/src/policy_toml.rs` | Genesis policy template generation (`raxis genesis`) |
| `crates/genesis-tools/src/lib.rs`         | Genesis ceremony orchestration |
| `cli/src/commands/policy.rs`              | `raxis policy sign` operator subcommand |
| `cli/src/commands/epoch.rs`               | `raxis epoch advance` operator subcommand (rotates active policy) |
| `specs/v1/kernel-store.md` §2.5.5/§2.5.6  | Normative `[[operators.entries]]`, `[[gates]]` schemas |
| `specs/v2/policy-plan-authority.md`       | Plan-vs-policy precedence (`INV-PLAN-POLICY-PRECEDENCE-01`) |
| `specs/v2/custom-tools.md`                | Custom-tools schema (lives in plan, capped by policy) |
| `specs/v2/credential-proxy.md` §12        | Credential entry schema (`raxis credential add`) |
