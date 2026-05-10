# RAXIS Policy Configuration — End-to-End Explained

## What is policy.toml?

`policy.toml` is the **single source of truth** for what an AI agent can and cannot do. The operator writes it, signs it, and the kernel enforces it. The agent never sees or modifies the policy.

---

## Policy Sections Overview

```toml
# ┌────────────────────────────────────┐
# │          policy.toml               │
# ├────────────────────────────────────┤
# │ [operators]     — who can operate  │
# │ [sessions]      — session limits   │
# │ [lanes]         — budget lanes     │
# │ [claim_req]     — proof gates      │
# │ [[gates]]       — verifier config  │
# │ [egress]        — outbound access  │
# │ [delegations]   — capability rules │
# │ [gateway]       — fetch proxy      │
# │ [[providers]]   — LLM providers   │
# │ [[custom_tools]]— agent tools     │
# │ [budget]        — cost limits      │
# └────────────────────────────────────┘
```

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
domains = ["github.com", "registry.npmjs.org"]
patterns = ["*.githubusercontent.com"]
max_fetches_per_window = 100
```

The agent can only make HTTP fetches to these domains. Everything else is blocked by the kernel's fetch proxy.

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

### `[[custom_tools]]` — Agent-Available Tools

```toml
[[custom_tools]]
name = "lint_check"
description = "Run the project linter"
command = "/usr/local/bin/lint.sh"
timeout_secs = 60
```

Custom tools are sandboxed subprocesses the agent can invoke.

### `[budget]` — Global Cost Limits

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

## Policy Signing

The operator signs the policy with their Ed25519 key. The kernel verifies the signature at load time:

```bash
raxis-cli policy sign --key operator.key --policy policy.toml
```

An unsigned or mis-signed policy is rejected at load time. The agent can never trick the kernel into loading a different policy.

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

## Key Source Files

| File | Role |
|------|------|
| `crates/policy/src/bundle.rs` | `PolicyBundle`, all sections, `RawPolicy` |
| `crates/policy/src/lib.rs` | `load_policy()` entry point |
| `kernel/src/policy_manager.rs` | Hot reload, epoch advance |
| `crates/genesis-tools/src/lib.rs` | Genesis policy generation |
