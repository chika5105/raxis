# `[model_routing]` — role model selection

> **Topic:** Policy reference | **Time to read:** ~3 min | **Complexity:** Intermediate

`[model_routing]` is the operator-owned policy surface for model
selection. It answers: which model may serve each planner role, in
what fallback order, and with what turn budget.

Gateway process mechanics are not policy. The kernel owns gateway
binary discovery, sockets, process tokens, respawn backoff, and crash
recovery as runtime behavior. A signed policy can approve providers
and choose role model routing, but it cannot point the kernel at an
arbitrary gateway binary.

When `[[providers]]` are declared, `[model_routing]` is required. Every
planner role must have at least one selected model.

---

## Field Reference

| Field | Type | Required | Effect |
|---|---|---|---|
| `orchestrator_model` | `String` | one of model or chain | Primary model for orchestrator sessions. |
| `executor_model` | `String` | one of model or chain | Primary model for executor sessions. |
| `reviewer_model` | `String` | one of model or chain | Primary model for reviewer sessions. |
| `orchestrator_chain` | `String[]` | one of model or chain | Ordered fallback chain for orchestrators. First entry is primary. |
| `executor_chain` | `String[]` | one of model or chain | Ordered fallback chain for executors. |
| `reviewer_chain` | `String[]` | one of model or chain | Ordered fallback chain for reviewers. |
| `executor_rotate_primary` | `bool` | no | Rotates executor primary model by task id while preserving the same fallback set. Useful for live e2e and provider diversification. |
| `planner_max_turns_default` | `u32` | no | Org default for planner turns when a task omits `max_turns`. Per-task values still win. |
| `planner_max_turns_step_default` | `u32` | no | Org default for progressive retry turn scaling when a task omits `max_turns_step`. |

---

## Example

```toml
[model_routing]
orchestrator_chain = ["claude-haiku-4-5", "gemini-2.5-flash"]
executor_chain     = ["claude-haiku-4-5", "gemini-2.5-flash", "gpt-5.3-codex"]
executor_rotate_primary = true
reviewer_chain     = ["gpt-5.3-codex", "claude-haiku-4-5"]

planner_max_turns_default = 100
planner_max_turns_step_default = 50
```

The chain order is the operator's business decision. The kernel uses a
fallback only for retryable provider/model availability failures; it
does not use fallbacks to bypass policy, budget, tool, or verifier
rejections.

---

## Policy And Plan Resolution

Policy is the security envelope; plan must fit inside it.

| Rule | Result |
|---|---|
| Permissions | Intersection: policy and plan must both allow it. |
| Protections | Union: policy-required gates and approvals remain active. |
| Ceilings | Smaller value wins. |
| Floors | Larger value wins. |
| Locked defaults | Policy wins completely; conflicting plans are rejected. |

For model routing, this means a plan can choose only models/providers
published by policy. It cannot introduce an unapproved provider, model,
credential, VM image, lane, or egress host.

---

## Common Failure Modes

| Symptom | Fix |
|---|---|
| `FAIL_POLICY_RUNTIME_SECTION_FORBIDDEN: [gateway]` | Remove `[gateway]`. Put approved vendors in `[[providers]]` and model choices in `[model_routing]`. |
| `[[providers]]` declared but `[model_routing]` missing | Add at least one model or chain for orchestrator, executor, and reviewer. |
| Empty chain entry | Remove empty strings from `<role>_chain`. |
| Plan targets model not in policy | Add the model/provider to policy, or change the plan to use an approved one. |
