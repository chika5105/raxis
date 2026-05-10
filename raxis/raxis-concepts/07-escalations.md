# RAXIS Escalations — End-to-End Explained

## What is an escalation?

An escalation is the kernel's **human-in-the-loop mechanism**. When an agent can't proceed — it needs file system access outside its worktree, needs to run a dangerous operation, or hit a policy wall — it submits an escalation request. The kernel parks the task and notifies the operator. Only when the operator approves (with their Ed25519 signature) does the task resume.

The agent **cannot** approve its own escalation.

---

## Step 1: Agent Hits a Boundary

The agent realizes it needs to do something outside its authorized scope:

```json
{
  "kind": "EscalationRequest",
  "reason": "NeedCapability",
  "capability_class": "WriteCode",
  "scope": "migrations/**",
  "justification": "Need to add a new migration for the users table"
}
```

---

## Step 2: Kernel Parks the Task

The kernel:
1. Writes an `escalation_requests` row with `state = Pending`
2. Transitions the task to `EscalationPending` state
3. Emits an `EscalationCreated` audit event
4. Pushes a `KernelPush::EscalationRequested` to the dashboard/notification system
5. Returns `IntentResponse::Escalated` to the agent

The agent enters a wait loop. It cannot submit any more intents until the escalation resolves.

---

## Step 3: Operator Reviews

The operator sees the escalation in the dashboard or CLI:

```bash
raxis-cli escalation list --pending
```

Output:
```
ID         | Task     | Capability | Scope          | Justification
esc-abc123 | task-1   | WriteCode  | migrations/**  | Need migration for users table
```

---

## Step 4: Operator Decides

### Approve:
```bash
raxis-cli escalation approve esc-abc123 \
  --scope "migrations/**" \
  --ttl 3600
```

This:
1. Generates an `ApprovalToken` with Ed25519 signature
2. Writes an `approval_tokens` row
3. Grants the delegation (if the escalation was for a capability)
4. Transitions the task back to `Running`
5. Emits `EscalationApproved` audit event
6. Pushes `KernelPush::EscalationResolved` to the agent

### Reject:
```bash
raxis-cli escalation reject esc-abc123 \
  --reason "Migration not needed for this task"
```

This:
1. Transitions the escalation to `Rejected`
2. The task stays parked (the agent can't proceed on this path)
3. The agent receives `EscalationRejected` and must adapt

---

## Step 5: Agent Resumes

After approval, the agent's next `IntentRequest` includes the `ApprovalToken`:

```json
{
  "intent_kind": "SingleCommit",
  "approval_token": {
    "approval_id": "apr-xyz",
    "escalation_id": "esc-abc123",
    "operator_sig": "ed25519-signature-hex"
  }
}
```

The kernel validates all three fields together:
- `approval_id` exists in `approval_tokens`
- `escalation_id` matches the original escalation
- `operator_sig` is a valid Ed25519 signature from the approving operator

---

## The Escalation Flow (Visual)

```
Agent needs WriteCode for migrations/**
        │
        ▼
    ┌── EscalationRequest ─────┐
    │  Submit to kernel        │
    └──────────────────────────┘
        │
        ▼
    ┌── Kernel Parks Task ─────┐
    │  task.state →            │
    │  EscalationPending       │
    │  Notify operator         │
    └──────────────────────────┘
        │
    ┌───┴───────────────┐
    ▼                   ▼
  Approve             Reject
    │                   │
    ▼                   ▼
  Grant delegation    Task stays
  Resume task         parked
    │
    ▼
  Agent includes
  ApprovalToken in
  next IntentRequest
```

---

## Edge Cases

### 1. Agent tries to use an expired approval token

Approval tokens have TTLs. If the agent waits too long → token expired → intent rejected with `FAIL_INVALID_REQUEST`. The agent must re-escalate.

### 2. Agent submits approval token for a different escalation

The kernel checks `approval_token.escalation_id` against the original escalation record. Mismatch → rejected.

### 3. Two escalations from the same task

The kernel allows multiple escalations, but only one can be `Pending` at a time per task. The second escalation is queued until the first resolves.

### 4. Operator approves but with narrower scope than requested

The operator can scope-restrict the approval:
```bash
raxis-cli escalation approve esc-abc123 --scope "migrations/v2/**"
```

This grants a delegation for `migrations/v2/**` even though the agent requested `migrations/**`. If the agent then touches `migrations/v1/...`, the scope check fails.

---

## Cooldown and Rate Limiting

> [!WARNING]
> **Escalation cooldown is spec'd but NOT fully enforced.**
>
> The spec says (kernel-core.md §2.4):
> "After a rejected escalation, the session enters a cooldown period
> during which no new escalations are accepted."
>
> The cooldown timer is present in the `escalation_requests` schema
> (`cooldown_until_at` column) but the enforcement in the intent handler
> is a TODO. Currently, an agent can re-escalate immediately after rejection.
>
> **Impact:** An agent could spam escalation requests, flooding the
> operator's notification queue. This is low-risk (the operator can
> revoke the session) but should be closed.

---

## Key Source Files

| File | Role |
|------|------|
| `kernel/src/ipc/handlers/escalation.rs` | Escalation create/resolve handlers |
| `kernel/src/scheduler/escalation.rs` | Escalation state management |
| `crates/types/src/intent.rs` | `ApprovalToken` wire type |
| `crates/types/src/lib.rs` | `EscalationId` type |
| `dashboard-fe/src/pages/Escalations.tsx` | Operator-facing escalation UI |
