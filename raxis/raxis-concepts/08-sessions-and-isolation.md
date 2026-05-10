# RAXIS Sessions & Isolation — End-to-End Explained

## What is a session?

A session is the kernel's **identity binding** for an agent. Every agent runs inside one session. The session determines:
- What task the agent is working on
- What capabilities the agent has (via delegations)
- What credentials the agent can access (via credential proxies)
- What its security boundaries are (via the isolation backend)

An agent cannot act without a session. A session cannot be created by the agent.

---

## Session Lifecycle

```
Kernel receives plan with tasks
        │
        ▼
    ┌── Session Creation ──────┐
    │  1. Generate session_id  │
    │  2. Generate session     │
    │     token (HMAC)         │
    │  3. Bind to task_id      │
    │  4. Set agent_type       │
    │     (Orchestrator/       │
    │      Executor/Reviewer)  │
    │  5. Start credential     │
    │     proxies              │
    │  6. Spawn agent VM       │
    └──────────────────────────┘
        │
        ▼
    ┌── Active ────────────────┐
    │  Agent submits intents   │
    │  Token validated on each │
    │  Sequence number enforced│
    └──────────────────────────┘
        │                    │
        │ Task completes     │ Operator revokes
        │ or fails           │ or TTL expires
        ▼                    ▼
    ┌── Teardown ─────────────┐
    │  1. Stop credential     │
    │     proxies              │
    │  2. Kill agent VM       │
    │  3. Release budget      │
    │  4. Mark session revoked│
    └──────────────────────────┘
```

---

## Session Authentication

Every `IntentRequest` is authenticated:

1. **Token check:** `HMAC(session_id, kernel_secret)` must match the token presented
2. **Sequence check:** The request's sequence number must be monotonically increasing. The kernel maintains a nonce cache. Replay → rejected.
3. **Revocation check:** `sessions.revoked_at IS NULL`. A revoked session's intents are permanently rejected.

The agent receives its session token at spawn time via environment variable. It cannot generate new tokens.

---

## Isolation Backends

The session specifies how the agent is isolated. The kernel supports multiple isolation backends:

| Backend | How it works | Boundary strength |
|---|---|---|
| **MicroVM (AVF/Firecracker)** | Dedicated VM per agent. Separate kernel, memory, network namespace | Hardware-level isolation |
| **Container (Docker/OCI)** | Isolated process namespace. Shared kernel | OS-level isolation |
| **Process (dev mode)** | Direct subprocess on the host | Minimal isolation |

### MicroVM isolation provides:
- **Separate memory space** — agent cannot read kernel memory
- **Separate filesystem** — agent sees only its worktree (mounted via VirtioFS)
- **Separate network namespace** — agent can only reach `localhost` (where credential proxies are bound)
- **Resource limits** — max CPU, max memory, max disk I/O

### What the agent can see:

```
/ (read-only root filesystem)
├── /work/            ← VirtioFS mount of the git worktree (read-write)
├── /raxis/session.env ← Session metadata (session_id, task_id, ports)
└── localhost:PORT    ← Credential proxy endpoints
```

The agent cannot:
- See the kernel's database
- See other agents' worktrees
- Make outbound network requests (unless egress is allowed in policy)
- Read credential values (only localhost proxy ports)

---

## System Prompt Assembly

The agent's system prompt is dynamically assembled at session start by the kernel:

```rust
// From planner-core/src/driver.rs
let prompt = render_system_prompt_for_role(
    role,
    task_description,
    policy_context,
    available_tools,
    credential_ports,
    ...
);
```

The system prompt tells the agent:
- What task it's working on
- What tools are available
- Where credentials are (as `localhost:PORT`)
- Its role-specific instructions (Orchestrator, Executor, Reviewer)

The system prompt does **not** tell the agent:
- What claim types it needs (the kernel handles this)
- Raw credential values
- Other sessions' information
- Kernel internals

---

## V2 Agent Types

V2 introduces three agent types per session:

| Type | Can do | Cannot do |
|---|---|---|
| **Orchestrator** | `ActivateSubTask`, `RetrySubTask`, `StructuredOutput` | Direct code commits |
| **Executor** | `SingleCommit`, `IntegrationMerge`, `CompleteTask`, `ReportFailure`, `StructuredOutput` | Spawn sub-tasks |
| **Reviewer** | `SubmitReview` (approve/reject executor's code) | Code commits, StructuredOutput |

This is enforced by the **static dispatch matrix** — the kernel has a compile-time table mapping `(IntentKind, AgentType) → Permitted/Denied`. Adding a new `IntentKind` breaks compilation until a row is added.

---

## Edge Cases

### 1. Agent tries to act on someone else's task

The kernel checks `task.session_id == request.session_id`. One session = one task. Mismatch → rejected.

### 2. Two agents share the same VM

Not possible. Each session gets its own isolation unit. The kernel enforces this at spawn time.

### 3. Session TTL expires mid-work

The kernel detects the expiry on the next intent submission. The task transitions to `Failed` with `reason = SessionExpired`. The agent's VM is torn down.

### 4. Agent crashes and the VM dies

The kernel detects the VM exit. The task enters a `Failed` state. In V2, the Orchestrator can issue `RetrySubTask` to re-spawn the executor (subject to retry limits).

### 5. Operator revokes a session while the agent is running

The session row gets `revoked_at = now`. The agent's next intent is rejected with `SessionRevoked`. The VM continues running but can't submit any work. On the next liveness check, the kernel terminates the VM.

---

## Gap Found: Session Liveness Check

> [!WARNING]
> **Proactive session liveness monitoring is spec'd but minimal.**
>
> The kernel detects session death reactively (when the next intent fails
> or the VM process exits). The spec envisions a periodic heartbeat from
> the agent to the kernel, with a timeout that triggers proactive cleanup.
>
> Currently, if an agent hangs (no crash, no exit, just infinite loop),
> the session stays active until its TTL expires. The wall-clock session
> TTL is the only safety net.
>
> **Impact:** A hung agent consumes its lane budget reservation for the
> full TTL duration, potentially blocking other tasks from running.

---

## Key Source Files

| File | Role |
|------|------|
| `kernel/src/session/mod.rs` | Session creation, revocation, lookup |
| `kernel/src/ipc/auth.rs` | Token validation, sequence check |
| `crates/planner-core/src/driver.rs` | System prompt assembly, agent dispatch loop |
| `crates/types/src/lib.rs` | `SessionId`, agent type enums |
| `crates/credential-proxy-manager/src/lib.rs` | Proxy lifecycle tied to session |
