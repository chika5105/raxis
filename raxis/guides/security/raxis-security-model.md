# RAXIS Security Model — Complete Reference

> **Audience:** Developers, security reviewers, and operators who want to understand every
> security mechanism in RAXIS — what it does, why it exists, what attack it prevents, and
> what scenarios it handles.
>
> This document is built iteratively. Each part covers one security domain completely before
> moving to the next.

---

## Structure

| Part | Domain | Status |
|---|---|---|
| [Part 1](#part-1--foundational-security-invariants) | Foundational Security Invariants | ✅ |
| [Part 2](#part-2--process-and-authority-separation) | Process and Authority Separation | ✅ |
| [Part 3](#part-3--vm-isolation-and-network-air-gap) | VM Isolation and Network Air-Gap | ✅ |
| Part 4 | Session Authentication and Token Model | 🔜 |
| Part 5 | Intent Admission Control Pipeline | 🔜 |
| Part 6 | Static Dispatch Matrix — Role-Based Authorization | 🔜 |
| Part 7 | Path Allowlist Enforcement | 🔜 |
| Part 8 | Cryptographic Audit Chain | 🔜 |
| Part 9 | Policy Signing and the Plan Ceremony | 🔜 |
| Part 10 | Credential Isolation | 🔜 |
| Part 11 | Budget Enforcement as a Security Primitive | 🔜 |
| Part 12 | Prompt Assembly and Authority Separation | 🔜 |
| Part 13 | Escalation FSM — Formal Operator Intervention | 🔜 |
| Part 14 | Adversarial Probe Detection | 🔜 |
| Part 15 | Pre-Authentication DoS Defense | 🔜 |
| Part 16 | Policy Store and Audit Store Isolation | 🔜 |

---

## Part 1 — Foundational Security Invariants

Before any mechanism is described, the invariants they collectively enforce must be
understood. Every security decision in RAXIS traces back to one or more of these. They
are not aspirational — they are enforced structurally, and any proposal that violates
them must be rejected regardless of how convenient it would be.

### INV-01: Fail-Closed Default

**Statement:** Every enforcement gate in the system defaults to denial. If the gate cannot
determine whether an action is permitted, the action is denied.

**Why:** In a system where agents submit potentially adversarial intents, a fail-open
default means the attacker only needs to find one edge case the gate didn't anticipate to
escalate privileges. A fail-closed default means every novel or ambiguous case is denied
automatically. The system is correct-by-default; permitted cases must be explicitly
authorized, not just not-explicitly-denied.

**Where it appears:** Every intent admission check returns `FAIL_*` if preconditions are
not met, rather than attempting a "best effort" interpretation. Unrecognized intent kinds
are rejected. Epoch mismatches cause staleness rather than optimistic continuation.
Unknown paths default to the strictest claim tier. The diff engine falls back to blunt
invalidation on error rather than permissive continuation.

**Scenario it prevents:** An agent submits a novel `IntentKind` variant that wasn't in the
dispatch matrix at the time the kernel was compiled. Under fail-open, the kernel might
forward it or ignore it. Under fail-closed, the kernel returns `FAIL_UNSUPPORTED_INTENT`
and the session gets a `SecurityViolation` audit event.

---

### INV-02A: Credential Isolation

**Statement:** Planner VMs hold no provider API keys, no signing keys, and no credentials
of any kind. The only auth material a VM holds is its Kernel-issued session token.

**Why:** A planner VM that holds an API key can make arbitrary provider calls that bypass
the Kernel's budget enforcement, audit logging, and cost ceiling. The key is also
exfiltrable — if the VM is compromised, the key leaves with it. By holding zero credentials,
a compromised VM is credential-sterile: it cannot authenticate to any external system.

**Where it appears:** Credentials are stored in `$RAXIS_DATA_DIR/credentials/`, outside
the workspace and outside the VM's VirtioFS mount. The `raxis-gateway` process (host-side)
holds credentials and makes provider API calls. The gateway returns inference responses to
the Kernel over a Unix domain socket. The Kernel forwards them to the VM over VSock. The
VM never sees the credential.

**Scenario it prevents:** An attacker jailbreaks the LLM running inside a VM and attempts
to exfiltrate the Anthropic API key to make unauthorized provider calls. Because the VM
holds no credential, there is nothing to exfiltrate. The compromised VM can only submit
`InferenceRequest` frames to the Kernel, which enforces budget and audit on every call.

---

### INV-02B: Network Isolation

**Statement:** Planner VMs have no network egress. There is no virtual NIC device in
the VM configuration.

**Why:** A VM with network access can exfiltrate secrets, receive C2 commands, push code
to unauthorized repositories, make API calls that bypass the Kernel's audit, and
communicate with other agents outside the Kernel-mediated channel. The only channel out
of the VM is the VSock connection to the Kernel. Everything else is structurally absent.

**Where it appears:** The Apple Virtualization Framework VM configuration for each agent
session omits all `VirtioNetworkDeviceConfiguration` entries. There is no NAT, no bridge,
no loopback interface beyond localhost. This is enforced by the hypervisor — a process
inside the VM cannot create a network interface through software.

**Scenario it prevents:** A compromised Executor VM attempts to `git push` the Executor's
branch directly to the remote repository, bypassing the Orchestrator's `IntegrationMerge`
review. Without a network interface, `git push` fails at the TCP connection attempt. The
only mechanism to get code into the remote repository is through `IntegrationMerge`, which
requires Reviewer approval and Kernel path-allowlist verification.

---

### INV-03: SHA Integrity (No Rewriting)

**Statement:** Git commits produced by agents are never rewritten, cherry-picked, or
rebased by the Kernel or the Orchestrator. The SHA produced by the Executor's `git commit`
is the same SHA that appears in the master branch after `IntegrationMerge`.

**Why:** SHA rewriting (rebase, cherry-pick, `git commit --amend`) creates a new commit
object with a new SHA. The original SHA — which appears in the audit event, in the
Reviewer's evaluation record, and in the witness manifest — no longer exists in the
repository. An auditor querying `git show <original_sha>` after a rebase gets "object not
found." The audit trail references ghost objects.

**Where it appears:** The Orchestrator's merge duty specifies `git merge` only (never
`git rebase`, `git cherry-pick`, or `git format-patch / git am`). The Kernel verifies
that `IntegrationMerge { commit_sha }` is a fast-forward or true merge commit that
preserves the Executor's original SHA as a parent. Any ancestry violation causes the
`IntegrationMerge` to be rejected.

**Scenario it prevents:** An Orchestrator (potentially compromised) attempts to rebase
the Executor's branch before merging, producing a new commit with the same diff but a
different SHA. The Reviewer evaluated SHA `abc123`. Post-rebase, master shows SHA `def456`.
An auditor cannot verify that what was reviewed is what was merged. RAXIS's ancestry
verification catches the SHA mismatch and rejects the `IntegrationMerge`.

---

### INV-05: Cryptographic Audit Chain Integrity

**Statement:** Every action in the system produces a signed, append-only audit event.
The audit chain is self-consistent and independently verifiable. No event can be removed,
modified, or inserted without detection.

**Why:** An audit log that can be tampered with is not an audit log — it is a history
that can be revised. For compliance, forensics, and post-incident reconstruction, the audit
chain must be authoritative. An agent that can modify the audit log can hide its own
malicious actions.

**Where it appears:** The audit store lives at `$RAXIS_DATA_DIR/audit/`, outside the
workspace and outside every VM's VirtioFS mount. Audit events are written exclusively
by the Kernel's append endpoint — no planner or gateway process has a write path to the
audit store. Each event is chained (hash of previous event included in the next), making
insertion or deletion detectable. The session's `plan_artifact_sha256` is included in the
`SessionCreated` event, cryptographically linking every session to the exact plan bytes
the operator signed.

**Scenario it prevents:** A compromised Executor attempts to delete the audit events
recording its malicious commits before a security review. The VM has no path to
`$RAXIS_DATA_DIR/audit/` — the VirtioFS mount only exposes the worktree. Even the
Kernel's own internal processes write to the audit store through the append-only endpoint,
not through direct file manipulation. The chain structure means any gap or modification
is detectable during verification.

---

### INV-STORE-02: Multi-Table Atomicity

**Statement:** Every state transition that spans multiple database tables is executed in a
single SQLite `BEGIN IMMEDIATE` transaction. A partial write — where some tables are updated
and others are not — never persists.

**Why:** A partial write creates an inconsistent state. For example, if a session is created
in `sessions` but the corresponding `subtask_activations` row is not created atomically,
the Kernel may attempt to activate a session with no plan context. Inconsistent state is
a security vulnerability: a carefully-timed crash or race condition at a partial write
boundary could leave the system in a state where authorization checks pass for a session
that was never properly admitted.

**Where it appears:** Every handler in `kernel/src/handlers/` wraps its multi-table writes
in `BEGIN IMMEDIATE ... COMMIT`. The audit event pointer is written in the same transaction
as the state change it records. If the transaction fails, it is rolled back entirely and
the Kernel returns a failure response to the submitter. The submitter must retry.

**Scenario it prevents:** An adversary times a SIGKILL to the Kernel process between the
`sessions` INSERT and the `subtask_activations` INSERT during `ActivateSubTask`. On restart,
the Kernel finds a session row with no activation context. Under the atomicity invariant,
this is impossible — the transaction either completes entirely or not at all.

---

*Part 1 complete — 6 foundational invariants documented. Next: Part 2 — Process and
Authority Separation.*

---

## Part 2 — Process and Authority Separation

### Why Intelligence and Authority Cannot Share a Process

The most foundational structural decision in RAXIS is that the process that runs LLM
inference is **never** the same process that enforces policy. This is not a preference — it
is a hard architectural invariant enforced by the separation of the `raxis-kernel` binary
from the `raxis-planner` binary, with IPC as the only bridge.

**The attack the separation prevents:**

If the LLM inference loop and the policy enforcement logic share a process, then a
jailbroken LLM output can influence policy decisions in the same memory space. Example:
the LLM produces output that looks like a function return value from the policy check,
or that overwrites a capability flag in shared memory, or that exploits a deserialiation
bug in the policy parser that the LLM's output triggers. None of these are theoretical —
prompt injection attacks that exploit shared-process architectures are a known class.

More practically: a shared-process architecture means the inference layer and the
enforcement layer are updated together. Hot-reloading inference logic (desirable for
agility) also affects the enforcement layer, creating nondeterminism in the authority
model. Separate processes mean the Kernel binary can be versioned and updated
independently of the planner binary.

**What "separate process" means structurally:**

```
┌─────────────────────────────────────────────────────────┐
│                    HOST MACHINE                          │
│                                                          │
│  ┌──────────────┐    UDS socket    ┌──────────────────┐ │
│  │ raxis-kernel │◄─────────────────│  raxis-gateway   │ │
│  │  (authority) │                  │ (provider proxy) │ │
│  └──────┬───────┘                  └──────────────────┘ │
│         │ VSock                                          │
│  ┌──────▼───────────────────────────────────────────┐   │
│  │         AVF microVM (per agent session)           │   │
│  │                                                   │   │
│  │   ┌─────────────────────────────────────────┐    │   │
│  │   │  raxis-planner (intelligence only)      │    │   │
│  │   │  - No API keys                          │    │   │
│  │   │  - No network access                    │    │   │
│  │   │  - No policy visibility                 │    │   │
│  │   │  - No audit store access                │    │   │
│  │   └─────────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

**The IPC boundary is the trust boundary.** Every intent crosses from the untrusted
intelligence layer to the trusted authority layer as a structured, typed, serialized frame
(bincode with 4-byte length prefix). The Kernel deserializes it, validates it, runs all
enforcement checks, and returns a typed response. The planner never executes in the
Kernel's address space.

### What the Planner Cannot Do (Structural Prohibitions)

These are not policy rules the planner is asked to follow. They are structural absences —
the planner binary does not have the code, the file handles, or the network sockets to
perform these actions.

| Prohibition | Mechanism |
|---|---|
| Make provider API calls | No network interface in VM; `AnthropicClient` crate not linked in planner binary |
| Read policy configuration | `$RAXIS_DATA_DIR/policy/` not mounted in VirtioFS |
| Write to audit store | `$RAXIS_DATA_DIR/audit/` not mounted; planner has no audit write IPC endpoint |
| Write to witness store | `$RAXIS_DATA_DIR/witness/` not mounted; planner has no witness write IPC endpoint |
| Evaluate its own permissions | Permission evaluation code lives in the Kernel, not in the planner |
| Observe another session's intents | Session tokens are per-session; the planner only sees responses to its own submitted intents |
| Influence prompt assembly | The Kernel Prompt Assembler prepends the non-negotiable system prompt before forwarding to the gateway; the planner's `messages` array is appended after |

### The Gateway as a Controlled Provider Proxy

The `raxis-gateway` process runs on the host (not inside any VM) and is the only process
that holds provider credentials and makes outbound API calls. It receives `InferenceRequest`
frames from the Kernel over a Unix domain socket, makes the provider API call, and returns
`InferenceResponse`.

**Why this is necessary beyond INV-02A:**
Even if the Kernel holds the credentials (not the planner), having the Kernel itself make
HTTP calls to providers embeds complex, IO-bound, provider-specific code in the authority
process. Provider APIs change; retry logic has bugs; streaming parsers have edge cases.
Embedding all of this in the Kernel grows its attack surface with every provider integration.
The gateway is separately restartable, separately auditable, and can be updated without
touching the Kernel binary.

**The gateway's authority is narrow:** It receives `InferenceRequest` (conversation history
+ tool definitions) and returns `InferenceResponse` (model output). It cannot write to the
database, cannot emit audit events, and cannot modify session state. It is a pure
computation function: request in, response out.

---

*Part 2 complete. Next: Part 3 — VM Isolation and Network Air-Gap.*

---

## Part 3 — VM Isolation and Network Air-Gap

### Why Software Sandboxes Are Insufficient for Agent Isolation

Before AVF microVMs, process-level isolation (bubblewrap, Seatbelt, seccomp) was the
candidate mechanism. These are software sandboxes — they constrain what a process can do
via kernel system call filtering.

**The fundamental problem with software sandboxes for agentic workloads:**

Software sandboxes run in the same kernel as the host. A sufficiently privileged exploit
in the sandboxed process can potentially escape to the host kernel. For agentic systems,
where the sandboxed process runs arbitrary LLM-generated code (via `bash` tool calls),
the attack surface is large. Every `sh -c "..."` call the agent makes is potential sandbox
escape surface.

AVF microVMs run in a separate virtual machine. The attack surface for escape is not the
system call interface — it is the hypervisor interface (virtio devices, VSock protocol,
VirtioFS protocol). These are significantly smaller, better-audited surfaces.

### Apple Virtualization Framework (AVF) Configuration

Each agent session runs in an AVF microVM configured as follows:

**CPU and Memory:**
- Guest vCPUs: 2 (configurable per task in the plan)
- Memory: 2 GiB default (configurable per task)
- No memory balloon device (prevents host from reclaiming memory mid-task)

**Storage devices (VirtioFS mounts only):**

| Mount point (guest) | Host path | Access |
|---|---|---|
| `/workspace` | `$RAXIS_DATA_DIR/worktrees/<session_uuid>/` | Read-write |
| `/raxis` | `$RAXIS_DATA_DIR/sessions/<session_uuid>/config/` | Read-only |

No block devices. No disk image. The planner binary itself is provided via the read-only
`/raxis` mount. The worktree is the only writable surface.

**Network devices: None.**

This is the critical configuration point. The AVF VM configuration contains no
`VirtioNetworkDeviceConfiguration` entries. No virtual NIC is created. No NAT routing
is configured. No loopback alias to the host. The VM has no network stack.

**VSock device:**
One `VirtioSocketDeviceConfiguration` is created. This is the sole communication channel
between the VM and the host. The Kernel accepts connections on the VSock port assigned to
the session (derived from the session's CID). No other VSock endpoints exist.

**Serial console:** One `VirtioConsoleDeviceConfiguration` for crash output only. Output
is written to `$RAXIS_DATA_DIR/sessions/<session_uuid>/console.log` on the host. The
console is one-directional (guest → host) and cannot receive input.

### What the Air-Gap Prevents

**Unauthorized code push:** A compromised agent cannot `git push` to the remote repository.
Without a network interface, the TCP connection attempt fails at the OS level inside the
VM. The only mechanism to get agent-produced code into the remote repository is through
the `IntegrationMerge` intent, which goes through the Kernel's ancestry verification and
path-allowlist check.

**C2 communication:** A jailbroken LLM that produces shell commands attempting to contact
a command-and-control server gets no route out. The agent can generate the command; the
network call fails silently inside the VM.

**Data exfiltration:** Secrets the agent encounters during its work (API keys in config
files, database connection strings in environment files) cannot be sent to an external
server. The VSock channel is the only egress, and it carries only structured RAXIS IPC
frames that the Kernel inspects.

**Cross-session communication:** Agents cannot reach each other's VSock ports directly.
VSock CIDs are host-assigned; VMs do not know each other's CIDs. The only mechanism to
influence another agent's work is to write files into the git worktree, which are then
mediated by the Orchestrator's merge cycle (see the file-mediation discussion in
`structured-debate.md`).

### VirtioFS Boundary

The VirtioFS mount is how the host exposes the git worktree to the guest VM. The host
controls which directories are mounted and with what permissions.

**Security properties of VirtioFS in RAXIS:**

1. **Per-session isolation:** Each session gets its own `worktrees/<session_uuid>/`
   directory. One session's VirtioFS mount does not overlap with any other session's mount.
   A compromised VM cannot traverse into a sibling VM's worktree.

2. **Read-only config mount:** The `/raxis` mount contains `session.env` (session token,
   task ID, system prompt path) and the planner binary. It is mounted read-only in the
   guest. The planner cannot modify its own session token or system prompt.

3. **Host-side path enforcement:** The host kernel enforces VirtioFS access control. A
   process inside the VM cannot construct a path traversal (`../../`) that reaches outside
   the mount point on the host — the VirtioFS driver on the host resolves paths relative
   to the mount root and rejects traversals.

### The VSock Channel — Sole Communication Surface

Every communication between the VM and the outside world goes through VSock. This makes
VSock the complete attack surface for the VM-to-host channel. RAXIS's VSock security:

**Frame format:** Every frame is a 4-byte big-endian length prefix followed by a
bincode-serialized payload. Oversized frames (length prefix > 4 MiB) are rejected without
reading the payload — preventing memory exhaustion via malformed frames.

**Session token validation:** The first frame on any new VSock connection must be a
`Handshake { session_token }` frame. The Kernel validates the token against the `sessions`
table. A token mismatch causes the connection to be closed immediately; the host-side CID
that connected is logged for pre-auth DoS tracking (see Part 15).

**CID binding:** After handshake, the Kernel records the VSock CID in `sessions.vsock_cid`.
All subsequent frames on the session must arrive on the same CID. A connection from a
different CID with a valid token is rejected — the token may have been stolen, but it can
only be used from the original VM's CID.

**Frame type validation:** Every deserialized frame is matched against the valid intent
enum. Unknown variants return `FAIL_UNSUPPORTED_INTENT` and trigger `SecurityViolation`.

---

*Part 3 complete. Next: Part 4 — Session Authentication and Token Model.*

---

## Part 4 — Session Authentication and Token Model

### Session Token Issuance

Every agent session is authenticated by a session token issued by the Kernel at session
creation time. Tokens are never created by the planner, never derived from a shared secret,
and never reused across sessions.

**Token structure:**
```
<session_id>:<hmac_sha256(session_id || initiative_id || created_at || kernel_secret)>
```

- `session_id`: UUID v4 generated by the Kernel at `ActivateSubTask`
- `initiative_id`: The initiative the session belongs to
- `created_at`: Unix timestamp of session creation
- `kernel_secret`: A random 32-byte secret generated at Kernel startup, stored in
  `$RAXIS_DATA_DIR/kernel.secret`, never exposed over any IPC channel

**Why HMAC rather than a random token:** A random token requires a database lookup to
validate every frame. An HMAC token allows the Kernel to validate authenticity without
a database hit — it re-computes the HMAC and compares. The database lookup (`sessions`
table) still happens, but only after the HMAC validates, preventing database DoS from
forged tokens.

**Scenario: forged token attempt.** A compromised Executor VM attempts to forge the
Orchestrator's session token to submit `ActivateSubTask`. Without `kernel_secret`, the
attacker cannot compute a valid HMAC. The forged token fails HMAC verification and is
rejected before the database is queried. The host-side CID that submitted the forged
token is logged for pre-auth blocklist evaluation.

### Token Lifecycle

| Event | Token state |
|---|---|
| `ActivateSubTask` admitted | Token issued; written to `.raxis/session.env` in VirtioFS before VM boots |
| Session active | Token valid; validated on every intent frame |
| `CompleteTask` or `SubmitReview` admitted | Session state → `Completed`; token remains technically valid until explicit revocation |
| `SecurityViolation` (repeated) | Token explicitly revoked: `UPDATE sessions SET revoked = 1` |
| VM exits (SIGCHLD received by Kernel) | Token invalidated; session state → `Crashed` or `Completed` |

**Why tokens persist through `Completed` state:** A completed session may still receive
a `KernelPush::EscalationResolved` if the Orchestrator needs to send it a hint after
completion. The token must be valid to authenticate the push delivery. The Kernel checks
`session.state` before allowing new intent submissions regardless of token validity.

### Session Revocation

Revocation is immediate and unconditional. When `sessions.revoked = 1`:
- Every subsequent frame on the session's VSock connection is rejected with `FAIL_REVOKED`
- The Kernel closes the VSock connection
- The VM continues running but can no longer communicate with the Kernel
- The Kernel sends SIGTERM to the VM process after a 5-second grace period

**Revocation triggers:**
1. `SecurityViolation` counter exceeds threshold (default: 3 violations)
2. Operator explicitly revokes via `raxis session revoke <session_id>`
3. Policy epoch advance that invalidates the session's `AuthPolicy` delegation and
   renewal fails (see `specs/v2/policy-epoch-diffing.md`)
4. Budget exhaustion: `sessions.budget_exhausted = 1` set after `FAIL_BUDGET_EXCEEDED`

### VSock CID Binding — Defense Against Token Theft

Even a valid token cannot be used from a different VM. At handshake time, the Kernel
records the VSock CID in `sessions.vsock_cid`. All subsequent frames must arrive on the
same CID.

**Scenario: token theft attempt.** A compromised Executor VM reads another session's
token from `/raxis/session.env` — impossible because each VM's `/raxis` mount is
session-specific and not accessible from other VMs. But assume an attacker obtained the
token through some other means (memory scraping, process injection). They attempt to use
it from a different CID. The Kernel's CID check fails: `incoming_cid ≠ sessions.vsock_cid`.
The frame is rejected with `FAIL_AUTH` and `SecurityViolation` is emitted. The original
session is flagged as potentially compromised.

**CID persistence through hot-restart:** If the Kernel restarts while a VM is running,
the VM's VSock CID is stable (assigned by the hypervisor, not the Kernel). The Kernel
reads `sessions.vsock_cid` from the database on startup and re-binds the connection when
the VM reconnects. The session resumes without requiring a new token.

---

*Part 4 complete. Next: Part 5 — Intent Admission Control Pipeline.*

---

## Part 5 — Intent Admission Control Pipeline

Every action an agent takes — whether writing a file, completing a task, or requesting
an inference — arrives at the Kernel as a typed `IntentKind` frame. The Kernel's admission
control pipeline is the central security enforcement point. It runs synchronously before
any state change is committed.

### The 13-Step Pipeline

Every intent submission passes through these checks in order. Failure at any step returns
the corresponding error code and stops processing — later steps do not run.

```
1.  Frame deserialization     → FAIL_MALFORMED_FRAME
2.  HMAC token validation     → FAIL_AUTH
3.  Session lookup            → FAIL_SESSION_NOT_FOUND
4.  Revocation check          → FAIL_REVOKED
5.  VSock CID binding check   → FAIL_AUTH (CID mismatch → SecurityViolation)
6.  Session state check       → FAIL_INVALID_STATE (e.g., Completed session submitting)
7.  Policy epoch check        → epoch_stale triggers renewal decision
8.  Dispatch matrix check     → FAIL_POLICY_VIOLATION (wrong role for intent kind)
9.  Intent-specific validation → FAIL_* (see below per intent)
10. Budget reservation        → FAIL_BUDGET_EXCEEDED
11. Dependency gate check     → DEPENDENCY_NOT_MET (for ActivateSubTask)
12. Path allowlist check      → FAIL_PATH_POLICY_VIOLATION (for SingleCommit)
13. Database commit (INV-STORE-02 atomicity)
```

**Why this order matters:** The cheapest checks (frame validity, HMAC, session lookup)
come first to prevent expensive operations being triggered by cheap attacks. A flood of
malformed frames or forged tokens is rejected before any database query runs. Path
allowlist checks (which require a VCS diff operation) come late, after cheaper checks
have already filtered the request.

### Step 9 — Intent-Specific Validation

The per-intent validation varies by `IntentKind`. Key security-relevant validations:

**`SingleCommit { base_sha, head_sha }`:**
- `base_sha` must exist in the repository: prevents phantom base references
- `head_sha` must be a descendant of `base_sha`: prevents the agent from submitting
  a commit that doesn't include the base (prevents history hiding)
- `head_sha` must be a descendant of the initiative's base branch: prevents importing
  commits from outside the initiative's scope
- Path diff of `base_sha..head_sha` computed and stored for step 12

**`ActivateSubTask { task_id }`:**
- `task_id` must exist in `subtask_activations` for this initiative: prevents phantom
  task activation
- `session.session_agent_type` must be `Orchestrator`: dispatch matrix check (step 8)
  catches this first, but intent-specific validation double-checks
- All predecessors in `task_dag_edges` must be in `Completed` state: step 11 dependency gate

**`IntegrationMerge { commit_sha, resolved_via_escalation }`:**
- `commit_sha` must be a descendant of the Orchestrator's base branch via merge commit
- `commit_sha` diff must contain only paths within the initiative's aggregate allowlist
- If `resolved_via_escalation: Some(id)` is present, `escalations.id` must be in
  `Consumed` state under `MergeConflict` class and owned by this session

**`SubmitReview { approved, critique }`:**
- Session must be a Reviewer: dispatch matrix catches this at step 8
- If `approved: false`, `critique` must be non-empty and ≤ 32,768 bytes
- The Reviewer's `evaluation_sha` must still exist in the repository (not garbage-collected)

### Fail-Closed Guarantee

Steps 1–12 are pure validation — no state change occurs. Step 13 (database commit) is the
only step that modifies state, and it runs atomically (INV-STORE-02). If any validation
step fails, the pipeline returns the error code, emits the appropriate audit event, and
does **not** run step 13. There is no partial admission.

**Scenario: time-of-check to time-of-use (TOCTOU) race.** Two concurrent `ActivateSubTask`
requests for the same `task_id` arrive simultaneously from a compromised Orchestrator. Both
pass steps 1–11 (the first request's commit hasn't landed yet). At step 13, SQLite's
`BEGIN IMMEDIATE` serializes them — the second request finds `subtask_activations.state =
'Active'` set by the first and fails. One activation succeeds; the second is rejected.
INV-STORE-02 atomicity prevents double-activation.

### SecurityViolation vs. Standard Rejection

Not all failures are equal. The Kernel distinguishes two failure classes:

**Standard rejection (`FAIL_*`):** The intent violated policy but the violation is
consistent with legitimate agent behavior (path out of scope, budget exceeded, dependency
not met). These are operational failures. They do not affect the session's trust state.

**`SecurityViolation`:** The intent indicates adversarial probing or active compromise
attempt. Triggers:
- HMAC validation failure (forged token)
- CID mismatch (token stolen and used from wrong VM)
- Submission of an unknown `IntentKind` variant
- Repeated dispatch matrix violations (same session submitting forbidden intent kinds
  multiple times — consistent with a jailbroken LLM trying different approaches)
- Frame length prefix claiming a size > 4 MiB (malformed frame attack)

`SecurityViolation` events are:
1. Emitted to the audit log with the offending CID and session (if known)
2. Counted on the session; if the count exceeds threshold, the session is revoked
3. The offending CID is added to the pre-auth blocklist for the session's duration
   (see Part 15)

---

*Part 5 complete. Next: Part 6 — Static Dispatch Matrix.*

---

## Part 6 — Static Dispatch Matrix (Role-Based Authorization)

### Why Intent Authorization Must Be Static

The dispatch matrix maps `(session_agent_type, IntentKind)` → `Permitted | Denied`. It is
compiled into the Kernel binary and is not configurable by operators, plans, or agents.

**Why static:** If the dispatch matrix were operator-configurable (e.g., "allow this
Executor to submit `ActivateSubTask`"), then a compromised plan or compromised operator
ceremony could create sessions with expanded authority. The boundary between Orchestrator
and Executor authority would become negotiable at runtime. Static dispatch means the
authority model is fixed by the binary — not by any data that flows through the system.

**Why not per-session:** Per-session dispatch rules (stored in the database and evaluated
at admission) would allow the matrix to be influenced by database state. A SQL injection
or a partial write vulnerability could alter a session's effective dispatch rules. By
making dispatch purely a function of `session_agent_type` (which is set at creation and
immutable), the Kernel has one authoritative source.

### The Matrix

| `IntentKind` | Orchestrator | Executor | Reviewer |
|---|---|---|---|
| `ActivateSubTask` | ✅ | ❌ | ❌ |
| `RetrySubTask` | ✅ | ❌ | ❌ |
| `IntegrationMerge` | ✅ | ❌ | ❌ |
| `EscalationRequest` | ✅ | ❌ | ❌ |
| `InferenceRequest` | ✅ | ✅ | ✅ |
| `SingleCommit` | ❌ | ✅ | ❌ |
| `CompleteTask` | ❌ | ✅ | ❌ |
| `ReportFailure` | ❌ | ✅ | ❌ |
| `SubmitReview` | ❌ | ❌ | ✅ |
| `FetchEvaluation` | ❌ | ❌ | ✅ |

**`session_agent_type` is immutable:** Set at `ActivateSubTask` admission from the plan's
task definition. Written to `sessions.session_agent_type` and `sessions.can_delegate` at
session creation. Never updated thereafter. No intent can change a session's type.

### INV-DELEGATE-01: Delegation Is Orchestrator-Exclusive

`ActivateSubTask` — the mechanism for spawning new agent sessions — is only permitted for
`session_agent_type = Orchestrator`. This is enforced by the dispatch matrix.

**Why this is a hard constraint rather than a policy rule:**

If Executors could delegate, the plan's pre-approved task topology becomes advisory. An
Executor could spawn arbitrary sub-sessions, each with their own path allowlists and
budgets, creating a tree of agent sessions not present in the signed plan. The operator's
signed plan covers a specific set of tasks — any spawning outside that set is unauthorized.

**The Orchestrator's delegation authority is still bounded:** Even though the Orchestrator
can submit `ActivateSubTask`, it can only activate tasks that exist in `subtask_activations`
for its initiative (validated at step 9 of the admission pipeline). The Orchestrator cannot
invent new tasks — it can only advance the execution of pre-approved tasks in the correct
dependency order.

### What Happens When a Forbidden Intent Is Submitted

1. Admission pipeline reaches step 8 (dispatch matrix check)
2. `(session_agent_type, IntentKind)` pair is looked up in the static matrix
3. Result: `Denied`
4. `FAIL_POLICY_VIOLATION` returned to the submitter
5. `AuditEventKind::SecurityViolation { kind: DispatchViolation, session_id, intent_kind }`
   emitted
6. Session violation counter incremented

**Why `SecurityViolation` rather than just `FAIL_POLICY_VIOLATION`:** A legitimate agent
operating correctly never submits a forbidden intent — the system prompt, the tool
definitions exposed to the LLM, and the `PermissionPolicy` in the planner all prevent the
LLM from attempting this in normal operation. A dispatch violation indicates either a
jailbroken LLM attempting privilege escalation or a compromised VM process bypassing the
planner entirely. Either case warrants escalated response.

**Client-side filtering (defense in depth):** The `raxis-planner` binary uses
`PermissionPolicy` to filter which tool definitions are exposed to the LLM based on
`session_agent_type`. A Reviewer's LLM never sees `SingleCommit` or `ActivateSubTask` in
its available tools — they are not in the tool list presented at inference time. This is
*not* the primary enforcement mechanism (the Kernel dispatch matrix is), but it prevents
the LLM from wasting inference turns attempting tools it cannot use, and it reduces the
attack surface for jailbreak-based dispatch violations.

---

*Part 6 complete. Next: Part 7 — Path Allowlist Enforcement.*


---

## Part 7 — Path Allowlist Enforcement

### What Path Allowlists Are

Every agent session has a `path_allowlist`: a list of file paths or directory prefixes that
the session is permitted to write. This list is declared in `plan.toml`, included in the
`plan_bytes` that the operator signs, and sealed into the `signed_plan_artifacts` record
at `approve_plan` time. It cannot be changed at runtime.

```toml
[[tasks]]
task_id        = "auth_implementer"
path_allowlist = ["src/auth/"]       # may write anything under src/auth/
```

**Exact file vs. directory prefix:**
- `"src/auth/rate_limit.rs"` — the session may only write this exact file
- `"src/auth/"` — the session may write any file whose path begins with `src/auth/`
  (including new files, nested subdirectories)

Globs (`*`, `**`) are explicitly rejected at `approve_plan` validation — they make the
effective scope unauditable. A glob like `"src/**"` could match the entire codebase.

### Enforcement Mechanism: VCS Diff at Admission

Path allowlist enforcement happens at `SingleCommit` admission (step 12 of the pipeline).
The Kernel computes:

```rust
let touched_paths = vcs::diff_paths(base_sha, head_sha, &worktree_path)?;
for path in &touched_paths {
    if !session.path_allowlist.iter().any(|allowed| path.starts_with(allowed)) {
        return Err(KernelError::PathPolicyViolation { path: path.clone() });
    }
}
```

This is a **post-commit, pre-integration** check. The agent's VM has already made the git
commit in its local worktree — the check evaluates the diff of that commit against the
allowlist before the commit is allowed to propagate anywhere. If any touched path is outside
the allowlist, the entire `SingleCommit` intent is rejected. The commit exists in the VM's
local git history but never leaves the VM.

**Why post-commit rather than pre-commit (file interception):**
Pre-commit interception (intercepting file writes at the VirtioFS layer before git commit)
would require the Kernel to hook every filesystem write in the VM — a massive, fragile,
and performance-destroying surface. Post-commit diff evaluation is clean: one check, on a
bounded, well-defined artifact (a git commit), at a single enforcement point.

### The Subset Invariant

The Orchestrator's `path_allowlist` must be a superset of the union of all its sub-tasks'
allowlists. Validated at `approve_plan` time (shift-left check #4):

```
orchestrator.path_allowlist ⊇ UNION(task.path_allowlist for task in all_tasks)
```

**Why:** The Orchestrator performs `IntegrationMerge` — it merges sub-task commits into
the master branch. If the Orchestrator's allowlist is narrower than a sub-task's, the
Orchestrator's `IntegrationMerge` intent would include paths outside its own allowlist,
causing the merge to be rejected at admission. The subset invariant is validated before
the initiative starts to prevent this class of planning error.

**Scenario: sneaky path expansion.** An operator writes a plan where `executor_a` has
`path_allowlist = ["src/auth/", "src/admin/"]` but the Orchestrator has
`path_allowlist = ["src/auth/"]`. At `approve_plan` time, shift-left check #4 computes
the union (`{"src/auth/", "src/admin/"}`) and finds it is not a subset of the
Orchestrator's allowlist. The plan is rejected before any VM boots.

### Path Allowlists Are Write-Only Restrictions

Path allowlists restrict **writing** (git commits). They do not restrict reading. An agent
using `blobless` or `full` clone strategy has the entire repository available for reading.
This is intentional — agents need read access to understand the codebase they are working
in.

**Implication for the debate pattern:** Proposer agents can read any file in the repository
to build context for their proposals. They can only write to their declared proposal file.
The debate knowledge is unrestricted; the debate authority is narrowly scoped.

**The security boundary:** Reading has no direct security consequence — it cannot modify
state. Writing does, and that is what the allowlist controls.

### Scenario: Path Traversal via Git

An adversarial commit could theoretically use git's submodule or symlink mechanisms to
write outside the declared worktree. RAXIS's defenses:

1. **`SingleCommit` intent validation (step 9)** rejects commits that modify `.gitmodules`
   or add new submodule entries — submodules are out of scope for agent sessions entirely.
2. **VCS diff computation** follows resolved paths, not raw tree entries — a symlink in the
   commit pointing outside the worktree does not affect the diff of actual file paths.
3. **VirtioFS boundary** — even if the agent's git commit claims to write outside the
   worktree directory, the VirtioFS host-side driver resolves paths relative to the mount
   root and rejects host-path traversal attempts.

---

*Part 7 complete. Next: Part 8 — Cryptographic Audit Chain.*


---

## Part 8 — Cryptographic Audit Chain

### Why the Audit Chain Exists

Every security system eventually relies on the question: "what actually happened?" The
audit chain is RAXIS's answer. It is the ground truth record of every action taken in
the system — who submitted it, under what plan, at what policy epoch, and with what result.

An audit chain that can be tampered with is not an audit chain. A chain that can be
selectively deleted is not a chain. RAXIS enforces three properties:

1. **Append-only:** Only the Kernel's append endpoint writes to the audit store. No process
   has a delete or update path to existing records.
2. **Cryptographically linked:** Each event includes the hash of the previous event. Gaps
   or modifications break the chain hash and are detectable.
3. **Out-of-bubble isolation:** The audit store lives at `$RAXIS_DATA_DIR/audit/`, outside
   the workspace and outside every VM's VirtioFS mount. Agents have no write path to it.

### Audit Event Structure

Every Kernel state change produces an `AuditEvent`:

```rust
pub struct AuditEvent {
    pub event_id:       Uuid,
    pub previous_hash:  [u8; 32],        // SHA-256 of previous event bytes
    pub session_id:     Option<Uuid>,    // None for system-level events
    pub initiative_id:  Option<Uuid>,
    pub kind:           AuditEventKind,
    pub timestamp:      i64,             // Unix epoch microseconds
    pub payload_hash:   [u8; 32],        // SHA-256 of the full intent payload
}
```

The chain integrity check: `SHA-256(serialize(event_n)) == event_{n+1}.previous_hash`.
A verifier replays the chain from genesis and checks every link. Any insertion, deletion,
or modification of event bytes causes a hash mismatch at the next event.

### The 4-Field Attribution Chain (INV-05)

Every session-scoped audit event carries four fields that together uniquely identify the
human-authorized context for every action:

```
session_id       → which session submitted the intent
initiative_id    → which initiative it belongs to
plan_sha256      → SHA-256 of the exact plan.toml bytes the operator signed
policy_epoch     → the policy epoch active when the session was created
```

**What this enables for forensics:**
- Given any audit event, find `initiative_id`, look up `initiatives.plan_artifact_sha256`,
  retrieve the plan bytes, verify the Ed25519 signature → confirm who authorized this work
- Given `policy_epoch`, retrieve the policy bundle active at that time → confirm what rules
  applied
- Given `session_id`, replay all events for that session in order → reconstruct the exact
  sequence of intents and Kernel responses

No event can be "accidentally undocumented." If the Kernel processes an intent, an audit
event exists. If no audit event exists for an expected action, the chain is broken — which
is itself detectable.

### Events That Are Always Recorded

Every event below is emitted regardless of whether the admission succeeded or failed.
A failed admission is audited with the failure code.

| Event | Trigger |
|---|---|
| `InitiativeCreated` | `approve_plan` succeeds |
| `SessionCreated` | `ActivateSubTask` succeeds |
| `IntentAdmitted { kind, session_id }` | Any intent passes all 13 pipeline steps |
| `IntentRejected { kind, session_id, error_code }` | Any intent fails any pipeline step |
| `SecurityViolation { kind, cid, session_id }` | Adversarial probe detected |
| `SessionRevoked { session_id, reason }` | Token revoked for any reason |
| `ReviewSubmitted { approved, session_id, evaluation_sha }` | Reviewer submits |
| `IntegrationMergeAdmitted { commit_sha, initiative_id }` | Merge admitted |
| `EscalationRequested { class, session_id }` | Agent submits escalation |
| `EscalationConsumed { resolved_by, escalation_id }` | Operator resolves escalation |
| `PolicyEpochAdvanced { from, to, affected_classes }` | Epoch advance committed |
| `BudgetExhausted { lane_id, initiative_id }` | Lane ceiling reached |

### Audit Store Physical Isolation

The audit store is not a table in the Kernel's SQLite database. It is a separate append-only
JSONL file at `$RAXIS_DATA_DIR/audit/<date>.jsonl`, rotated daily.

**Why separate from the database:** The Kernel's SQLite database contains mutable state
(session status, delegation staleness, budget reservations). A bug in the database layer
(transaction rollback, WAL corruption recovery) might roll back or lose audit records if
they shared the same file. A separate append-only file cannot be rolled back — `append()`
is atomic at the filesystem level for records smaller than the filesystem block size.

**Why JSONL rather than binary:** JSONL is human-readable and independently parseable
without RAXIS tooling. A security auditor can `grep`, `jq`, and verify the chain without
access to the RAXIS binary. The format is self-documenting.

**Access control:** `$RAXIS_DATA_DIR/audit/` is owned by the `raxis-kernel` user with
mode `700`. The gateway process, the planner processes, and all VMs run as a separate
`raxis-agent` user with no access to this directory.

---

*Part 8 complete. Next: Part 9 — Policy Signing and the Plan Ceremony.*


---

## Part 9 — Policy Signing and the Plan Ceremony

### Two Things That Must Be Signed

RAXIS has two independently signed artifacts. Both require the operator's Ed25519 private
key. Neither can be substituted, forged, or amended at runtime.

**1. The Policy Bundle (`policy.toml`)**
Defines the rules of the system: path tiers, claim requirements, lane budgets, provider
allowlist, escalation classes, auth parameters. Signed once when the operator configures
a deployment. Stored at `$RAXIS_DATA_DIR/policy/policy.toml` with its detached signature.

**2. The Initiative Plan (`plan.toml`)**
Defines the work for a specific initiative: task topology, per-task path allowlists,
agent types, budgets, context. Signed per initiative. Submitted to `approve_plan` with
the signature bytes and the operator's public key certificate.

These two signing ceremonies are intentionally separate. A policy update does not require
re-signing every plan. A new initiative does not require re-signing the policy. Each
artifact's scope is exactly its own content.

### The Ed25519 Key

**Why Ed25519 specifically:**
- Deterministic signing (no per-signature randomness, no side-channel from weak RNG)
- Small key and signature sizes (32-byte public key, 64-byte signature)
- Fast verification (Kernel verifies every `approve_plan` call)
- Widely audited (libsodium, `ed25519-dalek`)

**Key storage:** `operator_private.pem` is never stored on the RAXIS host. The operator
holds it locally (hardware security key recommended). `operator_public.pem` is installed
at `$RAXIS_DATA_DIR/operator_public.pem` and is the only authority source the Kernel
trusts.

**Compromise scenario:** If `operator_private.pem` is compromised, an attacker can sign
plans with arbitrary task topologies and allowlists. This is the highest-severity credential
compromise in RAXIS. Mitigation: use a hardware key (YubiKey) for the Ed25519 key — the
private key never leaves the hardware device. The RAXIS signing ceremony calls the hardware
key's signing API, not a file-resident key.

### The `approve_plan` Ceremony — 7 Shift-Left Checks

`approve_plan` is the gate between a signed plan and an active initiative. It runs before
any VM boots. All 7 checks must pass; failure at any check aborts the entire plan.

**Check 1 — Ed25519 signature verification:**
`ed25519_dalek::PublicKey::verify(plan_bytes, signature, operator_public_key)`.
If this fails, the plan is forged or corrupted. Reject immediately.

**Check 2 — Schema validity:**
Deserialize `plan_bytes` as `PlanManifest`. Reject unknown fields, missing required fields,
invalid enum variants. A plan that doesn't parse is either from a different protocol
version or malformed.

**Check 3 — DAG acyclicity:**
Topological sort of `task_dag_edges`. If a cycle exists, reject. A cyclic plan would
deadlock: no task can activate because its predecessor depends on it.

**Check 4 — Path subset invariant:**
For each task, verify `task.path_allowlist ⊆ orchestrator.path_allowlist`. Reject if
any task's allowlist contains paths not covered by the Orchestrator. (See Part 7.)

**Check 5 — Single Orchestrator:**
Exactly one task must have `session_agent_type = Orchestrator`. Zero Orchestrators means
nothing can activate sub-tasks. Two Orchestrators creates ambiguity about which one
performs `IntegrationMerge`.

**Check 6 — Budget feasibility:**
`SUM(task.estimated_cost for all tasks) ≤ lane.max_cost_per_epoch`. If the plan's total
estimated cost exceeds the lane ceiling, the initiative would be guaranteed to exhaust its
budget before completing. Reject before any compute is spent.

**Check 7 — Policy compliance:**
Each task's capabilities are checked against the current policy bundle. A task requesting
a model not in the provider allowlist, or a path tier that doesn't exist, or an escalation
class not defined in the policy — all cause rejection here. This check ensures the plan
is executable under current policy at submission time.

**Why shift-left:** All 7 checks run before any VM boots and before any budget is reserved.
A plan that fails check 4 never consumes any compute. A plan that fails check 7 is caught
before an Executor wastes inference turns on a task that will always fail policy. Every
minute of shift-left validation saves N minutes of runtime failure.

### Plan SHA in the Audit Chain

At `approve_plan` success, the Kernel records:
```
initiatives.plan_artifact_sha256 = SHA-256(plan_bytes)
```

This SHA is included in every `SessionCreated` audit event for every session in the
initiative. It cryptographically links every agent action to the exact plan bytes the
operator signed. An auditor can:

1. Extract `plan_artifact_sha256` from any audit event
2. Retrieve the plan bytes from cold storage
3. Verify `SHA-256(plan_bytes) == plan_artifact_sha256`
4. Verify `ed25519_verify(plan_bytes, signature, operator_public_key)`

This four-step chain proves: "this agent action was authorized by plan bytes that the
operator cryptographically committed to."

---

*Part 9 complete. Next: Part 10 — Credential Isolation.*

