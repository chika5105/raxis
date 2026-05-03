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
