# RAXIS v2 Architecture & Implementation Roadmap

> **Audience:** anyone trying to understand *why* V2 looks the way it
> does. This is the original architecture brief that scoped the V2
> effort end-to-end — native planner, hardware-isolated VMs,
> hierarchical multi-agent coordination, multi-provider routing, and
> advanced quality gates.
>
> **Status of this document:** historical roadmap, kept verbatim. For
> the live implementation ledger see [`V2_STATUS.md`](V2_STATUS.md);
> for the systematic spec-vs-code gap audit see
> [`V2_GAPS.md`](V2_GAPS.md). Anything in this roadmap that has since
> been refined, reshaped, or superseded is reflected in those two
> files and in the per-feature specs alongside it in `raxis/specs/v2/`.

The v1 release of RAXIS serves as the foundational proof-of-concept for the "Separation of Authority" paradigm. It proves that a kernel can constrain an LLM agent using typed IPC, deterministic Git path enforcement, and an unforgeable audit chain.

**RAXIS v2** is the production-grade maturation of this system. It transforms the reference implementation into a highly concurrent, fully isolated, multi-agent Control Plane. It heavily leverages patterns from mature agentic codebases (like `claw-code`) for the planner loop, but encapsulates them within hardware-accelerated security sandboxes (VMs) and sophisticated multi-provider routing logic.

Below is the step-by-step, detailed enumeration of what the v2 specification entails.

---

## 1. The RAXIS-Native Planner (The Agent Loop)

In v1, the planner was largely treated as a "black-box" client. 
**What is the "Black-Box" Assumption?** In v1, the RAXIS architecture only defined the IPC interface. It assumed developers would bring their own planner scripts (written in Python, Node.js, etc.) and simply connect to the kernel socket. The kernel treated this planner as an opaque, untrusted black box—it didn't care how the planner managed LLM context, parsed tools, or handled retries, so long as it sent valid `IntentRequest` bytes. 

In v2, while the kernel *still* treats the planner as untrusted for security purposes, the project ships a first-class, statically compiled **RAXIS-Native Planner** (`raxis-planner`). This replaces the "bring your own script" approach with a rigorously engineered, `claw-code` inspired agent loop that runs seamlessly inside the new VM sandboxes.

### 1.1. Architectural Critique: Native Planner vs. Black-Box Scripts
The decision to build a native planner involves strict trade-offs, particularly concerning the security architecture:

**Arguments FOR a Native Planner (`raxis-planner`)**
*   **The "Distroless" Sandbox Guarantee (Security):** If an operator uses a Python/Node.js script, the isolation VM must include a script interpreter, standard libraries, and package managers (like `pip`). This presents a massive attack surface for an LLM to attempt "living off the land" escapes. A statically compiled Rust binary (`raxis-planner`) allows the VM rootfs to be completely "distroless." There is no `/bin/sh`, no package manager, and no interpreter. Even if the LLM hallucinates a malicious script, there is nothing to execute it.
*   **Hypervisor-Native Transports (Security):** Managing raw vsock connections and binary framing (`bincode`) in arbitrary Python scripts is brittle. A native Rust planner natively integrates the `raxis-ipc` crate, ensuring memory-safe transport.
*   **Out-of-the-Box Viability (Ergonomics):** Managing context windows, parsing tool calls, and implementing exponential backoff retries is extremely difficult. Forcing every operator to build their own script from scratch severely hinders adoption.

**Arguments AGAINST a Native Planner**
*   **Blurring the Trust Boundary (Security Risk):** The core philosophy of RAXIS is the *Separation of Authority from Intelligence*. If the same engineers maintain both the Kernel and the Planner, there is a psychological risk of "coupling"—designing kernel features specifically to make the planner's life easier, accidentally introducing trusted backdoors.
*   **Loss of AI Research Flexibility:** Hardcoding the loop in Rust makes it harder for AI researchers to plug in novel Python-based frameworks (like new LangChain paradigms) without rewriting them.

**The Mitigation Strategy:**
To preserve the philosophy while gaining the sandbox security benefits, the V2 spec enforces two strict rules:
1.  **The "Hostile Client" Test:** The Kernel's integration tests must not use `raxis-planner`. They must simulate a hostile, mutated script sending garbage IPC frames to prove the Kernel survives.
2.  **No Private APIs:** The `raxis-planner` must use the exact same public `planner.sock` protocol that any third-party script would use. Zero special privileges.

### 1.2. The Strict Need for Prompt Engineering & Context Assembly
Building a native planner is not just an infrastructure task; it is fundamentally an exercise in highly constrained **Prompt Engineering**. Lifting concepts heavily from `claw-code` and `Aider`, the planner must be engineered to keep the LLM tightly aligned to the strict `raxis-ipc` intent model without drifting into conversational halucinations.

*   **The "Claw-Code" Context Pack**: The planner manages a sliding context window to prevent token exhaustion. Before sending a request to the kernel, it engineers the prompt to include:
    *   **Repo-Maps**: A compact representation of the file tree and AST (Abstract Syntax Tree) signatures to give the LLM spatial awareness without dumping entire files.
    *   **File Fences**: Active file contents explicitly fenced with strict delimiters (e.g., `<file path="src/main.rs">...` ) so the LLM understands exactly what code is in scope.
    *   **History Truncation**: Keeping the N most recent turns, but ruthlessly summarizing older turns to save context space.
*   **Kernel Interception (The Non-Negotiable Prompt)**: When the `InferenceRequest` hits the kernel, the kernel *prepends* a non-negotiable policy block to the system prompt. This block contains the path allowlist, the remaining budget, and the available tools from `policy.toml`. The planner's prompt engineering must anticipate and harmoniously integrate with this kernel-injected block.
*   **Structured Intent Coercion & Provider-Specific Parsers**: The prompt must coerce the LLM to output actions that explicitly map to RAXIS `IntentKind` requests. Because different models excel at different formats (e.g., Anthropic excels at XML `<intent kind="CommitRange">`, while OpenAI is highly optimized for strict JSON Schema), the `raxis-planner` implements **Provider-Specific Parsing Adapters**. 
    *   Drawing heavily from how `claw-code` abstractly supports multiple providers, the planner adjusts its few-shot examples and active parser (XML vs JSON) based on which provider the Kernel/Gateway routed the task to. 
    *   If a model hallucinates an invalid format or an intent outside the tool manifest, the provider-specific parser catches it, emits a local parsing error, and appends the correction to the context window without ever sending a malformed IPC intent to the kernel.

### 1.3. The Core Execution Loop (`claw-code` pattern)
The loop operates continuously without human intervention until the task is complete or an escalation is triggered:
1.  **Poll for Work**: Planner connects over IPC and requests `NextReadyTasks`.
2.  **Pick Up**: Planner claims a task (`IntentKind::PickUpTask`).
3.  **Inference**: Planner sends `InferenceRequest` to the kernel.
4.  **Parse & Act**: Planner parses the LLM output. If the LLM requested a file edit, the planner applies the edit locally to the worktree, creates a Git commit, and submits `IntentKind::CommitRange` to the kernel.
5.  **Evaluate Verdict**:
    *   If **`Accepted`**, the planner proceeds to the next step.
    *   If **`Rejected`**, the planner ingests the kernel's structured failure reason (e.g., "Out of Path Bounds"), appends it to the LLM's context window as an error correction turn, and retries.
6.  **Termination**: The planner submits `CompleteTask` when the LLM declares the objective met.

### 1.4. Retry Heuristics & Context Truncation
The planner implements sophisticated circuit breakers. If an intent is rejected 3 times in a row, the planner does not spin endlessly. It truncates the context, summarizes the failure, and triggers an `Escalate` intent back to the kernel to request human intervention.

---

## 2. VM-Based Subprocess Isolation (Host Containment)

v1 relies on the "Honest IPC Client" assumption (same OS user). v2 enforces true, hardware-level isolation. An agent that is actively malicious or completely compromised cannot escape to the host OS.

### 2.1. The `SpawnBackend` Hypervisor Abstraction
The kernel dynamically selects the strongest virtualization backend:
*   **Linux**: `Firecracker` microVMs (direct KVM API, <125ms boot, 5MB RAM overhead).
*   **macOS**: `AppleVirtualization.framework` (native Apple Silicon VMs).
*   **Fallback**: Linux namespaces / macOS Seatbelt sandbox.

### 2.2. Immutable Rootfs & Network Denial
The `raxis-planner` and `raxis-verifier` are compiled to statically linked `musl` binaries. They boot inside a minimal rootfs that contains **no shell (`/bin/sh`)**, no package managers, and no system utilities.
*   **No Network Egress**: The hypervisor enforces strict network denial. The VM has no virtual NIC. The *only* way the agent can communicate with the outside world is via the Vsock IPC channel to the kernel.

### 2.3. Vsock Transport & VirtioFS
*   **IPC via `AF_VSOCK`**: The exact same `bincode` message frames from v1 are routed over hypervisor vsock rather than Unix Domain Sockets. 
*   **Strict Worktree Mounts**: The agent does not have access to the whole repository. The kernel uses VirtioFS to mount *only* the specific `git worktree` assigned to the session. For Verifier VMs, this mount is strictly Read-Only.

---

## 3. Multi-Agent Coordination (Strictly Hierarchical)

v2 introduces the ability for multiple agents to operate concurrently, but **strictly forbids conversational "agent-to-agent chatter."** Agents do not talk to each other; they communicate exclusively through structured deliverables (code commits and formal task completions).

### 3.1. `session_agent_type` and Hierarchical Delegation
Agents are typed at spawn time (e.g., `Orchestrator`, `Executor`, `Reviewer`). 
*   An `Orchestrator` session can spawn sub-planners by submitting new Tasks to the Kernel.
*   The Orchestrator defines the formal success criteria for the sub-task. 
*   The kernel enforces that an Orchestrator can only delegate a subset of its own path allowlists and budgets to its children (Hierarchical Scoping).

**Critique on "Conversational" Orchestration:**
If back-and-forth communication (e.g., a Coder seeking critique from a Reviewer) is required, it cannot be unstructured, real-time "chat". Unstructured chat is highly susceptible to prompt-injection and makes it impossible for the kernel to enforce structural authority boundaries. 
Therefore, if an Orchestrator requires conversation or orchestration, it must model it as **Asynchronous RPC (Remote Procedure Calls)** via the kernel:
1.  The Orchestrator submits an `IntentKind::RequestSubTask` (e.g., "Review this commit").
2.  The kernel spawns or routes this to a `Reviewer` sub-planner.
3.  The `Reviewer` completes the task and submits a structured `TaskResult` (containing the critique) to the kernel.
4.  The kernel returns the `TaskResult` payload to the Orchestrator. 

This guarantees that all multi-agent "conversations" are actually discrete, kernel-audited, typed state transitions.

### 3.2. Complete Git-Level Isolation
Using `git worktree` is insufficient because it shares the underlying `.git` object database (allowing one compromised agent to access unmerged objects from another).
*   **Standalone Ephemeral Clones**: Each agent session is provisioned with a completely standalone, ephemeral `git clone` of the repository within its VirtioFS mount.
*   **Air-Gapped Object Databases**: Agents share zero Git state. 
*   **Kernel-Mediated Merging**: When a sub-planner completes its task, it submits an `IntentKind::CommitRange`. The kernel extracts the commits as a patch or git-bundle and applies them back to the Orchestrator's worktree. The agents never cross-pollinate files directly.

### 3.3. Worktree Path Locks & Shared Artifacts
Even with standalone clones, the kernel maintains a logical `worktree_lock` table for the master branch:
*   If the Orchestrator assigns `src/api.rs` to Agent A and `src/db.rs` to Agent B, the kernel locks these paths.
*   If Agent A submits a commit touching `src/db.rs` (Path Conflict), the kernel rejects the intent immediately.
*   **Shared Artifacts**: The policy defines merge strategies for global files (e.g., `Cargo.toml`). The kernel holds a global lock on these files during the patch-application phase.

---

## 4. Multi-Provider Routing & Operator Tool Manifests

v2 breaks the hardcoded 1:1 relationship between a planner and an LLM provider.

### 4.1. Operator-Defined Provider Routing (Strict Fail-Closed)
The planner does **not** decide which model or provider to use, nor does it request specific "capabilities". The mapping of task to model is explicitly and exclusively configured by the human operator in the signed `policy.toml`.
*   **Kernel-Driven Routing**: When the planner sends an `InferenceRequest`, the kernel derives the correct provider based solely on the current `session_agent_type` or the active Lane/Task schema defined in the policy. 
*   **Operator Default Provider**: The operator can optionally configure a global `default_provider` in the policy. If a specific task or agent type has no explicit routing mapping, the kernel routes the request to this default provider.
*   **Configurable Fallback Behavior**: For explicitly mapped tasks, the operator specifies what happens if the provider is unavailable using the `on_unavailable` key (e.g., `on_unavailable = "fail"` or `on_unavailable = "fallback_to_default"`).
*   **Strict Fail-Closed Default**: If the `on_unavailable` key is omitted from a route's configuration, its value **defaults to `"fail"`**. If an explicit mapping exists for Kombai but Kombai is offline, the kernel immediately rejects the intent and fails the task *unless* the operator explicitly opted-in to a fallback. The system strictly enforces the operator's routing graph without silent compromises.
*   This centralizes model spend, API keys, and model selection entirely inside the Kernel/Gateway, stripping the planner of any routing authority.

### 4.2. Operator Tool Manifest (`[[tools]]`)
In v1, tools are implicit. In v2, tools are rigorously defined in the signed `policy.toml`.
*   The operator defines schemas for tools (e.g., `execute_bash`, `search_codebase`, `run_linter`).
*   During prompt assembly, the kernel injects only the tools that this specific `session_agent_type` is authorized to use.
*   If the LLM hallucinates a tool call that is not in the manifest, the planner fails parsing; if it somehow bypasses parsing, the kernel rejects the `ToolExecutionIntent`.

---

## 5. Advanced Quality Gates & Analytics

v1 relies on basic binary test pass/fail checks. v2 introduces continuous quality and semantic drift monitoring.

### 5.1. The `IntegrationMerge` Gate
When multiple agents finish their respective branches, the kernel orchestrates an `IntegrationMerge`. The kernel spawns a Verifier VM to run the test suite against the *merged* SHA, ensuring that Agent A's changes don't break Agent B's changes.

### 5.2. Semantic Drift Analytics
The kernel compares the original signed `plan.toml` success criteria against the generated Git diffs using a highly constrained, local-only embedding comparison or structural AST check. If the code deviates massively from the plan (e.g., rewriting the DB layer when the task was UI), the kernel flags an `AntiGamingSignal` and escalates to the human operator before allowing the task to transition to `Completed`.

### 5.3. Composite & Conditional Gates
*   **M-of-N Quorum**: A task might require 2 out of 3 Reviewer agents to submit an `IntentKind::ApproveTask` before the kernel admits it.
*   **Conditional Activation**: A security audit gate only activates if the agent's commit touched files inside `src/crypto/` or `src/auth/`.

---

## Summary of the Engineering Path to V2

1.  **Refactor `raxis-planner`**: Strip out old prototypes, implement the `claw-code` loop in strict Rust, define the Context Window struct, and build the XML/JSON intent parsers.
2.  **Implement `SpawnBackend`**: Build the VMM wrapper for Firecracker/Apple Virtualization. Plumb `AF_VSOCK` into the `raxis-ipc` crate.
3.  **Upgrade `kernel-store`**: Add the `worktree_lock` tables, hierarchical capability tracking, and `MessageIntent` schemas.
4.  **Extend Policy**: Add `[[tools]]` manifests and provider routing tables to the operator's TOML format.
