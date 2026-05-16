# RAXIS — Design Decisions and Rejected Alternatives

> This document records every significant design alternative evaluated and discarded during RAXIS v1 design. It exists as a guardrail against re-litigating settled decisions. Each entry follows the same structure: what was tempting about the alternative, and what made it unsafe or wrong.
>
> **Navigation:** [README](../README.md) | [Part 1](v1/philosophy.md) | [Part 2 Core](v1/kernel-core.md) | [Part 2 Store](v1/kernel-store.md)

---

## Alternatives Considered and Rejected

This section records every significant design alternative that was evaluated and discarded during Phase 1 design.
It exists as a guardrail: if a future agent, contributor, or refactor proposes reverting to one of these, the reasoning below explains why the current design was chosen instead.
Each entry follows the same structure — what was tempting about the alternative, and what made it unsafe or wrong.

---

### Process and Authority Model

#### A.1 — Single Intelligent Server (Monolith)

**Considered because:** a single process is simpler to build, deploy, and debug. Most existing agent frameworks follow this pattern.

**Rejected because:** intelligence and authority cannot safely share a process boundary. If the process that runs LLM inference is the same process that checks permissions, a compromised inference result can influence policy decisions. Hot-reloading the intelligence layer — which is desirable for agility — would also affect the enforcement layer if they share a process, creating nondeterminism in the authority model. The phrase "single intelligent server" is architecturally dangerous: *intelligent* and *authoritative* are incompatible properties in the same process when the inputs are untrusted.

**Guardrail:** any proposal to merge kernel logic into the planner process, or to let the planner "call the kernel internally" via a shared library rather than IPC, must be rejected on the same grounds.

---

#### A.2 — Hot Reload of Kernel Behavior

**Considered because:** operators want to push configuration changes without restarting. Hot reload is common in production services.

**Rejected because:** *uncontrolled* hot reload on a control surface introduces nondeterminism. In-flight decisions may resolve under Config A while new decisions use Config B, with no clear audit record of which rule set applied. More critically, if the kernel's enforcement logic itself can be hot-reloaded via a file-system watcher or admin push endpoint, an agent that can write to the config path can alter the rules mid-run.

**What is explicitly permitted — signed epoch advance:** The kernel supports in-process policy epoch advance via `policy_manager::advance_epoch`. This is not "hot reload" in the dangerous sense: the new policy artifact is fetched from a kernel-controlled path, verified against the authority public key (must pass signature check), atomically swapped via `ArcSwap<PolicyBundle>`, and recorded as `AuditEventKind::PolicyEpochAdvanced`. The delegation sweep runs synchronously, and all subsequent enforcement decisions use the new bundle. This is kernel-mediated, signed, audit-recorded, and not triggerable by the planner — it is the correct mechanism for policy updates without a binary restart.

**The kernel binary itself is firmware:** the binary is versioned, signed, and replaced via a full restart. Policy *artifacts* are separately versioned and separately signed; they can advance via `advance_epoch` while the kernel binary continues running.

**Guardrail:** Reject any proposal for policy update that operates via: (a) OS-signal file watcher, (b) admin API push without signing ceremony, (c) any path writable by the planner or gateway processes, or (d) unsigned artifact. `advance_epoch` called through the signed policy-update ceremony is the only permitted in-process policy change path.

---

#### A.3 — MCP (Model Context Protocol) for Authority Decisions

**Considered because:** MCP is an emerging standard for agent tool communication and was an obvious candidate for inter-process messaging.

**Rejected because:** MCP is a tool protocol, not an authority protocol. It is designed for flexible, extensible communication between models and their tools, which makes it unsuitable as the channel over which promotion decisions, permission grants, and escalation verdicts travel. Using MCP for authority would mean authority semantics are encoded in the same layer as tool invocations — a planner could potentially construct a tool call that looks like an authority grant. The kernel uses a typed, schema-fixed UDS protocol with kernel-assigned session tokens precisely because it is *not* extensible by the planner.

**Guardrail:** MCP may be appropriate for planner-to-tool communication. It must never be used for any message that carries an authority decision or modifies kernel-owned state.

---

#### A.4 — Agent-to-Agent Direct Channels (Early)

**Considered because:** direct low-latency channels between agents seem efficient and are a natural extension of multi-agent frameworks.

**Rejected for v1 because:** direct channels create trust and attribution problems that the kernel cannot observe. If Agent A talks directly to Agent B, the kernel has no record of what was said, cannot enforce capability constraints on the communication, and cannot attribute the resulting actions to a lineage. Kernel-mediated messaging — where the kernel is the relay and records the envelope of every inter-agent message — is the only model that preserves auditability and authority enforcement. Direct channels are not ruled out permanently, but they require a fully specified attribution and audit model before they can be introduced safely.

**Committed v2 items (require dedicated gap specs before implementation):** kernel-mediated agent channels, orchestrator-spawns-sub-planner hierarchical delegation, kernel-push notifications, and `session_agent_type`. These are promoted from "design intent" to committed v2 deliverables. None may be implemented until a gap spec exists with: the IPC message types, the capability scoping rules, the audit event shapes, and the session lifecycle rules for sub-planner spawn. Until those spec slices exist, any implementation claiming to deliver these features is out-of-scope. See the v3 roadmap section for architectural patterns that build on top of these v2 primitives.

**Guardrail:** any proposal for agent-to-agent communication must specify how the kernel observes, audits, and enforces capability constraints on that channel before implementation.

---

### Verification and Evidence

#### A.5 — LLM-as-Reviewer (Rhetorical Verification)

**Considered because:** it is the default pattern in virtually all existing agentic systems. Having one model review another model's output is simple and requires no additional infrastructure.

**Rejected because:** this creates a shared-delusion loop. Both the producer and the reviewer are LLMs that can hallucinate. A hallucinated claim is reviewed by a process that is subject to the same hallucination dynamics, and the review itself becomes evidence of correctness that the underlying system cannot distinguish from genuine mechanical verification. This is not a prompting problem — it is a structural problem. The only fix is to replace LLM review with deterministic, machine-generated witnesses: exit codes, hashes, static analysis results, test pass records. No amount of prompt engineering makes an LLM reviewer structurally independent of the LLM it is reviewing.

**Guardrail:** the Goldfish / verifier role must never be implemented as "ask a model to check the output of another model." Witness records must come from deterministic tools, not from language model judgments.

---

#### A.6 — Test Coverage Percentage as a Behavioral Witness

**Considered because:** coverage is widely used, easy to measure, and integrates cleanly into CI pipelines.

**Rejected because:** coverage is a structural witness (which lines were executed), not a behavioral witness (whether the expected outcomes were asserted). An agent under promotion pressure will write tests that execute code without asserting anything meaningful — these tests pass coverage thresholds while providing zero correctness evidence. For security, auth, and storage-touching paths, the witness must demonstrate that specific inputs produce specific outputs and that denial cases are explicitly tested. Coverage may supplement a behavioral witness but cannot satisfy it alone.

**Guardrail:** coverage percentage must never appear as the sole gate criterion on any path tagged as security, auth, or data-integrity. Insufficient behavioral tests produce `FAIL_INSUFFICIENT_WITNESS`, not a pass.

---

#### A.7 — Planner-Authored Claim Manifests as Sole Evidence

**Considered because:** the implementer knows what they changed and is well-positioned to declare what claims their work satisfies.

**Rejected because:** self-reporting is the failure mode the entire system is designed to prevent. A planner under pressure to get a change promoted will claim the witnesses it can produce, at the lowest risk tier it can argue for, and will not claim risks it does not want to address. The solution is a union model: the planner proposes claims it believes apply, the kernel derives required claims from the touched paths via a deterministic lookup table, and promotion requires the union — not just the planner's proposal. Required claims that are missing from the planner's manifest cause an early gate failure, not a planner override.

**Guardrail:** the claim-requirement policy table is in the protected kernel policy store. The planner cannot read it to shape its proposals. The planner cannot propose lower risk tiers. Tier assignment from the policy table is non-negotiable by planner argument. To keep development usable, the planner receives a coarse deficiency class on gate failure (`FAIL_MISSING_WITNESS`, `FAIL_INSUFFICIENT_WITNESS`, `FAIL_POLICY_VIOLATION`) but not the specific policy rule that fired; operator-facing tooling may inspect the full policy mismatch details for debugging.

---

#### A.8 — LLM-Derived Claim-Requirement Inference

**Considered because:** a language model could flexibly infer which claim types are relevant for a given diff, adapting to novel code patterns without requiring a policy table update.

**Rejected because:** LLM-derived claim inference is rhetorical verification at the meta-level. The planner (or any LLM-adjacent component) could influence the inference toward requiring fewer or weaker claims for a change it wants to push through. Claim-requirement inference must be a deterministic, static lookup: path/module patterns map to required claim types in a signed, versioned policy artifact that the planner cannot read or modify. Unknown paths default to the strictest claim tier. This is operationally rigid but structurally safe.

**Guardrail:** any proposal to use an LLM to decide which claims are required for a diff must be treated as equivalent to letting the planner self-report its own quality obligations. The same coarse-deficiency-class / operator-inspection split from A.7 applies here: the planner sees failure class, not policy internals.

---

#### A.9 — Prose "Done" Criteria

**Considered because:** business goals are naturally expressed in prose ("implement authentication," "deploy the payment module").

**Rejected because:** LLMs declare completion sycophantically under pressure. A prose done criterion gives the planner room to argue that the work satisfies the goal regardless of whether it actually does. Terminal success criteria must be machine-checkable: required artifact paths and digests, required gate pass records bound to specific commits, required approval proof IDs, and a maximum count of unresolved critical escalations. These are evaluated by the kernel against its own stores — no planner assertion is involved in the completion check. The prose business goal lives in the initiative record as context, not as the completion predicate.

**Guardrail:** any "done" field that is a free-text string is not a done criterion. It is a label. Done criteria must be typed fields the kernel can evaluate deterministically.

---

### Human-in-the-Loop Patterns

#### A.10 — Email Reply as Approval

**Considered because:** email is the natural async communication medium and reply-based approval is familiar.

**Rejected because:** email reply has no strong identity verification. A sufficiently crafted escalation email can cause the human's reply to be misinterpreted as approving a broader scope than intended. Thread injection, spoofing, and reply-parsing ambiguity all create exploitable surfaces. Email is the notification channel — it tells the human that an escalation exists and what it contains. The approval itself is always a local signed command, out-of-band from the email thread, requiring the human to deliberately pick up a separate tool and issue a typed, scoped, expiring approval token.

**Guardrail:** no code path in the system should read an email message body and use its content as an authorization input. Email is write-only from the kernel's perspective.

---

#### A.11 — "Best Judgment Approve/Deny" (LLM as Authorization Oracle)

**Considered because:** having the system make intelligent routing decisions about whether an escalation warrants human attention seemed efficient.

**Rejected because:** this makes an LLM the authorization oracle, which is exactly the failure mode the design rejects. A model deciding whether another model's escalation is legitimate will sometimes agree when it should not — either from sycophancy, from insufficient context, or from a well-crafted escalation request. The correct model is default deny with structured escalation: all escalations that exceed the role ceiling or leave a defined exception class require a human token. The system does not have a "seems fine" opinion that can replace that token.

**Guardrail:** the kernel must not have a code path that calls an LLM to evaluate whether an escalation should be approved. Escalation decisions are binary: either within-ceiling auto-grant, or explicit human token required.

---

#### A.12 — LLM-Based Agreeability Detection

**Considered because:** model sycophancy is a real quality problem, and detecting it seemed like a natural use of another model.

**Rejected because:** any LLM-based sycophancy detector is itself subject to sycophancy — a recursive failure. Detectors based on surface features (repeated affirmations, absence of contradiction, hedging language) can be evaded by a model that produces technically correct but subtly steered outputs. Genuine agreeability detection is an audit and outcome-tracking problem, not a real-time model evaluation problem: log model recommendations over time, log human decisions, and track the divergence rate. A model whose recommendations agree with the human 98% of the time is either very good or very agreeable — the only way to know which is longitudinal outcome data, not turn-by-turn analysis.

**Guardrail:** do not implement real-time agreeability detectors. Implement recommendation logging and outcome tracking in the audit store. Review divergence rates manually.

---

#### A.26 — Direct Chat Channels (Operator-to-Planner and Planner-to-Planner)

**Considered because:** conversational chat is the standard interaction model for almost all existing agentic systems. Operators are used to telling agents "actually, do X instead" in a chat window, and multi-agent systems often rely on free-text message passing between agents.

**Rejected because:** policy cannot be inferred from prose.
- **For Operator-to-Planner:** If an operator can bypass the structured task DAG by typing new instructions into a chat window, the cryptographically signed `plan.toml` is no longer the source of truth. This breaks the audit trail and enables implicit task creation that the kernel cannot properly gate or budget.
- **For Planner-to-Planner:** Direct free-text chat between agents creates invisible trust boundaries and un-auditable coordination that the kernel cannot enforce capabilities against (see also A.4).

**How to adjust behavior without chat:**
If a planner is doing the wrong thing or needs coordination, course-correction must flow through structured state transitions:
1. **Change the Code/Spec:** Edit the target files or specs in the Git worktree. The planner will see the new context on its next iteration.
2. **Change the Plan:** Abort the current task (`raxis-cli task abort`), update the structured `plan.toml`, sign it, and submit a new plan.
3. **Escalation Response:** If the planner is blocked on a missing capability, it files an `EscalationRequest`. The operator responds with a structured `raxis-cli escalation approve` or `deny` (which allows a brief text reason that is stored strictly in the audit log, not passed as a conversational instruction to the planner).

**Guardrail:** the CLI must never implement a `chat` command. The kernel must never expose an IPC endpoint that allows arbitrary prose instructions to be pushed into a planner's context window from either the operator or another planner.

---

### Credential and Storage Model

#### A.13 — Planner-Held Provider API Keys

**Considered because:** giving the planner direct API access is simpler and removes a round-trip through the kernel.

**Rejected because:** a planner that holds raw API keys can make direct provider calls that bypass the kernel's budget enforcement, cost accounting, and audit logging. The kernel's cost ceiling is structurally bypassed — it becomes advisory rather than enforceable. All provider calls must go through the provider gateway, which is a kernel-owned subprocess. The planner never receives a raw key. This is the only way to make budget enforcement real.

**Guardrail:** provider API keys must be stored in the kernel's protected credential store, never in the planner's configuration, environment, or working cache.

---

#### A.14 — Workspace-Resident Policy Storage

**Considered because:** storing policy files in the repository (like `CLAUDE.md` or `.cjplane.json`) is the convention in most existing agent frameworks (including claw-code).

**Rejected because:** workspace-resident policy means agents operating inside the workspace can read and potentially modify the rules that govern their own behavior. A compromised planner can propose changes to its own constraints as normal repository edits. Policy must live outside the repository write-bubble; in v1 this reduces accidental access through normal file paths (see Assumptions and Limits for the full same-user caveat). The policy store at `~/.raxis/policy/` is outside the workspace, versioned as signed artifacts, and updatable only through the signed policy-update ceremony.

**Guardrail:** any proposal to put policy configuration, tier rules, capability ceilings, or sentinel rules inside the repository must be rejected. These belong in the protected kernel policy store.

---

#### A.15 — Audit Store Inside the Workspace

**Considered because:** keeping everything co-located with the repository simplifies path management.

**Rejected because:** if the audit log lives inside the workspace, agents can tamper with the system's memory of what happened. An agent that can write repository files can delete or modify audit records, making past decisions invisible or falsified. The audit store must be outside the workspace write-bubble, with append-only semantics enforced at the kernel level. In v1 this is process/protocol-enforced rather than OS-enforced (see Assumptions and Limits); the audit log path and append-only constraint are still the correct design regardless of that limitation.

**Guardrail:** `~/.raxis/audit/` is the audit store. No audit records live inside the Git workspace (repository checkout) for the project under automation—only under the kernel data directory. Any code that writes audit events must call the kernel's append endpoint, not write files directly.

---

#### A.16 — Planner Direct Write to Witness Store

**Considered because:** the planner or verifier could write witness blobs directly to `~/.raxis/witness/` for simplicity.

**Rejected because:** if the planner has a direct write path to the witness store, it can fabricate witnesses — writing a test output that shows green without actually running the tests. Witness blobs must be written exclusively by the kernel and kernel-owned verifier subprocesses. The planner submits a witness claim (raw tool output) to the kernel via IPC; the kernel validates provenance, hashes the content, binds the blob to the task ID and commit SHA, and writes the index entry. The planner never has a file path to the witness store.

**Guardrail:** no code in the planner process may open a file handle under `~/.raxis/witness/`. Witness store writes are kernel-only operations. In v1, this is enforced by protocol (the planner has no path and no write IPC endpoint to the witness store), not by OS file permissions, consistent with the documented same-user limitation.

---

### Data Model Decisions

#### A.17 — Branch Refs for VCS Diff Inference

**Considered because:** branch names are human-readable and convenient. Submitting a branch name like `feature/auth-refactor` is more ergonomic than a commit SHA.

**Rejected because:** branch refs are mutable. The planner can force-push the branch after submitting it, causing the kernel to evaluate a different codebase state than the one that will actually be deployed. Claim-requirement inference — which determines what witness types are required for a change — must be computed against an immutable object. Kernel accepts only commit SHAs for this purpose. Branch refs are treated as non-authoritative hints, if accepted at all.

**Guardrail:** any kernel code path that computes touched paths or required claims must begin by resolving and pinning a commit SHA. Branch names must not be used as the basis for any policy decision.

---

#### A.18 — Per-Capability Epoch Staleness Checking

**Considered because:** a fine-grained staleness model — where a delegation becomes stale
only if the specific capability classes it covers changed in the new epoch — is more precise
and operationally less disruptive than invalidating all delegations on any epoch change.

**Rejected for V1 because:** implementing this correctly requires the kernel to diff two
policy epochs and determine per-capability impact, which is a complex and failure-prone piece
of infrastructure to build before the basic system is proven. The V1 rule is deterministic
and auditable: any epoch advance marks active delegations stale-on-next-use, triggering a
renewal decision at first use. This is operationally disruptive if epochs change frequently
— which is itself a pressure to keep policy changes rare, which is the correct incentive.

**V1 guardrail:** do not implement per-capability epoch diffing in V1 code. Stale = any
epoch mismatch. Renewal = new kernel decision required.

**Status: Promoted to V2 specified deliverable.**
V2's multi-session initiatives (Orchestrator + multiple Executor + Reviewer VMs) make the
blunt-invalidation operational cost higher in aggregate — though V2 sessions are short-lived
and the incentive to schedule epoch advances between initiatives remains correct. The
per-capability diffing is a targeted quality-of-life improvement for cases where epoch
advances cannot be scheduled (emergency key rotation, security incident response). It is
not a V2 correctness requirement; it is an operational improvement with a clear safety
contract: diff failure always falls back to blunt invalidation.

**Full specification:** [`specs/v2/policy-epoch-diffing.md`](v2/policy-epoch-diffing.md)
Key design points: `CapabilityClass` enum (6 classes), coarse section-level diff (not
field-level, which has false-negative risk), targeted SQL UPDATE, silent auto-renewal for
unaffected sessions, blunt fallback on diff error, genesis-phase abort constraint.

---

#### A.19 — Quality Gates and Authority Gates as One System

**Considered because:** treating all gates the same — hard block, no exceptions — simplifies the mental model and implementation.

**Rejected because:** quality gates and authority gates have fundamentally different threat models and therefore need different override semantics. Authority gates protect safety boundaries: no agent-accessible override, no business-urgency exception, cryptographic human ceremony required. Quality gates protect engineering outcomes: negotiable under governed exception, human-signed exception artifact, scope-bound and expiring. Merging these into one system produces either a quality gate that is too rigid for real software development (causing workarounds and bypass pressure) or an authority gate that can be argued away under quality-exception semantics. The systems must remain separate in code, in signing keys, and in override logic.

**Guardrail:** the kernel must have two physically separate override code paths. A quality exception cannot grant authority capabilities. An authority override cannot be triggered by a quality gate failure.

---

#### A.20 — Kernel Owning Provider HTTP Directly (Fat Kernel)

**Considered because:** having the kernel make provider API calls directly keeps the trust boundary clean — only one process has the keys and makes the calls.

**Rejected because:** HTTP client code, streaming response handling, rate-limit backoff, and provider-specific error taxonomy are complex, IO-bound, and subject to frequent change as provider APIs evolve. Embedding this complexity in the kernel violates the principle of a thin, deterministic authority core. The kernel's attack surface grows with every provider integration. The fix is the provider gateway: a kernel-owned subprocess that handles all transport complexity and reports structured results back to the kernel. The kernel remains thin; the gateway is replaceable and independently restartable without touching authority logic.

**Guardrail:** the kernel must not perform provider inference HTTP flows directly. Lightweight kernel-internal HTTP (e.g., health checks or telemetry probes) is a separate concern and may be permissible under its own review; the constraint specifically targets streaming inference calls and provider-credential flows.

---

#### A.21 — Planner Read Access to Audit Store for Gate Tuning

**Considered because:** giving the planner read access to the audit store would allow it to understand why a gate failed and produce better-targeted subsequent attempts, improving iteration speed.

**Rejected because:** unrestricted audit read access turns the audit store into a policy oracle. The planner can submit boundary proposals, observe which witness combinations produced a pass or fail, and learn the kernel's exact acceptance surface over many iterations — systematically probing the policy without ever triggering the probe-rate limiter on the IPC channel. This is a feedback-loop attack on the quality gate system: the planner optimizes toward passing gates rather than toward producing correct code. The gate verdicts must remain opaque beyond coarse deficiency classes.

**Guardrail:** the planner receives only structured gate verdicts (`PASS`, `FAIL_MISSING_WITNESS`, `FAIL_INSUFFICIENT_WITNESS`, `FAIL_POLICY_VIOLATION`). Detailed witness linkage, specific policy rule hits, and audit record contents are accessible only through operator-authenticated tooling — not through any planner-facing IPC endpoint. Any proposal to expose audit query endpoints to the planner must be evaluated as a potential gate-tuning oracle.

---

### Planner Integration Strategy

#### A.22 — Option A: RAXIS as a Proxy Layer Wrapping Existing Agents (Not Adopted)

**Considered because:** existing agent tooling — Cursor, Claude Code (claw-code), Antigravity, Cline, Aider — already has sophisticated planner loops, context management, tool execution, and provider integrations. Rather than building a planner from scratch, RAXIS could sit between the existing agent and its provider, intercepting API calls and file writes to enforce policy. The agent runs on the host as normal; RAXIS is transparent middleware. This would immediately support every existing agent without modification, dramatically lowering the barrier to adoption.

**Not adopted because of five structural weaknesses:**

1. **No enforceable process boundary.** The agent runs on the host with the same privileges as the operator. RAXIS can intercept at the HTTP layer (provider calls) and possibly at the filesystem layer (file writes), but it cannot prevent the agent from making direct `connect(2)` calls to the provider, reading the proxy's credentials from memory, or writing to paths that RAXIS doesn't monitor. The isolation is advisory — the agent *cooperates* with the proxy rather than being *confined* by it. This directly contradicts the fail-closed thesis (A.1).

2. **No authority over the prompt.** In Option A, the existing agent assembles its own system prompt, selects its own tools, and manages its own context window. RAXIS cannot inject policy context that the agent cannot read or modify (INV-02A). The agent's prompt is a black box; RAXIS can only observe the outbound API call after the prompt is already assembled. This means the kernel cannot enforce operator policy at the prompt level — it can only reject requests that violate policy after the fact, which is reactive rather than preventive.

3. **Tool execution is unobservable.** Existing agents execute tools (file edits, bash commands, search) locally without routing through RAXIS. The proxy sees the provider response (which contains tool-use blocks) but not the tool execution itself. RAXIS would need to reconstruct what the agent did from VCS diffs after the fact, rather than mediating each action as it happens. This breaks the intent-before-action model: the agent acts first, RAXIS judges later.

4. **Budget enforcement is bypassable.** If the agent holds or can observe the provider API key (which it does in Cursor, Claude Code, etc.), it can make direct calls that bypass the proxy's budget accounting. Even if the key is stripped and RAXIS holds it, the agent can cache responses, make speculative calls, or route through alternative endpoints. True budget enforcement requires the planner to have no network access — which is only possible if the planner is a confined process or VM, not a host-level application.

5. **No agent-agnostic IPC contract.** Each existing agent has its own internal state model, tool definitions, and error handling. A proxy that works with Cursor would not work with Claude Code without separate integration code. The "universal proxy" becomes N separate integrations, each tracking upstream agent internals that change across releases. The maintenance burden scales with the number of supported agents rather than being fixed by a single IPC contract.

**What Option A would have given:** immediate compatibility with the existing agent ecosystem. Operators could use their preferred editor-integrated agent (Cursor, Claude Code) with RAXIS providing guardrails. This is a significant adoption advantage that Option B sacrifices.

**What Option A costs:** the entire enforcement model becomes advisory rather than structural. RAXIS becomes a monitoring/audit layer, not an authority layer. The guarantees degrade from "the planner cannot do X" to "the planner should not do X, and we will notice if it does." For a project whose thesis is that agents need structural boundaries, not advisory ones, this is a foundational compromise.

**Guardrail:** Option A may be revisited as a "RAXIS-lite" product for teams that want observability without hard enforcement. It must never be presented as providing the same guarantees as Option B. If implemented, it must carry a clear caveat: "advisory mode — the agent cooperates with RAXIS but is not confined by it."

---

#### A.23 — Option B: RAXIS-Native Planner Loop (Adopted)

**Adopted because:** a purpose-built planner binary that runs inside RAXIS's isolation boundary (process, namespace, or VM) is the only integration model that makes the enforcement guarantees structural rather than advisory. The planner speaks `raxis-ipc`, holds no API keys, has no network access, and submits structured intents that the kernel independently verifies. Every boundary — prompt assembly, budget enforcement, path policy, gate evaluation — is enforced by the kernel, not by agent cooperation.

**Trade-off acknowledged:** this means operators cannot use Cursor, Claude Code, or other existing agents as the planner. They use the RAXIS-native planner, which must provide its own context management, tool execution, and model interaction. This is a higher barrier to adoption than Option A.

**Structural constraints on the planner binary:**

The `raxis-planner` binary is defined by what it *cannot* do, not by what it can:

| Constraint | Mechanism | Invariant |
|---|---|---|
| No network access | No virtio-net device (VM tiers), no `connect(2)` permitted (sandbox tiers), advisory (direct tier) | INV-02B |
| No API keys | Keys held exclusively by gateway; planner process env is cleared at spawn | INV-02A, A.13 |
| No policy visibility | Planner cannot read `policy.toml`, claim-requirement table, or gate definitions; kernel injects policy context into assembled prompt | A.7, A.8, A.21 |
| No witness store access | Planner has no file path to `$RAXIS_DATA_DIR/witness/`; witnesses are kernel-written | A.16 |
| No audit store access | Planner has no file path to `$RAXIS_DATA_DIR/audit/`; audit is kernel-appended | A.15, A.21 |
| No self-permission | Planner does not evaluate path or capability permissions; kernel evaluates on intent admission | A.22 §3 |
| Single IPC channel | All planner ↔ kernel communication is over one authenticated socket (UDS or vsock); no side channels | A.3, A.4 |

**Agent loop structure — the planner's entire runtime is this loop:**

```text
1. CONNECT    → IPC handshake with kernel; receive session_token
2. PICK UP    → kernel.send(NextReadyTasks) → receive task list
3. BIND       → kernel.send(IntentRequest { PickUpTask, task_id }) → task bound to session
4. INFER      → kernel.send(InferenceRequest { task_id, messages })
                 kernel checks budget, assembles prompt (injecting policy context),
                 forwards to gateway, returns InferenceResponse
5. PARSE      → extract structured actions from model output
                 (file edits, tool calls, "I'm done", "I can't do this")
6. EXECUTE    → apply file changes to worktree (local fs ops within VirtioFS mount)
                 git add + git commit → new head_sha
7. DECLARE    → kernel.send(IntentRequest { SingleCommit, base_sha, head_sha })
                 kernel independently diffs base..head, checks path policy,
                 consumes budget, spawns verifiers for required gates
8. VERDICT    → IntentResponse::Accepted → continue from step 4
                 IntentResponse::Rejected → revert commit, adjust, retry from step 4
9. COMPLETE   → kernel.send(IntentRequest { CompleteTask, head_sha })
                 kernel checks path closure + gate closure → Accepted (task done)
                 or Rejected (fix and retry from step 4)
10. FAIL      → kernel.send(IntentRequest { ReportFailure, justification })
                 → task transitions to Failed; planner returns to step 2
```

Steps 4–8 repeat until the task is complete, failed, or budget is exhausted. Steps 2–10 repeat for each task in the session. The planner never exits the loop except on session revocation or shutdown.

**What the kernel does that the planner cannot influence:**

| Responsibility | Kernel action | Planner visibility |
|---|---|---|
| **Prompt assembly** | Kernel receives planner's `messages` array, prepends the operator-signed system prompt (from policy), appends policy context (path allowlist, budget state, gate status), and forwards the assembled prompt to the gateway. The planner's `messages` are the conversation history; the kernel controls the framing. | Planner sees `InferenceResponse` (the model's output). It never sees the assembled prompt, the system prompt, or the policy context the kernel injected. |
| **Model selection** | Kernel reads `[[providers]]` from the signed policy and selects the model + provider based on the intent kind, lane, and operator routing rules. | Planner does not specify a model, temperature, or provider in `InferenceRequest`. It sends the conversation and receives the output. |
| **Budget enforcement** | Kernel computes admission cost from VCS-derived `touched_paths` + `intent_kind` + policy. Deducts from lane budget. Returns `remaining_budget` (opaque admission units) on `Accepted`. | Planner sees `remaining_budget.admission_units` and tracks deltas for self-throttling. Cannot influence the cost computation. |
| **Path policy** | Kernel diffs `base_sha..head_sha`, extracts `touched_paths`, evaluates against `effective_allow(task_id)`. Rejects if any path is out of scope. | Planner sees `FAIL_PATH_POLICY_VIOLATION`. Does not see which path or which rule. |
| **Gate evaluation** | Kernel evaluates `touched_paths` against `[[claim_requirements.rules]]`, determines required gates, spawns verifiers, collects witnesses. | Planner sees `task_state: GatesPending`. Does not see which gates, which verifiers, or which witnesses. |
| **Approval tokens** | Kernel validates operator-signed approval tokens for escalations. Planner submits `EscalationRequest`; kernel parks it until operator approves or denies. | Planner sees `EscalationResponse::Approved` or `EscalationResponse::Denied`. Does not see the token, the operator's identity, or the approval rationale. |

**Worktree interaction model:**

The planner operates on a Git worktree that is the *only* writable filesystem it can access:

- **VM tiers (Firecracker, Apple Virtualization.framework):** The worktree is a VirtioFS mount from the host. The planner sees `/worktree` (read-write). No other host filesystem path is mounted. `$RAXIS_DATA_DIR` is not accessible.
- **Sandbox tiers (bubblewrap, Seatbelt):** The worktree is the planner's only writable directory. Sandboxing rules deny access to `$RAXIS_DATA_DIR`, `$HOME`, and other host paths.
- **Direct tier (v1 default):** The worktree is a normal directory. Access to `$RAXIS_DATA_DIR` is prevented by protocol (the planner does not receive the path) but not by OS enforcement (same-UID limitation, documented in Assumptions and Limits).

The planner reads files, writes files, runs git operations, and commits — all within the worktree. The kernel independently verifies what changed by diffing the commit range. The planner cannot "claim" to have changed fewer files than it actually did — the kernel's VCS diff is the source of truth.

**Context management (planner-internal, does not cross IPC):**

The planner maintains its own conversation context across inference turns. This includes:

- **Message history:** The `messages` array sent with each `InferenceRequest`. The planner is responsible for trimming, summarizing, and managing the context window to stay within the model's token limit.
- **Session JSONL:** Append-only local log of all messages for crash recovery and debugging. Adapted from the claw-code `session.rs` pattern (see A.24). Stored within the planner's writable area, not in `$RAXIS_DATA_DIR`.
- **Tool-use parsing:** The planner must parse the model's tool-use blocks (Claude's `tool_use` content blocks or equivalent) into structured actions. The parsing logic is planner-internal; the kernel does not prescribe how the planner interprets model output.
- **Retry heuristics:** On `Rejected` verdicts, the planner decides whether to revert, adjust, and retry. The kernel provides the rejection code and remaining budget; the planner decides the strategy. There is no kernel-prescribed retry algorithm.

These are explicitly *not* kernel concerns. The kernel does not manage the planner's context window, does not parse model output, and does not prescribe retry strategy. The IPC boundary is clean: the planner sends structured intents, the kernel returns structured verdicts.

**Reference implementation candidate — claw-code (see A.24):** the claw-code open-source agent provides a well-structured Rust turn loop, session management, and tool execution model that can be studied and selectively adapted for the RAXIS planner. It is not a direct dependency — it is an architectural reference.

**Guardrail:** the RAXIS planner must never escalate to "just wrap an existing agent." If integration with existing agent tooling is desired, it must go through the formal IPC boundary as a separate product tier (see A.22 caveat), not by relaxing the planner's confinement.

---

#### A.24 — claw-code as Direct Planner Implementation (Not Adopted Directly)

**Considered because:** [claw-code](https://github.com/ultraworkers/claw-code) (the open-source Rust implementation of Claude Code) provides a production-quality agent turn loop with bounded iteration, JSONL session persistence, typed provider error handling, tool execution, and context management — exactly the mechanics the RAXIS planner needs. Importing it as a crate or forking it wholesale would save significant implementation time.

**Not adopted as a direct dependency because of five incompatible architectural assumptions:**

1. **Direct provider API access.** claw-code's `api` crate (`api/src/lib.rs`) makes HTTP streaming calls directly to the Anthropic API. The RAXIS planner must not hold API keys or make provider calls (INV-02A, A.13). All inference goes through `InferenceRequest` → kernel → gateway. The entire `api` crate is unusable.

2. **Workspace-resident policy.** claw-code's configuration system (`config.rs`) discovers and merges JSON config files from within the workspace (`.claw/settings.json`, `.claw.json`). This is explicitly rejected by A.14 — policy must live outside the repository write-bubble. The `config.rs`, `config_validate.rs`, and `trust_resolver.rs` modules are unusable.

3. **Self-enforced permissions.** claw-code's permission system (`permissions.rs`, `permission_enforcer.rs`) evaluates tool permissions locally within the agent process. In RAXIS, the planner has no permission enforcement role — the kernel enforces all path and capability policies via intent admission. The entire permission layer is not only unusable but contradicts the RAXIS authority model.

4. **MCP for tool transport.** claw-code uses MCP (`mcp_stdio.rs`, `mcp_tool_bridge.rs`) for external tool communication. MCP for authority decisions is rejected by A.3. The RAXIS planner communicates exclusively over `raxis-ipc` (bincode with 4-byte length prefix over UDS/vsock).

5. **No IPC boundary.** claw-code is a monolithic agent — the turn loop, provider client, permission system, and tool executor share a process. RAXIS requires the planner to be a separate process (or VM) communicating with the kernel over IPC. There is no `IpcClient` abstraction in claw-code; the provider response is consumed in the same process that decides what to do with it.

**What is adopted — study and selective adaptation:**

The following mechanics from claw-code are studied and selectively reimplemented (not imported) in the RAXIS planner:

| claw-code mechanic | Source | RAXIS adaptation |
|---|---|---|
| Bounded turn loop with `max_iterations` | `conversation.rs` | Core agent loop structure: iterate until task complete, failed, or budget exhausted. Replace tool execution with `IntentRequest` submission. |
| JSONL session persistence with fork lineage | `session.rs` | Planner-internal context management across turns. Does not cross the IPC boundary. |
| `ProjectContext` with git status/diff | `prompt.rs` | Planner-side context assembly before `InferenceRequest`. The kernel completes prompt assembly by injecting policy context. |
| Typed provider error taxonomy | `error.rs` | Adapted for `IntentResponse::Rejected` handling — `retryable`, error classification, exhaustion tracking. |
| Health probe after compaction | `conversation.rs` | Defensive sanity check after context trimming — verify the planner's internal state is consistent before submitting the next intent. |
| Recovery-as-data pattern | `recovery_recipes.rs` | Structured failure scenarios mapped to retry recipes with escalation policies. |

**Estimated reuse:** ~500 lines of loop mechanics and session management patterns are adaptable. ~3000 lines of permissions, config, MCP, and direct-API code are discarded. ~800 lines of new IPC integration, intent submission, and kernel-mediated inference are written fresh.

**Guardrail:** claw-code is an architectural reference, not a runtime dependency. The RAXIS planner must not depend on any claw-code crate. If claw-code's turn loop is adapted, the adaptation must replace all IO boundaries (provider calls → `IpcClient`, permissions → removed, config → kernel policy) rather than wrapping them. A planner that imports claw-code and "just disables" the permission or API layers inherits their assumptions and their attack surface.

---

#### A.25 — opencode as Additional Architecture Reference (Study Candidate)

**Context:** [opencode](https://github.com/sst/opencode) (`sst/opencode`) is an open-source, Go-based terminal coding agent with a client/server architecture. Unlike claw-code (which is a monolithic CLI), opencode runs as a **background server** that maintains persistent state across sessions, with a TUI client that connects to the running agent instance. It supports multiple providers (Anthropic, OpenAI, Gemini, Bedrock, Ollama), MCP for tool extensibility, LSP integration for code understanding, and a plugin architecture with pre/post tool-call hooks. It also distinguishes between a **Plan agent** (static analysis, suggestions) and a **Build agent** (file edits, environment interaction).

**What is worth studying for RAXIS:**

| opencode mechanic | RAXIS relevance |
|---|---|
| **Client/server split** | The background-server model is architecturally closer to RAXIS than claw-code's monolithic CLI. The opencode server maintains persistent state and accepts connections from multiple clients — similar to how the RAXIS kernel maintains persistent state and accepts connections from planner sessions. The session lifecycle management patterns may inform `raxis-kernel`'s IPC listener design. |
| **Plan/Build agent separation** | opencode's split between a planning agent and an execution agent mirrors the RAXIS intent model: the planner proposes, the kernel verifies. The specific implementation of "plan then execute" is worth comparing against RAXIS's `IntentRequest` → `IntentResponse` cycle. |
| **Plugin hooks (pre/post tool-call)** | opencode's plugin architecture for registering custom logic before and after tool calls is analogous to the kernel's pre-intent validation and post-intent audit emission. The hook registration API may inform the `[[tools]]` policy schema (v2 Operator tool manifest). |
| **`AGENTS.md` / `opencode.md` behavioural anchor** | opencode generates a project-specific instruction file from codebase analysis. RAXIS's equivalent is the operator-signed policy artifact + the kernel-injected prompt context. The comparison highlights the tradeoff: opencode trusts the workspace-resident file (A.14 violation); RAXIS requires the behavioural anchor to be signed and stored outside the workspace. |

**What is incompatible with RAXIS (same categories as claw-code A.24):**

1. **Written in Go.** RAXIS is a Rust workspace. opencode cannot be imported as a crate. Any adoption is study-and-rewrite, not dependency.
2. **Direct provider API access.** opencode holds API keys and makes direct HTTPS calls to providers. Same rejection as A.13/A.24 §1.
3. **Workspace-resident config.** `opencode.md` / `AGENTS.md` is the behavioural anchor — lives in the repo. Same rejection as A.14/A.24 §2.
4. **MCP for tool transport.** Same rejection as A.3/A.24 §4.
5. **Self-enforced permissions.** The agent decides what tools to run and what files to edit. No external authority boundary. Same rejection as A.22 §3.

**Disposition:** study the client/server session lifecycle, the plan/build agent split, and the plugin hook model. Do not adopt the Go codebase, the MCP integration, the workspace-resident config, or the direct-provider architecture. Add findings to `learnings/egm-agentic/` when reviewed.

---

---

#### A.27 — Unmediated Direct Operator-to-Agent Communication

**Considered because:** operators naturally want to steer a running agent — "actually, also handle the edge case in `auth.rs`", "stop what you're doing and focus on the test suite." Chat-based instruction is the default interaction model for every existing agentic system. Adding a side-channel from the operator terminal directly into the agent's context window (via SSH into the VM, via a CLI `raxis message` command that bypasses kernel mediation, or via any mechanism that writes into the agent's context without going through the Kernel's IPC pipeline) feels like a usability improvement.

**Rejected because the system breaks along four independent axes:**

**Axis 1 — Audit chain integrity (INV-05).** The Kernel maintains a cryptographically chained JSONL audit log. Every action an agent takes — every intent submitted, every state transition — produces a signed audit event. An operator message delivered outside the IPC pipeline never appears in the audit log. The agent acts on it; the audit log has no record that the instruction existed. An auditor examining the log sees an agent that spontaneously changed behavior for no recorded reason. The audit chain is broken at the exact point where the behavior changed, making the record useless for compliance and forensics.

**Axis 2 — Path enforcement becomes reactive rather than preventive.** The Kernel's admission gate evaluates every intent *before* any action is taken. If the operator says "also fix `src/legacy/`" and the agent tries to comply, the Kernel's path-allowlist check on the resulting `SingleCommit` intent catches it and rejects it — but only *after* the file has been modified in the worktree and a commit has been staged. The damage is already done at the filesystem level. The gate fires post-action, not pre-action. For the path gate to work as designed, the scope of what the agent is attempting must be visible to the Kernel *before* the agent attempts it.

**Axis 3 — The signed plan is no longer the authoritative specification.** The operator's Ed25519 key (see `operator_public.pem`) is used for exactly one purpose: signing `plan.toml` at `create_initiative` time. That signature cryptographically commits the operator's intent — what agents may touch, what tasks exist, what the budget is. A direct runtime message is not signed with that key. It cannot be verified as originating from the plan-signing operator. It carries no authority — it is text from someone at a terminal. If the agent acts on it, the plan has been effectively amended at runtime without a signature. The entire ceremony of signing the plan becomes advisory.

**Axis 4 — Non-repudiation gap.** If the operator sends "go ahead and write to `src/payments/`" and the agent complies, and a security incident follows, the operator can deny having sent that instruction. The only record is in the agent's ephemeral context window, which is not independently attested. By contrast, every operator action that goes through the Kernel's escalation mechanism produces `EscalationConsumed { resolved_by: operator_alice }` — permanently, cryptographically, in the audit chain. The operator cannot repudiate it.

**Edge case — the operator is malicious:** A direct operator message is structurally identical to a prompt injection attack from the Kernel's perspective. An adversary who gains terminal access (and does not have the operator's Ed25519 private key) can inject messages indistinguishable from a legitimate operator. The only protection against this is that the operator's authority channel (the signed plan) requires the private key. A side-channel that doesn't require the private key destroys this protection.

**Guardrail:** The CLI must never implement a command that writes into an agent's context window from the operator terminal without going through the Kernel's structured IPC pipeline. The Kernel must never expose an endpoint that accepts operator prose and pushes it to a session outside of the formal escalation FSM. This constraint applies even if the message is "just a hint" or "read-only guidance" — the attack surface doesn't care about the operator's intent.

---

#### A.28 — Kernel-Mediated Ad-Hoc Operator Messages (Not Originating from an Escalation)

**Considered because:** if the concern with A.27 is the absence of kernel mediation, the obvious fix is to route the message through the Kernel. The operator runs `raxis message <session_id> "<text>"`. The Kernel logs `OperatorMessage { text, session_id, timestamp }` in the audit record, wraps the text in `KernelPush::OperatorMessage { text }`, and delivers it to the agent over VSock. The Kernel is now the intermediary. The message is auditable. Why is this still insufficient?

**Rejected because kernel mediation solves the audit problem but not the authority problem:**

**Problem 1 — Auditability ≠ authority.** The audit log now records that the message was sent. But recording that someone typed `raxis message <id> "fix auth.rs"` is not the same as authorizing the agent to touch `auth.rs`. The Kernel can log the message; it cannot validate whether the message's content is within the scope of the signed plan, whether it conflicts with the DAG, whether the requested action is within the agent's `path_allowlist`, or whether the request makes any semantic sense in the context of the current task. The Kernel is a policy enforcer, not a semantic reasoner. Logging an instruction the Kernel cannot validate is surveillance without enforcement.

**Problem 2 — Content validation is unsolvable at the message layer.** When `approve_plan` runs, the 7 shift-left checks validate the entire plan against a typed schema before any VM boots. An ad-hoc operator message arrives as a natural-language string after VMs are running. The Kernel cannot:
- Parse intent from natural language
- Check whether the requested action is within the agent's `path_allowlist`
- Verify it doesn't introduce an implicit sub-task the DAG didn't authorize
- Determine if it conflicts with a Reviewer's criteria for the current task
- Know whether it amends, overrides, or merely clarifies the signed plan

The only safe assumption is that the message's content is unvalidated operator prose — and unvalidated prose should never drive an agent's actions in a system where validated plans drive everything else.

**Problem 3 — The LLM cannot distinguish a legitimate `KernelPush` from an injected one.** Even if the Kernel wraps the message as `KernelPush::OperatorMessage { text: "..." }`, the agent processes it as text in its context window. A prompt injection embedded in a file the agent is reading (a documentation file, a README, a code comment) could produce identically-structured output and impersonate the `KernelPush` format. The LLM has no cryptographic verification capability. If the Kernel creates a `KernelPush::OperatorMessage` channel, it creates an attack surface where any actor who can control text the agent reads can impersonate the operator via the Kernel's own delivery mechanism.

The escalation mechanism avoids this because `KernelPush::EscalationResolved` can only be delivered after the Kernel has verified a matching `EscalationRequested` event in `Consumed` state and a valid operator token. The `KernelPush` is produced by the Kernel's own FSM transition, not by forwarding operator prose. The Kernel is not an operator-message relay; it is a state machine.

**Problem 4 — The agent cannot act on it without violating another invariant.** If the operator message says "also handle `src/legacy/`" and the agent tries to comply, the next `SingleCommit` intent touching `src/legacy/` will be rejected by the path-allowlist gate — because `src/legacy/` is not in the agent's signed allowlist. The message caused the agent to waste inference turns attempting something structurally impossible. To make the message *actionable*, the Kernel would need to expand the agent's path allowlist in response to the message — which means unsigned runtime plan amendment (the rejected case in A.27).

**Problem 5 — It breaks the "blocked" signal semantics.** The escalation FSM encodes a specific semantic: `EscalationRequested` means the agent is genuinely blocked and cannot proceed autonomously. This is a verifiable state — the Kernel knows the agent's FSM paused at the escalation submission. A general `KernelPush::OperatorMessage` mechanism has no such semantic. The operator can send messages to agents that are not blocked, are mid-task, or have just submitted `CompleteTask`. The message can arrive at any point and steer the agent off its planned trajectory without the Kernel knowing whether the agent was blocked or making normal progress.

**The one legitimate version of this mechanism:** There *is* a correct, kernel-mediated, operator-to-agent message channel — the system prompt written to `.raxis/system_prompt.txt` before VM boot. This is:
- Operator-sourced content via the signed plan's `[orchestrator.context]` / `[subtask.context]` fields
- Validated at `approve_plan` time (part of the 7 shift-left checks)
- Sealed into `signed_plan_artifacts` with `SHA-256(plan_bytes)`
- Written once by the Kernel Prompt Assembler before the VM starts
- Immutable for the session's lifetime

The pre-boot system prompt is the correct "operator tells agent what to do" channel because it was committed at plan-signing time, under the operator's Ed25519 key, and is immutable during execution. An ad-hoc runtime message has none of these properties.

**Invariant summary:**

| Channel | Signed | Content validated | Immutable after delivery | Kernel state-machine-gated |
|---|---|---|---|---|
| `plan.toml` + pre-boot system prompt | ✅ Ed25519 | ✅ 7 approve_plan checks | ✅ | N/A (pre-execution) |
| Escalation hint via `EscalationResolved` | ✅ operator token | ✅ FSM-gated (EscalationRequested must exist) | ✅ | ✅ |
| Direct operator message (A.27) | ❌ | ❌ | ❌ | ❌ |
| Kernel-mediated ad-hoc message (A.28) | ❌ | ❌ | ❌ | ❌ |

**Guardrail:** The Kernel must never expose an IPC endpoint or CLI handler that accepts operator prose at runtime and pushes it to an active session's context window outside of the escalation FSM. The `KernelPush` enum must not include a variant that carries free-text operator input without an associated `EscalationId` that the Kernel has verified is in `Consumed` state. Any proposal to add `KernelPush::OperatorMessage` or equivalent must be evaluated as equivalent to A.27 and rejected on the same grounds.

