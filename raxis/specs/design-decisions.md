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

**Considered because:** a fine-grained staleness model — where a delegation becomes stale only if the specific capability classes it covers changed in the new epoch — is more precise and operationally less disruptive than invalidating all delegations on any epoch change.

**Rejected for v1 because:** implementing this correctly requires the kernel to diff two policy epochs and determine per-capability impact, which is a complex and failure-prone piece of infrastructure to build before the basic system is proven. The v1 rule is deterministic and auditable: any epoch advance marks active delegations stale-on-next-use, triggering a renewal decision at first use. This is operationally disruptive if epochs change frequently — which is itself a pressure to keep policy changes rare, which is the correct incentive. Per-capability staleness diffing is a v2 optimization.

**Guardrail:** do not implement per-capability epoch diffing in v1 code. Stale = any epoch mismatch. Renewal = new kernel decision required.

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

