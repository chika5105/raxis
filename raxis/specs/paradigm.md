# The RAXIS Paradigm

> **Status:** Foundational. This document defines what RAXIS *is* — independent of any particular implementation. The current Rust workspace under this repository is one **reference implementation** of the paradigm, applied to the domain of autonomous software engineering. Other reference implementations may exist or be built; all RAXIS implementations satisfy the invariants in this document.
> **Audience:** Architects evaluating RAXIS as a category, implementers building a new RAXIS, auditors verifying conformance, contributors making structural changes to the current reference implementation.
> **Cross-references:**
> - [`README.md`](../README.md) — the current reference implementation overview
> - [`POSITIONING.md`](../POSITIONING.md) — how RAXIS positions against existing categories
> - [`specs/invariants.md`](invariants.md) — `INV-*` invariants of the current reference implementation; each maps to one or more `R-*` paradigm invariants
> - [`perspectives/raxis-concept.md`](../perspectives/raxis-concept.md) — earlier conceptual analysis that this document formalizes

---

## 1. What RAXIS Is

**RAXIS — Runtime Attestation eXchange for Intelligent Systems —** is a paradigm for the structural separation of intelligence and authority in autonomous systems. It defines how an intelligent system (an LLM-driven agent, a planner, an autonomous executor) must interact with its operating environment so that every action is authorized by an independent authority before any side effect occurs and recorded in a tamper-evident ledger after.

The paradigm has one foundational claim: **the component that decides what to do must not be the same component that decides whether it is allowed.** This is enforced at every level — by execution-domain isolation, by typed mediated I/O, by cryptographically signed capabilities, by append-only audit, by fail-closed defaults — not by training, prompt engineering, or convention.

RAXIS is not an alignment technique. It is not an agent framework. It is not a sandbox runtime. It is the *structural enforcement layer* that sits between intelligence and the world, making intelligence's actions accountable, bounded, and reproducible regardless of how the intelligence itself behaves.

### 1.1 The asymmetric trust premise

Every RAXIS implementation rests on one premise: **intelligence is untrusted; authority is trusted.** The intelligence may hallucinate, may be prompt-injected, may be fine-tuned adversarially, may be replaced silently, may collude with other intelligence instances — and the system's safety properties must not depend on any of this being false. Authority — the kernel, the policy, the audit log — is the trust root. RAXIS confines the blast radius of intelligence misbehavior to what authority explicitly permits.

This premise is what distinguishes RAXIS from every adjacent category:

- **Alignment** improves intelligence's intent. RAXIS assumes intent is irrelevant.
- **Sandboxing** isolates the process. RAXIS isolates the *authority surface*.
- **Agent frameworks** orchestrate intelligence. RAXIS subordinates intelligence to authority.
- **Policy engines** evaluate rules. RAXIS makes the rules a cryptographic contract whose application is auditable.
- **Audit logging** records what happened. RAXIS makes the record cryptographically non-repudiable.

A system that satisfies the RAXIS invariants is *correct under adversarial intelligence*: its safety guarantees hold even if the intelligence is actively trying to bypass them.

---

## 2. Paradigm vs Reference Implementation

A clear separation between *paradigm* and *implementation* is essential to RAXIS as a discipline.

### 2.1 The paradigm

The paradigm is a finite set of structural invariants (§3) that any RAXIS implementation must satisfy, plus a conformance contract (§4) that defines what it means to claim RAXIS conformance.

The paradigm does NOT prescribe:

- Implementation language (Rust, Go, Zig, C++, formally verified Coq, etc. all viable)
- Isolation primitive (microVM, hardware enclave, formally verified microkernel partition, etc.)
- Storage backend (SQLite, embedded RocksDB, custom append-only WAL, etc.)
- Audit log format (JSONL, CBOR, Protobuf — any append-only signed format)
- Provider integration mechanism (direct HTTPS, gRPC, in-process plugin)
- Domain (software engineering, customer support, trading, robotics — see §5)

Two implementations satisfying the same paradigm invariants on different hardware, in different languages, for different domains are both RAXIS. Their audit logs may not be cross-verifiable (different formats), but their structural guarantees are equivalent.

### 2.2 Reference implementations

A *reference implementation* is a concrete realization of the paradigm for a specific domain, with specific technology choices, specific authority semantics, and specific tooling. Reference implementations make the paradigm concrete — they prove it is buildable and they give operators something they can deploy.

The current reference implementation in this repository targets **autonomous software engineering**: planners that read code, write code, run tests, and integrate changes into a master git repository. Its concrete instantiations of the paradigm are:

- Intelligence runs in microVMs (Firecracker on Linux, Apple Virtualization.framework on macOS)
- Authority is a Rust daemon (`raxis-kernel`) speaking VSock to planners and Unix sockets to operators
- Capabilities are declared in TOML artifacts (`policy.toml`, `plan.toml`) signed with operator Ed25519 keys
- Audit log is hash-chained JSONL transitioning to a two-level Merkle tree in V3
- The domain-specific authority operations are git-shaped: `IntegrationMerge`, `CompleteTask`, `SubmitReview`, `EscalationRequest`, `InferenceRequest`, `EgressRequest`, `FetchRequest`

A different reference implementation could exist for, say, autonomous customer support (intent kinds: `SendEmail`, `IssueRefund`, `EscalateToHuman`; capabilities: response templates, refund ceilings, escalation triggers) and still be RAXIS — same paradigm invariants, different domain semantics.

### 2.3 Why this distinction matters

The paradigm/implementation split protects RAXIS as a discipline:

- **Implementations are improvable without changing what RAXIS means.** The current reference impl can adopt better isolation primitives, better storage, better audit formats — none of these change whether it is RAXIS.
- **Domain expansion does not dilute the paradigm.** New domain reference implementations inherit all paradigm guarantees automatically; they only add domain-specific authority semantics.
- **Verification has a stable target.** "Is this RAXIS-verified?" reduces to "does it satisfy the paradigm invariants?" not "does it look like the current implementation?"
- **Conformance is portable.** A team building a domain-specific RAXIS for trading does not need to rebuild this Rust codebase; they need to build something that satisfies the same R-invariants.

---

## 3. The Paradigm Invariants

The paradigm is defined by twelve invariants in four groups: structural separation, authority model, accountability, and coordination. Each invariant is independent — none can be derived from the others — and the conjunction of all twelve is necessary for an implementation to be RAXIS.

Each invariant is stated normatively, with rationale, what it rules out, and a verification method.

### Group A: Structural Separation

These invariants establish the foundational boundary between intelligence and authority. Without them, no other invariant can be enforced — a co-located intelligence can simply edit the policy or the audit log directly.

#### R-1 — Domain Separation

> **Statement:** Intelligence and authority MUST run in distinct execution domains with no shared mutable state. Compromise of intelligence MUST NOT, by itself, grant intelligence the capabilities of authority.

**Rationale.** If intelligence and authority share an address space, a single memory-safety bug or in-process injection grants intelligence everything authority can do. The boundary must be enforced by an isolation primitive whose security properties do not depend on intelligence's correctness.

**What it rules out.** In-process plugin agents (LangChain in the same Python process as the policy engine). "Tool use" frameworks where the tool implementation runs in the agent's process. Single-binary "kernel + agent" designs. Configuration where the agent has filesystem write access to the policy or audit storage.

**Verification.** The implementation's isolation primitive must be at least equivalent to a hardware-virtualized microVM, a hardware enclave, or a formally verified microkernel partition. Independent code audit must trace every authority resource (policy, audit log, kernel state, credentials) and confirm intelligence has no read or write path to it that bypasses authority's mediation.

#### R-2 — Mediated I/O

> **Statement:** Intelligence MUST NOT have direct access to credentials, network, persistent storage, external systems, or other intelligence instances. All such access MUST be mediated by authority through typed intents subject to admission checks.

**Rationale.** I/O is how intelligence affects the world. If any I/O class is direct, that class bypasses every authority guarantee — credentials can be exfiltrated, networks can be reached, peer agents can be coordinated with, storage can be tampered with — and the rest of the paradigm's protections become irrelevant for that class.

**What it rules out.** Environment-variable credential injection. Direct outbound TCP from the agent process. Mounted filesystems the agent can write to without authority observation. Direct VSock or shared-memory channels between agents. Any "fast path" that bypasses authority for performance.

**Verification.** The intelligence execution environment must be inspected to confirm it has no network device, no credential material, no writable filesystem outside an authority-mediated workspace, and no IPC channel except the authority IPC channel. Penetration testing must confirm that an adversarial agent cannot reach external systems through any channel except authority-mediated intents.

### Group B: Authority Model

These invariants define how authority makes decisions. Without them, authority becomes either too permissive (degrading to "the agent can do anything") or too rigid (degrading to "the agent can do nothing").

#### R-3 — Signed Capability Declaration

> **Statement:** Every action available to intelligence MUST be a capability declared in a cryptographically signed policy artifact attributable to a human principal. Capabilities not so declared MUST be denied.

**Rationale.** Authority's decisions must trace to a verifiable human authorization. Without cryptographic signing, the policy is mutable by anyone with filesystem access (including a compromised authority host); without explicit declaration, capabilities are inferred from prose or convention, neither of which is auditable.

**What it rules out.** YAML config files in plaintext (`config.yaml` with API keys and tool lists, AIOS-style). Capability inference from the LLM's tool descriptions. "If the prompt says it's allowed, do it." Implicit capabilities ("of course the agent can read its own working directory").

**Verification.** Policy artifacts must be inspectable, verifiable against a public key the operator controls, and structurally validated against a closed schema. Intelligence must be confirmed unable to generate signatures (it does not hold the operator key).

#### R-4 — Authority Derivation Hierarchy

> **Statement:** All operational authority MUST trace through a verifiable chain to a human-signed root. Intermediate authority layers (plans, sub-policies, delegated sessions) MAY only narrow upstream authority, never expand it.

**Rationale.** The whole point of cryptographic signing is undermined if intermediate layers can grant capabilities the root did not authorize. A plan that exceeds policy bounds, or a sub-session that holds capabilities its parent does not, breaks the chain of accountability.

**What it rules out.** Plans that add capabilities not enumerated in policy. Orchestrator agents that grant sub-agents capabilities exceeding the orchestrator's own. "Privilege escalation by composition." Implicit authority widening through configuration changes that don't pass back through a human signature.

**Verification.** The policy admission pipeline must include a structural check that any signed sub-artifact (plan, sub-policy) is a strict narrowing of its parent. Adversarial test cases must include attempted privilege widening at every intermediate layer.

#### R-5 — Bounded Capabilities

> **Statement:** Every granted capability MUST carry explicit numerical bounds (count, rate, value, time, or equivalent). Unbounded grants MUST be rejected at policy admission time.

**Rationale.** An autonomous agent with even a permissible capability can cause unbounded harm if the capability has no ceiling. "Send email" without a rate limit can spam. "Submit trade" without a size cap can liquidate the firm. "Call inference API" without a token budget can cost millions. Bounds make the worst-case harm calculable in advance.

**What it rules out.** "Unlimited" anything in policy. Capabilities granted "for the duration of the session" without a session length limit. Budgets without rate limits. Network egress without bandwidth caps. Implicit defaults of infinity.

**Verification.** The policy schema must require explicit bounds for every capability type. Static analysis of policy artifacts must reject any unbounded grant. Worst-case-budget reservation logic must be present and tested.

#### R-6 — Fail-Closed Default

> **Statement:** The default for any action lacking explicit authority MUST be deny. Ambiguity, missing policy, evaluation failure, communication failure with authority, and authority-internal errors MUST all resolve to denial.

**Rationale.** Fail-open systems silently admit actions when verification cannot complete, providing false assurance precisely when assurance matters most. A RAXIS that fails open is worse than no RAXIS — it tells operators their agent is constrained when it is not.

**What it rules out.** "If the policy file is missing, allow everything" (common in less-careful systems). "If the audit log is full, write to stderr and continue." "If the authority is unreachable, cache the last decision." "If the capability is ambiguous, prefer the permissive interpretation."

**Verification.** Adversarial tests must verify that every fault injection (missing policy, corrupted policy, authority crash, IPC timeout, audit failure, signature verification failure) results in denial, not admission.

### Group C: Accountability

These invariants make authority's behavior verifiable after the fact. Without them, authority becomes a black box the operator must trust on faith — which defeats the paradigm's purpose.

#### R-7 — Cryptographic Audit Chain

> **Statement:** Every authority decision (admit, deny, escalate, error) MUST be recorded in an append-only log such that any modification, deletion, or insertion is detectable by an independent verifier holding only the log and the public keys of recorded signers. The log's integrity MUST NOT depend on continued operation of the authority that produced it.

**Rationale.** The audit log is the only evidence available after the fact for what authority decided. If the log is mutable, it is useless — a compromised authority simply rewrites it. If the log's integrity depends on the authority that produced it (e.g., the authority's process must be alive to verify), the operator cannot independently audit a deceased or hostile authority.

**What it rules out.** Mutable log files. Log rotation that overwrites without retaining cryptographic continuity. Audit storage in the same SQLite database the authority uses for state (write transactions can roll back the audit too). Audit signing keys that the authority can rotate without operator knowledge. Rolling logs that drop old segments without preserving inclusion proofs for any potentially-cited prior event.

**Verification.** An independent tool (not the authority) must be able to verify the audit log's integrity given only the log files and the operator's public key. Tampering tests must demonstrate that any single-byte modification is detected. The verification tool must be open source and reproducibly built.

#### R-8 — Auditable Decisions

> **Statement:** Authority decisions MUST be reproducible from recorded inputs. Any ambient state consulted during a decision (clock, derived state, randomness, prior decision history) MUST be recorded in or derivable from the audit log such that an independent verifier can replay the decision and arrive at the same outcome.

**Rationale.** The audit log is a record of decisions; it must also be sufficient to *reconstruct* those decisions. Without reproducibility, a malicious or buggy authority can record one decision while having actually made another. With reproducibility, the audit log becomes a verifiable trace of authority's behavior.

**What it rules out.** Decisions that depend on un-recorded ambient state ("the authority decided based on whatever circuit-breaker state happened to be in memory"). Random tie-breaking without a recorded seed. Wall-clock dependencies that don't record the consulted timestamp. Floating-point arithmetic in admission paths.

**Verification.** An audit replay tool must exist that takes the audit log + signed policy + signed plans + intent stream and produces the same admission decisions the authority recorded. Discrepancies are conformance failures.

#### R-9 — Attributable Intent

> **Statement:** Every intent submitted to authority MUST be attributable to a specific intelligence identity verifiable by authority. Anonymous intents MUST be rejected.

**Rationale.** Without per-intent attribution, the audit log records actions without actors — it can prove what was admitted but not who requested it, defeating accountability for intelligence-side compromise.

**What it rules out.** Intents over an unauthenticated channel. Shared session tokens used by multiple intelligence instances. "Anyone with the kernel socket can submit" designs. Identity verification that depends on network position alone (any compromise of the host bypasses it).

**Verification.** Every recorded intent must carry a session-or-equivalent identifier. The audit log must permit construction of "all intents submitted by intelligence X" queries. Adversarial tests must verify that intents without valid identity are rejected before any admission logic executes.

#### R-10 — Opaque Rejection

> **Statement:** Authority decisions communicated to intelligence MUST NOT reveal which specific policy rule fired. Rejection codes MUST be coarse-grained categories, not pointers to internal policy structure.

**Rationale.** If intelligence learns exactly which rule fired, it can craft its next intent to just-barely satisfy each rule — gaming the verification rather than complying with its spirit. Adversarial intelligence converges to the boundary of permitted behavior; opaque rejection prevents the boundary from being mapped.

**What it rules out.** Error messages like "denied by rule policy.toml:42 (maximum file size)". Revealing the policy hash in rejection responses. Differential timing attacks (rejection time correlated with which rule fired). Verbose stack traces in agent-facing errors.

**Verification.** The set of agent-facing rejection codes must be a closed enumeration. Audit logs may contain detailed rejection rationale (operator-facing); agent responses must contain only the coarse code. Timing tests must show no correlation between rejection latency and which rule fired.

### Group D: Coordination and Recovery

These invariants govern how intelligence interacts with peers and how authority handles cases where intelligence's needs exceed its current authority.

#### R-11 — Mediated Coordination

> **Statement:** When multiple intelligence instances cooperate, they MUST communicate through authority, not directly. Inter-intelligence messages MUST pass admission checks equivalent to other intent classes.

**Rationale.** Direct intelligence-to-intelligence channels create authority blind spots. A compromised orchestrator agent could coordinate with a compromised executor agent to exfiltrate data through an audit gap. Authority-mediated coordination preserves the audit chain across multi-agent flows.

**What it rules out.** Direct VSock or pipe channels between agents. Shared-memory message passing. "Agent broker" services that route between agents without authority involvement. Implicit coordination through shared filesystem state.

**Verification.** Architectural review must confirm there is no IPC primitive between intelligence domains that does not pass through authority. Audit logs must record every cross-agent message at the same fidelity as other intents.

#### R-12 — Out-of-Band Escalation

> **Statement:** When an intent exceeds available authority, intelligence MUST NOT be able to self-authorize. Either the intent fails, or it escalates through a channel intelligence cannot influence to a human principal authorized to grant the additional authority.

**Rationale.** Static authority is useless if it cannot be widened safely when intelligence encounters legitimate work outside its scope. But widening must be human-mediated through a channel intelligence cannot manipulate (no email-reply approval, no in-prompt "say yes," no shared chat channel intelligence can also write to). Without this, agents either get stuck on every edge case or grow their own authority through social engineering.

**What it rules out.** Approval by email reply (intelligence might compose the reply). Approval by chat message (intelligence might send the message). Approval tokens delivered through any channel intelligence has read access to. Self-extending sessions ("I'll just ask my manager agent for more permissions").

**Verification.** The escalation channel must be cryptographically distinct from any intelligence-accessible channel. Approval must require a signature from a key intelligence does not hold. Adversarial tests must include attempted escalation forgery.

### 3.13 Summary table

| ID | Name | Group | One-line statement |
|---|---|---|---|
| **R-1** | Domain Separation | Structural | Intelligence and authority in distinct execution domains; no shared mutable state |
| **R-2** | Mediated I/O | Structural | All credential, network, storage, peer-intelligence access mediated by authority |
| **R-3** | Signed Capability Declaration | Authority | Every capability declared in a cryptographically signed policy artifact |
| **R-4** | Authority Derivation Hierarchy | Authority | Sub-artifacts may only narrow parent authority; no expansion |
| **R-5** | Bounded Capabilities | Authority | Every capability carries explicit numerical bounds |
| **R-6** | Fail-Closed Default | Authority | Ambiguity, errors, and missing policy resolve to deny |
| **R-7** | Cryptographic Audit Chain | Accountability | Audit modifications detectable by independent verifier with public keys only |
| **R-8** | Auditable Decisions | Accountability | Decisions reproducible from recorded inputs; ambient state recorded |
| **R-9** | Attributable Intent | Accountability | Every intent traces to a verified intelligence identity |
| **R-10** | Opaque Rejection | Accountability | Agent-facing rejections reveal no specific rule fired |
| **R-11** | Mediated Coordination | Coordination | Multi-agent communication passes through authority |
| **R-12** | Out-of-Band Escalation | Recovery | Authority widening requires human approval via a channel intelligence cannot reach |

---

## 4. Conformance — RAXIS-Verified

A claim of "RAXIS-Verified" is a claim of conformance to the twelve paradigm invariants. To prevent the term from becoming meaningless marketing, this section defines three conformance tiers with progressively stronger evidentiary requirements. The unqualified term "RAXIS-Verified" refers to Tier 3.

### 4.1 Tier 1 — RAXIS-Aligned

**Definition.** The implementation is *designed* to satisfy all twelve R-invariants. The implementer publishes a *conformance statement* mapping each R-invariant to the architectural mechanism that enforces it.

**Evidence required.**

- A public conformance statement with one section per R-invariant, naming the specific mechanism (e.g., "R-1 enforced by Firecracker microVM with no shared memory between agent and kernel address spaces") and citing the source files or specs that implement it.
- An architectural diagram showing the intelligence/authority boundary and every channel that crosses it.
- Acknowledgment of any deviations or partial conformance, with a remediation plan.

**Verification mechanism.** Self-attestation. The community can challenge published conformance statements but the burden of disproof is on the challenger.

**Use case.** Early-stage implementations, research prototypes, RAXIS adapted to a new domain where the conformance test suite has not yet been adapted.

### 4.2 Tier 2 — RAXIS-Tested

**Definition.** Tier 1 + the implementation passes the canonical RAXIS conformance test suite. The test suite exercises each R-invariant with both positive cases (action correctly admitted) and adversarial cases (action correctly denied despite attempted bypass).

**Evidence required.**

- All Tier 1 evidence.
- Conformance test suite passes (continuous integration logs, reproducible build).
- Documentation of any test suite cases that are skipped (with rationale) or replaced with equivalent tests (with the equivalence argument).

**Verification mechanism.** Self-tested. The conformance test suite is open source and reproducibly runnable; any third party can independently re-run it.

**Conformance test suite categories.**

1. **Separation tests** — verify intelligence cannot read authority memory, cannot bypass IPC, cannot reach storage directly. Includes adversarial fuzzing of the IPC protocol.
2. **Capability tests** — verify undeclared capabilities are denied. Includes adversarial intent submissions claiming undeclared capabilities.
3. **Hierarchy tests** — verify sub-artifacts cannot exceed parent authority. Includes attempted plan-widening.
4. **Bounds tests** — verify every capability hits its bound. Includes deliberate overage attempts at every bound type.
5. **Fail-closed tests** — verify denial under fault injection (missing policy, IPC timeout, audit failure, etc.).
6. **Audit chain tests** — verify single-byte tampering is detected. Includes random mutation of audit segments.
7. **Reproducibility tests** — verify the audit replay tool reproduces recorded decisions.
8. **Identity tests** — verify unauthenticated intents are rejected.
9. **Opacity tests** — verify rejection codes do not leak rule structure; includes timing-based information leak tests.
10. **Coordination tests** — verify no inter-agent IPC primitive exists outside authority mediation.
11. **Escalation tests** — verify escalation channel cannot be reached or forged by intelligence.

The full test suite is maintained as an independent repository (`raxis-conformance`) so test updates are decoupled from any single implementation's release cycle.

**Use case.** Production-bound implementations seeking to demonstrate they have engineered conformance, not merely claimed it.

### 4.3 Tier 3 — RAXIS-Verified

**Definition.** Tier 2 + independent third-party audit by a qualified verifier. This is the certification level and the only tier that may be advertised as "RAXIS-Verified" without qualification.

**Evidence required.**

- All Tier 2 evidence.
- Independent audit report from a qualified verifier (see §4.4) covering:
  - Source code audit of the authority layer (kernel, admission pipeline, audit subsystem)
  - Architectural review of the separation primitive (isolation soundness)
  - Verification of audit log format conformance to the canonical schema
  - Penetration testing of credential isolation and inter-domain boundary
  - Operator and policy artifact format conformance (to enable policy portability between RAXIS-Verified implementations)
- Public certification statement signed by the auditor.
- Annual re-audit (audit certification expires after one year).

**Verification mechanism.** Third-party audit. Auditors must be qualified per §4.4 and must publish their methodology publicly so the audit itself is reviewable.

**Use case.** Regulated deployments, customer-facing claims, contractual conformance commitments, and any context where the operator needs to defend the conformance claim to a third party (regulator, insurer, customer, court).

### 4.4 Qualified verifiers

To prevent the verification ecosystem from collapsing into a self-certifying cartel, qualified verifiers must satisfy:

- **Independence.** The verifier MUST NOT have a financial relationship with the implementation under audit other than the audit fee itself.
- **Methodology transparency.** The verifier MUST publish its audit methodology, including which conformance test cases are included beyond the canonical suite, what penetration tests are performed, and how each R-invariant is evaluated. Methodologies are open to community review.
- **Reproducibility.** Audit findings MUST be reproducible by a second independent verifier given the same source tree and methodology.
- **Conflict disclosure.** The verifier MUST disclose any prior or ongoing engagements with the implementation team or its dependencies.
- **Certification.** Verifiers MUST themselves be certified by the RAXIS specification body (initially the maintainers of this repository; later a neutral standards body).

This is intentionally analogous to the model used by FIPS 140 cryptographic module validation labs, Common Criteria evaluation labs, and SOC 2 auditors.

### 4.5 Mapping invariants to verification

| R-Invariant | Tier 1 evidence | Tier 2 test | Tier 3 audit focus |
|---|---|---|---|
| R-1 Domain Separation | Architecture doc citing isolation primitive | Adversarial IPC fuzz; cross-domain memory access tests | Code audit of isolation boundary; penetration test |
| R-2 Mediated I/O | Inventory of all I/O channels and their mediation path | Adversarial direct-I/O attempts (network, fs, IPC) | Penetration test of intelligence environment |
| R-3 Signed Capability | Policy schema; signing key inventory | Undeclared-capability rejection tests | Code audit of policy verification path |
| R-4 Authority Hierarchy | Policy/plan hierarchy schema | Plan-widening rejection tests | Code audit of admission narrowing logic |
| R-5 Bounded Capabilities | Bounds enumeration for every capability type | Per-bound overage tests; worst-case reservation tests | Code audit of bounds enforcement |
| R-6 Fail-Closed | Fault-handling design doc | Comprehensive fault injection suite | Code audit of error paths |
| R-7 Audit Chain | Audit format spec; verification tool | Single-byte tampering detection; deletion detection | Code audit of audit subsystem; format conformance |
| R-8 Auditable Decisions | Decision input enumeration | Replay tool reproduces recorded decisions | Code audit of admission determinism |
| R-9 Attributable Intent | Identity verification design | Unauthenticated intent rejection tests | Code audit of identity binding |
| R-10 Opaque Rejection | Closed enumeration of agent-facing codes | Code-level + timing-based information leak tests | Code audit of error formatting paths |
| R-11 Mediated Coordination | IPC channel inventory | Direct inter-agent IPC attempt tests | Architectural review |
| R-12 Out-of-Band Escalation | Escalation channel design | Escalation forgery tests; intelligence-readable channel scan | Penetration test of escalation channel |

### 4.6 Conformance for the current reference implementation

The current Rust workspace under this repository is, as of V2:

- **Tier 1 — Aligned:** ✓. The architectural mechanisms for all twelve R-invariants are present and documented across `specs/v1/` and `specs/v2/`. The mapping from R-invariants to implementation invariants is in §6.
- **Tier 2 — Tested:** Partial. The implementation has extensive INV-* test coverage in its own test suite, but the canonical RAXIS conformance test suite is not yet adapted to this implementation's intent shape. Adapting the canonical suite is V3 GA scope.
- **Tier 3 — Verified:** Not yet. Requires the canonical conformance suite to be adopted (Tier 2) and a qualified verifier engagement.

The current implementation also has acknowledged paradigm gaps that limit its ceiling even at Tier 3 — see [`perspectives/raxis-concept.md`](../perspectives/raxis-concept.md) Part 3 for the eight known gaps (no model identity attestation, no hardware root of trust, retrospective rather than prospective attestation, etc.). These gaps do not violate any R-invariant as stated but represent open research problems that would strengthen the paradigm itself in a future revision.

---

## 5. Reference Implementations

The paradigm is domain-agnostic. Different reference implementations apply it to different problems. This section names the current implementation and sketches what other reference implementations could look like, to make the paradigm/implementation distinction concrete.

### 5.1 Current — Autonomous Software Engineering

**Reference implementation:** the Rust workspace in this repository.

**Domain.** A planner agent reads code, writes code, runs tests, integrates changes into a master git repository, and may coordinate with reviewer agents and orchestrator agents on complex initiatives.

**Domain-specific authority operations.**

- `IntentRequest::CompleteTask` — agent claims to have finished a task at a specific commit SHA
- `IntentRequest::IntegrationMerge` — orchestrator merges sub-task commits into the master branch
- `IntentRequest::SubmitReview` — reviewer agent submits a verdict on a peer's work
- `IntentRequest::EscalationRequest` — agent requests authority for an action outside its plan
- `IntentRequest::InferenceRequest` — agent calls an LLM provider via the kernel-mediated gateway
- `IntentRequest::EgressRequest` — agent makes an HTTP call to an allowlisted external URL
- `IntentRequest::FetchRequest` — agent reads from an allowlisted external resource

**Domain-specific policy.** `policy.toml` declares allowed operators, allowed providers and pricing, allowed master-repo bindings with push credentials, allowed worktree roots, allowed egress hosts, host capacity caps, audit retention, etc. `plan.toml` declares per-initiative path allowlists, per-task token limits, per-task egress allowlists, agent role declarations (Orchestrator, Executor, Reviewer), `can_delegate` capabilities, and per-task reviewers.

### 5.2 Possible — Autonomous Customer Support

**Hypothetical reference implementation.** Not yet built; described here to make the paradigm/domain distinction concrete.

**Domain.** A planner agent reads customer messages, drafts responses, may issue refunds within a bounded amount, may escalate complex cases to human agents.

**Domain-specific authority operations.**

- `IntentRequest::SendEmail` — agent sends a templated response to a customer
- `IntentRequest::IssueRefund` — agent issues a refund (subject to per-amount bounds and per-customer rate limits)
- `IntentRequest::EscalateToHuman` — agent escalates to a human support agent
- `IntentRequest::FetchCustomerHistory` — agent reads customer history (subject to PII access controls)
- `IntentRequest::InferenceRequest` — same as the SE implementation

**Domain-specific policy.** Allowed response template families, refund ceilings (per-incident, per-customer-per-day, per-agent-per-hour), escalation triggers, PII access scopes, escalation routing rules.

The R-invariants are unchanged. R-3 (Signed Capability Declaration) means refund ceilings are in signed policy, not config. R-5 (Bounded Capabilities) means there is no "unlimited refund" mode. R-7 (Cryptographic Audit) means every email sent is in the audit chain. R-12 (Out-of-Band Escalation) means a customer cannot trick the agent into approving a refund that exceeds policy by phrasing the request cleverly — escalation goes to a human.

### 5.3 Possible — Autonomous Trading

**Hypothetical reference implementation.**

**Domain.** A planner agent reads market data, runs strategies, submits orders to brokerages within bounded position sizes, escalates portfolio rebalances or large positions to human traders.

**Domain-specific authority operations.**

- `IntentRequest::SubmitOrder` — agent submits a buy/sell order
- `IntentRequest::CancelOrder` — agent cancels a pending order
- `IntentRequest::RebalancePortfolio` — agent triggers a rebalance (typically requires escalation)
- `IntentRequest::ReadMarketData` — agent reads from allowlisted market-data feeds
- `IntentRequest::InferenceRequest` — same

**Domain-specific policy.** Allowed instruments, per-instrument position limits, per-day loss limits, allowed counterparties (brokerages), market-data feed credentials (held by authority, not agent), required human approval for orders above threshold, kill-switch triggers.

R-5 (Bounded Capabilities) is the load-bearing invariant in this domain — the difference between a bug and a firm-ending event is whether position limits are bounded in signed policy. R-6 (Fail-Closed) means market-data outages do not cause silent fallback to "trade with stale data."

### 5.4 Possible — Autonomous Robotics

**Hypothetical reference implementation.**

**Domain.** A planner agent perceives its environment, plans physical actions, executes motor commands within bounded force/speed/workspace envelopes, escalates to a human supervisor on unexpected conditions.

**Domain-specific authority operations.**

- `IntentRequest::ExecuteMotion` — agent commands joint angles/velocities (subject to safety envelopes)
- `IntentRequest::ChangeOperatingMode` — agent transitions between operating modes (typically requires escalation)
- `IntentRequest::ReportObservation` — agent records sensor data
- `IntentRequest::EmergencyStop` — agent triggers safe stop (always permitted, no admission gate)

**Domain-specific policy.** Joint position/velocity/force envelopes, allowed operating modes, allowed workspace volumes, mandatory human supervision conditions, safety reflex triggers.

R-1 (Domain Separation) takes on physical meaning — intelligence runs on a separate compute board from the safety-critical authority that commands the motor controller. R-12 (Out-of-Band Escalation) is a literal physical button.

### 5.5 What does NOT make a new RAXIS

Several adjacent things might be tempting to call "RAXIS for X" but are not:

- **A new agent framework that adds a logging library.** Logging is not R-7 (Cryptographic Audit Chain). Mutable logs do not provide the property.
- **A wrapper around an existing agent framework that adds a policy file.** If the policy file is not signed (R-3), if intelligence runs in the same process (R-1), if the policy can be edited at runtime by intelligence (R-3 + R-7), it is not RAXIS.
- **A sandboxed agent runtime.** Sandboxing addresses R-1 partially but says nothing about R-3 through R-12. A sandboxed agent with an unsigned config file and stdout-style logging is not RAXIS.
- **A monitoring dashboard for an agent.** Observability is not enforcement. A dashboard that *records* all the actions an agent took without *gating* them does not satisfy R-2, R-3, R-5, or R-6.

The bar for "this is RAXIS" is high by design. The whole point of having a paradigm is to mean something specific.

---

## 6. Mapping — Paradigm Invariants to Reference Implementation Invariants

The current reference implementation enforces the R-invariants through specific mechanisms documented in [`specs/invariants.md`](invariants.md). This table maps each R-invariant to the implementation invariants that enforce it.

| R-Invariant | Enforced by INV-* in current reference implementation |
|---|---|
| **R-1 Domain Separation** | `INV-VM-CAP-01` (planner runs in microVM); `INV-VM-CAP-02` (no virtio-net); `INV-VM-CAP-03` (VSock-only IPC); `INV-VM-CAP-04` (credential isolation); `INV-VM-CAP-05` (CID drift detection) |
| **R-2 Mediated I/O** | `INV-02A` (no provider creds in planner); `INV-02B` (no direct egress); `INV-CRED-KERNEL-01` (closed credential-reading set); kernel-mediated FetchRequest, EgressRequest, InferenceRequest pipelines |
| **R-3 Signed Capability Declaration** | `INV-CERT-01` (operator certs mandatory); policy artifact signing; plan signing; signature verification on every artifact load |
| **R-4 Authority Derivation Hierarchy** | `INV-POLICY-01` (plans cannot exceed policy); `approve_plan` shift-left validation; `INV-DELEGATION` (sub-session scope ⊆ parent scope) |
| **R-5 Bounded Capabilities** | `INV-04` (financial ceiling); token limits in plan; budget lanes with `admission_units`; host capacity caps (`INV-CAPACITY-01`–`INV-CAPACITY-06`); `INV-PROVIDER-05` (worst-case reservation) |
| **R-6 Fail-Closed Default** | `INV-01` (planner cannot act without session token); `INV-CAPACITY-04` (audit write impossible halts kernel); fail-closed admission throughout `kernel/src/handlers/` |
| **R-7 Cryptographic Audit Chain** | `INV-04` (hash chain integrity); V3's `INV-AUDIT-RETENTION-03` (Merkle tree); `INV-AUDIT-RETENTION-05` (O(log N) inclusion proofs); `INV-AUDIT-RETENTION-06` (chain-truncation attestation for redaction) |
| **R-8 Auditable Decisions** | `INV-05` (kernel decisions reproducible from stored records); `INV-PROVIDER-08` (per-attempt audit immediacy); audit replay via `raxis admin audit-replay` |
| **R-9 Attributable Intent** | `INV-01` (session token required); session token is 256-bit CSPRNG bound to session identity; envelope nonce + sequence number prevents replay |
| **R-10 Opaque Rejection** | `INV-08` (rejection reason codes do not reveal which rule fired); planner-API spec defines closed enumeration of `PlannerErrorCode` values |
| **R-11 Mediated Coordination** | Kernel-mediated `git bundle` IPC between Orchestrator and Executors; no direct agent VSock channels; `KernelPush` notifications for cross-session coordination |
| **R-12 Out-of-Band Escalation** | `INV-06` (escalation requires signed approval token); escalation requests over operator UDS, signed with operator Ed25519 key intelligence does not hold |

Each row demonstrates that the current implementation's enforcement of the R-invariant is structural — it is not a single check but a constellation of related mechanisms throughout the codebase. The mapping is also useful in the inverse direction: when adding or modifying an INV-* invariant, the change is justifiable iff it strengthens (or preserves) the enforcement of the corresponding R-invariant.

---

## 7. Acknowledged Paradigm Limitations

The R-invariants as stated represent the paradigm's current formalization. They have known limitations, documented honestly here so that future work can address them rather than pretending they don't exist.

### 7.1 No model identity

R-9 (Attributable Intent) requires intelligence identity verifiable by authority. The current paradigm formalization satisfies this through session-level identity (session token bound to a known principal). It does not require identity at the *model* level — two different LLMs could in principle hold the same session token. A stronger paradigm would require the model itself to attest to its identity (model hash, provider attestation, runtime hash). This is the subject of ongoing research in trusted-AI infrastructure.

### 7.2 No hardware root of trust

R-1 (Domain Separation) requires a strong isolation primitive but does not currently require that primitive be hardware-attested. A compromised host operating system could potentially undermine the isolation. A stronger paradigm would require the authority itself to be attested by a hardware root of trust (TPM, SGX/TDX, Apple Secure Enclave, Arm CCA). This is V4+ territory.

### 7.3 Retrospective verification

The current paradigm is formulated around verifying actions after they occur (commit, then admit). A stronger paradigm would be prospective: intelligence attests to its planned action before execution, receives a pre-authorization, executes under that pre-authorization, and provides completion evidence. The current formulation does not preclude prospective verification (an implementation could add it) but does not require it.

### 7.4 Syntactic, not semantic, verification

R-2 through R-5 verify the *syntactic scope* of intelligence's actions (which paths were touched, which providers were called, which budgets were consumed). They do not verify *semantic effect* — a clever agent could touch only allowed paths while inserting a backdoor that activates based on data not visible in the diff. A stronger paradigm would require formal verification or semantic analysis of the action's effect relative to its claimed intent. This is open research.

### 7.5 No standardized interoperability schema

R-7 requires audit logs verifiable by an independent verifier with public keys, but does not yet require those audit logs to follow a *standardized schema* (e.g., W3C Verifiable Credentials, IETF RATS, or DICE) that would let one RAXIS implementation's audit log be verified by tools written for another. Adding this requirement is the path to true policy and audit portability between RAXIS-Verified implementations and is the subject of active design work.

### 7.6 Authority is itself a trusted third party

In the strongest formulation of the paradigm, the attestation exchange would be a protocol that does not require either party to trust a specific implementation of authority. Authority's correctness would be verifiable by any party holding the public keys and the audit log, even without the authority being present or honest. The current paradigm requires authority itself to be honest — a malicious authority could omit logging certain decisions. Closing this gap likely requires combining R-7 with hardware attestation (R-1 strengthened) and perhaps decentralized witnessing.

These limitations are not violations of the paradigm as stated; they are areas where the paradigm itself can be strengthened in future revisions. They are documented here so that implementers, auditors, and prospects can understand the current ceiling of what RAXIS guarantees.

---

## 8. Document Maintenance

This document is the canonical source for what RAXIS *is*. Changes to it have outsize impact:

- **Adding an R-invariant** changes the bar for every RAXIS implementation. New R-invariants require structural justification — what failure mode does omitting them allow?
- **Removing an R-invariant** weakens the paradigm. Removal requires demonstrating that the property is either redundant (derivable from others) or not essential to the paradigm's purpose.
- **Changing an R-invariant's statement** changes the conformance test suite, the qualification for verifiers, and potentially the certification status of every existing implementation. Such changes increment the paradigm version (e.g., RAXIS 1.0 → RAXIS 2.0) and are NOT made silently.

The current paradigm version is **RAXIS 1.0**. Future paradigm revisions will be tracked here with explicit migration guidance for existing implementations.

The relationship between this document and the implementation invariants in [`specs/invariants.md`](invariants.md) is one-way: the implementation invariants exist to enforce the R-invariants in this document, not vice versa. When an INV-* is added or modified, §6 of this document MUST be updated to reflect any change in the R→INV mapping.
