# RAXIS — Positioning and Framing

> **Purpose.** This document is the canonical source for how RAXIS positions itself externally — what it is, what it is not, why we use the framings we use, why we reject the framings we reject, and how it compares to adjacent categories. It exists alongside the formal paradigm spec ([`specs/paradigm.md`](specs/paradigm.md)) and the reference implementation README ([`README.md`](README.md)).
> **Audience.** Prospects evaluating RAXIS, contributors writing external materials, anyone explaining RAXIS to a third party.
> **Authority rule.** When external content (website, marketing, talks, social posts) needs a positioning claim, this document wins. When it needs a structural claim, [`specs/paradigm.md`](specs/paradigm.md) wins.

---

## 1. The One-Line Positioning

> **RAXIS is the structural enforcement layer between intelligence and authority. The current implementation is the reference RAXIS for autonomous software engineering.**

That sentence does three jobs:

1. Names the category — *structural enforcement layer*, not framework, not sandbox, not OS metaphor.
2. Names the boundary — *between intelligence and authority*, signaling the asymmetric trust premise.
3. Names the implementation status — *reference implementation for autonomous software engineering*, signaling there is a paradigm above and other domains alongside.

If you remember nothing else from this document, remember that sentence.

---

## 2. The Two Layers

Every external description should preserve the distinction between **the paradigm** and **the reference implementation**. Conflating them is the most common positioning error.

### 2.1 The paradigm

**RAXIS — Runtime Attestation eXchange for Intelligent Systems.** Twelve structural invariants ([`specs/paradigm.md`](specs/paradigm.md) §3) that any implementation must satisfy to claim RAXIS conformance. The paradigm is domain-agnostic: it can apply to autonomous software engineering, autonomous customer support, autonomous trading, autonomous robotics, or any other autonomous system where intelligence acts on the world with consequences.

The paradigm makes one foundational claim: **the component that decides what to do must not be the same component that decides whether it is allowed.** Every R-invariant elaborates this claim into a structural requirement.

### 2.2 The reference implementation

**The Rust workspace in this repository** is one realization of the paradigm, applied to the domain of autonomous software engineering. It is the *reference implementation* in the sense that:

- It is the first complete RAXIS implementation
- It is the proving ground for the paradigm — every R-invariant has a concrete enforcement mechanism in this codebase
- Other implementations (in other languages, for other domains) can be measured against this one for correctness and completeness
- It is open source under the SSPL

Other reference implementations may exist in the future — for trading, for support, for robotics. They will be different codebases satisfying the same paradigm.

### 2.3 Why the distinction matters

When prospects ask "is RAXIS [X]?" the answer depends on whether they're asking about the paradigm or the implementation:

| Question | Paradigm answer | Implementation answer |
|---|---|---|
| Is RAXIS Rust? | No. Implementation language is unconstrained. | Yes, this implementation is Rust. |
| Does RAXIS use microVMs? | No. Any sufficiently strong isolation primitive satisfies R-1. | Yes, this implementation uses Firecracker / Apple Virtualization.framework. |
| Does RAXIS use git? | No. The paradigm doesn't know what git is. | Yes, this implementation's domain is software engineering, so it uses git. |
| Is RAXIS for coding agents? | No. The paradigm applies to any autonomous-action domain. | Yes, this implementation is for coding agents. |
| Does RAXIS run on Windows? | The paradigm is OS-agnostic. | Not currently — this implementation requires Linux or macOS. |

Conflating "this implementation does X" with "RAXIS requires X" gives prospects a wrong mental model and makes it harder to bring new domain implementations into the RAXIS family.

---

## 3. Working Taglines

Use these. They are technically honest, set the right expectations, and don't pattern-match RAXIS into the wrong category.

### 3.1 Primary tagline

> **The OS kernel for AI agents — every action authorized, every action audited.**

Two layers of message: an architectural analogy that is actually correct (intents are syscalls, the kernel is the authority gate, intelligence is userspace), plus the security claim ("authorized + audited") in plain English. The OS-kernel metaphor maps cleanly to the codebase (the literal `raxis-kernel` daemon is named for it) and to the paradigm (R-1 + R-2 + R-7 in OS-systems vocabulary).

### 3.2 Acceptable secondary taglines

- **"The trust boundary for AI agents."** Drops the technical analogy, leads with the security framing. Recognized vocabulary in security and compliance circles. Good for non-technical audiences.
- **"Audit-grade execution layer for AI agents."** Emphasizes both audit and execution mediation. Good for compliance and regulated-industry audiences.
- **"Capability-based runtime for AI agents."** Precise, signals security thinking. Good for technical security audiences who recognize "capability-based" as a category (seL4, Capsicum, EROS).
- **"Air traffic control for AI agents."** Non-technical and evocative — every action requires authorization from a controller, every action is recorded. Slightly off (ATC implies real-time human controllers; RAXIS is policy-driven with human escalation only when needed) but lands well for non-technical audiences.

### 3.3 Taglines we explicitly reject

See §4 for the full reasoning. The short list:

- ❌ **"Auditable Docker for agents"** — undersells audit by 95%, sets permissive-by-default expectations that break on first encounter with policy signing
- ❌ **"Docker for AI agents"** — pattern-matches RAXIS into a category (lightweight container runtime for LLM agents) that already has six YC startups and that is the *opposite* of where RAXIS sits in the stack
- ❌ **"Kubernetes for AI agents"** — slightly less wrong than Docker, but inherits Kubernetes' "operationally heavy" baggage and still misses the security-by-default story
- ❌ **"Agent Operating System"** — taken by AIOS (academic project, see §6.5); collision creates confusion and inherits AIOS's permissive-by-default expectations
- ❌ **"AI safety platform"** — too vague; "safety" is contested vocabulary that ranges from alignment to RLHF to existential risk; says nothing about *how* RAXIS provides safety
- ❌ **"AI governance platform"** — closer, but "governance" connotes policy management at the organizational level (data retention, model approval workflows), not runtime enforcement on every action
- ❌ **"Sandbox for AI agents"** — sandboxing addresses one R-invariant (domain separation) but says nothing about the other eleven; positions RAXIS as a containment primitive when it is an authority primitive

---

## 4. Why "Docker for Agents" Was Rejected

This was a serious internal proposal. We rejected it after analysis. Documenting the analysis prevents it from being re-proposed every six months and gives external contributors the rationale.

### 4.1 The four reasons

**1. "Auditable Docker" reads as "Docker with the audit log turned on."**

Docker's audit story is "the daemon writes events to a log file you can grep." RAXIS's audit story is a cryptographically chained, Merkle-tree-verifiable, signed-attestation, optional-Sigstore-anchored, GDPR-redactable-via-chain-truncation forensic record. The tagline sells the strongest part of the product at maybe 5% of its actual value. A CISO hearing "auditable Docker" thinks "ELK stack + Falco" and moves on — the entire reason they would care about RAXIS is the cryptographic non-repudiation guarantee, and that does not fit in the Docker mental model.

**2. Docker is permissive-by-default. RAXIS is fail-closed-by-default. This is the biggest misalignment.**

Docker says: "here is a sandbox, the container can do whatever it wants inside, the host is somewhat protected." RAXIS says: "the agent can do *nothing* except what `policy.toml` and `plan.toml` jointly authorize, with cryptographic signatures, with admission gates on every intent." Prospects arriving with the Docker mental model will be confused or annoyed by plan signing, the approval workflow, the credential proxy, the egress allowlist, the policy authority hierarchy. They expected "run the agent and let it cook." They got "every action requires pre-authorization." Marketing should *set* that expectation, not paper over it.

**3. The Docker mental model carries over for ~2 concepts and actively misleads on a dozen.**

| Maps cleanly | Maps badly or doesn't exist in Docker |
|---|---|
| Daemon + CLI | Capability-based authorization |
| Image registry ≈ artifact store | Cryptographic policy/plan signing |
| | Credential proxy (`INV-VM-CAP-04`: credential value never enters the VM) |
| | Per-intent admission pipeline |
| | Hierarchical agent orchestration with kernel-mediated IPC |
| | Budget lanes / cost ceilings |
| | Two-tier policy + plan authority hierarchy |
| | Escalation FSM with operator approval gates |
| | Provider failure handling + circuit breakers |
| | Append-only Merkle-tree audit log |

**4. "Docker for X" is exhausted as a category and already taken in our space.**

There are at least six current YC companies whose actual product is "we put an LLM agent inside a Docker container with some MCP tooling and call it agent infrastructure." That is the category prospects will pattern-match RAXIS to — which is the *opposite* of where we want to be positioned. RAXIS is the control plane those products are missing; calling it "Docker for agents" puts it in the substrate-runtime bucket, not the security/governance bucket.

### 4.2 Where Docker comparison still works

Docker analogies are productive *internally* in technical comparison sections. Sentences like:

> "Unlike container runtimes, RAXIS mediates every intent the agent submits rather than just isolating its process."

are useful. They give the comparison without inheriting the wrong mental model as positioning. The rule of thumb: Docker as a *contrast* is fine; Docker as a *category claim* is not.

---

## 5. Where RAXIS Sits in the Stack

The single most useful diagram for explaining RAXIS to a technical audience.

```text
┌──────────────────────────────────────────────────────────────────┐
│  Agent Frameworks                                                │
│  LangChain · AutoGen · MetaGPT · OpenAI Agents SDK ·             │
│  AIOS (academic) · CrewAI · Claude Agent SDK                     │
│  ─────────────────────────────────────────────────────────────   │
│  Concern: "How do I build an agent that can do work?"            │
│  Provides: orchestration, memory, prompt management, tool use    │
└──────────────────────────────────────────────────────────────────┘
                              │
                              │ submits work to
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  RAXIS                                                           │
│  ─────────────────────────────────────────────────────────────   │
│  Concern: "How do I run that agent in production with            │
│            cryptographic accountability?"                        │
│  Provides: policy authority, capability gating, audit chain,     │
│            credential isolation, budget enforcement, escalation  │
└──────────────────────────────────────────────────────────────────┘
                              │
                              │ enforces policy on
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  Isolation & Runtime Substrates                                  │
│  Firecracker · Apple Virtualization.framework · gVisor ·         │
│  Docker · LXC · WebAssembly runtimes                             │
│  ─────────────────────────────────────────────────────────────   │
│  Concern: "How do I isolate untrusted code?"                     │
│  Provides: process/memory/syscall isolation                      │
└──────────────────────────────────────────────────────────────────┘
                              │
                              │ runs on
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  Operating System & Hardware                                     │
└──────────────────────────────────────────────────────────────────┘
```

**Reading the diagram:** RAXIS is the layer between the agent framework (which knows how to *build* an agent) and the isolation runtime (which knows how to *contain* a process). Neither layer alone provides what RAXIS provides:

- Frameworks orchestrate intelligence; they do not enforce authority.
- Isolation runtimes contain processes; they do not gate per-action authorization or produce non-repudiable audit.

RAXIS uses the isolation runtime as a primitive (per R-1) and is consumed by frameworks (or by the planner directly speaking the RAXIS protocol). It does not replace either. It is the missing layer.

---

## 6. Comparison to Adjacent Categories

The detailed category-by-category comparison. Use this to answer "how is RAXIS different from [X]?"

### 6.1 Alignment / Safety Training (RLHF, Constitutional AI, etc.)

**What they do.** Train the model to want to do the right thing. Adjust weights so harmful outputs are less likely.

**Where they end.** At the model boundary. Once the model emits a token, alignment has done all it can.

**How RAXIS differs.** RAXIS operates at the action boundary, not the token boundary. It does not care whether the model wants to do the right thing; it requires that the model's output be authorized as an action before any side effect occurs. RAXIS and alignment are complementary — you want both.

**Pitch line.** "Alignment governs the model's intent. RAXIS governs the model's actions. Use both."

### 6.2 Agent Frameworks (LangChain, AutoGen, MetaGPT, CrewAI, OpenAI Agents SDK, Claude Agent SDK)

**What they do.** Provide abstractions for building agent loops: memory, tool use, multi-step planning, multi-agent orchestration, prompt management.

**Where they end.** Frameworks orchestrate the agent's execution. They do not enforce that the agent's actions are authorized, do not produce a tamper-evident record, do not isolate credentials, do not bound costs structurally.

**How RAXIS differs.** RAXIS subordinates the agent (whatever framework it is built with) to a separate authority that enforces policy on every action. A framework agent could run inside a RAXIS planner microVM; the framework provides the *intelligence* layer, RAXIS provides the *authority* layer.

**Pitch line.** "LangChain helps you build an agent. RAXIS lets you deploy it without losing sleep."

### 6.3 Sandbox Runtimes (Docker, gVisor, Firecracker, Wasm, container-use, etc.)

**What they do.** Isolate untrusted code from the host. Limit syscalls, memory, network, filesystem.

**Where they end.** At the process boundary. Inside the sandbox, the agent is permissive — it can do whatever the sandbox allows, with no per-action authorization, no audit chain, no policy gating, no cost enforcement.

**How RAXIS differs.** RAXIS uses sandboxing as a primitive (R-1 requires hypervisor-grade isolation) but adds eleven more invariants on top. Sandboxing alone satisfies maybe 1 of 12 R-invariants.

**Pitch line.** "Sandboxes contain the process. RAXIS contains the *authority surface*."

### 6.4 Policy Engines (OPA / Open Policy Agent, AWS Cedar, Casbin)

**What they do.** Evaluate authorization rules. Given an input (subject + action + resource), return allow/deny.

**Where they end.** As a library or sidecar. Policy engines do not run the application, do not produce audit logs of admission decisions in a non-repudiable form, do not isolate the application from credentials, do not enforce that the application *uses* the policy engine for every action.

**How RAXIS differs.** RAXIS embeds a policy-engine-equivalent inside its kernel as just one of twelve invariants. RAXIS adds the structural enforcement that the policy is consulted for every action (R-2), that the policy is cryptographically signed (R-3), that the application cannot bypass it (R-1), and that the decisions are auditable (R-7, R-8). A policy engine alone is a library; RAXIS is the runtime that makes the library mandatory.

**Pitch line.** "OPA evaluates rules. RAXIS makes the rules mandatory and the evaluations non-repudiable."

### 6.5 Agent Operating Systems (AIOS — agiresearch/AIOS)

This deserves the deepest comparison because both projects use the "OS for agents" framing.

**What AIOS is.** An academic research framework (COLM 2025, NAACL 2025) that "embeds large language model (LLM) into the operating system and facilitates the development and deployment of LLM-based AI Agents." It addresses developer-experience problems: scheduling, context switch, memory management, storage management, tool management, agent SDK management. It supports many agent frameworks (AutoGen, MetaGPT, Open Interpreter, etc.) as a portability layer and many LLM providers (Anthropic, OpenAI, Deepseek, Gemini, Groq, HuggingFace, ollama, vLLM, Novita).

**Where AIOS uses the OS metaphor.** As a research framing for *resource management* — like an OS scheduler manages CPU, an AIOS scheduler manages LLM time and context windows. The "syscall" is a request for a managed resource. The agent and the kernel run in the same process; the boundary is a function call. There is no enforcement separation, because that is not the problem AIOS is solving.

**Where RAXIS uses the OS metaphor.** As a *structural enforcement boundary*. The planner is literal userspace (in a separate address space, in a separate hypervisor-isolated VM, with no shared memory). The kernel is literal kernelspace (the only thing with credentials, with git push authority, with policy validation logic). The intent is a literal syscall (passes through an admission pipeline that can deny it; cannot bypass via shared state because there is no shared state). The capability model maps to OS capabilities (POSIX, Linux capabilities, capability-based microkernels like seL4).

**Side-by-side.**

| Dimension | AIOS | RAXIS |
|---|---|---|
| Goal | Make agent *development* easier across frameworks | Make agent *deployment* safer in production |
| Threat model | Implicit — agent is benign developer code | Explicit — agent is untrusted, possibly compromised |
| Authority default | Permissive — agent decides; kernel routes/schedules | Fail-closed — agent can do *nothing* except what signed policy + plan authorize |
| Authorization | None at runtime; framework provides tools | Cryptographically signed two-tier hierarchy; admission checks on every intent |
| Credentials | API keys in `config.yaml` plaintext, in agent process | Credential value never enters the VM; per-session localhost proxies |
| Isolation | Single Python process; "VM" only for computer-use GUI sandbox | Every agent in a microVM; zero shared address space; VSock-only IPC |
| Audit | Standard logs (`uvicorn.log`) | Cryptographically chained append-only log; Merkle tree (V3); signed attestations; non-repudiation guarantee |
| Cost ceiling | Not enforced | Budget lanes per provider/model; worst-case reservation; billing on failed attempts |
| Posture | Multi-framework portability layer | Opinionated protocol; specific intent shapes |
| Audience | Agent developers, researchers, ecosystem builders | Operators/SREs deploying autonomous agents in production with audit/compliance requirements |
| Operational shape | `nohup uvicorn ... &`; YAML config | systemd/launchd daemonization; signed TOML artifacts; `raxis doctor` preflight |

**Could they compose?** In principle: a RAXIS planner microVM could load AIOS as its agent runtime. AIOS would provide framework abstractions; RAXIS would provide the security and audit boundary around them. In practice this would have friction (AIOS expects API keys in its config; RAXIS forbids credential value from entering the VM; AIOS's tool manager would have to route through RAXIS's intent admission). The simpler answer for most use cases: AIOS for development and research; RAXIS for production deployment where audit, compliance, or untrusted-input concerns dominate.

**Pitch line.** "AIOS asks 'how do I help my agent get work done?' RAXIS asks 'how do I prove what my agent did and prevent it from doing what it shouldn't?' Different problems, different layers."

### 6.6 Model Context Protocol (MCP)

**What MCP is.** An Anthropic-published protocol for connecting LLMs to tools and data sources. Standardizes the wire format between an LLM client and an MCP server providing tools, resources, prompts.

**Where MCP ends.** As a protocol for tool discovery and tool invocation. MCP does not enforce that tool invocations are authorized, does not produce non-repudiable audit, does not isolate credentials structurally, does not bound costs. Each MCP server can implement its own authorization scheme, but there is no common enforcement layer.

**How RAXIS differs.** RAXIS is orthogonal to MCP at the protocol level — an MCP server could be exposed to RAXIS-managed agents through `EgressRequest` or a future MCP-aware intent kind. The enforcement that the agent only invokes MCP servers in its plan-declared allowlist, that every invocation is audited, that credentials for the MCP server stay in the kernel — those are RAXIS concerns, not MCP concerns.

**Pitch line.** "MCP standardizes how an agent talks to a tool. RAXIS enforces which tools an agent is allowed to talk to and records every conversation."

### 6.7 Coding Agent Products (Cursor, Claude Code, Windsurf, Codex, Devin, etc.)

**What they are.** End-user coding agent products that pair an LLM with editor integration, project context, tool use, and a UX for accepting/rejecting suggestions.

**Where they end.** As products. They are not protocols, not infrastructure, not policy enforcement layers. They are the consumer surface that an organization adopts to get coding-agent productivity.

**How RAXIS differs.** RAXIS is not a coding agent product. It is the substrate a coding agent product (or an internal one) could be deployed on top of when the deployment context demands cryptographic accountability — regulated industries, sensitive codebases, multi-tenant environments, contractor/vendor isolation. Cursor or Claude Code could in principle target RAXIS as a deployment mode for their enterprise tier (this is a hypothetical; no such integration exists today).

**Pitch line.** "Cursor is the agent your engineers use. RAXIS is the substrate you deploy that agent on when the cost of being wrong is real."

### 6.8 Confidential Computing (Intel TDX, AMD SEV-SNP, Apple Secure Enclave, Azure Confidential Containers)

**What they are.** Hardware-backed isolation primitives that protect the confidentiality and integrity of workloads from the host operator.

**Where they end.** At the isolation boundary. Confidential computing protects the *workload* from the host; it does not impose policy on what the workload does, does not produce non-repudiable audit, does not isolate credentials within the workload, does not bound costs.

**How RAXIS differs.** Confidential computing is a stronger isolation primitive that RAXIS could *adopt* in a future paradigm revision (mentioned in [`specs/paradigm.md`](specs/paradigm.md) §7.2). The current RAXIS reference implementation uses microVMs (Firecracker / Apple Virtualization.framework), which is hypervisor-grade but not hardware-attested. A RAXIS implementation built on TDX or SEV-SNP would satisfy R-1 more strongly while still requiring all eleven other R-invariants.

**Pitch line.** "Confidential computing protects the workload from the host. RAXIS protects the world from the workload."

---

## 7. Talking Points and FAQ

Common questions with prepared answers.

### 7.1 "Is this RAXIS-Verified?"

The current implementation is **Tier 1 — RAXIS-Aligned** (designed to satisfy all twelve R-invariants, with documented enforcement mechanisms). It is **partially Tier 2 — Tested** (extensive INV-* test coverage in this codebase, but the canonical paradigm conformance test suite is V3 GA scope). It is **not yet Tier 3 — Verified** (independent third-party audit). See [`specs/paradigm.md`](specs/paradigm.md) §4 for the full conformance contract.

### 7.2 "Why is the audit log a big deal? My logs work fine."

Because most logs are mutable. A compromised system rewrites them. RAXIS's audit log is cryptographically chained — any modification is detectable by an independent verifier holding only the log and the operator's public key. That property is the difference between "we have records" and "we have evidence." See R-7 in [`specs/paradigm.md`](specs/paradigm.md) §3.

### 7.3 "Why can't the agent have the API key directly?"

Because then the agent IS the cost ceiling, the rate limiter, the egress allowlist, and the budget enforcer. A compromised agent burns the credit card. R-2 (Mediated I/O) requires that credentials live in authority and are accessed via authority's mediation. The cost enforcement, rate limiting, and audit follow automatically. See `INV-VM-CAP-04` for the implementation.

### 7.4 "Doesn't this slow the agent down?"

For inference: negligibly (microseconds of admission overhead per call against a 3-10 second LLM call). For tool calls: imperceptibly (the IPC + admission path is sub-millisecond). For multi-agent coordination: yes, a small overhead from kernel-mediated coordination vs. direct IPC, but the alternative (direct IPC) violates R-11 and is structurally outside the paradigm. RAXIS's design cost is optimization complexity, not runtime latency.

### 7.5 "What about open-source models running locally? Do I still need RAXIS?"

Yes, more than ever. Local open-source models have weaker safety training, can be modified by the operator to remove safeguards, and run with even less cost-ceiling discipline (no provider bill to surprise you, just disk and electricity until something else fails). RAXIS's enforcement is independent of the model's source — it bounds *actions*, not *thoughts*.

### 7.6 "Is RAXIS open source?"

The reference implementation is licensed SSPL (see `LICENSE-SSPL.txt`). The paradigm spec ([`specs/paradigm.md`](specs/paradigm.md)) is open and intended to support multiple implementations. The conformance test suite (when it ships) will be open source.

### 7.7 "Does RAXIS work with my agent framework?"

The current reference implementation has its own planner protocol — it does not adapt arbitrary frameworks today. The path to using existing frameworks is either (a) port them to speak the RAXIS planner protocol or (b) wait for adapter layers. The paradigm itself is framework-agnostic; the implementation gap is concrete work that hasn't shipped.

### 7.8 "What's the relationship between RAXIS and Aegis?"

[Aegis](https://tryaegis.io/) is the parent company building EDR (endpoint detection and response) for AI workloads — observability and security for ML training/inference clusters. RAXIS is a separate paradigm developed by the same author addressing a different problem (autonomous agent enforcement, not workload monitoring). They share design DNA (separation of concerns, structural enforcement) but are independent products. See [`perspectives/naming-rationale.md`](perspectives/naming-rationale.md) for the longer history.

### 7.9 "Is this just for big companies?"

The paradigm is for any deployment where autonomous agent action has consequences the operator must defend later — to a customer, a regulator, a court, or themselves. That includes solo developers running an agent against their own production codebase and a Fortune 500 deploying a fleet of agents to handle customer support. The current reference implementation is single-host (per V2's `system-requirements.md`); operationally it scales from a developer laptop to a dedicated server.

### 7.10 "What if I just want a coding agent?"

Use Cursor, Claude Code, Windsurf, Codex, or one of many other excellent products. RAXIS is for deployment contexts where those products are not enough — either because the agent needs to operate without per-action human review, or because the deployment context (regulated industry, sensitive codebase, contractor/vendor isolation) demands cryptographic accountability that none of those products provide.

---

## 8. The Twelve Paradigm Invariants — One-Line Summary

For full statements with rationale and verification methods, see [`specs/paradigm.md`](specs/paradigm.md) §3.

**Structural separation:**

- **R-1 Domain Separation** — Intelligence and authority in distinct execution domains.
- **R-2 Mediated I/O** — All credential, network, storage, peer access mediated by authority.

**Authority model:**

- **R-3 Signed Capability Declaration** — Every capability declared in cryptographically signed policy.
- **R-4 Authority Derivation Hierarchy** — Sub-artifacts may only narrow parent authority.
- **R-5 Bounded Capabilities** — Every capability carries explicit numerical bounds.
- **R-6 Fail-Closed Default** — Ambiguity, errors, missing policy resolve to deny.

**Accountability:**

- **R-7 Cryptographic Audit Chain** — Audit modifications detectable by independent verifier.
- **R-8 Auditable Decisions** — Decisions reproducible from recorded inputs.
- **R-9 Attributable Intent** — Every intent traces to a verified intelligence identity.
- **R-10 Opaque Rejection** — Agent-facing rejections reveal no specific rule.

**Coordination and recovery:**

- **R-11 Mediated Coordination** — Multi-agent communication passes through authority.
- **R-12 Out-of-Band Escalation** — Authority widening requires human approval via a channel intelligence cannot reach.

A system claiming to be RAXIS satisfies all twelve. Anything less is not RAXIS.

---

## 9. RAXIS-Verified — One-Page Summary

The full conformance contract is in [`specs/paradigm.md`](specs/paradigm.md) §4. Three tiers:

| Tier | Name | Evidence | Use case |
|---|---|---|---|
| **Tier 1** | **RAXIS-Aligned** | Self-attested conformance statement mapping each R-invariant to its enforcement mechanism | Early-stage implementations, research prototypes, new domain ports |
| **Tier 2** | **RAXIS-Tested** | Tier 1 + canonical conformance test suite passes | Production-bound implementations seeking engineered conformance |
| **Tier 3** | **RAXIS-Verified** | Tier 2 + independent third-party audit by a qualified verifier; annual re-audit | Regulated deployments, customer-facing claims, contractual commitments |

The unqualified term "RAXIS-Verified" refers to Tier 3 only. Lower tiers must be qualified ("RAXIS-Aligned" or "RAXIS-Tested").

Verifiers must be independent (no financial relationship beyond the audit fee), publish their methodology publicly, produce reproducible findings, disclose conflicts, and themselves be certified by the RAXIS specification body. This mirrors FIPS 140 and Common Criteria evaluation models.

The current reference implementation is **Tier 1 with partial Tier 2 work**. Tier 3 is not currently claimed.

---

## 10. Document Maintenance

This document is the authoritative source for RAXIS positioning. When external content (website copy, marketing materials, talks, social posts, sales decks) needs a positioning claim, this document is the source of truth. Disagreements between external content and this document resolve in favor of this document.

When the positioning evolves:

1. Update this document first.
2. Then update [`README.md`](README.md) to reflect any change in the lead framing.
3. Then update external content (website, etc.) to match.

When new categories emerge that prospects might confuse RAXIS with (a new agent framework category, a new sandbox technology, a new policy engine), add a comparison subsection in §6 with the same structure (what they do, where they end, how RAXIS differs, pitch line).

The paradigm spec ([`specs/paradigm.md`](specs/paradigm.md)) is the source of truth for *what RAXIS is*. This document is the source of truth for *how to talk about it*.
