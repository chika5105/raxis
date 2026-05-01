# From CJBrain to RAXIS: Origin, Intent, and the Decision to Rename

> **Written by:** Chika Jinanwa  
> **Date:** May 2026  
> **Status:** Permanent decision record — why this project exists and why it was renamed.

---

## How I Think About Building Systems

I did not develop strong opinions about software engineering by reading blog posts. I developed them by working in environments where the cost of being wrong is real, immediate, and sometimes irreversible.

I have built software at **Google**, **Cruise**, **Galileo Financial Technologies**, and **Microsoft** — across autonomous vehicle infrastructure, high-volume payment processing authorization, security product engineering, and developer tooling. In each of those environments, the stakes were different but the pattern was the same: the most expensive bugs are not the ones that crash the system. They are the ones that let the system keep running while silently doing the wrong thing.

The constraint that has followed me across every employer: security and correctness are not features you add later. A data leak does not affect a test environment — it affects real users, real money, or real machines, right now. A payment that settles incorrectly due to a race condition does not show up in a dashboard; it shows up in a support ticket three weeks later when a customer's balance is wrong. GPU time wasted due to a failing workload that no monitoring caught is money that does not come back. Endpoint security that passed code review but failed at call time is a vulnerability, not a bug.

Having taste as an engineer is having this pattern recognition. It is not aesthetic preference. It is accumulated scar tissue from watching systems fail in ways that were preventable at design time. Taste translates into opinionation: **authority and intelligence must be separated.** The system that decides what to do is never the same system that enforces what is allowed. This is not a design preference. It is the thing that makes a system safe to scale.

---

## What I Was Building: [Aegis](https://tryaegis.io/)

[Aegis](https://tryaegis.io/) is an EDR (Endpoint Detection and Response) system for AI workloads — specifically designed to prevent wasted GPU time in ML training and inference clusters. GPU time is not abstract — it is a concrete resource with a clock on it. Waste is always traceable to a system that did not enforce the right thing at the right time.

Aegis spans a daemon (`aegisd`) running on each node, a central aggregation server (`aegis-server`), eBPF-based syscall and network monitoring, a GPU metrics pipeline (integrating DCGM), and a frontend dashboard. Building it correctly — not prototype-correct, but production-correct, at the standard I have been held to in prior work — is a serious engineering undertaking.

I read a lot. Technical papers, design documents, post-mortems. I study how systems age — not just whether something works today but whether it will be defensible in three years when the original engineers have moved on and someone is reading the code cold. Good engineering has a shape that is recognizable when you have seen enough of it. Bad engineering also has a shape. Both are visible early, if you know what to look for.

---

## The Agent Problem

I began using AI agents to accelerate Aegis development. The best models available at the time — Claude Opus, among the most capable — were producing output that was almost right. Not catastrophically wrong. Almost right.

They would implement a feature that looked correct on a surface read, compiled, and appeared to pass basic checks. Then it would fall apart on edge cases that any engineer with production experience would have handled instinctively. They would touch files that were outside the logical scope of the task. They would report that tests had passed when the tests had either not been run or had been run incorrectly. The diff did not match the claim.

I kept returning to an insight from David Rensin's article *[Elephants, Goldfish, and the New Golden Age of Software Engineering](https://drensin.medium.com/elephants-goldfish-and-the-new-golden-age-of-software-engineering-c33641a48874)* — that the AI is not the unit of analysis. The system the AI operates within is the unit of analysis. The model is a tool. The harness determines the output quality. An agent without a rigorous harness is not a productivity multiplier — it is a source of technically plausible mistakes, produced at higher velocity.

The core flaw I observed in every existing agentic harness: **intelligence and authority live in the same process.** The agent decides what to do and also executes it, with no independent verification layer between the decision and the side effect. A human reviewer can be satisfied by confident, coherent-looking output even when the underlying change violates invariants that only matter later. There is no cryptographic boundary between "what the agent claimed to do" and "what the agent actually did." There is no independent verifier. There is no audit trail the agent did not produce itself.

I had fixed this class of error before — a system that trusted its own state without independent verification, where the solution was a component that ran separately and verified the state against ground truth. The solution to the agent problem is structurally identical: you need a component that independently verifies what the agent claims to have done, and you need to enforce that no action is admitted until that verification passes.

When I needed to scale from one agent to multiple concurrent agents to cover the full scope of Aegis, the problem did not continue — it multiplied. Verification that ran in parallel to catch regressions across high-volume systems is a pattern I had already implemented in prior work. Multi-agent development without a kernel that enforces correctness independently is not faster development. It is faster accumulation of errors that look like progress.

---

## Why I Built CJBrain

CJBrain — "CJ" for Chika Jinanwa, "Brain" as a working name for what is functionally a control plane — was the answer I designed from first principles.

The design principle: **the planner must not be trusted.** Not because the model is adversarial, but because the model is probabilistic. In any system where the cost of being wrong is high enough to matter — and Aegis, processing GPU telemetry for production clusters, is such a system — probabilistic correctness is not sufficient. You need deterministic enforcement. The agent is the intelligence. The kernel is the authority. They are separate processes, and the kernel never takes the agent's word for anything it can independently verify.

The specific failure modes I was engineering against:

- Agents touching files outside the scope of their task, without detection or audit
- Agents claiming gates passed when they did not, or when the gates were not run at all
- No tamper-evident record distinguishing what the agent reported from what the agent did
- No escalation path when the task required authority the agent did not have
- No budget enforcement: unbounded context consumption with no admission control

Hardware-backed cryptographic validation is a pattern I had applied in prior work — software trust is insufficient at the levels of assurance that high-stakes systems require. CJBrain applies the same logic: the plan is Ed25519-signed by the operator, every intent is verified by the kernel against the actual VCS state (not the agent's report of the VCS state), gate claims are certified by independent subprocess verifiers, and every admitted action is recorded in a SHA-256 chained audit log.

The name CJBrain was always provisional. A lab name. It communicated nothing about what the system did or why it mattered.

---

## Why RAXIS

As the v1 specification was written — 18 SQLite tables, a full IPC protocol, an escalation FSM, a plan signing ceremony, a chained audit ledger — a pattern became visible that I had not named when designing it.

The system independently derived what is now called **Runtime Attestation eXchange for Intelligent Systems**: a protocol framework where an intelligent system must continuously produce and exchange cryptographically verifiable attestations of its actions at runtime, before those actions are admitted into the shared environment.

The mapping is not forced:

| Engineering decision | The RAXIS principle it instantiates |
|---|---|
| Planner submits `IntentRequest`; cannot act directly | Intent attestation before admission |
| Kernel runs `git diff` independently (INV-07) | Verifier does not trust attester's self-characterization |
| Operator Ed25519-signs `plan.toml` before any session | Human-anchored authority chain |
| Verifier is a separate subprocess with a single-use token | Third-party evidence attestation |
| `nonce_cache` + monotonic `sequence_number` | Replay and ordering protection |
| Escalation → operator-signed `ApprovalToken` | Dynamic authority upgrade via attestation exchange |
| SHA-256 chained JSONL audit log | Tamper-evident attestation ledger |
| INV-08 opaque rejection codes | Asymmetric information enforcement |
| Failure-closed on every error path | RAXIS liveness guarantee |

None of this was designed to implement RAXIS. It was designed to make the control plane correct. Separation of the system that acts from the system that verifies, cryptographic enforcement of that boundary, and an unforgeable record of every admission decision — these are patterns I had applied in different domains across my career. RAXIS is the name for that answer in the domain of intelligent systems.

Renaming CJBrain to RAXIS is intellectually honest: the system earned the name through engineering necessity, not through naming intent. The rename also makes a verifiable claim. See `raxis-concept.md` for the serious counterarguments — where this implementation falls short of a complete RAXIS system (no hardware root of trust, no model identity, retrospective attestation only, no standardized interoperability). Those gaps are the roadmap, not the refutation.

CJBrain was what I built. RAXIS is what it turned out to be.

---

## How Far We Are — And Why v1 + v2 Are Worth Building Anyway

RAXIS at its most complete form requires things this project does not yet have and cannot deliver alone:

- **Hardware root of trust.** The kernel process is assumed honest. A compromised OS defeats every attestation guarantee. True RAXIS needs a hardware anchor — a TPM, a secure enclave, a FIDO2-class root — so the verifier itself can be attested. That is not a problem any single project can solve alone; it requires industry-wide infrastructure standards.
- **Model identity.** The planner holds a session token, not a cryptographic identity. Two completely different LLMs — or an adversarially fine-tuned variant of the same model — are indistinguishable to the kernel. True RAXIS would attest the model: its weights hash, its provider, its runtime environment. No standard for this exists today.
- **Prospective attestation.** RAXIS v1 verifies what the agent *did* (commit-then-verify). A complete system would also pre-authorize what the agent *will do* before it acts, creating a two-phase protocol that prevents unauthorized compute from happening at all.
- **Standardized interoperability.** This project's attestation schema is closed — it does not speak W3C Verifiable Credentials, IETF RATS (RFC 9334), or DICE. A true RAXIS implementation would be verifiable by any party holding the public keys, on any conforming system.
- **Semantic effect attestation.** Path scope is verified by diff. Whether the code does what the task description *means* is not verified at all. Formal verification or semantic analysis of agent actions is an open research problem.

These are not gaps I can close alone. They are the AI governance and safety problems of the next decade.

What v1 and v2 do deliver is different — and it is a powerful enough proof of the concept to be worth building, publishing, and building on:

**v1** closes the gap between "AI agent with no authority enforcement" and "AI agent operating under a cryptographically enforced control plane." Every action is explicitly attested before admission. Every admission is recorded in a tamper-evident ledger. Authority is human-anchored at the plan level. The planner cannot self-certify correctness. Gate results come from independent verifiers. The system fails closed. This is not a research prototype — it is a working, specifiable, implementable system that can be deployed today.

**v2** adds agent-to-agent communication channels through the kernel — meaning RAXIS can coordinate multiple planners under the same authority model, routing messages through a controlled channel rather than direct process-to-process communication. Each agent's actions remain bounded by its own signed plan. This is the first concrete step toward multi-agent attestation chains.

Together, v1 + v2 demonstrate the lower half of RAXIS: runtime enforcement, structured attestation exchange, audit traceability, operator-anchored authority, failure-closed admission, multi-agent coordination under a shared control plane. That is more than virtually any deployed autonomous agent system achieves today — not because the techniques are unavailable, but because nobody has built and formally specified the enforcement layer as a first-class system.

## A Call for Contribution

AI governance and safety is not a solved problem, and it is not going to be solved by the organizations that benefit most from moving fast. The gaps above — hardware attestation, model identity standards, prospective authorization protocols, semantic verification — require open, collaborative, adversarially scrutinized work to close. That work does not happen without people who care enough to look at a spec, find the holes, and propose better enforcement mechanisms.

If you are working in AI safety, formal verification, cryptographic protocols, or distributed systems, I want your input. The implementation is in Rust. The specification is in `specs/v1/`. The design is auditable. The counterarguments are documented honestly in `raxis-concept.md` — they are the starting point for the conversation, not the end of it.

This is an open-source project. The more eyes on the attestation model, the protocol boundaries, and the trust assumptions, the closer we get to AI agents that are genuinely accountable — not just aligned by training, not just sandboxed by isolation, but *verifiably accountable* at every action boundary, with a tamper-evident record of every decision that can be audited independently of the agent that made it.

That is what RAXIS is trying to be. We are not there yet. But the direction is right, the foundation is real, and we need help.
