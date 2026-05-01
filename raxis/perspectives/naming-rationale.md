# From CJBrain to RAXIS: Origin, Intent, and the Decision to Rename

> **Written by:** Chika Jinanwa  
> **Date:** May 2026  
> **Status:** Permanent decision record: why this project exists and why it was renamed.

This note tells one continuous story: how my work history and Aegis led to agents, why “helpful assistant in one process” stopped being enough, what I built first as **CJBrain**, and why that became **RAXIS**.

The companion piece **[`need-for-cj-brain.md`](need-for-cj-brain.md)** is where I go problem-by-problem: verification theater, where authority actually lives, why the context window is not a trust boundary, budget and egress, correlated LLM failure modes, audit replay, scope creep, and structured escalation—plus privilege separation (worker vs supervisor, narrow typed channel). Read this file for motivation and naming; read that one when you want mechanics and numbered gaps.

---

## How I think about building systems

I did not learn what “good systems” look like from blog posts. I learned it from jobs where a mistake shows up as a bad balance on a cardholder account, a silent failure in endpoint security at billion-call scale, or GPU budget bleeding into production without anyone noticing until the bill arrives.

I have worked at **Google**, **Cruise**, **Galileo Financial Technologies**, and **Microsoft**: AV infrastructure, payment authorization, security products, developer tooling. The domains change; the failure mode that scares me does not. The expensive bugs are rarely the ones that take the service down. They are the ones that let everything stay green while something important is wrong.

I read a lot—technical papers, design documents, post-mortems—and I study how systems age: not only whether something works today, but whether it will be defensible in three years when the original engineers have moved on and someone is reading the code cold. Good engineering has a shape that is recognizable when you have seen enough of it. Bad engineering also has a shape. Both are visible early, if you know what to look for.

Security and correctness were never “phase two” in those environments. A leak is not a staging issue. A race that corrupts balances does not announce itself in a dashboard; it surfaces weeks later in support. Bad validation that slips past review is not a normal bug when the product is endpoint defense. After enough of that, you stop treating separation of concerns as advice and start treating it as structural: **the thing that decides must not be the same thing that executes without someone else checking.**

---

## What I was building: [Aegis](https://tryaegis.io/)

[Aegis](https://tryaegis.io/) is EDR for AI workloads, built to cut wasted GPU time in training and inference clusters. GPU hours are a finite resource with a price tag; “we probably ran the right thing” is not an acceptable operational story.

The stack spans a per-node daemon (`aegisd`), a central server (`aegis-server`), eBPF-based syscall and network monitoring, workload-aware visibility on the machines where training and inference actually run, and a dashboard. The aim is endpoint detection and response for ML clusters: catch waste, misuse, and risky behavior where it happens, not bolt on a GPU-centric metrics pipeline and call the problem solved. Building it to the standard I am used to from prior roles is a full production problem, not a weekend prototype.

---

## The agent problem

### I still want models in the loop

I **strongly advocate** for using AI in software engineering: it is how I want to work, and it is how I did much of the exploration and implementation around Aegis and later RAXIS. Nothing that follows is an argument against models; it is an argument for **pairing** them with enforcement where it matters.

### What broke when I tried to move faster

I started using agents to move faster on Aegis. The best models at the time (Claude Opus included) were *almost* right often enough to be dangerous.

A change could compile, look fine on review, and still miss edge cases any engineer who has shipped production code would have caught. Models wandered outside the task’s file scope. Sometimes they said tests passed when they had not run, or had run the wrong thing. The diff and the story did not match.

Bugs have always been part of shipping software; even exceptional human engineers make mistakes. Over decades we built reviews, tests, type systems, staging, rollbacks, and incident practice to live with imperfection: those processes narrow risk and catch whole classes of failures, but they never eliminate them outright. Using models did not create defect risk from nothing; it exploded how much code and churn move through a team in the same calendar time, which widens exposure if the safety margins around the human stay flat. Accountability did not transfer to the weights. **Humans are still responsible for what they ship**, full stop, whether they authored every line by hand or accepted AI-drafted changes under their own sign-off.

### Design discipline vs enforcement

I stumbled on Dave Rensin’s *[Elephants, Goldfish, and the New Golden Age of Software Engineering](https://drensin.medium.com/elephants-goldfish-and-the-new-golden-age-of-software-engineering-c33641a48874)*. I was not looking for a manifesto to anchor on; I read it and was genuinely struck by how much substantive insight sat in one place. The piece is organized around **trust-but-verify** use of models for ordinary work (Part 1), then in Part 2 introduces the **Elephant-Goldfish Model (EGM)**: the **Elephant** is the long-lived, context-rich collaboration that produces a rigorous design document; the **Goldfish** is a fresh session with no chat history that must prove it understands and can stress-test that document alone (comprehension, critic review, implementation readiness) before code is treated as allowed to proceed. His thesis there is **design is the new code**: if models write the implementation but humans do not force design judgments into reviewed prose first, you mass-produce unmaintainable slop and lose accountability; he also argues plain-English design is far cheaper context than dumping raw source (`sizeof(docs) << sizeof(code)` is how he puts it).

That workflow is about human judgment and documentation discipline. I still cared about the **pattern**: separating artifact authoring from independent verification. What I added on top was kernel authority, deterministic witnesses, and budgets—because LLM-on-LLM checks are not an enforcement layer when the job is a control plane.

The answer is not better prompting. Stronger system prompts or longer spec files do not turn a probabilistic planner into an authority layer, a witness generator, or admission control. Compliance still lives inside the model’s head.

### What “harness” means—and why product harnesses are not enough

**How people use the word now.** [Aparna Dhinakaran](https://x.com/aparnadhinak/status/2046980769747533830?s=48) wrote something I agree with at the definitional level: we throw the word “harness” around without a shared meaning. She argues LangChain and LangGraph are **frameworks** (human architect wires chains, state graphs, memory, dozens of knobs), not harnesses in her sense, and she pushes back on collapsing early agent frameworks into “harness” vocabulary (she cites [Akshay Pachaar’s post](https://x.com/akshay_pachaar/status/2041146899319971922), which she reads as part of that confusion). Fair distinction for labeling.

**What she calls a real harness.** Products like Cursor, Claude Code, Windsurf, and Codex did not start from abstract graphs; they started from “make an LLM edit real repos” and converged on similar bones: an outer iteration loop over tool calls, context management and compression, a tool registry plus permission layer, dynamic system-prompt assembly from project files, hooks, session persistence, sub-agents for parallel work. She lists nine recurring component areas (outer loop, context management, skills/tools, sub-agents, built-in skills, session recovery, prompt assembly, lifecycle hooks, permission/safety). That convergence is the signal she cares about. She also points to a visual summary: [What is an AI harness?](https://arize.com/what-is-a-AI-harness.pdf) (Arize).

**Why that still is not strict enough for a control plane.** In her account, a harness “works out of the box”: fixed architecture, no assembly step, and it is optimized so the **model** reads instructions, **discovers** tools and skills, composes them, spawns sub-agents, and often gets steering on what to keep in context. That is the right tradeoff for general coding agents. It is the wrong shape when you need **deterministic admission**, **VCS-grounded authority**, **witnesses that are not LLM persuasion**, and **no silent expansion of capability**. In that setting the model should not drive tool discovery and composition as the primary control mechanism; the operator declares the tool surface in signed policy, the kernel injects only what that session may see, fetch and budget are mediated outside the planner process, and widening capability is a governed change with an audit trail—not something the model improvises by finding new skill files.

So RAXIS is not “use a better harness prompt.” It is a **different layer**: privilege-separated enforcement that treats planner output like untrusted input, regardless of how polished the productized harness loop is.

### Intelligence and authority in the same place

What bothered me about every harness I tried was structural: **intelligence and authority lived in the same place.** The agent proposed and executed with nothing enforceable in between. A human reviewer can nod along at confident prose while invariants quietly break. There is no cryptographic gap between “what it said it did” and “what actually landed.”

I had already fixed a cousin of this once: a component that trusted its own picture of state until a separate verifier reconciled against ground truth. The agent case is the same shape. You need independent verification of claims, and you need admission control so nothing commits until that checks out.

Scaling from one agent to several concurrent ones did not “add complexity”; it multiplied the blast radius. Parallel verification against high-volume systems is a pattern I had shipped before. Multiple agents without a kernel that enforces correctness independently is not velocity; it is faster stacking of work that *looks* finished.

[`need-for-cj-brain.md`](need-for-cj-brain.md) names what goes wrong in more detail: **verification theater** when one LLM “reviews” another (same failure modes, coherent rationalizations); **correlated mistakes** across agents; treating the **spec as something inside the model’s context** so compliance becomes whatever the model convinces itself of; and **no structural ceiling** on spend or network unless something external notices. RAXIS is the answer to those specifics, not only to “agents hallucinate sometimes.”

---

## Why I built CJBrain

CJBrain (“CJ” for Chika Jinanwa, “Brain” as a placeholder for the control plane) was the design I wrote down when I stopped accepting “helpful assistant in one process” as enough.

### Probability is not enforcement

What stuck from **using models day to day to build real software**, not from theory, was this: **probability is not a substitute for enforcement** wherever mistakes have durable side effects. Helpful completions and fluent plans still leave you with a stochastic worker; without an external boundary, “probably fine” is what ships. On **Aegis** that gap stopped being academic: **Aegis-class stakes** meant real clusters, real telemetry, and real money if you mis-account resources, so “the agent believed its own summary” was never good enough. The same lesson shows up in smaller repos too; Aegis was just where I could not pretend otherwise.

The rule I refused to compromise: **do not trust the planner** as the authority boundary. Not because the model is evil, but because it is probabilistic. The agent proposes; the kernel decides what may happen. Different processes; the kernel does not accept the agent’s report of repo state when it can check Git itself.

### Failures I was trying to kill

- Agents touching files outside the scope of their task, without detection or audit
- Agents claiming gates passed when they did not, or when the gates were not run at all
- No tamper-evident record distinguishing what the agent reported from what the agent did
- No escalation path when the task required authority the agent did not have
- No budget enforcement: unbounded context consumption with no admission control

Those map to the numbered gaps in [`need-for-cj-brain.md`](need-for-cj-brain.md). At a high level, the design responses look like this:

- **Authority and scope from ground truth, not prose.** Paths and claims come from VCS diff and the signed policy artifact; the planner does not interpret its own permission to touch `src/auth/session.rs`. Scoped work that leaks outside declared claims should trip gates, not rely on the model’s reading of a spec.
- **Witnesses, not LLM judges.** Gates bind to subprocess-produced evidence (tests, linters, exit codes) tied to commit SHA and task ID, not to another model agreeing the output “looks fine.”
- **Enforcement state outside the planner’s context.** Admission, budgets, and gate outcomes live in the kernel store; what the model remembers or forgets in-chat does not move the trust boundary.
- **Structural budgets** reserved at intent time, not hope that N agents stop spending.
- **No unauthorized egress** from the planner binary: external fetch mediated kernel → gateway with allowlists, not “the spec says don’t call random URLs.”
- **Tamper-evident audit** so replay beats archaeology through chat logs and ad hoc diffs.
- **Escalation as a typed control-plane path**: recorded, timeout-bounded, operator-issued approval tokens, instead of the model improvising or going silent.

That doc also states the tradeoff plainly: a spec file has almost no design cost; **RAXIS pays upfront** (policy artifact, claim tables, gates, ceremony) and buys safety that does not erode when you add agents or stretch runtime. The **asymmetric cost** section there is the full version of that argument.

### Architecture and crypto—the same instinct

Architecturally this is the familiar **privilege-separation** pattern: unprivileged worker handles untrusted input, privileged supervisor admits side effects, narrow typed channel between them—except here the untrusted input is **model output**, for the same reason network bytes are untrusted. OpenSSH’s monitor/child split and Chrome’s browser-kernel vs renderer are the precedent; [`need-for-cj-brain.md`](need-for-cj-brain.md) spells out the mapping table explicitly.

I had already worked with hardware-backed crypto boundaries where “trust the software stack” was not enough. CJBrain applies the same instinct: operator-signed plans (Ed25519), kernel verification against actual VCS state, gate artifacts from separate verifier processes, SHA-256 chained JSONL for anything that gets admitted.

### The old name

The name CJBrain was always provisional—a lab name. It communicated nothing about what the system did or why it mattered.

---

## Why RAXIS

While the v1 spec grew (SQLite schema, IPC, escalation state machine, signing ceremony, chained audit), a pattern surfaced that I had not labeled up front.

Independently, it lines up with what I now call **Runtime Attestation eXchange for Intelligent Systems**: before side effects land in a shared environment, an intelligent system has to exchange cryptographically checkable attestations at runtime, and a verifier that does not live in the proposer’s trust boundary gets a vote.

The fit is not strained:

| Engineering decision | RAXIS idea it reflects |
|---|---|
| Planner sends `IntentRequest`; cannot act alone | Intent attested before admission |
| Kernel runs `git diff` itself (INV-07) | Verifier does not trust self-description |
| Operator signs `plan.toml` before sessions | Human-anchored authority chain |
| Verifier subprocess + single-use token | Third-party evidence attestation |
| `nonce_cache` + monotonic `sequence_number` | Replay / ordering controls |
| Escalation → operator-signed `ApprovalToken` | Authority upgrades via exchange |
| SHA-256 chained JSONL audit | Tamper-evident ledger |
| INV-08 opaque rejection codes | Deliberate information asymmetry |
| Failure-closed error paths | No “best effort” admissions |

I did not set out to “implement RAXIS.” I set out to make a control plane I could trust: separation of actor and verifier, crypto at the boundary, an append-only record of admissions. Those habits came from payment systems, security work, and watching verification save teams from themselves. **RAXIS** is the name for what that habit produces when the workload is an intelligent system.

Renaming CJBrain to RAXIS is partly honesty—the architecture earned the term. It is also a claim you can argue with. `raxis-concept.md` spells out where this stack stops short (no hardware root of trust, weak model identity story, mostly retrospective attestation, no interoperability standard yet). Those gaps are the roadmap, not an excuse to pretend we are done.

CJBrain was what I named it on day one. RAXIS is what the spec turned out to describe.

---

## How far along we are—and why v1 / v2 still matter

A “complete” RAXIS story wants things one repo cannot deliver by itself:

- **Hardware root of trust.** We assume the kernel process is honest; a compromised host blows up the guarantees. Serious deployment eventually wants TPM / enclave / FIDO-class anchors so the verifier chain is attestable too. That is bigger than this project.
- **Model identity.** The planner holds a session, not a cryptographic identity. Swap weights or providers behind the same API and the kernel cannot tell. A fuller RAXIS would attest model provenance; the standards barely exist.
- **Prospective attestation.** v1 is largely commit-then-verify. A tighter world pre-authorizes compute before it runs; that is a second phase of protocol design.
- **Interoperability.** Our schema is ours: not VC, not RATS (RFC 9334), not DICE. A portable RAXIS would let third parties verify with published keys on conforming stacks.
- **Semantic effects.** We can bound paths and diffs. We do not prove the change matches what English meant; that is research-grade territory.

I cannot close those alone. They are the messy middle of AI governance for the next decade.

What v1 *does* do is narrow the gap between “agent with no enforcement” and “agent under a crypto-backed control plane”: attest before admission, record admissions in a chained log, anchor authority at the human/plan layer, pull gate truth from subprocess verifiers, fail closed. It is specified enough to implement without hand-waving.

v2’s kernel-mediated agent channels matter because multiple planners need a relay that preserves the same authority model instead of ad hoc peer sockets: a step toward attestation chains across agents, still bounded per signed plan.

Together that is the enforcement-heavy half of the RAXIS picture: runtime gates, structured exchange, auditability, operator-rooted authority, closed failure modes, coordinated multi-agent use. Plenty of agent demos skip that layer—not because the crypto is impossible, but because specifying and shipping it as a first-class system is rare.

---

## Contributing

AI governance is not a checkbox inside a single vendor roadmap. Hardware attestation, model identity, prospective authorization, semantic checks: those need open review and people who enjoy finding holes.

If you work on protocols, formal methods, crypto, or distributed systems, I want the criticism. The code is Rust; the contracts live under `specs/v1/`. `raxis-concept.md` states the limitations on purpose so argument can start from facts.

The goal is simple to say and hard to reach: agents whose actions are *checkable by someone who is not the agent*, with a log that survives storytelling. RAXIS is my attempt to build that foundation. It is incomplete. It is also real enough to extend, and I would rather extend it in public than polish a private fiction.
