# The Case Against RAXIS: Why Constraining Models Is the Wrong Answer

*Deliberately adversarial: the strongest version of the objection, not a straw man.*

For the structured response, see **[`raxis-defense.md`](raxis-defense.md)**.

---

## 1. You are solving the wrong problem with the wrong tool

The failures that motivated RAXIS—agents touching the wrong files, falsely claiming tests passed, drifting outside task scope—are **reliability** failures, not **safety** failures in the cryptographic sense. The proportionate response is better feedback loops, better test harnesses, better task decomposition, and more representative examples in context. Responding to a software-quality problem with a distributed-systems-style protocol is a category mismatch, and mismatches have consequences.

A surgeon who keeps cutting in the wrong place does not need a hospital administrator locking scalpel access behind a signed plan. The surgeon needs better training, better imaging, and better instrument feedback. RAXIS is the signed plan. It does not make the cut more accurate.

## 2. Flexibility is literally the point

You chose an LLM over a rule-based system for one core reason: rules cannot anticipate all cases. The moment you write a `path_allowlist` into a signed plan, you are writing rules. The moment you define `intent_kinds`, you are writing rules. Every constraint in RAXIS is a rule you encode that the LLM would otherwise handle probabilistically and adaptively. At the limit—full enforcement, all paths specified, all gate types defined—RAXIS becomes a rule-based system with a very expensive planner bolted on for cases the rules already cover.

The probabilistic nature of models is not a bug you are defending against; it is the capability you are paying for. A model that can handle a task you did not fully anticipate is more valuable than one constrained precisely to tasks you already specified completely. If you could specify tasks completely, you would not need the model.

## 3. The signed plan is a bet you cannot win

RAXIS requires the operator to sign a plan before execution begins. The plan includes path allowlists, terminal criteria, task dependencies, gate types. So the system works best precisely when you already knew, before starting, exactly what the agent would need to do.

Real engineering is often the opposite. You discover the planned architecture is wrong. You discover the dependency exposes a different API. You discover the task is blocked by an upstream problem nobody anticipated. In those situations RAXIS does not help you adapt—it forces you to stop, re-specify, re-sign, and re-admit. The overhead of renegotiating the plan with the operator every time reality diverges from the document is often **higher** than the cost of the original reliability problem you were trying to solve.

You get a system that works well for work already well understood, and poorly for work that requires discovery. The work that requires discovery is often the work worth automating.

## 4. The independent verifier is not independent

The verifier runs tests. Who wrote those tests? The same human (or agent) that wrote the code. If the code is wrong in a way the tests do not catch—and that is the most common kind of wrong—the verifier passes with full confidence. RAXIS does not solve the test-quality problem; it makes test quality **load-bearing**. A gate that passes confidently on bad tests yields more confidence in a wrong answer, not a correct one. Without RAXIS, you are at least epistemically honest about what you do not know.

## 5. Cryptography cannot answer epistemic questions

Cryptographic attestation answers a narrow class of questions well: did this key sign this message? Was this file unmodified? RAXIS answers those with high assurance. The question you actually care about is different: is this code correct, and does it do what the task description intends?

The gap between what RAXIS can verify—path scope, gate pass/fail, sequence integrity—and what you need to know—**semantic** correctness—is enormous. The danger is that RAXIS fills the gap with **confidence** rather than answers. You get a tamper-evident record of events that were cryptographically admitted but may have been semantically wrong from the start. The audit trail is unforgeable; the work can still be bad.

## 6. The human is still there—but now they are doing more work

RAXIS does not remove the human from the loop. It formalizes human involvement: sign the plan, approve escalations, handle blocked states, manage retries, review gate results. If you have a human engaged enough to do all of that, you have a human who could review the agent’s output directly—with less ceremony, more judgment, and faster iteration. RAXIS adds structure to oversight without clearly reducing how much oversight is required. That is overhead, not an obvious net safety win.

## 7. The frontier is moving faster than your spec

The problems RAXIS targets—agents drifting out of scope, false completion reports, unverified gate claims—are also being addressed upstream by model improvements, better tool-use frameworks, and agent scaffolding that improves grounding and self-checking. RAXIS is an engineering response to a capability gap that models and harnesses are closing. The spec you write today may enforce constraints that a model eighteen months from now would not have violated anyway—while operators still sign plans and run genesis ceremonies.

## 8. The failure mode of RAXIS can be worse than the failure mode it prevents

RAXIS is failure-closed. When something is ambiguous, it blocks. The cost of a blocked agent—operator intervention, plan re-signing, task retry—is real, certain, and synchronous. The cost of the failure RAXIS mitigates—an agent touching a file outside scope—is probabilistic, often recoverable with version control, and asynchronous. You trade low-probability, recoverable failures for high-probability, workflow-blocking stops. The expected-cost comparison is not obviously in RAXIS’s favor.

## 9. You have made the enforcement layer the most complex thing

The kernel—with its many SQLite tables, FSM transitions, IPC protocol, challenge–response handshake, escalation machinery, and audit chain—is now among the most complex components in the system. It can exceed the moving parts in the agent it governs. Every bug in the kernel is a **systematic** failure affecting all agents. The agent’s probabilistic failures are distributed and partial; the kernel’s deterministic failures can be total. Risk is concentrated where you hoped to reduce it.

## 10. Authority separation is a metaphor, not a mechanism—at least in v1

“Intelligence and authority must be separated” is a powerful intuition. In RAXIS v1, the planner and the kernel typically run as the **same OS user**. There is no hardware boundary and no memory isolation against a compromised planner process. A sophisticated adversary controlling the planner could, in principle, reach kernel-adjacent paths. What RAXIS enforces is largely a **protocol convention** on a shared operating system. That has real value against careless mistakes. It has limited value against deliberate evasion—which is the threat model you invoke when you emphasize that models are probabilistic and unpredictable.

---

## Conclusion: what a strong opponent would say

RAXIS does not make models more capable. It makes them more auditable in a narrow, largely **syntactic** sense. The trade — flexibility, adaptability, development velocity, and system simplicity in exchange for deterministic enforcement of pre-specified rules plus a cryptographic paper trail — is one many practitioners should decline.

If you need that level of assurance, the objection continues, you do not need an LLM agent in the hot path; you need formal verification with a deterministic executor—which is neither what you built nor what LLMs are good at.

For most applications, the better path is: use models freely, review outputs at integration boundaries, use version control as recovery, and invest in **test quality** rather than enforcement machinery. The blast radius of a well-reviewed agent in a version-controlled repository is often already bounded. RAXIS adds a second containment layer around a blast that was already manageable—while the preventer can become more complex than the system it protects.

---

**Where do you think this is wrong?**  
See **[`raxis-defense.md`](raxis-defense.md)** for a point-by-point framing of the other side. Technical motivation for building RAXIS remains in **[`need-for-cj-brain.md`](need-for-cj-brain.md)**; design alternatives in **[`specs/design-decisions.md`](../specs/design-decisions.md)**.
