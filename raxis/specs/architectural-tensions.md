# RAXIS — Architectural Tensions

> This document records known tensions between RAXIS's foundational design choices and
> directions the AI field is actively moving. These are not bugs or mistakes — they are
> deliberate trade-offs. They are recorded so future engineers understand what they are
> accepting when they work within the architecture, and where the boundaries of the
> current design lie.
>
> Each tension is a signal for future versioned work, not an immediate action item.

---

## T-01: Static Authority vs. Dynamic Agent Capability Discovery

**The invariant:** The task topology, per-task allowlists, and dispatch matrix are
declared in a signed plan before any VM boots. The Kernel enforces this statically at
admission time. No agent can negotiate, discover, or expand its capabilities at runtime.

**The tension:** The AI field is moving toward agents that discover their environment
and adapt their tool use dynamically based on what they find mid-task. Models are
increasingly capable of decomposing problems in ways that weren't anticipated at
planning time.

**What RAXIS gives up:** Operators must think carefully about plan topology before
running. Highly exploratory tasks — where the right tool set isn't known until the model
starts working — cannot be efficiently expressed as a signed plan. Large, over-broad
plans (to accommodate dynamic needs) weaken the auditability benefit.

**What RAXIS gains:** Every agent action is traceable to a human authorization made
before the initiative started. The audit chain is complete. There is no runtime
authority expansion that can't be attributed to a signed plan.

**Resolution in V2:** Accept the friction. Operators invest more in plan design.
The structured debate pattern and multi-wave DAG model reduce friction for complex tasks
by allowing pre-declared multi-round coordination. Per-capability epoch diffing (A.18)
allows policy evolution without re-signing plans.

---

## T-02: Plan-Time Topology vs. Emergent Agent Spawning

**The invariant:** The number of sessions, their types, and their activation
dependencies are fixed in the signed plan. An Orchestrator can activate sub-tasks but
cannot create new task types or grant new capabilities that weren't declared.

**The tension:** Highly capable models increasingly benefit from spawning specialized
sub-agents on demand — a "meta-agent" that decides mid-task it needs a security reviewer
or a documentation writer. This is architecturally excluded in RAXIS: the plan is sealed.

**What this costs:** For dynamic, open-ended initiatives, RAXIS requires the operator
to predict the agent composition in advance. This is feasible for well-understood tasks
(implement feature X, refactor Y) and hard for open-ended research tasks.

**Future consideration:** A "dynamic sub-task slot" model — where the signed plan
declares a budget of unnamed Executor slots that the Orchestrator can instantiate with
task-specific context — could reduce this friction without breaking the audit chain.
Not in V2 scope.

---

## T-03: Intent Model vs. UI-Native / Computer-Use Agents

**The invariant:** All agent actions are expressed as typed intents (`IntentKind`) with
well-defined admission checks. The intent set is discrete and enumerable.

**The tension:** Models with computer-use capabilities (taking screenshots, clicking,
typing into applications) produce actions that don't fit the current intent model. There
is no `ComputerUseAction` intent. The path allowlist model doesn't apply to UI
interactions. The audit model (commit SHA integrity) doesn't apply to UI state.

**What this means:** RAXIS currently cannot safely admit computer-use capable agents.
Admitting them without a defined intent type and admission pipeline would require
bypassing the dispatch matrix, making their actions unauditable.

**Future consideration:** A `ComputerUseAction { application, action_type, bounds }` intent
class with its own admission checks, screen content filtering policy, and audit model
would need to be specified before admitting computer-use sessions. This is a significant
specification effort — not a mechanical extension of the existing pipeline.

---

## T-04: Initiative-Scoped State vs. Persistent Agent Memory

**The invariant:** Each initiative starts from a fresh VM provisioned from the current
`base_sha`. There is no cross-initiative memory primitive in the Kernel or the plan model.
Agent state that persists beyond a VM's lifetime must live in the workspace (auditable,
subject to allowlists) or outside RAXIS entirely (unaudited).

**The tension:** As AI architectures increasingly rely on persistent memory (episodic
recall, vector databases, long-term preference models), agents that can't access prior
context start each initiative cold. This reduces performance on tasks that build on
prior work.

**The risk:** Memory outside the RAXIS workspace is an unaudited side channel. If an
agent reads from an external memory store that was written by a previous (potentially
compromised) session, the contamination is invisible to the audit chain.

**Partial mitigation in V2:** The workspace persists between initiatives on the same
repo — the `base_sha` advances. Agents can read prior work from git history. This covers
code-based memory (what was built before) but not semantic memory (what the agent
learned about the problem domain).

**Future consideration:** A Kernel-managed memory store (analogous to `raxis-egress`
for web access) — admited `MemoryRead` / `MemoryWrite` intents with content-addressed
storage and full audit — would close this gap without introducing unaudited side channels.
Not in V2 scope.

---

## T-05: Host OS Trust Boundary

**The invariant:** RAXIS assumes the host OS user boundary is intact. The security
model for INV-GATEWAY-01 and INV-EGRESS-01 explicitly states: "host-level privilege
escalation is a host security problem, not a RAXIS problem."

**The tension:** As AI models become more capable of reasoning about system internals —
memory layouts, syscall semantics, kernel exploits — the host OS boundary becomes a
more attractive target. A sufficiently capable jailbroken agent that can discover and
exploit a host privilege escalation vulnerability could reach `raxis-kernel` user and
connect to the gateway or egress proxy directly, bypassing admission.

**What makes this harder over time:** Current jailbreaks require prompting. A model
trained or fine-tuned on system internals could produce more targeted exploit attempts
through tool calls (bash execution within the VM). The AVF boundary stops VM-level
code from affecting the host directly — but a multi-stage exploit (VM → hypervisor
escape → host) cannot be ruled out as models improve.

**Mitigations that improve this boundary (not currently specified):**
- Hardware security keys for all credential material (no file-resident keys on the host)
- macOS System Integrity Protection and Gatekeeper for all RAXIS binaries
- Signed and notarized `raxis-kernel`, `raxis-gateway`, `raxis-egress` binaries
- Host process isolation via macOS App Sandbox for gateway and egress processes

---

## T-06: Discrete Request-Response vs. Long-Running Streaming Agents

**The invariant:** The planner-kernel protocol is frame-based. Each `InferenceRequest`
produces one `InferenceResponse`. The admission pipeline validates discrete intents.

**The tension:** Emerging agent architectures include long-running "always-on" agents
that maintain a continuous reasoning stream rather than discrete request-response cycles.
If providers move toward streaming inference as the primary interaction model (rather
than an optimization of request-response), the framing model needs to evolve.

**Current state:** The gateway handles streaming HTTP responses from providers and
buffers them into a single `InferenceResponse` before returning to the Kernel. This
works today but introduces latency for very long responses and doesn't allow the planner
to react to partial model output.

**Future consideration:** Streaming `InferenceResponse` chunks delivered over VSock —
the planner processes partial output while the model is still generating. This requires
changes to the planner-kernel VSock protocol (frame types for stream start, chunk, end)
and to the budget model (cost is only known at stream end, but must be reserved at stream
start). Not in V2 scope.

---

## Summary

| Tension | RAXIS Principle at Stake | Field Direction | V2 Position |
|---|---|---|---|
| T-01 Static authority | Signed plan is immutable authority | Dynamic capability discovery | Accept friction; invest in plan design |
| T-02 Plan-time topology | Sealed session composition | Emergent agent spawning | Excluded by design; dynamic slots deferred |
| T-03 Intent model | Typed, enumerable actions | Computer-use / UI agents | Unspecified; requires new spec effort |
| T-04 Initiative state | No cross-initiative memory primitive | Persistent agent memory | Partial: git history; Kernel memory store deferred |
| T-05 Host OS trust | OS user boundary assumed intact | More capable exploit generation | Mitigated by hardware keys + signed binaries (not yet specified) |
| T-06 Discrete protocol | Frame-based request-response | Streaming / always-on agents | Gateway buffers streams today; native streaming deferred |
