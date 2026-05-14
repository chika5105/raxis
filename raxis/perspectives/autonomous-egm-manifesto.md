# The Autonomous EGM: Hardening the Elephant and Goldfish for an Agentic Workforce

Dave Rensin’s original [Elephant-Goldfish Model (EGM)](https://drensin.medium.com/elephants-goldfish-and-the-new-golden-age-of-software-engineering-c33641a48874) solved a critical human problem in the age of AI: preventing "unmaintainable slop" by forcing developers to treat *design as the new code*. You use a high-context AI session (the Elephant) to define an English design document, and a zero-context AI session (the Goldfish) to validate that the document is perfectly understandable. Only then do you write the code. **In the Autonomous EGM, the Goldfish does not replace that human comprehension step with prose alone:** it enforces a **Claim Manifest** (complete coverage of risky claims) and **Deterministic Verifier** verdicts—rhetorical “sounds good” is insufficient.

But the original EGM is fundamentally a human-in-the-loop framework. When you remove the human from the critical path and attempt to run EGM as an *autonomous agentic pipeline*, the friction that slows down an engineer becomes a deadly trap for an AI, and the rhetorical validation becomes a vector for shared delusion.

To make EGM survive an autonomous workforce, we must replace rhetorical trust with mechanical physics. This is the Autonomous EGM Framework.

---

## 1. The Shared Delusion Problem
In a human-led EGM, the human prevents hallucination. If the Elephant hallucinates that an API has an `extract_telemetry()` method, the human spots the lie. 

If you replace the Implementer with an agent, you have a fatal problem. The Elephant writes a plausible design based on hallucinated methods. When misused as a rhetorical reviewer, the Goldfish reads it, finds the prose logically consistent, and rubber-stamps it as "Implementation-Ready." You cannot use a rhetorical engine to validate the factual grounding of another rhetorical engine. They share the same blind spots.

## 2. The Goldfish is a Verifier, Not a Reviewer
To break the shared delusion, a Goldfish pass is impossible without a **Witness Set**. No witness, no pass.

Every non-trivial design claim (per team policy or hazard list) made by the Elephant must be mechanically tagged in a **Claim Manifest** and proven by a Deterministic Verifier. The Goldfish checks this manifest for completeness—ensuring no risky claims are un-witnessed—and reads the Verifier's verdicts, not the Elephant's prose. If the Verifier says "unproven," the Goldfish hard-fails the design.

*Note: Witness strictness is scoped by boundary and risk tier (see Section 3). Demanding airtight integration proofs for every internal helper function re-introduces infinite latency.*

**Risk tier (deterministic):** Any unknown or unclassified behavioral surface defaults to the **stricter** tier until disproven. An LLM may *suggest* a tier; a static ruleset (paths touched, dependency signals—e.g. `unsafe`, crypto, network, persistence, auth) **overrides** those suggestions. Tier assignment is not self-attested truth.

**Core Witness Types:**
*   `api_exists`: Symbol path, commit SHA, and AST lookup proof.
*   `behavioral_assumption`: Scoped test pass output hash (e.g., `cargo test`) under resource limits (**local runner; no hosted CI required**—this is the on-machine witness).
*   `dependency_capability`: Pinned version, docs URL, and local compile probe.
*   `security_claim`: Policy rule ID and static-analysis result.

## 3. Escaping the Latency Trap: Contract Boundaries & Two-Speed Execution
If every claim requires an airtight cryptographic proof, you create an infinite escalation loop. We escape this by implementing a **two-speed model**: cheap stochastic exploration vs. strict mechanical promotion.

Contract authority is scoped based on boundaries:
*   **Public/External Boundaries:** Strict admission gates. An `api_proposed` must have a machine-readable contract, compatibility proofs, and a migration shape. Autonomous agents cannot quietly alter global promises.
*   **Private/Internal Boundaries:** The compiler is the truth. The implementation agent is allowed to auto-merge contract revisions internally as long as the compiler passes (e.g., `rustc`), visibility is maintained, and consumers compile. We let the compiler update the contract inside the autonomous loop without forcing a full Elephant rewrite.

## 4. Sentinel Attrition and Budgeted Autonomy
Agents optimize locally. If an agent writes code that breaks a test (a sentinel), its default objective is to get a green build—often by deleting or rewriting the test to match its broken code.

To prevent this **Sentinel Attrition**, we split sentinels:
*   **Hard Invariants (Authz, Data Loss):** Placed in a protected path with "deny-write" for implementation agents. They require explicit policy/human escalation to change.
*   **Behavioral Smoke:** Agents are granted *budgeted autonomy* to update these sentinels via constrained deltas, provided the changes link back to a stable requirement ID from the human product doc.

## 5. The Boiling Frog Architecture
Independent of test deletion, there is the risk of **Boiling Frog Architecture**—incremental decay across many promoted branches resulting in a highly coupled, unreadable graph. Verifiers optimize against declared constraints, not entropy. 

This requires a distinct governance cadence: periodic human-led simplification passes or explicit "complexity budgets" in promotion rules. **Agents record lightweight learnings durably** (e.g. failed hypothesis, runner-classified flake bucket, “promotion blocked because…” one-liners in append-only logs or linked notes—not silent chat). When architecture decays, humans analyze what failed and tighten admission gates, closing the loop.

## 6. The Operating Physics of a Local Workforce
Running an autonomous workforce locally requires strict environmental hygiene to prevent an agent from DDoS-ing your workstation or laundering malicious inputs:

The repo may be **pushed to GitHub** (remote backup, collaboration, PR review—human, agent-assisted, or mixed)—but **hosted CI is not used** there (e.g. no GitHub Actions). Verification and witness generation stay on the machine unless you deliberately adopt remote pipelines later.

*   **The Thin Runner:** Every agent-spawned command runs under a lightweight runner enforcing wall-clock timeouts, `setrlimit` (CPU/Memory bounds), and build concurrency caps (e.g., `CARGO_BUILD_JOBS`).
*   **Parallelism Caps:** To prevent the "Agentic Fork Bomb," global orchestration policies must cap concurrent exploration branches and max verifier runs per hour.
*   **Trust Boundaries (Confused Deputy):** **Mechanically** separate untrusted buckets from trusted ones. Use structured ticket fields or non-LLM parsers for metadata. Untrusted prose stays out of the same context pack as policy/config tools unless explicitly quoted and labeled.
*   **Policy Firewalls:** Untrusted text (issues, web snippets) must never be commingled with policy tools. The Elephant must treat external prose as untrusted, and it can never rewrite tier labels or sentinel policies without a trusted human gate.
*   **Intent Garbage Collection:** To prevent context poisoning, design docs must declare explicit edges (REQ-IDs) to the human product doc. Stale intent is tombstoned and excluded from agent context packs, never destructively deleted by an agent.
*   **Flake Taxonomy:** Classification must come from the runner's exit codes and signals (e.g., timeout vs. OOM vs. assertion failure), not an LLM reading terminal exhaust. **Best-effort on macOS/Linux;** ambiguous outcomes **escalate** (re-run under the same limits, human triage, or quarantine)—never silently trust a weak label.


