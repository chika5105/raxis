# RAXIS: Runtime Attestation eXchange for Intelligent Systems
## Conceptual Analysis, RAXIS as PoC, and Serious Counterarguments

---

## Part 1 — What RAXIS Means and Why It Matters

### The Name, Decomposed

**Runtime** — attestation happens continuously during execution, not at design time, not at training time, not post-hoc. The system is being held accountable in the present tense, at the moment of action.

**Attestation** — a cryptographically unforgeable assertion of a claim. Not a log entry. Not a promise. A binding, verifiable statement: "I assert X is true, and here is evidence that cannot have been produced without the private key that corresponds to my known public key." Attestation is the tool that converts *claims* into *facts a third party can verify independently*.

**eXchange** — a two-or-more-party protocol. Attestation alone is a monologue. Exchange is a dialogue: one party presents a claim + evidence, the other party independently verifies it against ground truth, and either admits or rejects — with the verdict itself becoming an attested record. The exchange is the enforcement mechanism.

**Intelligent Systems** — AI agents, LLMs, planners, autonomous orchestrators. Systems whose behavior is emergent, non-deterministic, and not fully inspectable from the outside. This is the domain where static verification fails and runtime enforcement is not optional — it is the only viable strategy.

### The Problem RAXIS Is Solving

There are five fundamental problems with AI agents acting in shared environments:

**1. The Trust Gap.** An AI agent claims it performed an action correctly and within authorized scope. How does the environment know this is true? Training doesn't help — you cannot train trustworthiness to a level that satisfies a cryptographic verifier. RAXIS answers: don't trust the claim; verify the evidence against independent ground truth at the moment of exchange.

**2. The Authority Problem.** Different principals have different permission levels: the operator owns the system, the planner executes tasks, verifiers attest to quality, other agents may delegate authority. These relationships are dynamic — they change at runtime (a task is admitted, an escalation is granted, a session expires). Static capability lists in config files cannot enforce this. RAXIS answers: every action requires a current, runtime-verified authority credential traceable to a human-signed root.

**3. The Non-Determinism Problem.** You cannot statically verify what an LLM will do. Alignment training reduces harmful outputs but cannot eliminate them. Sandboxing prevents damage but doesn't produce evidence of correct behavior. RAXIS answers: instead of predicting what the agent will do, verify what it *did* at every admission gate.

**4. The Composition Problem.** When Agent A feeds Agent B, and Agent B feeds Agent C, the trust boundary multiplies. A compromise at A, undetected, propagates through B to C. RAXIS answers: attestation must chain — each exchange carries a reference to the prior attested exchange that authorized it, so the chain of custody is verifiable end-to-end.

**5. The Audit Problem.** When something goes wrong, you need an unforgeable record of exactly what was admitted, by whom, under what authority, at what time. A mutable log is useless — a sophisticated attacker patches the log. RAXIS answers: a cryptographically chained audit ledger where every record includes the hash of the prior record, making retroactive falsification computationally infeasible.

### Why RAXIS Is a Paradigm, Not a Feature

The prior dominant paradigm for AI safety is **alignment** — make the model not want to do bad things. RAXIS does not compete with alignment; it operates at a different layer. Alignment governs the model's internal goals. RAXIS governs the model's interactions with the environment. You want both, but:

- Alignment can fail (jailbreaks, prompt injection, distributional shift).
- RAXIS failure modes are engineering failures — they can be formally specified, tested, and audited.
- RAXIS makes AI systems *accountable*, not just *safer*. Accountability is what organizations, regulators, and operators actually need.

A mature RAXIS implementation means: even if the model is adversarial, it cannot take an unattested action. Even if it succeeds at deception, the deception is bounded by what the attestation exchange admits. The exchange is the last line of enforcement.

---

## Part 2 — How RAXIS Maps to RAXIS (Step by Step)

RAXIS was designed to solve a specific engineering problem: how do you run an autonomous coding agent without losing control of what it does to your codebase? The answer it arrived at is, in retrospect, a concrete instantiation of RAXIS principles. Here is the mapping, component by component.

### Step 1 — Intent Attestation: `IntentRequest`

The planner cannot take an action. It can only *declare an intent* and submit it for verification. The `IntentRequest` is the planner's attestation:

- "I am the holder of session token `T`" (identity/authority claim)
- "I am acting within task `task_id`" (scope claim)
- "The VCS state went from `base_sha` to `head_sha`" (action claim)
- "I submit these claims as evidence: `submitted_claims[]`" (quality claim)

None of these claims are trusted. They are inputs to a verification pipeline. This is exactly what RAXIS demands: the intelligent system must produce an explicit, structured claim before the environment admits any side effect.

### Step 2 — Independent Ground Truth Verification: `vcs::diff` + `path_allowlist`

The kernel does not read the planner's claim about what files were touched. It runs `git diff base head --name-status --no-renames` itself (INV-07: "kernel derives required claims from VCS state independently"). The result is compared against `path_allowlist` from the signed plan.

This is the most important RAXIS property: **the verifier does not trust the attester's characterization of the evidence**. The kernel has its own view of ground truth (the git history) that the planner cannot forge (it cannot rewrite committed history without the kernel detecting it via `rev_parse_parent`). The attestation exchange is meaningful precisely because the two sides have access to different but overlapping views of reality, and the verifier's view is authoritative.

### Step 3 — Authority Chain: Signed Plan → Session → Token → Intent

Every admitted intent traces back through a verifiable chain:

```
Operator Ed25519 private key
    ↓ signs
policy.toml + plan.toml (operator-signed artifacts)
    ↓ admits
Kernel session (session_token, 256-bit CSPRNG, stored in SQLite)
    ↓ bound to
IntentRequest (sequence_number, envelope_nonce, session_token)
    ↓ admitted into
task_intent_ranges (permanent record in kernel.db)
```

No intent can be admitted without a session token, no session can be created without an approved plan, no plan can be approved without an operator signature. This is the RAXIS authority chain: human-anchored, cryptographically enforced, auditable at every link.

### Step 4 — Third-Party Witness Attestation: `WitnessSubmission`

The planner cannot self-certify quality. It submits `submitted_claims[]` which reference witness blob hashes, but the actual gate result comes from an independent verifier subprocess — spawned by the kernel, given a single-use `verifier_run_token`, operating against the committed VCS state. The planner has no channel to influence the verifier's output.

This is third-party attestation: the entity claiming credit (planner) is structurally separated from the entity certifying quality (verifier). In RAXIS terms, this is the separation between the *attester* and the *evidence generator*. The exchange requires both.

### Step 5 — Replay and Ordering Protection: Nonce Cache + Sequence Numbers

Every `IntentRequest` carries an `envelope_nonce` (16-byte random, cached to prevent reuse) and a `sequence_number` (strictly monotonic). A captured intent envelope cannot be replayed because:
- The nonce is consumed
- The sequence number has advanced

This is RAXIS's liveness guarantee: the attestation exchange is fresh and ordered. Without this, an adversary who captures a valid intent envelope could replay it to double-admit an action.

### Step 6 — Dynamic Authority Upgrade: Escalation Protocol

When a planner needs authority beyond its current scope, it cannot self-authorize. It submits an `EscalationRequest` — a structured claim that it needs expanded capability, with a justification. The operator reviews and issues a signed `ApprovalToken` (Ed25519, single-use via `nonce_cache`, epoch-bound). The planner presents this token on the next intent.

This is runtime dynamic attestation: the authority surface expands not by the agent's request alone, but by an operator-signed credential issued in response to an attested escalation claim. No escalation path is unattensted.

### Step 7 — Tamper-Evident Audit Ledger: Chained JSONL

Every admitted and rejected action produces an audit record appended to `segment-NNN.jsonl`. Each record includes `prev_sha256` — the SHA-256 of the prior line's raw bytes. The chain is verifiable by `raxis-audit-tools verify-chain`. Any retroactive modification to a prior record breaks every subsequent hash.

This is RAXIS's accountability property: not just that the right things happen, but that the record of what happened cannot be falsified without detection. The audit ledger is the attestation history.

### Step 8 — Information Asymmetry Enforcement: INV-08

The kernel returns opaque rejection codes (`FAIL_PATH_POLICY_VIOLATION`, not the specific glob that fired). `error_detail` is `null` for all codes except `FAIL_POLICY_VIOLATION`, which gets a fixed generic template — no policy internals leak back to the planner.

This is a subtle but important RAXIS property: **the exchange must not leak the verification criteria back to the attester**. If the planner could learn exactly which rules fired, it could craft its next intent to just barely satisfy each rule — gaming the attestation exchange rather than genuinely complying. INV-08 prevents this.

### Step 9 — Failure-Closed Design: All Invariants

The kernel is designed failure-closed: if the kernel crashes, tasks go to `BlockedRecoveryPending` and require operator intervention to resume. If the policy epoch advances, all sessions are invalidated. If the operator socket handshake fails, no operations execute. If the gateway's policy reload fails, all external requests are denied.

RAXIS requires failure-closed semantics: a system that fails open (admits actions when verification fails) is worse than no RAXIS at all, because it provides false assurance. RAXIS never silently admits — every path to admission goes through the attestation exchange, and every failure path blocks.

---

## Part 3 — Serious Counterarguments: Why RAXIS Is Not RAXIS

These are not polish issues. These are architectural gaps that distinguish RAXIS from a general RAXIS implementation.

### Counterargument 1 — The Attester Has No Identity

RAXIS's planner holds a `session_token` — a kernel-issued credential. But the token attests to the *session*, not to the *model*. Two completely different LLMs (or a fine-tuned adversarial variant of the same model) are indistinguishable to the kernel. RAXIS requires that the intelligent system itself be an attested identity: model hash, provider attestation, runtime environment hash. Without this, the kernel is running a protocol with an anonymous party whose fundamental nature it cannot verify. The session token says "someone with this credential is acting here." RAXIS demands "this specific model, running in this specific environment, with this attestable computational identity, is acting here."

### Counterargument 2 — No Hardware Root of Trust

RAXIS at full strength requires hardware attestation: the verification kernel itself must be attested by a hardware trust anchor (TPM, SGX enclave, TrustZone, etc.) so that the attester can verify the verifier is running the correct, unmodified code. RAXIS is a Rust process. The OS can be compromised. The kernel binary can be replaced. A sufficiently privileged adversary can patch `kernel.db`. There is no attestation that the kernel is the kernel — its authority is assumed, not proven. This is the bootstrapping problem: *quis custodiet ipsos custodes?* RAXIS needs an answer. RAXIS does not have one.

### Counterargument 3 — Retrospective, Not Prospective Attestation

RAXIS's attestation model is retrospective: the planner commits code, then presents the commit SHA as the object of attestation. The kernel verifies what *happened*. True RAXIS would include prospective attestation: the planner attests to its *plan of action* before execution (a signed capability request), receives a pre-authorization, executes under that pre-authorization, and then provides completion evidence. The two-stage protocol (authorize-then-verify) is stronger than the one-stage protocol (verify-after-commit) because it prevents execution of unauthorized work even when the commit is clean-looking. RAXIS's model means work has already been done before attestation occurs — the kernel can reject it, but the compute (and any side effects not captured by VCS) has already happened.

### Counterargument 4 — No Multi-Agent Attestation Chains

RAXIS v1 has one planner, one kernel, one operator. In a real RAXIS environment, Agent A's attested output becomes input to Agent B's attested task. B's `IntentRequest` should carry a reference to A's admitted `WitnessSubmission` as the authority for acting on A's work. RAXIS has no mechanism for this: `IntegrationMerge` handles the VCS merge case but does not link B's authority to A's prior attestation. If A's prior work was adversarially crafted to influence B, B's attestation exchange does not detect it — the kernel verifies B's scope against B's task, not against A's attested intent. This is the composition problem, and RAXIS does not solve it.

### Counterargument 5 — The Plan Must Be Fully Known Upfront

RAXIS should handle emergent, adaptive behavior: an agent that discovers new tasks at runtime, discovers it needs different tools, discovers the scope of work was wrong. RAXIS requires the operator to sign a plan (`plan.toml`) before execution. New tasks cannot be added mid-initiative without a new plan and new operator signature. In a real RAXIS system, the attestation framework must accommodate dynamic task discovery with attestation keeping pace — perhaps through a structured escalation-and-re-planning protocol. RAXIS's escalation mechanism is a partial answer (it can request capability expansion) but it cannot add new tasks, cannot modify the signed plan structure, and cannot accommodate fundamentally changed scope without a new ceremony. This limits RAXIS to problems whose shape is fully known before execution.

### Counterargument 6 — The Verifier Is Operator-Defined, Not Standardized

RAXIS's verifier protocol (`WitnessSubmission`, `result_class: Pass|Fail|Error`, `body: GateType-specific`) is specified in `raxis-types`. But it is a closed system — verifiers are operator-written binaries, the body schema is defined per `GateType` in RAXIS's own types crate, and there is no interoperability standard. RAXIS at a paradigm level requires a standardized attestation schema: one that allows an attestation produced by RAXIS's verifier to be verified by a different RAXIS-compliant system, and vice versa. Without this, RAXIS is a per-system silo, not an exchangeable protocol. W3C Verifiable Credentials, RATS (IETF RFC 9334), and DICE are existing standards in this space. RAXIS does not speak any of them.

### Counterargument 7 — The Planner Controls Its Own Evidence

The kernel independently verifies touched paths via `vcs::diff`. But the planner controls the VCS state that `vcs::diff` reads. A sophisticated planner that controls the worktree could construct commits that satisfy `path_allowlist` while concealing the actual effect of the code (e.g., a commit that touches only allowed paths but injects a backdoor that activates based on data not visible in the diff). The attestation exchange verifies *file scope*, not *semantic effect*. RAXIS would require semantic attestation — formal verification or semantic analysis of the action's effect relative to its claimed intent. RAXIS has no such mechanism. This is perhaps the deepest gap: the exchange proves the planner operated within a syntactic scope; it does not and cannot prove the planner's actions were semantically aligned with the task description.

### Counterargument 8 — The Kernel Is a Trusted Third Party, Not a Neutral Protocol

In RAXIS's strongest form, the attestation exchange is a protocol that does not require either party to trust a specific third-party implementation. The trust is in the cryptographic protocol, not in the kernel binary. RAXIS's kernel is a trusted third party: all attestation flows through it, it holds the authority keypair, it writes the audit ledger. If the kernel is compromised or malicious, the entire attestation scheme collapses without detection (see Counterargument 2). A true RAXIS protocol would be verifiable by any party holding the public keys and the audit log — even without the kernel being present or trustworthy. RAXIS's audit log is verifiable (chain integrity), but the log's completeness depends entirely on the kernel's honesty. A malicious kernel can simply not log a rejected intent.

### Summary of the Gap

| RAXIS property | RAXIS status |
|---|---|
| Intent must be explicitly declared before action | ✅ `IntentRequest` before admission |
| Verification is independent of attester's claims | ✅ `vcs::diff` + `path_allowlist` |
| Authority chain is human-anchored | ✅ Operator Ed25519 → signed plan → session |
| Third-party evidence attestation | ✅ Verifier subprocess, single-use token |
| Tamper-evident audit ledger | ✅ SHA-256 chained JSONL |
| Failure-closed semantics | ✅ All admission paths gated |
| Attester has cryptographic identity | ❌ Model is anonymous; session ≠ model |
| Hardware root of trust | ❌ Software-only; kernel is assumed trustworthy |
| Prospective attestation | ❌ Retrospective only (commit-then-verify) |
| Multi-agent attestation chains | ❌ No cross-session attestation linkage |
| Emergent task discovery | ❌ Plan must be fully signed upfront |
| Standardized attestation schema | ❌ Closed system (no W3C VC / RATS / DICE) |
| Semantic effect attestation | ❌ Syntactic scope only (diff-based) |
| Protocol-level trust (no trusted third party) | ❌ Kernel is the trust root; its honesty assumed |

---

## Conclusion

RAXIS is a rigorous, implementable, failure-closed proof of concept for the **lower half** of RAXIS: the runtime enforcement layer. It proves that you can enforce structured attestation exchanges between an LLM planner and a verification kernel, with full audit traceability and operator-anchored authority, in a working software system. That is not nothing — it is more than virtually any deployed AI agent system achieves today.

What RAXIS does not prove is the **upper half** of RAXIS: the parts that require hardware attestation, model identity, standardized interoperability, semantic verification, and multi-agent chain-of-custody. These are not implementation gaps — they are open research and standardization problems.

The honest framing: **RAXIS is a single-domain, software-only, retrospective, closed-system instantiation of RAXIS principles.** It demonstrates that the RAXIS pattern is buildable and practical. It does not demonstrate that RAXIS is solved.
