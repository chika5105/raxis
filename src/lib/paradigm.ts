// The 12 RAXIS paradigm invariants.
//
// These are sourced verbatim in shape from `raxis/specs/paradigm.md` §3 and
// `raxis/POSITIONING.md` §8. Copy is condensed to executive-readable form for
// the marketing site; the canonical, normative statements live in the spec.
//
// Anyone editing this list must also update `raxis/specs/paradigm.md` first
// (paradigm spec wins; this file is downstream).

export type InvariantGroup =
  | "Structural separation"
  | "Authority model"
  | "Accountability"
  | "Coordination & recovery";

export interface Invariant {
  id: string;
  name: string;
  group: InvariantGroup;
  oneLiner: string;
  rationale: string;
  example: string;
}

export const INVARIANTS: Invariant[] = [
  {
    id: "R-1",
    name: "Domain Separation",
    group: "Structural separation",
    oneLiner:
      "Intelligence and authority run in distinct execution domains with no shared mutable state.",
    rationale:
      "If the planner and the kernel share an address space, a single memory bug or in-process injection grants the LLM everything authority can do. The boundary must be enforced by an isolation primitive whose security does not depend on the model's correctness.",
    example:
      "The reference implementation runs every agent inside a Firecracker (Linux) or Apple Virtualization.framework (macOS) microVM. The kernel speaks only typed VSock IPC.",
  },
  {
    id: "R-2",
    name: "Mediated I/O",
    group: "Structural separation",
    oneLiner:
      "All credential, network, storage, and peer-agent access is mediated by authority through typed intents.",
    rationale:
      "I/O is how intelligence affects the world. If any I/O class is direct, every other guarantee — credential isolation, audit, budget enforcement — silently degrades for that class.",
    example:
      "The planner has no HTTP client in its dependency closure and no API keys. Every fetch and inference call goes planner → kernel → gateway, and the kernel logs each one before content returns.",
  },
  {
    id: "R-3",
    name: "Signed Capability Declaration",
    group: "Authority model",
    oneLiner:
      "Every capability is declared in a cryptographically signed policy artifact attributable to a human principal.",
    rationale:
      "Authority decisions must trace to a verifiable human authorization. Without signatures, policy is mutable by anyone with filesystem access; without explicit declaration, capabilities are inferred from prose, neither of which is auditable.",
    example:
      "Operators sign `policy.toml` with an Ed25519 key. The kernel rejects any artifact whose signature does not verify against an enrolled operator certificate.",
  },
  {
    id: "R-4",
    name: "Authority Derivation Hierarchy",
    group: "Authority model",
    oneLiner:
      "Sub-artifacts (plans, sub-policies, delegated sessions) may only narrow parent authority — never expand it.",
    rationale:
      "Cryptographic signing is meaningless if intermediate layers can grant capabilities the root did not authorize. Privilege escalation by composition breaks the chain of accountability.",
    example:
      "An orchestrator session that holds capability set C cannot mint a sub-session with capabilities outside C — the kernel enforces strict subset narrowing on every delegation.",
  },
  {
    id: "R-5",
    name: "Bounded Capabilities",
    group: "Authority model",
    oneLiner:
      "Every granted capability carries explicit numerical bounds (count, rate, value, time).",
    rationale:
      "An autonomous agent with even a permissible capability can cause unbounded harm if the capability has no ceiling. \"Send email\" without a rate limit can spam. \"Submit trade\" without a size cap can liquidate the firm.",
    example:
      "Every lane in policy carries `max_concurrent_tasks` and `max_cost_per_epoch`. Worst-case budget is reserved at intent admission; overage attempts fail closed.",
  },
  {
    id: "R-6",
    name: "Fail-Closed Default",
    group: "Authority model",
    oneLiner:
      "Ambiguity, missing policy, evaluation failure, and authority errors all resolve to deny.",
    rationale:
      "Fail-open systems silently admit actions when verification cannot complete — providing false assurance precisely when assurance matters most. A RAXIS that fails open is worse than no RAXIS.",
    example:
      "If the policy file is missing, the kernel refuses to start. If a verifier subprocess crashes, gates remain open and the task stays Blocked until an operator inspects.",
  },
  {
    id: "R-7",
    name: "Cryptographic Audit Chain",
    group: "Accountability",
    oneLiner:
      "Audit modifications are detectable by an independent verifier holding only the log and the operator's public keys.",
    rationale:
      "The audit log is the only evidence available after the fact. If it is mutable, it is useless — a compromised authority simply rewrites it. Detection must not depend on the authority that produced the log being alive or honest.",
    example:
      "Every audit record carries `prev_sha256`. Any single-byte modification breaks every subsequent hash. `raxis-audit-tools verify-chain` is a separate binary.",
  },
  {
    id: "R-8",
    name: "Auditable Decisions",
    group: "Accountability",
    oneLiner:
      "Authority decisions are reproducible from recorded inputs; ambient state is recorded with the decision.",
    rationale:
      "The log records decisions; it must also be sufficient to reconstruct them. Without reproducibility, a buggy or malicious authority can record one decision while having actually made another.",
    example:
      "Audit replay takes the log, signed policy, signed plans, and intent stream, and reproduces the same admission decisions byte-for-byte.",
  },
  {
    id: "R-9",
    name: "Attributable Intent",
    group: "Accountability",
    oneLiner:
      "Every intent traces to a verified intelligence identity. Anonymous intents are rejected.",
    rationale:
      "Without per-intent attribution, the audit log records actions without actors — proving what was admitted but not who requested it. That defeats accountability for intelligence-side compromise.",
    example:
      "Every IPC message carries a kernel-issued session token bound at session creation. Tokens are HMAC-signed; forged or stale tokens raise SecurityViolation events.",
  },
  {
    id: "R-10",
    name: "Opaque Rejection",
    group: "Accountability",
    oneLiner:
      "Agent-facing rejections never reveal which specific policy rule fired.",
    rationale:
      "If the agent learns exactly which rule fired, it can craft its next intent to just-barely satisfy each rule — gaming the verifier rather than complying with its spirit. Adversarial intelligence converges to the boundary of permitted behavior; opacity prevents the boundary from being mapped.",
    example:
      "The agent receives `FAIL_PATH_POLICY_VIOLATION`; the operator sees the exact glob in the audit log. Two views of the same rejection, asymmetric on purpose.",
  },
  {
    id: "R-11",
    name: "Mediated Coordination",
    group: "Coordination & recovery",
    oneLiner:
      "When multiple agents cooperate, they communicate through authority — not directly.",
    rationale:
      "Direct agent-to-agent channels create authority blind spots. A compromised orchestrator could coordinate with a compromised executor to exfiltrate data through a logging gap. Authority-mediated coordination preserves the audit chain across multi-agent flows.",
    example:
      "Orchestrator → Executor handoffs are kernel-mediated `ActivateSubTask` intents. Every cross-agent message is logged at the same fidelity as any other intent.",
  },
  {
    id: "R-12",
    name: "Out-of-Band Escalation",
    group: "Coordination & recovery",
    oneLiner:
      "Authority widening requires human approval through a channel intelligence cannot reach.",
    rationale:
      "Static authority is useless if it cannot be widened safely when an agent encounters legitimate work outside its scope. But widening must be human-mediated through a channel the model cannot manipulate — no email-reply approval, no in-prompt \"say yes,\" no shared chat.",
    example:
      "Escalations create a typed event the operator approves with a CLI signed by an Ed25519 key the model has no path to. Approval is a token consumed once and bound to the originating escalation.",
  },
];

export function invariantsByGroup(): Record<InvariantGroup, Invariant[]> {
  const groups: Record<InvariantGroup, Invariant[]> = {
    "Structural separation": [],
    "Authority model": [],
    "Accountability": [],
    "Coordination & recovery": [],
  };
  for (const inv of INVARIANTS) groups[inv.group].push(inv);
  return groups;
}
