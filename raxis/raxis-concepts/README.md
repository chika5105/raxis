# RAXIS Concepts

A complete guide to every core concept in the RAXIS kernel. Each document explains one concept from operator configuration through kernel enforcement, with edge cases and implementation gap analysis.

---

## Concept Guides

| # | Concept | What it covers |
|---|---------|---------------|
| [01](01-claims-and-gates.md) | **Claims & Gates** | Proof requirements, verifier subprocesses, witness records, auto-derivation fix |
| [02](02-intent-admission.md) | **Intent Admission** | The 13-step pipeline from request to acceptance |
| [03](03-credential-proxies.md) | **Credential Proxies** | Protocol-aware proxies (Postgres, HTTP, SMTP, Redis, AWS, GCP, Azure, MySQL, MSSQL, MongoDB) |
| [04](04-delegations-and-authority.md) | **Delegations & Authority** | Operator-signed capability grants, TTL, epoch staleness |
| [05](05-lanes-and-budgets.md) | **Lanes & Budgets** | Per-lane concurrency/cost limits, token-cost budgets, TOCTOU fix |
| [06](06-audit-chain.md) | **Audit Chain** | Hash-linked tamper-evident logging, chain verification |
| [07](07-escalations.md) | **Escalations** | Human-in-the-loop: request → park → approve/reject → resume |
| [08](08-sessions-and-isolation.md) | **Sessions & Isolation** | Session lifecycle, microVM isolation, system prompt assembly |
| [09](09-policy-configuration.md) | **Policy Configuration** | Every section of policy.toml, signing, hot reload, epochs |
| [10](10-v2-orchestration.md) | **V2 Orchestration** | Multi-agent DAG, Orchestrator/Executor/Reviewer, review loops, retry counters |

---

## Gaps Found During Documentation

Each concept guide includes a "Gap Found" section when an implementation gap was discovered during the analysis. Summary:

| Concept | Gap | Severity | Status |
|---------|-----|----------|--------|
| Claims & Gates | Planner hardcoded `submitted_claims: vec![]` | 🔴 Critical | **Fixed** — kernel auto-derives from witnesses |
| Credential Proxies | Per-request audit emit uses `warn!` not hard abort | 🟡 Low | Accepted deviation |
| Escalations | Cooldown timer not enforced after rejection | 🟡 Medium | Needs implementation |
| Sessions & Isolation | No proactive liveness monitoring (heartbeat) | 🟡 Medium | Needs implementation |

---

## How to Read

Each document follows the same structure:
1. **What is it?** — one-paragraph explanation
2. **Step by step** — operator configures → agent acts → kernel enforces
3. **Visual pipeline** — ASCII flow diagram
4. **Edge cases** — what happens when things go wrong
5. **Gap analysis** — implementation issues found during review
6. **Key source files** — where to look in the code
