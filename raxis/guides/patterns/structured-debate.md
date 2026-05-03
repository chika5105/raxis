# Pattern: Structured Debate

> **Complexity:** ⭐⭐⭐ Advanced | **Agents:** 2+ Proposers, 1 Synthesizer, 1 Implementer, Orchestrator
>
> Two agents argue a design across N rounds by writing proposal documents to the git
> worktree. A third agent synthesizes the debate into a final design. A fourth implements it.
> All communication is file-mediated — no agent ever speaks to another directly.

---

## When to Use

- The design space has genuine trade-offs with no obvious right answer
- You want to surface competing architectural perspectives before committing to implementation
- The cost of a wrong design choice is high (security architecture, data model, API surface)
- You have budget for the extra inference turns the debate consumes

## When Not to Use

- The design is already settled — debate is wasted compute
- You need consensus (the debate always ends with the Synthesizer making a call regardless)
- You want unlimited debate rounds — the plan is static, rounds must be declared upfront

---

## Core Mechanic: File-Mediated Argument

Agents communicate exclusively through the git worktree. There is no message passing.

```
Round 1:
  Proposer A boots  → reads nothing (first mover) → writes proposal-a-r1.md → CompleteTask
  Orchestrator merges A's commit
  Proposer B boots  → reads proposal-a-r1.md → writes proposal-b-r1.md → CompleteTask
  Orchestrator merges B's commit

Round 2:
  Proposer A boots  → reads proposal-a-r1.md AND proposal-b-r1.md → writes proposal-a-r2.md
  Orchestrator merges A's commit
  Proposer B boots  → reads all three prior proposals → writes proposal-b-r2.md

Synthesis:
  Synthesizer boots → reads all 4 proposals → writes final-design.md

Implementation:
  Implementer boots → reads final-design.md → implements
```

Each agent's clone is provisioned AFTER the Orchestrator merges the previous round. So
every subsequent agent has access to everything written so far — through normal git history,
not through any message channel.

---

## The Plan (2-Round Debate)

```toml
[workspace]
name    = "Auth module design debate"
lane_id = "auth-design"
description = """
  Two architects debate the auth module design before an Executor implements it.
  The debate covers: JWT vs session tokens, Redis vs in-memory state, and
  token refresh strategy. Two rounds, then synthesis, then implementation.
"""

# ── Orchestrator ──────────────────────────────────────────────────────────────
[[tasks]]
task_id            = "orchestrator"
session_agent_type = "Orchestrator"
clone_strategy     = "full"                  # MUST be full or blobless; never sparse
path_allowlist     = ["docs/design/", "src/auth/"]
cross_cutting_artifacts = ["Cargo.lock"]

# ── Round 1: Initial Positions ────────────────────────────────────────────────

[[tasks]]
task_id            = "proposer_a_r1"
session_agent_type = "Executor"
clone_strategy     = "blobless"              # needs to READ the full repo for context
path_allowlist     = ["docs/design/proposal-a-r1.md"]   # can only WRITE this file
depends_on         = []
context            = """
  You are Architect A, advocating for a JWT-based, stateless auth design.
  Read the existing codebase in src/ for context.
  Write a structured design proposal to docs/design/proposal-a-r1.md covering:
  - Token format and signing strategy
  - Refresh token handling
  - State management approach (stateless vs stateful)
  - Failure modes and revocation
  Make a clear recommendation with specific implementation details.
"""

[[tasks]]
task_id            = "proposer_b_r1"
session_agent_type = "Executor"
clone_strategy     = "blobless"
path_allowlist     = ["docs/design/proposal-b-r1.md"]
depends_on         = ["proposer_a_r1"]       # waits until A's proposal is merged
context            = """
  You are Architect B, advocating for a session-based, stateful auth design.
  Read docs/design/proposal-a-r1.md carefully — understand A's position before responding.
  Write a structured counter-proposal to docs/design/proposal-b-r1.md covering the same
  four areas. Address A's proposal directly: where do you agree, where do you disagree,
  and why is your approach superior for this use case?
"""

# ── Round 2: Rebuttals ────────────────────────────────────────────────────────

[[tasks]]
task_id            = "proposer_a_r2"
session_agent_type = "Executor"
clone_strategy     = "blobless"
path_allowlist     = ["docs/design/proposal-a-r2.md"]
depends_on         = ["proposer_b_r1"]       # waits for B's round-1 counter-proposal
context            = """
  You are Architect A. Read both round-1 proposals:
    - docs/design/proposal-a-r1.md  (your initial position)
    - docs/design/proposal-b-r1.md  (B's counter-proposal)
  Write a revised position to docs/design/proposal-a-r2.md.
  - Acknowledge any valid points B raised
  - Sharpen your argument where B's criticism was weak
  - If B raised a concern you cannot rebut, concede it explicitly
"""

[[tasks]]
task_id            = "proposer_b_r2"
session_agent_type = "Executor"
clone_strategy     = "blobless"
path_allowlist     = ["docs/design/proposal-b-r2.md"]
depends_on         = ["proposer_a_r2"]
context            = """
  You are Architect B. Read all three prior proposals:
    - docs/design/proposal-a-r1.md
    - docs/design/proposal-b-r1.md  (your initial position)
    - docs/design/proposal-a-r2.md  (A's rebuttal)
  Write a final rebuttal to docs/design/proposal-b-r2.md. This is your last word.
"""

# ── Synthesis ─────────────────────────────────────────────────────────────────
# The Synthesizer reads all 4 proposals and makes a definitive design decision.
# It does not debate — it decides. Its output is the spec the Implementer follows.

[[tasks]]
task_id            = "design_synthesizer"
session_agent_type = "Executor"
clone_strategy     = "blobless"
path_allowlist     = ["docs/design/final-design.md"]
depends_on         = ["proposer_a_r2", "proposer_b_r2"]   # waits for BOTH round-2 proposals
context            = """
  You are the Design Synthesizer. Read all four debate proposals:
    - docs/design/proposal-a-r1.md
    - docs/design/proposal-b-r1.md
    - docs/design/proposal-a-r2.md
    - docs/design/proposal-b-r2.md
  Write a final, authoritative design to docs/design/final-design.md.
  Your job is NOT to pick a side — it is to produce the best design given all arguments.
  You may hybridize (e.g., JWT for access tokens, session store for refresh tokens).
  The final-design.md must be specific enough for an Implementer to follow without ambiguity.
  Structure: Decision, Rationale, Implementation Spec, Open Questions (if any).
"""

# ── Optional: Design Reviewer ─────────────────────────────────────────────────
# Reviews the synthesized design document before implementation begins.
# Catch logical inconsistencies or security issues in the design itself.

[[tasks]]
task_id            = "design_reviewer"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["docs/design/final-design.md"]
depends_on         = ["design_synthesizer"]
context            = """
  Review docs/design/final-design.md before implementation begins.
  Check for: logical inconsistencies, missing failure modes, security antipatterns,
  and ambiguities that would block the Implementer.
  Approve if the design is implementable as written. Reject with specific critique if not.
"""

# ── Implementation ────────────────────────────────────────────────────────────

[[tasks]]
task_id            = "auth_implementer"
session_agent_type = "Executor"
clone_strategy     = "sparse"                # only needs src/auth/ to write
path_allowlist     = ["src/auth/"]
depends_on         = ["design_reviewer"]     # depends on Reviewer, not Synthesizer directly
                                             # (Reviewer is the last gate before impl)
max_crash_retries     = 2
max_review_rejections = 2
context            = """
  Implement the auth module as specified in docs/design/final-design.md.
  You have read access to the full repository. Your write access is scoped to src/auth/.
  Follow the design document exactly. If you find an ambiguity, pick the simpler
  interpretation and note it in a code comment.
"""

# ── Implementation Reviewer ───────────────────────────────────────────────────

[[tasks]]
task_id            = "impl_reviewer"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["src/auth/"]
depends_on         = ["auth_implementer"]
context            = """
  Review the auth implementation in src/auth/ against the design in
  docs/design/final-design.md. Verify the implementation matches the design decisions.
  Also check: tests present, no obvious security issues in the implementation.
"""
```

---

## The Synthesizer in Detail

The Synthesizer is the most important agent in this pattern. Its quality determines whether
the debate produced value. Here is a concrete example of what it sees and what it should produce.

### What the Synthesizer Reads (its worktree at boot)

When the Synthesizer VM boots, the Orchestrator has already merged all four proposal commits.
The Synthesizer's clone contains:

```
docs/design/
  proposal-a-r1.md    ← A's initial JWT position
  proposal-b-r1.md    ← B's initial session-token counter-position
  proposal-a-r2.md    ← A's rebuttal
  proposal-b-r2.md    ← B's final word
```

The Synthesizer reads all four files in its first inference turn.

### System Prompt (written by Kernel Prompt Assembler to `.raxis/system_prompt.txt`)

```
ROLE: Design Synthesizer
TASK ID: design_synthesizer
PATH ALLOWLIST: docs/design/final-design.md
WRITE RESTRICTION: You may ONLY write to docs/design/final-design.md.

OPERATOR CONTEXT:
You are the Design Synthesizer for the auth module debate. Two architects have argued
their positions across two rounds. Your job is not to pick a winner — it is to produce
the best design given all arguments. You are the final decision-maker.

PROCEDURE:
1. Read all four proposal documents in docs/design/.
2. Identify the strongest arguments from each position.
3. Identify where the debaters actually agreed (they often agree more than they think).
4. Make a definitive design decision. You may hybridize if that is genuinely better —
   but a clear hybrid is better than a vague compromise.
5. Write the final design to docs/design/final-design.md.
6. Submit CompleteTask when the file is written and complete.

FINAL DESIGN STRUCTURE (required):
## Decision
  One paragraph. What did you decide and why?

## What Both Sides Got Right
  Brief acknowledgment of valid points from each.

## Rejected Arguments
  What arguments did you find unpersuasive, and why?

## Implementation Specification
  Specific enough that the Implementer can follow it without ambiguity.
  Include: data structures, function signatures, error handling conventions,
  state management approach, and any external dependencies.

## Open Questions
  Any decisions left to the Implementer's judgment. Minimize this section.
```

### Example Synthesizer Output (`docs/design/final-design.md`)

```markdown
# Auth Module — Final Design Decision

## Decision

Hybrid approach: short-lived JWTs (15m) for access tokens, opaque refresh tokens
stored in Redis with a 7-day TTL. A's stateless access token argument is correct
for horizontal scaling; B's stateful refresh token argument is correct for revocation.
These are not mutually exclusive — they solve different parts of the problem.

## What Both Sides Got Right

**Architect A:** Stateless access tokens eliminate per-request database lookups on
the hot path. Correct. The 15-minute window makes stolen tokens self-expiring.

**Architect B:** Refresh token revocation requires server-side state. Correct.
JWT-only systems cannot revoke sessions without a blocklist, which defeats the
stateless claim anyway. A Redis store for refresh tokens is the right scope.

## Rejected Arguments

**A's "JWTs are simpler":** Simple to issue, not simple to operate. Key rotation,
algorithm pinning, and the HS256/RS256 choice add operational complexity A did not
address.

**B's "session IDs are more auditable":** Both approaches are equally auditable if
the refresh token store logs issuance and consumption events. Auditability is an
implementation choice, not a token format property.

## Implementation Specification

### Access Tokens
- Format: JWT, RS256 (asymmetric — public key distributable to other services)
- TTL: 15 minutes, encoded in `exp` claim
- Claims: `sub` (user_id), `jti` (unique token ID), `iat`, `exp`, `scope`
- Signing key: loaded from `$RAXIS_DATA_DIR/keys/auth_signing.pem` at startup

### Refresh Tokens
- Format: opaque 32-byte random token, hex-encoded (64 chars)
- Storage: Redis hash `refresh:<token_hex>` with fields:
    `user_id`, `issued_at`, `expires_at`, `revoked` (bool)
- TTL: 7 days, set on the Redis key itself (auto-expiry)
- Rotation: every refresh call issues a NEW refresh token and revokes the old one

### Function Signatures (Rust)
```rust
pub async fn issue_tokens(user_id: UserId, scope: Scope)
    -> Result<TokenPair, AuthError>;

pub async fn refresh(refresh_token: &str)
    -> Result<TokenPair, AuthError>;  // returns both new access + new refresh

pub async fn revoke(refresh_token: &str)
    -> Result<(), AuthError>;

pub async fn verify_access(jwt: &str)
    -> Result<Claims, AuthError>;
```

### Error Handling
All functions return `AuthError` from `src/auth/error.rs`. Add variants:
`InvalidRefreshToken`, `ExpiredRefreshToken`, `RevokedRefreshToken`.
Do NOT expose internal Redis errors in `AuthError` — log them and return
`AuthError::Internal`.

## Open Questions

1. Key rotation schedule: left to the operator. The implementation should support
   reading a new signing key from the key path on SIGHUP without restart.
2. Redis cluster vs. single instance: left to infrastructure. The client should
   accept a Redis URL from environment.
```

---

## Execution Flow

```
approve_plan validates:
  ✓ DAG: a_r1 → b_r1 → a_r2 → b_r2 → synthesizer → design_reviewer → implementer → impl_reviewer
  ✓ Path subset: all proposal/design paths ⊆ orchestrator's ["docs/design/", "src/auth/"]
  ✓ No cycle
  ✓ Orchestrator clone_strategy = "full" (not sparse)

Kernel boots Orchestrator

Round 1:
  Orchestrator activates proposer_a_r1
  → A writes proposal-a-r1.md, CompleteTask
  → Orchestrator merges A's commit (no conflict; file is new)
  → Orchestrator activates proposer_b_r1
  → B reads proposal-a-r1.md from its clone (it was merged before B booted)
  → B writes proposal-b-r1.md, CompleteTask
  → Orchestrator merges B's commit

Round 2: (same pattern with both prior files visible in each clone)

Synthesizer:
  → Reads all 4 proposals
  → Writes final-design.md, CompleteTask
  → Orchestrator merges

Design Reviewer:
  → Evaluates final-design.md
  → Approve: impl activates
  → Reject with critique: Synthesizer retries with critique prepended to its prompt

Implementer → impl_reviewer → IntegrationMerge → master updated
```

---

## Invariant Checklist

- [x] No agent-to-agent communication — all information flows through merged git commits
- [x] Orchestrator uses `full` clone (required for multi-branch merges)
- [x] Proposers use `blobless` clone (need read access to prior proposals, not `sparse`)
- [x] Each proposer's `path_allowlist` is a single file — they cannot overwrite each other
- [x] Debate proposals are dependency-ordered: B cannot start until A's commit is merged
- [x] `UNION(all path_allowlists) ⊆ orchestrator path_allowlist` — validated at approve_plan
- [x] `synthesizer depends_on ["proposer_a_r2", "proposer_b_r2"]` — waits for BOTH
- [x] Single `lane_id` at workspace level

---

## Key Constraints to Understand

### Rounds Must Be Fixed at Plan-Signing Time

The plan is static. You must declare how many debate rounds you want before the initiative
starts. You cannot have agents decide mid-flight to add a third round.

**Consequence:** The Synthesizer always produces a final design regardless of whether the
debaters reached consensus. This is correct — the Synthesizer is not a mediator waiting for
agreement. It is a decision-maker that reads the arguments and chooses. If the debate was
inconclusive, the Synthesizer makes a judgment call. This produces a deterministic output
at the end of the DAG regardless of debate quality.

### Read vs. Write Access

Path allowlists restrict **writing only**. Agents can read any file in their git clone.
This is how Proposer B reads Proposer A's proposal — it is in the repo history after the
Orchestrator merges it. You do not need to add `docs/design/proposal-a-r1.md` to Proposer
B's `path_allowlist` — that would be a write permission, not a read permission.

### Clone Strategy Matters for Read Access

If Proposer B uses `sparse` checkout configured only for `docs/design/proposal-b-r1.md`,
it will NOT have `docs/design/proposal-a-r1.md` in its working tree. Use `blobless` for
all debaters so they have the full tree available for reading.

---

## Variant: Parallel Panel Review Instead of Sequential Debate

If you want multiple perspectives on a single design *without* the sequential back-and-forth,
see [Panel Review](panel-review.md). Panel review is faster (parallel execution) but produces
independent critiques rather than an iterative argument.

---

## Variant: 3-Way Debate

For three competing positions, extend the pattern:

```
a_r1 → b_r1 → c_r1 → a_r2 → b_r2 → c_r2 → synthesizer
```

Each agent waits for all prior agents in that round before it starts (or just for the
immediately prior agent, for a rolling sequential structure). Both are valid DAG topologies.
