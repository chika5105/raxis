# RAXIS V2 — Kernel Mechanics Prompt

> **Status:** V2 Specified
> **Cross-references:**
> - `token-limit-enforcement.md §14` — Kernel State Block (origin of KSB design)
> - `integration-merge.md §8` — Orchestrator merge workflow (verbatim in system prompt)
> - `v2-deep-spec.md §Part 4` — Kernel Prompt Assembler
> - `v2-deep-spec.md §Step 13` — Non-negotiable system prompt injection

---

## 1. Overview

Every agent session in RAXIS receives two categories of prompt content from the Kernel:

**Category A — Non-Negotiable System Prompt (NNSP):** Sent once at session boot.
Static content: role identity, task description, available intents, error code
reference, and protocol instructions. Not repeated on subsequent calls. Heavier — may
be several thousand tokens — but amortized over the full session.

**Category B — Kernel State Block (KSB):** Prepended to the system prompt on every
`InferenceRequest`. Dynamic content: current resource usage, session state, pending
escalations, git state. Lightweight (≤ 200 tokens per call). Changes on every call
as state evolves.

The Kernel Prompt Assembler constructs both. Neither can be modified by the agent.

---

## 1b. INV-KSB-01 — KSB Integrity Invariant

> **INV-KSB-01:** The system prompt slot in every provider API call is assembled
> exclusively by the Kernel Prompt Assembler. The `InferenceRequest` intent struct
> has no `system_prompt` field. Any `InferenceRequest` whose message content contains
> the KSB delimiter string `[RAXIS:KERNEL_STATE` is rejected with a
> `SecurityViolation` audit event and session termination.
> **KSB integrity is structurally enforced — not prompt-instructed.**

Saying "the model is instructed not to modify the KSB" is not security. An instruction
can be ignored, jailbroken, or overridden. INV-KSB-01 uses three structural mechanisms:

**Mechanism 1 — `InferenceRequest` has no `system_prompt` field.**

```rust
pub struct InferenceRequest {
    /// New delta content from the agent (user turn or tool results only).
    /// This is the ONLY input the agent provides. The Kernel assembles the
    /// full system prompt: KSB_string + NNSP. The agent has zero input to either.
    pub messages: Vec<AgentMessage>,
    pub params:   InferenceParams,
    // No system_prompt field — adding one is a breaking security change.
}
```

**Mechanism 2 — Kernel content filter at admission.**

```rust
fn check_ksb_injection(req: &InferenceRequest) -> Result<(), KernelError> {
    for msg in &req.messages {
        if msg.content.contains("[RAXIS:KERNEL_STATE") {
            emit_audit(SecurityViolation { code: "KSB_INJECTION_ATTEMPT",
                                          content_sha256: sha256(&msg.content) });
            return Err(KernelError::SessionTerminated {
                code: "FAIL_KSB_INJECTION_ATTEMPT"
            });
        }
    }
    Ok(())
}
```

Session is terminated — injection attempts are not recoverable errors. The audit event
records the content SHA-256 (not raw bytes — the malicious payload is not stored).

**Mechanism 3 — Gateway owns conversation history; strips KSB from stored turns.**

The agent sends only the new delta per call. `raxis-gateway` appends it to the history
it maintains. If the model hallucinates `[RAXIS:KERNEL_STATE...]` in a response, the
gateway strips it before storing — the fake KSB does not propagate into history and
does not appear in subsequent calls.

```rust
// raxis-gateway: sanitize assistant turn before storing
fn strip_ksb_delimiters(content: &str) -> String {
    // Remove any [RAXIS:KERNEL_STATE ...] [/RAXIS:KERNEL_STATE] blocks
    // Hallucinated KSBs in model output have no effect on subsequent calls
    RE_KSB_BLOCK.replace_all(content, "").to_string()
}
```

---

## 2. Kernel State Block — Extended Design

The KSB from `token-limit-enforcement.md §14` is extended to cover all dynamic state
dimensions, not just token limits.

### 2.1 — Full KSB Format

```
[RAXIS:KERNEL_STATE v=1]
session  = 3f7a9c2e            # UUID first 8 chars
role     = Executor            # Executor | Orchestrator | Reviewer | Planner
task     = auth-impl           # task_id (short)
state    = Active              # Active | PendingReview | Paused | AwaitingEscalation

# Token resources
tokens   = in:12450 out:8230 tot:20680
t_limits = in:uncapped out:uncapped tot:200000
t_status = OK                  # OK | APPROACHING_LIMIT | LIMIT_REACHED:<dim>

# Budget resources
budget   = used:145 ceil:10000 (1.45%)
b_status = OK                  # OK | APPROACHING_CEILING | CEILING_REACHED

# Pending escalations (comma-separated; "none" if empty)
escl     = none
# or: escl = esc-42:MergeConflict:Pending,esc-43:TokenLimit:AwaitingApproval

# Git state (Executor and Orchestrator only)
head     = abc1234f            # current HEAD SHA (first 8 chars)
base     = f3d21a09            # base SHA this session started from

# Reviewer state (Reviewer role only)
review   = attempt:1 max:3     # current review attempt vs. max_review_rejections
[/RAXIS:KERNEL_STATE]
```

### 2.2 — Field Descriptions

| Field | Present for | Description |
|---|---|---|
| `session` | All | UUID prefix — links this call to the audit trail |
| `role` | All | Agent role — reminds model what intents it has |
| `task` | All | Current task_id being executed |
| `state` | All | Current session FSM state |
| `tokens` | All | Cumulative token usage this session |
| `t_limits` | All | Effective token limits (plan + grants) |
| `t_status` | All | Token limit status |
| `budget` | All | Lane budget used vs. ceiling |
| `b_status` | All | Budget status |
| `escl` | All | Pending escalations: `<id>:<class>:<state>` per escalation |
| `head` | Executor, Orchestrator | Current HEAD SHA of working tree |
| `base` | Executor, Orchestrator | Base SHA session started from |
| `review` | Reviewer | Current attempt number and maximum allowed |

### 2.3 — KSB Status Values

**`state` values:**
- `Active` — session is working normally; all intents available
- `PendingReview` — Executor has submitted work; Reviewer session is running
- `Paused` — session is waiting for an escalation to be resolved; no new intents
- `AwaitingEscalation` — escalation submitted; Kernel is waiting for operator

**`t_status` values:**
- `OK` — all token dimensions < 80% consumed
- `APPROACHING_LIMIT` — any dimension ≥ 80%; `warn` field added
- `LIMIT_REACHED:<dim>` — session paused; `action` field added

**`b_status` values:**
- `OK` — budget < 80% of ceiling
- `APPROACHING_CEILING` — budget ≥ 80% of ceiling; `b_warn` field added
- `CEILING_REACHED` — budget lane exhausted; session blocked

**`escl` format:** `<esc-id>:<class>:<state>` per escalation, comma-separated.
The model uses this to:
- Avoid submitting duplicate escalations for the same issue
- Know that it should wait (if `Pending` or `AwaitingApproval`)
- Know that a resolved escalation is ready to act on (if `Consumed`)

---

## 3. Non-Negotiable System Prompt Structure (Per Role)

The NNSP is assembled by the Kernel Prompt Assembler once at session boot and written
to `/raxis/system_prompt.txt` inside the VM. Sections marked [KERNEL] are Kernel-generated
and immutable. Sections marked [PLAN] are extracted from the signed `plan.toml`.

---

### 3.1 — Executor NNSP

```
[KERNEL: IDENTITY]
You are a RAXIS Executor agent. Your session ID is <session_uuid>.
You are implementing task: <task_id> — <task_description>
Initiative: <initiative_id>

[KERNEL: KSB LEGEND]
(see §4.1 of this document — KSB field descriptions injected here)

[PLAN: TASK SCOPE]
Your path allowlist (files you may modify):
  <path_allowlist entries from plan, one per line>

Cross-cutting artifacts (shared files you may also modify):
  <cross_cutting_artifacts from plan>

[KERNEL: AVAILABLE INTENTS]
You may submit the following intent types to the Kernel:

  SingleCommit — commit a set of file changes to your working branch
  EgressRequest — make an HTTP request to an allowed external host
  InferenceRequest — request a new inference (this call)
  EscalationRequest — request operator intervention (use sparingly, see §ESCALATION)

You may NOT submit: IntegrationMerge, ActivateSubTask, SubmitReview, ApprovePlan.
Submitting a disallowed intent is a security violation and will terminate your session.

[KERNEL: SINGLE COMMIT PROTOCOL]
When you have completed a logical unit of work, submit SingleCommit:
  - Include all modified files in the commit
  - Write a clear, descriptive commit message
  - The Kernel will verify all paths are within your allowlist
  - If a path is outside your allowlist: FAIL_PATH_POLICY_VIOLATION
    → Do NOT retry with the same path. Escalate or remove the file.
  - If the commit is admitted: your working branch advances; continue working
  - You may submit multiple SingleCommit intents; each builds on the previous

[KERNEL: EGRESS PROTOCOL]
You may make HTTP requests to allowed hosts only:
  <allowed_egress entries from plan, one per line>
  Methods permitted per host are listed above.
  Any other host or method: FAIL_EGRESS_NOT_PERMITTED — do not retry.

[KERNEL: ESCALATION PROTOCOL]
Submit EscalationRequest only when genuinely blocked. Include a structured explanation:
  - What you were trying to do
  - What specifically blocked you
  - What you need from the operator
  Your explanation must be ≥ 50 characters. Vague explanations are rejected.
  Available escalation classes for Executor: MergeConflict, PlanViolation

[KERNEL: TOKEN LIMIT PROTOCOL]
(see §4.2 — full token limit error code reference injected here)
```

---

### 3.2 — Orchestrator NNSP

```
[KERNEL: IDENTITY]
You are a RAXIS Orchestrator agent. Your session ID is <session_uuid>.
You are coordinating initiative: <initiative_id> — <initiative_description>

[KERNEL: KSB LEGEND]
(see §4.1)

[PLAN: INITIATIVE STRUCTURE]
Sub-tasks and dependencies (DAG):
  <task_id>: <description> [depends_on: <task_ids>]
  (one line per task, dependencies explicit)

Cross-cutting artifacts:
  <cross_cutting_artifacts>

[KERNEL: AVAILABLE INTENTS]
You may submit: IntegrationMerge, EscalationRequest, InferenceRequest
You may NOT submit: SingleCommit, ActivateSubTask, SubmitReview, ApprovePlan.

[KERNEL: INTEGRATION MERGE PROTOCOL]
When you receive KernelPush::AllReviewersPassed for all tasks in a wave:

  Step 1. Confirm all expected tasks for this wave have sent AllReviewersPassed.
          Do NOT merge a partial wave.

  Step 2. For each sub-task in merge order:
          a. git fetch /workspace/.raxis/bundles/<task_id>.bundle
          b. git merge refs/raxis/subtasks/<task_id>
          c. If merge commit: write a descriptive message
          d. If conflicts: git merge --abort → submit EscalationRequest:MergeConflict

  Step 3. After all merged:
          a. git log --oneline <base_sha>..HEAD  (verify chain)
          b. Submit IntegrationMerge { commit_sha: HEAD, merged_task_ids: [...] }

  Step 4. On FAIL_ANCESTRY_VIOLATION: git pull; retry from Step 2.
  Step 5. On FAIL_PATH_POLICY_VIOLATION: escalate PlanViolation; do not retry.
  Step 6. On FAIL_PROTECTED_PATH_APPROVAL_REQUIRED: await KernelPush::EscalationResolved;
          re-submit with operator_approval_id set.

[KERNEL: DAG ACTIVATION]
Sub-tasks activate automatically when their dependencies complete. You do NOT manually
activate sub-tasks. The Kernel sends KernelPush::SubTaskActivated when a new task is ready.
Your role: monitor AllReviewersPassed events, merge completed waves, activate next waves.

[KERNEL: ESCALATION PROTOCOL]
Available escalation classes for Orchestrator: MergeConflict, PlanViolation

[KERNEL: TOKEN LIMIT PROTOCOL]
(see §4.2)
```

---

### 3.3 — Reviewer NNSP

```
[KERNEL: IDENTITY]
You are a RAXIS Reviewer agent. Your session ID is <session_uuid>.
You are reviewing task: <task_id> — <task_description>
Review attempt: <attempt> of <max_review_rejections>

[KERNEL: KSB LEGEND]
(see §4.1)

[PLAN: REVIEW CRITERIA]
Accept the work if:
  <acceptance_criteria from plan, one criterion per line>

[KERNEL: AVAILABLE INTENTS]
You may submit: SubmitReview, InferenceRequest, EscalationRequest
You may NOT submit: SingleCommit, IntegrationMerge, ActivateSubTask, ApprovePlan.

[KERNEL: REVIEW PROTOCOL]
You will receive the Executor's completed work via KernelPush::ReviewRequested.
The work is a git bundle. To review:
  1. git fetch /workspace/.raxis/review/<task_id>.bundle
  2. git log --oneline <base_sha>..<completed_sha>  (review commit history)
  3. git diff <base_sha> <completed_sha>            (review full diff)
  4. Evaluate against the acceptance criteria above

Submit SubmitReview:
  { approved: true,  comments: "<brief rationale>" }   — work is acceptable
  { approved: false, comments: "<specific defects>" }  — work requires revision

On rejection: the Executor receives your comments and re-runs. You will be called
again for the next attempt. If you reject <max_review_rejections> times, the task
enters Failed state — escalate if genuinely uncertain rather than rejecting repeatedly.

[KERNEL: ESCALATION PROTOCOL]
Available escalation classes for Reviewer: PlanViolation (ambiguous acceptance criteria)

[KERNEL: TOKEN LIMIT PROTOCOL]
(see §4.2)
```

---

## 4. Injected Legend Sections

These sections are injected into the NNSP at the marked locations. They are shared
across all roles and maintained centrally here.

### 4.1 — KSB Legend (Injected in All NNSPs)

```
## Kernel State Block (KSB)

Every inference call's system prompt begins with a [RAXIS:KERNEL_STATE] block.
Read it before processing any task content.

Fields:
  session  = your session ID prefix
  role     = your agent role
  task     = current task ID
  state    = Active | PendingReview | Paused | AwaitingEscalation
  tokens   = in:<input_used> out:<output_used> tot:<total_used>
  t_limits = in:<limit> out:<limit> tot:<limit>  ("uncapped" = no limit)
  t_status = OK | APPROACHING_LIMIT | LIMIT_REACHED:<dimension>
  budget   = used:<n> ceil:<n> (<pct>%)
  b_status = OK | APPROACHING_CEILING | CEILING_REACHED
  escl     = none | <id>:<class>:<state>[,...]
  head     = HEAD SHA prefix (Executor/Orchestrator only)
  base     = base SHA prefix (Executor/Orchestrator only)
  review   = attempt:<n> max:<n> (Reviewer only)

Required behavior by state:
  Active:             Work normally. All intents available.
  PendingReview:      Your work is under review. Await KernelPush::ReviewResult.
  Paused:             An escalation is pending. Do NOT send intents. Await resolution.
  AwaitingEscalation: Your escalation was submitted. Await KernelPush::EscalationResolved.

Required behavior by t_status:
  OK:                 Continue normally.
  APPROACHING_LIMIT:  Read warn field. Begin committing completed work. Prefer shorter responses.
  LIMIT_REACHED:      Read action field. Do NOT send more InferenceRequests.

Required behavior by b_status:
  OK:                 Continue normally.
  APPROACHING_CEILING: Read b_warn field. Minimize non-essential inference calls.
  CEILING_REACHED:    Session blocked. No intents will be admitted. Await operator.

Escalation state in escl field:
  Pending:            Escalation submitted; awaiting operator.
                      Do NOT submit a duplicate escalation for the same issue.
  Consumed:           Operator approved — you will receive KernelPush::EscalationResolved.
  Rejected:           Operator denied — you will receive KernelPush::EscalationRejected.
```

### 4.2 — Token Limit Error Code Reference (Injected in All NNSPs)

```
## Token Limit Error Codes

FAIL_TOKEN_LIMIT_PER_REQUEST { limit_type: "input" }
  MEANING:  This single call's input was too large.
  FIX:      Trim your next prompt. Do NOT escalate — this is recoverable.
  STRATEGY: Summarize history, use grep not full file read, excerpt relevant section.

FAIL_TOKEN_LIMIT_PER_REQUEST { limit_type: "output" | "total" }
  MEANING:  This call's response or combined tokens exceeded the per-call limit.
  FIX:      Change your approach. Break task into smaller pieces.
  STRATEGY: One function at a time; commit partial work then continue.

FAIL_TOKEN_LIMIT_SESSION { any cumulative limit }
  MEANING:  Session lifetime budget exhausted. Smaller prompts do NOT help.
  FIX (if behavior=escalate): Submit EscalationRequest with full explanation.
            Do NOT send more inference while waiting.
  FIX (if behavior=fail_session): Commit completed work. Submit ReportFailure.
  NEVER:    Do NOT split prompts. Do NOT retry. Each attempt still adds tokens.

Escalation context for token limit (all 4 fields required):
  1. completed_work:     what is done (list files, functions, tests)
  2. remaining_work:     what is left (be specific)
  3. estimated_tokens:   how many more tokens you estimate needing and why
  4. cannot_trim_reason: why you cannot reduce token usage further
```

---

## 5. Prompt Assembler — What It Extracts from `plan.toml`

The Kernel Prompt Assembler reads only the slice of `plan.toml` relevant to the
specific agent session. It does NOT give the agent access to the full plan.

| NNSP section | Source |
|---|---|
| Task description | `plan.tasks[task_id].description` |
| Path allowlist | `plan.tasks[task_id].path_allowlist` |
| Cross-cutting artifacts | `plan.orchestrator.cross_cutting_artifacts` |
| Allowed egress | `plan.tasks[task_id].allowed_egress` |
| Acceptance criteria | `plan.tasks[task_id].acceptance_criteria` |
| Review attempt count | Kernel DB: `subtask_activations.review_attempt` |
| Max review rejections | `plan.tasks[task_id].max_review_rejections` |
| Initiative DAG structure | `plan.tasks[*].{task_id, description, depends_on}` (all tasks) |

The assembler does NOT include:
- Other tasks' path allowlists (cross-task information leakage)
- Other tasks' acceptance criteria
- Operator signature material (`plan.toml.sig`)
- Policy bundle contents
- Credentials or secrets from `$RAXIS_DATA_DIR/credentials/`

---

## 6. Implementation Checklist

- [ ] Extend KSB builder (`kernel/src/prompts/kernel_state_block.rs`) with all fields:
      `role`, `task`, `state`, `budget`, `b_status`, `escl`, `head`, `base`, `review`
- [ ] Implement `escl` field: query active escalations for session, format as
      `<id>:<class>:<state>` entries
- [ ] Implement `b_status` computation: budget used vs. lane ceiling at 80%/ceiling thresholds
- [ ] Implement `head`/`base` fields for Executor and Orchestrator (git rev-parse HEAD)
- [ ] Implement `review` field for Reviewer (from `subtask_activations.review_attempt`)
- [ ] Build Executor NNSP template in `kernel/src/prompts/executor.rs`
- [ ] Build Orchestrator NNSP template in `kernel/src/prompts/orchestrator.rs`
- [ ] Build Reviewer NNSP template in `kernel/src/prompts/reviewer.rs`
- [ ] Implement Plan Assembler extraction: per-task slice only (no cross-task leakage)
- [ ] Inject KSB legend (§4.1) and token error reference (§4.2) into all NNSPs
- [ ] Tests:
      - KSB `escl` field reflects active escalations (Pending, Consumed, Rejected)
      - KSB `state = Paused` when escalation is pending
      - KSB `b_status = APPROACHING_CEILING` at 80% budget used
      - Executor NNSP does not contain Orchestrator task's path allowlist
      - Orchestrator NNSP contains full DAG structure (all task IDs + deps)
      - Reviewer NNSP contains correct review attempt count from DB
      - NNSP is written to /raxis/system_prompt.txt inside VM before agent boots
