# RAXIS — Part 4: CLI, Genesis Ceremony, and Fixtures

> **Scope:** `raxis` subcommands and their normative behaviour (§4.1), the genesis key ceremony step-by-step (§4.2), and the canonical integration test fixtures with their v1 test matrix cross-references (§4.3).
>
> **Navigation:** [README](../../README.md) | [Part 2 Store](kernel-store.md) | [Part 3](peripherals.md) | [Planner API](planner-api.md)
>
> **Authority:** Where this file and [`kernel-store.md`](kernel-store.md) conflict on key file names, formats, or paths, [`kernel-store.md`](kernel-store.md) §2.5.4 wins. Where this file describes CLI subcommand behaviour that drives the operator auth protocol, [`kernel-store.md`](kernel-store.md) §2.5.5 wins on the wire format.
>
> **Binary vs crate name.** The user-facing operator binary is **`raxis`**. The Cargo crate that produces it is `raxis-cli` (kept stable so workspace dependencies do not have to churn). Earlier drafts of this spec used `raxis-cli` everywhere; treat any remaining `raxis-cli <subcommand>` example below as equivalent to `raxis <subcommand>` — the binary on disk and on `$PATH` is `raxis`.

---

## §4.1 — `raxis` Subcommands

> **V2 supersession notice (authoring lifecycle).** The V2
> operator-ergonomics layer (`v2/operator-ergonomics.md`) supersedes
> the parts of this section that describe the **plan-authoring
> lifecycle** — specifically:
>
> - `raxis plan sign` (V1) is removed in V2 in favour of atomic
>   sign+submit via `raxis-cli submit plan` (`v2/plan-bundle-sealing.md
>   §4`); see also the per-section V2 supersession notice on
>   `plan submit` further down.
> - V2 introduces a canonical authoring flow:
>   `raxis-cli plan init → plan prepare → submit plan` documented in
>   `v2/operator-ergonomics.md §5–§6`. The V1 expectation that the
>   operator hand-authors a complete `plan.toml` and signs it with
>   `plan sign` is no longer the canonical path.
> - V2 adds new authoring CLI commands not described in this document:
>   `plan validate`, `plan diff`, `plan explain`, `plan fmt`,
>   `plan cost-estimate`, `submit plan --dry-run`, `initiative watch`,
>   `initiative resume`, `setup wizard`. Their
>   canonical specifications live in `v2/operator-ergonomics.md
>   §6–§17`.
> - `raxis initiative list` (read-only bucketed listing) is **NOT
>   deferred to V2** — it ships in V1 as a read-only observation
>   surface alongside `raxis sessions` / `raxis escalations`. Spec'd
>   in [`cli-readonly.md`](cli-readonly.md) §5.5.6b. The richer v2 form (with `--mine`,
>   `--since`, per-row task progress) is documented in
>   `v2/operator-ergonomics.md §15` and strictly extends the v1
>   baseline.
>
> Mutating subcommands NOT in the operator-ergonomics surface
> (`policy sign`, `plan approve`, `escalation approve`, `task abort`,
> `session create`, `delegation grant`, `epoch advance`, plus
> `genesis`) remain canonical in this document for both V1 and V2
> deployments.  Audit-chain integrity verification has been
> consolidated into the read-only `verify-chain` command (see
> §"`verify-chain`" below); the V1-draft `audit verify` / `audit gaps`
> shims were removed in V2 to preserve the no-duplicate-action
> invariant.
>
> The two surfaces (V1 mutating commands here, V2 ergonomics
> commands in `operator-ergonomics.md`) are designed to coexist on
> the same `raxis` binary; an operator on V2 uses V2 ergonomics for
> authoring and the V1 surface in this spec for genesis, policy
> management, approvals, and audit operations.

`raxis` is the operator-facing binary. It has two distinct surfaces:

1. **Mutating subcommands** (this document, §4.1) — every command that
   changes kernel state (`genesis`, `policy sign`, `plan submit`,
   `plan approve`, `escalation approve`, `task abort`, `session create`,
   `delegation grant`, `epoch advance`).
   These communicate exclusively over the operator UDS
   (`<data_dir>/sockets/operator.sock`), performing the challenge-response
   handshake on every invocation.
2. **Read-only subcommands** ([`cli-readonly.md`](cli-readonly.md) Part 5 — `status`, `top`,
   `queue`, `log`, `inspect`, `escalations`, `sessions`, `verifiers`,
   `witnesses`, `budget`, `policy show`, `policy diff`, `verify-chain`,
   `explain`, `doctor`, `inbox`). These NEVER connect to the kernel
   socket — they open `kernel.db` directly with
   `OpenFlags::SQLITE_OPEN_READ_ONLY` and parse the audit JSONL
   directly. The contract, schema-version-pinning rules, and the
   `Redactable<T>` confidentiality layer are spec'd in
   [`cli-readonly.md`](cli-readonly.md) §5.1–5.4. Both surfaces share the `--data-dir`
   global flag below; `--socket` is meaningful only for §4.1
   subcommands.

### Global flags

```bash
raxis [--data-dir <path>] [--socket <path>] <subcommand>
```

| Flag | Default | Description |
|---|---|---|
| `--data-dir` | `~/.raxis` | Kernel data directory. All relative paths are resolved from here. Honoured by both §4.1 and [`cli-readonly.md`](cli-readonly.md) Part 5 subcommands. |
| `--socket` | `<data_dir>/sockets/operator.sock` | Override operator socket path. **§4.1 subcommands only**; ignored by read-only subcommands. |

All §4.1 subcommands that require kernel connectivity will fail with `ERR_SOCKET_NOT_FOUND` if the operator socket does not exist (kernel not running). Read-only subcommands ([`cli-readonly.md`](cli-readonly.md) Part 5) work whether the kernel is running or stopped — they read state directly from disk.

### Unknown-subcommand handling — "did you mean ...?"

When the operator types a subcommand the dispatcher does not recognise — at any level (top-level, or inside a parent like `cert`, `plan`, `initiative`, `operator`, `task`, `session`, `delegation`, `escalation`, `epoch`, `audit`, `policy`) — the CLI MUST print to **stderr** (and exit non-zero — `1`, the standard `CliError::Usage` exit) a single line of the shape:

```text
error: usage: unknown <kind>: "<typo>"[. Did you mean ...?]
```

where `<kind>` is `subcommand` at the top level and `<parent> sub-command` underneath a parent (e.g. `cert sub-command`, `plan sub-command`, `initiative sub-command`). The `error: ` prefix comes from `main`'s `eprintln!`; the `usage: ` prefix comes from the `CliError::Usage` `Display` impl; the `unknown <kind>: "<typo>"` core comes from `closeness::unknown_with_suggestion`. The `. Did you mean …?` clause is appended only when at least one candidate clears the closeness threshold below.

Closeness ranking is deterministic and operator-friendly:

- **Distance:** Damerau–Levenshtein with optimal string alignment — adjacent transpositions count as one edit (so `apporve` → `approve` is distance 1 rather than 2).
- **Threshold:** length-aware. Single-letter inputs only match exact prefixes; len-2/3 inputs accept distance ≤ 1; len-4 accept ≤ 2; len-5+ accept ≤ 3. This keeps `raxis xyzzy` quiet rather than suggesting random commands.
- **Order:** exact-prefix matches always come first, in the dictionary's canonical order (so `raxis ce` surfaces `cert` before any distance-bounded match). Distance-bounded matches follow, sorted by `(distance, original_index)`.
- **Cap:** at most 5 suggestions per error to keep the line short. Three formatting variants:
  - 1 entry — `Did you mean `cert`?`
  - 2 entries — `Did you mean `cert` or `escalation`?`
  - 3+ — `Did you mean one of: `cert`, `escalation`, `epoch`?`

The closeness ranking and the per-parent subcommand catalogues used to drive it live in `cli/src/closeness.rs`. The dispatcher in `cli/src/main.rs` MUST keep its `*_SUBCOMMANDS` constants in sync with the actual `match` arms; two `catalog_consistency_tests` scrape `main.rs` and hard-fail on drift, so the suggestions can never silently lie about which commands exist. The exit code is `1` (the standard `CliError::Usage` exit) regardless of whether a suggestion was emitted.

---

### `genesis`

**Purpose:** Run the initial key generation ceremony. Generates all four key families and writes the initial `policy.toml`. Must be run before the kernel is started for the first time.

**Usage:**

```text
raxis-cli genesis [--force]
                  ( --operator-cert <path>                                           # air-gapped path
                  | --operator-key <path>
                       --operator-name <display>
                       [--cert-validity-days <n>]                                    # convenience path
                       [--admin]                                                     # opt into OperatorCertInstall
                  )
                  [--force-misconfig]
```

> **Cert is mandatory (INV-CERT-01).** The legacy `--operator-pubkey`
> flag was removed: a bare public key cannot accompany the policy
> bundle because every `[[operators.entries]]` block now requires a
> self-signed `[operators.entries.cert]` sub-table, and minting that
> sub-table requires the operator's private key. The two flows below
> are the only two genesis paths.

**Two operator-identity paths (mutually exclusive):**

1. **Air-gapped (`--operator-cert <path>`)** — the operator minted the
   cert offline (typically `raxis cert mint` on a separate machine
   that holds the private key) and supplies the resulting
   `*.cert.toml`. The CLI never sees the operator private key. This
   is the recommended path for production: the operator key never
   touches the host running the kernel.

2. **Convenience (`--operator-key <path> --operator-name <display>`)** —
   the operator hands the CLI a private-key PEM (or 64-char hex
   seed); the CLI mints a cert in-process from that key and embeds
   it in the policy. The private key bytes are read into memory and
   used only for the in-process `sign_cert` call; **they are NEVER
   persisted under `<data_dir>`** (the CLI tests assert this with a
   recursive seed-leakage scan). Optional `--cert-validity-days <n>`
   sets the cert's `not_after = now + n*86400`; default is the
   `cert::DEFAULT_VALIDITY_DAYS` constant (one year). Optional
   `--admin` adds `OperatorCertInstall` to the minted cert. That is
   an operator trust-root capability, not a dashboard-specific flag;
   the dashboard maps it, together with `RotateEpoch`, to its local
   `admin` role for sensitive surfaces such as credential reveal. Use
   this path for development / single-machine setups; use
   `--operator-cert` for tighter security.

For the air-gapped path, admin is decided when the cert is minted:
include `OperatorCertInstall` in `raxis cert mint --ops ...` only for
operators that should be able to install/rotate operator certs. Genesis
does not mutate a supplied cert because doing so would invalidate its
self-signature.

After genesis, widening an operator to include `OperatorCertInstall`
MUST use the signed epoch path: mint a replacement cert for the same
operator key, install it with
`raxis cert install --replace-for <old-fp> --new-cert <cert> --policy <policy.toml>`,
re-sign the policy, then run `raxis epoch advance --policy <path> --sig <sig>`.
This preserves the `OperatorCertInstalled.previous_fingerprint` audit
link and avoids treating genesis as an authority-upgrade command.

If neither flag is supplied AND the CLI is attached to a TTY, it
prompts the operator to paste a cert TOML body on stdin (Ctrl-D to
end). This mirrors the kernel-side `RAXIS_BOOTSTRAP=1` fallback so
both genesis entry points behave identically.

**Cert validation:** every path runs `validate_cert_structurally`
(window sanity for `Standard`, value pinning for `EmergencyRecovery`)
and `verify_cert_self_signature`. Self-signature failures and
pubkey mismatches are unbypassable (they would let an attacker spoof
an operator's identity). Structural failures can be bypassed by
adding `--force-misconfig`, which:

1. Sets `force_misconfig_bypass = true` on the genesis operator
   entry in `policy.toml`.
2. Triggers an `OperatorCertMisconfigBypassed` audit event on the
   first policy load (one event per relaxed invariant).

The bypass is loud by design — every read path for the operator
entry surfaces it (`raxis cert show`, `raxis doctor`, the kernel's
boot log) so a forensic auditor can reconstruct exactly which
checks the operator overrode and why.

**Behaviour:**
1. Checks that `<data_dir>/keys/` does not already contain key files. Exits with `ERR_ALREADY_INITIALIZED` if it does (prevents accidental re-genesis). Use `--force` only with explicit intent to destroy existing keys. **`--force` semantics**: the genesis path MUST proactively `rm` every prior-genesis artifact (`authority_keypair.pem`, `quality_keypair.pem`, `verifier_token_key.bin`, every `operator_<fp>.pub`, every `operator_<fp>.cert.toml`, and `<data_dir>/audit/segment-000.jsonl`) before re-running steps 2–7 — otherwise the per-file `O_CREAT|O_EXCL` writes inside the helpers will fire and `--force` will silently fail mid-ceremony. The cert file MUST be in the purge set because it is written at mode `0444` and a second `fs::write` would otherwise fail with `EACCES`. Both genesis emitters (CLI's `raxis genesis` and the kernel's `RAXIS_BOOTSTRAP=1` path) implement this purge.
2. Generates `authority_keypair` (Ed25519) → writes `<data_dir>/keys/authority_keypair.pem`.
3. Generates `quality_keypair` (Ed25519) → writes `<data_dir>/keys/quality_keypair.pem`.
4. Generates `verifier_token_key` (32 CSPRNG bytes) → writes `<data_dir>/keys/verifier_token_key.bin`.
5. Operator cert handling (see "Two operator-identity paths" above): the resolved cert is validated, then both the cert and the public-key-only artefact are persisted to `<data_dir>/keys/`:
   - `<data_dir>/keys/operator_<fp>.pub` — operator pubkey hex (mode `0444`); kept for backward-compatible discovery (`raxis doctor`, `raxis policy show`).
   - `<data_dir>/keys/operator_<fp>.cert.toml` — the full self-signed cert TOML (mode `0444`); the canonical on-disk source for `raxis cert show` / `raxis cert verify --data-dir`.
   The kernel **never** sees the operator's private key — even on the convenience path, the private bytes live only in process memory.
6. Writes initial `policy.toml` to `<data_dir>/policy/policy.toml` via the SHARED canonical emitter `raxis_genesis_tools::render_genesis_policy_toml` (the same function the kernel's `RAXIS_BOOTSTRAP=1` self-bootstrap path calls — see [`philosophy.md`](philosophy.md) §1.6 `crates/genesis-tools/` for the convergence rationale and drift history). The CLI is responsible only for plumbing the inputs to the emitter; the spec invariants are all enforced inside the shared crate. The emitted artifact contains:
   - `authority_pubkey` = public key extracted from `authority_keypair.pem`
   - `quality_pubkey` = public key extracted from `quality_keypair.pem`
   - `[[operators.entries]]` = the registered operator entry. By default, `permitted_ops = ["CreateInitiative", "ApprovePlan", "RejectPlan", "CreateSession", "RevokeSession", "GrantDelegation", "RetryTask", "ResumeTask", "AbortTask", "AbortInitiative", "ApproveEscalation", "DenyEscalation", "RotateEpoch", "QuarantineInitiative", "QuarantinePlansBy"]` (the canonical 15-operation v1 IPC set per [`kernel-store.md`](kernel-store.md) §2.5.5 IPC discriminant table). `OperatorCertInstall` is appended only when the operator explicitly opts into admin/trust-root authority; the entry mirrors the embedded cert's `permitted_ops`.
   - `[operators.entries.cert]` = the self-signed `OperatorCert` (mandatory by INV-CERT-01). The emitter ALWAYS writes this sub-table — there is no cert-less branch. Loading a `policy.toml` without this sub-table fails serde deserialisation with a clear `missing field "cert"` error.
   - `[budget.base_cost_per_intent_kind]` = an entry for EACH of the four canonical `IntentKind` variants (`SingleCommit`, `IntegrationMerge`, `CompleteTask`, `ReportFailure`). Omitting any of these is a latent bug: any task whose intent-kind has no cost entry would fail admission with `BudgetError::UnknownIntentKindCost`. The shared emitter ships fixed defaults (10/50/5/1) that the operator may re-tune via `raxis epoch advance`.
   - `[[lanes]]` = a `default` lane entry. Without at least one lane entry, `scheduler::admit::admit_task` cannot resolve `lane_id = "default"` (the lane every plan defaults to) and admission fails with `SchedulerError::UnknownLane`.
   - `[sessions] allowed_worktree_roots` = a NON-EMPTY placeholder list (`<data_dir>/worktrees`), with a TOML comment directing the operator to replace it before creating sessions. **Writing an empty list at this step is a contract violation:** `raxis_policy::PolicyBundle::validate` rejects an empty `allowed_worktree_roots` as `MalformedArtifact`, so the kernel would refuse to load its own genesis-emitted artifact (regression-pinned by `bootstrap::integration::policy_toml_round_trips_through_raxis_policy_load_policy` AND by `cli/tests/genesis_emitter_round_trip.rs`). The placeholder is scoped under `<data_dir>` so it cannot grant access to anything the operator did not opt into; the operator is expected to advance the epoch with their real allowlist before creating sessions.
   - Empty `[[tasks]]`, `[[gates]]`, and `[[tools]]` sections
7. Prompts the operator to sign `policy.toml` with the generated authority key using `raxis-cli policy sign` and store the raw `policy.sig` alongside it. The ceremony is not complete until `policy.sig` exists.
8. Prints a summary of generated files and next steps.

**Migration note (legacy `--operator-pubkey`):** Operators who hit
`unknown flag --operator-pubkey` from prior CLI versions should
switch to one of the two flows above. The CLI emits a typed error
naming both replacement paths to make migration mechanical:

```text
--operator-pubkey was removed in the cert-mandatory release
(INV-CERT-01): a bare pubkey cannot accompany the policy bundle.
Re-run genesis with one of:
  --operator-cert <path>   (air-gapped: pre-mint via `raxis cert mint`)
  --operator-key  <path>   (convenience: CLI mints + embeds in-process;
                            private key bytes are NOT persisted)
```

**Files written:**
- `<data_dir>/keys/authority_keypair.pem`
- `<data_dir>/keys/quality_keypair.pem`
- `<data_dir>/keys/verifier_token_key.bin`
- `<data_dir>/keys/operator_<fingerprint>.pub`
- `<data_dir>/keys/operator_<fingerprint>.cert.toml`
- `<data_dir>/policy/policy.toml`

**Does not start the kernel.** The operator starts the kernel separately after ceremony completion.

---

### `genesis --rotate <key-family>`

**Purpose:** Key rotation ceremony for a single key family. Safe to run while kernel is stopped.

**Usage:** `raxis-cli genesis --rotate [authority | quality | verifier-token]`

**Behaviour:**
- Stops cleanly if the kernel is detected as running (checks for active socket).
- Generates new key material for the specified family.
- For any key: prints "You must advance the policy epoch before resuming work. After restarting the kernel, stage the new signed policy artifact under `<data_dir>/policy/` and run: `raxis-cli epoch advance --policy <path> --sig <path>` (both arguments required; see the `epoch advance` section below)."
- Does **not** automatically advance the epoch — that is a separate explicit step requiring the operator to stage the new signed artifact and pass its paths.

> **Note on `operator` family.** `genesis --rotate operator` was
> removed in the cert-mandatory release (INV-CERT-01) — it was a
> footgun: the old flow swapped the on-disk pubkey file but left
> the policy's `[[operators.entries]]` cert sub-table untouched, so
> the kernel's epoch-advance check would reject the resulting policy
> with a fingerprint mismatch. The replacement is `raxis cert
> install --replace-for <old-fp> --new-cert <path>` (see [`cert
> install`](#cert-install) below), which atomically rewrites the
> cert block in `policy.toml`, mirrors the new cert into the
> `operator_certificates` view table at next epoch advance, and
> emits a typed `OperatorCertInstalled.previous_fingerprint =
> Some(<old-fp>)` audit event so the rotation is forensically
> traceable. Per INV-CERT-04 a `cert install --replace-for` MUST
> NOT change the underlying public key — to rotate the operator's
> Ed25519 key itself (a separate, audited operation), the operator
> must run a fresh `raxis genesis` ceremony in a new data dir; v1
> does not support in-place pubkey rotation.

---

### `policy sign`

**Purpose:** Sign a policy artifact with the authority key, or another non-plan artifact with the operator's private key.

**Usage:** `raxis-cli policy sign <artifact.toml> --key <signing_key_path> [--force-misconfig]`

**Behaviour:**
1. Reads `<artifact.toml>` bytes verbatim.
2. Performs a best-effort scan of the TOML for any `[[operators.entries]]`
   row with `force_misconfig_bypass = true`. If any are found AND
   `--force-misconfig` was not passed, signing aborts with a usage
   error listing the offending entries — refuses to silently sign a
   policy that has structural overrides baked in.
3. With `--force-misconfig` present, emits a structured stderr warning
   (`policy_sign_misconfig_bypass`) per offending entry and proceeds.
4. If the artifact contains `[authority].authority_pubkey`, treats it as a policy artifact: verifies that `--key` is the matching authority key, signs the exact raw policy bytes, and writes `<artifact>.sig` as 64 raw Ed25519 signature bytes. This is the format `raxis epoch advance` verifies.
5. For non-policy artifacts, computes `SHA-256(file_bytes)`, signs the canonical non-plan artifact domain with the operator Ed25519 private key, and writes the TOML sidecar form.
6. Prints the signer fingerprint and artifact hash for verification.

**Note:** Private keys are read locally and are never sent to the kernel. `raxis-cli policy sign` does not open the operator socket. The operator key signs IPC requests and non-policy operator artifacts; `policy.toml` itself is signed by `<data_dir>/keys/authority_keypair.pem`. The `--force-misconfig` flag is the operator-explicit acknowledgement that the policy contains a cert with a structural validation override; the matching kernel-side audit event is `OperatorCertMisconfigBypassed`.

---

### `plan submit`

> **V2 supersession notice.** The two-argument form below
> (`plan submit <initiative_id> <plan_dir>`) and the companion
> `plan sign` step are the **V1** ceremony. V2 collapses these into a
> single atomic command: `raxis-cli submit plan <plan.toml>` (file
> argument, not directory; `--initiative-id` optional). The V2 CLI
> reads `plan.toml`, bundles all referenced artifacts, hashes,
> signs, and submits in one in-process operation — there is no
> intermediate `plan.sig` file and no on-disk `plan_dir`. See
> `v2/plan-bundle-sealing.md` for the V2 mechanism. The V2 CLI
> rejects the V1 invocation form at argument parse time with a hint
> pointing to the new command. This V1 section is retained for
> users on pre-V2 deployments and for documentation of historical
> behavior.

**Purpose:** Submit a signed plan to the kernel to create a new initiative.

**Usage:** `raxis-cli plan submit <initiative_id> <plan_dir>`

`<plan_dir>` must contain both `plan.toml` and `plan.sig`.

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `CreateInitiative { initiative_id, plan_toml_path, plan_sig_path }`.
3. Kernel verifies signature and creates the initiative row.
4. On success: prints `Initiative <initiative_id> created. Status: Draft`.
5. On `FAIL_UNKNOWN_SIGNER`: prints the fingerprint from `plan.sig` and instructs the operator to register the key with `raxis-cli operator add-key`.
6. On `FAIL_INITIATIVE_EXISTS`: prints existing status; does not overwrite.

---

### `plan approve`

**Purpose:** Approve a draft initiative, transitioning it from `Draft → ApprovedPlan` and scheduling tasks for execution.

**Usage:** `raxis-cli plan approve <initiative_id>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `ApprovePlan { initiative_id }`.
3. Kernel transitions state and schedules all ready tasks (those with no predecessors).
4. On success: prints initiative status and list of tasks now queued.
5. Requires `ApprovePlan ∈ permitted_ops` for the authenticated operator.

---

### `plan reject`

**Purpose:** Abandon a draft initiative without instantiating tasks.

**Usage:** `raxis-cli plan reject <initiative_id>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `RejectPlan { initiative_id }`.
3. Kernel calls `lifecycle::reject_plan` — requires initiative `Draft`; transitions initiative to `Aborted`.
4. Requires `RejectPlan ∈ permitted_ops`.

---

### `initiative abort`

**Purpose:** Force-terminate an active initiative and bulk-cancel all non-terminal tasks (`lifecycle::abort_initiative`).

**Usage:** `raxis-cli initiative abort <initiative_id>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `AbortInitiative { initiative_id }`.
3. Kernel bulk-cancels tasks per store spec; initiative → `Aborted`.
4. Requires `AbortInitiative ∈ permitted_ops`.

---

### `initiative cancel` (V2)

**Purpose:** Graceful operator-initiated cancellation of an
initiative. Distinct from `abort` (which is destructive — immediate
task termination, no grace) and `quarantine` (which freezes new
intent admission but leaves existing tasks running indefinitely).
`cancel` admits no new tasks AND signals existing tasks to wind down
within a bounded grace window, then transitions the initiative to a
terminal `Cancelled` state.

The semantic distinction lets operators express *intent*:

- `abort` → "this initiative is broken or harmful; kill it now."
- `quarantine` → "this initiative is suspicious; freeze it for
  forensic review without destroying state."
- `cancel` → "I no longer want this initiative's work, but I want
  the in-flight pieces to finish (or fail with an audit-clear
  reason) so the audit chain reflects intent rather than abandonment."

**Usage:**
```bash
raxis-cli initiative cancel <initiative_id>
    [--reason <text>]
    [--grace-seconds <N>]      # default 600 (10 min)
    [--force-after-grace]      # default true
```

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `CancelInitiative { initiative_id, reason,
   grace_seconds, force_after_grace }`. `reason` is capped server-
   side at 512 bytes (truncated, not rejected).
3. Kernel transitions the initiative to a new transient state
   `CancelPending` (added to the initiative FSM in [`kernel-store.md`](kernel-store.md)'s
   V2 migration). In `CancelPending`:
   - **No new task admissions.** `ActivateSubTask` and
     `IntegrationMerge` intents from this initiative's sessions
     return `FAIL_INITIATIVE_CANCEL_PENDING`. The error code is
     distinct from `FAIL_INITIATIVE_QUARANTINED` so planners can
     drain rather than escalate.
   - **In-flight tasks continue.** Existing `Active` / `Reviewing`
     tasks complete normally. Their `CompleteTask` /
     `SubmitReview` / `IntegrationMerge` intents on already-active
     sessions admit as usual; only NEW task admissions are blocked.
   - **Orchestrator receives a kernel push.** The kernel enqueues
     `KernelPush::InitiativeCancelPending { initiative_id, reason,
     grace_deadline_ms, force_after_grace }` to the Orchestrator
     session (per `kernel-push-protocol.md §10.3`). The Orchestrator's
     NNSP routes this as "wind-down mode" — finalize current tasks,
     do not schedule new ones, then submit a single
     `IntegrationMerge` for whatever has reached `Reviewed` if the
     plan permits partial-merge.
4. At `grace_deadline_ms = now + grace_seconds`:
   - If all child sessions have reached terminal state
     (`Completed` / `Failed` / `Cancelled` / `Aborted`): the kernel
     atomically transitions the initiative `CancelPending →
     Cancelled` and emits `InitiativeCancelled { initiative_id,
     cancelled_by, reason, grace_used_seconds, finalized_naturally:
     true }`.
   - Else if `force_after_grace = true` (default): the kernel
     bulk-cancels remaining non-terminal tasks (using the same
     `lifecycle::abort_initiative` underlying machinery used for
     `abort`, but with `cancellation_class = OperatorCancel`); the
     initiative transitions `CancelPending → Cancelled` and emits
     `InitiativeCancelled { ..., finalized_naturally: false,
     forced_task_count: N }`.
   - Else (`force_after_grace = false`): the initiative remains in
     `CancelPending` indefinitely. Operators using this mode are
     responsible for monitoring and re-issuing `cancel
     --force-after-grace` or `abort` if they want a terminal state.
5. After the initiative reaches `Cancelled`, all subsequent intents
   for any of its sessions return `FAIL_INITIATIVE_CANCELLED`. This
   is a terminal state — there is no `un-cancel`. (Operators who
   want to revisit the work submit a new initiative referencing the
   cancelled one in their plan's `notes` field.)
6. Requires `CancelInitiative ∈ permitted_ops`. The new permitted-op
   variant is added to `policy.toml [[operators.entries]].permitted_ops`
   in V2; pre-V2 operators MUST add it to their cert's `permitted_ops`
   list to use the new command. (Existing `AbortInitiative` does NOT
   imply `CancelInitiative` — they are distinct authorities so an
   operator can be granted graceful cancel without the destructive
   abort hammer.)
7. Audit events (in order):
   - `InitiativeCancelPending { initiative_id, cancelled_by, reason,
     grace_seconds, force_after_grace, deadline_ms }` — emitted at
     step 3.
   - `InitiativeCancelled { ... }` — emitted at step 4 (one of the
     two outcomes above).
   - On `force_after_grace` path: one `TaskCancelled { task_id,
     reason: GraceExceeded }` per task forced to terminate.

**Idempotency.** Re-issuing `cancel` against an initiative already
in `CancelPending` returns `was_already_cancel_pending: true` with
the existing `grace_deadline_ms`; flags from the second call are
silently ignored. Re-issuing against an initiative in `Cancelled`
returns `FAIL_INITIATIVE_CANCELLED` (the operation has already
completed). Re-issuing against `Aborted` or `Quarantined` returns
`FAIL_INITIATIVE_NOT_CANCELLABLE` with the existing terminal state
in the failure detail.

**Composition with `abort` and `quarantine`.** An operator who
issued `cancel` and decides to escalate to `abort` mid-grace can do
so directly — `abort` works against any non-terminal state. An
operator who wants to halt cancellation pre-grace cannot: there is
no `cancel --revoke`. This is intentional; revocability of a
graceful cancel creates ambiguous audit semantics for in-flight
work. If reversal is needed, the operator submits a new initiative.

---

### `initiative quarantine`

**Purpose:** Freeze an initiative without aborting it. Every subsequent
`IntentRequest` against the initiative is rejected by the kernel with the
terminal code `FAIL_INITIATIVE_QUARANTINED`
(`raxis_types::PlannerErrorCode::FailInitiativeQuarantined`). In-flight
tasks remain in their current state — quarantine is a curtain, not a
guillotine. Use `initiative abort` for the destructive path.

**Usage:** `raxis-cli initiative quarantine <initiative_id> [--reason <text>]`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `QuarantineInitiative { initiative_id, reason }`. `reason` is
   capped server-side at 512 bytes (truncated, not rejected).
3. Kernel inserts one row into `initiative_quarantines`. The call is
   idempotent: re-issuing it on an already-quarantined initiative
   returns `was_already_quarantined: true` and does NOT re-emit the
   audit event.
4. Emits `InitiativeQuarantined { initiative_id, quarantined_by, reason }`
   to the audit chain.
5. Requires `QuarantineInitiative ∈ permitted_ops`.

---

### `operator quarantine-plans-by`

**Purpose:** The big-red-button revocation primitive. Sweeps every
initiative whose plan was approved by `<target_fingerprint>` and
quarantines each in a single atomic transaction. Used as the immediate
containment step when an operator key is suspected compromised;
operator-key removal is a separate `policy sign` + `epoch advance`
ceremony.

**Usage:** `raxis-cli operator quarantine-plans-by <target_fingerprint> [--reason <text>]`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `QuarantinePlansBy { target_fingerprint, reason }`.
3. Kernel `JOIN`s `signed_plan_artifacts.signed_by_fingerprint = ?`
   and `INSERT`s one `initiative_quarantines` row per match. Rows
   already quarantined are silently skipped.
4. Emits one `InitiativeQuarantined` audit event per newly-quarantined
   initiative PLUS one rollup `OperatorQuarantineSwept { target_fingerprint, count }`.
   The rollup is emitted even on an empty sweep so the audit chain
   shows the operator pressed the button (forensic continuity).
5. Initiatives whose `signed_plan_artifacts.signed_by_fingerprint` is
   `NULL` (legacy approvals predating migration 3) are silently skipped
   — the kernel cannot prove who approved them. The audit chain remains
   the authoritative record for those.
6. Requires `QuarantinePlansBy ∈ permitted_ops`.

---

### `cert mint` / `cert mint-emergency`

**Purpose:** Issue an operator certificate that binds together
`(display_name, pubkey, validity window, permitted_ops)` and is
self-signed by the operator's Ed25519 private key. Standard certs have
the four-zone expiry model (Active / Expiring / Grace / Expired);
`EmergencyRecovery` certs are structurally pinned and never expire.

**Usage:**
- `raxis cert mint --display-name <text> --key <signing_key.pem> --ops "RotateEpoch,ApprovePlan,..." [--validity-days N] [--warn-days N] [--grace-days N] [--not-before <unix_ts>] --out <cert.toml>`
- `raxis cert mint-emergency --display-name <text> --key <signing_key.pem> --out <cert.toml>`

**Behaviour:**
1. Reads the signing key (PEM) and derives the public key. An
   emergency cert MUST be self-signed by the operator key it certifies.
2. Builds the canonical signing input
   `display_name|pubkey_hex|kind|not_before|not_after|warn|grace|permitted_ops_json`
   (hashed before signing per `raxis_crypto::cert::sign_cert`).
3. For `mint-emergency`: rejects `--ops` other than `["RotateEpoch"]`
   and rejects `--not-before` outright. The kernel structurally pins
   `permitted_ops = ["RotateEpoch"]` and `not_after = 0` (sentinel for
   "always active"); supplying anything else is a misconfiguration the
   CLI catches before policy-sign time.
4. Writes a TOML cert artifact to `--out`.

Defaults (Standard kind): `not_after = now + 365d`, `warn = 30d`, `grace = 7d`.

### `cert show / verify / list / install`

| subcommand | purpose |
|------------|---------|
| `cert show <cert.toml>` | Pretty-print a cert (use `--json` for machine output). |
| `cert verify <cert.toml> [--at <unix_ts>]` | Verify structure + self-signature; report current zone (`active`, `expiring`, `grace`, `expired`, `not_yet_valid`, `always_active_emergency`). Returns `Ok` even on `expired` — expiry is informational. |
| `cert list [--json]` | Read `operator_certificates` from `kernel.db` and print one row per installed cert with current zone. |
| `cert install <cert.toml> --policy <policy.toml>` | **First install / refresh** mode. Splice a cert into the `[[operators.entries]]` entry whose `pubkey_hex` matches the cert's pubkey. Asserts pubkey-hex match before mutating the file. The policy MUST then be re-signed with `policy sign` before the next epoch advance picks it up. |
| `cert install --replace-for <old-fp> --new-cert <path> --policy <policy.toml>` | **Rotation / authority-widening primitive (typed; INV-CERT-04).** Locate the entry by `<old-fp>` and rewrite its embedded cert sub-table with the contents of `<path>`. The new cert's `pubkey_hex` MUST equal the existing entry's (rotation never changes the underlying pubkey — that is `genesis` in a fresh data dir, not `cert install`). The command also mirrors the cert's `permitted_ops` onto the entry-level field so policy reviewers see exactly what will become active. On the next epoch advance the kernel's cert mirror emits `OperatorCertInstalled.previous_fingerprint = Some(<old-fp>)` so the audit chain captures the rotation event with continuity back to the prior cert. The two install forms are mutually exclusive at the CLI parse layer; mixing them or omitting one half of the rotation pair fails loud. |

**`cert install --force-misconfig`** (applies to either form): the new
cert's structural validation can be bypassed with `--force-misconfig`;
the bypass sets `force_misconfig_bypass = true` on the entry and the
kernel will emit `OperatorCertMisconfigBypassed` per relaxed
invariant on the next policy load. Self-signature failures and
pubkey mismatches are NEVER bypassable. Rotations also drop any
prior `force_misconfig_bypass = true` from the entry on success
(unless `--force-misconfig` is also passed for the new cert), so a
silent over-relaxation across rotations is impossible.

---

### `escalation approve`

**Purpose:** Approve a pending escalation, issuing an `approval_token` for the planner.

**Usage:** `raxis-cli escalation approve <escalation_id> --scope <capability_class> --max-uses <n> --valid-for <seconds>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Constructs `approval_scope = { capability_class, max_uses, valid_for_seconds }`.
3. Signs `(escalation_id || approval_scope_canonical_bytes)` with operator's private key → `operator_sig`.
4. Sends `ApproveEscalation { op_token, escalation_id, approval_scope, operator_sig }`.
5. Kernel writes `approval_tokens` + `approval_proofs` rows.
6. On success: prints the `approval_token` value. Operator passes this to the planner out-of-band (e.g. via the plan or a side channel).
7. Requires `ApproveEscalation ∈ permitted_ops`.

---

### `escalation deny`

**Purpose:** Deny a pending escalation. The planner receives no approval token; the escalation transitions `Pending → Denied`. The task remains in whatever state it was in when the escalation was submitted — the operator must follow up with `task abort` or `task retry` depending on intent.

**Usage:** `raxis-cli escalation deny <escalation_id> [--reason <text>]`

**Wire format (operator → kernel):**

```yaml
Operator → Kernel: DenyEscalation {
  op_token:       "<operator session token>",
  escalation_id:  "<uuid>",
  reason:         "<optional free text, max 512 chars; stored in audit only>"
}
```

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `DenyEscalation { op_token, escalation_id, reason }`.
3. Kernel validates: `escalation.status == Pending`. Any other status → `FAIL_ESCALATION_NOT_PENDING { current_status }`.
4. Kernel transitions escalation `Pending → Denied`; emits `AuditEventKind::EscalationDenied { escalation_id, denied_by: operator_id, reason }`.
5. Kernel does **not** issue any token or notify the planner automatically — the planner will time out waiting for approval and receive `EscalationTimedOut` semantics on next check. Operator decides next step for the task independently.
6. Requires `DenyEscalation ∈ permitted_ops`.

**Note:** `DenyEscalation` does not carry an `operator_sig` over escalation scope (unlike `ApproveEscalation`) — denial creates no durable approval artifact. The denial is recorded in the audit log only. INV-ESC-01 is not implicated: denial does not involve token issuance.

---

### `task abort`

**Purpose:** Abort a running task immediately.

**Usage:** `raxis-cli task abort <task_id>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `AbortTask { task_id }`.
3. Kernel transitions task to `Aborted` with `BlockReason::OperatorAbort`, records audit event.
4. On success: prints new task status.
5. Requires `AbortTask ∈ permitted_ops`.

---

### `task resume`

**Purpose:** Resume a `BlockedRecoveryPending` task after a kernel crash recovery. Transitions the task from `BlockedRecoveryPending → Running` so the planner session that was interrupted can continue (or a new session can be attached). This is the **recovery resume** operation.

INV-INIT-05: the planner cannot self-resume a `BlockedRecoveryPending` task. Only operator CLI can trigger this transition.

**Usage:** `raxis-cli task resume <task_id>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `OperatorRequest::ResumeTask { task_id }` (operator IPC variant).
3. Kernel calls `recovery::resume_task(task_id, operator_id)` — validates `task.state == TaskState::BlockedRecoveryPending`. Any other state → `OperatorResponse::Error { code: FAIL_TASK_NOT_RESUMABLE, detail: TaskNotResumable { current_state } }` per the operator-error envelope normatively defined in [`peripherals.md`](peripherals.md) §3 "Operator socket". The CLI deserialises `detail` and renders `"Cannot resume: task is in state <current_state> (must be BlockedRecoveryPending)"` to stderr; exit code is non-zero.
4. On success, kernel transitions task `BlockedRecoveryPending → Running`; emits `AuditEventKind::TaskResumed`; returns `OperatorResponse::TaskResumed { task_id, prior_state, transitioned_at }` (`prior_state` echoed from the `TaskNeedsRecovery` audit event so the operator sees what was interrupted).
5. Requires `ResumeTask ∈ permitted_ops`.

**Note:** After `task resume`, the operator must attach a planner session to the task to continue work. The kernel does not automatically reconnect the prior session (it may have been terminated at crash time).

**Gate-progress preservation across recovery (per INV-INIT-08, [`kernel-core.md`](kernel-core.md) §4.4):** `task resume` always lands the task in `Running` regardless of its `prior_state` (`Admitted` / `GatesPending` / `Running` at crash time — visible in the `TaskNeedsRecovery { prior_state, … }` audit event written during `recovery::reconcile_tasks`). Pre-crash gate progress is not lost: `witness_records` (Table 13) preserves every accepted witness across restarts, and the next `IntentRequest` from the attached planner session re-runs `evaluate_claims` against those records. Witnesses that arrived before the crash satisfy their gates without re-execution; gates whose verifier subprocesses died with the kernel re-spawn fresh verifiers; verifier tokens issued before the crash were invalidated by `expire_orphan_verifier_tokens` during the recovery sweep, so any stray pre-crash subprocess that somehow re-presents its token is rejected with `AuthorityError::TokenExpired`. **Practical implication:** for tasks whose `prior_state` was `GatesPending`, the operator does not need to issue any extra command beyond `task resume` — the planner's first post-resume intent restores gate evaluation to a consistent state. For tasks whose `prior_state` was `Running`, the operator should also confirm with the planner whether any partial work was in flight (the planner may need to inspect its working tree for uncommitted changes before submitting the next intent).

---

### `task retry`

**Purpose:** Retry a `Failed` task — one where the planner self-reported failure via `IntentKind::ReportFailure`. Transitions the task from `Failed → Admitted` so it is re-queued for a new planner session. This is the **operator-directed retry** operation, distinct from recovery resume.

**Usage:** `raxis-cli task retry <task_id>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `OperatorRequest::RetryTask { task_id }` (separate IPC variant from `ResumeTask`).
3. Kernel validates `task.state == TaskState::Failed` AND the containing initiative is non-terminal (`initiative.state ∈ {ApprovedPlan, Executing, Blocked}`). Failing preconditions return one of two envelope shapes per [`peripherals.md`](peripherals.md) §3 "Operator socket":
   - **Task-state failure** → `OperatorResponse::Error { code: FAIL_TASK_NOT_RETRYABLE, detail: TaskNotRetryable { current_state } }`. CLI prints `"Cannot retry: task is in state <current_state> (must be Failed; Aborted/Cancelled tasks are non-retryable in v1 — see specs/v1/kernel-core.md INV-INIT-07)"` and exits non-zero.
   - **Initiative-state failure** → `OperatorResponse::Error { code: FAIL_INITIATIVE_TERMINAL, detail: InitiativeTerminal { initiative_state, terminal_criteria } }`. CLI prints `"Cannot retry: initiative is in terminal state <initiative_state> under criterion <terminal_criteria> — re-submit a new initiative via `raxis-cli plan submit`"` and exits non-zero. This case is most commonly hit under `AllTasksSucceeded` criteria where `evaluate_terminal_criteria` already moved the initiative to `Failed` synchronously with the task failure (see [`kernel-core.md`](kernel-core.md) §4.5 "Operator decision on partial failure" for the criterion-dependent applicability table); the `terminal_criteria` field in `detail` lets the operator immediately understand *why* the initiative is unrecoverable rather than having to look it up.
4. On success, kernel resets `session_id`, `evaluation_sha`, `base_sha`, `submitted_claims_json`, `admission_reserved_units`, and `actual_cost` on the task row, then transitions it `Failed → Admitted` via `transition_task`. The post-write `evaluate_terminal_criteria` hook fires automatically; under `MinSuccessCount` or `AllTasksTerminal` this may transition the initiative `Blocked → Executing` if `next_ready_tasks` becomes non-empty as a result. Emits `AuditEventKind::TaskTransitioned { from: Failed, to: Admitted, actor: Operator(<operator_id>), … }` plus `AuditEventKind::TaskRetried { task_id, initiative_id, retried_by, prior_failure_reason, at }` (full payload defined in [`kernel-core.md`](kernel-core.md) §4.6 `lifecycle::retry_task`); both audit writes are in the same store transaction as the row update. Returns `OperatorResponse::TaskRetried { task_id, initiative_id, transitioned_at }`.
5. Requires `RetryTask ∈ permitted_ops`. Authorisation failure returns `OperatorResponse::Error { code: UNAUTHORIZED, detail: OperationNotPermitted { operator_id, attempted_op: "RetryTask" } }` per the standard operator-permitted-ops gate ([`kernel-store.md`](kernel-store.md) §2.5.5 L1424 + [`peripherals.md`](peripherals.md) §3 "Operator socket" auth flow). All other operator IPC commands return the same envelope on permitted-ops failure; this is documented once here for the `task retry` example.

**Note:** `Aborted` and `Cancelled` tasks cannot be retried in v1 — `Aborted` is terminal by infrastructure or operator decision, `Cancelled` is bulk-terminated by initiative-level operations (and per-task retry is meaningless when the initiative itself is terminal). `BlockedRecoveryPending` tasks use `task resume`, not `task retry`. After a successful retry, the operator should attach a planner session to the task (or wait for an existing session's next pickup) — `retry_task` only rewinds the task state, it does not re-spawn or re-attach planners. Each retry charges the lane budget afresh; there is no built-in retry cap in v1 (a future `policy.tasks.max_retries` field is deferred to v2).

---

**IPC discriminant table for operator task state operations:**

| CLI command | IPC message | Precondition | Transition | Handler |
|---|---|---|---|---|
| `task resume <id>` | `ResumeTask { task_id }` | `BlockedRecoveryPending` | `→ Running` | `recovery::resume_task` |
| `task retry <id>` | `RetryTask { task_id }` | `Failed` | `→ Admitted` | `initiatives::lifecycle::retry_task` |
| `task abort <id>` | `AbortTask { task_id }` | Any non-terminal | `→ Aborted` | `initiatives::lifecycle::abort_task` |

These are three distinct IPC variants — no single `ResumeTask` variant overloads multiple preconditions.

---

### `session create`

**Purpose:** Mint a planner session row in the kernel and return the session token to the operator. The operator is then responsible for spawning the planner subprocess with the token injected via the `RAXIS_SESSION_TOKEN` environment variable. v1 does **not** auto-spawn planners — planners are operator-supplied AI agents whose process lifecycle is owned by the operator's orchestration scripts; the kernel only owns the authentication credential.

This is the v1 answer to "how does a planner get a session token before its first intent." Gateway and verifier sessions are separate code paths (`spawn_gateway` at kernel boot, `spawn_verifier` on demand for each gate); only **planner** sessions flow through this CLI.

**Usage:** `raxis-cli session create --role planner --worktree-root <path> [--base-tracking-ref <ref>] [--task <task_id>] [--lineage-id <uuid>]`

- `--role planner` — required, must be the literal string `planner`. v1 rejects any other role on this CLI (`FAIL_ROLE_NOT_OPERATOR_CREATABLE`); gateway/verifier sessions are created elsewhere and never via operator IPC.
- `--worktree-root <path>` — required, absolute path to a git worktree the planner will operate in. Must exist; must contain `.git` (validated by `git -C <path> rev-parse --git-dir`); must be under one of the operator-allowed roots configured in `policy.toml` (`[sessions] allowed_worktree_roots = ["/home/operator/work", ...]`); a path outside any allowed root → `FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS`.
- `--base-tracking-ref <ref>` — optional, the symbolic ref the kernel resolves into `sessions.base_sha` for stale-base re-resolution on `IntegrationMerge` intents. Defaults to `refs/heads/main` (per [`kernel-core.md`](kernel-core.md) Part 2.3 §`session.rs`). Resolution failure → `FAIL_BASE_REF_UNRESOLVED`.
- `--task <task_id>` — optional. When supplied, the kernel binds the new session to a single specific `Admitted` task; subsequent intents from this session whose `task_id` does not match are rejected with `FAIL_SESSION_TASK_MISMATCH`. When omitted, the session may submit intents for any `Admitted` task in any initiative the operator's policy entry can reach (the bind is established at first intent admission). The single-task mode is the standard v1 pattern; the unbound mode is reserved for test fixtures and future multi-task planner work.
- `--lineage-id <uuid>` — optional. Operator-supplied UUID v4 (hyphenated form, 36 ASCII bytes) identifying the **agent instance** this session belongs to. **Reuse the same `lineage_id` across sessions of the same logical agent** (e.g. a session-revoke + re-create cycle for a crashed agent that you want to resume under the same identity); use a **fresh** `lineage_id` for genuinely independent agents. The `lineage_id` is what per-lineage rate-limiting (`policy.escalation_max_per_window`) and quarantine (`policy.escalation_quarantine_threshold`) key on — sharing a lineage across independent agents pools their escalation budgets, which is almost always a mistake. When omitted, the CLI generates a fresh `Uuid::new_v4()` and prints it in the success summary so the operator can capture it. **Note:** there is no `initiative_id` parameter — sessions are not bound to initiatives at the session-row level; binding flows through `--task` (which implies an initiative) or through the first accepted intent's `task_id` (for unbound sessions). See [`kernel-store.md`](kernel-store.md) §2.5.5 "Lineage ownership and supply" for the full rationale.

**Behaviour:**
1. CLI opens operator socket; performs challenge-response handshake.
2. CLI sends `OperatorRequest::CreateSession { role: Role::Planner, worktree_root: PathBuf, base_tracking_ref: Option<String>, task_id: Option<TaskId>, lineage_id: LineageId }`. If `--lineage-id` was omitted, the CLI substitutes a freshly generated `Uuid::new_v4()` before sending.
3. Kernel handler (`handlers/operator::handle_create_session`) checks `permitted_ops` ∋ `CreateSession`, validates the worktree root, validates the `lineage_id` parses as a UUID v4 (`FAIL_INVALID_LINEAGE_ID` on failure), resolves `base_tracking_ref` (if provided) into a `base_sha`, then calls `authority::session::create_session(Role::Planner, Some(worktree_root), base_sha, base_tracking_ref, lineage_id, &cfg, &store)` — the canonical helper signature is extended to take `lineage_id: LineageId` (the column is `NOT NULL` in Table 4, so the parameter is required, not `Option`).
4. On success, kernel responds `OperatorResponse::SessionCreated { session_id, session_token, role, worktree_root, base_sha, base_tracking_ref, expires_at, lineage_id }`. The `session_token` is **256 bits of CSPRNG random as a 64-char lowercase hex string** (matching the storage shape in `sessions.session_token` per [`kernel-store.md`](kernel-store.md) §2.5.1 Table 4).
5. CLI prints all fields except the token to stdout (human-readable confirmation, including the `lineage_id` so the operator can record it for future reuse), and prints the token by itself to stderr with the leading marker `RAXIS_SESSION_TOKEN=` so the operator can pipe it into a `.env` file or capture it via shell redirection without it appearing in shell history under default zsh/bash settings. Example invocation: `raxis-cli session create --role planner --worktree-root /work/agent-1 --lineage-id $(uuidgen) 2>session-1.env`.
6. Audit: `AuditEventKind::SessionCreated { session_id, role, worktree_root, base_sha, base_tracking_ref, lineage_id, created_by_operator: <fingerprint>, bound_task_id }` (the `bound_task_id` field is `None` when `--task` was omitted).

**Token delivery to the planner.** The operator MUST deliver the token to the planner subprocess via a private channel — env var (`RAXIS_SESSION_TOKEN`), Unix file descriptor inheritance, or argv (least preferred — visible in `ps`). v1 does not constrain the choice; the trust boundary is the operator's process orchestration. The kernel never logs the token value (only the SHA-256 hash of it goes to the audit chain — `created_by_operator` audit field).

**Authorisation:** Requires `CreateSession ∈ permitted_ops`. Failure → `OperatorResponse::Error { code: UNAUTHORIZED, detail: OperationNotPermitted { operator_id, attempted_op: "CreateSession" } }` per the standard envelope.

---

### `session revoke`

**Purpose:** Mark a planner session as revoked, after which any further IPC frames presenting that token are rejected with `UNAUTHORIZED { reason: SessionRevoked }`. This is the v1 mechanism for terminating a misbehaving planner without killing the kernel; combine with `task abort` if the underlying task should also be terminated.

**Usage:** `raxis-cli session revoke <session_id>`

**Behaviour:**
1. CLI opens operator socket; performs challenge-response handshake.
2. CLI sends `OperatorRequest::RevokeSession { session_id }`.
3. Kernel handler (`handlers/operator::handle_revoke_session`) checks `permitted_ops`, then calls `authority::session::revoke_session(session_id, &store, &audit)` which executes `UPDATE sessions SET revoked_at = now() WHERE session_id = ? AND revoked_at IS NULL` inside one store transaction (INV-STORE-02) and appends `AuditEventKind::SessionRevoked { session_id, revoked_by_operator: <fingerprint>, revoked_at }` to the chain.
4. On success: `OperatorResponse::SessionRevoked { session_id, revoked_at }`. CLI prints `Session <session_id> revoked at <timestamp>`.
5. On precondition failure: if the session row does not exist → `OperatorResponse::Error { code: FAIL_SESSION_NOT_FOUND, detail: SessionNotFound { session_id } }`. If it was already revoked (idempotency hit — `rows_affected == 0`) → `OperatorResponse::Error { code: FAIL_SESSION_ALREADY_REVOKED, detail: SessionAlreadyRevoked { session_id, revoked_at } }`. Both are non-fatal from the operator's perspective (the desired end state is the same), but the CLI exits non-zero to make orchestration scripts notice the unexpected condition.
6. **Effect on in-flight IPC.** A planner that has an open connection holding an active stream is **not** disconnected synchronously — the kernel does not currently reach into the per-connection task to close the socket on revocation. The next IPC frame that flows through `ipc/auth.rs::validate` reads the now-revoked session row and is rejected with `UNAUTHORIZED { reason: SessionRevoked }`, which closes the connection. Practically this means a long-running inference call may complete before the planner sees the revocation; operators relying on hard cut-off semantics MUST also `task abort` the relevant task (which prevents further state writes from any subsequent intent regardless of session validity).

**Effect on `delegations`.** Active delegations on the revoked session remain rows in the `delegations` table for audit purposes; they cannot be exercised because every gated action goes through `validate` first. v1 does not eagerly mark delegations `Revoked`; this is by design (one source of truth — the session row).

**Authorisation:** Requires `RevokeSession ∈ permitted_ops`. Failure → `OperatorResponse::Error { code: UNAUTHORIZED, detail: OperationNotPermitted { operator_id, attempted_op: "RevokeSession" } }`.

---

### `delegation grant`

**Purpose:** Grant a planner session a specific `CapabilityClass` for a bounded TTL, scoped under a specific `delegating_role_id` whose ceiling in `policy.toml` constrains what may be granted. Until a delegation is granted, the planner cannot pass any gate that requires that capability class — its first attempt returns `FAIL_CAPABILITY_REQUIRED`. The standard operator workflow is `session create` → `delegation grant` × N → hand the token to the planner spawn.

**Usage:** `raxis-cli delegation grant --session <session_id> --capability <capability_class> --role <role_id> --ttl <seconds> [--scope-json <inline-json>]`

- `--session <session_id>` — required; the session that will receive the delegation. Must be active (not revoked, not expired).
- `--capability <capability_class>` — required; one of the canonical `CapabilityClass` enum names (e.g. `WriteSecrets`, `NetworkEgress`, `BreakGlass`). The full enum is defined in `raxis-types/src/capability.rs`; the kernel rejects any value not in the enum at deserialise time (`FAIL_UNKNOWN_CAPABILITY_CLASS`).
- `--role <role_id>` — required; the role under whose ceiling the grant is being made. Must be a key of `policy.role_ceilings`; the requested capability must be present in that role's ceiling bitmap. Roles are operator-defined; common v1 examples are `software-engineer`, `infra-operator`, `incident-responder`.
- `--ttl <seconds>` — required; integer seconds into the future. Must satisfy `0 < ttl <= policy.delegations.max_ttl_seconds` (default 86400 = 24h). The kernel computes `expires_at = now() + ttl` and stores it.
- `--scope-json <inline-json>` — optional; a free-form JSON document that scopes the capability beyond the class itself (e.g. `{"domains":["api.stripe.com"]}` for `NetworkEgress`). Schema is per-capability and lives in `raxis-types`. The kernel stores the raw JSON in `delegations.scope_json` and passes it to capability checks via `gates/claim.rs`.

**Behaviour:**
1. CLI opens operator socket; performs challenge-response handshake. The handshake establishes which operator is authenticated; the operator's **private** key (loaded from `--operator-key <path>` or the configured default keystore location — same key used by `raxis-cli policy sign` and `raxis-cli escalation approve`) must be available to the CLI process for the next step.
2. CLI builds the canonical signing-domain bytes per [`kernel-store.md`](kernel-store.md) §2.5.5 "Delegation grant signing domain on the operator socket" — the byte-exact concatenation `"RAXIS-V1-DELEGATION-GRANT" || 0x00 || session_id (UUID hyphenated) || 0x00 || capability_class || 0x00 || role_id || 0x00 || expires_at_le_u64 || 0x00 || scope_json_present_byte || (length-prefixed scope_json bytes if Some)`. CLI computes `signing_input = SHA-256(canonical_bytes)` and `operator_sig = Ed25519Sign(operator_private_key, signing_input)`.
3. CLI sends `OperatorRequest::GrantDelegation { session_id, capability_class, delegating_role_id, expires_at, scope_json, operator_sig }`. The `op_token` (operator session token from step 1's handshake) is carried in the IPC envelope header per the standard operator socket auth.
4. Kernel handler (`handlers/operator::handle_grant_delegation`) checks `permitted_ops ∋ GrantDelegation`, then calls `authority::delegation::grant_delegation(req, &store, &policy, &audit)` (full contract in [`kernel-core.md`](kernel-core.md) Part 2.3 §`authority/delegation.rs`). The handler runs the now-six-step sequence: session validity → policy ceiling check → operator-signature verification (step 2.5) → TTL bounds check → uniqueness check → insert + audit (single transaction, INV-STORE-02).
5. On success: `OperatorResponse::DelegationGranted { delegation_id, granted_at, expires_at, capability_class }`. CLI prints `Delegation <delegation_id> granted: session=<session_id> capability=<class> role=<role_id> expires=<timestamp>`.
6. On precondition failure, the response is `OperatorResponse::Error { code, detail }` with one of the failure codes enumerated in [`kernel-store.md`](kernel-store.md) §2.5.5 operator-error envelope: `FAIL_SESSION_INVALID`, `FAIL_CAPABILITY_ABOVE_CEILING`, `FAIL_DELEGATION_SIGNATURE_INVALID`, `FAIL_DELEGATION_TTL_OUT_OF_RANGE`, `FAIL_DELEGATION_ALREADY_ACTIVE`, `FAIL_UNKNOWN_CAPABILITY_CLASS`. The CLI deserialises `detail` and renders a human-readable message. **`FAIL_DELEGATION_SIGNATURE_INVALID` almost always indicates a CLI/kernel disagreement on the canonical-bytes serialisation** — implementers MUST add a regression test that round-trips the canonical bytes between the CLI signer and the kernel verifier on every supported `(scope_json present/absent, capability class, role id)` cross-product before merging changes to either side.
7. Audit: `AuditEventKind::DelegationGranted { delegation_id, session_id, capability_class, delegating_role_id, granted_by_operator: <fingerprint>, expires_at, operator_sig_sha256, scope_json_sha256 }` (both the signature and the scope JSON are stored as SHA-256 in the audit event, with the raw signature persisted in `delegations.operator_signature` and the raw scope JSON in `delegations.scope_json` — keeps the audit chain compact and avoids leaking large scope payloads into a frequently-rotated segment).

**Re-granting after expiry or revocation.** v1 has no in-place "renew" path. To re-grant after expiry, the operator submits a fresh `delegation grant` for the same `(session, capability)` — the prior row's `status` will already be `Expired` (TTL passed), so the UNIQUE constraint (`status IN ('Active', 'StaleOnNextUse')`) does not block. After a `RotateEpoch`, all `Active` delegations transition to `StaleOnNextUse` per `mark_stale_on_epoch_advance`; the planner gets one final use with `warn_delegation_stale = true`, after which a new `delegation grant` is required. There is no `RevokeDelegation` operator IPC in v1; deferred to v2 alongside the broader `policy.delegations.lifecycle` features.

**Authorisation:** Requires `GrantDelegation ∈ permitted_ops`. Failure → `OperatorResponse::Error { code: UNAUTHORIZED, detail: OperationNotPermitted { operator_id, attempted_op: "GrantDelegation" } }`.

---

### `epoch advance`

**Purpose:** Advance the policy epoch by loading and verifying a new signed policy artifact, sweeping all active delegations to `StaleOnNextUse`, invalidating all session prompt caches, swapping the in-memory policy bundle and domain allowlist, and signalling the gateway to reload.

**Usage:** `raxis-cli epoch advance --policy <path> --sig <path>`

Both arguments are **required**. There is no implicit staged location. The kernel canonicalises both paths and rejects any path that does not resolve under `<data_dir>/policy/` (`PolicyError::PathOutsideDataDir`); operators stage new artifacts inside `<data_dir>/policy/` (e.g. `policy.toml.next` + `policy.toml.next.sig`) before invoking the command. Capturing the exact paths in shell history and in the audit record is intentional — it ties an epoch-advance event to a specific on-disk artifact pair without an implicit "current staged" mutable pointer.

**Behaviour:**
1. CLI opens the operator socket; performs the challenge-response handshake ([`peripherals.md`](peripherals.md) operator socket auth). The handshake establishes the `OperatorId` of the invoker (looked up from `[[operators.entries]]` in the current policy artifact); this `OperatorId` is forwarded to the kernel as `triggered_by` in step 2.
2. CLI sends `OperatorRequest::RotateEpoch { policy_path: PathBuf, sig_path: PathBuf }` carrying the resolved absolute paths from the `--policy` / `--sig` arguments. (Empty payload is **not** valid; the kernel rejects `RotateEpoch` IPC messages with empty paths at the deserialiser before reaching the handler.)
3. Kernel handler (`handlers/operator::handle_rotate_epoch`) calls `policy_manager::advance_epoch(policy_path, sig_path, &triggered_by, &registry, &ctx)` (full contract in [`kernel-core.md`](kernel-core.md) §`policy_manager.rs`). The handler runs the four-phase sequence: (Phase 0) verify the artifact signature, epoch-monotonicity, and TOML shape; (Phase 1) one SQL transaction holding the `Store` mutex, doing the delegations sweep + session-prompt invalidation + `policy_epoch` row insert + `PolicyEpochAdvanced` audit append; (Phase 2) `ArcSwap` swaps for `ctx.policy` and `ctx.allowlist_cache`; (Phase 3) best-effort `GatewayMessage::EpochAdvanced` signal.
4. On success, kernel responds `OperatorResponse::EpochAdvanced { new_epoch_id, n_delegations_marked_stale, n_sessions_invalidated, policy_sha256 }`. CLI prints all four values so the operator can confirm the artifact identity and the scope of the sweep.
5. On failure, kernel responds `OperatorResponse::Error { code, detail }` where `code` is one of `FAIL_POLICY_SIGNATURE_INVALID`, `FAIL_POLICY_EPOCH_REPLAY`, `FAIL_POLICY_MALFORMED`, `FAIL_PATH_OUTSIDE_DATA_DIR`, or `FAIL_STORE_WRITE` (Phase 0 rejection codes vs Phase 1 commit failure; per the audit-on-rejection contract in [`kernel-core.md`](kernel-core.md), the corresponding `PolicyAdvanceRejected` or `PolicyAdvanceFailed` audit event is appended before the kernel returns). CLI exits non-zero and prints the error.
6. Active planner sessions are **not** disconnected — their next inference request triggers prompt reassembly under the new epoch (per `prompt::epoch_binding` flow in [`kernel-core.md`](kernel-core.md)). Active delegations are flagged `StaleOnNextUse`: the next gated action against each delegation passes once with `warn_delegation_stale = true` in the `IntentResponse` (see [`peripherals.md`](peripherals.md) §3.1), then must be renewed before the following action.

**Audit event name correction:** the canonical event kind is `AuditEventKind::PolicyEpochAdvanced` (with payload `{ old_epoch, new_epoch, policy_sha256, signed_by_authority, triggered_by, advanced_at, n_delegations_marked_stale, n_sessions_invalidated }`). Older draft text using `AuditEventKind::EpochAdvanced` is non-canonical and is being swept out of all spec sites in this revision.

---

### `verify-chain` (was `audit verify` in V1 drafts)

**Purpose:** Verify the integrity of the JSONL audit chain. Does not connect to the kernel.

**Status:** **CONSOLIDATED in V2.** The V1-draft `audit verify` single-segment shim has been removed; `verify-chain` is the only audit-verification surface (no two CLI commands may perform the same action).

**Usage:** `raxis verify-chain [--quick] [--from <seq>] [--audit-dir <path>]`

Default audit dir: `<data_dir>/audit/` (every `segment-NNN.jsonl` in numeric order). The full canonical reference is [`cli-readonly.md §5.5.13`](cli-readonly.md).

**Behaviour:**

1. Walks `<audit-dir>/segment-NNN.jsonl` in numeric order via `raxis_audit_tools::ChainReader`.
2. Asserts `prev_sha256` linkage and `seq` monotonicity per record AND across the segment seam.
3. `--quick` is a fast first-+-last-record check (mirrors `raxis status`'s liveness probe).
4. `--from <seq>` narrows the reported stats to records with `seq ≥ <seq>`; the whole chain is still walked end-to-end for linkage.
5. Exit codes: `0` (intact), `3` (broken — chain link mismatch / gap / malformed record), `2` (CLI usage error).

**Why the consolidation:** The V1 `audit verify` did the same job (chain-walk per record) but only on a single hand-named segment, with a hand-rolled JSON parser that drifted from `raxis_audit_tools`. Folding it into `verify-chain` removes a duplicate audit surface AND ensures every operator path through the codebase parses chain bytes through the same library.

---

### `notify channel add | delete | probe | test` (V2)

**Purpose:** Manage operator notification channels (`Email`, `Sidecar`; v1 carryover `Shell`, `File`). The full subsystem is specified in `email-and-notification-channels.md`. These commands wrap edits to the `[[notifications.channels]]` section of `policy.toml` and call the existing `policy sign` ceremony — the signed bundle remains the source of truth.  The V1-draft `Webhook` kind was folded into `Sidecar` in V2.5 (forward-only).

**Usage:**

```bash
# Add an Email channel (interactive; smtp_relay/auth/cred_ref prompted then re-signed)
raxis-cli notify channel add ops-email \
    --kind email \
    --to alerts@example.com,oncall@example.com \
    --from raxis@example.com \
    --smtp-relay smtps://smtp.example.com:587 \
    --auth-method plain \
    --cred-ref smtp-ops-cred

# Add a Sidecar channel (POST → operator-run translator → Slack /
# PagerDuty / Teams / Discord / ...).  The sidecar handles its own
# upstream auth; kernel-to-sidecar trust is the localhost boundary.
raxis-cli notify channel add ops-sidecar \
    --kind sidecar \
    --target http://localhost:9200/notify \
    --max-in-flight 8

# Delete a channel (refused if any [[notifications.routes]] still references it)
raxis-cli notify channel delete ops-email

# Synchronous probe (same code path as boot probe)
raxis-cli notify channel probe ops-email

# Send a synthetic event; emits AuditEventKind::NotificationTestSent
raxis-cli notify test --channel ops-email --severity Operational
```

**Behaviour:**

1. CLI opens the operator socket; performs the challenge-response handshake.
2. For `add`/`delete`: kernel parses the requested edit, applies it to a tentative `policy.toml`, runs `PolicyBundle::validate` (returns any `FAIL_NOTIFY_CHANNEL_*` / `FAIL_NOTIFY_ROUTE_*` failure code per `policy-plan-authority.md` failure-code catalog), prompts the operator to confirm and re-sign, then advances the policy epoch.
3. For `probe`: kernel calls `OperatorNotificationChannel::probe()` directly; CLI prints `ProbeOutcome` (reachable, auth_ok, round_trip_ms, server_banner). Probe failure is non-fatal — channel marked Degraded but boot continues.
4. For `test`: kernel emits a synthetic `AuditEventKind::NotificationTestSent { channel_id, actor, triggered_at_ms }` and routes it through the dispatcher. Outcome reaches the operator via the channel under test (closing the loop end-to-end). Audit record records both the test send and the dispatcher's eventual `NotificationDelivered` / `NotificationDeliveryFailed`.

**Cross-reference:** Schema in [`cli-readonly.md §5.6.2`](cli-readonly.md); trait in `extensibility-traits.md §6A`; threat model in `email-and-notification-channels.md §1.2`.

---

### `notify route add | delete` (V2)

**Purpose:** Manage `[[notifications.routes]]` mapping audit-event kinds to notification channel IDs. Same signing-ceremony as `notify channel add`.

**Usage:**

```bash
raxis-cli notify route add \
    --event-kind EscalationSubmitted \
    --channel ops-email,audit-mirror

raxis-cli notify route delete \
    --event-kind EscalationSubmitted \
    --channel ops-email
```

**Behaviour:** edits the `[[notifications.routes]]` block in `policy.toml`, validates that every `event_kind` is a real `AuditEventKind` variant and every channel id is declared in `[[notifications.channels]]`, prompts for re-sign, advances the epoch.

---

### `notify credential add | delete | rotate` (V2)

**Purpose:** Manage credentials the **kernel itself** uses to talk to upstream notification channels (SMTP relay password, future Slack token). Sidecar channels handle their own upstream auth — the kernel-to-sidecar boundary is loopback only — so no `notify credential` entry is required for Sidecar.  Distinct from `raxis credential add` which manages credentials the kernel proxies *for an agent*. Stored at `<data_dir>/credentials/<cred-ref>.notify-cred`, mode 0600, kernel-readable only.

**Usage:**

```bash
# SMTP relay password (read from STDIN, never argv — no shell history leakage)
raxis-cli notify credential add smtp-ops-cred \
    --kind smtp-plain \
    --username service@example.com \
    --password-stdin

# OAuth2 (Gmail / Office365)
raxis-cli notify credential add smtp-oauth-cred \
    --kind smtp-xoauth2 \
    --username service@example.com \
    --refresh-token-from-stdin

raxis-cli notify credential delete <cred-ref>
raxis-cli notify credential rotate <cred-ref>
```

**Why a separate `notify credential` namespace** (not reused `raxis credential`): the trust line is real. `raxis credential add ...` registers credentials the kernel proxies *for an agent*, referenced from `[[permitted_credentials]]` and bound to a `proxy_type`. `notify credential` registers credentials the kernel uses *itself* to reach an external operator-notification destination, referenced from `[[notifications.channels]]` and never injected into a VM. Mixing them would erase that trust line. See `email-and-notification-channels.md §4.1.3` for the full rationale.

---

### `audit gaps` — consolidated into `verify-chain`

**Status:** **REMOVED in V2.** Reporting reconstructed records (`reconstructed: true` rows from `recovery::reconcile`) lives inside the same chain walk that `verify-chain` already performs. A separate `audit gaps` subcommand would mean two operator paths through the same JSONL parser, which violates the no-duplicate-action invariant. `raxis verify-chain` already exits non-zero (code 3) on a chain break or gap; `raxis log --kind reconciliation` (the catalogued read-only surface) renders the per-record `reconstructed: true` rows.

---

## §4.2 — Genesis Ceremony Step-by-Step

This section is the normative walkthrough for a first-time operator setting up RAXIS v1 from scratch.

### Prerequisites

- The `raxis-kernel` and `raxis-cli` binaries are installed and on `$PATH`.
- The operator has generated their own Ed25519 keypair on a machine they control (the private key should never touch the machine running the kernel if possible, but v1 permits co-location).
- The data directory (`~/.raxis` by default) is empty.
- The operator has minted a self-signed `OperatorCert` (cert-mandatory by INV-CERT-01) — see [`cert mint`](#cert-mint) below — OR is willing to let the CLI mint one in-process from a private-key PEM via `--operator-key` (the convenience path; private bytes are never persisted).

### Step 1 — Run genesis

**Path A — air-gapped (recommended)**: pre-mint the cert on the
machine that holds the operator private key, then run genesis on the
target host with the cert file:

```bash
# On the operator's air-gapped workstation
raxis-cli cert mint --key ~/my-operator-key.pem \
    --display-name "chika" --out chika.cert.toml

# Transfer chika.cert.toml to the kernel host, then:
raxis-cli genesis --operator-cert ./chika.cert.toml
```

**Path B — convenience (single-machine setups)**: hand the CLI the
private key directly; it mints + embeds the cert in-process and
never persists the private bytes:

```bash
raxis-cli genesis --operator-key ~/my-operator-key.pem \
    --operator-name "chika"
```

Both paths generate all kernel keys and a skeleton `policy.toml`
with the operator cert embedded under `[operators.entries.cert]`.
Review the output file at `~/.raxis/policy/policy.toml` before
proceeding.

### Step 2 — Edit `policy.toml`

Add at minimum:
- `[[gates]]` entries for each gate type you want to enforce.
- `[[tasks]]` entries if you want a global task allowlist (optional in v1 — the signed plan is the authoritative task list).
- Domain allowlist entries for provider URLs.
- Budget limits.

Do not modify `authority_pubkey` or `quality_pubkey` — these were written by genesis and match the generated keypairs.

### Step 3 — Sign the policy

```bash
raxis-cli policy sign ~/.raxis/policy/policy.toml --key ~/.raxis/keys/authority_keypair.pem
```

This writes `~/.raxis/policy/policy.sig`. The kernel verifies this signature at boot. If `policy.sig` is absent or invalid, the kernel will not start.

### Step 4 — Start the kernel

```bash
raxis-kernel --data-dir ~/.raxis
```

The kernel loads keys, verifies `policy.sig`, binds all three sockets, and is ready.

### Step 5 — Write and sign a plan

Create `~/my-plan/plan.toml` following the plan schema (see §2.5.3 and the fixture examples in §4.3). Then:

```bash
raxis-cli policy sign ~/my-plan/plan.toml --key ~/my-operator-key
```

### Step 6 — Submit and approve

```bash
raxis-cli plan submit initiative-001 ~/my-plan
raxis-cli plan approve initiative-001
```

Tasks are now scheduled. The planner session can begin.

### Re-genesis / key rotation

**Always stop the kernel before any key rotation.** Run:

```bash
raxis-cli genesis --rotate <key-family>
# After the kernel restarts, stage the re-signed policy artifact under
# <data_dir>/policy/ (e.g. as policy.toml.next + policy.toml.next.sig) then:
raxis-cli epoch advance \
  --policy <data_dir>/policy/policy.toml.next \
  --sig    <data_dir>/policy/policy.toml.next.sig
```

---

## §4.3 — Integration Test Fixtures

The canonical fixtures live at `raxis/fixtures/`. Each fixture is a minimal valid plan TOML that exercises a specific invariant or system behaviour. The v1 test matrix (§1.3 in [`philosophy.md`](philosophy.md)) cross-references these fixtures by name.

### Fixture schema

All fixture files follow the signed plan schema defined in §2.5.3. They are not pre-signed — test harnesses sign them with a test key generated at test setup time.

---

### `fixtures/minimal_plan.toml` — Simplest valid plan

**Exercises:** INV-INIT-06 (plan immutability), INV-TASK-PATH-01 (path scope admission), INV-SCHED-01 (admit called only from approve_plan).

```toml
[plan]
initiative_id  = "test-minimal-001"
description    = "Minimal single-task plan with no gates and no dependencies"
version        = "1"

[[tasks]]
task_name        = "task-alpha"
description    = "Implement the feature"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/", "tests/"]
predecessors   = []
gates          = []

terminal_criteria = "AllTasksSucceeded"
```

**Expected terminal state:** `initiative.status = Completed` after `task-alpha` reaches `Completed`.

**Key checks:**
- `create_session` with `worktree_root` pointing to a valid git repo succeeds.
- `IntentRequest { intent_kind: "SingleCommit", task_id: "task-alpha" }` with a path outside `["src/", "tests/"]` → `FAIL_PATH_POLICY_VIOLATION`.
- `IntentRequest` with `task_id: "task-unknown"` → `FAIL_UNKNOWN_TASK`.
- `CompleteTask` with all paths in scope and no gate requirements → accepted; task transitions to `Completed`.

---

### `fixtures/gated_plan.toml` — Single gate

**Exercises:** INV-03 (witness SHA binding), INV-07 (kernel-derived claims), gate evaluation lifecycle, `FAIL_MISSING_WITNESS`, `FAIL_INSUFFICIENT_WITNESS`.

```toml
[plan]
initiative_id  = "test-gated-001"
description    = "Single task with one TestCoverage gate"
version        = "1"

[[tasks]]
task_name        = "task-beta"
description    = "Implement and test the feature"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/", "tests/"]
predecessors   = []
gates          = [{ gate_type = "TestCoverage", threshold = 80 }]

terminal_criteria = "AllTasksSucceeded"
```

**Expected terminal state:** `initiative.status = Completed` only after `task-beta` has a `Pass` witness for `TestCoverage` bound to the final `head_sha`.

**Key checks:**
- `CompleteTask` before a witness exists → `FAIL_MISSING_WITNESS`.
- `CompleteTask` with a witness bound to a different SHA → kernel rejects the CompleteTask (INV-03 — witness is SHA-bound, not reusable).
- A witness with `result_class: "Fail"` (coverage below threshold) → `FAIL_INSUFFICIENT_WITNESS`.
- A witness with `result_class: "Pass"` bound to the correct `evaluation_sha` → `CompleteTask` accepted.

---

### `fixtures/dag_plan.toml` — DAG with dependencies

**Exercises:** DAG scheduling, predecessor-gate blocking, `scheduler::next_ready_tasks`, task lifecycle across multiple tasks.

```toml
[plan]
initiative_id  = "test-dag-001"
description    = "Three-task dependency chain"
version        = "1"

[[tasks]]
task_name        = "task-1-foundation"
description    = "Build the foundation layer"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/foundation/"]
predecessors   = []
gates          = []

[[tasks]]
task_name        = "task-2-feature"
description    = "Build the feature on top"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/feature/"]
predecessors   = ["task-1-foundation"]
gates          = []

[[tasks]]
task_name        = "task-3-integration"
description    = "Integration wiring"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/integration/", "tests/integration/"]
predecessors   = ["task-1-foundation", "task-2-feature"]
gates          = []

terminal_criteria = "AllTasksSucceeded"
```

**Expected terminal state:** `initiative.status = Completed` after all three tasks complete in dependency order.

**Key checks:**
- `task-2-feature` is in `Admitted` state but is **not returned by `next_ready_tasks`** until `task-1-foundation` is `Completed`. (`Blocked` is an initiative-level state, not a task state — individual tasks with unsatisfied predecessors remain `Admitted`.)
- `task-3-integration` is similarly in `Admitted` with two unsatisfied predecessor edges; `next_ready_tasks` does not surface it until both are `Completed`.
- Attempting to submit an intent for a task not returned by `next_ready_tasks` → `FAIL_TASK_NOT_RUNNING` (the task is `Admitted`, not `Running`).
- After `task-1-foundation` completes, the next `next_ready_tasks` query surfaces `task-2-feature` (now all predecessor edges satisfied); a planner session may claim it.

---

### `fixtures/integration_plan.toml` — IntegrationMerge task

**Exercises:** `IntentKind::IntegrationMerge` 5-predicate topology check, stale-base check, `FAIL_STALE_BASE`, `FAIL_INVALID_COMMIT_TOPOLOGY`.

```toml
[plan]
initiative_id  = "test-integration-001"
description    = "Two agent tasks plus one integration merge task"
version        = "1"

[[tasks]]
task_name        = "task-agent-a"
description    = "Agent A feature branch"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/feature-a/"]
predecessors   = []
gates          = []

[[tasks]]
task_name        = "task-agent-b"
description    = "Agent B feature branch"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/feature-b/"]
predecessors   = []
gates          = []

[[tasks]]
task_name        = "task-integration"
description    = "Merge agent branches onto main"
intent_kinds   = ["IntegrationMerge", "CompleteTask"]
path_allowlist = ["src/feature-a/", "src/feature-b/"]
predecessors   = ["task-agent-a", "task-agent-b"]
gates          = []

terminal_criteria = "AllTasksSucceeded"
```

**Expected terminal state:** All three tasks `Completed`; initiative `Completed`.

**Key checks:**
- `IntegrationMerge` intent where `head_sha` is not a merge commit → `FAIL_INVALID_COMMIT_TOPOLOGY`.
- `IntegrationMerge` intent where the merge base has advanced past `sessions.base_tracking_ref` → `FAIL_STALE_BASE`.
- Valid merge commit (exactly two parents, both fast-forward reachable from the integration branches, merge base equals `sessions.base_sha`) → accepted.
- `task-integration` is in `Admitted` state with two unsatisfied predecessor edges; `next_ready_tasks` does not surface it until both agent tasks are `Completed`.

---

### Test harness notes

- All fixtures are signed at test-harness setup time with a test-generated Ed25519 keypair. The test harness runs a `genesis` step with the test key before each fixture test.
- Each fixture test runs the kernel in a temporary `--data-dir` to ensure isolation.
- Gate fixtures (`gated_plan.toml`) use a test verifier binary that reads `RAXIS_GATE_TYPE` and returns a configurable `result_class` via a control file, making gate outcomes deterministic.
- All fixture tests must pass before a v1 release gate is signed (§1.4 in [`philosophy.md`](philosophy.md)).
