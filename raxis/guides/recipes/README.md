# RAXIS Recipes

> **Audience.** Operators and plan authors who want a focused
> answer to "how do I configure / drive / inspect this one
> thing?" without reading a full architecture spec.

This is the **recipe book**: 105 short, self-contained tutorials,
each scoped to one concept (one CLI verb, one policy section,
one plan field, one operational task, or one common pattern).
Every recipe is a single Markdown file with the answer, the
config, and the failure modes. They do not chain — each is
runnable on its own.

> **What this is NOT.** It is not a runnable scenario folder. If
> you want a full plan + policy + walkthrough you can `cd` into
> and run end-to-end, see [`../scenarios/`](../scenarios/) (the
> scenario catalogue). Recipes are for "I just need to know how
> X works"; scenarios are for "show me an initiative running
> from genesis to merged commit".

---

## How to use this book

1. **Browse by category** below. Each folder is one slice of the
   surface area: setup, env vars, policy, plan, patterns, CLI,
   ops.
2. **Use the lookup tables** in this file to jump straight to
   "how do I `<verb>`?" without scanning folders.
3. **Read whichever recipe answers the question and stop.**
   Recipes are deliberately self-contained; no recipe assumes
   you've read another. The cost is some duplication; the
   benefit is no link-chasing.

Every recipe ends with a `Reference` table linking to the
normative spec (`specs/v1/`, `specs/v2/`) and the source of truth
(`crates/`, `kernel/src/`). Use those when the recipe says
"trust me" and you don't.

---

## Layout

```text
guides/recipes/
├── setup/        — One-time bootstrapping, key/cert ceremony, daemon install
├── env/          — Every RAXIS_* and per-binary env var the runtime honours
├── policy/       — Each top-level section of policy.toml, signed and explained
├── plan/         — Each top-level field/section of plan.toml
├── patterns/     — Common multi-task plan patterns (fan-out, panel, retry, …)
├── cli/          — Every `raxis <verb>` subcommand, with examples and exit codes
└── ops/          — Day-2 operational tasks (rotate, restore, upgrade, debug)
```

| Category | Count | Best for |
|---|---:|---|
| [setup](#setup-bootstrapping) | 10 | Fresh machine; first kernel; first plan |
| [env](#env-environment-variables) | 12 | Tuning binary behaviour without touching policy |
| [policy](#policy-the-operator-signed-config) | 16 | Authoring or auditing `policy.toml` |
| [plan](#plan-the-toml-plan-bundle) | 12 | Authoring or debugging `plan.toml` |
| [patterns](#patterns-common-plan-shapes) | 8 | Choosing the right multi-task topology |
| [cli](#cli-every-raxis-subcommand) | 33 | "What does `raxis <X>` do? What's the JSON schema?" |
| [ops](#ops-day-2-operations) | 15 | Running RAXIS in anger: outages, rotations, debugging |

---

## Quick lookup — "How do I…?"

### Authoring plans

| I want to… | Recipe |
|---|---|
| Write the smallest possible `plan.toml` | [`plan/01-plan-initiative-block`](plan/01-plan-initiative-block.md) |
| Set the workspace base/target ref | [`plan/02-workspace-block`](plan/02-workspace-block.md) |
| Declare an Executor or Reviewer task | [`plan/03-tasks-block`](plan/03-tasks-block.md), [`plan/06-session-agent-type`](plan/06-session-agent-type.md) |
| Restrict what files a task can write | [`plan/04-path-allowlist`](plan/04-path-allowlist.md) |
| Pick `full` / `sparse` / `blobless` clones | [`plan/05-clone-strategy`](plan/05-clone-strategy.md) |
| Order tasks (DAG / chain) | [`plan/07-predecessors`](plan/07-predecessors.md) |
| Inject credentials into a task | [`plan/08-task-credentials`](plan/08-task-credentials.md) |
| Allow specific outbound HTTP egress | [`plan/09-vm-image-and-egress`](plan/09-vm-image-and-egress.md) |
| Configure the auto-spawned Orchestrator | [`plan/10-orchestrator-block`](plan/10-orchestrator-block.md) |
| Add a `cargo test` / `pytest` mechanical gate | [`plan/11-task-verifiers`](plan/11-task-verifiers.md) |
| Set per-task wall-clock + retry budgets | [`plan/12-cumulative-max-seconds`](plan/12-cumulative-max-seconds.md), [`patterns/04-retry-on-failure`](patterns/04-retry-on-failure.md) |

### Choosing a multi-task topology

| I have… | Recipe |
|---|---|
| Independent slices that can run in parallel | [`patterns/01-fan-out-then-merge`](patterns/01-fan-out-then-merge.md) |
| One Executor that needs multiple Reviewer perspectives | [`patterns/02-reviewer-panel`](patterns/02-reviewer-panel.md) |
| A merge that must pass `cargo test --workspace` | [`patterns/03-merge-with-integration-verifiers`](patterns/03-merge-with-integration-verifiers.md) |
| A flaky Executor or refactor that may need re-runs | [`patterns/04-retry-on-failure`](patterns/04-retry-on-failure.md) |
| A migration that must apply in stages | [`patterns/05-staged-rollout`](patterns/05-staged-rollout.md) |
| A refactor where every Executor edits a shared lockfile | [`patterns/06-cross-cutting-refactor`](patterns/06-cross-cutting-refactor.md) |
| A risky change I want to canary first | [`patterns/07-canary-then-broad-change`](patterns/07-canary-then-broad-change.md) |
| A bulk job I need to throttle by host capacity | [`patterns/08-budget-bounded-cohort`](patterns/08-budget-bounded-cohort.md) |

### Authoring policy

| I want to… | Recipe |
|---|---|
| Write the smallest valid `policy.toml` | [`policy/01-meta-section`](policy/01-meta-section.md) |
| Add a second operator | [`policy/02-authority-section`](policy/02-authority-section.md), [`setup/10-add-second-operator`](setup/10-add-second-operator.md) |
| Configure escalation routing | [`policy/03-escalation-policy`](policy/03-escalation-policy.md) |
| Bound session lifetimes | [`policy/04-sessions-section`](policy/04-sessions-section.md) |
| Permit cross-session delegation | [`policy/05-delegations-section`](policy/05-delegations-section.md) |
| Cap operator/lane spend | [`policy/06-budget-section`](policy/06-budget-section.md) |
| Define a lane and its concurrency | [`policy/07-lanes-section`](policy/07-lanes-section.md) |
| Tie operators to roles | [`policy/08-operators-section`](policy/08-operators-section.md) |
| Configure the kernel's egress proxy | [`policy/09-gateway-section`](policy/09-gateway-section.md) |
| Configure LLM providers | [`policy/10-providers-section`](policy/10-providers-section.md) |
| Publish a VM image alias | [`policy/11-vm-images-section`](policy/11-vm-images-section.md) |
| Tune host CPU/RAM/disk caps | [`policy/12-host-capacity`](policy/12-host-capacity.md) |
| Require operator-signed plans | [`policy/13-plan-signing`](policy/13-plan-signing.md) |
| Cap plan-bundle byte size and task count | [`policy/14-plan-bundle-limits`](policy/14-plan-bundle-limits.md) |
| Wire kernel notifications to email/Slack/webhook | [`policy/15-notifications-section`](policy/15-notifications-section.md) |
| Bound elastic VM scaling + transient-retry budget | [`policy/16-elastic-section`](policy/16-elastic-section.md) |

### Driving the kernel via CLI

| I want to… | Recipe |
|---|---|
| First-time machine setup | [`cli/01-genesis`](cli/01-genesis.md) |
| Sign / view / diff `policy.toml` | [`cli/02-policy-sign`](cli/02-policy-sign.md), [`cli/03-policy-show`](cli/03-policy-show.md), [`cli/04-policy-diff`](cli/04-policy-diff.md) |
| Validate / format / scaffold a plan | [`cli/05-plan-validate`](cli/05-plan-validate.md), [`cli/06-plan-fmt`](cli/06-plan-fmt.md), [`cli/07-plan-init`](cli/07-plan-init.md) |
| Submit / approve / reject a plan | [`cli/08-submit-plan`](cli/08-submit-plan.md), [`cli/09-plan-approve-reject`](cli/09-plan-approve-reject.md) |
| List / show / abort an initiative | [`cli/10-initiative-list`](cli/10-initiative-list.md), [`cli/11-initiative-show`](cli/11-initiative-show.md), [`cli/12-initiative-abort-quarantine`](cli/12-initiative-abort-quarantine.md) |
| Pause / resume / requeue tasks | [`cli/13-task-control`](cli/13-task-control.md) |
| Manage sessions, delegations, escalations | [`cli/14-session-create-revoke`](cli/14-session-create-revoke.md), [`cli/15-delegation-grant`](cli/15-delegation-grant.md), [`cli/16-escalation-approve-deny`](cli/16-escalation-approve-deny.md), [`cli/27-sessions-escalations-inbox`](cli/27-sessions-escalations-inbox.md) |
| Mint / verify / install / revoke certs | [`cli/17-cert-mint`](cli/17-cert-mint.md), [`cli/18-cert-show-verify`](cli/18-cert-show-verify.md), [`cli/19-cert-install-revoke`](cli/19-cert-install-revoke.md) |
| Add or rotate credentials | [`cli/20-credential-add`](cli/20-credential-add.md), [`cli/21-credential-list-show-rotate`](cli/21-credential-list-show-rotate.md) |
| Install / uninstall the kernel | [`cli/22-kernel-install-uninstall`](cli/22-kernel-install-uninstall.md) |
| Run health checks (`status` / `doctor`) | [`cli/23-status-doctor`](cli/23-status-doctor.md) |
| Verify the audit chain | [`cli/24-log-verify-chain`](cli/24-log-verify-chain.md) |
| Inspect the queue, witnesses, budgets | [`cli/25-queue-inspect`](cli/25-queue-inspect.md), [`cli/28-witnesses-verifiers`](cli/28-witnesses-verifiers.md), [`cli/29-budget-top`](cli/29-budget-top.md) |
| Explain a kernel decision | [`cli/26-explain`](cli/26-explain.md) |
| Advance a policy epoch by hand | [`cli/30-epoch-advance`](cli/30-epoch-advance.md) |
| Check provider health | [`cli/31-providers-status`](cli/31-providers-status.md) |
| Configure auth signing | [`cli/32-auth-sign-setup`](cli/32-auth-sign-setup.md) |
| Quarantine all plans from a single operator | [`cli/33-operator-quarantine-plans-by`](cli/33-operator-quarantine-plans-by.md) |

### Day-2 operations

| I want to… | Recipe |
|---|---|
| Rotate an operator's certificate | [`ops/01-rotate-operator-cert`](ops/01-rotate-operator-cert.md) |
| Respond to a suspected key compromise | [`ops/02-respond-to-key-compromise`](ops/02-respond-to-key-compromise.md) |
| Back up / restore the kernel store | [`ops/03-backup-and-restore`](ops/03-backup-and-restore.md) |
| Upgrade the kernel binary safely | [`ops/04-upgrade-kernel`](ops/04-upgrade-kernel.md) |
| Investigate a stuck task | [`ops/05-investigate-stuck-task`](ops/05-investigate-stuck-task.md) |
| Tune a lane's concurrency / budget | [`ops/06-tune-lane-budget`](ops/06-tune-lane-budget.md) |
| Monitor the audit chain in production | [`ops/07-monitor-audit-chain`](ops/07-monitor-audit-chain.md) |
| Tune host capacity (CPU/RAM/disk) | [`ops/08-host-capacity-tuning`](ops/08-host-capacity-tuning.md) |
| Publish a verifier or executor VM image | [`ops/09-publish-verifier-image`](ops/09-publish-verifier-image.md), [`ops/10-publish-executor-image`](ops/10-publish-executor-image.md) |
| Add or swap an LLM provider | [`ops/11-add-llm-provider`](ops/11-add-llm-provider.md) |
| Debug a `FAIL_EGRESS_DENIED` | [`ops/12-debug-egress-denial`](ops/12-debug-egress-denial.md) |
| Handle a reconciliation gap on kernel restart | [`ops/13-handle-reconciliation-gap`](ops/13-handle-reconciliation-gap.md) |
| Promote a plan from staging to prod | [`ops/14-staging-to-prod-promotion`](ops/14-staging-to-prod-promotion.md) |
| Run an incident postmortem | [`ops/15-incident-postmortem`](ops/15-incident-postmortem.md) |

### Tuning runtime via env vars

| I want to override… | Recipe |
|---|---|
| Where the kernel data dir lives | [`env/01-raxis-data-dir`](env/01-raxis-data-dir.md) |
| Operator key / cert paths | [`env/02-raxis-operator-key`](env/02-raxis-operator-key.md), [`env/03-raxis-operator-cert`](env/03-raxis-operator-cert.md) |
| Log format (text vs JSON) | [`env/04-raxis-log-format`](env/04-raxis-log-format.md) |
| Force / bootstrap behaviour | [`env/05-raxis-force-and-bootstrap`](env/05-raxis-force-and-bootstrap.md) |
| Where the kernel binary is found | [`env/06-raxis-install-dir`](env/06-raxis-install-dir.md), [`env/08-raxis-kernel-binary`](env/08-raxis-kernel-binary.md) |
| VCS subprocess timeouts | [`env/07-raxis-vcs-timeout`](env/07-raxis-vcs-timeout.md) |
| Fall back from microVM to container isolation | [`env/09-raxis-unsafe-fallback-isolation`](env/09-raxis-unsafe-fallback-isolation.md) |
| Verifier VMs' env passthrough | [`env/10-verifier-env-vars`](env/10-verifier-env-vars.md) |
| Planner VMs' env passthrough | [`env/11-planner-env-vars`](env/11-planner-env-vars.md) |
| The egress proxy and image-encryption keys | [`env/12-tproxy-and-imagekey-env`](env/12-tproxy-and-imagekey-env.md) |

---

## Catalogue (full)

### setup — bootstrapping

| # | Recipe | Topic |
|---|---|---|
| 01 | [`verify-fresh-install`](setup/01-verify-fresh-install.md) | Confirm a clean machine before the genesis ceremony |
| 02 | [`sandbox-on-clean-machine`](setup/02-sandbox-on-clean-machine.md) | Disposable RAXIS sandbox for experimentation |
| 03 | [`offline-keypair`](setup/03-offline-keypair.md) | Generate the operator Ed25519 keypair without network |
| 04 | [`cert-mint`](setup/04-cert-mint.md) | Mint the operator's first certificate |
| 05 | [`install-system-daemon`](setup/05-install-system-daemon.md) | Install kernel as a systemd / launchd service |
| 06 | [`uninstall-cleanly`](setup/06-uninstall-cleanly.md) | Remove RAXIS without stranded files / sockets |
| 07 | [`multiple-data-dirs`](setup/07-multiple-data-dirs.md) | Run multiple isolated kernels on one host |
| 08 | [`allowlist-worktree-roots`](setup/08-allowlist-worktree-roots.md) | Restrict where Executors may clone repositories |
| 09 | [`default-executor-image`](setup/09-default-executor-image.md) | Set the default `[[vm_images]]` for new plans |
| 10 | [`add-second-operator`](setup/10-add-second-operator.md) | Bring a second operator into the policy |

### env — environment variables

| # | Recipe | Variable(s) |
|---|---|---|
| 01 | [`raxis-data-dir`](env/01-raxis-data-dir.md) | `RAXIS_DATA_DIR` |
| 02 | [`raxis-operator-key`](env/02-raxis-operator-key.md) | `RAXIS_OPERATOR_KEY` |
| 03 | [`raxis-operator-cert`](env/03-raxis-operator-cert.md) | `RAXIS_OPERATOR_CERT` |
| 04 | [`raxis-log-format`](env/04-raxis-log-format.md) | `RAXIS_LOG_FORMAT` |
| 05 | [`raxis-force-and-bootstrap`](env/05-raxis-force-and-bootstrap.md) | `RAXIS_FORCE`, `RAXIS_BOOTSTRAP` |
| 06 | [`raxis-install-dir`](env/06-raxis-install-dir.md) | `RAXIS_INSTALL_DIR` |
| 07 | [`raxis-vcs-timeout`](env/07-raxis-vcs-timeout.md) | `RAXIS_VCS_TIMEOUT_SECS` |
| 08 | [`raxis-kernel-binary`](env/08-raxis-kernel-binary.md) | `RAXIS_KERNEL_BINARY` |
| 09 | [`raxis-unsafe-fallback-isolation`](env/09-raxis-unsafe-fallback-isolation.md) | `RAXIS_UNSAFE_FALLBACK_ISOLATION` |
| 10 | [`verifier-env-vars`](env/10-verifier-env-vars.md) | `RAXIS_VERIFIER_*` |
| 11 | [`planner-env-vars`](env/11-planner-env-vars.md) | `RAXIS_PLANNER_*` |
| 12 | [`tproxy-and-imagekey-env`](env/12-tproxy-and-imagekey-env.md) | `RAXIS_TPROXY_*`, `RAXIS_IMAGE_KEY` |

### policy — the operator-signed config

| # | Recipe | `policy.toml` section |
|---|---|---|
| 01 | [`meta-section`](policy/01-meta-section.md) | `[meta]` (epoch, name, signed-by) |
| 02 | [`authority-section`](policy/02-authority-section.md) | `[authority]` (operator authority graph) |
| 03 | [`escalation-policy`](policy/03-escalation-policy.md) | `[[escalations]]` |
| 04 | [`sessions-section`](policy/04-sessions-section.md) | `[sessions]` |
| 05 | [`delegations-section`](policy/05-delegations-section.md) | `[[delegations]]` |
| 06 | [`budget-section`](policy/06-budget-section.md) | `[[budget]]` |
| 07 | [`lanes-section`](policy/07-lanes-section.md) | `[[lanes]]` |
| 08 | [`operators-section`](policy/08-operators-section.md) | `[[operators]]` |
| 09 | [`gateway-section`](policy/09-gateway-section.md) | `[gateway]` (egress proxy) |
| 10 | [`providers-section`](policy/10-providers-section.md) | `[[providers]]` (LLM providers) |
| 11 | [`vm-images-section`](policy/11-vm-images-section.md) | `[[vm_images]]` |
| 12 | [`host-capacity`](policy/12-host-capacity.md) | `[host_capacity]` |
| 13 | [`plan-signing`](policy/13-plan-signing.md) | Plan signature requirements |
| 14 | [`plan-bundle-limits`](policy/14-plan-bundle-limits.md) | Plan-bundle size / task / depth caps |
| 15 | [`notifications-section`](policy/15-notifications-section.md) | `[[notifications]]` |
| 16 | [`elastic-section`](policy/16-elastic-section.md) | `[elastic]` |

### plan — the TOML plan bundle

| # | Recipe | Plan field / block |
|---|---|---|
| 01 | [`plan-initiative-block`](plan/01-plan-initiative-block.md) | `[plan.initiative]` |
| 02 | [`workspace-block`](plan/02-workspace-block.md) | `[workspace]` (base/target ref) |
| 03 | [`tasks-block`](plan/03-tasks-block.md) | `[[tasks]]` overview |
| 04 | [`path-allowlist`](plan/04-path-allowlist.md) | `path_allowlist` |
| 05 | [`clone-strategy`](plan/05-clone-strategy.md) | `clone_strategy` |
| 06 | [`session-agent-type`](plan/06-session-agent-type.md) | `session_agent_type` |
| 07 | [`predecessors`](plan/07-predecessors.md) | `predecessors` |
| 08 | [`task-credentials`](plan/08-task-credentials.md) | `[[tasks.credentials]]` |
| 09 | [`vm-image-and-egress`](plan/09-vm-image-and-egress.md) | `vm_image_alias`, `egress_allowed` |
| 10 | [`orchestrator-block`](plan/10-orchestrator-block.md) | `[orchestrator]` |
| 11 | [`task-verifiers`](plan/11-task-verifiers.md) | `[[tasks.verifiers]]` |
| 12 | [`cumulative-max-seconds`](plan/12-cumulative-max-seconds.md) | `cumulative_max_seconds`, `max_crash_retries`, `max_review_rejections` |

### patterns — common plan shapes

| # | Recipe | Topology |
|---|---|---|
| 01 | [`fan-out-then-merge`](patterns/01-fan-out-then-merge.md) | N parallel Executors → reviewers → Orchestrator-led merge |
| 02 | [`reviewer-panel`](patterns/02-reviewer-panel.md) | One Executor + N Reviewers (logical-AND) |
| 03 | [`merge-with-integration-verifiers`](patterns/03-merge-with-integration-verifiers.md) | Policy-side verifiers gate the integration merge |
| 04 | [`retry-on-failure`](patterns/04-retry-on-failure.md) | Crash + review-rejection retry budgets, `RetrySubTask` |
| 05 | [`staged-rollout`](patterns/05-staged-rollout.md) | Sequential predecessor chain (stub → impl → flip) |
| 06 | [`cross-cutting-refactor`](patterns/06-cross-cutting-refactor.md) | `cross_cutting_artifacts` for shared lockfiles / generated files |
| 07 | [`canary-then-broad-change`](patterns/07-canary-then-broad-change.md) | Verified canary commit gating broader rollout |
| 08 | [`budget-bounded-cohort`](patterns/08-budget-bounded-cohort.md) | Lane concurrency + budget cap throttling many tasks |

### cli — every `raxis` subcommand

| # | Recipe | Subcommand |
|---|---|---|
| 01 | [`genesis`](cli/01-genesis.md) | `raxis genesis` |
| 02 | [`policy-sign`](cli/02-policy-sign.md) | `raxis policy sign` |
| 03 | [`policy-show`](cli/03-policy-show.md) | `raxis policy show` |
| 04 | [`policy-diff`](cli/04-policy-diff.md) | `raxis policy diff` |
| 05 | [`plan-validate`](cli/05-plan-validate.md) | `raxis plan validate` |
| 06 | [`plan-fmt`](cli/06-plan-fmt.md) | `raxis plan fmt` |
| 07 | [`plan-init`](cli/07-plan-init.md) | `raxis plan init` |
| 08 | [`submit-plan`](cli/08-submit-plan.md) | `raxis submit-plan` |
| 09 | [`plan-approve-reject`](cli/09-plan-approve-reject.md) | `raxis plan approve` / `reject` |
| 10 | [`initiative-list`](cli/10-initiative-list.md) | `raxis initiative list` |
| 11 | [`initiative-show`](cli/11-initiative-show.md) | `raxis initiative show` |
| 12 | [`initiative-abort-quarantine`](cli/12-initiative-abort-quarantine.md) | `raxis initiative abort` / `quarantine` |
| 13 | [`task-control`](cli/13-task-control.md) | `raxis task pause` / `resume` / `requeue` |
| 14 | [`session-create-revoke`](cli/14-session-create-revoke.md) | `raxis session create` / `revoke` |
| 15 | [`delegation-grant`](cli/15-delegation-grant.md) | `raxis delegation grant` |
| 16 | [`escalation-approve-deny`](cli/16-escalation-approve-deny.md) | `raxis escalation approve` / `deny` |
| 17 | [`cert-mint`](cli/17-cert-mint.md) | `raxis cert mint` |
| 18 | [`cert-show-verify`](cli/18-cert-show-verify.md) | `raxis cert show` / `verify` |
| 19 | [`cert-install-revoke`](cli/19-cert-install-revoke.md) | `raxis cert install` / `revoke` |
| 20 | [`credential-add`](cli/20-credential-add.md) | `raxis credential add` |
| 21 | [`credential-list-show-rotate`](cli/21-credential-list-show-rotate.md) | `raxis credential list` / `show` / `rotate` |
| 22 | [`kernel-install-uninstall`](cli/22-kernel-install-uninstall.md) | `raxis kernel install` / `uninstall` |
| 23 | [`status-doctor`](cli/23-status-doctor.md) | `raxis status` / `doctor` |
| 24 | [`log-verify-chain`](cli/24-log-verify-chain.md) | `raxis log verify` |
| 25 | [`queue-inspect`](cli/25-queue-inspect.md) | `raxis queue inspect` |
| 26 | [`explain`](cli/26-explain.md) | `raxis explain` |
| 27 | [`sessions-escalations-inbox`](cli/27-sessions-escalations-inbox.md) | `raxis sessions` / `escalations inbox` |
| 28 | [`witnesses-verifiers`](cli/28-witnesses-verifiers.md) | `raxis witnesses` / `verifiers` |
| 29 | [`budget-top`](cli/29-budget-top.md) | `raxis budget top` |
| 30 | [`epoch-advance`](cli/30-epoch-advance.md) | `raxis epoch advance` |
| 31 | [`providers-status`](cli/31-providers-status.md) | `raxis providers status` |
| 32 | [`auth-sign-setup`](cli/32-auth-sign-setup.md) | `raxis auth sign setup` |
| 33 | [`operator-quarantine-plans-by`](cli/33-operator-quarantine-plans-by.md) | `raxis operator quarantine-plans-by` |

### ops — day-2 operations

| # | Recipe | Task |
|---|---|---|
| 01 | [`rotate-operator-cert`](ops/01-rotate-operator-cert.md) | Cert rotation (planned) |
| 02 | [`respond-to-key-compromise`](ops/02-respond-to-key-compromise.md) | Compromise response (incident) |
| 03 | [`backup-and-restore`](ops/03-backup-and-restore.md) | Store backup + restore drill |
| 04 | [`upgrade-kernel`](ops/04-upgrade-kernel.md) | Safe kernel binary upgrade |
| 05 | [`investigate-stuck-task`](ops/05-investigate-stuck-task.md) | Diagnose a `Pending` / `Active` task that won't progress |
| 06 | [`tune-lane-budget`](ops/06-tune-lane-budget.md) | Lane concurrency + budget knobs |
| 07 | [`monitor-audit-chain`](ops/07-monitor-audit-chain.md) | Continuous audit-chain health monitoring |
| 08 | [`host-capacity-tuning`](ops/08-host-capacity-tuning.md) | CPU/RAM/disk caps in `[host_capacity]` |
| 09 | [`publish-verifier-image`](ops/09-publish-verifier-image.md) | Build, sign, publish a verifier image |
| 10 | [`publish-executor-image`](ops/10-publish-executor-image.md) | Build, sign, publish an executor image |
| 11 | [`add-llm-provider`](ops/11-add-llm-provider.md) | Wire up a new LLM provider |
| 12 | [`debug-egress-denial`](ops/12-debug-egress-denial.md) | Trace `FAIL_EGRESS_DENIED` end-to-end |
| 13 | [`handle-reconciliation-gap`](ops/13-handle-reconciliation-gap.md) | Recovery after a kernel restart with in-flight work |
| 14 | [`staging-to-prod-promotion`](ops/14-staging-to-prod-promotion.md) | Promote signed plan from staging policy to prod policy |
| 15 | [`incident-postmortem`](ops/15-incident-postmortem.md) | Run a postmortem using the audit chain |

---

## Conventions

- **Self-contained.** Every recipe is readable on its own. If you
  follow exactly one link from this index, the linked recipe
  answers the question without further reading.
- **Specs are normative.** Where a recipe quotes a spec section,
  the spec wins on disagreement. Recipes are descriptions; specs
  are contracts.
- **Code references resolve.** Every `kernel/src/...` or
  `crates/.../...` link is a real path on `main`. If a link
  rots, file a bug — it means a refactor moved the surface and
  the recipe needs to follow.
- **Failure modes first.** Every recipe ends with a "Common
  errors" or equivalent table. If you're debugging, scroll
  there first.

If a recipe is missing for something you needed, that's a
documentation gap — open an issue tagged `docs/recipes` with
the question you wished was answered.
