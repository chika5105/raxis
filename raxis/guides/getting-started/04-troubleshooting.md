# 04 · Troubleshooting

> **Scope.** The ten failure modes a brand-new operator hits in the
> first hour, ranked by frequency. Each entry: symptom → why → fix.

Before scrolling further, run the one command that diagnoses 80% of
issues:

```bash
raxis doctor
```

`doctor` prints `[ok]`, `[warn]`, or `[error]` for every host-side
check the kernel knows about and exits non-zero on any error. Exit `0`
= all green or warns only; `1` = at least one error. Reference:
[`recipes/cli/23-status-doctor.md`](../recipes/cli/23-status-doctor.md).

For machine-readable output:

```bash
raxis status --json
raxis doctor --json
```

The catalog below covers the failures `doctor` cannot fix by itself.

---

## 1 · `Algorithm ed25519 not found` (macOS)

**When.** Generating the operator keypair with `openssl genpkey`.

**Why.** macOS' default `/usr/bin/openssl` is LibreSSL, which has no
Ed25519 support in `genpkey`.

**Fix.**

```bash
brew install openssl@3
# Apple Silicon:
export PATH="/opt/homebrew/opt/openssl@3/bin:$PATH"
# Intel macOS:
export PATH="/usr/local/opt/openssl@3/bin:$PATH"

openssl version          # MUST say "OpenSSL 3.x"
openssl genpkey -algorithm ED25519 -out operator_private.pem
```

The workspace's `cargo xtask dev-prereqs --install` does this for you.

---

## 2 · `genesis: refusing to overwrite existing data dir`

**When.** Re-running `raxis genesis` against a `RAXIS_DATA_DIR` that
already saw a successful run.

**Why.** Genesis is intentionally non-idempotent — overwriting an
existing chain anchor would destroy the audit trail.

**Fix.** If you really want a fresh install (destroys everything,
including the audit chain):

```bash
rm -rf "$RAXIS_DATA_DIR"
raxis genesis --operator-key "$RAXIS_OPERATOR_KEY" --operator-name "$USER"
```

Or set `RAXIS_FORCE=1` to skip the rm step.

If you are coming back to an existing install, do **not** re-run
genesis. Confirm it instead:

```bash
test -f "$RAXIS_DATA_DIR/policy/policy.toml"        && echo "policy ok"
test -f "$RAXIS_DATA_DIR/audit/segment-000.jsonl"   && echo "audit ok"
raxis verify-chain | tail -3
```

---

## 3 · `BOOT_ERR_ISOLATION_UNAVAILABLE`

**When.** `raxis-kernel` exits at startup.

**Why.** No AVF (macOS) or KVM (Linux) substrate is reachable.

**Fix.**

| Host                               | Diagnostic                                                 | Fix                                                                                                                 |
| ---------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Linux                              | `cargo xtask linux-prereqs` (or `ls -l /dev/kvm; groups` ) | `sudo usermod -aG kvm $USER && newgrp kvm`; `sudo modprobe vhost_vsock`                                             |
| macOS 12 or earlier                | n/a                                                        | Upgrade to macOS 13+. AVF was introduced in macOS 13.                                                               |
| Container / CI without nested virt | n/a                                                        | Use `RAXIS_UNSAFE_FALLBACK_ISOLATION=1` **only for in-process tests**, never for an agent that runs untrusted code. |

Reference: [`specs/v2/system-requirements.md`](../../specs/v2/system-requirements.md).

---

## 4 · `BOOT_ERR_CREDENTIAL_MODE`

**When.** Kernel boot fails after you added a provider credential.

**Why.** A file under `<data_dir>/providers/*.toml` is not mode `0600`.
The kernel's `FileCredentialBackend` refuses to load any credential
file readable by anyone other than the owner.

**Fix.**

```bash
chmod 600 "$RAXIS_DATA_DIR/providers/"*.toml
```

Then re-start the kernel.

---

## 5 · `FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS` on `session create` / plan approval

**When.** A scenario picks a scratch worktree path the policy
hasn't allowlisted.

**Why.** `[sessions].allowed_worktree_roots` must contain a prefix that
covers your worktree. The kernel does a canonical-path check — symlinks
and `..` segments do not satisfy the check.

**Fix.** Add the parent directory and re-sign:

```toml
[sessions]
allowed_worktree_roots = ["/tmp", "/var/folders"]
```

```bash
raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"
raxis epoch advance \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml" \
  --sig    "$RAXIS_DATA_DIR/policy/policy.sig"
```

Reference: [`recipes/setup/08-allowlist-worktree-roots.md`](../recipes/setup/08-allowlist-worktree-roots.md).

---

## 6 · `FAIL_PATH_NOT_IN_ALLOWLIST` on a planner intent

**When.** The agent tries to write a file outside `path_allowlist`.

**Why.** `INV-TASK-PATH-01`: every path in `touched_paths(intent)` must
be a member of `effective_allow(task_id)` at admission. Glob
characters (`*`, `?`, …), negation (`!…`), leading `/`, and `..` are
all rejected at admission — entries must be exact filenames or
trailing-slash directory prefixes.

**Fix.** Widen the allowlist deliberately (re-sign + re-submit the
plan), or tell the agent (via the task's `context`) to constrain
itself to the existing scope. The audit event records exactly which
path tripped the check; look at
`raxis log <init_id> --kind IntentRejected --task <task_id>`.

Reference: [`recipes/plan/04-path-allowlist.md`](../recipes/plan/04-path-allowlist.md).

---

## 7 · Stuck task in `GatesPending` / `Admitted`

**When.** `raxis initiative show <id> --with-tasks` shows a task that
never advances.

**Why.** One of:

- A predecessor task isn't `Completed` yet (DAG).
- An expected verifier hasn't emitted a witness for the right
  `evaluation_sha` (`GatesPending`).
- A lane is concurrency-saturated (`Admitted` waiting for a free slot).
- The Orchestrator harness hasn't yet called `ActivateSubTask` for it.

**Fix.**

```bash
# What the kernel thinks is blocking.
raxis explain <task_id>

# All audit events for the task, newest first.
raxis log <init_id> --task <task_id> --limit 40

# Lane saturation snapshot.
raxis budget top
```

Reference: [`recipes/ops/05-investigate-stuck-task.md`](../recipes/ops/05-investigate-stuck-task.md).

---

## 8 · Egress denial — `FAIL_EGRESS_DENIED` / `TransparentProxyDenied`

**When.** The agent tries to reach a host the policy / plan doesn't
list.

**Why.** Two-tier enforcement:

1. **Network tier.** `raxis-tproxy` does SNI allowlisting on outbound
   TLS. Hosts not in `allowed_egress` are denied at the transport
   layer.
2. **Protocol tier.** Credential proxies (Postgres, S3, Stripe, …)
   reject methods/paths/SQL the policy did not authorise.

**Fix.** Decide whether the egress was legitimate. If yes, add the
host to the plan task's `allowed_egress` (re-submit) or the policy's
`[[egress]]` (re-sign + epoch advance). If no, no action — the deny is
the system working.

The audit event records the exact host and decision class:

```bash
raxis log <init_id> --kind TransparentProxyDenied --limit 10
```

Reference: [`recipes/ops/12-debug-egress-denial.md`](../recipes/ops/12-debug-egress-denial.md),
[`specs/v2/vm-network-isolation.md`](../../specs/v2/vm-network-isolation.md).

---

## 9 · Audit chain reports a gap or hash mismatch

**When.** `raxis verify-chain` exits non-zero with a "gap at seq=N" or
"hash mismatch at seq=N" message.

**Why.** Either disk corruption between two segments, or someone (or
something) edited a segment file by hand.

**Fix.** Treat as a security incident:

1. Stop the kernel immediately.
2. Copy the `<data_dir>/audit/` tree aside.
3. Run `raxis verify-chain --full` against the copy to identify the
   exact seq.
4. If the disk is healthy and the gap pre-dates a known restore,
   restore from a known-good backup (see
   [`recipes/ops/03-backup-and-restore.md`](../recipes/ops/03-backup-and-restore.md)).
5. If the disk is healthy and no restore explains the gap, the chain
   has been tampered with — follow your incident-response runbook
   ([`recipes/ops/15-incident-postmortem.md`](../recipes/ops/15-incident-postmortem.md)).

The chain link primitive is described in
[`specs/v2/audit-paired-writes.md`](../../specs/v2/audit-paired-writes.md);
the integrity property is `INV-04` (V1 philosophy).

---

## 10 · The kernel restarted with in-flight work

**When.** `raxis-kernel` SIGTERM'd or crashed; on restart, sessions
that were `Running` are gone.

**Why.** V2 reconciles on boot: every `Running` session whose VM is
no longer alive is transitioned to `Aborted` with reason
`KernelRestart`. Worktrees are retained for forensics.

**Fix.** No action needed. Inspect:

```bash
raxis log --since 5m --kind SessionReconciled
ls "$RAXIS_DATA_DIR/worktrees/"
```

When you are ready to clean up orphan worktrees:

```bash
raxis doctor --fix-orphans
```

Reference: [`recipes/ops/13-handle-reconciliation-gap.md`](../recipes/ops/13-handle-reconciliation-gap.md),
[`specs/v2/kernel-lifecycle.md`](../../specs/v2/kernel-lifecycle.md) (recovery).

---

## Where to look next

| Symptom class            | Reference                                                                                                                                                             |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Kernel won't start       | `raxis doctor` + [`recipes/ops/04-upgrade-kernel.md`](../recipes/ops/04-upgrade-kernel.md)                                                                            |
| Cert / key issues        | [`recipes/cli/18-cert-show-verify.md`](../recipes/cli/18-cert-show-verify.md), [`recipes/ops/01-rotate-operator-cert.md`](../recipes/ops/01-rotate-operator-cert.md)  |
| Plan won't admit         | [`recipes/cli/05-plan-validate.md`](../recipes/cli/05-plan-validate.md), [`recipes/cli/26-explain.md`](../recipes/cli/26-explain.md)                                  |
| Provider outage          | [`recipes/cli/31-providers-status.md`](../recipes/cli/31-providers-status.md), [`specs/v2/provider-failure-handling.md`](../../specs/v2/provider-failure-handling.md) |
| Suspected key compromise | [`recipes/ops/02-respond-to-key-compromise.md`](../recipes/ops/02-respond-to-key-compromise.md)                                                                       |

The full operational recipe book is at [`../recipes/`](../recipes/);
the full set of runnable end-to-end scenarios is at
[`../scenarios/`](../scenarios/).
