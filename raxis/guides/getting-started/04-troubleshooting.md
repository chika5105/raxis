# 04 · Troubleshooting

> **Scope.** The failure modes a brand-new Homebrew operator hits in
> the first hour, ranked by frequency. Each entry: symptom → why → fix.

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

## 1b · "Allow `raxis-kernel` to accept incoming network connections?" popup on every macOS build

**When.** Every `cargo build && ./target/debug/raxis-kernel` (and
every `cargo run -p raxis-kernel`) on macOS pops a modal asking you to
allow incoming connections.

**Why.** The macOS Application Firewall keys per-binary
allowlist decisions on the binary's code-signing identity. Every
`cargo build` re-emits a binary with a fresh ad-hoc CDHash, so the
firewall treats each rebuild as a brand-new app and re-prompts.

**Fix.** One-time per workspace:

```bash
cargo xtask macos-firewall-prereq         # idempotent; prompts for sudo once
cargo xtask macos-firewall-status         # verify every raxis host binary shows "Allow"
```

`cargo xtask dev-prereqs` runs the same step automatically on macOS,
so a fresh `--install` covers this. Pass `--skip-firewall` on managed
devices where `sudo` is disallowed.

Reference: [`recipes/setup/11-macos-firewall-popup.md`](../recipes/setup/11-macos-firewall-popup.md).

---

## 1c · `permission denied: raxis` after Homebrew install

**When.** You run `raxis` and the shell prints `permission denied:
raxis`.

**Why.** Usually the shell is resolving `raxis` to the local source
directory named `./raxis`, not to the Homebrew binary. This happens
most often when you are standing in a cloned repo root and `.` is on
your `$PATH`.

**Fix.**

```bash
command -v raxis
ls -l "$(brew --prefix raxis)/bin/raxis"
hash -r
```

`command -v raxis` should point at Homebrew, for example
`/opt/homebrew/bin/raxis` on Apple Silicon. If the Homebrew binary is
not executable, reinstall the corrected bottle:

```bash
brew reinstall raxis
```

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

If the operator also needs admin/trust-root authority after genesis,
do not re-run genesis just to widen permissions. Mint a replacement
cert for the same operator key that includes both `RotateEpoch` and
`OperatorCertInstall`, install it with
`raxis cert install --replace-for ...`, re-sign `policy.toml`, then run
`raxis epoch advance`. Use genesis `--admin` only during the initial
bootstrap ceremony.

Or pass `--force` to make the destructive reset explicit:

```bash
raxis genesis --force --operator-key "$RAXIS_OPERATOR_KEY" --operator-name "$USER"
```

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

## 3b · `FAIL_INSUFFICIENT_FD_LIMIT` from `brew services`

**When.** `brew services list` shows `raxis error 75` and
`$(brew --prefix)/var/log/raxis/kernel.err.log` contains:

```text
RLIMIT_NOFILE soft limit 256 is below floor 4096
```

**Why.** macOS launchd starts user LaunchAgents with a low default file
descriptor limit unless the service raises it before launching the
kernel. RAXIS needs at least `4096` because the kernel owns IPC sockets,
audit files, dashboard connections, gateway pipes, and VM/session
handles.

**Fix.** Upgrade to a Homebrew formula that starts the supervisor
through `ulimit -n 4096`. Then reset the supervisor circuit breaker and
restart the service:

```bash
brew update
brew upgrade raxis

export RAXIS_DATA_DIR="$(brew --prefix)/var/lib/raxis"
raxis-supervisor reset-circuit-breaker --yes
brew services restart raxis
brew services list | awk 'NR==1 || $1=="raxis"'
raxis-supervisor status
```

Expected: service status `started` and supervisor status `Healthy`.

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

## 4b · Anthropic returns `401` from the gateway

**When.** The kernel starts, but the first Executor fails during the
model call and the gateway log mentions Anthropic authentication.

**Why.** Anthropic does not use the default `Authorization: Bearer`
header. Its credential file must tell the gateway to send the key as
`x-api-key` with no prefix.

**Fix.**

```bash
printf 'Anthropic API key: '
stty -echo
IFS= read -r RAXIS_ANTHROPIC_API_KEY
stty echo
printf '\n'
{
  printf 'api_key = "%s"\n' "$RAXIS_ANTHROPIC_API_KEY"
  printf 'auth_header = "x-api-key"\n'
  printf 'auth_prefix = ""\n'
} > "$RAXIS_DATA_DIR/providers/anthropic-prod.toml"
unset RAXIS_ANTHROPIC_API_KEY
chmod 600 "$RAXIS_DATA_DIR/providers/anthropic-prod.toml"
```

Restart the kernel after replacing the credential file.

---

## 4c · `timeout 120000 ms exceeds provider cap 30000 ms`

**When.** `raxis plan approve` succeeds, the Orchestrator starts, and
the first model request is rejected before it reaches the provider.

**Why.** The starter agent runtime can request a 120-second inference
budget. If `policy.toml` caps the provider at 30 seconds, the gateway
rejects the call locally.

**Fix.** Raise the provider timeout, re-sign, and advance the epoch or
restart the kernel:

```toml
[[providers]]
provider_id          = "anthropic-prod"
inference_timeout_ms = 120000
data_fetch_timeout_ms = 30000
```

```bash
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_DATA_DIR/keys/authority_keypair.pem"
raxis epoch advance \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml" \
  --sig    "$RAXIS_DATA_DIR/policy/policy.sig"
```

---

## 5 · `FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS` on `session create` / plan approval

**When.** A plan approves, but session creation fails because the
worktree path is outside policy.

**Why.** `[sessions].allowed_worktree_roots` must contain a prefix that
covers your worktree. The kernel does a canonical-path check — symlinks
and `..` segments do not satisfy the check.

**Fix.** For the Homebrew production flow, allow the kernel-managed
worktree root under your data dir and re-sign:

```toml
[sessions]
allowed_worktree_roots = ["/Users/you/.raxis/worktrees"]
```

```bash
perl -0pi -e 's|allowed_worktree_roots = \[[^\]]*\]|allowed_worktree_roots = ["'"$RAXIS_DATA_DIR"'/worktrees"]|' \
  "$RAXIS_DATA_DIR/policy/policy.toml"
raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_DATA_DIR/keys/authority_keypair.pem"
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

## 7b · Only the Orchestrator appears; no Executor task runs

**When.** `raxis initiative show <id> --with-tasks` shows the
auto-generated Orchestrator row, but your declared Executor never
appears or never admits.

**Why.** The most common cause in repeated local demos is a reused
`task_id`. Task IDs are globally indexed in `kernel.db`; reusing
`task_id = "greeter"` in the same data dir can collide with an older
demo run.

**Fix.** Use a fresh data dir or generate unique task IDs for reruns:

```bash
export RAXIS_TASK_ID="greeter-$(date +%Y%m%d%H%M%S)"
```

Then put `task_id = "$RAXIS_TASK_ID"` in the plan you submit. For the
checked-in scenario plans, the simplest repeatable path is a fresh
`RAXIS_DATA_DIR` per scenario suite.

---

## 7c · The managed repository cannot be opened

**When.** A task starts and then fails before editing because the
kernel cannot find or clone the source repo.

**Why.** Homebrew production runs clone from the managed repository
named by `[workspace] repository`, for example
`$RAXIS_DATA_DIR/repositories/hello-world`. A `/tmp/raxis-*`
directory is only a staging convenience for humans; the kernel does
not infer it from your current working directory.

**Fix.** Seed the canonical repo before submitting:

```bash
export RAXIS_REPO_ID="hello-world"
export RAXIS_MANAGED_REPO="$RAXIS_DATA_DIR/repositories/$RAXIS_REPO_ID"
rm -rf "$RAXIS_MANAGED_REPO"
install -d "$(dirname "$RAXIS_MANAGED_REPO")"
git init -q "$RAXIS_MANAGED_REPO"
git -C "$RAXIS_MANAGED_REPO" symbolic-ref HEAD refs/heads/main
printf '# demo\n' > "$RAXIS_MANAGED_REPO/README.md"
git -C "$RAXIS_MANAGED_REPO" -c user.email=demo@raxis.local -c user.name=Demo add README.md
git -C "$RAXIS_MANAGED_REPO" -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

After the initiative completes, inspect results with
`git -C "$RAXIS_MANAGED_REPO" ...`, not with `git -C /tmp/...`.

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

> **V2 default-include for inference providers.** The kernel
> auto-grants the canonical FQDN of every `[[providers]]` entry in
> `policy.toml` (`Anthropic ⇒ api.anthropic.com`,
> `OpenAI ⇒ api.openai.com`, `Gemini ⇒
> generativelanguage.googleapis.com`, `Bedrock ⇒
> bedrock-runtime.us-east-1.amazonaws.com`, `http_sidecar ⇒ host of
> sidecar_endpoint`). So you usually do NOT need to list the
> provider's FQDN under `[egress] domains` — it's already in the
> effective allowlist. Each implicit grant emits one
> `DefaultProviderEgressApplied` audit at kernel boot and after
> every `RotateEpoch` for full traceability:
>
> ```bash
> raxis log <init_id> --kind DefaultProviderEgressApplied --limit 20
> ```
>
> If you intentionally want to deny a provider's FQDN (e.g. you're
> phasing out an old `[[providers]]` entry), set `[egress]
> deny_provider = ["<provider_id>"]` (validator rejects typos) or
> opt out entirely with `[egress] implicit_provider_grants = false`
> (validator also rejects the false / zero-explicit-egress
> combination — that would leave every agent unable to reach any
> provider).

> **Egress stall detection.** When the same `(session, host, port)`
> tuple is denied 3 times within a 30-second sliding window, the
> kernel emits one `SessionEgressStallDetected` audit event tagged
> `source = "tproxy"` (admission-loop chokepoint) or `source =
> "kernel_mediated_fetch"` (kernel-mediated `PlannerFetchRequest`
> chokepoint). If a Reviewer / Orchestrator / Executor agent looks
> stuck and you suspect an egress problem:
>
> ```bash
> raxis log <init_id> --kind SessionEgressStallDetected --limit 10
> ```
>
> The event carries the destination, the chokepoint, the denial
> count inside the window, and a stable `reason` string identical
> to the underlying `TransparentProxyDenied.reason`.

Reference: [`recipes/ops/12-debug-egress-denial.md`](../recipes/ops/12-debug-egress-denial.md),
[`specs/v2/vm-network-isolation.md`](../../specs/v2/vm-network-isolation.md),
[`specs/v2/reviewer-egress-defaults-decision.md`](../../specs/v2/reviewer-egress-defaults-decision.md).

---

## 8b · The executor's Python script cannot connect to `<service>`

**When.** An Executor task that runs a stock Python script
(`psycopg2.connect(...)`, `pymongo.MongoClient(...)`,
`redis.from_url(...)`, `smtplib.SMTP(...)`, `pymysql.connect(...)`,
`pymssql.connect(...)`) raises a connection / authentication
error inside the VM. Symptoms in the task log:

* `psycopg2.OperationalError: could not translate host name "..."` —
  the script tried to connect to a raw upstream host, not the
  proxy.
* `pymongo.errors.InvalidURI: ... Scheme must be one of mongodb` —
  the script received a malformed connection string.
* `redis.exceptions.ConnectionError: Error 111 connecting to ...` —
  egress to the upstream's real address was admission-denied; the
  proxy URL was not consumed.
* `smtplib.SMTPServerDisconnected: ... server refused connection` —
  same as above, for SMTP.

**Why.** The credential-proxy manager injects a per-service URL
env var (`DATABASE_URL`, `MONGO_URL`, `REDIS_URL`, `SMTP_URL`,
`MYSQL_URL`, `MSSQL_URL`) into the task VM. The script MUST read
the URL from the env var verbatim; hard-coding the upstream host
is rejected by Tier-1 egress with a `TransparentProxyDenied`
audit event. Common root causes:

1. The script is reading a non-standard env var (e.g.
   `MONGODB_URI`, `POSTGRES_URL`) the proxy did not mount.
2. The script is hard-coding the upstream `host:port` from a
   pre-RAXIS config file.
3. The plan task is missing a `[[tasks.credentials]]` entry for
   the service the script needs — the proxy was never started so
   no env var was injected.
4. The executor image is missing the pinned client library so
   the import fails before the connect call. Symptoms then
   include `ModuleNotFoundError: No module named '<library>'`.

**Fix.**

1. Confirm the script reads from the canonical env var:

   ```bash
   raxis log --task <task-id> --kind CredentialProxyStarted
   ```

   This lists the proxies that were started for the task and the
   `mount_as` env var each was bound to. Match those against the
   `os.environ[...]` reads in the script.

2. Confirm the plan declares the credential mount. In the plan
   TOML the task must carry a credentials entry:

   ```toml
   [[tasks.credentials]]
   name       = "test-mongo-dev"
   proxy_type = "mongodb"
   mount_as   = "MONGO_URL"
   ```

3. If the executor image is custom (not the starter), confirm it
   ships the client library at the same pinned version the script
   imports. The starter image installs
   `psycopg2-binary==2.9.10`, `pymongo==4.10.1`, `redis==5.2.1`,
   `PyMySQL==1.1.1`, `pymssql==2.3.2`; pin to these versions if
   you are inheriting from a custom base.

4. If you see a `TransparentProxyDenied{reason: "proxy_target_bypass"}`
   event in the chain, the script tried to dial the upstream
   directly. That's the *correct* kernel behaviour — the proxy
   is the only legal egress — and the fix is to remove the
   hard-coded host from the script, NOT to widen the egress
   allowlist.

Reference: [`specs/v2/transparent-proxy-validation.md`](../../specs/v2/transparent-proxy-validation.md),
[`specs/v2/credential-proxy.md`](../../specs/v2/credential-proxy.md),
[`live-e2e/seed/scripts/transparent_proxy/`](../../live-e2e/seed/scripts/transparent_proxy/)
for canonical script shapes.

---

## 9 · Audit chain reports a gap or hash mismatch

**When.** `raxis verify-chain` exits non-zero with a "gap at seq=N" or
"hash mismatch at seq=N" message.

**Why.** Either disk corruption between two segments, or someone (or
something) edited a segment file by hand.

**Fix.** Treat as a security incident:

1. Stop the kernel immediately.
2. Copy the `<data_dir>/audit/` tree aside.
3. Run `raxis verify-chain --audit-dir <copy>/audit` against the copy
   to identify the exact seq.
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

When you are ready to clean up orphan worktrees, first confirm no
active session references them:

```bash
raxis sessions --json
ls "$RAXIS_DATA_DIR/worktrees/"
```

Reference: [`recipes/ops/13-handle-reconciliation-gap.md`](../recipes/ops/13-handle-reconciliation-gap.md),
[`specs/v2/kernel-lifecycle.md`](../../specs/v2/kernel-lifecycle.md) (recovery).

---

## 10b · `gateway_embedded_materialize_failed` / permission denied

**When.** Restarting `raxis-kernel` fails while materialising the
embedded gateway under `$RAXIS_DATA_DIR/runtime/embedded-gateway`.

**Why.** An older kernel run may have left the materialised
`raxis-gateway` file owner-executable only. The next run then tries to
replace the file and hits a host permission error.

**Fix.** Stop the kernel, clear the materialised copy, and restart.
The immutable Homebrew binary remains under the brew prefix.

```bash
rm -rf "$RAXIS_DATA_DIR/runtime/embedded-gateway"
raxis-kernel
```

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
