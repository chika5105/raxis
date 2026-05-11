# Run multiple RAXIS installs side by side

> **Topic:** Setup | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

A single host can host as many independent RAXIS installs as you
want — each pinned by a unique `RAXIS_DATA_DIR`. Use this for:

- A "prod-like" install + a sandbox install on one developer machine.
- Per-customer multi-tenant operator hosts.
- Comparison testing two policy revisions in parallel.

Two installs **must not** share a data dir. The kernel SQLite store
is exclusive-locked; the second kernel will fail-loop on boot with
`store: kernel.db is locked`.

---

## Prerequisites

- An existing first install at `~/.raxis-prod` (or wherever).
- A second worktree-roots prefix that doesn't overlap the first.

---

## Step-by-step — second sandbox install

```bash
# 1. Pick a fresh data dir + bind it in this shell only.
export RAXIS_DATA_DIR="$HOME/.raxis-sandbox"

# 2. Fresh keys for the sandbox (or reuse the prod keys — your call).
mkdir -p "$HOME/raxis-keys-sandbox"
openssl genpkey -algorithm ED25519 \
  -out "$HOME/raxis-keys-sandbox/operator_private.pem"
openssl pkey -pubout \
  -in   "$HOME/raxis-keys-sandbox/operator_private.pem" \
  -out  "$HOME/raxis-keys-sandbox/operator_public.pem"
chmod 600 "$HOME/raxis-keys-sandbox/operator_private.pem"
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys-sandbox/operator_private.pem"

# 3. Genesis the sandbox.
raxis genesis \
  --operator-key  "$RAXIS_OPERATOR_KEY" \
  --operator-name "$USER-sandbox"

# 4. Allowlist a sandbox-specific worktree root (NOT shared with prod).
$EDITOR "$RAXIS_DATA_DIR/policy/policy.toml"
#  [sessions]
#  allowed_worktree_roots = ["/tmp/raxis-sandbox"]

raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"

# 5. Start the sandbox kernel — different binary instance, different
#    data dir, different operator key.
raxis-kernel
```

In a separate terminal, your prod install is still on its own data dir:

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-prod"
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys-prod/operator_private.pem"
raxis status   # operates against prod, not sandbox
```

---

## Why two kernels in one shell session is dangerous

If you accidentally run two kernels against the **same** data dir
(e.g., one as a daemon, one in a foreground terminal), SQLite's
exclusive WAL lock prevents the second from booting:

```text
{"level":"fatal","event":"BootFailed","reason":"store: kernel.db is locked","hint":"another kernel is writing to RAXIS_DATA_DIR — stop it first"}
```

The first kernel keeps running; the second dies. The fix is always
to stop one of them before starting the other.

---

## Switch which install your shell talks to

```bash
# Helper functions — paste into ~/.zshrc / ~/.bashrc.
raxis-prod() {
  export RAXIS_DATA_DIR="$HOME/.raxis-prod"
  export RAXIS_OPERATOR_KEY="$HOME/raxis-keys-prod/operator_private.pem"
  echo "Now talking to: $RAXIS_DATA_DIR"
}
raxis-sandbox() {
  export RAXIS_DATA_DIR="$HOME/.raxis-sandbox"
  export RAXIS_OPERATOR_KEY="$HOME/raxis-keys-sandbox/operator_private.pem"
  echo "Now talking to: $RAXIS_DATA_DIR"
}
```

Source the rc, then `raxis-prod` / `raxis-sandbox` flips the active
install in the current shell. The two kernels keep running
unchanged; only the CLI's view shifts.

---

## What success looks like

```bash
raxis-prod    && raxis status   # one install reports "live"
raxis-sandbox && raxis status   # the other also reports "live"

# Cross-check that the audit chains are independent:
test -f "$HOME/.raxis-prod/audit/segment-000.jsonl"
test -f "$HOME/.raxis-sandbox/audit/segment-000.jsonl"
diff -q  "$HOME/.raxis-prod/audit/segment-000.jsonl" \
         "$HOME/.raxis-sandbox/audit/segment-000.jsonl"
# → Files differ. The chains share NO genesis bytes.
```

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `store: kernel.db is locked` on second kernel | Two kernels point at the same data dir. Stop one. |
| CLI reports "stopped" but the kernel terminal shows it running | `RAXIS_DATA_DIR` mismatch between the two terminals. `echo $RAXIS_DATA_DIR` on both. |
| `cannot connect to operator socket: No such file or directory` | The kernel is running but at a different data dir than the CLI is configured for — the socket lives at `<data-dir>/sockets/operator.sock`. Match the env var. |
| Both installs bind the same `lane_id` and you see budget bleed | Lane IDs are scoped per-install; there can't actually be cross-install bleed. The symptom is more likely two scenarios in the same install hitting the same lane budget. Inspect with `raxis budget`. |

---

## Reference: env vars

| Variable | Set per shell | Purpose |
|---|---|---|
| `RAXIS_DATA_DIR` | yes | Pins which install this shell talks to. |
| `RAXIS_OPERATOR_KEY` | yes | Per-install operator signing key path. |
| `RAXIS_LOG_FORMAT=json` | optional | Set in the kernel's terminal to switch to single-line JSON logs. |

---

## Variations

- **Per-customer multi-tenant.** One operator key per customer; one
  data dir per customer; one kernel daemon per customer (each running
  under its own systemd unit with a customer-specific service name).
  Use `raxis kernel install --binary $(which raxis-kernel)` from a
  shell that has the customer's `RAXIS_DATA_DIR` exported, so the
  unit file's env block is templated correctly.
- **Shared-key, separate-data.** Same operator key path, different
  `RAXIS_DATA_DIR`. Each install has its own audit chain, but a
  single key compromise affects all of them — only useful when the
  installs are *trusted* by the same operator.
- **Test-mode install.** Set `RAXIS_LOG_FORMAT=json` and pipe the
  kernel into a log collector. The structured logs are stable
  enough to grep / `jq` directly without re-parsing.
