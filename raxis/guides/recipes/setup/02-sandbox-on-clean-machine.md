# Bring up a sandbox RAXIS install on a clean machine

> **Topic:** Setup | **Time to read:** ~10 min | **Complexity:** ⭐ Beginner

A throwaway, single-developer install you can wipe with `rm -rf`.
Use this for demos, scratch experiments, or first-touch evaluation.
Production installs follow the same shape but use a dedicated user,
system-level services, and a key-management story (HSM / Vault); this
recipe is explicitly NOT that.

---

## Prerequisites

- macOS 13+ or Linux with KVM (`/dev/kvm` readable by your user).
- Rust toolchain (`rustup default stable` is sufficient).
- OpenSSL **3.x** on `$PATH`. macOS' `/usr/bin/openssl` is LibreSSL
  and **cannot generate Ed25519 keys**; install Homebrew `openssl@3`
  and `export PATH="$(brew --prefix openssl@3)/bin:$PATH"` first.
- `git ≥ 2.30`, `uuidgen`, `jq`.
- An LLM provider API key (Anthropic by default).

Verify:

```bash
openssl version    # MUST start with "OpenSSL 3" — NOT "LibreSSL"
git --version
cargo --version
```

---

## Step 1 — Build the binaries

```bash
cd /path/to/raxis     # the workspace root containing Cargo.toml
cargo install --path cli      --locked --force
cargo install --path kernel   --locked --force
cargo install --path gateway  --locked --force
which raxis raxis-kernel raxis-gateway
```

The kernel auto-spawns the gateway as a subprocess; the gateway MUST
be on `$PATH` even though you never invoke it directly.

---

## Step 2 — Pin a throwaway data directory

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"
```

Use the **same** value in every shell that runs `raxis*` binaries.
This is the entire kernel's state root: `kernel.db`, audit segments,
policy, providers, credentials, and worktree handles all live under
it. Wiping it (`rm -rf "$RAXIS_DATA_DIR"`) wipes the whole install.

---

## Step 3 — Mint an operator keypair

```bash
mkdir -p "$HOME/raxis-keys" && cd "$HOME/raxis-keys"
openssl genpkey -algorithm ED25519 -out operator_private.pem
openssl pkey -in operator_private.pem -pubout -out operator_public.pem
chmod 600 operator_private.pem
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"
```

The env var stores the **path**, not the bytes. The CLI never sends
the bytes anywhere; `RAXIS_OPERATOR_KEY` exists purely so subcommands
that need to sign (e.g. `policy sign`, `submit plan`,
`escalation approve`) can find the file without a `--operator-key`
flag every time.

---

## Step 4 — Run genesis

```bash
raxis genesis \
  --operator-key  "$RAXIS_OPERATOR_KEY" \
  --operator-name "$USER"
```

This is the **only** ceremony that ever writes the data dir from
empty. It mints kernel authority/quality/verifier keys, self-signs
your operator cert in-process (private bytes never persist), writes
`policy/policy.toml` with the cert embedded, installs the genesis
row in `policy_epoch_history`, and writes `audit/segment-000.jsonl`.

Re-running it on an existing dir fails with `genesis: refusing to
overwrite existing data dir`. To start clean, `rm -rf
"$RAXIS_DATA_DIR"` first.

---

## Step 5 — Allowlist your scratch worktree roots

```bash
# Edit policy.toml: add /tmp + /var/folders to allowed_worktree_roots
$EDITOR "$RAXIS_DATA_DIR/policy/policy.toml"

# Find or add the [sessions] block:
#   [sessions]
#   default_ttl_secs       = 86400
#   max_ttl_secs           = 604800
#   allowed_worktree_roots = ["/tmp", "/var/folders"]

# Re-sign — every policy edit invalidates the previous signature.
raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"
```

Without this step every scenario hits `FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS`
because the demo plans use `/tmp/raxis-scenario-NN` paths.

---

## Step 6 — Wire your LLM provider

```bash
mkdir -p "$RAXIS_DATA_DIR/providers"
cat > "$RAXIS_DATA_DIR/providers/anthropic-prod.toml" <<EOF
api_key = "sk-ant-REPLACE_ME"
EOF
chmod 600 "$RAXIS_DATA_DIR/providers/anthropic-prod.toml"
```

Then add the matching policy block (`$EDITOR
"$RAXIS_DATA_DIR/policy/policy.toml"`):

```toml
[[providers.entries]]
id            = "anthropic-prod"
kind          = "Anthropic"
credentials   = "anthropic-prod.toml"
default_model = "claude-haiku-4-5"

  # Optional operator pricing override for enterprise contracts or
  # volume discounts. Leave unset to let RAXIS label provider-reported
  # usage with runtime/provider pricing where available, then bundled
  # estimates.
  # pricing.input_tokens_per_dollar  = 200000
  # pricing.output_tokens_per_dollar = 50000
```

Re-sign:

```bash
raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"
```

`pricing.*` is optional for LLM provider entries. Use it only when
your contract or volume discount should override the default pricing
resolver. Without an override, the dashboard makes the provenance
explicit: provider-reported tokens, runtime/provider pricing when
available, and bundled estimate as the final fallback.

---

## Step 7 — Boot the kernel

In a dedicated terminal (leave it running):

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"
raxis-kernel
```

You should see four anchor log lines within ~2 seconds:

```text
{"level":"info","event":"PolicyLoaded","epoch_id":1}
{"level":"info","event":"KeyRegistryLoaded"}
{"level":"info","event":"AuditChainGenesis"}
{"level":"info","event":"KernelStarted"}
```

---

## Step 8 — Sanity-check from a second terminal

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"

raxis status         # exit 0 = live
raxis doctor         # exit 0 = all checks pass
raxis verify-chain   # exit 0 = chain intact
```

You're now ready to run any `guides/scenarios/*` recipe.

---

## Tear-down

```bash
# In the kernel terminal: Ctrl-C
rm -rf "$RAXIS_DATA_DIR"
rm -rf "$HOME/raxis-keys"   # only if you also want the keypair gone
```

---

## Reference: env vars introduced here

| Variable | Set at | Purpose |
|---|---|---|
| `RAXIS_DATA_DIR` | Step 2 | Root of every kernel state file. Default `~/.raxis`. |
| `RAXIS_OPERATOR_KEY` | Step 3 | Path to the operator's Ed25519 PEM. Read by every signing CLI when `--operator-key` isn't passed. **Holds a path, never key bytes.** |
| `RAXIS_LOG_FORMAT` | (unset) | Set to `json` to switch the kernel's stderr to single-line JSON; otherwise human-readable. |
| `--force` | command flag | Explicit destructive re-genesis for throwaway dev installs. Do not use on production state without archiving first. |

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `Algorithm ed25519 not found` | macOS LibreSSL — install `brew install openssl@3` and prepend its `bin/` to `$PATH`. |
| `genesis: refusing to overwrite existing data dir` | Genesis already ran here. To redo from scratch, delete the dir (`rm -rf "$RAXIS_DATA_DIR"`) — irreversible. |
| `BOOT_ERR_CREDENTIAL_MODE` | A `providers/<x>.toml` is not `0600`. `chmod 600 "$RAXIS_DATA_DIR/providers/"*.toml`. |
| `BOOT_ERR_ISOLATION_UNAVAILABLE` | No KVM (Linux) or Apple Virtualization.framework (macOS). On Linux: confirm `/dev/kvm` exists and your user is in the `kvm` group. On macOS: must be 13+. |
| `cannot connect to operator socket` | Either the kernel isn't running OR the two terminals have different `RAXIS_DATA_DIR` values. Confirm `echo $RAXIS_DATA_DIR` matches. |
