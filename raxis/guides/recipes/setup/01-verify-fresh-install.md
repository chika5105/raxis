# Verify a fresh RAXIS install is healthy

> **Topic:** Setup | **Time to read:** ~3 min | **Complexity:** ⭐ Beginner

The four-command preflight that proves a freshly-genesised RAXIS data
directory is intact, the audit chain is anchored, and the kernel can
boot cleanly. Run this any time you sit down at an unfamiliar
machine; if any of the four exits non-zero, do **not** run a plan
through the kernel until it's fixed.

---

## Prerequisites

- The `raxis` CLI on your `$PATH` (run `which raxis` to confirm).
- A `RAXIS_DATA_DIR` you believe was previously initialised. The
  default is `~/.raxis`; demos typically use `~/.raxis-demo`.
- The kernel does NOT need to be running for the first three checks;
  it's required for `raxis status` only.

---

## Step-by-step

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"   # use whatever path was used at genesis

# 1. The genesis ceremony's two anchor files exist.
test -f "$RAXIS_DATA_DIR/policy/policy.toml"        && echo "policy:       present"
test -f "$RAXIS_DATA_DIR/audit/segment-000.jsonl"   && echo "audit chain: present"

# 2. The chain links end-to-end. Exit 0 = intact, 3 = broken.
raxis verify-chain
echo "verify-chain exit: $?"

# 3. The store opens read-only and the schema pin matches.
raxis doctor

# 4. The kernel is up (only if you've started raxis-kernel).
raxis status
```

---

## What success looks like

```text
policy:       present
audit chain: present
verify-chain — segments=1 records=N gaps=0 broken=0
verify-chain exit: 0
doctor — all checks: PASS
status — kernel: live
```

`verify-chain` reports **gaps=0 broken=0**. `doctor` reports every
subdir present + correctly moded (notably `providers/*.toml` at
`0600`). `status` shows the kernel as live or stopped — both are
fine for a healthy install; "ambiguous" (heartbeat fresh but PID
gone) is the only state that indicates a problem.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `policy/policy.toml` missing | Genesis was never run on this dir; run `raxis genesis` (see `guides/SETUP.md` Step 4). |
| `audit/segment-000.jsonl` missing | Genesis crashed mid-write; `rm -rf "$RAXIS_DATA_DIR"` and rerun genesis. The data dir is unrecoverable without the anchor segment. |
| `verify-chain` exit 3 | A segment was edited or deleted post-genesis. The chain is hash-linked: the only honest fix is to roll forward from the last known-good segment using `raxis verify-chain --from <seq>` to identify the break point. |
| `doctor` reports `BOOT_ERR_CREDENTIAL_MODE` | Run `chmod 600 "$RAXIS_DATA_DIR/providers/"*.toml`. The `FileCredentialBackend` refuses to load any provider credential file with broader perms. |
| `status` exit 1 (`stopped`) | Kernel isn't running. `raxis-kernel` in another terminal — or `systemctl --user start raxis-kernel` if you used `raxis kernel install`. |
| `status` exit 2 (`ambiguous`) | A previous kernel left a stale `runtime/heartbeat.json` after a crash. `rm "$RAXIS_DATA_DIR/runtime/heartbeat.json"` then start the kernel again. |

---

## Reference: env vars used here

| Variable | Purpose |
|---|---|
| `RAXIS_DATA_DIR` | Root of every kernel state file. The CLI honours this for read-only inspection without needing the kernel. |
| `RAXIS_OPERATOR_KEY` | NOT required for `verify-chain` / `doctor` / `status`. Required for `policy sign`, `submit plan`, `escalation approve`, and any other mutating operator-socket call. |

---

## Variations

- **One-line health rollup.** `raxis status --json | jq '.kernel_state, .chain_state'` — handy for shell scripting.
- **CI-friendly preflight.** `raxis doctor --json | jq -e '.summary == "all_pass"'` returns exit 0 for green, non-zero for any failure.
- **Quick chain check.** `raxis verify-chain --quick` mirrors what `status` does internally — same as `--from <last-segment-seq>`. Use it when the chain is large and a full walk is slow.
