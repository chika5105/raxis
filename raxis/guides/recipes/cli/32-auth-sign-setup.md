# `raxis auth sign` and `raxis setup`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

Two utility commands. `auth sign` produces an ad-hoc Ed25519
signature with the operator key (used in tooling that needs to
attest a payload). `setup` is the interactive first-run wizard that
calls `genesis`, mints the genesis cert, and writes a starter
`policy.toml`.

---

## auth sign — ad-hoc signature

```bash
raxis auth sign \
  --operator-key /tmp/genesis.key \
  --payload "deploy:abc123:2026-05-10T17:30:00Z"
# Output:
# signature: <hex>
# signer_kid: 8a4f...
```

What it's for:

- A CI step needs to prove an operator authorized a build artifact
  before the kernel ingests it.
- A custom tool needs to attach an operator signature to a payload
  that's not directly a Raxis intent.
- Pre-flight verification: sign a known message, run `auth verify`
  on the other side, confirm the operator key chain is intact.

Important: `auth sign` does NOT mint a kernel-recognized intent.
If you want the kernel to act, use the appropriate command
(`submit plan`, `plan approve`, etc.); those internally sign their
canonical payloads.

To verify a signature out-of-band:

```bash
raxis auth verify \
  --signer-kid 8a4f... \
  --pubkey /tmp/genesis.pub \
  --payload "deploy:abc123:2026-05-10T17:30:00Z" \
  --signature <hex>
# Output:
# verdict: VALID
```

---

## setup — first-run wizard

`setup` is the easiest path from "fresh machine" to "kernel
running with a genesis cert and a runnable policy". Equivalent to
running `genesis` plus a few `cert mint` / `policy sign` commands
manually.

```bash
RAXIS_DATA_DIR="$HOME/.raxis" raxis setup
# Interactive prompts:
# - "Operator name [ops-default]:"
# - "Operator key path [$HOME/.raxis/operator.key]:"
# - "Generate new key? [Y/n]"
# - "Lane name for default work [default]:"
# - ...
# Output:
# data_dir:        ~/.raxis
# operator_key:    ~/.raxis/operator.key
# operator_cert:   embedded in ~/.raxis/policy.toml
# kernel_running:  yes (pid 17234)
# Next: try `raxis status` and submit a hello-world plan via
#       guides/scenarios/00-hello-orchestrator/.
```

Non-interactive (env-driven):

```bash
RAXIS_DATA_DIR=/var/raxis \
RAXIS_OPERATOR_KEY=/etc/raxis/operator.key \
RAXIS_OPERATOR_NAME=ops-prod \
raxis setup --non-interactive
```

After `setup`:

- `RAXIS_DATA_DIR` is initialized.
- The operator key exists (generated if missing).
- A genesis cert is signed and embedded in `policy.toml`.
- `policy.toml` has a default `[[lanes]]`, `[budget]`,
  `[[operators.entries]]`, `[plan_signing]`.
- Kernel is registered as a system service (use
  `--no-install` to skip).

`setup` is idempotent: if `RAXIS_DATA_DIR` is already initialized,
it reports the current state and exits cleanly.

---

## Common errors

| Symptom | Fix |
|---|---|
| `auth sign: --operator-key unreadable` | Path / perms; chmod 600 the key file. |
| `auth verify: VERDICT INVALID` | Either the signature is wrong or the pubkey doesn't match the signer kid. |
| `setup: data_dir already initialized` | Either nuke and rerun, or use `--force` (destructive). |
| `setup: missing required env in --non-interactive` | The non-interactive mode wants `RAXIS_DATA_DIR`, `RAXIS_OPERATOR_KEY`, `RAXIS_OPERATOR_NAME` at minimum. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis genesis` | Lower-level data-dir bootstrap. |
| `raxis cert mint` | Mint individual operator certs. |
| `raxis policy sign` | Re-sign policy after manual edits. |
| `raxis status` / `raxis doctor` | Verify install. |

---

## Variations

- **Sandbox setup.** `RAXIS_DATA_DIR=$(mktemp -d) raxis setup --no-install`
  for a throwaway sandbox you can blow away with `rm -rf`.
- **Multi-instance setup.** Different `RAXIS_DATA_DIR` and
  `RAXIS_INSTALL_DIR` per setup run; each instance independent.
- **CI quickstart.** A CI image that runs `setup --non-interactive`
  in its prepare step, then runs scenario plans for tests.
- **Custom signer.** Pre-generate the operator key in a hardware
  signer; pass `--operator-key` pointing at a fifo / proxy that
  speaks to the signer.
