# `RAXIS_OPERATOR_CERT` — pre-minted operator cert path

> **Topic:** Environment variables | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

`RAXIS_OPERATOR_CERT` holds the path to a pre-minted
`operator.cert.toml` — typically minted offline via
`raxis cert mint` on a machine that holds the private key. The
kernel reads this path at genesis time when no `--operator-cert`
flag is passed.

The variable is read **only by `raxis genesis`**. Other CLI
commands ignore it (they read `RAXIS_OPERATOR_KEY` instead, which
points at the private PEM — the cert is in policy already once
the install is up).

---

## Read by

- `raxis genesis` — when neither `--operator-cert` nor
  `--operator-key + --operator-name` is passed, falls back to
  `RAXIS_OPERATOR_CERT`.

---

## Default

Unset. When the variable is unset AND no flag is passed, genesis
exits with:

```text
genesis: provide either --operator-cert <path> OR --operator-key <pem> --operator-name <name>
```

---

## Set

```bash
export RAXIS_OPERATOR_CERT="$HOME/raxis-keys/operator.cert.toml"
```

Then:

```bash
raxis genesis
# Equivalent to:
raxis genesis --operator-cert "$HOME/raxis-keys/operator.cert.toml"
```

---

## When to use this vs `--operator-key`

### `--operator-cert` (or `RAXIS_OPERATOR_CERT`) — air-gapped flow

The cert was minted on a separate machine via `raxis cert mint`,
which holds the private key locally. You ship **only the cert
file** to the kernel host. Genesis embeds the cert into policy
without ever seeing the private bytes.

```bash
# On the offline machine:
raxis cert mint \
  --key operator_private.pem \
  --display-name alice \
  --validity-days 365 \
  --out operator.cert.toml

# Transfer operator.cert.toml to the kernel host. NOT the private key.

# On the kernel host:
export RAXIS_OPERATOR_CERT="$HOME/transfers/operator.cert.toml"
raxis genesis
```

### `--operator-key + --operator-name` — same-host flow

The private PEM is on the kernel host (e.g., a single-developer
laptop). Genesis mints the cert in-process from the PEM, then
embeds it into policy. The private bytes never persist under
`RAXIS_DATA_DIR`.

```bash
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"
raxis genesis --operator-name "$USER"
```

The same private PEM continues to live at the path under
`$RAXIS_OPERATOR_KEY` for subsequent signing operations.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `genesis: cert file not found` | The path doesn't exist. `ls -l "$RAXIS_OPERATOR_CERT"`. |
| `genesis: cert verify: signature did not match` | The cert was tampered with in transit. Reject; re-mint. |
| `genesis: cert expired` | The cert's `not_after` has elapsed. Re-mint with a fresh validity window. |
| `genesis: refusing to overwrite existing data dir` | This data dir was already genesis'd. To re-genesis: `rm -rf "$RAXIS_DATA_DIR"` first. |

---

## Reference: related env vars + commands

| Variable / command | Relationship |
|---|---|
| `RAXIS_OPERATOR_KEY` | Used by every signing CLI **after** genesis. The cert path env var is genesis-only. |
| `raxis cert mint --key <pem> --display-name <name> --out <cert>` | Produces the file `RAXIS_OPERATOR_CERT` references. |
| `raxis cert show <path>` | Inspect a cert before trusting it. |
| `raxis cert verify <path>` | Cryptographic self-signature check. |
| `--operator-cert <path>` (genesis flag) | Always wins over the env var. |

---

## Variations

- **Multi-operator genesis.** Genesis only takes ONE operator cert.
  Add additional operators after the kernel is up via
  `raxis cert install <other-operator.cert.toml>` (which appends
  the entry and re-signs policy).
- **HSM-backed signing.** Mint the cert on an HSM-equipped offline
  machine; ship only the cert. The HSM never lets the private
  bytes escape. Pair with `cert revoke` ceremonies for rotation.
