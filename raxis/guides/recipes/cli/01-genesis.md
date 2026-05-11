# `raxis genesis`

> **Topic:** CLI | **Time to read:** ~3 min | **Complexity:** ⭐ Beginner

The one-time ceremony that initialises a fresh `RAXIS_DATA_DIR`.
Mints kernel keys, signs the operator cert (or accepts a pre-minted
one), writes `policy/policy.toml`, and lays down the chain anchor
audit segment. Runs **exactly once** per data dir; subsequent runs
fail with `genesis: refusing to overwrite existing data dir`.

---

## Syntax

```text
raxis genesis [--force]
              ( --operator-cert <path>
              | --operator-key <pem> --operator-name <name>
                                     [--cert-validity-days <days>] )
              [--force-misconfig]
```

---

## Flags

| Flag | Effect |
|---|---|
| `--operator-cert <path>` | Path to a pre-minted `operator.cert.toml` (air-gapped flow). Mutually exclusive with `--operator-key + --operator-name`. |
| `--operator-key <pem>` | Path to an Ed25519 private PEM. The CLI mints the cert in-process; private bytes never persist. |
| `--operator-name <name>` | Display name for the in-process-minted cert. Required when `--operator-key` is used. |
| `--cert-validity-days <N>` | Validity window for the in-process-minted cert. Defaults to 365. |
| `--force` | Overwrite an existing data dir. **Destroys** the prior install — audit chain, policy, keys, all. |
| `--force-misconfig` | Allow boot even when an operator cert has structural-validation issues. The bypass is audited. |

Env-var fallbacks:

- `RAXIS_OPERATOR_KEY` ← `--operator-key`.
- `RAXIS_OPERATOR_CERT` ← `--operator-cert`.
- `RAXIS_FORCE` (any non-empty) ← `--force`.

---

## Examples

### Same-host, single developer

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"
mkdir -p "$HOME/raxis-keys" && cd "$HOME/raxis-keys"
openssl genpkey -algorithm ED25519 -out operator_private.pem
chmod 600 operator_private.pem

raxis genesis \
  --operator-key  "$HOME/raxis-keys/operator_private.pem" \
  --operator-name "$USER"
```

### Air-gapped — pre-minted cert

```bash
# On the offline machine:
raxis cert mint \
  --key operator_private.pem \
  --display-name alice \
  --validity-days 365 \
  --out operator.cert.toml

# Transfer operator.cert.toml to the kernel host. NOT the private key.

# On the kernel host:
raxis genesis --operator-cert "$HOME/transfers/operator.cert.toml"
```

### Re-genesis a dev install

```bash
rm -rf "$RAXIS_DATA_DIR"
raxis genesis --operator-key "$RAXIS_OPERATOR_KEY" --operator-name "$USER"

# OR, if you can't rm:
RAXIS_FORCE=1 raxis genesis --operator-key "$RAXIS_OPERATOR_KEY" --operator-name "$USER"
```

---

## What `raxis genesis` writes

```text
$RAXIS_DATA_DIR/
├── policy/policy.toml          # Genesis bundle, embedded operator cert
├── policy/policy.toml.sig      # Sidecar Ed25519 signature
├── audit/segment-000.jsonl     # Chain anchor (epoch=1)
├── keys/authority.key          # Kernel authority private (mode 0600)
├── keys/quality.key            # Kernel quality private (mode 0600)
├── keys/verifier_token.key     # HMAC seed (mode 0600)
├── kernel.db                   # Empty SQLite store with schema applied
└── runtime/                    # Created lazily by the kernel daemon
```

---

## Common errors

| Symptom | Fix |
|---|---|
| `genesis: refusing to overwrite existing data dir` | Either `rm -rf "$RAXIS_DATA_DIR"` or `RAXIS_FORCE=1`. **Irreversible.** |
| `genesis: provide either --operator-cert OR --operator-key + --operator-name` | Pass one of the two flag sets. |
| `Algorithm ed25519 not found` (when generating the key first) | macOS LibreSSL — install `brew install openssl@3` and prepend its `bin/`. |
| `genesis: cert verify: signature did not match` | The `--operator-cert` was tampered with. Re-mint and re-transfer. |
| `genesis: BOOT_ERR_CREDENTIAL_MODE` | The `keys/*.key` files were left at wrong mode by a partial run. Wipe and re-genesis. |

---

## Variations

- **Provider credentials separately.** Genesis does NOT write
  `[gateway]` or `[[providers]]` blocks. Add them after the kernel
  is up via `$EDITOR` + `raxis policy sign`.
- **No-LLM install.** Genesis is fine; just don't add a
  `[gateway]` / `[[providers]]` block. The kernel boots without
  inference capability.
- **Multi-operator.** Add additional operators after genesis with
  `raxis cert install <other.cert.toml>`.
