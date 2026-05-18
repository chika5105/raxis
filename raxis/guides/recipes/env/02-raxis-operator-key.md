# `RAXIS_OPERATOR_KEY` — operator signing key path

> **Topic:** Environment variables | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

`RAXIS_OPERATOR_KEY` holds the **path** to the operator's Ed25519
private PEM. Every signing CLI (`policy sign`, `submit plan`,
`escalation approve`, `delegation grant`, `cert install`,
`cert revoke`, `epoch advance`) reads it as a fallback when
`--operator-key` isn't passed.

The variable holds a **path**, never the key bytes themselves. This
is by design — secret material in env blocks would leak via
`ps eww`, `/proc/$pid/environ`, kernel core dumps, and child-process
inheritance.

---

## Read by

`raxis-cli` only. The kernel never reads this variable; it
verifies signatures against the public keys in `[[operators.entries]]`.

---

## Default

No default. When the variable is unset and `--operator-key` isn't
passed, signing CLIs exit with:

```text
usage: --operator-key <path> is required for this command
```

Read-only commands (`status`, `log`, `verify-chain`, `doctor`,
`inspect`, etc.) don't need the key and run fine without it.

---

## Set

```bash
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"
```

The file at the path must:

- Exist.
- Be mode `0600` (CLI doesn't enforce this, but the kernel rejects
  signatures from broader-permission key files via the credential
  store).
- Be a valid Ed25519 PKCS#8 PEM (what `openssl genpkey -algorithm
  ED25519` produces).

---

## Precedence

```text
--operator-key <path>           ← always wins, even if env is set
   ├── if NOT passed:
   │      RAXIS_OPERATOR_KEY    ← fall back here
   │      └── if unset: error "usage: --operator-key <path> is required"
```

The CLI deliberately does NOT silently consult the env var when an
explicit flag is passed: a stale shell export should not override
the path the operator just typed.

---

## What it's used for

| Operation | CLI |
|---|---|
| Sign / re-sign policy | `raxis policy sign <path> --key <pem>` |
| Submit a plan bundle | `raxis --operator-key <pem> submit plan <plan.toml> --no-dry-run` |
| Approve an escalation | `raxis --operator-key <pem> escalation approve <id> --scope ...` |
| Grant a delegation | `raxis --operator-key <pem> delegation grant --session ... --capability ... --ttl ...` |
| Install a new operator cert | `raxis cert install <cert.toml> --policy <policy.toml>` then `raxis policy sign ... --key <pem>` |
| Revoke a cert | `raxis --operator-key <pem> cert revoke <cert.toml> --reason <rotation\|compromise> --reference <id>` |
| Advance the policy epoch | `raxis --operator-key <pem> epoch advance --policy <new.toml> --sig <new.sig>` |
| Quarantine plans by signer | `raxis --operator-key <pem> operator quarantine-plans-by <fp>` |

For commands shown with `raxis --operator-key <pem> ...`, the key flag
is global and must appear before the subcommand. Those commands also
fall back to `RAXIS_OPERATOR_KEY` when the global flag is absent.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `usage: --operator-key <path> is required` | Either set the env var or pass `--operator-key`. |
| `cannot read key file: Permission denied` | Mode is wrong. `chmod 600 "$RAXIS_OPERATOR_KEY"`. |
| `Algorithm ed25519 not found` (when generating) | LibreSSL — install Homebrew `openssl@3` and prepend its `bin/`. Doesn't apply to *reading* an existing PEM, only to creating one. |
| Multiple operators on one host pick the wrong key | Don't put two operators' env in the same shell. Use per-shell helper functions (see *Run multiple RAXIS installs* recipe). |

---

## Security model

The CLI:

1. Reads the file from `RAXIS_OPERATOR_KEY` (or the explicit flag).
2. Loads the key into process memory.
3. Signs the artifact's canonical bytes.
4. Writes the signature alongside.
5. Drops the key from memory at process exit.

The env var holds the **path**, not the bytes. This means:

- An operator can rotate keys without touching their shell rc.
- A leaked process env (via `ps eww`, etc.) reveals the path but
  not the key bytes.
- A leaked file (via `cat`, etc.) is locally containable: rotate
  the key, revoke the old cert, advance the epoch.

---

## Reference: related env vars + commands

| Variable | Relationship |
|---|---|
| `RAXIS_OPERATOR_CERT` | Path to a pre-minted operator cert; used at `raxis genesis --operator-cert <path>`. Independent of the private key. |
| `--operator-key <path>` | Explicit flag; always wins over the env var. |
| `raxis cert mint` | Use this to convert a private PEM into a self-signed cert. The cert can then be shipped offline; the private key stays where it was. |
| `raxis cert revoke <cert.toml> --reason <rotation\|compromise> --reference <id>` | Revoke a key after it is compromised; pass `--operator-key` globally or use `RAXIS_OPERATOR_KEY`. |

---

## Variations

- **Per-install shell switch.** Pair `RAXIS_OPERATOR_KEY` with
  `RAXIS_DATA_DIR` in helper functions; `raxis-prod` /
  `raxis-sandbox` flips both at once.
- **Hardware-backed keys.** V2 doesn't natively support PKCS#11
  / HSM at the CLI level, but you can mint a cert offline (with
  the HSM signing) and use `--operator-cert` at genesis. Beyond
  that, signing happens at the CLI; you'd need to wrap the CLI's
  signer or wait for V3 HSM support.
- **CI signing key.** Put a narrow-scope CI cert (with limited
  `permitted_ops`) in the CI runner's secret store; export
  `RAXIS_OPERATOR_KEY=<path>` in the CI job's env block.
