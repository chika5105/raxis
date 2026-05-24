# `raxis policy sign`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

Signs a `policy.toml` (or other non-plan artifact) and writes a
detached `<file>.sig`. Policy artifacts are signed with the kernel
authority key and produce the raw 64-byte signature that
`raxis epoch advance` verifies. Other non-plan artifacts use the
operator-key sidecar format. Plans are signed and submitted
atomically through `submit plan` — this command intentionally
rejects `plan.toml` artifacts.

---

## Syntax

```text
raxis policy sign <artifact.toml> --key <pem>
```

---

## Flags

| Flag | Effect |
|---|---|
| `--key <pem>` | For `policy.toml`, pass `$RAXIS_DATA_DIR/keys/authority_keypair.pem`. For other non-plan artifacts, pass the operator Ed25519 private PEM or rely on `RAXIS_OPERATOR_KEY`. |

---

## Example

```bash
$EDITOR "$RAXIS_DATA_DIR/policy/policy.toml"
# … make edits …
# Bump [meta].epoch to the next integer before signing.

raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_DATA_DIR/keys/authority_keypair.pem"

# Apply the signed artifact through the policy-epoch ceremony:
raxis epoch advance \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml" \
  --sig    "$RAXIS_DATA_DIR/policy/policy.sig"
raxis log --kind PolicyEpochAdvanced --limit 1
```

---

## What it does

1. Reads the file.
2. If the file has `[authority].authority_pubkey`, verifies that
   `--key` is the matching authority key.
3. Computes Ed25519 over the exact policy bytes on disk.
4. Writes `<artifact>.sig` as raw 64-byte Ed25519 signature bytes.

For non-policy artifacts, the command keeps the operator-key TOML
sidecar shape.

`policy sign` is local file work. The kernel does not adopt the new
bundle until `raxis epoch advance --policy <path> --sig <path>`
commits the signed artifact.

### Sections that also require a kernel restart

- `[gateway]` — the gateway supervisor is wired at boot.
- `[host_capacity] required_min_fd_limit` — RLIMIT is set at boot.

For everything else, signed epoch advance is sufficient.

---

## Plans are NOT signed via this command

```bash
raxis policy sign /path/to/plan.toml ...
# → policy sign: refusing to sign a plan.toml artifact
#   hint: use `raxis submit plan <plan.toml> --no-dry-run` to sign + submit atomically.
```

Plans use a different signing surface (`submit plan`) because the
plan-bundle envelope includes a `signed_at` and nonce specifically
to defeat replay; signing them via `policy sign` would skip that
envelope.

---

## Common errors

| Symptom | Fix |
|---|---|
| `policy sign: --key <path> is required` | Pass the authority key for policy artifacts, or set `RAXIS_OPERATOR_KEY` for other artifacts. |
| `policy sign: cannot read key file: Permission denied` | `chmod 400 "$RAXIS_DATA_DIR/keys/authority_keypair.pem"` for policy signing, or `chmod 600 "$RAXIS_OPERATOR_KEY"` for operator-key artifacts. |
| `policy artifact ... must be signed with the authority key` | You passed the operator key. Use `$RAXIS_DATA_DIR/keys/authority_keypair.pem` for `policy.toml`. |
| `policy sign: refusing to sign plan.toml` | Use `raxis submit plan` for plans. |
| `FAIL_POLICY_EPOCH_REPLAY` during advance | `[meta].epoch` was not bumped. Re-read with `raxis policy show --history`, set the next epoch, sign again, and retry. |
| Kernel still shows the old policy | Run `raxis epoch advance --policy <path> --sig <sig>` against the exact signed artifact. |

---

## Reference

| Surface | Purpose |
|---|---|
| `raxis policy show [--history]` | Inspect the active bundle and the epoch history. |
| `raxis policy diff <left.toml> <right.toml>` | Semantic diff between two bundles. |
| `raxis epoch advance --policy <path> --sig <sig>` | Force-advance the epoch (used for atomic policy hand-off ceremonies). |
| `raxis policy generate-sidecar-secret` | Mint a sidecar HMAC for sub-process IPC integrity (less common). |

---

## Variations

- **CI signing.** Store the authority signing key in the release
  secret store and only run this after an operator-reviewed policy
  diff.
- **Detached signature.** The policy `.sig` sidecar is raw Ed25519
  bytes; archive it with the policy file for forensic reconstruction.
- **Multi-operator co-signing.** V2 admits one signature per
  bundle; multi-sig is V3. For now, designate a single signer per
  policy bundle.
