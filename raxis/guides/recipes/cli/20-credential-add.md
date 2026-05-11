# `raxis credential add`

> **Topic:** CLI | **Time to read:** ~3 min | **Complexity:** ⭐⭐⭐ Advanced

Register a new credential entry in the kernel's credential store.
Credentials are not delivered to sessions directly; instead the
kernel exposes a localhost TCP credential proxy that the session
talks to. The proxy injects the credential into the outbound
request and logs every use into the audit chain.

---

## Syntax

```text
raxis credential add --id <credential_id>
                     --kind <generic|github_token|aws_iam|gcp_service_account|postgres|...>
                     --secret <secret_or_path>
                     [--restriction <restriction_json>]
                     [--label <text>]
```

---

## Concepts

| Term | Meaning |
|---|---|
| `credential_id` | Stable name used in `[[tasks.credentials]]` to bind a proxy to the secret. |
| `kind` | Determines the proxy implementation — what protocol/headers/restrictions are valid. |
| Restriction | Per-credential limits beyond the protocol default (e.g., only allow GET, only POST to `/v1/x`). Applied by the proxy, not the session. |
| Audit | Every proxy request becomes a `CredentialUsed` event with sha256 of the request URL + redacted body. |

---

## Examples

### Generic bearer-token credential

```bash
raxis credential add \
  --id   github-deploy \
  --kind github_token \
  --secret /tmp/github.token \
  --label "GitHub deploy token, repo: my-org/my-repo"
# Output:
# credential_id:   github-deploy
# kind:            github_token
# id_hash_prefix:  9c41...
# label:           GitHub deploy token, repo: my-org/my-repo
```

In `plan.toml`:

```toml
[[tasks.credentials]]
id        = "github-deploy"
proxy_var = "GITHUB_TOKEN"  # env var the session sees pointing at the proxy
```

Inside the session, `$GITHUB_TOKEN` is **not** the actual token —
it's a per-session opaque credential reference. The session emits
HTTP requests via the proxy URL (also injected); the proxy decodes
the reference, validates the request against the credential's
restriction, injects the real token, and forwards.

### Postgres credential proxy

```bash
raxis credential add \
  --id   postgres-write \
  --kind postgres \
  --secret /tmp/pg.json \
  --restriction '{"allowed_statements": ["INSERT", "UPDATE"], "allowed_tables": ["events"]}' \
  --label "Postgres write to events table"
```

The Postgres credential proxy speaks the Postgres wire protocol on
a localhost TCP port; the session connects with `psql` or any pg
driver. Statements outside the restriction are rejected.

See [`raxis-concepts/credential-proxies.md`](../../../raxis-concepts/credential-proxies.md)
for the full credential-proxy taxonomy.

### AWS IAM credential

```bash
raxis credential add \
  --id   aws-readonly \
  --kind aws_iam \
  --secret /tmp/aws-iam.json \
  --restriction '{"allowed_actions": ["s3:GetObject"], "allowed_resources": ["arn:aws:s3:::my-bucket/*"]}'
```

The AWS proxy intercepts AWS Signature v4 requests and rejects any
action / resource not in the restriction.

---

## Restriction JSON shape

Each `kind` defines its own restriction JSON schema:

| Kind | Common keys |
|---|---|
| `github_token` | `allowed_methods`, `allowed_repos`, `allowed_paths` |
| `postgres` | `allowed_statements`, `allowed_tables`, `allowed_databases` |
| `aws_iam` | `allowed_actions`, `allowed_resources`, `allowed_regions` |
| `gcp_service_account` | `allowed_methods`, `allowed_resources` |
| `generic` | `allowed_hosts`, `allowed_paths`, `allowed_methods` |

If `--restriction` is omitted, the proxy uses the kind's
permissive default. **For production credentials, always set a
restriction.**

---

## Common errors

| Symptom | Fix |
|---|---|
| `add: credential id already exists` | Either `raxis credential rotate <id>` to replace the secret, or pick a new id. |
| `add: --secret path not readable` | Path typo or perms; check `ls -la`. |
| `add: kind unsupported by kernel version` | Upgrade the kernel or pick a supported kind. Run `raxis credential add --help-kinds` for the supported list. |
| `add: restriction JSON malformed` | Validate the JSON; restriction schemas are strict per kind. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis credential list` | All credentials. |
| `raxis credential show <id>` | One credential's metadata + restriction. |
| `raxis credential rotate <id> --secret ...` | Replace the secret without changing the id. |
| `raxis credential remove <id>` | Delete a credential. |
| `raxis credential verify <id>` | Sanity-check the proxy is reachable and the secret is valid. |
| `raxis credential audit <id>` | Show recent `CredentialUsed` events. |

---

## Variations

- **Per-environment IDs.** `github-prod`, `github-staging` —
  separate ids prevent a staging task from accidentally using a
  prod token.
- **Tight restrictions for AI Reviewers.** A reviewer needs to
  fetch evidence; restrict to GET-only on a specific repo.
- **Time-windowed credentials.** Pair `credential add` with a cron
  that calls `credential remove` after the window. Kernel handles
  in-flight removal cleanly.
- **Forensic credentials.** `credential audit <id>` is per-credential;
  combine with `raxis log <initiative_id>` to correlate
  credential use with task progress.
