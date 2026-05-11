# `raxis credential list/show/rotate/remove/verify/audit`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

The day-2 credential surface. Read-only inspection (`list`, `show`,
`audit`), in-place rotation (`rotate`), removal (`remove`), and
proxy reachability check (`verify`).

---

## Syntax

```text
raxis credential list                       [--json]
raxis credential show   <id>                [--json]
raxis credential rotate <id> --secret <path|inline>
raxis credential remove <id>                [--reason <text>]
raxis credential verify <id>
raxis credential audit  <id>                [--limit N] [--json]
```

---

## list — inventory

```bash
raxis credential list
# Output:
# CREDENTIAL_ID   KIND                LAST_USED              RESTRICTION
# github-deploy   github_token        2026-05-10T16:20:00Z   methods=GET,POST repos=my-org/my-repo
# postgres-write  postgres            2026-05-10T16:42:00Z   stmts=INSERT,UPDATE tables=events
# aws-readonly    aws_iam             —                      actions=s3:GetObject

raxis credential list --json | jq '.[] | {id, kind, restriction}'
```

`LAST_USED` is the most recent `CredentialUsed` audit event. `—`
means the credential exists but has never been used (audit
column-cap).

---

## show — one credential

```bash
raxis credential show github-deploy
# Output:
# credential_id:   github-deploy
# kind:            github_token
# label:           GitHub deploy token, repo: my-org/my-repo
# created_at:      2026-04-01T00:00:00Z
# last_used:       2026-05-10T16:20:00Z
# secret_sha:      9c41...   (sha256 of secret bytes; secret itself never printed)
# restriction:
#   allowed_methods: ["GET", "POST"]
#   allowed_repos:   ["my-org/my-repo"]
```

The secret is never printed in any form — the kernel surfaces only
the sha256 prefix for auditability.

---

## rotate — replace the secret

```bash
raxis credential rotate github-deploy \
  --secret /tmp/new-github.token
# Output:
# credential_id:   github-deploy
# old_secret_sha:  9c41...
# new_secret_sha:  3b1d...
# rotated_at:      2026-05-10T17:00:00Z
```

Rotation is atomic: in-flight proxy requests still complete with
the old secret, but new requests use the new one. No session
restart required.

The audit chain captures `CredentialRotated { id, old_sha_prefix, new_sha_prefix }`.

---

## remove — delete

```bash
raxis credential remove github-deploy --reason "no longer used"
# Output:
# credential_id:  github-deploy
# state:          Removed
# in_use_now:     no
```

Removal fails-closed if any active session references the
credential; check with `raxis sessions --json | jq '... credentials_referenced'`
or simply remove the binding from the relevant `plan.toml` first.

---

## verify — proxy sanity check

```bash
raxis credential verify github-deploy
# Output:
# credential_id:   github-deploy
# proxy_endpoint:  127.0.0.1:48121
# liveness:        ok
# auth_check:      ok (HEAD https://api.github.com → 200 OK)
```

`verify` makes a synthetic request through the proxy that
exercises the credential against its target service. Useful
pre-flight before a long-running plan that depends on the
credential.

For credentials where a synthetic auth check isn't well-defined
(e.g., a Postgres credential to a private VPC), the kernel falls
back to liveness only.

---

## audit — credential-use history

```bash
raxis credential audit github-deploy --limit 20
# Output:
# AT                       SESSION    URL_SHA   METHOD  STATUS
# 2026-05-10T16:20:00Z     91a7c83f   3a2c01ff  GET     200
# 2026-05-10T16:18:00Z     91a7c83f   7f880c2e  POST    201
# ...
```

The `URL_SHA` column is sha256 of the canonical URL (path +
sorted-query-params); it lets you correlate proxy requests with
the audit chain without leaking the URL itself in the listing. Pull
the full URL from `raxis log <initiative_id>` if needed.

---

## Common errors

| Symptom | Fix |
|---|---|
| `verify: liveness ok, auth_check failed` | Secret rotated upstream but not in Raxis; `credential rotate` to update. |
| `remove: in use by sessions [...]` | Active sessions still reference this credential; abort or wait, then retry. |
| `show: credential not found` | Wrong id or already removed. |
| `rotate: --secret unreadable` | Path / perm issue. |
| `audit: empty` | Credential exists but has never been used. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis credential add` | Register a new credential. |
| `raxis log <initiative_id>` | Audit chain for an initiative (includes `CredentialUsed`). |
| `raxis explain <task_id>` | Per-task decision tree (includes credential decisions). |

---

## Variations

- **Pre-flight before a plan.** Run `verify` for every credential
  the plan binds; abort plan submission if any fails.
- **Drift dashboard.** `audit --json` per credential, fed to a
  dashboard that flags credentials with sudden traffic spikes.
- **Compromise drill.** `rotate` the secret; the proxy switches
  atomically; `audit` post-rotation confirms only the new secret
  hash appears.
- **Credential expiry monitor.** Combine
  `credential list --json` with the kind-specific TTL data (e.g.,
  AWS sts token expiry) to alert on certs nearing expiry.
