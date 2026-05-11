# `raxis delegation grant`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐⭐ Advanced

Operator-signed permission slip. A delegation lets a session
perform an action it doesn't otherwise have direct authority for
(e.g., a Reviewer reading a non-allowlisted file for evidence, an
Executor talking to a non-allowlisted host for a one-off probe).
Delegations have a strict TTL ceiling (`[delegations].max_ttl_seconds`)
and live alongside `subtask_activations` in the audit chain.

---

## Syntax

```text
raxis delegation grant --session <session_id>
                       --capability <capability>
                       --scope <scope_json>
                       [--ttl <seconds>]
                       [--reason <text>]
```

---

## Capabilities

| Capability | Use |
|---|---|
| `read_path` | Read a file outside the task's `path_allowlist`. Scope: `{"path": "<absolute>"}`. |
| `write_path` | Write a file outside `path_allowlist`. Scope: `{"path": "<absolute>"}`. |
| `egress` | Talk to a host outside `allowed_egress`. Scope: `{"host": "...", "port": ...}`. |
| `read_audit` | Read the audit chain. Scope: `{"initiative_id": "..."}`. |

---

## Example

A reviewer needs to read `docs/architecture.md` for context, but
the task's `path_allowlist` is `["src/auth/"]`:

```bash
raxis delegation grant \
  --session 91a7c83f \
  --capability read_path \
  --scope '{"path": "/var/raxis/worktrees/.../docs/architecture.md"}' \
  --ttl 600 \
  --reason "review of auth refactor needs architecture context"
# Output:
# delegation_id:  d8a93c1f...
# capability:     read_path
# expires_at:     2026-05-10T17:40:00Z
# operator_sig:   <hex>
```

The reviewer's session can now read that one file for 10 minutes.

---

## Lifecycle states

A delegation moves through:

```text
Active            ── after grant, before TTL
StaleOnNextUse    ── policy.toml changed under the delegation; next use revokes it
Expired           ── TTL passed
RenewalRequired   ── operator manually marked
NotGranted        ── never existed
```

Every state transition is in the audit chain (`DelegationStateChanged`).

To list active delegations on a session:

```bash
raxis sessions show 91a7c83f --with-delegations
```

To revoke early:

```bash
raxis delegation revoke d8a93c1f --reason "no longer needed"
```

---

## Common errors

| Symptom | Fix |
|---|---|
| `grant: --ttl exceeds [delegations].max_ttl_seconds` | Lower the TTL or raise the policy cap and re-sign policy. |
| `grant: --scope JSON malformed` | Validate the JSON; capability schemas are strict. |
| `grant: capability unsupported by kernel version` | Upgrade the kernel or pick a known capability. |
| `OPERATOR_NOT_AUTHORIZED` | Cert lacks `GrantDelegation` in `permitted_ops`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis delegation list [--session <id>]` | Active delegations on a session. |
| `raxis delegation revoke <id> [--reason ...]` | Pre-empt a delegation. |
| `raxis sessions show <id> --with-delegations` | Drill into one session's delegations. |
| `raxis log <initiative_id>` | Audit events including grants. |

---

## Variations

- **Egress delegation for a one-off probe.** Grant `egress` for
  `https://api.example.com` for 5 minutes; the kernel proxy admits
  the request only inside that window.
- **Read-audit delegation for a debugging tool.** A diagnostic
  session needs to read the audit chain for one initiative; grant
  `read_audit` scoped to that initiative.
- **TTL ceilings.** Set `[delegations].max_ttl_seconds = 3600` in
  policy and operators cannot accidentally grant a 24-hour bypass.
- **Operator-key compromise drill.** Revoke the operator's cert,
  then `raxis delegation revoke` every active delegation they
  signed.
