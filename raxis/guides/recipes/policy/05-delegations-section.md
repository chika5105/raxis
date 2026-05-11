# `[delegations]` — capability delegation TTL ceiling

> **Topic:** Policy reference | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

A **delegation** is an operator-issued, time-bounded capability slip
that lets a session perform a specific class of operation it
otherwise couldn't. The classic example: an Executor session needs
write access to a credential-protected secret store for the next
30 seconds. The operator runs `raxis delegation grant` with a
specific `--capability` and `--ttl`; the session presents the slip
with each IPC; the kernel verifies the operator's signature, the TTL,
and the capability class. This block sets the upper bound on the TTL
operators may request.

---

## Field reference

| Field | Type | Required | Default-ish | Effect |
|---|---|---|---|---|
| `max_ttl_secs` | `u64` | yes | `86400` (1d) | Hard ceiling on `--ttl` passed to `raxis delegation grant`. The kernel rejects a longer TTL with `FAIL_DELEGATION_TTL_ABOVE_CEILING`. |

That's the entire block — one knob. Delegations have no per-class
overrides; the same ceiling applies regardless of capability.

---

## Example

```toml
[delegations]
max_ttl_secs = 3600    # 1 hour ceiling
```

For high-trust environments, ratchet it down:

```toml
[delegations]
max_ttl_secs = 300     # 5 minutes — every delegation expires fast
```

---

## Step-by-step — granting a delegation

```bash
# 1. The Executor session needs `secret_read` for the next 30s.
raxis delegation grant \
  --session  c4f1e8b2... \
  --capability secret_read \
  --role     "secret-reader" \
  --ttl      30

# 2. The kernel validates:
#    - operator key matches a [[operators]] entry,
#    - capability is a known class,
#    - --ttl <= [delegations] max_ttl_secs,
#    - --role is a known [[roles]] entry,
#    - --session is a live planner session.

# 3. The operator socket returns the signed slip; the kernel auto-
#    delivers it to the session over its IPC. The Executor uses it
#    for the next 30s, after which every subsequent IPC frame using
#    it is rejected with FAIL_DELEGATION_EXPIRED.
```

The slip is stored only in memory — there's no on-disk delegation
file. A kernel restart drops every active delegation; long-running
sessions that need ongoing capability must request a new slip
post-restart.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `FAIL_DELEGATION_TTL_ABOVE_CEILING` | Lower `--ttl` OR raise `max_ttl_secs` and re-sign policy. |
| `FAIL_UNKNOWN_CAPABILITY_CLASS` | The `--capability` string isn't one the kernel recognises. Run `raxis delegation grant --help` for the canonical list. |
| `FAIL_UNKNOWN_ROLE` | The `--role` isn't declared in `[[role_entries]]`. Add it; re-sign. |
| Delegation works, then suddenly stops | The slip's TTL elapsed mid-task. The session must request a fresh slip. |

---

## Reference: related CLI + policy

| Surface | Purpose |
|---|---|
| `raxis delegation grant --session <id> --capability <class> --role <id> --ttl <secs>` | Grant a slip to one session. |
| `[[role_entries]]` | Declares the role IDs that delegations can reference. |
| `raxis log --kind DelegationGranted` | Audit every grant. |
| `raxis log --kind DelegationExpired` | Audit every TTL expiry. |
| `raxis log --kind DelegationRevoked` | Audit operator-mediated revocations (V3 — not yet a CLI command). |

---

## Variations

- **No delegations.** Set `max_ttl_secs = 1` (one second). The CLI
  command technically still works but no useful delegation can be
  issued. For full prohibition, simply never run
  `raxis delegation grant`; the kernel never auto-issues delegations.
- **Per-environment ceilings.** Not directly supported in V2 — one
  global ceiling. For per-env policy, run separate kernel installs
  with separate `RAXIS_DATA_DIR` values.
- **Audit-only.** All delegations are audited regardless of TTL;
  there's no "silent" mode.
