# Reveal a credential through the dashboard

> **Audience.** Operators who need to inspect a credential's
> plaintext value (e.g. for a database connection check, a
> billing audit, a rotation handoff) WITHOUT shelling onto the
> kernel host. Recipe-level detail; the normative contract lives
> in `specs/invariants.md` (`INV-DASHBOARD-CREDENTIAL-*`) and
> `specs/v2/dashboard-operator-action-audit-coverage.md`.

## Before you start

You will need:

  1. **An `admin`-role dashboard JWT.** Per
     `INV-DASHBOARD-CREDENTIAL-REVEAL-ROLE-GATED-01`, only
     `admin`-role tokens can reveal plaintext. `read` and
     `write_policy` tokens get an explicit `403 Forbidden` —
     not a confusing 500 — and the rejection is itself audited.
     If you don't have an admin token, request a policy epoch
     advance from the operator who holds the authority key; do NOT
     attempt a workaround. Dashboard `admin` is derived from the
     operator cert's `permitted_ops`: the operator must have both
     `RotateEpoch` and `OperatorCertInstall`.
     **Follow-up:** split this into a narrower
     `CredentialReveal` or `CredentialReadSensitive` permission so
     operators can inspect credentials without also holding
     certificate-install authority.
  2. **A reason to look at the bytes.** Every reveal is a
     forensic event in the audit chain. For initiative-bound
     credentials (database URLs, SMTP passwords, etc.) the
     emission is `OperatorRevealedCredential` at `high`
     severity. For system-wide credentials (Anthropic, OpenAI,
     other provider keys) the emission is
     `OperatorRevealedSystemCredential` at `critical` severity
     AND fans out to every operator's notification inbox.
     Reveal only when the action is justified.

## Step 1 — Find the credential

The dashboard surfaces credentials in two places:

  * **Per-initiative credentials** live on the InitiativeDetail
    page under the `Credentials` tab. Open the initiative you
    care about, then click `Credentials`. You will see one card
    per credential with name, proxy type (`postgres`, `http`,
    `smtp`, `redis`, …), mount alias (the env-var the kernel
    injects into the agent's session), byte size, and SHA-256
    prefix.
  * **System-wide credentials** live at `/system/credentials`.
    Sidebar nav → `Credentials`. The link is visible to every
    authenticated operator (`read` or higher) — per
    `INV-DASHBOARD-CREDENTIAL-VIEWER-LISTS-ALL-OPERATOR-VISIBLE-SECRETS-01`,
    every credential the kernel uses, including the planner /
    reviewer LLM provider keys, MUST appear here so the
    operator can audit the surface area without shelling onto
    the kernel host. The Anthropic key is the canonical
    example. Read-role operators see metadata only; the
    `Reveal plaintext` action stays admin-only and a non-admin
    attempt returns a structured 403 with a paired audit row.

The default state is hidden. The card shows a `Reveal plaintext`
button but no bytes — per
`INV-DASHBOARD-CREDENTIAL-DEFAULT-MASKED-01`, plaintext is
revealed only on explicit operator action.

## Step 2 — Click reveal

1. Click `Reveal plaintext`.
2. A confirmation modal appears. For per-initiative credentials
   the body reads:

   > Reveal credential plaintext? This action will be audited
   > as `OperatorRevealedCredential`.

   For Anthropic and other system credentials, the modal
   carries a stronger warning:

   > The Anthropic API key is a high-value secret. Revealing
   > will be audited as `OperatorRevealedSystemCredential` at
   > Critical severity. Confirm only if necessary for
   > diagnostics.

3. Click `Confirm`. The dashboard issues a `POST` to
   `/api/initiatives/:id/credentials/:name/reveal` (or
   `/api/system/credentials/:name/reveal` for system creds).
   The plaintext is rendered in a Monaco viewer (read-only,
   monospace, copy button) inside the card.

## Step 3 — Observe the auto-hide

A countdown timer starts above the plaintext block. Per
`INV-DASHBOARD-CREDENTIAL-AUTO-HIDE-01`:

  * **Per-initiative credentials** — 30 seconds.
  * **System / Anthropic credentials** — 15 seconds.

When the timer hits zero the card returns to the masked state
automatically. You can also click `Hide now` for an immediate
manual mask.

The plaintext is NEVER persisted to the FE's `localStorage`.
Closing the tab discards it.

## Step 4 — Check the audit row

Open the Audit tab in the dashboard sidebar. The most recent row
will be:

  * `OperatorRevealedCredential` — for per-initiative reveals.
    Outcome: `Accepted`. Severity: `high`. Carries the
    initiative id, credential name, and your operator
    fingerprint.
  * `OperatorRevealedSystemCredential` — for system reveals.
    Outcome: `Accepted`. Severity: `critical`. Carries the
    credential name and your fingerprint.

For Anthropic reveals, the same event ALSO appears in the
notification inbox at Critical priority. Other operators see it
within seconds of the reveal.

## Failure modes

  * **403 Forbidden** — your token is not `admin`. The FE
    renders the structured 403 inline (a red dismissable
    banner naming the missing role) and the audit chain
    records the attempt as
    `OperatorRevealedCredential { outcome = "RejectedPermission" }`
    (or `OperatorRevealedSystemCredential` at `critical`
    severity for the system surface). Per
    `INV-DASHBOARD-CREDENTIAL-REVEAL-PLAINTEXT-WORKS-OR-EXPLAINS-01`,
    the click is NEVER a silent no-op — every reveal click
    either returns plaintext or denies cleanly with a
    visible message AND a paired audit row.
    If the operator should be admin, mint a replacement cert for the
    same operator key that includes both `RotateEpoch` and
    `OperatorCertInstall`, install it with `raxis cert install
    --replace-for <old_fp> --new-cert <cert.toml> --policy
    "$RAXIS_DATA_DIR/policy/policy.toml"`, bump `[meta].epoch`,
    sign with `"$RAXIS_DATA_DIR/keys/authority_keypair.pem"`, then
    run `raxis epoch advance`. Sign out and back into the dashboard
    afterward so the JWT is re-minted with the new `admin` role.
  * **404 Not Found** — the credential name does not match any
    declaration in the initiative's plan, or the on-disk file is
    missing. Audit emission carries `outcome =
    "RejectedValidation"`. Check the credential name against
    `plan_*.toml` and the on-disk path against
    `<data_dir>/credentials/<name>.env` (or
    `<data_dir>/providers/<id>.toml` for system credentials).
  * **429 Too Many Requests** — you have exceeded the reveal
    rate limit (5 reveals per operator per 60-second window).
    Wait for the `Retry-After-Secs` window to elapse and try
    again. The throttled call also audits with `outcome =
    "RejectedValidation"` so a chatty operator pattern is
    forensically visible.
  * **500 Internal Error** — the kernel's audit-sink failed (or
    the credential file's mode/uid validator rejected the on-
    disk state). The plaintext is NOT returned; the failure
    audits with `outcome = "InternalError"`. File a kernel bug
    with the dashboard's correlation id from the response
    envelope.

## Rate limit

The reveal endpoints are rate-limited to **5 reveals per operator
per 60-second sliding window** (configurable via the
`reveal_rate_limit_per_window` and `reveal_rate_limit_window_secs`
fields in `[dashboard]` policy.toml block; defaults are baked
into `KernelDashboardData`).

The limit applies independently to per-initiative and system
reveals — so 5 per-initiative reveals + 5 system reveals in the
same minute is fine. The 429 response carries
`Retry-After-Secs` in the JSON body so the FE can render an
accurate countdown.

## Cross-references

  * `INV-DASHBOARD-CREDENTIAL-DEFAULT-MASKED-01` /
    `INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01` /
    `INV-DASHBOARD-CREDENTIAL-REVEAL-ROLE-GATED-01` /
    `INV-DASHBOARD-CREDENTIAL-AUTO-HIDE-01` /
    `INV-DASHBOARD-ANTHROPIC-CREDENTIAL-SEVERITY-01` /
    `INV-DASHBOARD-CREDENTIAL-VIEWER-LISTS-ALL-OPERATOR-VISIBLE-SECRETS-01` /
    `INV-DASHBOARD-CREDENTIAL-REVEAL-PLAINTEXT-WORKS-OR-EXPLAINS-01` —
    canonical statements.
  * `specs/v2/dashboard-operator-action-audit-coverage.md` —
    the per-endpoint emission table.
  * `specs/v2/secrets-model.md` — the credential lifecycle.
  * `specs/v2/dashboard-hardening.md §credentials-view` — the
    dashboard's TCB boundary for the reveal surface.
