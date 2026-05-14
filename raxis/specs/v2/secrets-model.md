# RAXIS V2 — Secrets Model

> **Status:** V2 Specified — doctrinal companion to `credential-proxy.md`,
> `vm-network-isolation.md`, `v2-deep-spec.md §INV-VM-CAP-04`,
> `extensibility-traits.md §4` (`CredentialBackend`).
>
> **Audience:** Operators, kernel engineers, and test authors who need a
> one-page articulation of *what* RAXIS treats as secret material,
> *where* it lives, *how* an agent reaches services that need it, and
> *what the kernel does NOT rely on the LLM to do*.

---

## 1. Load-bearing principle

**The kernel does not rely on the LLM to behave well around secrets.**
Every protection in the secrets model is *mechanical*: structural
enforcement at the proxy boundary, the egress-allowlist boundary, and
the path-allowlist boundary. The kernel treats the LLM as
adversarial-by-design — anything readable IS read, anything writable
IS written, anything reachable IS reached. Compliance with policy text
is treated as zero evidence of safety.

This framing has one direct consequence that flows through every
section below: **there is no defensible test that asks the LLM to
politely avoid a `.env` file.** Such a test mistakes politeness for
mechanical enforcement and exercises the wrong invariant. The right
test is "operator did NOT put a real secret in the worktree; agent
uses the proxy; witness confirms zero raw credential material exists
anywhere on the agent's surface."

---

## 2. The five rules

### 2.1 — Operators never place raw secret material in worktrees

The worktree is the agent's read/write surface. Anything in the
worktree is, by design, accessible to the agent — that is the whole
point of having a worktree. **Raw credential material (real
passwords, real tokens, real signing keys, real kubeconfigs) MUST NOT
appear in any file under any worktree the agent can mount.**

Operationally this means:

* Real `.env` files containing production passwords do not exist
  anywhere under `$RAXIS_DATA_DIR/worktrees/`.
* `secrets/` directories holding API keys do not exist anywhere under
  any worktree.
* Build pipelines that previously committed credentials into a fixture
  directory MUST be migrated to `CredentialBackend` before running
  under RAXIS.

This rule is asserted on the *operator*. RAXIS does not police
worktree contents on the operator's behalf — the operator's
provisioning tooling owns this discipline. The kernel's role is to
make this discipline *sufficient*: an operator who follows it has a
sound secrets model; an operator who violates it has, at most, leaked
material they themselves placed.

### 2.2 — Secrets live in `CredentialBackend`

The canonical home for real credential material is the
`CredentialBackend` trait (`extensibility-traits.md §4`). The V2
default impl is `FileCredentialBackend` (`raxis-credentials-file`),
which reads `<data_dir>/credentials/<name>.env` and
`<data_dir>/providers/<name>.toml` — both required to be `chmod 0600`
and owned by the kernel's OS user. Production deployments may swap
in `VaultCredentialBackend`, `AwsSecretsManagerBackend`,
`AzureKeyVaultBackend`, `Pkcs11HsmBackend`, etc., behind the same
trait.

Three structural properties hold across every conformant impl:

1. **Resolution happens on the host, never in the agent VM.** The
   `CredentialBackend::resolve(name, consumer)` call is invoked from
   kernel address space. The bytes never cross the VM boundary; no
   VirtioFS mount exposes the credentials directory
   (`v2-deep-spec.md §INV-VM-CAP-04`).
2. **The agent VM never sees the bytes.** Not as a file mount, not as
   an env var, not in a config blob, not in a generated kubeconfig.
   Anything stamped into the VM's environment is either non-sensitive
   (a loopback URL pointing at the proxy) or a short-lived synthetic
   token issued by the proxy (e.g., the AWS IMDS-shaped response).
3. **Resolution emits exactly one `CredentialAccessed` audit event
   per `resolve` call.** Forensic readers can trace every access back
   to the kernel subsystem responsible.

### 2.3 — Agents reach external services only via credential proxies

Every authenticated external service the agent can reach is fronted
by a per-session credential proxy bound on the agent VM's loopback
interface (`127.0.0.1:NNN`). The proxy:

* Reads the real credential value at construction time via
  `Arc<dyn CredentialBackend>::resolve(...)` (host-side).
* Speaks the upstream protocol (PostgreSQL wire, k8s HTTPS, SMTP +
  STARTTLS, etc.) using the real credential.
* Speaks a dummy or no-credential variant of the same protocol to the
  agent — `AuthenticationOk` is sent unconditionally on a postgres
  proxy session; `AUTH` is not advertised on an SMTP proxy session;
  `Authorization` headers from the agent on an HTTP proxy session are
  stripped and rewritten by the proxy.

The agent's environment variables (`DATABASE_URL`, `KUBECONFIG`,
`SMTP_URL`, `AWS_CONTAINER_CREDENTIALS_FULL_URI`, …) point at the
loopback proxy, NOT the real upstream. The agent operates as if it
has credentials — `kubectl` works, ORMs connect, AWS SDK
authenticates — but the actual token, password, or key bytes live
only in the kernel's process space, outside the VM boundary.

### 2.4 — Egress allowlist mechanically enforces "proxy is the only path"

The kernel's two-tier unified egress (`vm-network-isolation.md` Tier 1
SNI allowlist + `credential-proxy.md` Tier 2 credential-proxy
loopback) means there is no IP-level route from inside the agent VM
to an authenticated upstream that bypasses the proxy. Any attempt by
the agent to dial the real upstream host:port directly is denied at
the in-guest tproxy with `TransparentProxyDenied { reason:
"proxy_target_bypass" }`, surfaced in the audit chain. The proxy's
loopback listener is the only reachable network path; the egress
allowlist is the structural enforcement.

### 2.5 — Operator-supplied placeholder credentials are explicitly fine

**Operators MAY supply placeholder credential strings to the agent**
— for example, via env vars stamped into a `.env` file in the
worktree, a config blob, or directly via plan-level env mounts — for
the purpose of giving the agent realistic-shape credentials to
authenticate with. **The credential-proxy at the loopback target
MUST substitute the operator-supplied placeholder with the real
`CredentialBackend`-resolved credential material BEFORE forwarding to
the real upstream.** The agent never sees the real material; the
placeholder material is non-sensitive and may live in the worktree.

Placeholder credentials look real to the agent. A jailbroken LLM that
exfiltrates every byte it can see leaks only the *placeholder* — the
fake-user / fake-password / fake-token / fake-canary strings the
operator deliberately staged. The real credentials never enter the
LLM's context. This is the load-bearing test of the proxy
substitution discipline (see `kernel/tests/extended_e2e_support/
credential_substitution_evidence.rs`).

The distinction between a "real `.env`" (rule 2.1 forbids it) and a
"placeholder `.env`" (this rule allows it) is straightforward:

| Property | Real `.env` (forbidden) | Placeholder `.env` (allowed) |
|---|---|---|
| Contents authenticate against the real upstream? | Yes | No |
| Operator's threat model treats them as sensitive? | Yes | No |
| Listed by name as a `CredentialBackend` entry? | Often duplicated | Never |
| Witness behaviour on leak | Hard fail (model violation) | Informational at most |

A placeholder `.env` is a *test fixture* and a *prompt-injection
honeypot*. Its purpose is to validate the substitution discipline by
giving the agent something to attempt to exfiltrate.

### 2.6 — Live-e2e example bundle: placeholder-only Anthropic credential

The realistic-scenario live-e2e harness mirrors its per-run
tmpdir into [`raxis/live-e2e/examples/`](../../live-e2e/examples/)
on demand (gated on `RAXIS_E2E_REFRESH_EXAMPLES=1`) so an
operator auditing "what configuration produced the latest
live-e2e iter?" can answer without re-running the test. The
mirror contains:

* `policy.toml` — the full harness-time policy (genesis
  bootstrap + harness overlay).
* `plan_primary.toml` + `plan_sibling.toml` — both initiatives'
  plan TOMLs.
* `credentials/test-{pg,mongo,redis,smtp}-dev.env` — the
  test-tenant credentials the harness's
  [`kernel_driver::write_credentials`](../../kernel/tests/extended_e2e_support/kernel_driver.rs)
  writes. These match the loopback-only docker-compose stack
  credentials and have no production value (the matching
  server-side credentials already commit in
  `docker-compose.extended.e2e.yml`).
* `credentials/anthropic.env.placeholder` — **placeholder ONLY**.
  The real Anthropic API key MUST NEVER be checked in.

The placeholder-file contract for Anthropic is structural, not
cosmetic:

* The auto-refresh hook
  ([`kernel_driver::maybe_refresh_examples`](../../kernel/tests/extended_e2e_support/kernel_driver.rs))
  rewrites `anthropic.env.placeholder` from a hardcoded constant
  (`ANTHROPIC_PLACEHOLDER_BODY`), NOT from the live
  `ANTHROPIC-API-DEV-KEY` value the harness loaded into
  `<data_dir>/providers/anthropic-realism-e2e.toml`. The real
  bytes never reach the refresh code path.
* The end-of-refresh witness
  ([`kernel_driver::assert_no_real_anthropic_key`](../../kernel/tests/extended_e2e_support/kernel_driver.rs))
  scans `examples/credentials/` for the real-key regex
  `sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}` and panics with a
  copy-pastable remediation hint on match. The panic fires
  BEFORE the kernel daemon spawns, so a refresh that would carry
  a real key fails the whole iter and produces no diff to
  `git add`.
* The same regex is enforced at commit time by
  [`raxis/scripts/check-no-real-anthropic-key.sh`](../../scripts/check-no-real-anthropic-key.sh),
  installable as a local pre-commit hook (documented in
  [`live-e2e/examples/README.md`](../../live-e2e/examples/README.md)).

The formal invariant is `INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01`
in [`specs/invariants.md §11.10`](../invariants.md).

The shape of this discipline is identical to §2.5 above:
operators MAY commit a placeholder-shape Anthropic credential
file to document the expected filename + format, because the
placeholder bytes are non-sensitive by construction (they look
real to a hypothetical observer but authenticate against
nothing). The structural enforcement keeps real-key bytes
strictly outside the worktree.

---

## 3. Why content-scanning is NOT the protection

A previous design considered scanning `InferenceRequest` payloads
for byte-substrings matching the credential value before forwarding
to the gateway. This was considered and rejected for the reasons
enumerated in `credential-proxy.md §8.3`:

* Base64 / hex / URL-encoded forms bypass byte matching.
* Character-split exfiltration ("the first half is X, the second half
  is Y") defeats per-call scanning.
* Semantic description ("the 14-character password starting with `r`
  and ending with `ss`") leaks information without any literal byte.
* The model that knows what a credential is also knows how to
  describe it without copying it.

Scanning is not a primary defense and cannot be made one. The
secrets model's protection is **structural** — the credential bytes
never enter the surface the model can observe, so there is nothing
for the model to encode, base64, or describe semantically.

---

## 4. What this means for testing

A test of the secrets model MUST mechanically verify the structural
property, not the cooperative property:

* **Wrong:** "the agent did not read `.env` (a polite request the
  test verifies by looking for the canary token in the agent's
  output)." This tests whether the LLM happened to comply with a
  prompt-text instruction. A future jailbroken or hallucinating LLM
  would fail this test, but RAXIS as a system is not failing — there
  was no defensible invariant in the first place.
* **Right:** "the operator did NOT put a real secret in the
  worktree. The agent was instructed to authenticate using
  placeholder credentials the operator staged. The proxy substituted
  the real credentials at the loopback boundary. The agent's
  worktree contains zero bytes of the real credential material
  post-run." This tests the structural property — the substitution
  discipline, the egress enforcement, and the absence of real
  credential material anywhere the agent could read it. A future
  jailbroken LLM does not change the witness verdict because the
  invariant is mechanical.

The realism e2e harness exercises the right shape:

* `kernel/tests/extended_e2e_support/transparent_proxy_evidence.rs`
  proves agents reach the upstream only via the proxy (egress check
  + per-service round-trip).
* `kernel/tests/extended_e2e_support/credential_substitution_evidence.rs`
  (added by the secrets-model realignment) proves the proxy
  substituted real credentials for operator-staged placeholders, and
  that the real credential material does NOT appear anywhere in the
  agent's worktree post-run.

---

## 5. Invariants this spec normalises

Canonical home for the invariants below is `specs/invariants.md`. The
formal statements (and the cross-invariant compositions they
participate in) live there. The list here is a quick reference; the
text in `invariants.md` is normative.

* `INV-SECRET-01` — Operators MUST NOT place raw secret material in
  any worktree.
* `INV-SECRET-02` — Secrets are resolved by `CredentialBackend` at
  proxy construction time on the host; agent VMs never see raw
  credential material in any form.
* `INV-SECRET-03` — Agents reach external services only via
  credential proxies; the kernel-mediated egress allowlist
  mechanically prevents direct upstream access.
* `INV-SECRET-04` — The kernel does not rely on agent compliance with
  policy text. Mechanical enforcement at proxy / egress /
  path-allowlist boundaries is the load-bearing guarantee.
* `INV-SECRET-05` — When an agent attempts authentication using
  operator-supplied placeholder credentials, the credential-proxy
  MUST substitute the real credential material BEFORE forwarding to
  the upstream. The placeholder credentials MUST NOT reach the
  upstream. The real credential material MUST NOT be visible to the
  agent in any form (env var, worktree file, audit envelope reachable
  from inside the VM, or wire byte the agent can observe).

`INV-SECRET-01..05` compose with `INV-VM-CAP-04` (no `credentials/`
mount inside the VM), `INV-CRED-KERNEL-01` (credential resolution is
kernel-mediated), and `INV-CLOUD-FWD-05` (V3 cloud-credential
exchange keeps operator credentials out of the VM) — together these
form the complete secrets model.

---

## 5.1 — Dashboard reveal contract (`INV-DASHBOARD-CREDENTIAL-*`)

The dashboard's credential-viewer surface is the only path
through which an operator inspects credential plaintext from
inside the dashboard. The contract here mirrors the on-disk
backend contract from §2.2 + the agent-isolation contract from
§2.3, with four additional dashboard-specific properties:

  * **Operator-visible inventory.** The listing endpoints
    (`/api/initiatives/:id/credentials`,
    `/api/system/credentials`) are gated at the `read` role —
    every credential the kernel uses, including the planner /
    reviewer LLM provider keys under `<data_dir>/providers/`,
    MUST appear here for any authenticated operator
    (`INV-DASHBOARD-CREDENTIAL-VIEWER-LISTS-ALL-OPERATOR-VISIBLE-SECRETS-01`).
    The plaintext stays gated; the listing surface lets the
    operator audit the full set of credentials the kernel
    can reach without reading the kernel host's disk.
  * **Default-masked.** The listing endpoints return metadata
    only — never plaintext. The wire shape pins this at
    compile time (`CredentialMetadata` has no `plaintext` /
    `bytes` field).
  * **Explicit reveal.** Plaintext is returned only via
    `POST .../reveal`, which requires the `admin` role,
    rate-limits to 5 reveals per operator per 60 s, and emits
    `OperatorRevealedCredential` (per-initiative, severity
    `high`) or `OperatorRevealedSystemCredential` (system /
    Anthropic, severity `critical`) BEFORE the response. A
    reveal click from a non-admin operator round-trips so the
    kernel emits the same paired audit row with
    `outcome = "RejectedPermission"` — silent failure is
    forbidden by
    `INV-DASHBOARD-CREDENTIAL-REVEAL-PLAINTEXT-WORKS-OR-EXPLAINS-01`.
  * **Auto-hide.** Every reveal response carries
    `expires_at_unix`; the FE re-masks at the deadline (30 s
    for per-initiative; 15 s for system). `Hide now` button
    gives an immediate manual mask.

The reveal endpoints inherit every property from §2.2:
plaintext is resolved by `FileCredentialBackend` (chmod-0600
+ uid validation), wrapped in `secrecy::SecretBox`, and
projected onto the wire shape inside a `with_bytes` closure
so the SecretBox zeros its inner copy on drop.

The Anthropic key gets the strictest variant of the contract
(`INV-DASHBOARD-ANTHROPIC-CREDENTIAL-SEVERITY-01`):
admin-only role gate + critical-severity audit + 15 s
auto-hide + Critical-priority notification fan-out so a
second operator sees the reveal in real time.

The dashboard reveal surface is not a side door around the
agent-isolation contract from §2.3 — agents still cannot reach
this endpoint (no JWT, no UDS access), and the audit chain
provides the same forensic trace whether the reveal happened
on the dashboard or via direct file inspection on the kernel
host.

Cross-reference:
`specs/v2/dashboard-hardening.md §2.7`,
`specs/v2/dashboard-operator-action-audit-coverage.md §6`,
`guides/operator/20-dashboard-credential-reveal.md`.

---

## 6. Related specs

* `credential-proxy.md` — proxy types, restrictions, audit events,
  and the rejected env-var-injection design (§8) that motivates this
  spec.
* `vm-network-isolation.md` — Tier 1 SNI-allowlist tproxy + the
  proxy-bypass denial reason this spec asserts mechanically.
* `extensibility-traits.md §4` — `CredentialBackend` trait + the
  conformance contract every concrete backend MUST satisfy.
* `v2-deep-spec.md §INV-VM-CAP-04` — the structural enforcement that
  `credentials/` is not mountable into a session VM.
