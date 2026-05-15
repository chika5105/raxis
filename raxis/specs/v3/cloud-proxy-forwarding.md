# cloud-proxy-forwarding.md

V3 normative spec. Converts the V2 IMDS / metadata-server
**emulators** in
`crates/credential-proxy-{aws,gcp,azure}` into real upstream-
forwarding proxies that exchange long-lived operator-held
credentials for short-lived agent-facing tokens via the real cloud
control planes (`sts.amazonaws.com`, `oauth2.googleapis.com`,
`login.microsoftonline.com`).

Normative companion to:

- `specs/v2/credential-proxy.md §3.2 / §3.3 / §3.4` (V2 emulator
  contract — preserved; V3 is opt-in per-decl).
- `specs/v2/audit-paired-writes.md` (audit-emission shape).
- `specs/v2/vm-network-isolation.md` (egress allowlist invariant).
- `specs/v2/extensibility-traits.md §4` (`CredentialBackend` trait).
- `specs/v3/observability-prometheus.md §3.5` (credproxy metrics).

This document is the V3 cloud-forwarding contract. Implementations
in `crates/credential-proxy-cloud-shared/`,
`crates/credential-proxy-aws/`, `crates/credential-proxy-gcp/`,
and `crates/credential-proxy-azure/` MUST mirror it byte-for-
field. If implementation reality diverges, the spec is updated
FIRST in the same commit train and the change justified.

---

## 1. Goals & non-goals

### 1.1 Goals

- **G1 — Real token-exchange forwarding.** V3 proxies forward
  real `sts:AssumeRole` (AWS), JWT-bearer-grant (GCP), and
  `client_credentials`-grant (Azure) requests to the canonical
  cloud control-plane endpoints, then surface the upstream's
  short-lived credentials to the in-VM client through the same
  IMDS / metadata-server wire shapes V2 already serves.

- **G2 — Long-lived material never crosses the VM boundary.** The
  IAM access key (AWS), service-account private key (GCP), and
  service-principal secret (Azure) live exclusively in the
  kernel's `CredentialBackend`. They reach the V3 proxy through
  `CredentialBackend::resolve`; they NEVER reach the agent VM,
  the audit chain payload, the observability stream, or any log
  line.

- **G3 — Backward-compatible per-plan opt-in.** V2 emulator
  behavior is preserved on every existing plan. A plan opts a
  single credential into V3 forwarding by setting
  `forwarding_enabled = true` on that one
  `[[tasks.credentials]]` block. Plans can mix V2 and V3
  credentials freely.

- **G4 — Canonical wire-shape preservation on failure.** When
  the upstream exchange fails, the V3 proxy surfaces the
  upstream's documented error envelope unchanged. The in-VM
  client's error-handling code path treats the V3 proxy
  identically to talking to the real cloud.

- **G5 — Construction-enforced egress allowlist.** The upstream
  HTTPS dispatch surface is a closed, hardcoded set of FQDNs
  (Section 3). Plan / policy / operator configuration CANNOT
  redirect to an arbitrary endpoint. Misconfiguration is
  mechanically impossible.

- **G6 — In-memory token cache only.** Cached short-lived
  tokens never touch disk. The cache is per-`(proxy instance,
  exchange-key)` and evicted on proxy `Drop`.

- **G7 — Audit redaction discipline matches V2.** Every
  forwarded exchange, every cache hit, every cache refresh, and
  every denial emits a structured event through the existing
  `AuditSink`. NEVER carries access-key bytes, secrets,
  assertions, signed payloads, or response bodies.

### 1.2 Non-goals

- **NG1 — No broader credential surface.** V3 does NOT add new
  grant types beyond the three named (AWS `AssumeRole`, GCP
  JWT-bearer, Azure `client_credentials`). Workload Identity
  Federation, `AssumeRoleWithWebIdentity`, `device_code`,
  `refresh_token`, and `authorization_code` grants are out of
  scope and rejected at plan admission if declared.

- **NG2 — No raw upstream API proxying.** V3 forwards to the
  token-exchange endpoints only. The agent's subsequent calls
  to `s3.amazonaws.com`, `storage.googleapis.com`, or
  `management.azure.com` flow through the kernel-managed
  TProxy egress allowlist — same path as V2. The V3 proxy is
  a credential-issuance proxy, not an API gateway.

- **NG3 — No regional STS endpoint discovery.** AWS region is
  operator-declared (`region` field in the plan); V3 does
  NOT call `GetCallerIdentity` on the global endpoint to
  discover a default region.

- **NG4 — No disk-backed cache, no on-process restart cache
  warming.** Process restart = cache cold start = next request
  drives a fresh exchange. The trade-off is documented in
  `§4.3` (Spec invariant `INV-CLOUD-FWD-03`).

- **NG5 — No fallback to V2 emulator on V3 failure.** When
  `forwarding_enabled = true` and the upstream exchange
  fails AND the cache is empty (or expired), the proxy
  surfaces the upstream error to the in-VM client. It does
  NOT silently fall back to mirroring the long-lived
  credential — that would defeat the entire point of V3.

---

## 2. Per-provider exchange contracts

### 2.1 AWS — `sts:AssumeRole`

| Parameter | Source |
|---|---|
| `AWS_ACCESS_KEY_ID` | resolved from `CredentialBackend` via the decl's `credential_name` |
| `AWS_SECRET_ACCESS_KEY` | same |
| `AWS_SESSION_TOKEN` | optional, same |
| `RoleArn` | `[[tasks.credentials]].role_arn` (decl field) |
| `RoleSessionName` | `raxis-<session_id>-<unix_seconds>` (proxy-built) |
| `ExternalId` | optional, `[[tasks.credentials]].external_id` |
| `DurationSeconds` | decl `lease_seconds` (default `900`, max `43_200` enforced by AWS) |
| Endpoint host | `sts.amazonaws.com` (default) OR `sts.{region}.amazonaws.com` when `region` is declared |

**Wire shape (request).** `POST /` with
`Content-Type: application/x-www-form-urlencoded`, body:

```text
Action=AssumeRole
&Version=2011-06-15
&RoleArn=<urlencoded role_arn>
&RoleSessionName=<urlencoded session name>
&DurationSeconds=<lease_seconds>
&ExternalId=<urlencoded external_id, when declared>
```

SigV4-signed with the resolved long-lived IAM key. Service is
`sts`, region is the configured region (or `us-east-1` when
hitting the global `sts.amazonaws.com` endpoint).

**Wire shape (success response).** XML body:

```xml
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIA...</AccessKeyId>
      <SecretAccessKey>...</SecretAccessKey>
      <SessionToken>...</SessionToken>
      <Expiration>2026-05-12T15:00:00Z</Expiration>
    </Credentials>
    ...
  </AssumeRoleResult>
  ...
</AssumeRoleResponse>
```

**Translation to in-VM IMDS response.** The proxy parses the four
fields above and emits the V2 IMDS-compatible JSON envelope
(`AccessKeyId` / `SecretAccessKey` / `Token` / `Expiration` /
`RoleArn`) byte-identically to V2 — so the in-VM AWS SDK reads
the same shape regardless of V2 or V3 mode.

### 2.2 GCP — JWT-bearer grant

| Parameter | Source |
|---|---|
| Service-account JSON | resolved from `CredentialBackend` (PKCS#8 RSA private key + `client_email` + `token_uri`) |
| `iss` (JWT claim) | `client_email` from SA JSON |
| `aud` (JWT claim) | `https://oauth2.googleapis.com/token` |
| `scope` (JWT claim) | space-joined `restrictions.allowed_scopes` (REQUIRED non-empty when forwarding) |
| `iat` (JWT claim) | now() |
| `exp` (JWT claim) | now() + 3600 |
| Signing algorithm | RS256 (`RSASSA-PKCS1-v1_5` + SHA-256) over `b64url(header).b64url(claims)` |
| Endpoint | `https://oauth2.googleapis.com/token` |

**Wire shape (request).** `POST /` with
`Content-Type: application/x-www-form-urlencoded`, body:

```text
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&assertion=<signed JWT>
```

**Wire shape (success response).** JSON body:

```json
{ "access_token": "ya29....", "expires_in": 3599, "token_type": "Bearer" }
```

**Translation to in-VM metadata response.** Proxy emits the V2
metadata-server token shape on
`/computeMetadata/v1/instance/service-accounts/default/token`
byte-identically.

### 2.3 Azure — `client_credentials` grant

| Parameter | Source |
|---|---|
| `tenant_id` | `[[tasks.credentials]].tenant_id` (decl) |
| `client_id` | `[[tasks.credentials]].client_id` (decl) |
| `client_secret` | resolved from `CredentialBackend` (decl `credential_name`) |
| `scope` | `[[tasks.credentials]].scope` (decl, defaults to `<resource>/.default` at request time) |
| Endpoint | `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token` |

**Wire shape (request).** `POST` to the endpoint above, body:

```text
grant_type=client_credentials
&client_id=<urlencoded client_id>
&client_secret=<urlencoded client_secret>
&scope=<urlencoded scope>
```

**Wire shape (success response).** JSON body:

```json
{ "access_token": "eyJ0eXAi...", "expires_in": 3599, "token_type": "Bearer" }
```

**Translation to in-VM IMDS response.** Proxy emits the V2 IMDS
`/metadata/identity/oauth2/token` shape (stringified numeric
fields, `client_id` mirrored from decl, `resource` echoed from
the agent's `?resource=` query) byte-identically.

---

## 3. Egress contract

### 3.1 Closed allowlist

The shared HTTP client constructor in
`credential-proxy-cloud-shared` accepts upstream URLs only
when the URL's host (case-insensitive, trailing-dot tolerant,
no port stripping) matches ONE of:

| Provider | Allowlisted host pattern |
|---|---|
| AWS  | exactly `sts.amazonaws.com` OR matches `^sts\.[a-z0-9-]+\.amazonaws\.com$` |
| GCP  | exactly `oauth2.googleapis.com` |
| Azure | exactly `login.microsoftonline.com` |

The allowlist is a `const`-evaluable function in
`cloud-proxy-shared::allowlist`. It accepts a candidate URL,
parses it, validates scheme is `https`, validates host matches
one of the patterns above, and returns the validated `Url` or a
`UpstreamNotAllowed` error. The function is the ONLY constructor
for the type that the HTTP client accepts as its dispatch target.

Plan / policy CANNOT pass an alternative host. The allowlist
patterns are hardcoded. Adding a new pattern is a code change
that requires re-publishing.

### 3.2 TLS

- Mandatory TLS via `rustls` (workspace pin, no system OpenSSL).
- Default `rustls-native-certs` chain.
- No `accept_invalid_certs`, no `accept_invalid_hostnames`,
  no `danger_accept_invalid_certs` codepath, ever.

### 3.3 DNS

DNS resolution is performed by the underlying `reqwest`
client. The kernel's TProxy is not involved for the V3
forwarding sockets — they are kernel-process outbound
connections, not in-VM connections. They are still subject to
the closed-allowlist check at the proxy-construction layer (above
DNS).

---

## 4. Token caching & refresh

### 4.1 Cache key

The cache is keyed by `(provider, exchange_key)` where
`exchange_key` is provider-specific:

- AWS: `(role_arn, external_id, region)` — distinct role
  assumptions produce distinct cache entries.
- GCP: `(client_email, scope_set)` — distinct scope-sets
  produce distinct entries.
- Azure: `(tenant_id, client_id, scope, resource)` — distinct
  resource-or-scope produce distinct entries.

### 4.2 Lifetime

Each cache entry stores:

```yaml
CachedToken {
    token: String,           // SecretBox-wrapped, redacted on Debug
    expires_at_unix: u64,    // absolute, from upstream Expiration / expires_in
    refreshed_at_unix: u64,  // when this entry was minted
}
```

Plus the rendered in-VM response body bytes (the proxy can re-
serve the same bytes to multiple in-VM requests within the
safety window without re-rendering).

### 4.3 Refresh policy

- The cache `safety_window_ms` is configurable per plan
  (`cache_ttl_safety_window_ms`, default `300_000` = 5 min,
  minimum `60_000` = 1 min).
- When a request arrives and the cache holds a fresh entry
  (`now < expires_at - safety_window`), the proxy serves the
  cached token. Emits `CloudCredentialCacheHit`.
- When a request arrives and the cache holds an aging entry
  (`expires_at - safety_window <= now < expires_at`), the
  proxy **serves the cached token synchronously** AND spawns
  a background task to refresh the cache before the next
  request needs it. The in-VM client is NEVER blocked on a
  refresh. Emits `CloudCredentialCacheHit` (synchronous
  serve) plus `CloudCredentialCacheRefreshed` (when the
  background refresh completes).
- When a request arrives and the cache is empty or expired
  (`now >= expires_at`), the proxy drives a synchronous
  exchange. Emits `CloudCredentialForwarded` on success.
- A failed background refresh DOES NOT poison the cache: the
  prior-good token remains until its hard expiry. The next
  in-VM request then drives a synchronous refresh.
- The cache is `tokio::sync::RwLock<HashMap<CacheKey,
  CachedToken>>`. Reads acquire the read lock; refreshes
  acquire the write lock under a per-key in-flight semaphore
  so two refreshes for the same key never race.

### 4.4 Persistence

NEVER persisted. The cache lives in `Arc<TokenCache>`. On
`AwsProxy::drop` / `GcpProxy::drop` / `AzureProxy::drop` the
cache is reclaimed via normal `Arc` drop semantics — the
underlying `HashMap` zeroes its inner `String` storage as
`SecretBox` zeroizes on drop.

---

## 5. Audit event taxonomy

The V3 cloud-forwarding paths emit four new audit events in
addition to the existing V2 events (`AwsCredentialServed`,
`GcpMetadataServed`, `AzureTokenServed`). The new events are
internal-tagged `AuditEventKind` variants per the V2 wire
shape.

### 5.1 `CloudCredentialForwarded`

Emitted on every SUCCESSFUL synchronous OR background-refresh
exchange.

```yaml
CloudCredentialForwarded {
    session_id:       String,
    credential_name:  String,
    provider:         String,   // "aws" | "gcp" | "azure"
    exchange_kind:    String,   // "assume_role" | "jwt_bearer" | "client_credentials"
    upstream_host:    String,   // exact FQDN dialed
    outcome:          String,   // "success"
    latency_ms:       u32,
    status_code:      u16,
    response_bytes:   u32,      // size of upstream response (for traffic accounting)
    request_signed:   bool,     // true for SigV4 path; false for OAuth2 paths
}
```

### 5.2 `CloudCredentialForwardingDenied`

Emitted on every FAILED exchange (synchronous OR background).
The `reason` is a closed-enum stable wire string.

```yaml
CloudCredentialForwardingDenied {
    session_id:      String,
    credential_name: String,
    provider:        String,
    exchange_kind:   String,
    upstream_host:   String,
    reason:          String, // see closed enum below
    status_code:     u16,    // 0 if no HTTP response was received
    latency_ms:      u32,
}
```

**`reason` closed enum:**

- `"egress_allowlist"` — construction-time refusal (should never
  appear in practice since the allowlist is enforced at proxy
  bind; pinned here for completeness).
- `"missing_credential"` — `CredentialBackend::resolve` returned
  `NotFound` or returned a body that failed to parse.
- `"misconfigured"` — plan declared `forwarding_enabled` without
  the required fields (e.g. missing `role_arn` for AWS).
- `"upstream_4xx"` — upstream returned a 4xx with a well-formed
  error envelope. The envelope is forwarded to the in-VM client
  unchanged; this audit event captures the proxy-side view.
- `"upstream_5xx"` — upstream returned a 5xx.
- `"upstream_malformed"` — upstream returned a 2xx but the body
  failed to parse (missing `Credentials.AccessKeyId`, etc.).
- `"timeout"` — request exceeded the proxy's per-request
  deadline (default 15s).
- `"network"` — DNS / TCP / TLS error before the HTTP wire.

### 5.3 `CloudCredentialCacheHit`

Emitted on every in-VM request that the proxy serves from
cache. The synchronous-serve path during an aging-window
background refresh ALSO emits this (not a refresh event — the
refresh emits its own when it completes).

```yaml
CloudCredentialCacheHit {
    session_id:       String,
    credential_name:  String,
    provider:         String,
    exchange_kind:    String,
    age_ms:           u32,
    ttl_remaining_ms: u32,
}
```

### 5.4 `CloudCredentialCacheRefreshed`

Emitted when a background refresh successfully replaces a
cache entry. Pairs with the `CloudCredentialForwarded` event
the same exchange wrote.

```yaml
CloudCredentialCacheRefreshed {
    session_id:       String,
    credential_name:  String,
    provider:         String,
    exchange_kind:    String,
    prior_age_ms:     u32,
    new_ttl_ms:       u32,
}
```

### 5.5 Redaction rules

The audit-emission helper in
`cloud-proxy-shared::audit::emit_cloud_credential_forwarded`
is the ONLY path that emits these events. The helper:

- NEVER serializes `access_token`, `secret_access_key`,
  `session_token`, `client_secret`, `private_key`, or any
  raw upstream response body bytes.
- Logs `response_bytes` as a length, not as content.
- Renders `upstream_host` from the validated allowlist host
  (not from a raw URL string — no risk of partial-URL leak).

The V2 events (`AwsCredentialServed`, `GcpMetadataServed`,
`AzureTokenServed`) continue to be emitted on EVERY request
the proxy serves to the in-VM client, regardless of whether
the request was served from cache or from a fresh exchange.
V3 events are ADDITIONAL — they describe the upstream-facing
side of the same in-VM request.

---

## 6. Failure-mode contract

When the upstream exchange fails, the V3 proxy MUST surface
the upstream's canonical error envelope to the in-VM client
UNCHANGED. The in-VM client's existing error-handling path
therefore behaves identically to "talking to the real cloud".

### 6.1 AWS

Upstream 4xx with `<ErrorResponse>` body:

```xml
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>MissingAuthenticationToken</Code>
    <Message>...</Message>
  </Error>
  <RequestId>...</RequestId>
</ErrorResponse>
```

The proxy returns HTTP 403 (the AWS-canonical status for STS
auth failures) with the XML body unchanged. The `<Code>` value
is asserted to be in the closed enum the
`slice_aws_proxy_real_endpoint` witness pinned:

```text
MissingAuthenticationToken | InvalidClientTokenId
| SignatureDoesNotMatch    | AccessDenied
```

Plus the V3-additional values that may appear when forwarding
real (mis-)configured AssumeRole calls:

```text
AccessDenied | ExpiredToken | ValidationError
| MalformedPolicyDocument
```

An unknown `<Code>` value triggers `upstream_malformed` and
the proxy emits a synthetic
`<Code>UpstreamUnknown</Code>` envelope to the in-VM client
so SDKs that pattern-match on `<Code>` still see a closed
enum. **Fail-closed**: never silently translate an unknown
upstream error to a known one.

### 6.2 GCP

Upstream 4xx with RFC 6749 §5.2 JSON body:

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid JWT: ..."
}
```

The proxy returns HTTP 400 with the JSON body unchanged. The
`error` field is asserted to be in the RFC 6749 §5.2 closed
enum the `slice_gcp_proxy_real_endpoint` witness pinned:

```text
invalid_request | invalid_client | invalid_grant
| unauthorized_client | unsupported_grant_type | invalid_scope
```

Unknown values trigger `upstream_malformed` and a synthetic
`{"error": "upstream_unknown", "error_description": "..."}`.

### 6.3 Azure

Upstream 4xx with AAD-flavored RFC 6749 JSON body:

```json
{
  "error": "invalid_client",
  "error_description": "AADSTS7000215: ...",
  "error_codes": [7000215],
  "correlation_id": "..."
}
```

The proxy returns HTTP 400 with the JSON body unchanged. The
`error` field is asserted to be in the RFC 6749 §5.2 closed
enum the `slice_azure_proxy_real_endpoint` witness pinned;
the proxy ALSO asserts `error_codes` is a non-empty JSON array
of integers (pinned by the witness slice).

Unknown values trigger `upstream_malformed` and a synthetic
`{"error": "upstream_unknown", "error_description": "...",
"error_codes": [0]}`.

### 6.4 The 5xx path

Upstream 5xx is NEVER surfaced as a fresh 5xx envelope to the
in-VM client — that would invite the agent's SDK to retry
indefinitely, hammering the real STS / OAuth2 endpoint. The
proxy:

1. Emits `CloudCredentialForwardingDenied{reason:"upstream_5xx"}`.
2. If the cache holds a still-valid (pre-hard-expiry) token,
   serves it. This is the "stale-while-error" fallback.
3. Otherwise returns a synthetic 503 to the in-VM client with
   the provider-canonical error envelope shape (e.g. AWS
   `<Code>ServiceUnavailable</Code>`).

---

## 7. Plan / policy surface

V3 extends the per-provider `ProxyDecl` variants in
`raxis-plan-credentials` with **OPT-IN** forwarding fields.
Defaults preserve V2 emulator behavior bit-identically.

### 7.1 AWS

```toml
[[tasks.credentials]]
name           = "aws-prod"
proxy_type     = "aws"
mount_as       = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
role_arn       = "arn:aws:iam::123456789:role/raxis-prod-agent"

# --- V3 forwarding (opt-in) ---
forwarding_enabled = true        # default false; when false, V2 emulator behavior.
exchange_region    = "us-east-1" # optional; defaults to global "sts.amazonaws.com".
external_id        = "..."       # optional, mirrored to STS as ExternalId.
lease_seconds      = 900         # used as STS DurationSeconds (clamped 900..=43200).
cache_ttl_safety_window_ms = 300000  # optional; default 300000, min 60000.

[tasks.credentials.restrictions]
# unchanged from V2.
```

**Validation rules** (enforced at plan admission):

- `forwarding_enabled = true` REQUIRES `role_arn` (already
  required at the AWS-decl shape, surfacing of this is
  unchanged; the validator hardens it to a hard error when
  forwarding is on).
- `exchange_region`, when present, MUST match the AWS region
  pattern (`^[a-z0-9-]+$`); the resulting endpoint host MUST
  pass the cloud-shared allowlist check.
- `lease_seconds` MUST be in `[900, 43200]` per AWS STS docs.

### 7.2 GCP

```toml
[[tasks.credentials]]
name           = "gcp-prod"
proxy_type     = "gcp"
mount_as       = "GCP_METADATA_HOST"
project        = "my-prod-project"

# --- V3 forwarding (opt-in) ---
forwarding_enabled = true
cache_ttl_safety_window_ms = 300000

[tasks.credentials.restrictions]
allowed_scopes = [
    "https://www.googleapis.com/auth/cloud-platform",
]
```

The decl's `credential_name` MUST resolve to a service-account
JSON body (with `private_key`, `client_email`, `token_uri`)
when forwarding is enabled. V2 expected a long-lived access
token in the body; V3 expects the full SA JSON. The proxy
parses both and chooses the path based on `forwarding_enabled`.

**Validation rules:**

- `forwarding_enabled = true` REQUIRES non-empty
  `restrictions.allowed_scopes`. (GCP's JWT-bearer grant
  REQUIRES a `scope` claim — without scopes, the upstream
  rejects with `invalid_scope` immediately.)
- The decl's `token_uri` (when present in the SA JSON) is
  IGNORED — V3 always dials `oauth2.googleapis.com`.

### 7.3 Azure

```toml
[[tasks.credentials]]
name      = "azure-prod"
proxy_type = "azure"
mount_as  = "AZURE_CLIENT_SECRET"
tenant_id = "11111111-2222-3333-4444-555555555555"
client_id = "66666666-7777-8888-9999-aaaaaaaaaaaa"

# --- V3 forwarding (opt-in) ---
forwarding_enabled = true
exchange_scope     = "https://management.azure.com/.default"
cache_ttl_safety_window_ms = 300000

[tasks.credentials.restrictions]
allowed_resources = ["https://management.azure.com/"]
```

The decl's `credential_name` MUST resolve to a body containing
`AZURE_CLIENT_SECRET` (env-style) or `client_secret` (JSON)
when forwarding is enabled.

**Validation rules:**

- `forwarding_enabled = true` REQUIRES `tenant_id`, `client_id`,
  and a non-empty `restrictions.allowed_resources` (so the
  agent can't ask for a token outside the declared resource
  set).
- `exchange_scope` defaults to `<resource>/.default` at
  request time, derived from the agent's `?resource=` query.

---

## 8. Migration path

V3 forwarding is opt-in per credential. A plan can:

- Stay fully on V2: every `[[tasks.credentials]]` keeps the
  existing fields, `forwarding_enabled` defaults to `false`,
  the proxy emits synthetic responses from the long-lived
  credential. Behavior is byte-identical to pre-V3.
- Migrate one credential to V3: that one decl adds
  `forwarding_enabled = true` and the required provider-
  specific fields. The proxy switches to upstream exchange
  for that decl ONLY. Sibling decls in the same task remain
  on V2 unchanged.
- Migrate all of them: each decl independently adds
  `forwarding_enabled = true`.

The witness slices (`slice_{aws,gcp,azure}_proxy_real_endpoint`)
gate the V3 path on BOTH `RAXIS_LIVE_CLOUD_NET=1`
AND `RAXIS_V3_CLOUD_FORWARDING=1`. The V2 paths (where the
slice dials `reqwest` directly against the real endpoint to
pin the canonical error shape) remain gated on
`RAXIS_LIVE_CLOUD_NET=1` ALONE — so existing V2 CI behavior
is unchanged.

---

## 9. Test surface

### 9.1 Unit tests (per crate)

- **`cloud-proxy-shared`**:
  - Allowlist construction: accept `sts.amazonaws.com`,
    accept `sts.us-east-1.amazonaws.com`, accept
    `oauth2.googleapis.com`, accept
    `login.microsoftonline.com`. Reject every other host
    (e.g. `evil.com`, `sts.amazonaws.com.evil.com`,
    `attacker.sts.amazonaws.com`).
  - Trailing-dot tolerance: `oauth2.googleapis.com.` is
    accepted; case-insensitive: `OAUTH2.GOOGLEAPIS.COM` is
    accepted.
  - Scheme validation: `http://` is rejected; only `https://`.
  - Token cache: TTL math, safety-window math, background-
    refresh inflight-dedupe.

- **`credential-proxy-aws`**:
  - SigV4 known-vector test (AWS-published sample request).
  - `<ErrorResponse>` envelope round-trip (parse, validate,
    re-render unchanged).
  - Cache TTL behavior (cold path → hit path → aging path →
    expired path).
  - Forwarding-disabled fallback: bit-identical V2 response.

- **`credential-proxy-gcp`**:
  - JWT assertion construction (header.body bytes deterministic
    given a fixed `iat`/`exp`).
  - RS256 signature against a known PEM-encoded RSA key
    (synthetic test key, not a real GCP SA key).
  - OAuth2 error envelope round-trip.

- **`credential-proxy-azure`**:
  - Form-encoding (URL-encode special chars in
    `client_secret`, multi-segment `scope`).
  - AAD error envelope round-trip (including `error_codes`
    array preservation).

### 9.2 Integration tests (live-e2e slices)

`slice_aws_proxy_real_endpoint.rs`,
`slice_gcp_proxy_real_endpoint.rs`,
`slice_azure_proxy_real_endpoint.rs`:

1. **V2 path (existing).** Gated on `RAXIS_LIVE_CLOUD_NET=1`.
   Direct `reqwest` to upstream, pin canonical error
   envelope. UNCHANGED from current.
2. **V3 path (new).** Gated on `RAXIS_LIVE_CLOUD_NET=1` AND
   `RAXIS_V3_CLOUD_FORWARDING=1` AND provider-specific
   credential env vars (skip with clear message if missing).
   Boots the proxy in `forwarding_enabled` mode, drives a
   real exchange through it, asserts:
   - HTTP 200 from the proxy to the in-VM client with a
     well-formed token envelope.
   - `CloudCredentialForwarded` was emitted exactly once.
   - Second call within the safety window emits
     `CloudCredentialCacheHit` (cache works).
   - Intentional bad-credential variant emits
     `CloudCredentialForwardingDenied` AND surfaces the
     upstream's canonical error envelope unchanged.
   - No credential prefix (`AKIA`, `ASIA`, `ya29.`,
     `service_account`, `private_key`, JWT-shaped
     substrings) appears in any audit event payload.

### 9.3 Negative tests

- `forwarding_enabled = false` → proxy serves V2 emulator;
  V3 audit events absent.
- `forwarding_enabled = true` + missing credential ref →
  `CloudCredentialForwardingDenied{reason:"missing_credential"}`.
- Egress-allowlist bypass attempt: NOT TESTABLE at runtime
  because the allowlist is constructor-enforced; we test it
  at the type-system layer instead (a unit test that tries
  to construct the HTTP client with a bad host and asserts a
  compile-time-shaped runtime error).
- Upstream 5xx with cache miss →
  `CloudCredentialForwardingDenied{reason:"upstream_5xx"}` +
  synthetic `503 ServiceUnavailable`.
- Upstream 5xx with cache hit → cache hit served, audit
  event still emitted (operator visibility into 5xx
  background storm).

---

## 10. Invariants checklist

The implementation MUST preserve every invariant below. Tests
for each invariant live in the named crate / slice.

| ID | Invariant | Enforced by |
|---|---|---|
| INV-CLOUD-FWD-01 | No upstream egress to anything outside the closed allowlist. | `cloud-proxy-shared::allowlist` constructor + `tests/allowlist_rejects.rs` |
| INV-CLOUD-FWD-02 | No credential material in audit events or logs. | `cloud-proxy-shared::audit::emit_cloud_credential_forwarded` + `tests/redaction_pins.rs` |
| INV-CLOUD-FWD-03 | Token cache never persists to disk. | Code review (no FS dep in `cloud-proxy-shared::cache`); witness `tests/cache_in_memory_only.rs` (negative — asserts no file under `<data_dir>/credential_proxy_cache/`). |
| INV-CLOUD-FWD-04 | `forwarding_enabled = false` plans behave bit-identically to V2. | Per-crate `tests/v2_fallback_unchanged.rs` |
| INV-CLOUD-FWD-05 | Upstream error shapes preserved unchanged to the in-VM client. | Per-crate `tests/error_envelope_passthrough.rs` |
| INV-CLOUD-FWD-06 | Cache refresh is asynchronous; in-VM client never blocked on refresh. | `cloud-proxy-shared::cache::serve_with_async_refresh` + `tests/cache_async.rs` |
| INV-CLOUD-FWD-07 | All forwarding paths emit audit events. | `tests/audit_emission_charter.rs` |
| INV-CLOUD-FWD-08 | Failed exchanges do not poison the cache (last-good token preserved if still valid). | `tests/cache_failed_refresh_preserves_prior.rs` |

---

## 11. Observability

Each forwarding path bumps the V3 cloud-proxy metric family
documented in `specs/v3/observability-prometheus.md §3.5`:

- `raxis.credential_proxy.statement.duration{service=<provider>,
   operation=<exchange_kind>, outcome=<success|failure>}` —
  histogram of upstream-exchange latency.
- `raxis.credential_proxy.statement.duration{..., operation="cache_hit"}` —
  cache-hit served path (latency dominated by per-request
  rendering, not network).
- `raxis.credential_proxy.policy_block.total{service=<provider>,
   reason=<forwarding_denied_reason>}` — counter of denied
  exchanges keyed by the closed reason enum (§5.2).

No new metric names are introduced — V3 reuses the existing
`raxis.credential_proxy.*` family with new attribute values.

---

## 12. Open questions deferred to a follow-up spec

- **Workload Identity Federation (GCP) / Web Identity (AWS)**:
  out of scope; deferred to a future V3.x spec when the
  operator-cert-signed JWT story crystallises.
- **Refresh token / device-code flows**: out of scope; the
  agent's UX never benefits from human-interactive grants.
- **Multi-tenant credential rotation under cache pressure**:
  the cache is per-`exchange-key`, so a key-rotation event
  in `CredentialBackend` does not automatically invalidate
  the cached token. A future spec will introduce a
  `cache_purge_on_credential_rotated` hook; until then, the
  operator manually restarts the proxy via plan-epoch advance
  to force a cold cache.
