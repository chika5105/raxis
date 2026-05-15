# V3 Cloud-Proxy Forwarding — operator recipe

Normative spec: `specs/v3/cloud-proxy-forwarding.md`.

This document is the **operator-facing** recipe for moving a plan
from the V2 cloud-proxy emulator path to the V3 upstream-forwarding
path. It pins the TOML shape, the credential-backend contract, the
egress-allowlist surface, the rollout knobs, and the rollback
procedure. It is deliberately *not* the spec — it is the working
playbook for an operator standing this up against a real AWS / GCP /
Azure account.

## 1. When to opt in

Default V2 emulator behaviour:

* `[[tasks.credentials]]` block declares `proxy_type = "aws" | "gcp" | "azure"`.
* Operator stores a long-lived IAM key / GCP OAuth2 access token /
  Azure access token in the credential backend.
* The proxy mirrors the long-lived credential to the in-VM SDK.
* Suitable for early experimentation against staging accounts where
  the operator is comfortable rotating the long-lived token
  out-of-band.

V3 forwarding behaviour:

* Operator stores **long-lived issuance material** in the credential
  backend (an IAM key with `sts:AssumeRole` permission, a
  service-account JSON private key, or a service-principal client
  secret).
* On every cache miss the proxy exchanges the long-lived material
  for a **short-lived, scope-narrowed** credential via the real cloud
  control plane and serves THAT to the in-VM SDK. The long-lived
  material never leaves the proxy.
* Required when:
  * The task uses an IAM role assumed via `ExternalId` (only AWS STS
    can issue this; an emulated mirror would not satisfy a
    requester-pays bucket).
  * The plan declares an `allowed_actions` ARM filter that needs
    AAD-side enforcement of scoped tokens.
  * The operator wants short TTLs (< 1 hour) without
    pre-staging refreshed tokens.

Co-existence: V2 and V3 paths can run side-by-side in the same kernel
build. Whether a given credential uses V3 is purely a per-decl flag.

## 2. Plan TOML — minimal V3 example

Same plan that drove a V2 proxy, with one added block per cloud
credential:

```toml
[[tasks]]
task_id = "deploy-aws-staging"

  [[tasks.credentials]]
  name           = "aws-staging"
  proxy_type     = "aws"
  mount_as       = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
  role_arn       = "arn:aws:iam::123456789012:role/raxis-staging-agent"
  lease_seconds  = 900

    # V3 forwarding — the only NEW block.
    [tasks.credentials.forwarding]
    enabled                     = true
    region                      = "us-east-1"
    endpoint_kind               = "global"   # or "regional"
    external_id                 = "raxis-staging-trust-policy-cookie"
    duration_seconds            = 900        # 900..=43_200
    cache_safety_window_seconds = 300        # ≥ 60
```

```toml
[[tasks]]
task_id = "deploy-gcp-staging"

  [[tasks.credentials]]
  name       = "gcp-staging"
  proxy_type = "gcp"
  mount_as   = "GOOGLE_APPLICATION_CREDENTIALS"
  project    = "raxis-staging"

    [tasks.credentials.forwarding]
    enabled                     = true
    scopes = [
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/cloud-platform.read-only",
    ]
    jwt_lifetime_seconds        = 3600       # ≤ 3600
    cache_safety_window_seconds = 300        # ≥ 60

    [tasks.credentials.restrictions]
    allowed_scopes = [
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/cloud-platform.read-only",
    ]
```

```toml
[[tasks]]
task_id = "deploy-azure-staging"

  [[tasks.credentials]]
  name       = "azure-staging"
  proxy_type = "azure"
  mount_as   = "AZURE_TOKEN_URL"
  tenant_id  = "00000000-1111-2222-3333-444444444444"

    [tasks.credentials.forwarding]
    enabled                     = true
    cache_safety_window_seconds = 300        # ≥ 60

    [tasks.credentials.restrictions]
    allowed_resources = ["https://management.azure.com/"]
```

## 3. Credential-backend contract

The operator stores **different bytes** for V2 vs V3.

### AWS

V2 (long-lived IAM key, env-style or JSON):

```bash
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
```

V3 (same shape — V3 reads the long-lived key, signs SigV4, and dials
STS):

```bash
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
```

No `AWS_SESSION_TOKEN`: V3 mints its own session by exchanging the
long-lived key for short-lived STS credentials.

### GCP

V2 (long-lived OAuth2 access token):

```json
{ "access_token": "ya29...", "client_email": "..." }
```

V3 (full service-account JSON key — the same shape `gcloud iam
service-accounts keys create` emits):

```json
{
  "type":             "service_account",
  "project_id":       "raxis-staging",
  "private_key_id":   "abc123...",
  "private_key":      "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n",
  "client_email":     "raxis-staging@raxis-staging.iam.gserviceaccount.com",
  "client_id":        "...",
  "auth_uri":         "https://accounts.google.com/o/oauth2/auth",
  "token_uri":        "https://oauth2.googleapis.com/token",
  ...
}
```

`token_uri` is parsed but ignored — the upstream is allowlist-pinned.
`private_key` MUST be PKCS#8 PEM-encoded RSA.

### Azure

V2 (long-lived bearer token):

```bash
AZURE_ACCESS_TOKEN=eyJ0eXAi...
```

V3 (service-principal client credential — env-style or JSON,
`az ad sp create-for-rbac` shape):

```bash
AZURE_TENANT_ID=tttt-tttt-tttt-tttt
AZURE_CLIENT_ID=cccc-cccc-cccc-cccc
AZURE_CLIENT_SECRET=opaque-secret-bytes
```

Or equivalently:

```json
{
  "appId":    "cccc-cccc-cccc-cccc",
  "password": "opaque-secret-bytes",
  "tenant":   "tttt-tttt-tttt-tttt",
  "tenantId": "tttt-tttt-tttt-tttt"
}
```

## 4. Egress-allowlist surface

V3 forwarding adds construction-time-enforced outbound HTTPS to the
following hosts (one per provider in use):

* AWS — `sts.amazonaws.com` (global) OR `sts.{region}.amazonaws.com`
  (regional).
* GCP — `oauth2.googleapis.com`.
* Azure — `login.microsoftonline.com`.

The host set is hard-coded in
`raxis-credential-proxy-cloud-shared::allowlist`. A plan that
declares `endpoint_kind = "regional"` with a region not on the AWS
public-region list fails at session start with
`ManagerError::CloudForwardingConfig`. Operators wiring egress
firewalls / cloud-NAT egress allowlists must permit these FQDNs on
TCP/443 from the kernel host.

## 5. Rollout knobs

In priority order:

1. **Per-decl flag** — `[tasks.credentials.forwarding].enabled =
   false` disables V3 for one credential, leaving others unchanged.
   Default `true` when the `[forwarding]` block is present at all
   (so operators can't accidentally declare V3 metadata while
   running V2 emulation).
2. **`cache_safety_window_seconds`** — bump up (e.g. 600 s) during
   incident recovery so any in-flight tokens stay served past their
   normal refresh window; bump down (e.g. 60 s) during routine ops
   to force tight refresh cycles.
3. **`duration_seconds` (AWS only)** — AssumeRole `DurationSeconds`.
   The plan field is clamped to 900..=43_200 per AWS spec; an
   IAM-role-side `MaxSessionDuration` smaller than the plan value
   wins (STS rejects, the proxy mirrors the 4xx envelope).
4. **`jwt_lifetime_seconds` (GCP only)** — JWT `exp - iat` window.
   The proxy clamps to 60..=3600 (Google's hard ceiling).

## 6. Audit chain — what changes

V2 emits one event per request: `AwsCredentialServed` /
`GcpMetadataServed` / `AzureTokenServed`. V3 ADDS four event kinds,
emitted at distinct flow points:

| Event                                  | Fires when                                                                              |
|----------------------------------------|------------------------------------------------------------------------------------------|
| `CloudCredentialForwarded`             | The proxy minted a fresh token from the upstream (cold-path or refresh).                |
| `CloudCredentialForwardingDenied`      | The upstream rejected the exchange, or the proxy refused to dial (allowlist / config).  |
| `CloudCredentialCacheHit`              | The proxy served the in-VM SDK from cache without dialling the upstream.                |
| `CloudCredentialCacheRefreshed`        | Aging-window background refresh succeeded; old cache entry was atomically replaced.     |

The per-request V2 event still fires on success so an existing audit
query that joins on `AwsCredentialServed` continues to see the same
shape. When V3 surfaces an upstream 4xx the V2 event is **omitted**
(no credential was served), and only `CloudCredentialForwardingDenied`
appears.

## 7. Rollback

To roll back a single credential from V3 to V2:

* Set `enabled = false` (or delete the `[tasks.credentials.forwarding]`
  block entirely) in the plan TOML.
* Replace the V3-shape credential body (service-account JSON,
  service-principal env) with the V2-shape body (long-lived OAuth2
  access token, IAM key with valid session token, etc.) in the
  credential backend.
* Restart the affected session(s). The kernel proxy manager rebinds
  the proxy on session start, so a live session keeps its prior V3
  proxy until the session ends.

No data migration is needed — the V3 work is binary-compatible with
V2 plans that don't declare `[forwarding]`.

## 8. Verification — what to look for

After enabling V3 on a staging credential:

1. **Cold-path latency.** First request to the proxy after kernel
   restart should take 200-800 ms (TLS handshake + upstream call).
2. **Warm-path latency.** Subsequent requests inside the cache window
   should take < 5 ms — they're pure in-memory dict lookups.
3. **Audit chain.** `audit list --kind CloudCredentialForwarded`
   should show one event per cold-path mint plus one per
   `CloudCredentialCacheRefreshed` per aging-window crossing. No
   `CloudCredentialForwardingDenied` unless the operator is
   intentionally testing a failure path.
4. **Egress observability.** The Prometheus exporter surfaces
   `raxis_cloud_forwarding_requests_total{provider, outcome}` and
   `raxis_cloud_forwarding_cache_hits_total{provider}`. The
   `outcome` label takes `{success, denied, malformed, timeout}`.

If the steady-state hit-rate is < 80 %, the cache safety window is
probably too aggressive — bump `cache_safety_window_seconds`.

## 9. Known limitations

* Workload Identity Federation (GCP / Azure cross-cloud trust) is
  NOT supported in V3. Operators still need long-lived issuance
  material in the credential backend.
* The shared `CloudHttpClient` does not support custom
  `proxy` / `no_proxy` environment variables — outbound HTTPS is
  point-to-point.
* The V3 token cache is in-process. Cross-process or cross-host
  sharing would require an external store; not in scope for this
  release.
