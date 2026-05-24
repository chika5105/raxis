# Scenario 37 — S3 / AWS Credential Proxy

> **Complexity:** ⭐⭐⭐⭐ Expert | **Wall clock:** ~15 min | **Provider:** Anthropic

The Executor calls AWS APIs through the V2 AWS credential proxy.
The proxy serves an IMDS-shaped JSON envelope at
`AWS_CONTAINER_CREDENTIALS_FULL_URI` (the URL is what the kernel
sets in the agent VM's env). The agent never sees the access key
or the secret access key — they live on disk under
`$RAXIS_DATA_DIR/credentials/<name>.env` (mode 0600), behind the
`CredentialBackend` trait, and the proxy looks them up per-
request so a rotation lands at the next SDK refresh window.

> **Note (V2 status):** The AWS proxy is implemented (see
> `crates/credential-proxy-aws/`). The proxy issues synthetic
> IAM credential JSON envelopes from the long-lived IAM key the
> operator stores in the credential backend; real
> `sts:AssumeRole` round-trips against `sts.amazonaws.com` are
> the V3 patch.

---

## Prerequisites

Same as scenario 04. An AWS access-key pair seeded under the
operator's data dir:

```bash
install -d -m 700 "$RAXIS_DATA_DIR/credentials"
cat > "$RAXIS_DATA_DIR/credentials/aws_main.env" <<'EOF'
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=                 # optional, for STS keys
EOF
chmod 600 "$RAXIS_DATA_DIR/credentials/aws_main.env"
```

The proxy parses both env-style (this file) and JSON
(`{ "AccessKeyId": "...", "SecretAccessKey": "...", "Token": "..." }`)
credential bodies, so paste whichever format your secret store
emits.

---

## What this scenario demonstrates

* `[[tasks.credentials]]` with `proxy_type = "aws"`,
  `mount_as = "AWS_CONTAINER_CREDENTIALS_FULL_URI"`, and an
  optional `lease_seconds` (default 900s).
* The proxy enforces a path allowlist (default `["/creds"]`) —
  any other GET returns `403 Forbidden`.
* The agent VM gets `AWS_CONTAINER_CREDENTIALS_FULL_URI` set
  to the loopback URL of the proxy. `boto3`, `aws-sdk-rust`,
  and Terraform's AWS provider all dial that URL automatically
  when the env var is set.
* Audit emission: `AwsCredentialServed { path, path_sha256,
  role_arn, blocked }` per request.
* On `CredentialProxyStopped`, the kernel ships the counter
  snapshot (`connections_served`, `credentials_served`,
  `requests_blocked`, `bytes_served`).

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```

The agent's `boto3` (or `aws s3 cp`) call inside the Executor's
VM will resolve credentials from
`AWS_CONTAINER_CREDENTIALS_FULL_URI` — no `~/.aws/credentials`
file, no `AWS_ACCESS_KEY_ID` in the agent's env.

---

## Verifying the audit trail

```bash
raxis audit dump --kind AwsCredentialServed --json | head -1
# {"event_kind":"AwsCredentialServed","payload":{
#   "credential_name":"aws_main",
#   "path":"/creds","path_sha256":"…",
#   "role_arn":"arn:aws:iam::…","blocked":false}}
```

Run the live-e2e harness for a wire-level assertion the
canonical envelope is shaped exactly like the AWS container-
credential provider:

```bash
cargo run -p raxis-live-e2e -- aws-proxy
```

---

## Variations

* **Tighten the path allowlist.** Set
  `restrictions.allowed_paths = ["/creds"]` (the default) so
  the proxy rejects any other path. The deny-path increments
  `requests_blocked` and emits a `blocked = true` audit event.
* **Use the AWS Lambda Container Image extension** (`/2018-03-12/runtime/...`)
  with a custom path allowlist. Add the path to
  `restrictions.allowed_paths`.
* **GCP equivalent.** Scenario 38 uses the GCP metadata-server
  shape on `/computeMetadata/v1/...`. Switch
  `proxy_type = "gcp"` and the metadata-server contract takes
  over, including `Metadata-Flavor: Google` enforcement.
