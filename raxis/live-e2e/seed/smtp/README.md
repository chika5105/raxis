# `live-e2e/seed/smtp/` — Docker Mailserver bootstrap

Read-only configuration files mounted into the SMTP service from
`docker-compose.e2e.yml` / `docker-compose.extended.e2e.yml`.

## Files

| Path | Purpose |
|---|---|
| `postfix-accounts.cf` | The single test mailbox the live-e2e SMTP slice authenticates as and delivers into. Format: `<email>\|{SCHEME}<password>`. We use `{PLAIN}` for test simplicity — production deployments should use `{SHA512-CRYPT}` or `{BCRYPT}`. |
| `postfix-virtual.cf` | Aliases routing `rcpt-a@live-e2e.test` and `rcpt-b@live-e2e.test` into the single `raxis-tenant@live-e2e.test` mailbox so the slice can drive a multi-recipient envelope without provisioning multiple users. |

## Why this lives in seeds, not in compose env vars

`docker-mailserver` reads its mailbox catalog from
`/tmp/docker-mailserver/postfix-accounts.cf` and aliases from
`/tmp/docker-mailserver/postfix-virtual.cf`. Neither has an
environment-variable equivalent: bind-mounting these files at the
canonical paths is the supported way to pre-bake users at first
boot. The `{PLAIN}` scheme keeps the test fixture readable and
removes the need for the build to run `doveadm pw` to compute a
hash at compose-up time.

## How the slice consumes this

`live-e2e/src/slice_smtp_proxy.rs` connects through the real
`SmtpProxy` to the mailserver, sends a single envelope, and
verifies delivery by reading the message back from the
`Maildir/new/` directory in the SMTP container via `docker exec`.
The slice asserts:

  * the proxy successfully authenticated to the real Postfix server
    using the credential the kernel resolved (otherwise the message
    would not have been delivered);
  * `MAIL FROM`, every `RCPT TO`, and the DATA body landed in the
    mailbox verbatim (modulo Postfix's `Received:` header and
    any virtual-alias rewriting).
