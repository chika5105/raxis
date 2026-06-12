# `raxis/live-e2e/examples/` — checked-in mirror of the live-e2e harness run

## Purpose

This directory is a checked-in mirror of what the realistic-scenario
live-e2e harness
(`kernel/tests/extended_e2e_realistic_scenario.rs`, the
`realistic_session_lifecycle` test) writes into its per-run
tmpdir at bootstrap. It is **reference documentation, not
runtime input**: nothing in the kernel reads from this directory.
The point is to let an operator answer
"what `policy.toml` / `plan.toml` / credential files produced
the latest live-e2e iter?" without having to re-run the test or
reconstruct it from the Rust constants.

Files mirrored:

| File / dir                                | Source in the harness                                                                                                                                                                                  |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `policy.toml`                             | `<data_dir>/policy/policy.toml` after `enable_gateway_in_policy` runs (bootstrap + harness overlay).                                                                                                    |
| `plan_primary.toml`                       | `realistic_plan_toml()` in `extended_e2e_support::plan_realistic`. The primary initiative (materializer + xfile-refactor + lint-defect/lint-runner/reviewer fan-out + allowlist + service/proxy/credential/egress/tooling evidence). |
| `plan_sibling.toml`                       | `sibling_plan_toml()` in `extended_e2e_support::multi_initiative`. The 1-task sibling initiative (`sibling-materialize-records`).                                                                       |
| `credentials/test-pg-dev.env`             | `write_credentials` — libpq URL for the local docker-compose Postgres at `127.0.0.1:54399`.                                                                                                             |
| `credentials/test-mongo-dev.env`          | `write_credentials` — mongo URI for the local docker-compose MongoDB at `127.0.0.1:27399`.                                                                                                              |
| `credentials/test-redis-dev.env`          | `write_credentials` — single-line `--requirepass` value for the local docker-compose Redis at `127.0.0.1:63799`.                                                                                        |
| `credentials/test-smtp-dev.env`           | `write_credentials` — raw SASL secret for the local docker-mailserver at `127.0.0.1:25199`.                                                                                                             |
| `credentials/anthropic.env.placeholder`   | **Hardcoded template (NEVER copied from the live credential).** Documents the Anthropic key shape; the real key MUST NEVER be checked in.                                                              |
| `credentials/gemini.env.placeholder`      | **Hardcoded template (NEVER copied from the live credential).** Documents the Gemini key shape; the real key MUST NEVER be checked in.                                                                 |
| `credentials/openai.env.placeholder`      | **Hardcoded template (NEVER copied from the live credential).** Documents the OpenAI key shape; the real key MUST NEVER be checked in.                                                                 |
| `seed/prompts/*`                          | Verbatim mirror of `raxis/live-e2e/seed/prompts/` — the per-task prompt markdown files the realistic plan embeds into `[[tasks]].prompt`. Mirrored so the bundle is a complete reproducible picture. |

> **The example bundle is the same shape as the live tmpdir.**
> Drop into any kernel data_dir, copy `policy.toml` to
> `<data_dir>/policy/policy.toml`, copy `credentials/*.env` to
> `<data_dir>/credentials/`, write synthetic provider creds files
> under `<data_dir>/providers/*-realism-e2e.toml`, and the
> kernel will boot in the same shape the live-e2e harness boots
> in. (This is not an end-to-end test, just a fidelity check.)

## Refresh contract

The harness auto-writes these files **only when
`RAXIS_E2E_REFRESH_EXAMPLES=1` is set**. Default-off so casual
`cargo test -p raxis-kernel --test extended_e2e_realistic_scenario`
runs don't dirty the worktree.

The fix-loop / CI / a working-e2e commit MUST set the env var
before the run that lands the `working e2e` commit so the
checked-in examples always match the most recent passing iter:

```bash
# requires raxis/.env with ANTHROPIC-API-DEV-KEY,
# GEMINI-API-DEV-KEY, and OPEN-AI-API-DEV-KEY
# executor primaries rotate across those three providers and keep
# the other two as fallback models
# provider pricing overrides are intentionally omitted from the
# default realism policy so the primary run exercises non-override
# pricing provenance
RAXIS_LIVE_E2E=1 RAXIS_LIVE_E2E_REALISTIC=1 \
  RAXIS_E2E_REFRESH_EXAMPLES=1 \
  cargo test -p raxis-kernel \
    --test extended_e2e_realistic_scenario -- --nocapture
```

After a green run, `git status` will show the diff under
`raxis/live-e2e/examples/`. Commit the diff alongside whatever
fix landed in the same iter. Recommended commit-message
convention:

```text
live-e2e(examples): refresh from <iter_label> (initiative <primary_id_8> + <sibling_id_8>)
```

(The initiative ids show up in the harness stderr as
`[realism-e2e] primary plan submitted, initiative_id=...` —
truncated to the first 8 chars for the commit subject so the
title stays readable.)

### Where the auto-refresh runs

The refresh hook lives in `kernel_driver.rs::maybe_refresh_examples`
(see [`kernel/tests/extended_e2e_support/kernel_driver.rs`](../../kernel/tests/extended_e2e_support/kernel_driver.rs)).
It is invoked from the realistic-scenario test driver **after**
the plan TOMLs are assembled but **before** the kernel daemon
starts — so a refresh failure short-circuits the whole iter,
not just the post-run reporting block. A half-baked examples
diff can never land.

The hook also runs from a unit test
(`kernel_driver::tests::refresh_examples_writes_plan_and_credentials_under_env_gate`)
that exercises the refresh path against a tmpdir fixture; the
unit test runs on every `cargo test -p raxis-kernel` so a
regression in the refresh shape surfaces immediately, no live
docker stack required.

## Provider credential rule (NON-NEGOTIABLE)

The provider placeholder files in `credentials/` document the local
development shapes for Anthropic, Gemini, and OpenAI. Real provider
API keys MUST NEVER be checked into this directory or any other
directory in the repo. The Anthropic shape is currently enforced
**three** ways because its key prefix is stable enough for a reliable
repo-wide guard:

1. **At refresh time** — `maybe_refresh_examples` rewrites
   `anthropic.env.placeholder`, `gemini.env.placeholder`, and
   `openai.env.placeholder` from hardcoded templates, NOT from
   whatever real provider values the harness loaded into the
   kernel's `providers/` directory. The real-key bytes never reach
   the refresh code path.
2. **At end of refresh** — `assert_no_real_anthropic_key` scans
   every file under `examples/credentials/` for the regex
   `sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}` and panics with a
   copy-pastable remediation hint if a match is found. The hook
   is wired BEFORE the kernel daemon starts, so a real key in
   the placeholder file fails the whole iter — no half-baked
   examples bundle lands.
3. **At commit time** — `raxis/scripts/check-no-real-anthropic-key.sh`
   runs the same regex over the whole `examples/` directory and
   exits non-zero on match. Wire it into your local pre-commit
   hook with:

   ```bash
   cat > .git/hooks/pre-commit <<'SH'
   #!/usr/bin/env bash
   set -euo pipefail
   raxis/scripts/check-no-real-anthropic-key.sh
   SH
   chmod +x .git/hooks/pre-commit
   ```

   (The script is intentionally NOT installed automatically —
   modifying the operator's git hooks behind their back is its
   own footgun. The README documents the wire-up; the operator
   does it once per clone.)

`INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01`
([`raxis/specs/invariants.md §11.10`](../../specs/invariants.md)) is the formal statement of
the contract.

## Other credentials in this directory

`test-pg-dev.env`, `test-mongo-dev.env`, `test-redis-dev.env`,
`test-smtp-dev.env` are real test-tenant secrets that match the
docker-compose stack credentials in
[`raxis/live-e2e/docker-compose.extended.e2e.yml`](../docker-compose.extended.e2e.yml).
They are explicitly OK to commit because:

1. They only authenticate against the local docker-compose stack,
   which binds to `127.0.0.1` (loopback only — no LAN, no public
   exposure).
2. The docker-compose file already commits the matching
   server-side credentials (Postgres `POSTGRES_PASSWORD`,
   MongoDB `MONGO_INITDB_ROOT_PASSWORD`, Redis `--requirepass`,
   SMTP `postfix-accounts.cf`), so the values are not secret —
   anyone who clones the repo can already see them in the
   compose YAML and the SASL config file.
3. They have **zero production value**. The local docker-compose
   stack is hermetic-per-run; the same credentials never
   authenticate against any operator-managed database.

This is consistent with [`raxis/specs/v2/secrets-model.md §2.5`](../../specs/v2/secrets-model.md)'s
operator-supplied-placeholder rule applied to the harness's own
self-managed test fixtures.

## Per-run drift — what to expect

The auto-refresh hook produces a diff after every refresh-mode
run. In **steady state** (no structural changes between green
iters) that diff is small:

* `policy.toml` — operator + authority + quality keypair
  fingerprints, the operator cert signature, and the
  `signed_at` Unix timestamp diff per-run. The dashboard /
  gateway / observability / lanes sections are byte-stable.
* `plan_primary.toml` / `plan_sibling.toml` — byte-stable
  across runs unless the realistic plan structure or one of
  the seed prompts changed. A diff here is a real signal.
* `credentials/*.env` — byte-stable. A diff here is a real
  signal too (`write_credentials` rebases its values from
  `kernel_driver.rs` source constants).
* `seed/prompts/*` — byte-stable mirror of
  `live-e2e/seed/prompts/`. The prompts files themselves are
  the canonical source; the examples bundle is the mirror.
  The auto-refresh hook copies them verbatim.

The initial seed of this directory (the first commit on the
branch that introduced it) captures the state as of that iter.
The auto-refresh path takes over from there.

## What this directory is NOT

* Not a runtime input. The kernel does not read from
  `raxis/live-e2e/examples/`; it reads from the per-run tmpdir.
* Not an installer-side template. The genesis ceremony's
  bootstrap policy lives in
  `crates/genesis-tools/src/policy_toml.rs::render_genesis_policy_toml`,
  not here. The example policy in this directory carries
  representative placeholder values for the genesis-emitted
  fields and adds the harness's runtime overlay on top.
* Not a substitute for `live-e2e/seed/prompts/`. Both
  directories carry the same prompt markdown files; the
  `seed/prompts/` copy is the canonical source the harness's
  `include_str!` macro reads. The `examples/seed/prompts/`
  copy is the mirror, kept in lock-step by the auto-refresh
  hook so an operator scanning `examples/` sees the complete
  reproducible bundle in one directory.

## See also

* [`raxis/live-e2e/README.md`](../README.md) — the live-e2e harness operator runbook (compose stack, env vars, fail-fast surfaces). The "Example bundle" section there points back at this directory.
* [`raxis/specs/v2/secrets-model.md`](../../specs/v2/secrets-model.md) — the operator-supplied-placeholder discipline (§2.5) and the `INV-SECRET-*` model the no-real-secrets rule slots into.
* [`raxis/specs/invariants.md §11.10`](../../specs/invariants.md) — the formal `INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01` statement, justification, scenario, witness.
* [`raxis/kernel/tests/extended_e2e_support/kernel_driver.rs`](../../kernel/tests/extended_e2e_support/kernel_driver.rs) — the harness code that constructs every file mirrored here, plus the `maybe_refresh_examples` hook.
* [`raxis/scripts/check-no-real-anthropic-key.sh`](../../scripts/check-no-real-anthropic-key.sh) — the pre-commit / CI guard.
