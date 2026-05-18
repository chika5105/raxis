# `raxis-live-e2e`

Live end-to-end test harness for the credential proxies and the
gateway. Every slice in this binary drives a **real** upstream
service (no in-process mocks, no hand-rolled wire fixtures) so a
regression in the proxy's wire-protocol handling cannot hide
behind a fixture that happens to mirror the proxy's own
assumptions.

This README is the operator-side runbook for the un-mocked stack.
The slices' docstrings carry the per-slice contract.

---

## What is and is NOT in scope

| Slice                                        | Real upstream                   | Status      | Notes                                                                                                            |
| -------------------------------------------- | ------------------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------- |
| `postgres-proxy*`                            | `postgres:16-alpine`            | 🟢 active   | Real upstream by default against the compose container; cap-paths covered: `allow_only_select` (`postgres-proxy-restrictions`), `allowed_tables` / `forbidden_tables` / multi-statement ambiguity (`postgres-proxy-table-allowlists`), `max_result_rows` streaming cap (`postgres-proxy-max-result-rows`). `RAXIS_LIVE_POSTGRES_URL` overrides for non-CI debugging. |
| `mongodb-proxy`                              | `mongo:7`                       | 🟢 active   | `--noauth` mode by default; `RAXIS_LIVE_MONGODB_URL` overrides.                                                  |
| `mongodb-proxy-collection-allowlists`        | `mongo:7`                       | 🟢 active   | Auth (SCRAM-SHA-256) against `admin`. Seeds `live_e2e_cap.users` via `docker exec mongosh` and drops on cleanup. |
| `redis-proxy`                                | `redis:7-alpine`                | 🟢 active   | `--requirepass`-protected; the slice drives a real RESP `AUTH` + round-trip.                                     |
| `smtp-proxy`                                 | `mailserver/docker-mailserver`  | 🟢 active   | Postfix + Dovecot SASL. The slice verifies delivery by `docker exec`-ing into the container's Maildir.           |
| `mysql-proxy`                                | `mysql:8.0.36`                  | 🟢 active   | Real upstream by default against the compose container; `RAXIS_LIVE_MYSQL_URL` overrides for non-CI debugging.   |
| `mssql-proxy`                                | SQL Server 2022                 | 🟢 active   | Real upstream by default against the compose container; `RAXIS_LIVE_MSSQL_URL` overrides for non-CI debugging.   |
| `aws-proxy`, `gcp-proxy`, `azure-proxy`      | n/a (V2 IMDS emulator)          | 🟢 active   | V2 proxies SYNTHESISE IMDS responses from the credential backend; they do NOT forward to AWS / GCP / Azure. The slices exercise the synthesizer wire shape on a localhost TCP socket.                                              |
| `aws-proxy-real-endpoint`                    | `https://sts.amazonaws.com/`    | 🟡 V3 witness | Skip-by-default; opt in with `RAXIS_LIVE_CLOUD_NET=1`. Pins the AWS STS canonical `MissingAuthenticationToken` / `InvalidClientTokenId` envelope for the V3 forwarding work. NOT a V2 coverage path — see Phase B notes below.  |
| `gcp-proxy-real-endpoint`                    | `https://oauth2.googleapis.com/`| 🟡 V3 witness | Skip-by-default; opt in with `RAXIS_LIVE_CLOUD_NET=1`. Pins the Google OAuth2 RFC 6749 §5.2 `error` envelope for the V3 forwarding work. NOT a V2 coverage path — see Phase B notes below.                                       |
| `azure-proxy-real-endpoint`                  | `https://login.microsoftonline.com/` | 🟡 V3 witness | Skip-by-default; opt in with `RAXIS_LIVE_CLOUD_NET=1`. Pins the AAD OAuth2 RFC 6749 §5.2 `error` + AAD-specific `error_codes` envelope for the V3 forwarding work. NOT a V2 coverage path — see Phase B notes below.        |
| `http-proxy*`, `gateway-anthropic`           | real HTTPS endpoints            | 🟢 active   | Drive real `https://` upstreams; nothing to un-mock.                                                             |
| `egress-enforcement`, `session-spawn`        | n/a (kernel-internal)           | 🟢 active   | Exercise the kernel's own state machines, not external services.                                                 |

---

## Example bundle (`live-e2e/examples/`)

The realistic-scenario harness writes a `policy.toml`, two
`plan.toml`s (primary + sibling initiative), and the
`test-{pg,mongo,redis,smtp}-dev.env` credential files into its
per-run tmpdir at bootstrap. A checked-in mirror of those files
lives at [`live-e2e/examples/`](examples/), so an operator
auditing "what configuration produced the latest live-e2e iter?"
can answer without re-running the test or reconstructing it from
the Rust constants.

The auto-refresh hook
([`kernel_driver::maybe_refresh_examples`](../kernel/tests/extended_e2e_support/kernel_driver.rs))
rewrites the bundle from the harness's authoritative source on
demand:

```bash
RAXIS_LIVE_E2E=1 RAXIS_LIVE_E2E_REALISTIC=1 \
  RAXIS_E2E_REFRESH_EXAMPLES=1 \
  cargo test -p raxis-kernel \
    --test extended_e2e_realistic_scenario -- --nocapture
```

Default-off (env var unset) so casual `cargo test` runs don't
dirty the worktree. The fix-loop / CI / a `working e2e` commit
MUST set the env var before the run that lands the commit, so the
checked-in bundle always matches the most recent passing iter.
Commit the `git diff raxis/live-e2e/examples/` alongside the
fix-loop diff with the convention
`live-e2e(examples): refresh from <iter_label> (initiative <primary_id_8> + <sibling_id_8>)`.

The Anthropic credential file (`examples/credentials/anthropic.env.placeholder`)
is the ONLY credential file in the bundle that carries a
placeholder value. The real `ANTHROPIC-API-DEV-KEY` MUST NEVER be
checked in:

* `INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01`
  (`specs/invariants.md §11.10`) is the formal statement.
* The refresh hook rewrites `anthropic.env.placeholder` from a
  hardcoded template, NOT from the loaded key value.
* `kernel_driver::assert_no_real_anthropic_key` scans
  `examples/credentials/` for `sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}`
  at end-of-refresh and panics with a copy-pastable remediation
  hint if matched — BEFORE the kernel daemon spawns, so no
  half-baked diff can land.
* `raxis/scripts/check-no-real-anthropic-key.sh` is the same
  regex as a pre-commit / CI guard. Install via:

  ```bash
  cat > .git/hooks/pre-commit <<'SH'
  #!/usr/bin/env bash
  set -euo pipefail
  raxis/scripts/check-no-real-anthropic-key.sh
  SH
  chmod +x .git/hooks/pre-commit
  ```

  Not installed automatically (modifying the operator's git
  hooks behind their back is its own footgun); the README under
  `examples/` documents the wire-up.

The other test-tenant credentials in the bundle
(`test-pg-dev.env` / `test-mongo-dev.env` / `test-redis-dev.env` /
`test-smtp-dev.env`) are explicitly OK to commit — they only
authenticate against the local docker-compose stack on loopback,
the matching server-side credentials already live in
`docker-compose.extended.e2e.yml`, and they have no production
value. See [`live-e2e/examples/README.md`](examples/README.md) for
the full per-file source-of-truth table and the diff-drift
expectations between runs.

---

## Compose stack

The harness pins every image to a SPECIFIC minor tag (see the
header of `docker-compose.e2e.yml` for the full rationale). A
silent base-image bump is the same class of failure the un-mock
sweep itself was meant to catch.

```bash
# Bring the stack up (hermetic — every `up` is a clean tmpfs slate)
docker compose -f live-e2e/docker-compose.e2e.yml up -d --wait

# Confirm everything is healthy
docker compose -f live-e2e/docker-compose.e2e.yml ps

# Tear down (drops every tmpfs)
docker compose -f live-e2e/docker-compose.e2e.yml down -v
```

Two compose files live in this directory:

* `docker-compose.e2e.yml` — the minimum stack the live-e2e
  slices and `kernel/tests/full_e2e_session_lifecycle.rs` need.
* `docker-compose.extended.e2e.yml` — true superset of
  `docker-compose.e2e.yml`: same upstream-service blocks plus the
  observability triple (otel-collector / prometheus / grafana on
  the same `127.0.0.1:4318` / `:9090` / `:3000` ports), and
  additionally pre-seeds `raxis_e2e_mongo.seeded_docs` and
  `raxis_e2e_pg.seeded_rows` for `kernel/tests/extended_e2e_*.rs`.
  It publishes the same ports on the same loopback addresses so
  a slice configured for one works against the other unchanged
  and dashboards populate end-to-end either way.

For the realistic extended scenario, prefer:

```bash
cargo xtask observability up --full --no-open
```

The `--full` path uses the extended compose file and converges the
seeded service stack. The harness also re-applies the Postgres and
Mongo seed scripts at startup so a long-running base stack cannot
masquerade as a ready extended stack.

> **Path A3 / Mediated egress.** After the Tier1Tproxy deletion
> (TODO `tier1-deletion-fold-into-cleanup-sweep`) every executor /
> orchestrator VM boots at `EgressTier::Mediated` unconditionally
> — there is no opt-in toggle and no separate compose file. Both
> compose files exercise the Mediated codepath; the previous
> `docker-compose.airgap-a3.yml` opt-in stamper was deleted in the
> same sweep. See `specs/v2/airgap-architecture.md` and
> `guides/operator/21-airgap-a3-egress-allowlist.md`.

Both compose files pin the project namespace to
`raxis-live-e2e-test` via the top-level `name:` field, which
means the auto-generated network and named volumes carry the
same prefix (`raxis-live-e2e-test_default`,
`raxis-live-e2e-test_prometheus_data`,
`raxis-live-e2e-test_grafana_data`) regardless of which directory
you invoke `docker compose -f <path>` from. Per-service
`container_name:` directives in the compose files keep the
short brand prefix (`raxis-e2e-pg`, `raxis-e2e-mongo`, ...) for
the actual containers.

> **Migration note (one-time).** The compose project was
> previously the implicit directory-derived `live-e2e` and is
> now `raxis-live-e2e-test` for namespace clarity on shared
> developer hosts. If you have leftover containers, networks,
> or named volumes from a pre-rename run, do a one-time cleanup
> against the OLD namespace before bringing the stack back up:
>
> ```bash
> docker compose -f live-e2e/docker-compose.e2e.yml -p live-e2e down -v
> ```
>
> Subsequent `up` / `down` invocations pick up the new
> `raxis-live-e2e-test` namespace from the compose file's
> `name:` field with no extra flags required.

Published loopback ports (offset from defaults to avoid colliding
with operator-side databases):

| Service            | Container port | Host port           |
| ------------------ | -------------- | ------------------- |
| `postgres`         | 5432           | `127.0.0.1:54399`   |
| `mongodb`          | 27017          | `127.0.0.1:27399`   |
| `redis`            | 6379           | `127.0.0.1:63799`   |
| `smtp`             | 25             | `127.0.0.1:25199`   |
| `mysql`            | 3306           | `127.0.0.1:33099`   |
| `mssql`            | 1433           | `127.0.0.1:14399`   |

---

## Building the host kernel with the matching trust anchor (`INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01`)

Live e2e boots the host `raxis-kernel` binary and expects it to
embed the public half of the key that signed the canonical image
manifests. The Linux guest kernel at `<install-dir>/kernel/vmlinux`
does not carry this trust anchor.

Use the short path:

```bash
cd raxis/

# 1. Bake canonical images. This also creates the per-clone signing
#    key at .git/info/raxis-signing-key/{sk.hex,pk.hex} on first run.
cargo xtask images bake

# 2. Rebuild the host daemon with the matching public key pinned via
#    the highest-priority build-script input.
RAXIS_KERNEL_SIGNING_KEY_HEX="$(cat .git/info/raxis-signing-key/pk.hex)" \
  cargo build --release -p raxis-kernel

# 3. Verify the host daemon bytes, not the guest vmlinux.
cargo xtask images verify-trust-anchor --kernel target/release/raxis-kernel
```

If you need to provide a fresh guest kernel, pass it to the first
command:

```bash
cargo xtask images bake \
  --kernel-from-file "$RAXIS_DEV_KERNEL_SOURCE" \
  --kernel-config "$RAXIS_DEV_KERNEL_CONFIG"
```

### Resolution chain

`crates/canonical-images/build.rs` reads, in order:

| # | Source | Notes |
|---|---|---|
| 1 | `RAXIS_KERNEL_SIGNING_KEY_HEX` | 64 lowercase hex chars. Preferred for CI and release builds. |
| 2 | `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` | Path to a 32-byte raw public-key file. |
| 3 | `.git/info/raxis-signing-key/pk.hex` | Per-clone dev key created by `cargo xtask images bake` or a dev build. |
| 4 | Profile fallback | Release embeds the all-zero fail-loud placeholder; dev/test auto-mints the per-clone key. |

`cargo xtask images bake` resolves its own signing key, creates the
per-clone key if absent, signs manifests with `sk.hex`, and injects
the resolved public key into Cargo subprocesses as
`RAXIS_KERNEL_SIGNING_KEY_HEX`. The host daemon is a separate Cargo
build, so rebuild it after the bake and run `verify-trust-anchor`.

### Failure modes

| Symptom | Fix |
|---|---|
| `trust_anchor_unpopulated` | Bake images, rebuild `raxis-kernel` with `RAXIS_KERNEL_SIGNING_KEY_HEX="$(cat .git/info/raxis-signing-key/pk.hex)"`, then verify the host binary. |
| Manifest signature failures for every image | The image bake and host daemon used different keys. Re-run the three-command sequence above. |
| `verify-trust-anchor` cannot find a kernel | Pass `--kernel target/release/raxis-kernel` or set `RAXIS_KERNEL_BINARY`. |
| Planner frame decode errors after code changes | Re-run `cargo xtask images bake`; its cache now includes source fingerprints. Use `--no-cache` only when you intentionally want a full rebuild. |

The `cargo:warning=raxis-canonical-images: trust anchor source = ...`
line on a kernel-crate rebuild is the operator-visible diagnostic.

---

## Run the slices

Selecting individual slices keeps the iteration loop tight:

```bash
# All slices (those that need a service will refuse to start if
# the service is not reachable)
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e

# A single slice
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- redis-proxy

# Several at once
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- redis-proxy smtp-proxy
```

Each slice prints `OK — all selected slices passed` on success
and exits non-zero with an actionable error (which compose
service to start, which env var to set) on failure.

### Witness verifier prerequisite (`INV-WITNESS-VERIFIER-LIVE-E2E-EXERCISED-01`)

The extended-e2e slices (concurrent-lifecycle, realistic-scenario,
single-task) inject a `[[gates]] gate_type = "NoSecretStrings"`
block into the bootstrapped `policy.toml` whenever the
`raxis-verifier-no-secrets` binary is found alongside
`raxis-gateway` in the same `target/<profile>/` tree. This drives
the iter63 paired-write recheck-clear edge in
`kernel/src/scheduler/dag.rs::transition_to_admitted`. If the
binary is absent, the gate is silently skipped and live-e2e runs
take the fast-path admission — `INV-WITNESS-VERIFIER-LIVE-E2E-
EXERCISED-01` coverage is then DROPPED for that run.

The live-e2e harness now auto-builds the latest release
`raxis-gateway` before injecting `[gateway].binary_path` into the
bootstrapped policy. This prevents the old failure mode where
`RAXIS_GATEWAY_BINARY` pointed at a stale binary. Set
`RAXIS_E2E_SKIP_GATEWAY_AUTO_BUILD=1` only when validating a
packaged/system-installed gateway, and pair it with an explicit
`RAXIS_GATEWAY_BINARY=/absolute/path/to/raxis-gateway`.

The default `cargo build --workspace --all-targets` already builds
`raxis-verifier-no-secrets` (it is a workspace member); the explicit
verifier invocation is only required when iterating on a narrower
build:

```bash
cargo build --release -p raxis-verifier-no-secrets
```

CI builds the verifier implicitly via the workspace build in
`.github/workflows/build-images.yml`; an explicit named step is
also pinned there so a future narrowing of the workspace build
does not silently drop verifier coverage.

---

## Executor image lint-toolchain contract (`INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01` + `INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01`)

The realistic-scenario plan's per-language `lint-runner-{python,
rust,js}` Executor tasks (iter55 split,
[`kernel/tests/extended_e2e_support/plan_realistic.rs`](../kernel/tests/extended_e2e_support/plan_realistic.rs))
invoke language-native lint pipelines verbatim inside the
executor VM:

```bash
# lint-runner-python (TASK_LINT_RUNNER_PYTHON)
( cd py-pkg && python -m ruff check . && python -m ruff format --check . )

# lint-runner-rust (TASK_LINT_RUNNER_RUST)
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

# lint-runner-js (TASK_LINT_RUNNER_JS)
( cd ts-pkg && \
    npx --no-install eslint --max-warnings 0 . && \
    npx --no-install prettier --check . && \
    npx --no-install tsc --noEmit )
```

The executor VM ships with an **empty default egress allowlist**
(`planner-harness.md §10.6` egress posture; `INV-VM-EGRESS-01`),
so the runner cannot `pip install ruff` or `npm install eslint`
at task time — the binaries / modules must already exist in the
rootfs. The seed materializer
([`live-e2e/seed/repo/rich-multilang-001/scripts/materialize_seed.sh`](seed/repo/rich-multilang-001/scripts/materialize_seed.sh))
deliberately ships no `node_modules/` or `.venv/` (every fixture
refresh would otherwise drag thousands of files through git);
the executor-starter Containerfile is the structural answer:

| Lane     | Pre-baked binaries                                                                                                          | Pinned in                                              |
| -------- | --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| Rust     | `cargo`, `rustfmt`, `clippy` (rustup stable)                                                                                | [`images/executor-starter/Containerfile`](../images/executor-starter/Containerfile) |
| Python   | `ruff==0.7.4` (pip → system site-packages; CLI shim at `/usr/local/bin/ruff`; importable as `python -m ruff`)               | Containerfile + [`manifest.toml`](../images/executor-starter/manifest.toml) `[lint_toolchain] ruff_version` |
| JS / TS  | `eslint@9.15.0`, `prettier@3.3.3`, `typescript@5.6.3`, `tsx@4.19.2`, `@types/node@20.17.6` (npm install -g; `/usr/bin/<bin>` shims) | Containerfile + `manifest.toml` `[lint_toolchain]` |

[`images/executor-starter/verify.sh`](../images/executor-starter/verify.sh)
asserts the bake actually contains both:

* Python — `usr/local/bin/ruff` exists AND
  `usr/lib/python3*/dist-packages/ruff-0.7.4.dist-info/` (or the
  `/usr/local/lib/python3*/...` mirror) is present. On a
  Linux-on-Linux bake the verifier additionally runs
  `python3 -c "import ruff" && python3 -m ruff --version` and
  asserts the version matches the pin.
* JS — `usr/lib/node_modules/{eslint,prettier,typescript,tsx}/`
  (or the `usr/local/lib/...` mirror) plus the
  `/usr/bin/{eslint,prettier,tsc}` (or `/usr/local/bin/...`)
  CLI shims so `npx --no-install` can resolve them via `$PATH`
  fallback.

If a future Containerfile change drops one of the lint
toolchains silently, `verify.sh` fails with `INV-EXECUTOR-IMAGE-
LINT-TOOLCHAIN-{PYTHON,JS}-01 VIOLATED` and a copy-pastable
`cargo xtask images bake --role executor-starter`
remediation. Witness coverage:
[`xtask/tests/executor_starter_lint_toolchain.rs`](../xtask/tests/executor_starter_lint_toolchain.rs).

Pin bumps require updating BOTH the Containerfile and the
`manifest.toml` `[lint_toolchain]` table; the verifier
cross-checks one against the other so an asymmetric bump
surfaces at bake time rather than at the next iter's
`lint-runner-*` task run.

---

## Dashboard FE bundle contract (`INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01` + `INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-FRESH-01`)

Every realistic-scenario / full-lifecycle live-e2e run mounts
the operator dashboard at `127.0.0.1:19820` (override via
`RAXIS_E2E_DASHBOARD_PORT`). The dashboard is the operator's
primary visibility surface for an in-flight run. Two failure
modes silently break this surface and are both treated as
the same invariant family:

* **Bundle absent** (`PRESENT-01`): no `dist/index.html` on disk
  ⇒ the dashboard falls back to JSON-only and every SPA route
  returns HTTP 404 — Dashboard QA workers attached to the run
  see nothing.
* **Bundle stale** (`FRESH-01`): a `dist/index.html` exists but
  its mtime is older than something under
  `dashboard-fe/src/**` or a tracked root config file (the
  iter68 hazard) ⇒ the dashboard serves an old build and new
  FE features (new pages, new sidebar entries, new types) are
  silently invisible. The operator sees the UI fine — they
  just don't see the work they shipped.

**Auto-install + auto-build + auto-rebuild-on-staleness
(default).** When `RAXIS_E2E_SKIP_DASHBOARD_BUILD` is
**unset**, the harness
([`tests::common::dashboard::locate_dashboard_dist`]) ensures
the bundle is BOTH present AND fresh before the kernel binds
the dashboard port:

1. **Freshness probe** ([`probe_dashboard_fe_freshness`]):
   single-pass mtime walk of `dashboard-fe/src/**` plus a fixed
   list of root config files (`package.json`,
   `package-lock.json`, `vite.config.ts`, `tsconfig*.json`,
   `tailwind.config.*`, `postcss.config.*`, `index.html`).
   Newest-source mtime is compared to
   `dashboard-fe/dist/index.html` mtime. Sub-millisecond on a
   normal tree.
2. Fast path: if dist exists AND every probed source mtime is
   `≤` the dist mtime, the harness uses it as-is and emits
   `[dashboard-bundle] freshness=fresh`. No subprocess work.
3. Stale path (`FRESH-01`): if dist exists BUT at least one src
   file is newer, the harness logs
   `[dashboard-bundle] freshness=stale dist_mtime_unix=… newest_source=… newest_source_mtime_unix=…`
   and runs `npm run build` in place (bounded by
   `RAXIS_E2E_NPM_BUILD_TIMEOUT_SECS`, default 300 s).
4. Missing-bundle path (`PRESENT-01`): if dist is absent, the
   harness runs `npm ci` (when `node_modules/.bin/vite` is
   absent, bounded by `RAXIS_E2E_NPM_INSTALL_TIMEOUT_SECS`,
   default 600 s) followed by `npm run build`.
5. Post-build sanity: the harness re-checks
   `dashboard-fe/dist/index.html` exists.

**Hard-fail policy.** Any failure in the install / build /
sanity chain panics the test with a panic body carrying ONE
of two literal tokens (so a CI log scraper can route on the
failure family):

* `INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01 VIOLATED` —
  first-time install/build broke (no dist on disk at all).
* `INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-FRESH-01 VIOLATED` —
  staleness rebuild broke (dist present but src newer; the
  in-place `npm run build` failed).

Failure modes that hard-fail:

| Failure                                | Token         | Surface |
|----------------------------------------|---------------|---------|
| `dashboard-fe/package.json` missing & no dist | PRESENT-01 | Workspace shape broken; restore or opt out. |
| `npm ci` spawn failure (no Node)       | PRESENT-01    | Install Node + npm; toolchain hint in panic body. |
| `npm ci` non-zero exit                 | PRESENT-01    | Real install failure (cold registry, EACCES, …); diagnose with the surfaced npm output. |
| `npm ci` timeout                       | PRESENT-01    | Cold pull >600 s; raise `RAXIS_E2E_NPM_INSTALL_TIMEOUT_SECS`. |
| `npm run build` failure (first build)  | PRESENT-01    | Real `tsc -b && vite build` failure; surfaced in npm output. |
| `npm run build` failure (stale rebuild)| FRESH-01      | Same diagnostic surface; the token tells operator the rebuild was triggered by an mtime delta. |
| Post-build dist still absent           | (both)        | Build step lying about success; inspect npm warnings. |

This is the iter52 + iter68 lesson:

* **iter52** (PRESENT-01): the previous behaviour silently
  swallowed `tsc: command not found` (caused by a fresh
  worktree with no `node_modules/`), surfaced only as a single
  `[dashboard-bundle]` warning line buried in the cargo log,
  and left the dashboard UI broken for the entire 65 min run.
* **iter68** (FRESH-01): a presence-only check silently served
  a 6-hour-old `dist/index.html` against an in-tree src that
  had a brand-new Gates page (and new sidebar entry, new
  types). The operator saw the dashboard load fine — just
  without any of the newly-shipped work. The fast-path
  rewrite checks src/dist mtimes and forces an in-place
  rebuild on any drift, mirroring the
  `INV-IMAGE-BAKE-NO-STALE-CACHE-01` staging-binary freshness
  check in `xtask::images`.

**Opt-out (release-CI lanes that pre-build).** Set
`RAXIS_E2E_SKIP_DASHBOARD_BUILD=1` to skip BOTH the install
+ build pipeline AND the staleness rebuild. The harness logs
an explicit opt-out line:

* If a dist exists on disk it is served as-is (even if stale)
  — the operator's "I manage the bundle externally" assertion
  wins over the freshness gate. A `[dashboard-bundle] WARNING:
  dist/ is stale relative to dashboard-fe/src/** but
  RAXIS_E2E_SKIP_DASHBOARD_BUILD=1` line is emitted so the
  staleness is still visible in CI logs.
* If no dist exists, the dashboard serves JSON API only.

Use this when your CI workflow bakes `dashboard-fe/dist/`
outside the cargo-test driver.

**Bounded-wait composition.** All subprocess steps satisfy
`INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01` via
[`tests::common::dashboard::run_npm_bounded`], which polls
`Child::try_wait` and `SIGKILL`s the child when the bounded
deadline elapses. Non-positive / unparseable timeout overrides
fall back to the default rather than disabling the bound.

**Witness coverage:**
[`tests::common::dashboard::tests::inv_live_e2e_dashboard_fe_bundle_present_01_*`](../kernel/tests/common/dashboard.rs)
— classifier exhaustion (5 arms × {fresh/stale} flag),
env-var spelling, PRESENT-01 panic-token shape, timeout
default bounds, env-override clamping, and `node_modules` probe
edge cases.
[`tests::common::dashboard::tests::inv_live_e2e_dashboard_fe_bundle_fresh_01_*`](../kernel/tests/common/dashboard.rs)
— stale-dist classifier routing (rebuild / install-then-rebuild
/ opt-out-preserves-stale / no-pkg-json-fallback), FRESH-01
panic-token shape, `DashboardFeFreshness::is_fresh()` mapping,
and an end-to-end filesystem round-trip exercising
`DistMissing` / `Fresh` / `Stale` / config-file-staleness arms
against a synthetic `dashboard-fe/` tree.

[`tests::common::dashboard::locate_dashboard_dist`]: ../kernel/tests/common/dashboard.rs
[`tests::common::dashboard::run_npm_bounded`]: ../kernel/tests/common/dashboard.rs
[`probe_dashboard_fe_freshness`]: ../kernel/tests/common/dashboard.rs

---

## OTel pusher auto-spawn contract (`INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01`)

Every realistic-scenario / full-lifecycle live-e2e run depends
on the kernel's metrics being forwarded from its in-process
JSONL ring (`<data_dir>/observability/{spans,metrics}/`) to the
OTLP collector at `http://127.0.0.1:4318` so Prometheus can
scrape them and Grafana can render them. The forwarding job is
owned by the `raxis-otel-pusher` sidecar binary
(`pusher/`); without it, the kernel buffers metrics
locally and every Grafana panel stays empty for the duration
of the run — `INV-OTEL-03` keeps the kernel itself out of the
OTLP transport business so the pusher MUST exist.

**Auto-locate-or-build + auto-spawn + smoke-probe (default).**
When `RAXIS_E2E_SKIP_OTEL_PUSHER` is **unset**, the harness
([`extended_e2e_support::otel_pusher::ensure_otel_pusher_or_panic`])
guarantees a forwarding pusher is alive before the first plan
is submitted:

1. Resolve the binary in this priority:
   1. `RAXIS_OTEL_PUSHER_BINARY` env var (operator override).
   2. `<workspace>/target/release/raxis-otel-pusher`, then
      `<workspace>/target/debug/raxis-otel-pusher`.
   3. `$RAXIS_INSTALL_DIR/bin/raxis-otel-pusher`.
2. If still missing, run `cargo build --release -p
   raxis-otel-pusher` from the workspace root, bounded by
   `RAXIS_E2E_OTEL_PUSHER_BUILD_TIMEOUT_SECS` (default 180 s,
   clamped to `[60s, 600s]`). The auto-build runs as part of
   the harness's own setup phase BEFORE the kernel daemon
   spawns, so it does NOT compete with an already-running
   kernel for RAM (mirrors how `npm ci` runs before the kernel
   binds the dashboard port). On a fresh worktree the cold-cache
   cost is ~16 s; on a warm cache it is a no-op (binary already
   on disk).
3. Spawn the pusher with `--config <data_dir>/policy/policy.toml
   --data-dir <data_dir> --health-port 0`; capture stderr to
   `<data_dir>/otel-pusher.stderr.log`; verify the child PID is
   alive after a 3 s startup window.
4. Smoke-probe Prometheus (`http://127.0.0.1:9090/api/v1/query?
   query=up`) for up to 30 s at 1 s cadence; assert at least
   one `raxis*` job appears with `up=1`. The probe loop
   short-circuits on supervised-child death so a crashed
   pusher surfaces immediately.
5. Emit exactly ONE operator-facing log line:
   `[realism-e2e] observability: pusher spawned (pid=N, bin=…,
   log=…), smoke-probed, live metrics flowing to Grafana
   http://127.0.0.1:3000/d/raxis-00-overview`.
6. Hold the supervised child in an `OtelPusherSupervisor` RAII
   guard whose `Drop` SIGTERM-then-SIGKILL's the child
   (500 ms grace window). No leaked processes on success
   or failure.

**Hard-fail policy.** Any failure in steps 2-4 panics the test
with a panic body containing the literal token `INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01
VIOLATED`. Failure modes that hard-fail:

| Failure                                  | Surface                                                                                                                |
|------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| `RAXIS_OTEL_PUSHER_BINARY` set but missing | Convention paths are still tried; if all miss → auto-build.                                                            |
| `cargo` not on PATH (no Rust toolchain)  | Spawn-failed panic with hint to install Rust + cargo OR set `RAXIS_OTEL_PUSHER_BINARY`.                                |
| `cargo build` non-zero exit              | Real build failure; surfaced npm-style with cargo's full output above the panic.                                       |
| `cargo build` exceeded 180 s             | Timeout panic with hint to raise `RAXIS_E2E_OTEL_PUSHER_BUILD_TIMEOUT_SECS` (clamped to `[60s, 600s]`).                |
| Pusher binary spawn failed (ENOENT etc.) | Spawn-failed panic naming the binary path.                                                                             |
| Pusher exited within 3 s of spawn        | Tail of `<data_dir>/otel-pusher.stderr.log` embedded in the panic body so the operator sees the OTLP / policy reason.  |
| Prometheus smoke probe timed out (30 s)  | "no `raxis*` job" / "raxis target up=0" remediation block including curl one-liners against Prometheus + the collector zPages. |

This is the iter53 lesson: the previous behaviour silently
emitted a warning when the pusher binary was absent, then
contradicted itself in the very next log line by claiming
"live metrics flowing to Grafana" — operators trusted the
second line, attributed dark Grafana panels to a misconfigured
panel rather than to a missing pusher, and the run continued
for ~30 minutes without any operator-visible signal that the
dashboards were dark. Hard-fail forces the failure to surface
immediately so the operator either pre-builds the pusher,
sets the explicit opt-out, or accepts the auto-build cost.

**Opt-out (operator-supervised pusher).** Set
`RAXIS_E2E_SKIP_OTEL_PUSHER=1` for the narrow case where you
are running your own long-lived pusher (systemd / launchd /
Terraform-provisioned) attached to the same `<data_dir>`
ring. The harness skips the auto-locate / auto-build / spawn
path and emits an explicit opt-out log line:

```text
[realism-e2e] observability: pusher skipped by RAXIS_E2E_SKIP_OTEL_PUSHER=1;
  assuming external pusher is forwarding to http://127.0.0.1:4318
```

The Prometheus smoke probe still runs — if no external pusher
is actually forwarding, the harness hard-fails with the
alternate remediation message:

```text
INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01 VIOLATED: Prometheus smoke probe failed after 30s …

Remediation:
  * Set RAXIS_E2E_SKIP_OTEL_PUSHER=0 (or unset it) to let the harness manage the pusher, OR
  * Ensure your external pusher is running and pointing at http://127.0.0.1:4318
  * Verify Prometheus has a `raxis*` job scraping the OTel collector
```

Mirrors the `RAXIS_LIVE_E2E_NO_AUTO_DOCKER` discipline for
the docker backing stack — operator-explicit "I'll handle it"
+ a smoke probe that catches the broken-promise case.

**Bounded-wait composition.** The auto-build subprocess
satisfies `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01` via
[`harness_timeout::run_command_output_timeout`]. The smoke
probe is bounded by `SMOKE_PROBE_BUDGET` (30 s). Non-positive
/ unparseable / out-of-range build-timeout overrides clamp to
the default rather than disabling the bound.

**No-contradiction guarantee
(`INV-LIVE-E2E-OBSERVABILITY-LOG-NO-CONTRADICTION-01`).** No
code path in the harness emits both `Grafana panels will stay
empty` AND `live metrics flowing to Grafana` in the same run.
Either the pusher is actively forwarding (success log fires
once, with the "flowing" phrase) or the pusher is not (the
harness hard-fails per `INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01`,
with the violation token and zero "flowing" claims). A future
maintainer who adds a third intermediate state (e.g.
`--dry-run` mode) MUST also drop one of the two conflicting
phrases — the witness asserts both surfaces.

**Witness coverage:**
[`extended_e2e_support::otel_pusher::tests::inv_live_e2e_otel_pusher_present_01_*`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
— 13 tests covering classifier exhaustion (5 arms +
"never returns hard-fail directly" guard), env-var spelling,
panic-token shape, default + override timeout bounds, supervisor
SIGKILL-on-drop, smoke-probe classifier (empty / non-raxis /
raxis-down / raxis-up shapes), opt-out smoke-probe path,
convention-path precedence, plus the
`inv_live_e2e_observability_log_no_contradiction_01_pusher_absent_emits_only_failure_path`
witness for the no-contradiction half of the contract.

[`extended_e2e_support::otel_pusher::ensure_otel_pusher_or_panic`]: ../kernel/tests/extended_e2e_support/otel_pusher.rs
[`harness_timeout::run_command_output_timeout`]: ../kernel/tests/extended_e2e_support/harness_timeout.rs

---

## Harness preflight: host disk hygiene + auto-bring-up + bounded waits

The realistic-scenario kernel test
(`kernel/tests/extended_e2e_realistic_scenario.rs`) runs three
preflight gates **before** any `seed_*` helper runs:

1. **Host disk hygiene** (`require_disk_hygiene` /
   `INV-HOST-HYGIENE-01`) — sub-second `df -P` probe across the
   repo volume, `/private/tmp`, and every `/var/folders/*` (AVF
   guest dir). Refuses to run when any monitored volume is at
   90% or above. On detected pressure the harness:
     * Builds a structured
       `raxis_types::HostPreflightError::DiskPressure { threshold_pct,
       observed_volumes, remediation_cmd, docs_url }`.
     * Emits one stable-prefixed stderr line —
       `OPERATOR_ATTENTION_REQUIRED HostHygieneDiskPressure {json}`
       — for harness / terminal / CI-log consumers. This is the
       only surface for the host-hygiene signal: it is a
       developer-/CI-host concern (see `INV-HOST-HYGIENE-01`'s
       scope clause in `specs/invariants.md §11.11`) and is
       deliberately not routed to the operator dashboard
       (`dashboard-hardening.md §5.7`). The audit chain stays
       kernel-scoped for runtime invariants only.
     * Panics with the structured `Display` rendering, putting
       the offending volume + `cargo xtask hygiene` remediation
       command into the `cargo test` failure summary so a
       developer who never reads stderr still sees the right
       next step.
   Converts what was a 31-min mid-flight `DiskFullHaltEntered`
   (iter 16 of the motivating incident, every activation
   rejected with `FailDiskFull`) into a sub-second skip with
   the right next step embedded in the structured payload.
2. **Docker compose stack** (`ensure_extended_stack_up_or_panic` /
   `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`) — verifies the
   docker-compose project `raxis-live-e2e-test` is up and
   healthy.
3. **Per-service reachability** + the rest of the existing
   preflight ladder (TCP probes, env-var checks, gateway
   binary presence, canonical-image bake).

The first gate is the "INV-HOST-HYGIENE-01" preflight; the
second is the "INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01"
preflight described in the rest of this section.

The default behaviour for the second gate is operator-ergonomic:
if the stack is not running the harness auto-brings-it-up via

```bash
docker compose -p raxis-live-e2e-test \
    -f live-e2e/docker-compose.extended.e2e.yml up -d --wait
```

and re-probes for health afterwards. The whole probe + bring-up
+ re-probe sequence is bounded — see the timeout table below —
so a missing `docker` binary, an unhealthy container, or a
firewall blocking image pulls all surface as a typed error
within seconds to a few minutes rather than hanging the test
runner indefinitely.

### Cold image cache → pre-pull stage

Before the harness reaches the `docker compose ... up -d --wait`
bounded-wait it runs an image pre-pull stage
(`ensure_compose_images_cached_or_pull` in
`kernel/tests/extended_e2e_support/docker_stack.rs`,
`INV-LIVE-E2E-HARNESS-IMAGE-PREPULL-01`). The stage:

1. Resolves the image list via `docker compose ... config --images`.
2. Checks each image with `docker image inspect` (sub-second
   per image when cached).
3. If every image is cached locally, logs `[live-e2e docker-stack]
   images cached locally: N images verified, skipping pull` and
   continues to the up-wait stage.
4. If any image is missing, logs `[live-e2e docker-stack] cold
   image cache; pulling N missing images (this can take 5-15
   minutes on a fresh machine)...` and shells out to
   `docker compose ... pull` under a generous bounded wait
   (default **20 minutes**).

**Failure mode this prevents.** The 240 s bound on
`docker compose ... up -d --wait` is sized for actual
healthcheck convergence (30-90 s once images are local). On a
cold image cache — e.g. immediately after
`docker system prune --volumes -f` — the pull alone exceeds
240 s on a typical operator machine; the bounded wait then
SIGKILLs the compose process mid-pull and surfaces a
`[bounded-wait:docker-compose-up] child did not exit within
240s; SIGKILLed` panic that misleadingly looks like a stack
startup failure rather than a missing image. The iter63 launch
attempt on 2026-05-15 burned a full operator iteration on
exactly this trap; the pre-pull stage closes it.

**Env vars:**

| Env var                                  | Default | Behaviour                                                                                                                                                                          |
| ---------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RAXIS_LIVE_E2E_PULL_TIMEOUT_SECS`       | 1200    | Bounded-wait ceiling for `docker compose pull` (seconds). Unset / empty / non-positive / unparseable values clamp to 1200 (no way to disable the bound — every harness shell-out is bounded per `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`). |
| `RAXIS_LIVE_E2E_NO_PREPULL=1`            | unset   | Skip the pre-pull stage entirely. Use when you manage `docker compose pull` externally (CI pipelines that warm the cache as a separate step). The dispatcher MUST NOT shell out to `docker` at all under this opt-out — witnessed by `prepull_opt_out_skips_all_docker_shell_outs`. |

On pull failure (non-zero `docker compose pull` exit OR timeout)
the harness panics with a structured remediation block:

```text
[live-e2e docker-stack] image pull failed: <reason>
Remediation:
  1. Confirm Docker Desktop has network access (curl https://registry-1.docker.io/v2/ -I).
  2. Manually pre-pull from a network-stable terminal:
       docker compose -p raxis-live-e2e-test \
         -f live-e2e/docker-compose.extended.e2e.yml pull
  3. If pull succeeds outside the harness, set RAXIS_LIVE_E2E_PULL_TIMEOUT_SECS=<seconds> to a larger value (default 1200s).
```

The remediation lines are copy-pastable — substituting your
own compose-file path / project name where appropriate.

### Opting out of auto-bring-up

Set `RAXIS_LIVE_E2E_NO_AUTO_DOCKER=1` to disable the harness
auto-bring-up. In that mode the harness fail-fast surfaces the
literal token `RAXIS_LIVE_E2E_DOCKER_STACK_DOWN` so a CI log
scraper can pin the failure mode without parsing the full panic
message:

```text
RAXIS_LIVE_E2E_DOCKER_STACK_DOWN: docker-compose project
`raxis-live-e2e-test` is not up + healthy and
`RAXIS_LIVE_E2E_NO_AUTO_DOCKER=1` opted out of harness
auto-bring-up. Bring up the backing services first via
`docker compose -p raxis-live-e2e-test -f
.../docker-compose.extended.e2e.yml up -d --wait` or unset
RAXIS_LIVE_E2E_NO_AUTO_DOCKER. (Probe details: ...)
```

CI pipelines that pre-bring the stack up themselves should
typically set `RAXIS_LIVE_E2E_NO_AUTO_DOCKER=1` so a stack
that's *missing* fails the build clearly instead of having the
harness paper over the missing pre-step.

### Timeout contract

Per `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`
(see `specs/invariants.md §11.10`) every external-process spawn
in the harness is bounded:

| Phase                                 | Constant                  | Default |
| ------------------------------------- | ------------------------- | ------- |
| Pre-seed reachability probe           | `HEALTH_PROBE_TIMEOUT`    | **5 s** |
| Per-seeder subprocess (psql / mongosh / redis-cli / mysql / sqlcmd) | `SEED_TIMEOUT`            | **30 s** |
| `docker compose ps` probe             | `DOCKER_PROBE_TIMEOUT`    | **30 s** |
| `docker compose up -d --wait`         | `DOCKER_BRINGUP_TIMEOUT`  | **240 s** |

On expiry the wrapper SIGKILLs and reaps the child, returning a
typed `BoundedWaitError::Timeout` (lifted to
`ServiceEvidenceError::SeedTimedOut` at the seed call sites).
The error carries the seed name, the wrapped subprocess label
(e.g. `"psql"`, `"mongosh"`), and the target service URL so an
operator finds the failure mode without grepping the audit
chain.

### Pre-seed health probes

Before each `seed_*` call the harness runs the protocol's
canonical "is the server up" check (`pg_isready`, `mongosh
ping`, `redis-cli PING`, `mysqladmin ping`, `sqlcmd -Q "SELECT
1"`, or a TCP handshake against the SMTP submission port). A
failed probe surfaces a typed
`ServiceEvidenceError::PreSeedHealthCheckFailed` within ~5 s —
well before the seeder gets to wait the full 30 s for the same
root cause.

The harness ships these wrappers in:

* `kernel/tests/extended_e2e_support/harness_timeout.rs` — generic
  bounded-wait + spawn wrappers.
* `kernel/tests/extended_e2e_support/health_probe.rs` —
  per-protocol probe helpers.
* `kernel/tests/extended_e2e_support/docker_stack.rs` —
  auto-bring-up + opt-out gate.
* `kernel/tests/extended_e2e_support/kernel_driver.rs` —
  `poll_for_dual_lifecycle_completion` and the
  `orchestrator_spawn_failed` scanner that satisfies the
  audit-poll half of the invariant (see below).

### Audit-poll fail-fast on `orchestrator_spawn_failed`

The same invariant applies to the lifecycle-completion poll
the realistic-scenario harness uses to wait for
`IntegrationMergeCompleted` events. Once the kernel emits a
terminal `orchestrator_spawn_failed` JSON line on stderr for
either watched initiative — after exhausting its
`session_vm_transient_retry` budget for a session VM — the
lifecycle cannot make further progress without operator-side
`recovery::reconcile`, which the harness does not drive.
Polling further is a guaranteed indefinite wait until the
`RAXIS_E2E_REALISTIC_DEADLINE_SECS` deadline (30 min default).

The harness therefore reads `<data_dir>/kernel.stderr.log`
on every poll iteration (cheap substring pre-filter) and
panics with the kernel's own `error` + `hint` surfaced
verbatim, so the operator sees the substrate failure in
seconds. The most common trigger today is an unpopulated
`EXPECTED_KERNEL_SIGNING_KEY_BYTES`: the kernel can't verify
the canonical-image manifest, silently degrades to
`ImageKind::RootfsErofs`, and apple-vz rejects the gzip'd
initramfs CPIO as "Invalid disk image". The current remediation
(`cargo xtask images bake` -> rebuild host `raxis-kernel` with the
matching `RAXIS_KERNEL_SIGNING_KEY_HEX` -> `verify-trust-anchor`) lives in
the [Building the host kernel with the matching trust
anchor](#building-the-host-kernel-with-the-matching-trust-anchor-inv-image-bake-kernel-trust-anchor-populated-01)
section above; `specs/v2/release-and-distribution.md §8.1–§8.2`
is the normative spec reference.

Mid-flight `session_vm_transient_retry` lines are
intentionally NOT a fail-fast trigger — those are stalls the
kernel may still resolve.

### Postgres + MySQL + MSSQL — active by default

All three SQL-database proxy slices now exercise the real
upstream forwarding path by default against the compose stack
containers. Bring the stack up first and the slices Just Work;
no env-var dance required:

```bash
docker compose -f live-e2e/docker-compose.e2e.yml \
    up -d postgres mysql mssql --wait

RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- postgres-proxy
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- postgres-proxy-restrictions
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- postgres-proxy-table-allowlists
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- postgres-proxy-max-result-rows
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- mysql-proxy
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- mssql-proxy
```

The slices TCP-preflight their respective host ports
(`127.0.0.1:54399` for Postgres, `127.0.0.1:33099` for MySQL,
`127.0.0.1:14399` for MSSQL) and fail fast with an actionable
error message if the container isn't reachable.

If you need to point at a non-compose upstream (e.g. an Aurora /
RDS / Azure SQL endpoint for non-CI debugging):

```bash
RAXIS_LIVE_POSTGRES_URL='postgresql://user:pass@host:5432/db' \
    cargo run -p raxis-live-e2e -- postgres-proxy
RAXIS_LIVE_MYSQL_URL='mysql://user:pass@host:3306/db' \
    cargo run -p raxis-live-e2e -- mysql-proxy
RAXIS_LIVE_MSSQL_URL='mssql://user:pass@host:1433/db?encrypt=false' \
    cargo run -p raxis-live-e2e -- mssql-proxy
```

Note: the proxy is plaintext-only on the upstream side (V2.1
MVP); `?encrypt=true` on the MSSQL URL fails fast at
`UpstreamSession::connect`, as does `?sslmode=require` on the
Postgres URL. TLS upstream lands in V3 alongside Windows /
Entra ID auth.

The slices no longer support a hermetic / no-container mode —
the upstream-failure audit path is covered by the unit tests in
`crates/credential-proxy-{postgres,mysql,mssql}/src/upstream.rs::tests`
(Postgres `tokio-postgres` SCRAM-SHA-256 + MD5 path + MySQL
fake-server fixtures + MSSQL `forward_sql_batch` rewrite
fuzzers).

#### Postgres cap-paths covered by real-upstream slices

| Capability                                         | Slice                              | Wire-shape assertion                                                                                                                       |
| -------------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `allow_only_select` (V2.1 verb-class)              | `postgres-proxy-restrictions`      | `INSERT` / `UPDATE` / `DELETE` ⇒ `ErrorResponse(42501)`; `SELECT` reaches `CommandComplete` against real upstream.                         |
| `allowed_tables` + `forbidden_tables`              | `postgres-proxy-table-allowlists`  | Walker resolves `public.users` → `42501` (`table_not_in_allowed_list`); `public.audit_log` → `42501` (`table_in_forbidden_list`).          |
| Ambiguous SQL (multi-statement) + `enforce=false`  | `postgres-proxy-table-allowlists`  | `SELECT ...; DROP ...` fail-closes with `ambiguous_sql_multi_statement`; audit-only mode admits and surfaces `restriction_reason`.         |
| `max_result_rows` (V2.2 streaming cap)             | `postgres-proxy-max-result-rows`   | `SELECT generate_series(1, 100)` capped at 5: wire shape `T + 5×D + E(54000) + Z`; `queries_capped_by_max_result_rows = 1`; audit carries `upstream_error = "max_result_rows_exceeded"`. |
| SCRAM-SHA-256 / MD5 password auth (Postgres 14+)   | all four slices                    | `tokio-postgres` performs the SASL exchange against the real `raxis_test` user (compose Postgres 16 default = SCRAM).                      |
| TLS upstream (`sslmode=require`)                   | unit test `upstream::tests`        | V2.1 MVP rejects `sslmode=require` at parse time with `FAIL_PROXY_TLS_NOT_SUPPORTED`; V3 lands TLS.                                        |

---

## Transparent-proxy validation tier

Beyond the per-protocol slices in `raxis-live-e2e`, the realism
e2e harness layers a second validation tier that proves the
credential proxy is **transparent to the agent** — a stock
Python program that knows nothing about RAXIS connects via the
proxy, pulls the seeded data, and writes byte-canonical outputs.
The contract, witness module, and assertion order are pinned in
[`raxis/specs/v2/transparent-proxy-validation.md`](../specs/v2/transparent-proxy-validation.md).

### Pieces

* Stock-Python scripts: `live-e2e/seed/scripts/transparent_proxy/`
  (`check_postgres.py`, `check_mongodb.py`, `check_redis.py`,
  `check_smtp.py`, `check_mysql.py`, `check_mssql.py`,
  `run_all_services.sh`, `requirements.txt`).
* Operator-realistic prompt:
  `live-e2e/seed/prompts/transparent_proxy_real_scripts.md`.
* Plan task: `transparent-proxy-realscripts` (a successor of
  `service-round-trip` in the realistic-scenario plan;
  `path_allowlist = ["out/services/", "scripts/last_run_summary.txt"]`).
* Witness module:
  `kernel/tests/extended_e2e_support/transparent_proxy_evidence.rs`.

### Run the scripts standalone (no kernel needed)

The scripts read `*_URL` env vars and have no RAXIS imports, so
an operator can run them directly against the un-mock compose
stack to confirm behaviour outside a kernel-driven flow:

```bash
docker compose -f live-e2e/docker-compose.extended.e2e.yml up -d --wait

cd live-e2e/seed/scripts/transparent_proxy
pip install -r requirements.txt   # or use a venv

DATABASE_URL='postgresql://raxis_test:raxis_test_pass@127.0.0.1:54399/raxis_e2e_pg' \
PG_DATABASE=raxis_e2e_pg \
python3 check_postgres.py --output /tmp/postgres-direct.txt

MONGO_URL='mongodb://127.0.0.1:27399/' \
MONGO_DATABASE=raxis_e2e_mongo \
python3 check_mongodb.py --output /tmp/mongodb-direct.txt

REDIS_URL='redis://:raxis_test_pass@127.0.0.1:63799/0' \
python3 check_redis.py --output /tmp/redis-direct.txt

SMTP_URL='smtp://127.0.0.1:25199/' \
python3 check_smtp.py --output /tmp/smtp-direct.txt

bash run_all_services.sh /tmp/run-all
```

Outputs are byte-canonical (pipe-delimited rows, sorted JSON
lines, etc.). The kernel-driven realism e2e uses the same scripts
through the credential proxies and asserts the resulting bytes
match seed-derived canonicals.

### Witness gating + smoke test

The realistic-scenario test (`cargo test -p raxis-kernel
--test extended_e2e_realistic_scenario`) exercises the
transparent-proxy witness in **two** modes:

1. **Wiring smoke test (default; both gates off).** Builds a
   tempdir fixture, writes the canonical output bytes from the
   `service_evidence` seed shapes, and asserts the witness
   accepts the fixture against a synthetic audit chain. Fast,
   no containers required.
2. **Live-driven (`RAXIS_LIVE_E2E=1 RAXIS_LIVE_E2E_REALISTIC=1`).**
   Stages the scripts into the executor's worktree, lets the
   real LLM-driven Executor task run them through the credential
   proxies, then asserts the chain + worktree against the witness.

For an interactive live run where the dashboard should remain
available after either success or failure, add keep-alive:

```bash
RAXIS_LIVE_E2E=1 RAXIS_LIVE_E2E_REALISTIC=1 \
RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT=1 RAXIS_E2E_KEEP_ALIVE_DURATION_SECS=7200 \
  cargo test -p raxis-kernel \
    --test extended_e2e_realistic_scenario \
    realistic_session_lifecycle -- --nocapture --test-threads=1
```

The older short aliases `RAXIS_KEEP_ALIVE=1` and
`RAXIS_KEEP_ALIVE_DURATION_SECS=7200` are accepted too.

---

## Credential-substitution canary (the secrets-model witness)

The credential-substitution canary is the structural witness for
[`raxis/specs/v2/secrets-model.md`](../specs/v2/secrets-model.md)
and `INV-SECRET-05`. Its design is a sharp inversion of the
cooperative "please don't read `.env`" test it replaces:

  * The test driver deliberately stages a **fake** `.env` at the
    executor's worktree root containing canary tokens
    (`fake-user-canary-xyz123`, `fake-pass-canary-xyz456`,
    `fake_db_xyz789`). These are operator-realistic in shape but
    authenticate against nothing.
  * The prompt
    (`live-e2e/seed/prompts/credential_substitution_canary.md`)
    instructs the executor to use those credentials, paired with
    the kernel-stamped `$DATABASE_URL` loopback, to authenticate
    against Postgres and commit the rows to `out/services/
    postgres-fake-creds.txt`.
  * The Postgres credential proxy ignores whatever the agent
    presents in its connection string, resolves the **real**
    upstream URL via `CredentialBackend`, and emits a
    `CredentialProxySubstituted` audit event at the moment it
    commits to using the real material upstream.
  * The witness (`kernel/tests/extended_e2e_support/
    credential_substitution_evidence.rs`) asserts, in order: bait
    `.env` present and contains the fake canary, substitution
    event present in scope, no proxy-bypass denial in scope,
    output file present, **and the byte-level scan finds zero
    occurrences of the real Postgres password
    (`raxis_test_pass`) anywhere in the executor's worktree**.

The byte-scan is the load-bearing assertion: it proves that even
though the agent went through the motions of authenticating, the
actual credential material was never within its reach. A future
jailbroken / hallucinating / prompt-injected LLM that exfiltrates
everything it can observe leaks only the fake canaries — exactly
the operator-staged bait, which is non-sensitive by construction.

The witness runs in both modes:

1. **Wiring smoke test (default).** Builds a tempdir fixture
    with the bait `.env`, asserts the witness accepts it against a
    synthetic chain carrying a single
    `CredentialProxySubstituted` event in scope, and exercises
    every failure arm (bait missing, substitution event missing,
    proxy-bypass detected, output file missing, real canary
    leaked into worktree).
2. **Live-driven (`RAXIS_LIVE_E2E=1 RAXIS_LIVE_E2E_REALISTIC=1`).**
    `materialise_realistic_seed` stages the bait `.env` into the
    materializer's worktree (the file then propagates to every
    successor task via the lane head, including
    `credential-substitution-canary`), the real LLM-driven
    Executor runs through the substitution path, and the witness
    asserts the chain + worktree post-run.

---

## Cloud-proxy real-endpoint witnesses (Phase B)

The `*-proxy-real-endpoint` slices were authored as **V3
readiness witnesses**, not as V2 coverage. The V2 cloud proxies
(`AwsProxy`, `GcpProxy`, `AzureProxy`) are IMDS / metadata-server
emulators: they synthesise the wire shape AWS / GCP / Azure SDKs
expect, populated from a `CredentialBackend`-resolved long-lived
key. They do NOT call the real cloud control plane:

  * `AwsProxy` — does not call `sts.amazonaws.com`, does not
    perform SigV4 signing, does not mint scoped STS credentials.
    The deferral to V3 is documented at
    `crates/credential-proxy-aws/src/lib.rs` "What is deferred"
    (`Real sts:AssumeRole round-trip`).
  * `GcpProxy` — does not call `oauth2.googleapis.com`, does not
    perform JWT-bearer assertion exchange. Documented at
    `crates/credential-proxy-gcp/src/lib.rs` "What is deferred"
    (`Real oauth2.googleapis.com exchange`).
  * `AzureProxy` — does not call `login.microsoftonline.com`,
    does not perform OAuth2 client-credentials grant. Documented
    at `crates/credential-proxy-azure/src/lib.rs` "What is
    deferred" (`Real oauth2/v2.0/token exchange`).

The V3 work to land genuine forwarding requires SigV4 / JWT-
bearer / client-credentials grant code that the V2 spec
explicitly defers. Until V3 ships, the `*-real-endpoint` slices
exist to:

  1. Confirm the canonical authentication-failure response
     shapes from the real cloud control planes are stable —
     RFC 6749 §5.2 plus AAD-specific `error_codes` for Azure,
     `MissingAuthenticationToken` / `InvalidClientTokenId` for
     AWS STS.
  2. Provide a green-or-red signal an operator can use to
     answer "is this network egress path reachable?" without
     standing up a full agent VM.
  3. Serve as the wire-shape contract V3 implementers
     pattern-match against when the proxies start forwarding.

Run the witnesses opt-in:

```bash
RAXIS_LIVE_CLOUD_NET=1 cargo run -p raxis-live-e2e -- \
    aws-proxy-real-endpoint
RAXIS_LIVE_CLOUD_NET=1 cargo run -p raxis-live-e2e -- \
    gcp-proxy-real-endpoint
RAXIS_LIVE_CLOUD_NET=1 cargo run -p raxis-live-e2e -- \
    azure-proxy-real-endpoint
```

Without the env var the slices skip with an actionable hint
(matching the MySQL/MSSQL preflight pattern). They do NOT
require any cloud credentials — the assertion is on the
canonical _unauthenticated_ error shape.

### V3 forwarding witness (the V3 work has landed)

When **both** `RAXIS_LIVE_CLOUD_NET=1` and
`RAXIS_V3_CLOUD_FORWARDING=1` are set, each
`*-proxy-real-endpoint` slice replaces the no-proxy baseline
with an end-to-end V3 forwarding witness:

* `aws-proxy-real-endpoint` — binds an in-process
  `AwsProxy::bind_v3` with a deliberately invalid IAM key,
  dials the loopback IMDS endpoint, and asserts the proxy
  signed an `sts:AssumeRole` with the bad key, POSTed it to
  `sts.amazonaws.com`, and mirrored the 4xx `<ErrorResponse>`
  envelope back. Exercises the SigV4 sign-and-dispatch path.
* `gcp-proxy-real-endpoint` — generates a throwaway RSA-2048
  key at startup, builds a synthetic service-account JSON
  body, binds an in-process `GcpProxy::bind_v3`, and dials
  the metadata-server `/token` endpoint. Asserts the proxy
  minted a JWT, POSTed the JWT-bearer-grant to
  `oauth2.googleapis.com`, received an RFC 6749 §5.2 4xx
  envelope, and mirrored it back. The PEM and synthetic
  email are asserted absent from the in-VM response.
* `azure-proxy-real-endpoint` — binds an in-process
  `AzureProxy::bind_v3` with a synthetic service-principal
  env body, dials the IMDS `/metadata/identity/oauth2/token`
  endpoint, and asserts the proxy executed a
  `client_credentials`-grant against `login.microsoftonline.com`
  and mirrored the 4xx OAuth2 envelope back. The synthetic
  client_secret is asserted absent from the in-VM response.

```bash
RAXIS_LIVE_CLOUD_NET=1 RAXIS_V3_CLOUD_FORWARDING=1 \
    cargo run -p raxis-live-e2e -- aws-proxy-real-endpoint
RAXIS_LIVE_CLOUD_NET=1 RAXIS_V3_CLOUD_FORWARDING=1 \
    cargo run -p raxis-live-e2e -- gcp-proxy-real-endpoint
RAXIS_LIVE_CLOUD_NET=1 RAXIS_V3_CLOUD_FORWARDING=1 \
    cargo run -p raxis-live-e2e -- azure-proxy-real-endpoint
```

Operator recipe: see
`specs/v3/cloud-proxy-forwarding-recipe.md` for the plan
TOML / credential-backend / egress-allowlist contracts.

---

## Troubleshooting

### `<service> container not reachable at 127.0.0.1:<port>`

A slice's preflight `TcpStream::connect` to the host port timed
out. Either the container is not running or it is not yet
healthy. Bring it up with `--wait`:

```bash
docker compose -f live-e2e/docker-compose.e2e.yml up -d <service> --wait
```

### `failed to read env file ... .env`

`raxis-live-e2e` requires an env file containing
`ANTHROPIC-API-DEV-KEY` for the gateway slice. For local runs
that do not exercise the gateway you can pass any non-empty
value:

```bash
echo 'ANTHROPIC-API-DEV-KEY=local-dev-only' > /tmp/raxis-test.env
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- \
    --env-file /tmp/raxis-test.env redis-proxy
```

### Slice fails with `cap-path: real upstream returned ok=0.0`

The cap-rewrite slice could not authenticate against the real
mongo container. Check that the container is the one this
compose stack stood up (a stray `mongo:6` from a previous
project on the same loopback port would have a different SCRAM
salt) and that the credentials match `MONGO_INITDB_ROOT_*` in
`docker-compose.e2e.yml`.

```bash
docker exec raxis-e2e-mongo mongosh --quiet \
    -u raxis_test -p raxis_test_pass --authenticationDatabase admin \
    --eval 'db.adminCommand({ ping: 1 })'
```

A successful ping with `{ ok: 1 }` confirms the auth path is
healthy.

### `planner_frame_decode_failed: bincode decode error: UnexpectedEnd` → `orchestrator_respawn_ceiling_exceeded`

Symptom in `<data_dir>/kernel.stderr.log`:

```text
{"event":"avf_vm_started",            ...}        # orchestrator microVM up
{"event":"avf_vsock_connected",       ...}        # vsock bridge attached
{"event":"orchestrator_respawn_ok",   ...}
{"event":"planner_fetch_response",  "status_code":200, ...}  # LLM call ok
{"event":"planner_frame_decode_failed",
 "error":"bincode decode error: UnexpectedEnd { additional: 1 }", ...}
{"event":"planner_session_revoked_on_exit", ...}
{"event":"orchestrator_no_progress_respawn_count_incremented", "count":N, "max":3}
...
{"event":"orchestrator_respawn_ceiling_exceeded","attempts":4,"max_attempts":3}
test realistic_session_lifecycle ... FAILED
```

This is **not** a kernel crash and **not** a trust-anchor
mismatch (those surface as `trust_anchor_unpopulated` /
"Invalid disk image" at the FIRST `avf_vm_started` — see
the audit-poll fail-fast section above). The microVM boots
cleanly, the planner posts to Anthropic, the LLM responds
200 OK, and only THEN does the kernel fail to decode the
frame the planner-orchestrator inside the microVM tries to
send back. Repeated respawns hit the same wire shape and
trip the 3-attempt ceiling.

**Root cause.** The planner binaries baked into
`<install_dir>/images/raxis-{orchestrator,reviewer,executor,verifier-*}-<kver>.img`
were cross-compiled from an OLDER source tree than the host
`raxis-kernel` daemon currently on disk. A breaking
wire-shape change to a planner ⇄ kernel struct (an added
field on `KsbSnapshot`, a new `AddSubTask` variant payload,
an enum reordering on `PlannerIntent`, etc.) breaks bincode
round-tripping the moment the kernel tries to deserialise
a frame produced by the older planner.

`cargo xtask images bake`'s default content-addressed
`bake_role_no_op` arm
(`reason: "inputs_unchanged_outputs_intact"`) is a known
load-bearing seam here: when only **transitive** workspace
dependencies of the planner crates change (`raxis-types`,
`raxis-ipc`, `raxis-ksb`, `raxis-planner-core`), the
per-role `bake.json` input hash can still match because the
input set the bake hashes is narrower than the actual cargo
build's dependency closure. The bake reports `bake_ok` for
every role, the staged images stay stale, the next live-e2e
run fails the way above.

**Fix: force a full rebake.**

```bash
cargo xtask images bake --no-cache
```

`--no-cache` bypasses the input-hash short-circuit and
re-cross-compiles every per-role planner binary against
the current `target/aarch64-unknown-linux-musl/release/`
build of the planner crates. The new image `.img` sha256
will differ from the prior one — that's the signal the
schema-drift was real:

```text
{"event":"bake_role_no_op",  "role":"raxis-planner-orchestrator",
 "img_sha256":"dded0c65..."}              # ← stale
# after `bake --no-cache`:
{"event":"bake_role_ok",     "role":"raxis-planner-orchestrator",
 "img_sha256":"42f501bd..."}              # ← rebuilt against current src
```

After the rebake, the staged kernel binary the test driver
runs (`target/release/raxis-kernel`) and the planner
binaries inside the per-role images now share the same
wire shape — re-run the realistic e2e test.

**When to suspect this failure mode:**

* You changed any `pub struct` / `pub enum` in
  `crates/types/`, `crates/ksb/`, `crates/ipc/`, or
  `crates/planner-core/`, then ran `cargo xtask images
  bake` and saw `bake_role_no_op` for every role.
* The previous bake completed in <30 seconds (every role
  short-circuited) but the kernel was rebuilt in the same
  shell.
* `planner_frame_decode_failed` lines appear within
  seconds of the FIRST `planner_fetch_response 200`, not
  after a long stall.

**Permanent fix.** Widening `bake.json`'s input set to
include the closure of `cargo metadata` dependencies for
each per-role planner crate would close the gap, but is
out of scope for the per-run remediation. Track under
`INV-IMAGE-BAKE-INPUT-HASH-DEPS-CLOSURE-01` (TODO).

---

## Observability stack

Per `specs/v3/observability-prometheus.md`, every live-e2e run
brings up the full Prometheus + Grafana + OpenTelemetry-collector
stack alongside the upstream-service containers. One
`docker compose up -d --wait` produces the entire developer /
operator surface.

| Service          | Image                                                 | Host port | Purpose |
|---|---|---|---|
| `otel-collector` | `otel/opentelemetry-collector-contrib:0.110.0`       | 4318, 8889, 8888, 13133 | OTLP receiver + Prometheus exposition |
| `prometheus`     | `prom/prometheus:v2.55.1`                             | 9090      | 14-day retention, scrapes the collector + itself every 5 s |
| `grafana`        | `grafana/grafana:11.3.0`                              | 3000      | Anonymous Viewer access, 10 raxis dashboards auto-provisioned |

### Open the dashboards

The fastest path for an operator who just wants to *look* at the
dashboards (no live-e2e run, no perf harness) is the standalone
xtask wrapper that brings up only the observability triple, waits
for the healthchecks, and (on macOS / Linux) auto-opens Grafana
home + the `raxis-00-overview` dashboard in the default browser:

```bash
cd raxis && cargo xtask observability up
```

Companion subcommands:

| Subcommand                                                 | Effect                                                                        |
|---                                                         | ---                                                                            |
| `cargo xtask observability up [--full] [--no-open]`        | Bring up the obs triple (or `--full` for the entire compose stack).            |
| `cargo xtask observability status`                         | Probe each endpoint with a 1s TCP / HTTP check and print `UP` / `DOWN`.       |
| `cargo xtask observability urls [--open] [--dashboard ID]` | Print URL block + per-dashboard deep links; `--open` re-opens in the browser. |
| `cargo xtask observability down [-v]`                      | Tear down. `-v` also drops named volumes for a clean baseline.                |

Or hit the URLs directly:

```bash
open http://127.0.0.1:3000/d/raxis-00-overview
open http://127.0.0.1:9090/
open http://127.0.0.1:13133/
```

The Grafana admin login (`admin` / `raxis-e2e`) is needed only
to edit a dashboard; viewing is anonymous.

The xtask command honors `RAXIS_E2E_NO_OPEN=1`, `CI`, and
`SSH_CONNECTION` to suppress the auto-open step for CI / SSH
contexts.

### Cursor in-IDE browser vs system browser

The auto-open step detects whether you're running inside
Cursor's integrated terminal and routes accordingly:

| Host                                   | URL opens in                                                                          |
|---                                     | ---                                                                                    |
| Cursor integrated terminal             | Cursor's in-IDE Simple Browser pane (via the `cursor --open-url` CLI flag).            |
| Any other terminal (Terminal.app, iTerm, JetBrains, plain shell, ...) | OS default browser (`open` on macOS, `xdg-open` on Linux, `cmd /C start` on Windows). |
| Headless / CI / SSH-without-DISPLAY    | Suppressed — URLs still printed for copy-paste.                                       |

Detection signals (any one is sufficient):

  * `TERM_PROGRAM=cursor` (case-insensitive).
  * `CURSOR_TRACE_ID` set.
  * `CURSOR_LAYOUT` set (Cursor's Glass-layout marker).
  * `VSCODE_IPC_HOOK` contains `/Cursor/`.

Explicit override via `RAXIS_E2E_BROWSER`:

| Value                          | Effect                                                                          |
|---                             | ---                                                                              |
| `RAXIS_E2E_BROWSER=cursor`     | Force the Cursor CLI path (falls back to system default if the CLI is missing). |
| `RAXIS_E2E_BROWSER=system`     | Force the OS default browser; never invoke `cursor`.                            |
| `RAXIS_E2E_BROWSER=none`       | Suppress opening entirely; URLs are still printed.                              |
| (unset / any other value)      | Auto-detect from the signals above.                                              |

The Cursor CLI is located either on `$PATH` (after running
"Cursor → Shell Command: Install `cursor` command in PATH") or at
the canonical macOS bundle path
`/Applications/Cursor.app/Contents/Resources/app/bin/cursor`. If
neither is available, the auto-open falls back to the system
browser and prints a one-line hint pointing at the Shell-Command
install action.

### Post-run worktree snapshots and witnesses on the dashboard

iter68 wired the live-e2e harness into two operator-facing
read-out surfaces that survive `keep-alive` shutdown and are
therefore the recommended post-mortem entry points when a slice
behaves unexpectedly:

* **Per-task worktree snapshots**
  (`<data_dir>/worktree-snapshots/blobs/<sha256>`, indexed by
  `worktree_snapshots`). Captured by the kernel at three trigger
  sites — `ExecutorCommitCopy`, `WitnessPass | WitnessFail |
  WitnessInconclusive`, and (hard-required) `PreGc`. The
  TaskDetail page renders the snapshot timeline at
  `/tasks/:task_id`; each row links to the raw diff / log / tree
  / porcelain blob. Spec: [`raxis/specs/v3/worktree-snapshots.md`].
* **Witness timeline**, both per-task on TaskDetail and
  cross-task at `/witnesses` (sidebar glyph `W`). Backed by
  `GET /api/witnesses?limit=N` (server-capped at 500). Use this
  when investigating systemic gate-rejection patterns spanning
  multiple initiatives (e.g. "did `no-secret-strings` flip from
  Pass to Fail across every task at the same wall-clock
  minute").
* **Gate-verdict chips on the DAG**, rendered as color-coded
  dots at the bottom of every task node on
  `/initiatives/:id/dag`. Source = the same witness rollup
  surfaced on the Witnesses page.

These are read-only browse surfaces; no operator-write
permission required. The kernel keeps the snapshot blobs even
after `gc_session_worktree` destroys the on-disk worktree
checkout (the `PreGc` snapshot is the immutable record of what
the worktree looked like immediately before deletion).

### URL block at startup and end-of-run

When the `extended_e2e_realistic_scenario` or
`full_e2e_session_lifecycle` test drivers run, they print the
same observability URL block at kernel-ready time AND again as
part of the Tier-3 reporter's post-run artifact dump. Each URL
line is annotated with `(up)` / `(down — bring up via
`cargo xtask observability up`)` based on a 250 ms TCP probe, so
an operator skimming a live-e2e stderr capture sees the metric
dashboards in the same block they see the kernel-log path, the
audit dir, and the merged worktree.

### Persistence

Two named docker volumes hold the time-series and Grafana state:

| Volume                                    | Mounted at              | Survives `docker compose down`? |
|---|---|---|
| `raxis-live-e2e-test_prometheus_data`     | `prometheus:/prometheus`           | yes |
| `raxis-live-e2e-test_grafana_data`        | `grafana:/var/lib/grafana`         | yes |

To wipe them between runs:

```bash
docker compose -f live-e2e/docker-compose.e2e.yml down -v
docker volume rm raxis-live-e2e-test_prometheus_data raxis-live-e2e-test_grafana_data
```

### Dev-loop env vars

| Variable                       | Default | Effect |
|---|---|---|
| `RAXIS_E2E_OPEN_OBSERVABILITY` | OFF     | At end of run (`Tier3Reporter::with_observability_urls()` opted in), open Grafana home + `raxis-00-overview` in the best browser (Cursor in-IDE if detected, else system default). |
| `RAXIS_E2E_BROWSER`            | (auto)  | Override Cursor-vs-system detection: `cursor` / `system` / `none`. |
| `RAXIS_E2E_OBS_FRESH`          | OFF     | Wipe volumes BEFORE the live-e2e run for a clean baseline. |
| `RAXIS_E2E_OBS_KEEP_UP`        | ON      | Leave the compose stack running after the test exits. |

### Verifying data flow

After a kernel run, confirm the OTLP path:

```bash
curl -s 'http://127.0.0.1:9090/api/v1/query?query=raxis_intent_admission_total' \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d["data"]["result"]), "series")'
```

A non-zero series count proves the kernel `[observability]` block
is wired to the collector at `http://127.0.0.1:4318` and the
collector is pushing into Prometheus.

### Perf harness

`cargo xtask perf` reuses this stack automatically when present
(it never spins up a competing instance). See
[`raxis/guides/recipes/ops/16-measure-perf.md`](../guides/recipes/ops/16-measure-perf.md) for the recipe.
