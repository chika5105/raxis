# `crates/store/migrations/` — auto-generated kernel.db DDL

This directory contains the rendered SQL output of every migration that
`raxis-store::migration::apply_pending` walks at startup. The files
are committed for documentation parity with the Rust code (which is
the source of truth) so:

* Operators auditing the on-disk SQLite schema can read a single
  self-contained `.sql` per migration without learning the kernel's
  `format!`-based DDL composer.
* `raxis doctor schema` and air-gapped review tools can diff the
  committed `.sql` against the running database without a Rust
  toolchain on the audit host.
* Forensic reviewers tracing a regression to a schema change can
  point at one filename per change instead of grepping a 4 KLOC Rust
  module.

## Naming

`{NNNN}_{slug}.sql`, four-digit zero-padded migration version, slug
chosen for descriptiveness. The version-number prefix is the source
of truth — slug renames are safe so long as the file rename + the
`slug()` table in `tests/migration_sql_dumps.rs` stay in sync.

## Source of truth

`crates/store/src/migration.rs` is authoritative. `raxis-store::
migration::render_migration_N_ddl()` produces the bytes; this
directory's `.sql` files are the rendered output.

## Regenerating

When a migration's DDL changes (typically: a new column, a
tightened CHECK list, a new index, or a brand-new migration_N+1):

```bash
RAXIS_DUMP_MIGRATION_SQL=1 cargo test -p raxis-store --test migration_sql_dumps
```

The test rewrites the matching `.sql` files with the freshly-rendered
DDL. Commit the regenerated files alongside the Rust change so the
Rust source and the documentation `.sql` stay in step.

## Drift detection

The default test run (no env var) compares every committed `.sql` to
its `render_migration_N_ddl()` output byte-for-byte. CI fails if a
maintainer edits a migration in Rust without re-running the dumper.

## V2 schema map

Migrations 5–10 carry the V2 deep-spec schema additions:

| Version | What it adds | Specs |
|--------:|-------------|------|
| 5  | `sessions.{session_agent_type, can_delegate, vsock_cid}` columns + `subtask_activations` table | `v2-deep-spec.md §Step 5`, `INV-DELEGATE-01` |
| 6  | `tasks.last_critique` column for V2 critique routing | `v2-deep-spec.md §Step 22 / §Step 25` |
| 7  | `tasks.review_verdict` column for parallel reviewer aggregation | `v2-deep-spec.md §Step 25` |
| 8  | `plan_bundles`, `plan_bundle_artifacts`, `plan_bundle_nonces_seen` (V2 plan-bundle sealing) | `plan-bundle-sealing.md §8.2` |
| 9  | `tasks.{clone_strategy, base_sha}` columns for sparse-clone provisioning | `v2-deep-spec.md §Step 7`, `clone-strategies.md` |
| 10 | `task_credential_proxies` table | `credential-proxy.md §3` |

## Why not pure SQL migrations?

The kernel's CHECK constraints reference `raxis_types` enum value
strings (`InitiativeState::ALL`, `TaskState::ALL`, ...) so their SQL
must stay in lockstep with the Rust enum definitions. A
maintainer-edited `.sql` would silently drift from the enum on the
next variant addition. The Rust composer + drift-detection test is
the only model that keeps the two in sync.
