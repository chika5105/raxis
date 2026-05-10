//! Drift-detection + on-demand dumper for `crates/store/migrations/*.sql`.
//!
//! Normative reference: `kernel-store.md §2.5.1` declares Rust as the
//! authoritative source of every migration's DDL. The `.sql` files in
//! `crates/store/migrations/` are documentation artefacts that mirror
//! the rendered output of each `render_migration_N_ddl()`. They exist
//! so:
//!
//! * Operators auditing the on-disk SQLite schema can read a single
//!   self-contained file per migration without learning the kernel's
//!   `format!`-based DDL composer.
//! * `raxis doctor schema` and air-gapped review tools can diff the
//!   committed `.sql` against the running database without a Rust
//!   toolchain.
//!
//! ## Drift-detection contract
//!
//! By default this test re-renders every migration's DDL and compares
//! it byte-for-byte to the committed file at
//! `crates/store/migrations/{NNNN}_{slug}.sql`. A mismatch fails the
//! test with a diff summary so the maintainer notices the drift.
//!
//! ## Updating the .sql files
//!
//! When a migration's DDL changes (or a new migration is added), set
//! `RAXIS_DUMP_MIGRATION_SQL=1` and re-run this test. The test will
//! overwrite the matching `.sql` files with the freshly-rendered DDL
//! and pass. Commit the regenerated files alongside the Rust change.
//!
//! ## Why a single integration test (not per-migration)
//!
//! Keeps the dumper logic in one place and makes "ten files
//! refreshed" a single review unit. The per-migration test would
//! require ten separate `#[test]` fns and ten `.sql` files would
//! drift independently.

use std::path::PathBuf;

/// Maps a migration version to the slug suffix used in
/// `migrations/{NNNN}_{slug}.sql`. Slugs are descriptive but the
/// version-number prefix is the source of truth — slug renames are
/// safe so long as the `.sql` filename + this slice stay in sync.
fn slug(version: u32) -> &'static str {
    match version {
        1  => "v1_baseline_kernel_db",
        2  => "v1x_operator_certificates",
        3  => "v1x_initiative_quarantines_and_signer",
        4  => "v1x_quarantined_at_index",
        5  => "v2_session_schema",
        6  => "v2_tasks_last_critique",
        7  => "v2_tasks_review_verdict",
        8  => "v2_plan_bundle_sealing",
        9  => "v2_clone_strategy_columns",
        10 => "v2_task_credential_proxies",
        11 => "v2_integration_merge_attempts",
        12 => "v25_tasks_token_usage",
        13 => "v32_structured_outputs",
        14 => "v2_notifications",
        15 => "v2_provider_circuit_state",
        _  => panic!("no slug registered for migration version {version}"),
    }
}

fn render(version: u32) -> String {
    use raxis_store::migration::*;
    match version {
        1  => render_migration_1_ddl(),
        2  => render_migration_2_ddl(),
        3  => render_migration_3_ddl(),
        4  => render_migration_4_ddl(),
        5  => render_migration_5_ddl(),
        6  => render_migration_6_ddl(),
        7  => render_migration_7_ddl(),
        8  => render_migration_8_ddl(),
        9  => render_migration_9_ddl(),
        10 => render_migration_10_ddl(),
        11 => render_migration_11_ddl(),
        12 => render_migration_12_ddl(),
        13 => render_migration_13_ddl(),
        14 => render_migration_14_ddl(),
        15 => render_migration_15_ddl(),
        _  => panic!("no renderer registered for migration version {version}"),
    }
}

fn migrations_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations")
}

fn sql_path(version: u32) -> PathBuf {
    migrations_dir().join(format!("{:04}_{}.sql", version, slug(version)))
}

const HEADER: &str = "\
-- ┌──────────────────────────────────────────────────────────────────────┐
-- │ Auto-generated from raxis_store::migration::render_migration_N_ddl. │
-- │ DO NOT EDIT BY HAND.                                                │
-- │                                                                     │
-- │ Source of truth: crates/store/src/migration.rs                      │
-- │ Regenerate:      RAXIS_DUMP_MIGRATION_SQL=1 cargo test               │
-- │                  -p raxis-store --test migration_sql_dumps           │
-- │ Drift detector:  cargo test -p raxis-store --test migration_sql_dumps│
-- └──────────────────────────────────────────────────────────────────────┘
";

fn wrap_with_header(rendered: &str) -> String {
    let mut out = String::with_capacity(HEADER.len() + rendered.len() + 1);
    out.push_str(HEADER);
    out.push('\n');
    out.push_str(rendered.trim_start_matches('\n'));
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

const VERSIONS: &[u32] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// Drift-detection: every committed `.sql` matches its
/// `render_migration_N_ddl()` output byte-for-byte. Set
/// `RAXIS_DUMP_MIGRATION_SQL=1` to regenerate.
#[test]
fn migration_sql_files_match_rendered_ddl() {
    let dir = migrations_dir();
    std::fs::create_dir_all(&dir).expect("ensure migrations dir exists");

    let dumping = std::env::var("RAXIS_DUMP_MIGRATION_SQL").is_ok();
    let mut drifted: Vec<String> = Vec::new();

    for &v in VERSIONS {
        let expected = wrap_with_header(&render(v));
        let path = sql_path(v);

        if dumping {
            std::fs::write(&path, &expected).expect("write migration sql");
            continue;
        }

        let observed = match std::fs::read_to_string(&path) {
            Ok(s)  => s,
            Err(_) => {
                drifted.push(format!(
                    "  - missing file: {} (run with RAXIS_DUMP_MIGRATION_SQL=1)",
                    path.display(),
                ));
                continue;
            }
        };
        if observed != expected {
            drifted.push(format!(
                "  - {} drifted from render_migration_{}_ddl()",
                path.display(),
                v,
            ));
        }
    }

    if dumping {
        // Summary so the maintainer sees the dump count in the test
        // log.
        eprintln!("RAXIS_DUMP_MIGRATION_SQL: refreshed {} files in {}",
            VERSIONS.len(), dir.display());
        return;
    }

    assert!(
        drifted.is_empty(),
        "committed migrations/*.sql disagrees with the Rust render functions:\n{}\n\n\
         Re-run with RAXIS_DUMP_MIGRATION_SQL=1 cargo test -p raxis-store \
         --test migration_sql_dumps to refresh, then commit the updated files.",
        drifted.join("\n"),
    );
}

/// Sanity-check the slug registry covers the same set of versions
/// that `apply_pending` walks. Pin against accidental drift between
/// the renderer dispatch table and the slug table.
#[test]
fn slug_registry_covers_every_known_migration_version() {
    for &v in VERSIONS {
        let s = slug(v);
        assert!(!s.is_empty(), "slug must be non-empty for version {v}");
        // Render must succeed for every version covered by the slug
        // table — catches a future "new migration_11 added but slug
        // not registered" drift.
        let _ = render(v);
    }
}
