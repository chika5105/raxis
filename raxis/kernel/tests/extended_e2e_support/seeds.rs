//! Seed-fixture loaders + DB connectivity preflight for the
//! extended e2e scenario.
//!
//! No new Rust DB driver dependencies — we shell out to `psql` and
//! `mongosh`, which are reliably present on the kind of host that
//! already runs `RAXIS_LIVE_E2E=1` (it must have `docker compose`
//! installed, which on every supported platform brings the
//! standard CLI tools alongside).
//!
//! The canonical expected JSON files are embedded at compile time
//! via `include_str!`, so the test binary never depends on a
//! runtime path to `live-e2e/seed/expected/`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;

/// `live-e2e/docker-compose.extended.e2e.yml` pins these.
pub const PG_HOST_PORT:    &str = "127.0.0.1:54399";
pub const MONGO_HOST_PORT: &str = "127.0.0.1:27399";
pub const PG_USER:         &str = "raxis_test";
pub const PG_PASSWORD:     &str = "raxis_test_pass";
pub const PG_DATABASE:     &str = "raxis_e2e_pg";
pub const MONGO_USER:      &str = "raxis_test";
pub const MONGO_PASSWORD:  &str = "raxis_test_pass";
pub const MONGO_DATABASE:  &str = "raxis_e2e_mongo";

/// Expected count for each seeded data source. Matched against the
/// actual count in `verify_seed_counts_or_skip`.
pub const EXPECTED_PG_ROWS:   usize = 25;
pub const EXPECTED_MONGO_DOCS: usize = 25;

// ---------------------------------------------------------------------------
// Canonical expected JSON — embedded at compile time.
// ---------------------------------------------------------------------------

/// Raw bytes of `live-e2e/seed/expected/postgres_rows.json`.
/// Embedded via `include_str!` so the test binary needs no runtime
/// filesystem path to the seed directory. The byte-stable canonical
/// expected output is the witness oracle.
pub const POSTGRES_ROWS_JSON: &str = include_str!(
    "../../../live-e2e/seed/expected/postgres_rows.json"
);

/// Raw bytes of `live-e2e/seed/expected/mongo_docs.json`.
pub const MONGO_DOCS_JSON: &str = include_str!(
    "../../../live-e2e/seed/expected/mongo_docs.json"
);

// ---------------------------------------------------------------------------
// Typed expected-record shapes.
// ---------------------------------------------------------------------------

/// One canonical postgres row. Field order matches the on-disk JSON
/// emitted by `materialize-records`; equality is structural.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExpectedPgRow {
    pub id:         String,
    pub payload:    serde_json::Value,
    pub created_at: i64,
}

/// One canonical mongo document. Note the `_id_hex` field — the
/// materializer prompt instructs the executor to normalise the
/// source `ObjectId` to a 24-char lowercase hex string.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExpectedMongoDoc {
    #[serde(rename = "_id_hex")]
    pub id_hex:     String,
    pub doc_id:     String,
    pub payload:    serde_json::Value,
    pub created_at: i64,
}

/// Decode the embedded canonical postgres expected JSON. Panics on
/// malformed JSON because the file is committed to the repository
/// and a parse failure is a build-time fixture-drift problem the
/// test surfaces immediately.
pub fn expected_postgres_rows() -> Vec<ExpectedPgRow> {
    serde_json::from_str(POSTGRES_ROWS_JSON)
        .expect("expected/postgres_rows.json is valid JSON (embedded fixture drift)")
}

/// Decode the embedded canonical mongo expected JSON.
pub fn expected_mongo_docs() -> Vec<ExpectedMongoDoc> {
    serde_json::from_str(MONGO_DOCS_JSON)
        .expect("expected/mongo_docs.json is valid JSON (embedded fixture drift)")
}

/// Index `expected_postgres_rows()` by `id` for O(1) lookups in the
/// witness validator.
pub fn expected_pg_by_id() -> BTreeMap<String, ExpectedPgRow> {
    expected_postgres_rows()
        .into_iter()
        .map(|r| (r.id.clone(), r))
        .collect()
}

/// Index `expected_mongo_docs()` by `doc_id`.
pub fn expected_mongo_by_doc_id() -> BTreeMap<String, ExpectedMongoDoc> {
    expected_mongo_docs()
        .into_iter()
        .map(|d| (d.doc_id.clone(), d))
        .collect()
}

// ---------------------------------------------------------------------------
// Preflight — verify the seed actually landed.
// ---------------------------------------------------------------------------

/// Resolved path to `live-e2e/seed/postgres/01-seed.sql`. Used by
/// the harness's reseed fallback for long-running containers.
pub fn pg_seed_script_path() -> PathBuf {
    workspace_root()
        .join("live-e2e")
        .join("seed")
        .join("postgres")
        .join("01-seed.sql")
}

/// Resolved path to `live-e2e/seed/mongo/01-seed.js`.
pub fn mongo_seed_script_path() -> PathBuf {
    workspace_root()
        .join("live-e2e")
        .join("seed")
        .join("mongo")
        .join("01-seed.js")
}

/// `<workspace>/raxis/`. Resolved from `CARGO_MANIFEST_DIR` at
/// compile time so the path is stable across the test binary's
/// runtime cwd. `CARGO_MANIFEST_DIR` for the kernel test binary
/// resolves to `<workspace>/raxis/kernel/`; we go up one to reach
/// `raxis/`.
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Verify the postgres seed via `psql -t -c 'SELECT COUNT(*) ...'`.
/// Panics with a remediation message on any failure.
pub fn verify_postgres_seed_count_or_panic() {
    let mut cmd = Command::new("psql");
    cmd.env("PGPASSWORD", PG_PASSWORD)
        .arg("--quiet")
        .arg("--tuples-only")
        .arg("--no-align")
        .arg(format!("postgresql://{PG_USER}@127.0.0.1:54399/{PG_DATABASE}"))
        .arg("-c")
        .arg("SELECT COUNT(*) FROM seeded_rows;")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().unwrap_or_else(|e| panic!(
        "spawn `psql` failed: {e}; install postgresql-client and re-run"
    ));
    if !out.status.success() {
        panic!(
            "psql preflight failed (exit {:?}): {}\n\
             remediation:\n  \
             1. docker compose -f live-e2e/docker-compose.extended.e2e.yml up -d --wait\n  \
             2. psql {PG_DATABASE} -h 127.0.0.1 -p 54399 -U {PG_USER} -f {script}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr),
            script = pg_seed_script_path().display(),
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let count: usize = stdout
        .lines()
        .find_map(|l| l.trim().parse::<usize>().ok())
        .unwrap_or_else(|| panic!(
            "psql returned no parseable count; stdout=\n{stdout}",
        ));
    assert_eq!(
        count, EXPECTED_PG_ROWS,
        "seeded_rows count drift: expected {EXPECTED_PG_ROWS}, got {count}; \
         re-apply the seed:\n  \
         psql {PG_DATABASE} -h 127.0.0.1 -p 54399 -U {PG_USER} -f {script}",
        script = pg_seed_script_path().display(),
    );
}

/// Verify the mongo seed via `mongosh --eval 'db.seeded_docs.countDocuments({})'`.
pub fn verify_mongo_seed_count_or_panic() {
    let uri = format!(
        "mongodb://{MONGO_USER}:{MONGO_PASSWORD}@127.0.0.1:27399/{MONGO_DATABASE}\
         ?authSource=admin",
    );
    let mut cmd = Command::new("mongosh");
    cmd.arg("--quiet")
        .arg(&uri)
        .arg("--eval")
        .arg("print(db.seeded_docs.countDocuments({}))")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().unwrap_or_else(|e| panic!(
        "spawn `mongosh` failed: {e}; install mongosh and re-run"
    ));
    if !out.status.success() {
        panic!(
            "mongosh preflight failed (exit {:?}): {}\n\
             remediation:\n  \
             1. docker compose -f live-e2e/docker-compose.extended.e2e.yml up -d --wait\n  \
             2. mongosh '{uri}' --file {script}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr),
            script = mongo_seed_script_path().display(),
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let count: usize = stdout
        .lines()
        .find_map(|l| l.trim().parse::<usize>().ok())
        .unwrap_or_else(|| panic!(
            "mongosh returned no parseable count; stdout=\n{stdout}",
        ));
    assert_eq!(
        count, EXPECTED_MONGO_DOCS,
        "seeded_docs count drift: expected {EXPECTED_MONGO_DOCS}, got {count}; \
         re-apply the seed:\n  \
         mongosh '{uri}' --file {script}",
        script = mongo_seed_script_path().display(),
    );
}

/// Run both DB-side preflights and additionally TCP-probe the
/// docker-compose ports. Cheap, safe to call before kernel boot;
/// each failure carries the matching `docker compose` remediation
/// hint.
pub fn preflight_or_panic() {
    require_tcp_reachable(PG_HOST_PORT, "postgres docker container");
    require_tcp_reachable(MONGO_HOST_PORT, "mongodb docker container");
    verify_postgres_seed_count_or_panic();
    verify_mongo_seed_count_or_panic();
}

fn require_tcp_reachable(host_port: &str, what: &str) {
    use std::net::TcpStream;
    use std::time::Duration;
    if TcpStream::connect_timeout(
        &host_port.parse().expect("static literal parses"),
        Duration::from_millis(500),
    ).is_err() {
        panic!(
            "{what} not reachable at {host_port}. Run:\n  \
             docker compose -f live-e2e/docker-compose.extended.e2e.yml up -d --wait",
        );
    }
}

/// Optional helper: re-apply both seed scripts via `psql` /
/// `mongosh` against a long-running container. Idempotent. Used
/// when an operator wants to refresh the seed mid-investigation
/// without `docker compose down -v`.
pub fn reseed_both_or_panic() {
    let pg_script = pg_seed_script_path();
    let pg_status = Command::new("psql")
        .env("PGPASSWORD", PG_PASSWORD)
        .arg("--quiet")
        .arg(format!("postgresql://{PG_USER}@127.0.0.1:54399/{PG_DATABASE}"))
        .arg("-f").arg(&pg_script)
        .status()
        .unwrap_or_else(|e| panic!("spawn psql for reseed failed: {e}"));
    assert!(
        pg_status.success(),
        "psql reseed failed: {pg_status:?}; script={}",
        pg_script.display(),
    );

    let mongo_script = mongo_seed_script_path();
    let mongo_uri = format!(
        "mongodb://{MONGO_USER}:{MONGO_PASSWORD}@127.0.0.1:27399/{MONGO_DATABASE}\
         ?authSource=admin",
    );
    let mongo_status = Command::new("mongosh")
        .arg("--quiet")
        .arg(&mongo_uri)
        .arg("--file").arg(&mongo_script)
        .status()
        .unwrap_or_else(|e| panic!("spawn mongosh for reseed failed: {e}"));
    assert!(
        mongo_status.success(),
        "mongosh reseed failed: {mongo_status:?}; script={}",
        mongo_script.display(),
    );
}

// ---------------------------------------------------------------------------
// Worktree path helpers — used by `MaterializationWitness`.
// ---------------------------------------------------------------------------

/// `<workdir>/out/postgres/`.
pub fn pg_output_dir(workdir: &Path) -> PathBuf {
    workdir.join("out").join("postgres")
}

/// `<workdir>/out/mongo/`.
pub fn mongo_output_dir(workdir: &Path) -> PathBuf {
    workdir.join("out").join("mongo")
}

// ---------------------------------------------------------------------------
// Tests — sanity-check the embedded fixtures decode correctly.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_expected_decodes_to_25_rows() {
        let rows = expected_postgres_rows();
        assert_eq!(rows.len(), EXPECTED_PG_ROWS);
        assert_eq!(rows[0].id, "row-0001");
        assert_eq!(rows[24].id, "row-0025");
        assert_eq!(rows[0].created_at, 1700000000);
    }

    #[test]
    fn mongo_expected_decodes_to_25_docs() {
        let docs = expected_mongo_docs();
        assert_eq!(docs.len(), EXPECTED_MONGO_DOCS);
        assert_eq!(docs[0].doc_id, "doc-0001");
        assert_eq!(docs[24].doc_id, "doc-0025");
        assert_eq!(docs[0].id_hex.len(), 24);
        assert!(docs[0].id_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn expected_indexers_keyed_correctly() {
        let pg = expected_pg_by_id();
        assert!(pg.contains_key("row-0013"));
        let mg = expected_mongo_by_doc_id();
        assert!(mg.contains_key("doc-0013"));
    }
}
