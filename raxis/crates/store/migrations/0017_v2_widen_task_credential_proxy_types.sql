-- ┌──────────────────────────────────────────────────────────────────────┐
-- │ Auto-generated from raxis_store::migration::render_migration_N_ddl. │
-- │ DO NOT EDIT BY HAND.                                                │
-- │                                                                     │
-- │ Source of truth: crates/store/src/migration.rs                      │
-- │ Regenerate:      RAXIS_DUMP_MIGRATION_SQL=1 cargo test               │
-- │                  -p raxis-store --test migration_sql_dumps           │
-- │ Drift detector:  cargo test -p raxis-store --test migration_sql_dumps│
-- └──────────────────────────────────────────────────────────────────────┘

BEGIN EXCLUSIVE;

-- 1. Build the rebuilt table under a temporary name with the widened
--    CHECK. Column order, types, and constraints mirror the original
--    DDL (migration 10) modulo the `proxy_type` whitelist.
CREATE TABLE task_credential_proxies_new (
    task_id              TEXT    NOT NULL
        REFERENCES tasks(task_id),
    credential_name      TEXT    NOT NULL,
    mount_as             TEXT    NOT NULL,
    proxy_type           TEXT    NOT NULL
        CHECK (proxy_type IN (
            'postgres', 'http', 'k8s', 'smtp', 'redis',
            'aws',      'gcp',  'azure',
            'mysql',    'mssql', 'mongodb'
        )),
    proxy_json           TEXT    NOT NULL,
    created_at_unix_secs INTEGER NOT NULL,
    PRIMARY KEY (task_id, credential_name)
);

-- 2. Copy every existing row over. Pre-migration rows by definition
--    pass the original (narrower) CHECK so they pass the widened
--    CHECK trivially.
INSERT INTO task_credential_proxies_new
    (task_id, credential_name, mount_as, proxy_type, proxy_json,
     created_at_unix_secs)
SELECT task_id, credential_name, mount_as, proxy_type, proxy_json,
       created_at_unix_secs
  FROM task_credential_proxies;

-- 3. Drop the old table (also drops the old index).
DROP TABLE task_credential_proxies;

-- 4. Rename the rebuilt table into place.
ALTER TABLE task_credential_proxies_new RENAME TO task_credential_proxies;

-- 5. Recreate the lookup index. CredentialProxyManager queries by
--    task_id at session-spawn time; the composite PK already covers
--    this prefix but the explicit index makes the query plan
--    self-documenting and survives any future PK refactor.
CREATE INDEX IF NOT EXISTS idx_task_credential_proxies_task_id
    ON task_credential_proxies (task_id);

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (17, strftime('%s', 'now'));

COMMIT;
