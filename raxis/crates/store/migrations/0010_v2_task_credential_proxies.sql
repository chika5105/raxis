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

-- ── Table: task_credential_proxies ───────────────────────────────────────
-- METADATA ONLY. One row per [[tasks.credentials]] block per task,
-- describing WHICH credential proxy should be bound for that task.
--
-- ⚠ Credential VALUES (passwords, tokens, kubeconfig bytes, etc.)
--   are NEVER stored in this table — or anywhere else in kernel.db.
--   They live with the kernel's CredentialBackend
--   (FileCredentialBackend on disk with 0600 perms; or a VaultBackend
--   / AwsSecretsManagerBackend in production).
--
--   * task_id          — FK to tasks(task_id).
--   * credential_name  — the policy-declared NAME of the credential
--                        the proxy will resolve at bind time
--                        (e.g. "db-prod"). NOT the secret bytes.
--   * mount_as         — the env-var the proxy injects into the
--                        agent VM (e.g. "DB_URL").
--   * proxy_type       — postgres | http | k8s | smtp. CHECK-pinned.
--   * proxy_json       — the per-proxy restriction blob (allow-lists,
--                        upstream URL, etc.). NOT the secret bytes.
--
-- Inserted by approve_plan in the same transaction that admits the
-- parent task. Read once at session-spawn time by
-- CredentialProxyManager.
-- See credential-proxy.md §3 and v2-deep-spec.md §Step 17.
CREATE TABLE IF NOT EXISTS task_credential_proxies (
    task_id              TEXT    NOT NULL
        REFERENCES tasks(task_id),
    credential_name      TEXT    NOT NULL,
    mount_as             TEXT    NOT NULL,
    proxy_type           TEXT    NOT NULL
        CHECK (proxy_type IN ('postgres', 'http', 'k8s', 'smtp', 'redis', 'aws', 'gcp', 'azure')),
    proxy_json           TEXT    NOT NULL,
    created_at_unix_secs INTEGER NOT NULL,
    PRIMARY KEY (task_id, credential_name)
);

-- Lookup index. CredentialProxyManager queries by task_id at
-- session-spawn time; the composite PK already covers this prefix
-- but the explicit index makes the query plan self-documenting in
-- EXPLAIN output and survives any future PK refactor.
CREATE INDEX IF NOT EXISTS idx_task_credential_proxies_task_id
    ON task_credential_proxies (task_id);

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (10, strftime('%s', 'now'));

COMMIT;
