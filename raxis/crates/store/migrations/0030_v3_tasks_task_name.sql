BEGIN EXCLUSIVE;

-- kernel-owned task ids -- plan authors provide task_name; the kernel
-- generates tasks.task_id as an internal UUID. Existing rows are
-- backfilled with task_id so historical dashboards and CLI views have
-- a stable display label.
ALTER TABLE tasks
    ADD COLUMN task_name TEXT;

UPDATE tasks
   SET task_name = task_id
 WHERE task_name IS NULL OR task_name = '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_tasks_initiative_task_name
    ON tasks (initiative_id, task_name);

CREATE INDEX IF NOT EXISTS idx_tasks_task_name
    ON tasks (task_name);

INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (30, strftime('%s', 'now'));

COMMIT;
