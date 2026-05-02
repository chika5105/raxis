// raxis-kernel::scheduler::admit — Plan-time task instantiation.
//
// Normative reference: kernel-core.md §2.3 `src/scheduler/admit.rs`.
//
// Called exclusively from `initiatives::lifecycle::approve_plan`.
// NOT called from the intent handler.
//
// Transaction (single store tx, per §2.3 Step 1–4):
//   Step 1: detect_cycle — pure read, returns CyclicDependency on violation
//   Step 2: INSERT task row in Admitted state (before edges, due to FK)
//   Step 3: insert_edges — insert task_dag_edges rows
//   Step 4: Emit TaskAdmitted audit event (log line in v1)
//
// Does NOT check or consume budget — that happens at intent time.

use raxis_store::Store;

use crate::scheduler::{dag, SchedulerError};

/// A task as derived from the plan artifact at approve_plan time.
///
/// Does NOT carry estimated_cost, touched_paths, or submitted_claims —
/// those are intent-time fields.
#[derive(Debug, Clone)]
pub struct PlanTask {
    pub task_id: String,
    pub initiative_id: String,
    pub lane_id: String,
    pub name: String,
    pub dependencies: Vec<String>,
}

/// Admit a task: insert it into the tasks table in Admitted state and
/// insert its DAG dependency edges.
///
/// Called exclusively from `initiatives::lifecycle::approve_plan`.
/// policy_epoch is the epoch from the currently loaded PolicyBundle.
pub fn admit(
    task: PlanTask,
    policy_epoch: u64,
    store: &Store,
) -> Result<String, SchedulerError> {
    // Step 1: Cycle detection (pure read).
    dag::detect_cycle(&task.task_id, &task.dependencies, store)?;

    let conn = store.lock_sync();
    let now = now_unix_secs();

    // Step 2: Insert task row in Admitted state.
    // FK on task_dag_edges → tasks requires the task row to exist first.
    conn.execute(
        "INSERT OR IGNORE INTO tasks
            (task_id, initiative_id, lane_id, name, state, admitted_at, policy_epoch, actual_cost)
         VALUES (?1, ?2, ?3, ?4, 'Admitted', ?5, ?6, 0)",
        rusqlite::params![
            &task.task_id,
            &task.initiative_id,
            &task.lane_id,
            &task.name,
            now,
            policy_epoch as i64,
        ],
    ).map_err(SchedulerError::Sql)?;

    // Step 3: Insert DAG edges.
    for dep_id in &task.dependencies {
        conn.execute(
            "INSERT OR IGNORE INTO task_dag_edges
                (predecessor_task_id, successor_task_id)
             VALUES (?1, ?2)",
            rusqlite::params![dep_id, &task.task_id],
        ).map_err(SchedulerError::Sql)?;
    }

    // Step 4: Emit TaskAdmitted audit event.
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"TaskAdmitted\",\"task_id\":\"{}\",\"lane_id\":\"{}\",\
         \"initiative_id\":\"{}\",\"dependency_count\":{}}}",
        task.task_id, task.lane_id, task.initiative_id, task.dependencies.len()
    );

    Ok(task.task_id)
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
