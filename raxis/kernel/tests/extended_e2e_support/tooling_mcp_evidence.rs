//! Tooling / MCP evidence witness for the realistic primary plan.
//!
//! The standalone live-e2e `tooling-mcp-unity` slice proves the
//! planner-core custom-tool loader can wrap an MCP-like local
//! service. This module pins the same operator-facing pattern
//! inside the full realistic primary initiative so the dashboard
//! shows the BYO-tool workflow as an ordinary Executor task.
//!
//! What the matching task does:
//!
//! 1. Receives the `unity_mcp_tools` Executor profile from
//!    `plan_realistic.rs`.
//! 2. Calls three operation-specific custom tools:
//!    `unity_list_scenes`, `unity_run_playmode_tests`, and
//!    `unity_build_player`.
//! 3. Commits `out/tools/unity-mcp-smoke.json` with the raw tool
//!    responses.
//!
//! The witness deliberately checks both the committed evidence file and
//! the kernel-owned `CustomToolInvoked` audit events. The evidence file
//! proves the agent used the returned tool data; the audit events prove
//! the subprocesses actually ran instead of an executor merely forging a
//! workspace side-effect file.

use std::path::{Path, PathBuf};

use raxis_audit_tools::{AuditEvent, AuditEventKind};

use super::witnesses::{events_by_kind, typed, EnforcementWitness};

/// Pinned task id in `plan_realistic.rs`.
pub const TASK_TOOLING_MCP_UNITY: &str = "tooling-mcp-unity";

/// Worktree-relative evidence path committed by the Executor.
pub const EVIDENCE_FILE_REL_PATH: &str = "out/tools/unity-mcp-smoke.json";

const REQUIRED_NEEDLES: &[&str] = &[
    "unity-editor-mcp-fixture",
    "unity_list_scenes",
    "unity_run_playmode_tests",
    "unity_build_player",
    "unity.listScenes",
    "unity.runPlaymodeTests",
    "unity.buildPlayer",
    "Assets/Scenes/Main.unity",
    "Builds/iOS/RaxisDemo.ipa",
];

/// Chain + disk witness for the primary-plan tooling task.
pub struct ToolingMcpEvidenceWitness {
    pub task_id: String,
    pub workdir: PathBuf,
}

impl ToolingMcpEvidenceWitness {
    #[must_use]
    pub fn for_realistic_plan(workdir: &Path) -> Self {
        Self {
            task_id: TASK_TOOLING_MCP_UNITY.to_owned(),
            workdir: workdir.to_path_buf(),
        }
    }

    #[must_use]
    pub fn absolute_evidence_path(&self) -> PathBuf {
        self.workdir.join(EVIDENCE_FILE_REL_PATH)
    }

    fn evidence_check(&self) -> Result<(), String> {
        let path = self.absolute_evidence_path();
        let body =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let parsed: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| format!("parse {} as JSON: {e}", path.display()))?;

        let mut haystacks = vec![body, parsed.to_string()];
        collect_json_strings(&parsed, &mut haystacks);
        let joined = haystacks.join("\n");
        for needle in REQUIRED_NEEDLES {
            if !joined.contains(needle) {
                return Err(format!("missing evidence substring `{needle}`"));
            }
        }

        let compact: String = joined
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '\\')
            .collect();
        if !compact.contains("\"failed\":0") {
            return Err("missing playmode result with failed == 0".to_owned());
        }

        Ok(())
    }

    fn tool_audit_check(&self, chain: &[AuditEvent]) -> Result<(), String> {
        for tool_name in [
            "unity_list_scenes",
            "unity_run_playmode_tests",
            "unity_build_player",
        ] {
            let found = chain.iter().any(|ev| {
                ev.task_id.as_deref() == Some(self.task_id.as_str())
                    && matches!(
                        typed(ev),
                        Some(AuditEventKind::CustomToolInvoked {
                            tool_name: audited_tool,
                            outcome,
                            ..
                        }) if audited_tool == tool_name && outcome == "Success"
                    )
            });
            if !found {
                return Err(format!(
                    "audit chain missing successful CustomToolInvoked for {tool_name}"
                ));
            }
        }
        Ok(())
    }
}

impl EnforcementWitness for ToolingMcpEvidenceWitness {
    fn name(&self) -> &'static str {
        "tooling-mcp-evidence"
    }

    fn satisfied_by(&self, chain: &[AuditEvent]) -> bool {
        let chain_positive = chain.iter().any(|ev| {
            matches!(
                typed(ev),
                Some(AuditEventKind::IntentAccepted {
                    task_id, head_sha: Some(_), ..
                }) if task_id == self.task_id
            )
        });
        let path_scope_clean = chain.iter().all(|ev| {
            !matches!(
                typed(ev),
                Some(AuditEventKind::IntentRejected {
                    task_id, error_code, ..
                }) if task_id == self.task_id
                    && error_code == "FAIL_TASK_PATH_NOT_ALLOWED"
            )
        });

        chain_positive
            && path_scope_clean
            && self.evidence_check().is_ok()
            && self.tool_audit_check(chain).is_ok()
    }

    fn diagnostic(&self, chain: &[AuditEvent]) -> String {
        let admissions = chain
            .iter()
            .filter(|ev| {
                matches!(
                    typed(ev),
                    Some(AuditEventKind::IntentAccepted {
                        task_id, head_sha: Some(_), ..
                    }) if task_id == self.task_id
                )
            })
            .count();
        let path_rejections: Vec<u64> = chain
            .iter()
            .filter_map(|ev| match typed(ev) {
                Some(AuditEventKind::IntentRejected {
                    task_id,
                    error_code,
                    ..
                }) if task_id == self.task_id && error_code == "FAIL_TASK_PATH_NOT_ALLOWED" => {
                    Some(ev.seq)
                }
                _ => None,
            })
            .collect();
        let total_rejections = events_by_kind(chain, "IntentRejected").len();
        let evidence_state = self
            .evidence_check()
            .map(|()| "valid".to_owned())
            .unwrap_or_else(|e| e);
        let audit_state = self
            .tool_audit_check(chain)
            .map(|()| "valid".to_owned())
            .unwrap_or_else(|e| e);
        format!(
            "ToolingMcpEvidence[{task}]:\n  \
             chain admissions (IntentAccepted{{head_sha=Some(_)}}) = {admissions}\n  \
             FAIL_TASK_PATH_NOT_ALLOWED rejections for this task    = {path_rejections_len} \
             (out of {total_rejections} total IntentRejected events)\n  \
             evidence path: {path}\n  \
             evidence state: {evidence_state}\n  \
             custom-tool audit state: {audit_state}\n  \
             false-rejection seqs: {path_rejections:?}",
            task = self.task_id,
            path_rejections_len = path_rejections.len(),
            path = self.absolute_evidence_path().display(),
        )
    }
}

fn collect_json_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_json_strings(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                collect_json_strings(item, out);
            }
        }
        other => out.push(other.to_string()),
    }
}

pub fn write_synthetic_evidence(workdir: &Path) -> std::io::Result<()> {
    let out_dir = workdir.join("out/tools");
    std::fs::create_dir_all(&out_dir)?;
    let body = serde_json::json!({
        "adapter": "unity-editor-mcp-fixture",
        "tool_calls": [
            {
                "tool": "unity_list_scenes",
                "content": "{\"adapter\":\"unity-editor-mcp-fixture\",\"mcp_method\":\"unity.listScenes\",\"scenes\":[\"Assets/Scenes/Main.unity\",\"Assets/Scenes/CombatArena.unity\"]}"
            },
            {
                "tool": "unity_run_playmode_tests",
                "content": "{\"adapter\":\"unity-editor-mcp-fixture\",\"mcp_method\":\"unity.runPlaymodeTests\",\"passed\":12,\"failed\":0}"
            },
            {
                "tool": "unity_build_player",
                "content": "{\"adapter\":\"unity-editor-mcp-fixture\",\"mcp_method\":\"unity.buildPlayer\",\"artifact\":\"Builds/iOS/RaxisDemo.ipa\"}"
            }
        ]
    });
    std::fs::write(
        out_dir.join("unity-mcp-smoke.json"),
        serde_json::to_vec_pretty(&body).expect("synthetic JSON serializes"),
    )?;
    std::fs::write(
        out_dir.join("_unity_mcp_tool_calls.jsonl"),
        b"{\"method\":\"unity.listScenes\"}\n{\"method\":\"unity.runPlaymodeTests\"}\n{\"method\":\"unity.buildPlayer\"}\n",
    )
}

#[must_use]
pub fn synthetic_commit_chain() -> Vec<AuditEvent> {
    let payload = AuditEventKind::IntentAccepted {
        task_id: TASK_TOOLING_MCP_UNITY.to_owned(),
        session_id: "sess-tooling-mcp-smoke".to_owned(),
        intent_kind: "CommitDelta".to_owned(),
        base_sha: Some("a".repeat(40)),
        head_sha: Some("b".repeat(40)),
        sequence_number: 1,
        remaining_units: 99,
    };
    let mut events = vec![AuditEvent {
        seq: 0,
        event_id: uuid::Uuid::nil(),
        event_kind: "IntentAccepted".to_owned(),
        session_id: Some("sess-tooling-mcp-smoke".to_owned()),
        task_id: Some(TASK_TOOLING_MCP_UNITY.to_owned()),
        initiative_id: Some("init-primary".to_owned()),
        payload: serde_json::to_value(&payload).unwrap(),
        emitted_at: 1700000000,
        prev_sha256: "0".repeat(64),
    }];
    for (idx, tool_name) in [
        "unity_list_scenes",
        "unity_run_playmode_tests",
        "unity_build_player",
    ]
    .into_iter()
    .enumerate()
    {
        let payload = AuditEventKind::CustomToolInvoked {
            tool_name: tool_name.to_owned(),
            profile_name: "unity_mcp_tools".to_owned(),
            execution_locality: "guest_subprocess".to_owned(),
            outcome: "Success".to_owned(),
            duration_ms: 25,
            exit_code: Some(0),
            signal: None,
            timeout_ms: 10_000,
            command_argv_sha256: "c".repeat(64),
            stdin_bytes_total: 2,
            stdin_sha256: "d".repeat(64),
            stdout_bytes_total: 128,
            stdout_bytes_captured: 128,
            stdout_sha256: "e".repeat(64),
            stdout_truncated: false,
            stderr_bytes_total: 0,
            stderr_bytes_captured: 0,
            stderr_sha256: "f".repeat(64),
            stderr_truncated: false,
            error: None,
        };
        events.push(AuditEvent {
            seq: (idx + 1) as u64,
            event_id: uuid::Uuid::nil(),
            event_kind: "CustomToolInvoked".to_owned(),
            session_id: Some("sess-tooling-mcp-smoke".to_owned()),
            task_id: Some(TASK_TOOLING_MCP_UNITY.to_owned()),
            initiative_id: Some("init-primary".to_owned()),
            payload: serde_json::to_value(&payload).unwrap(),
            emitted_at: 1700000001 + idx as i64,
            prev_sha256: "0".repeat(64),
        });
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_fixture_satisfies_witness() {
        let tmp = tempfile::tempdir().unwrap();
        write_synthetic_evidence(tmp.path()).unwrap();
        let witness = ToolingMcpEvidenceWitness::for_realistic_plan(tmp.path());
        let chain = synthetic_commit_chain();
        assert!(
            witness.satisfied_by(&chain),
            "synthetic fixture should satisfy: {}",
            witness.diagnostic(&chain),
        );
    }

    #[test]
    fn missing_build_artifact_fails_evidence_check() {
        let tmp = tempfile::tempdir().unwrap();
        write_synthetic_evidence(tmp.path()).unwrap();
        let evidence = tmp.path().join(EVIDENCE_FILE_REL_PATH);
        let mut body = std::fs::read_to_string(&evidence).unwrap();
        body = body.replace("Builds/iOS/RaxisDemo.ipa", "Builds/iOS/Other.ipa");
        std::fs::write(&evidence, body).unwrap();
        let witness = ToolingMcpEvidenceWitness::for_realistic_plan(tmp.path());
        assert!(witness.evidence_check().is_err());
    }

    #[test]
    fn missing_custom_tool_audit_fails_witness() {
        let tmp = tempfile::tempdir().unwrap();
        write_synthetic_evidence(tmp.path()).unwrap();
        let witness = ToolingMcpEvidenceWitness::for_realistic_plan(tmp.path());
        let chain: Vec<_> = synthetic_commit_chain()
            .into_iter()
            .filter(|ev| ev.event_kind != "CustomToolInvoked")
            .collect();
        assert!(!witness.satisfied_by(&chain));
        assert!(witness.tool_audit_check(&chain).is_err());
    }
}
