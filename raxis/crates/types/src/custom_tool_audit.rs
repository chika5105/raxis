// raxis-types::custom_tool_audit — planner↔kernel custom-tool audit wire types.
//
// Custom tools execute inside the untrusted executor VM, but the kernel owns
// the durable audit chain. The planner therefore reports one bounded metadata
// envelope per attempted custom-tool invocation over the existing planner IPC
// stream. The kernel stamps the session token for session-bound VM streams, so
// the agent still never receives bearer authority.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable outcome taxonomy for a custom-tool invocation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustomToolInvocationOutcome {
    /// Subprocess exited successfully and returned a non-error tool result.
    Success,
    /// Subprocess exited successfully but returned a ToolOutput with
    /// `is_error = true`.
    ToolError,
    /// The model-supplied JSON did not satisfy the operator-declared schema.
    SchemaRejected,
    /// Input JSON exceeded the declared stdin cap before the subprocess ran.
    InputTooLarge,
    /// The configured executable could not be spawned.
    SpawnFailed,
    /// Writing JSON to stdin failed before the subprocess could complete.
    StdinWriteFailed,
    /// Waiting for the child process returned an OS error.
    WaitFailed,
    /// Subprocess exceeded `timeout_seconds` and was killed.
    Timeout,
    /// Subprocess exited non-zero.
    NonZeroExit,
    /// Capturing stdout failed.
    StdoutReadFailed,
    /// Capturing stderr failed.
    StderrReadFailed,
    /// The tool ran, but the planner could not report its invocation to the
    /// kernel. This variant is reserved for local logs; the kernel normally
    /// will not persist it because the report itself failed.
    AuditReportFailed,
}

impl CustomToolInvocationOutcome {
    /// Stable PascalCase string for logs, dashboard filters, and audit payloads.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "Success",
            Self::ToolError => "ToolError",
            Self::SchemaRejected => "SchemaRejected",
            Self::InputTooLarge => "InputTooLarge",
            Self::SpawnFailed => "SpawnFailed",
            Self::StdinWriteFailed => "StdinWriteFailed",
            Self::WaitFailed => "WaitFailed",
            Self::Timeout => "Timeout",
            Self::NonZeroExit => "NonZeroExit",
            Self::StdoutReadFailed => "StdoutReadFailed",
            Self::StderrReadFailed => "StderrReadFailed",
            Self::AuditReportFailed => "AuditReportFailed",
        }
    }
}

/// Digest + size metadata for one captured byte stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomToolByteReport {
    /// Total bytes produced before truncation.
    pub bytes_total: u64,
    /// Bytes retained by the planner and, if applicable, shown to the agent.
    pub bytes_captured: u64,
    /// SHA-256 of the full stream where available. When the stream read itself
    /// failed, this is the digest of the bytes captured before the error.
    pub sha256: String,
    /// True when bytes were omitted from the retained tool result/audit payload.
    pub truncated: bool,
}

/// **Planner → kernel.** One report per attempted custom-tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomToolInvocationRequest {
    /// Per-invocation UUIDv4 minted by the planner for correlation.
    pub request_id: Uuid,
    /// Host-side session token. Session-bound VM planners send this empty; the
    /// kernel dispatcher stamps the canonical DB token before validation.
    pub session_token: String,
    /// Guest-visible session id. Safe correlation metadata, not authority.
    pub session_id: String,
    /// Task whose executor invoked the custom tool.
    pub task_id: String,
    /// Initiative id, carried for audit attribution.
    pub initiative_id: String,
    /// Operator-declared tool name.
    pub tool_name: String,
    /// Profile that contributed this tool to the task's effective bundle.
    /// Stamped by the kernel from the signed plan; the guest may report it
    /// only for correlation and the kernel verifies it against the signed
    /// bundle before writing audit.
    pub profile_name: String,
    /// Where the operation was executed. Current shipped value is
    /// `"guest_subprocess"` for VM-local tools, or one of the host-owned
    /// adapter localities: `"host_subprocess"`, `"host_mcp"`, or
    /// `"remote_mcp"`.
    pub execution_locality: String,
    /// SHA-256 of the static command argv JSON array. The argv is not copied
    /// into the audit chain because it may contain noisy local install paths.
    pub command_argv_sha256: String,
    /// Configured timeout for this invocation.
    pub timeout_ms: u64,
    /// Observed outcome.
    pub outcome: CustomToolInvocationOutcome,
    /// Wall-clock duration spent in the wrapper, including schema rejection.
    pub duration_ms: u64,
    /// POSIX exit code when available.
    pub exit_code: Option<i32>,
    /// POSIX signal when available.
    pub signal: Option<i32>,
    /// Stdin metadata.
    pub stdin: CustomToolByteReport,
    /// Stdout metadata.
    pub stdout: CustomToolByteReport,
    /// Stderr metadata.
    pub stderr: CustomToolByteReport,
    /// Short model-facing or wrapper-facing error, capped before sending.
    #[serde(default)]
    pub error: Option<String>,
}

/// **Kernel → planner.** Acknowledges whether the report landed in the audit
/// sink. A rejection is fail-closed for the planner wrapper: it should withhold
/// the tool response and return a structured tool error to the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomToolInvocationAck {
    /// Echoed request id.
    pub request_id: Uuid,
    /// True when the audit event was written.
    pub accepted: bool,
    /// Rejection reason when `accepted = false`.
    pub reason: Option<String>,
}

/// **Planner → kernel.** Request to execute an operator-declared custom tool
/// whose runtime locality is owned by the kernel (`host_subprocess`,
/// `host_mcp`, or `remote_mcp`). The planner supplies only the stable tool
/// name and model JSON input; the kernel resolves the command/adapter from the
/// signed plan bundle so the guest cannot smuggle host paths, URLs, or
/// credentials through the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomToolExecutionRequest {
    /// Per-invocation UUIDv4 minted by the planner for correlation.
    pub request_id: Uuid,
    /// Host-side session token. Session-bound VM planners send this empty; the
    /// kernel dispatcher stamps the canonical DB token before validation.
    pub session_token: String,
    /// Guest-visible session id. Safe correlation metadata, not authority.
    pub session_id: String,
    /// Task whose executor invoked the custom tool.
    pub task_id: String,
    /// Initiative id, carried for audit attribution.
    pub initiative_id: String,
    /// Operator-declared tool name.
    pub tool_name: String,
    /// Model-supplied JSON input. The kernel validates this again against the
    /// signed tool schema before running any host-side adapter.
    ///
    /// **Wire encoding:** the planner socket uses bincode, whose strict
    /// serde mode cannot decode `serde_json::Value` directly because
    /// `Value` asks the deserializer for `deserialize_any`. Encode the JSON
    /// value as a string on the wire, matching `WitnessSubmission.body`.
    #[serde(with = "json_value_as_string")]
    pub input: serde_json::Value,
}

/// **Kernel → planner.** Response from a kernel-owned custom-tool execution.
/// `accepted = true` means the audit event landed and the tool output may be
/// shown to the model. `accepted = false` is fail-closed: the planner wrapper
/// must surface `reason` as a tool error and withhold any partial response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomToolExecutionResponse {
    /// Echoed request id.
    pub request_id: Uuid,
    /// True when the tool execution was admitted, run or rejected in a
    /// kernel-audited way, and the audit event was written.
    pub accepted: bool,
    /// Tool output content. Present only when `accepted = true`.
    #[serde(default)]
    pub content: Option<String>,
    /// Tool-output error flag. `Some(true)` mirrors planner-core
    /// `ToolOutput::err`; `Some(false)` mirrors `ToolOutput::ok`.
    #[serde(default)]
    pub is_error: Option<bool>,
    /// Rejection reason when `accepted = false`.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Serde helper: round-trip `serde_json::Value` through non-self-describing
/// formats such as bincode by encoding it as a JSON string.
mod json_value_as_string {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_json::Value;

    pub fn serialize<S>(v: &Value, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let json = serde_json::to_string(v).map_err(serde::ser::Error::custom)?;
        s.serialize_str(&json)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        serde_json::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn custom_tool_execution_request_round_trips_through_bincode() {
        let original = CustomToolExecutionRequest {
            request_id: Uuid::new_v4(),
            session_token: String::new(),
            session_id: "session-1".to_owned(),
            task_id: "task-1".to_owned(),
            initiative_id: "init-1".to_owned(),
            tool_name: "host-search".to_owned(),
            input: json!({
                "query": "raxis",
                "limit": 3,
                "nested": {"ok": true},
                "paths": ["src", "docs"]
            }),
        };

        let bytes = bincode::serde::encode_to_vec(&original, bincode::config::standard())
            .expect("encode CustomToolExecutionRequest via bincode standard()");
        let (decoded, consumed): (CustomToolExecutionRequest, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("decode CustomToolExecutionRequest via bincode standard()");

        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.request_id, original.request_id);
        assert_eq!(decoded.input, original.input);
    }

    #[test]
    fn custom_tool_execution_response_round_trips_through_bincode_with_none_fields() {
        let original = CustomToolExecutionResponse {
            request_id: Uuid::new_v4(),
            accepted: true,
            content: Some("host-result".to_owned()),
            is_error: Some(false),
            reason: None,
        };

        let bytes = bincode::serde::encode_to_vec(&original, bincode::config::standard())
            .expect("encode CustomToolExecutionResponse via bincode standard()");
        let (decoded, consumed): (CustomToolExecutionResponse, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("decode CustomToolExecutionResponse via bincode standard()");

        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.request_id, original.request_id);
        assert!(decoded.accepted);
        assert_eq!(decoded.content.as_deref(), Some("host-result"));
        assert_eq!(decoded.is_error, Some(false));
        assert_eq!(decoded.reason, None);
    }

    #[test]
    fn custom_tool_invocation_request_round_trips_through_bincode_with_none_error() {
        let report = CustomToolByteReport {
            bytes_total: 0,
            bytes_captured: 0,
            sha256: "0".repeat(64),
            truncated: false,
        };
        let original = CustomToolInvocationRequest {
            request_id: Uuid::new_v4(),
            session_token: String::new(),
            session_id: "session-1".to_owned(),
            task_id: "task-1".to_owned(),
            initiative_id: "init-1".to_owned(),
            tool_name: "guest_probe".to_owned(),
            profile_name: "default".to_owned(),
            execution_locality: "guest_subprocess".to_owned(),
            command_argv_sha256: "1".repeat(64),
            timeout_ms: 1000,
            outcome: CustomToolInvocationOutcome::Success,
            duration_ms: 42,
            exit_code: Some(0),
            signal: None,
            stdin: report.clone(),
            stdout: report.clone(),
            stderr: report,
            error: None,
        };

        let bytes = bincode::serde::encode_to_vec(&original, bincode::config::standard())
            .expect("encode CustomToolInvocationRequest via bincode standard()");
        let (decoded, consumed): (CustomToolInvocationRequest, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("decode CustomToolInvocationRequest via bincode standard()");

        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.request_id, original.request_id);
        assert_eq!(decoded.error, None);
        assert_eq!(decoded.tool_name, "guest_probe");
    }
}
