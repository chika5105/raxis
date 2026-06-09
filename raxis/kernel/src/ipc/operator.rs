// raxis-kernel::ipc::operator — Operator IPC dispatcher.
//
// Normative reference: kernel-core.md §2.3 `src/ipc/handlers/operator.rs`.
//
// Single dispatcher for every OperatorRequest variant on the operator UDS.
// Common pre-handler pipeline per §2.3:
//   1. Read one OperatorRequest frame.
//   2. permitted_ops gate — reject if op not in authenticated_operator.permitted_ops.
//   3. Invoke per-variant handler.
//   4. Write OperatorResponse frame.
//
// v1 handler implementation status:
//   CreateSession      — fully wired (authority::session::create_session)
//   RevokeSession      — fully wired (authority::session::revoke_session)
//   GrantDelegation    — fully wired (authority::delegation::grant_delegation)
//   CreateInitiative   — fully wired (initiatives::v2_admission::create_initiative_v2_blocking)
//   ApprovePlan        — fully wired (initiatives::lifecycle::approve_plan)
//   RejectPlan         — fully wired (initiatives::lifecycle::reject_plan)
//   AbortInitiative    — fully wired (initiatives::lifecycle::abort_initiative)
//   AbortTask          — fully wired (initiatives::lifecycle::abort_task)
//   ResumeTask         — fully wired (task_transitions::transition_task)
//   RetryTask          — fully wired (initiatives::lifecycle::retry_task)
//   ApproveEscalation  — fully wired (authority::escalation::approve_escalation)
//   DenyEscalation     — fully wired (authority::escalation::deny_escalation)
//   RotateEpoch        — fully wired (policy_manager::advance_epoch)
//
// Observability instrumentation: every dispatched frame emits one
// `OperatorIpcTotal` counter increment plus one `OperatorIpcDuration`
// histogram observation, both labelled with `command_kind` (closed
// snake_case lexicon — see
// `crate::observability::COMMAND_KIND_CLOSED_SET`) and `accepted`
// (Bool — `false` iff the response is `OperatorResponse::Error`).
// Spec: `v3/otel-observability.md §8` rows for `OperatorIpc{Total,
// Duration}` + invariant `INV-OBS-OPERATOR-IPC-COVERAGE-01`.

use std::sync::Arc;

use raxis_ipc::{read_json_frame_async, write_json_frame_async, JsonFrameError};
use tokio::net::UnixStream;

use crate::authority;
use crate::initiatives;
use crate::initiatives::lifecycle;
use crate::ipc::auth::AuthenticatedOperator;
use crate::ipc::context::HandlerContext;

// ---------------------------------------------------------------------------
// Wire types (OperatorRequest / OperatorResponse)
//
// **Single source of truth: `raxis_types::operator_wire`.** Both this
// dispatcher (deserialise) and every `cli/src/commands/*` JSON
// construction site (serialise) MUST go through that module — the CLI
// builds typed values and serialises with `serde_json::to_value`, the
// kernel deserialises into the same types. Any new operator op MUST be
// added in `operator_wire.rs` first; the wire-shape contract tests
// there will catch field-name or tag drift between the two halves.
//
// Why a JSON-shape type set co-exists with `raxis_types::operator`
// (the bincode-shape design): the planner socket uses bincode + typed
// IDs; the operator socket uses JSON + plain strings. They are
// genuinely two protocols. `operator.rs` is the v2 destination,
// `operator_wire.rs` is the v1 contract.
// ---------------------------------------------------------------------------

pub use raxis_types::operator_wire::{OperatorRequest, OperatorResponse};

/// Dispatch loop for one authenticated operator connection.
///
/// Reads requests in a loop, dispatches each one, writes one response.
/// Returns when the connection is closed or a fatal framing error occurs.
///
/// Observability — every chokepoint here emits a structured stderr log line
/// via the `dispatch_log` helpers below. Before this was wired, an operator
/// hitting e.g. `FAIL_APPROVE_PLAN — initiative not found: …` got the error
/// at the CLI but the kernel's stderr was silent, leaving the operator
/// running the kernel with no record that the request happened. The four
/// chokepoints we cover are:
///
///   * request frame received  → `op_request`  (info)
///   * malformed JSON received → `frame_decode_failed` (warn)
///   * permitted_ops rejection → `unauthorized` (warn)
///   * response sent           → `op_response` (info on Ok
///     variants; warn on `OperatorResponse::Error`)
///
/// Each line carries the originating operator fingerprint and the per-op
/// context fields ([`request_context_fields`]: initiative_id, session_id,
/// task_id, escalation_id, delegation_id) so an operator grepping
/// `raxis-kernel`'s stderr for a specific id can find every interaction
/// with that entity.
pub async fn dispatch_loop(
    mut stream: UnixStream,
    operator: AuthenticatedOperator,
    ctx: Arc<HandlerContext>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Framing routes through `raxis-ipc::json_frame` so the kernel and CLI
    // share one source of truth (PR-2 — earlier the kernel and CLI used
    // independent hand-rolled framings with different byte orders, making
    // the operator socket non-functional end-to-end).
    loop {
        // §2.5.2 "Operator display-name fields" — resolve the
        // operator's name once per request iteration. The lookup
        // is an ArcSwap snapshot + linear scan over `operators[]`
        // (handful of entries in any realistic deployment), so
        // doing it per-iteration costs roughly nothing yet
        // guarantees that every stderr log line — even for
        // requests that fail decode/auth before they ever hit a
        // handler — carries the resolved name. Resolved here
        // rather than once at `dispatch_loop` entry so a policy
        // rotation mid-loop is reflected in subsequent logs
        // without restarting the per-operator connection.
        let operator_display: Option<String> = ctx
            .policy
            .load_full()
            .operator_display_name(&operator.fingerprint);
        let operator_display_str: Option<&str> = operator_display.as_deref();

        let request: OperatorRequest = match read_json_frame_async(&mut stream).await {
            Ok(r) => r,
            // Clean disconnect between frames — peer closed the socket.
            Err(JsonFrameError::Eof) => return Ok(()),
            // Malformed JSON: send an error frame and keep the connection
            // open so the CLI can show a useful message.
            Err(JsonFrameError::Decode(e)) => {
                dispatch_log::frame_decode_failed(
                    &operator.fingerprint,
                    operator_display_str,
                    &e.to_string(),
                );
                let resp = OperatorResponse::Error {
                    code: "INVALID_REQUEST".to_owned(),
                    detail: e.to_string(),
                };
                write_json_frame_async(&mut stream, &resp).await?;
                continue;
            }
            // Anything else (Io, TooLarge, Encode) is fatal for this connection.
            Err(other) => return Err(Box::new(other)),
        };

        // permitted_ops gate.
        let op_name = op_name(&request);
        if !crate::ipc::auth::is_permitted(&operator, op_name) {
            dispatch_log::unauthorized(op_name, &operator.fingerprint, operator_display_str);
            let resp = OperatorResponse::Error {
                code: "UNAUTHORIZED".to_owned(),
                detail: format!(
                    "operator '{}' not permitted to call '{op_name}'",
                    operator.fingerprint
                ),
            };
            write_json_frame_async(&mut stream, &resp).await?;
            continue;
        }

        // Cert four-zone gate (kernel-core.md §`authority/cert_check.rs`).
        // Runs AFTER `is_permitted` so an unauthorised request never even
        // reaches cert evaluation (avoids leaking cert state to operators
        // who shouldn't be able to call the op anyway), and BEFORE
        // handler dispatch so a denied request never mutates kernel state.
        // Certs are mandatory in the active policy; unknown or
        // invalid cert bindings deny before handler dispatch.
        let now_unix = raxis_types::unix_now_secs();
        let bundle_snapshot = ctx.policy.load_full();
        match ctx.cert_enforcer.enforce(
            &operator.fingerprint,
            op_name,
            &bundle_snapshot,
            ctx.audit.as_ref(),
            now_unix,
        ) {
            crate::authority::cert_check::CertGuard::Allow => { /* fall through */ }
            crate::authority::cert_check::CertGuard::Deny {
                wire_code,
                wire_detail,
            } => {
                dispatch_log::cert_denied(
                    op_name,
                    &operator.fingerprint,
                    operator_display_str,
                    wire_code,
                );
                let resp = OperatorResponse::Error {
                    code: wire_code.to_owned(),
                    detail: wire_detail,
                };
                write_json_frame_async(&mut stream, &resp).await?;
                continue;
            }
        }
        drop(bundle_snapshot);

        // Dispatch — instrument with request/response logging. We capture
        // the request's context fields BEFORE the handler runs so the log
        // works even on handlers that consume the request by value.
        let context_fields = request_context_fields(&request);
        dispatch_log::op_request(
            op_name,
            &operator.fingerprint,
            operator_display_str,
            &context_fields,
        );
        let started = std::time::Instant::now();

        // ── Streaming branch: SubscribeInitiative
        // ────────────────────────────────────
        //
        // SubscribeInitiative is the only operator op that needs
        // ownership of the connection AFTER the per-request
        // response. We handle it inline so the streaming runner
        // can write multiple frames before returning. The first
        // frame (`InitiativeSubscribed` ack) is logged as the
        // response for parity with all other handlers; subsequent
        // event frames are not individually logged (would flood
        // stderr at high event rates) — operators see them on the
        // CLI side.
        if let OperatorRequest::SubscribeInitiative { initiative_id } = &request {
            let initiative_id = initiative_id.clone();
            match crate::ipc::operator_ergonomics::validate_subscribe_admission(
                initiative_id.clone(),
                &ctx,
            )
            .await
            {
                Ok(ack) => {
                    let latency_ms = started.elapsed().as_millis() as u64;
                    dispatch_log::op_response(
                        op_name,
                        &operator.fingerprint,
                        operator_display_str,
                        &ack,
                        &context_fields,
                        latency_ms,
                    );
                    // iter44 — `INV-OBS-OPERATOR-IPC-COVERAGE-01`.
                    // Emit before the streaming runner takes over —
                    // the metric MUST cover the ack frame even
                    // though the connection persists for the
                    // subsequent event stream.
                    crate::observability::record_operator_ipc(
                        ctx.observability.as_ref(),
                        crate::observability::COMMAND_KIND_SUBSCRIBE_INITIATIVE,
                        crate::observability::operator_response_accepted(&ack),
                        latency_ms as i64,
                    );
                    // Hand the connection over to the streaming
                    // runner. It writes the ack, then loops
                    // events, then returns when the initiative
                    // terminates or the operator disconnects.
                    crate::ipc::operator_ergonomics::stream_subscribe_initiative(
                        &mut stream,
                        initiative_id,
                        &ctx,
                    )
                    .await?;
                    return Ok(());
                }
                Err(err_resp) => {
                    let latency_ms = started.elapsed().as_millis() as u64;
                    dispatch_log::op_response(
                        op_name,
                        &operator.fingerprint,
                        operator_display_str,
                        &err_resp,
                        &context_fields,
                        latency_ms,
                    );
                    crate::observability::record_operator_ipc(
                        ctx.observability.as_ref(),
                        crate::observability::COMMAND_KIND_SUBSCRIBE_INITIATIVE,
                        crate::observability::operator_response_accepted(&err_resp),
                        latency_ms as i64,
                    );
                    write_json_frame_async(&mut stream, &err_resp).await?;
                    continue;
                }
            }
        }

        // Capture the closed-lexicon `command_kind` BEFORE the
        // handler consumes the request by value. The closed lexicon
        // (`crate::observability::COMMAND_KIND_CLOSED_SET`) and the
        // exhaustive `operator_command_kind` match arm are the
        // structural witness for `INV-OBS-OPERATOR-IPC-COVERAGE-01`.
        let command_kind = crate::observability::operator_command_kind(&request);
        let response = handle_request(request, &operator, &ctx).await;
        let latency_ms = started.elapsed().as_millis() as u64;
        dispatch_log::op_response(
            op_name,
            &operator.fingerprint,
            operator_display_str,
            &response,
            &context_fields,
            latency_ms,
        );
        // iter44 — `INV-OBS-OPERATOR-IPC-COVERAGE-01`. Emit one
        // `OperatorIpcTotal` increment + one `OperatorIpcDuration`
        // sample per processed frame, regardless of response
        // outcome. The `accepted` label flips false iff the
        // response is `OperatorResponse::Error` (the sole error
        // envelope per `peripherals.md §3 "Operator socket"`).
        crate::observability::record_operator_ipc(
            ctx.observability.as_ref(),
            command_kind,
            crate::observability::operator_response_accepted(&response),
            latency_ms as i64,
        );
        write_json_frame_async(&mut stream, &response).await?;
    }
}

// ---------------------------------------------------------------------------
// Per-op context-field extraction
//
// Pulls the "what is this request operating on" identifiers out of each
// `OperatorRequest` variant so they can be threaded through the request
// log line, the response log line, and (later) any audit cross-reference.
//
// We use a small fixed key/value list (Vec<(&'static str, String)>) rather
// than `serde_json::to_value(&request)` because:
//   1. The full request can be huge (e.g. `CreateInitiative.plan_toml`
//      and `CreateInitiative.plan_sig_hex`) — emitting it to stderr
//      every call would bloat operator logs.
//   2. The full request can carry sensitive data (e.g. `signature_hex`
//      payloads) that we don't want in plain log lines.
//   3. The CLI / operator workflow is identifier-driven — operators
//      grep stderr for `"initiative_id":"<uuid>"`, not for plan bytes.
//
// New `OperatorRequest` variants MUST extend this match arm with their
// identifier fields; the wire-shape contract tests in
// `raxis-types::operator_wire::tests` will surface a missing arm at
// compile time as soon as the new variant is added to the dispatcher.
// ---------------------------------------------------------------------------

fn request_context_fields(req: &OperatorRequest) -> Vec<(&'static str, String)> {
    match req {
        OperatorRequest::CreateSession { lineage_id, .. } => {
            vec![("lineage_id", lineage_id.clone())]
        }
        OperatorRequest::RevokeSession { session_id } => {
            vec![("session_id", session_id.clone())]
        }
        OperatorRequest::GrantDelegation {
            session_id,
            delegation_id,
            capability_class,
            ..
        } => vec![
            ("session_id", session_id.clone()),
            ("delegation_id", delegation_id.clone()),
            ("capability_class", capability_class.clone()),
        ],
        OperatorRequest::CreateInitiative {
            initiative_id,
            bundle_sha256_hex,
            signed_by_hex,
            ..
        } => vec![
            // The plan-bundle-sealed envelope carries the
            // operator-chosen initiative_id + the bundle's
            // content-address + the operator fingerprint
            // (plan-bundle-sealing.md §3.4). Logging the sha256 +
            // fingerprint makes admission failures correlatable
            // with the operator's local bundle without dumping
            // kilobytes of plan_bundle_hex into operator stderr.
            ("initiative_id", initiative_id.clone()),
            ("bundle_sha256_hex", bundle_sha256_hex.clone()),
            ("signed_by_hex", signed_by_hex.clone()),
        ],
        OperatorRequest::ApprovePlan {
            initiative_id,
            approving_operator,
        } => vec![
            ("initiative_id", initiative_id.clone()),
            ("approving_operator", approving_operator.clone()),
        ],
        OperatorRequest::RejectPlan {
            initiative_id,
            rejected_by,
            ..
        } => vec![
            ("initiative_id", initiative_id.clone()),
            ("rejected_by", rejected_by.clone()),
        ],
        OperatorRequest::RetryTask { task_id } => {
            vec![("task_id", task_id.clone())]
        }
        OperatorRequest::ResumeTask {
            task_id,
            resumed_by,
        } => vec![
            ("task_id", task_id.clone()),
            ("resumed_by", resumed_by.clone()),
        ],
        OperatorRequest::AbortTask {
            task_id,
            aborted_by,
        } => vec![
            ("task_id", task_id.clone()),
            ("aborted_by", aborted_by.clone()),
        ],
        OperatorRequest::AbortInitiative {
            initiative_id,
            aborted_by,
        } => vec![
            ("initiative_id", initiative_id.clone()),
            ("aborted_by", aborted_by.clone()),
        ],
        OperatorRequest::ApproveEscalation { escalation_id, .. } => {
            vec![("escalation_id", escalation_id.clone())]
        }
        OperatorRequest::DenyEscalation { escalation_id, .. } => {
            vec![("escalation_id", escalation_id.clone())]
        }
        OperatorRequest::RotateEpoch {
            policy_path,
            sig_path,
        } => vec![
            ("policy_path", policy_path.clone()),
            ("sig_path", sig_path.clone()),
        ],
        OperatorRequest::QuarantineInitiative { initiative_id, .. } => {
            vec![("initiative_id", initiative_id.clone())]
        }
        OperatorRequest::QuarantinePlansBy {
            target_fingerprint, ..
        } => vec![("target_fingerprint", target_fingerprint.clone())],
        // operator-ergonomics IPC stubs. Identifier
        // fields are surfaced so audit grep flows behave the same
        // shape as the V3 wired handlers.
        OperatorRequest::ProposeDefaults { initiative_id } => {
            let id = initiative_id.clone().unwrap_or_else(|| "<unscoped>".into());
            vec![("initiative_id", id), ("feature", "ProposeDefaults".into())]
        }
        OperatorRequest::EstimateCost { .. } => {
            vec![("feature", "EstimateCost".into())]
        }
        OperatorRequest::DryRunAdmit { submitted_by, .. } => vec![
            ("submitted_by", submitted_by.clone()),
            ("feature", "DryRunAdmit".into()),
        ],
        OperatorRequest::SubscribeInitiative { initiative_id } => vec![
            ("initiative_id", initiative_id.clone()),
            ("feature", "SubscribeInitiative".into()),
        ],
        OperatorRequest::DescribeInitiativePause { initiative_id } => vec![
            ("initiative_id", initiative_id.clone()),
            ("feature", "DescribeInitiativePause".into()),
        ],
        OperatorRequest::ListTaskOutputs { task_id } => vec![
            ("task_id", task_id.clone()),
            ("feature", "ListTaskOutputs".into()),
        ],
    }
}

// ---------------------------------------------------------------------------
// Structured stderr logging for the operator dispatcher.
//
// Why this lives inline rather than in a shared kernel `log` crate: the
// rest of the kernel (main.rs, bootstrap.rs) emits one-off stderr lines
// via raw `eprintln!` with format-string JSON. Building a full kernel
// logging facade is a separate, larger refactor — see kernel-core.md
// §future-work. Until that lands, this module provides an escape-safe
// JSON emitter for the one surface where structured logging matters most
// (every operator-facing error flows through here).
//
// Why we go through `serde_json::to_string`: the existing 5
// `eprintln!(\"{{...{e}}}\")` call sites in this file do raw `format!`
// interpolation — if `e.to_string()` ever contained a `\"` (e.g. an
// SQL error wrapping a quoted column name), the resulting line is
// non-parseable JSON. Routing everything through `serde_json::json!`
// guarantees correctly escaped output.
// ---------------------------------------------------------------------------

pub(crate) mod dispatch_log {
    use super::OperatorResponse;
    use crate::ipc::log::{body_from_fields, finalize_line, level};
    use serde_json::json;

    pub(super) const MODULE: &str = "ipc.operator";

    // ── Pure formatters (`build_*_line`) → owned `String`. ──
    //
    // Each emit-helper (`op_request`, `op_response`, `frame_decode_failed`,
    // `unauthorized`) is a thin wrapper that calls its `build_*_line`
    // counterpart and pipes the result to `eprintln!`. Tests assert
    // against the formatter output directly — no stderr capture
    // dependency required.

    /// Build the JSON line that `op_request` will print. Pure — does no
    /// I/O. The test suite at the bottom of this file calls this
    /// directly and asserts the parsed `serde_json::Value` shape.
    ///
    /// `operator_display` is the operator's display-name resolved
    /// from the live `PolicyBundle` per `kernel-store.md` §2.5.2
    /// "Operator display-name fields". When `Some`, the line gets
    /// an extra `"operator_display"` field so an operator scanning
    /// stderr sees `Chika` next to `abcd1234abcd…` without having
    /// to cross-reference `raxis cert list`.
    pub(crate) fn build_op_request_line(
        op: &'static str,
        operator_fp: &str,
        operator_display: Option<&str>,
        context_fields: &[(&'static str, String)],
        ts_unix: i64,
    ) -> String {
        let mut body = body_from_fields(context_fields);
        body.insert("op".into(), json!(op));
        body.insert("operator_fp".into(), json!(operator_fp));
        if let Some(name) = operator_display {
            body.insert("operator_display".into(), json!(name));
        }
        finalize_line(level::INFO, MODULE, "op_request", body, ts_unix)
    }

    /// Build the JSON line that `op_response` will print. The `Error`
    /// variant of [`OperatorResponse`] is rendered at level=warn with
    /// `code` + `detail`; every success variant is rendered at level=info
    /// with a `variant` tag (and the freshly-minted `initiative_id` for
    /// `InitiativeCreated`, which is the one variant that surfaces an id
    /// the request side did not have).
    ///
    /// We deliberately do NOT include the success payload's secrets
    /// (e.g. `session_token`, `approval_token_raw`) — those values are
    /// in-band-only between kernel and CLI, and operator-visible stderr
    /// must never log them. Variant tag + latency + context is enough
    /// to correlate with the matching `op_request` line.
    pub(crate) fn build_op_response_line(
        op: &'static str,
        operator_fp: &str,
        operator_display: Option<&str>,
        response: &OperatorResponse,
        context_fields: &[(&'static str, String)],
        latency_ms: u64,
        ts_unix: i64,
    ) -> String {
        let mut body = body_from_fields(context_fields);
        body.insert("op".into(), json!(op));
        body.insert("operator_fp".into(), json!(operator_fp));
        if let Some(name) = operator_display {
            body.insert("operator_display".into(), json!(name));
        }
        body.insert("latency_ms".into(), json!(latency_ms));

        let log_level = match response {
            OperatorResponse::Error { code, detail } => {
                body.insert("status".into(), json!("error"));
                body.insert("code".into(), json!(code));
                body.insert("detail".into(), json!(detail));
                level::WARN
            }
            other => {
                body.insert("status".into(), json!("ok"));
                body.insert("variant".into(), json!(response_variant_name(other)));
                if let OperatorResponse::InitiativeCreated { initiative_id, .. } = other {
                    body.insert("initiative_id".into(), json!(initiative_id));
                }
                level::INFO
            }
        };
        finalize_line(log_level, MODULE, "op_response", body, ts_unix)
    }

    /// Build the JSON line for a malformed inbound frame. We don't have
    /// an op name yet (that's exactly what failed to decode), so the
    /// line carries only the operator fingerprint and the decode error.
    pub(crate) fn build_frame_decode_failed_line(
        operator_fp: &str,
        operator_display: Option<&str>,
        detail: &str,
        ts_unix: i64,
    ) -> String {
        let mut body = serde_json::Map::with_capacity(4);
        body.insert("operator_fp".into(), json!(operator_fp));
        if let Some(name) = operator_display {
            body.insert("operator_display".into(), json!(name));
        }
        body.insert("detail".into(), json!(detail));
        finalize_line(level::WARN, MODULE, "frame_decode_failed", body, ts_unix)
    }

    /// Build the JSON line for a `permitted_ops` rejection. The wire
    /// response is `UNAUTHORIZED`; this stderr line gives the operator
    /// running the kernel an audit trail of capability misses.
    pub(crate) fn build_unauthorized_line(
        op: &'static str,
        operator_fp: &str,
        operator_display: Option<&str>,
        ts_unix: i64,
    ) -> String {
        let mut body = serde_json::Map::with_capacity(4);
        body.insert("op".into(), json!(op));
        body.insert("operator_fp".into(), json!(operator_fp));
        if let Some(name) = operator_display {
            body.insert("operator_display".into(), json!(name));
        }
        finalize_line(level::WARN, MODULE, "unauthorized", body, ts_unix)
    }

    // ── Emit-side wrappers — used from `dispatch_loop`. ──

    pub(super) fn op_request(
        op: &'static str,
        operator_fp: &str,
        operator_display: Option<&str>,
        context_fields: &[(&'static str, String)],
    ) {
        eprintln!(
            "{}",
            build_op_request_line(
                op,
                operator_fp,
                operator_display,
                context_fields,
                raxis_types::unix_now_secs(),
            ),
        );
    }

    pub(super) fn op_response(
        op: &'static str,
        operator_fp: &str,
        operator_display: Option<&str>,
        response: &OperatorResponse,
        context_fields: &[(&'static str, String)],
        latency_ms: u64,
    ) {
        eprintln!(
            "{}",
            build_op_response_line(
                op,
                operator_fp,
                operator_display,
                response,
                context_fields,
                latency_ms,
                raxis_types::unix_now_secs(),
            ),
        );
    }

    pub(super) fn frame_decode_failed(
        operator_fp: &str,
        operator_display: Option<&str>,
        detail: &str,
    ) {
        eprintln!(
            "{}",
            build_frame_decode_failed_line(
                operator_fp,
                operator_display,
                detail,
                raxis_types::unix_now_secs(),
            ),
        );
    }

    pub(super) fn unauthorized(
        op: &'static str,
        operator_fp: &str,
        operator_display: Option<&str>,
    ) {
        eprintln!(
            "{}",
            build_unauthorized_line(
                op,
                operator_fp,
                operator_display,
                raxis_types::unix_now_secs(),
            ),
        );
    }

    /// Build the JSON log line for a cert-gate rejection (kernel-core.md
    /// §`authority/cert_check.rs`). Mirrors `build_unauthorized_line`
    /// shape but adds the wire `code` so an operator scanning stderr
    /// can grep for `"code":"FAIL_CERT_EXPIRED"` directly.
    pub(crate) fn build_cert_denied_line(
        op: &'static str,
        operator_fp: &str,
        operator_display: Option<&str>,
        wire_code: &'static str,
        ts_unix: i64,
    ) -> String {
        let mut body = serde_json::Map::with_capacity(4);
        body.insert("op".into(), json!(op));
        body.insert("operator_fp".into(), json!(operator_fp));
        if let Some(name) = operator_display {
            body.insert("operator_display".into(), json!(name));
        }
        body.insert("code".into(), json!(wire_code));
        finalize_line(level::WARN, MODULE, "cert_denied", body, ts_unix)
    }

    pub(super) fn cert_denied(
        op: &'static str,
        operator_fp: &str,
        operator_display: Option<&str>,
        wire_code: &'static str,
    ) {
        eprintln!(
            "{}",
            build_cert_denied_line(
                op,
                operator_fp,
                operator_display,
                wire_code,
                raxis_types::unix_now_secs(),
            ),
        );
    }

    // ── Operator-specific helpers ──
    //
    // The cross-dispatcher primitives `body_from_fields`,
    // `finalize_line`, and `level::*` live in `crate::ipc::log` so the
    // planner and gateway dispatchers share one escape-safe code path.

    /// Tag for an `OperatorResponse` variant, used in the success log
    /// line. Keep in sync with the variants in
    /// `raxis_types::operator_wire::OperatorResponse`.
    fn response_variant_name(r: &OperatorResponse) -> &'static str {
        match r {
            OperatorResponse::SessionCreated { .. } => "SessionCreated",
            OperatorResponse::SessionRevoked { .. } => "SessionRevoked",
            OperatorResponse::DelegationGranted { .. } => "DelegationGranted",
            OperatorResponse::InitiativeCreated { .. } => "InitiativeCreated",
            OperatorResponse::PlanApproved { .. } => "PlanApproved",
            OperatorResponse::EscalationApproved { .. } => "EscalationApproved",
            OperatorResponse::EscalationDenied { .. } => "EscalationDenied",
            OperatorResponse::EpochAdvanced { .. } => "EpochAdvanced",
            OperatorResponse::Ack { .. } => "Ack",
            OperatorResponse::Error { .. } => "Error",
            OperatorResponse::InitiativeQuarantined { .. } => "InitiativeQuarantined",
            OperatorResponse::QuarantineSwept { .. } => "QuarantineSwept",
            // operator-ergonomics IPC success
            // envelopes. As of V2.4 four of the five handlers emit
            // these arms for real (`ProposeDefaults`, `EstimateCost`,
            // `DryRunAdmit`, `DescribeInitiativePause`); only
            // `SubscribeInitiative` still answers with
            // `Error{FAIL_NOT_YET_IMPLEMENTED}` because it depends on
            // the V3 KernelPush bidirectional transport.
            OperatorResponse::ProposedDefaults { .. } => "ProposedDefaults",
            OperatorResponse::CostEstimated { .. } => "CostEstimated",
            OperatorResponse::DryRunAdmitted { .. } => "DryRunAdmitted",
            OperatorResponse::InitiativeSubscribed { .. } => "InitiativeSubscribed",
            OperatorResponse::InitiativePauseDescribed { .. } => "InitiativePauseDescribed",
            OperatorResponse::TaskOutputsListed { .. } => "TaskOutputsListed",
        }
    }
}

/// Dispatch a single request to the appropriate handler.
///
/// `ctx: &Arc<HandlerContext>` (rather than the historical
/// `&HandlerContext`) is required so handlers that need to spawn
/// detached tokio tasks bound to the same context — today: the
/// post-approve-plan planner-dispatch bridge — can `Arc::clone(ctx)`
/// without rebuilding a fresh `Arc` from the deref'd reference.
/// All existing call sites continue to work because `Arc<T>` derefs
/// to `&T` at every method-call site.
async fn handle_request(
    request: OperatorRequest,
    operator: &AuthenticatedOperator,
    ctx: &Arc<HandlerContext>,
) -> OperatorResponse {
    match request {
        OperatorRequest::CreateSession {
            role,
            worktree_root,
            base_sha,
            base_tracking_ref,
            lineage_id,
            ..
        } => {
            handle_create_session(
                role,
                worktree_root,
                base_sha,
                base_tracking_ref,
                lineage_id,
                ctx,
            )
            .await
        }
        OperatorRequest::RevokeSession { session_id } => {
            handle_revoke_session(session_id, operator, ctx).await
        }
        OperatorRequest::GrantDelegation {
            session_id,
            delegation_id,
            capability_class,
            scope_json,
            ttl_secs,
            max_uses,
            signature_hex,
        } => {
            handle_grant_delegation(
                session_id,
                delegation_id,
                capability_class,
                scope_json,
                ttl_secs,
                max_uses,
                signature_hex,
                operator,
                ctx,
            )
            .await
        }
        // Initiative lifecycle — plan-bundle-sealed admission.
        // Spec: `plan-bundle-sealing.md §3.4 + §8.1`. The hex
        // envelope is decoded here into the `V2AdmissionRequest`
        // typed shape, then handed to `create_initiative_blocking`
        // which runs the §8.1 step ordering (steps 2–9 pre-tx, 10a–12
        // inside `BEGIN IMMEDIATE`). Replay-protection invariants
        // (`INV-PLAN-BUNDLE-FRESH`) are enforced inside the
        // transaction.
        //
        // V2.5 dropped the V1 path-based `CreateInitiative` arm —
        // there is now a single `CreateInitiative` discriminant on
        // the wire and it carries the sealed-bundle payload below.
        OperatorRequest::CreateInitiative {
            initiative_id,
            plan_bundle_hex,
            bundle_sha256_hex,
            signature_hex,
            signed_by_hex,
        } => {
            handle_create_initiative(
                initiative_id,
                plan_bundle_hex,
                bundle_sha256_hex,
                signature_hex,
                signed_by_hex,
                ctx,
            )
            .await
        }
        OperatorRequest::ApprovePlan {
            initiative_id,
            approving_operator,
        } => handle_approve_plan(initiative_id, approving_operator, operator, ctx).await,
        OperatorRequest::RejectPlan {
            initiative_id,
            rejected_by,
            reason,
        } => handle_reject_plan(initiative_id, rejected_by, reason, ctx).await,
        OperatorRequest::RetryTask { task_id } => handle_retry_task(task_id, ctx).await,
        OperatorRequest::ResumeTask {
            task_id,
            resumed_by,
        } => handle_resume_task(task_id, resumed_by, ctx).await,
        OperatorRequest::AbortTask {
            task_id,
            aborted_by,
        } => handle_abort_task(task_id, aborted_by, ctx).await,
        OperatorRequest::AbortInitiative {
            initiative_id,
            aborted_by,
        } => handle_abort_initiative(initiative_id, aborted_by, ctx).await,
        OperatorRequest::ApproveEscalation {
            escalation_id,
            approval_scope,
            operator_sig_hex,
        } => {
            handle_approve_escalation(
                escalation_id,
                approval_scope,
                operator_sig_hex,
                operator,
                ctx,
            )
            .await
        }
        OperatorRequest::DenyEscalation {
            escalation_id,
            reason,
        } => handle_deny_escalation(escalation_id, reason, operator, ctx).await,
        OperatorRequest::RotateEpoch {
            policy_path,
            sig_path,
        } => handle_rotate_epoch(policy_path, sig_path, operator, ctx).await,
        OperatorRequest::QuarantineInitiative {
            initiative_id,
            reason,
        } => handle_quarantine_initiative(initiative_id, reason, operator, ctx).await,
        OperatorRequest::QuarantinePlansBy {
            target_fingerprint,
            reason,
        } => handle_quarantine_plans_by(target_fingerprint, reason, operator, ctx).await,

        // ----------------------------------------------------------------
        // Operator-ergonomics IPC. V2.4 lands real
        // handlers for ProposeDefaults / EstimateCost / DryRunAdmit /
        // DescribeInitiativePause. SubscribeInitiative remains a
        // wire-stub because it requires bidirectional streaming on
        // the operator socket (lands with V3 KernelPush transport,
        // ). All five handlers live in
        // `crate::ipc::operator_ergonomics` and uphold
        // `INV-OPERATOR-ERG-01` — read-only kernel operations.
        // ----------------------------------------------------------------
        OperatorRequest::ProposeDefaults { initiative_id } => {
            crate::ipc::operator_ergonomics::handle_propose_defaults(initiative_id, ctx).await
        }
        OperatorRequest::EstimateCost {
            plan_toml,
            plan_sig_hex,
        } => {
            crate::ipc::operator_ergonomics::handle_estimate_cost(plan_toml, plan_sig_hex, ctx)
                .await
        }
        OperatorRequest::DryRunAdmit {
            plan_toml,
            plan_sig_hex,
            submitted_by,
        } => {
            crate::ipc::operator_ergonomics::handle_dry_run_admit(
                plan_toml,
                plan_sig_hex,
                submitted_by,
                ctx,
            )
            .await
        }
        // SubscribeInitiative is handled by the streaming branch
        // in `dispatch_loop` BEFORE this dispatcher runs (it
        // needs ownership of the stream). Reaching this arm
        // means a non-streaming caller invoked it; we surface a
        // typed error so the misuse is obvious in the response
        // log line.
        OperatorRequest::SubscribeInitiative { .. } => OperatorResponse::Error {
            code: "FAIL_INVALID_TRANSPORT".into(),
            detail: "SubscribeInitiative must be invoked through the streaming dispatcher; \
                     the per-request dispatcher does not own the connection"
                .into(),
        },
        OperatorRequest::DescribeInitiativePause { initiative_id } => {
            crate::ipc::operator_ergonomics::handle_describe_initiative_pause(initiative_id, ctx)
                .await
        }
        OperatorRequest::ListTaskOutputs { task_id } => {
            crate::ipc::operator_ergonomics::handle_list_task_outputs(task_id, ctx).await
        }
    }
}

// ---------------------------------------------------------------------------
// Per-variant handlers
// ---------------------------------------------------------------------------

/// Map the wire `role` string to the kernel's `authority::session::Role`,
/// enforcing the operator-creatable role gate
/// (kernel-core.md §`handle_create_session` step 1, cli-ceremony.md §4.2).
///
/// Wire contract per cli-ceremony.md §4.2 line 300: the canonical
/// operator-creatable role string is the literal lowercase `"planner"`.
/// Gateway and verifier sessions are minted by kernel-internal spawn
/// paths (`spawn_gateway` / `spawn_verifier`) and MUST NOT be reachable
/// through operator IPC. Any other role string (wrong casing,
/// `"gateway"`, `"verifier"`, or unknown values) is rejected with
/// `FAIL_ROLE_NOT_OPERATOR_CREATABLE`.
#[allow(clippy::result_large_err)]
fn parse_operator_creatable_role(
    role_str: &str,
) -> Result<authority::session::Role, OperatorResponse> {
    match role_str {
        // Canonical wire shape per cli-ceremony.md §4.2 line 300: the
        // literal lowercase string "planner". Locked by the wire
        // round-trip tests in raxis_types::operator_wire and
        // raxis_cli::tests::operator_wire_shape.
        "planner" => Ok(authority::session::Role::Planner),
        // Everything else is rejected:
        //   * "Planner" / wrong casing → off-spec, drift caught here.
        //   * "gateway" / "verifier" → minted by spawn_gateway /
        //     spawn_verifier respectively, never via operator IPC.
        //   * unknown strings → defensive.
        other => Err(OperatorResponse::Error {
            code:   "FAIL_ROLE_NOT_OPERATOR_CREATABLE".to_owned(),
            detail: format!(
                "role '{other}' is not operator-creatable; only 'planner' is operator-creatable in v1"
            ),
        }),
    }
}

/// Convert a `Role` to its canonical wire string for outbound responses.
///
/// This is deliberately distinct from `Role::as_str()`, which returns
/// the PascalCase **SQL-storage** form (`"Planner"`/`"Gateway"`/`"Verifier"`)
/// stored in `sessions.role`. The IPC wire contract is lowercase
/// (cli-ceremony.md §4.2), and the round-trip fixtures in
/// `raxis_types::operator_wire::tests::create_session_response_wire_shape`
/// pin lowercase. Keeping inbound (`parse_operator_creatable_role`)
/// and outbound (`wire_role_str`) co-located makes the wire-shape
/// contract auditable in one place.
fn wire_role_str(role: &authority::session::Role) -> &'static str {
    use authority::session::Role;
    match role {
        Role::Planner => "planner",
        Role::Gateway => "gateway",
        Role::Verifier => "verifier",
    }
}

async fn handle_create_session(
    role_str: String,
    worktree_root: Option<String>,
    base_sha: Option<String>,
    base_tracking_ref: Option<String>,
    lineage_id_str: String,
    ctx: &HandlerContext,
) -> OperatorResponse {
    use authority::session::{Role, SessionConfig};

    let role = match parse_operator_creatable_role(role_str.as_str()) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Worktree containment check for Planner sessions.
    if role == Role::Planner {
        if let Some(ref wt) = worktree_root {
            let canonical = match std::fs::canonicalize(wt) {
                Ok(p) => p,
                Err(e) => {
                    return OperatorResponse::Error {
                        code: "FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS".to_owned(),
                        detail: format!("cannot canonicalize worktree_root '{wt}': {e}"),
                    }
                }
            };
            let canonical_str = canonical.to_string_lossy();
            if !ctx.policy.load().worktree_root_allowed(&canonical_str) {
                return OperatorResponse::Error {
                    code: "FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS".to_owned(),
                    detail: format!("worktree_root '{wt}' not in allowed_worktree_roots"),
                };
            }
        }
    }

    // Parse lineage_id.
    let lineage_id = match raxis_types::LineageId::parse(&lineage_id_str) {
        Ok(id) => id,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_INVALID_LINEAGE_ID".to_owned(),
                detail: format!("invalid lineage_id '{lineage_id_str}': {e}"),
            }
        }
    };

    // FSM call goes through spawn_blocking — `authority::session::create_session`
    // takes the store mutex via `Store::lock_sync()`, which panics if
    // called directly from an async task ("Cannot block the current
    // thread from within a runtime"). Same pattern as `main.rs` Step
    // 6/7b and the escalation handlers below.
    let config = SessionConfig::default();
    let role_for_blocking = role.clone();
    let worktree_for_blocking = worktree_root.clone();
    let base_sha_for_blocking = base_sha.clone();
    let base_track_for_blocking = base_tracking_ref.clone();
    let lineage_for_blocking = lineage_id.clone();
    let store_for_blocking = Arc::clone(&ctx.store);
    let join_result = tokio::task::spawn_blocking(move || {
        authority::session::create_session(
            role_for_blocking,
            worktree_for_blocking,
            base_sha_for_blocking,
            base_track_for_blocking,
            lineage_for_blocking,
            &config,
            &store_for_blocking,
        )
    })
    .await;
    let create_outcome = match join_result {
        Ok(r) => r,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_CREATE_SESSION".to_owned(),
                detail: format!("create_session spawn_blocking join failed: {e}"),
            }
        }
    };

    match create_outcome {
        Ok((session_id, session_token)) => OperatorResponse::SessionCreated {
            session_id: session_id.as_str().to_owned(),
            session_token,
            // Wire-canonical lowercase per cli-ceremony.md §4.2 — see
            // `wire_role_str` above. Do NOT use `role.as_str()` here:
            // that returns the PascalCase SQL form and would break the
            // wire round-trip pinned in raxis_types::operator_wire.
            role: wire_role_str(&role).to_owned(),
            worktree_root,
            base_sha,
            lineage_id: lineage_id.as_str().to_owned(),
        },
        Err(e) => OperatorResponse::Error {
            code: "FAIL_CREATE_SESSION".to_owned(),
            detail: e.to_string(),
        },
    }
}

async fn handle_revoke_session(
    session_id_str: String,
    operator: &AuthenticatedOperator,
    ctx: &HandlerContext,
) -> OperatorResponse {
    use raxis_types::SessionId;
    let session_id = match SessionId::parse(&session_id_str) {
        Ok(id) => id,
        Err(_) => {
            return OperatorResponse::Error {
                code: "FAIL_SESSION_NOT_FOUND".to_owned(),
                detail: format!("invalid session_id format: '{session_id_str}'"),
            }
        }
    };

    let store_for_blocking = Arc::clone(&ctx.store);
    let session_id_for_blocking = session_id.clone();
    let join_result = tokio::task::spawn_blocking(move || {
        authority::session::revoke_session(&session_id_for_blocking, &store_for_blocking)
    })
    .await;
    let revoke_outcome = match join_result {
        Ok(r) => r,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_REVOKE_SESSION".to_owned(),
                detail: format!("revoke_session spawn_blocking join failed: {e}"),
            }
        }
    };

    match revoke_outcome {
        Ok(()) => {
            let revoked_at = raxis_types::unix_now_secs();
            // INV-AUDIT-OPERATOR-REVOKE-SESSION-PAIRED-WRITE-01 — emit
            // the SessionRevoked audit row after the SQL state change
            // commits, mirroring the canonical paired-write contract on
            // every other kernel-driven `sessions.revoked` mutation
            // (`authority::session::revoke_session` is the SQL writer;
            // the paired-write was missing on the operator-driven seam
            // earlier — see the deep-sweep-2 D9 follow-up).
            let operator_display_name = ctx
                .policy
                .load()
                .operator_display_name(&operator.fingerprint);
            if let Err(e) = ctx.audit.emit(
                raxis_audit_tools::AuditEventKind::SessionRevoked {
                    session_id: session_id_str.clone(),
                    revoked_by: operator.fingerprint.clone(),
                    revoked_by_display_name: operator_display_name,
                },
                Some(session_id_str.as_str()),
                None,
                None,
            ) {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"SessionRevoked\",\
                     \"audit_emit_failed\":\"{e}\",\"session_id\":\"{session_id_str}\"}}",
                );
            }
            OperatorResponse::SessionRevoked {
                session_id: session_id_str,
                revoked_at,
            }
        }
        Err(authority::keys::AuthorityError::SessionRevoked { revoked_at }) => {
            OperatorResponse::Error {
                code: "FAIL_SESSION_ALREADY_REVOKED".to_owned(),
                detail: format!("session already revoked at {revoked_at}"),
            }
        }
        Err(e) => OperatorResponse::Error {
            code: "FAIL_REVOKE_SESSION".to_owned(),
            detail: e.to_string(),
        },
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_grant_delegation(
    session_id_str: String,
    delegation_id: String,
    capability_class: String,
    scope_json: Option<String>,
    ttl_secs: u64,
    max_uses: Option<i64>,
    signature_hex: String,
    operator: &AuthenticatedOperator,
    ctx: &HandlerContext,
) -> OperatorResponse {
    use raxis_types::SessionId;

    let session_id = match SessionId::parse(&session_id_str) {
        Ok(id) => id,
        Err(_) => {
            return OperatorResponse::Error {
                code: "FAIL_SESSION_NOT_FOUND".to_owned(),
                detail: format!("invalid session_id: '{session_id_str}'"),
            }
        }
    };

    let signature_bytes = match hex::decode(&signature_hex) {
        Ok(b) => b,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_GRANT_DELEGATION".to_owned(),
                detail: format!("signature_hex decode failed: {e}"),
            }
        }
    };

    // Get operator pubkey from policy. We pin one snapshot of the
    // bundle for the duration of this handler so the pubkey lookup and
    // the `max_delegation_ttl` read see the same epoch.
    let policy_snapshot = ctx.policy.load_full();
    let op_entry = match policy_snapshot.operator_entry(&operator.fingerprint) {
        Some(e) => e,
        None => {
            return OperatorResponse::Error {
                code: "FAIL_GRANT_DELEGATION".to_owned(),
                detail: "operator not found in policy".to_owned(),
            }
        }
    };
    let pubkey_bytes = match hex::decode(&op_entry.pubkey_hex) {
        Ok(b) => b,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_GRANT_DELEGATION".to_owned(),
                detail: format!("pubkey_hex decode failed: {e}"),
            }
        }
    };

    let store_for_blocking = Arc::clone(&ctx.store);
    let session_for_blocking = session_id.clone();
    let delegation_for_blocking = delegation_id.clone();
    let capability_for_blocking = capability_class.clone();
    let scope_for_blocking = scope_json.clone();
    let fp_for_blocking = operator.fingerprint.clone();
    let max_ttl = policy_snapshot.max_delegation_ttl().as_secs();
    let join_result = tokio::task::spawn_blocking(move || {
        authority::delegation::grant_delegation(
            &session_for_blocking,
            &delegation_for_blocking,
            &capability_for_blocking,
            scope_for_blocking.as_deref(),
            &fp_for_blocking,
            ttl_secs,
            max_uses,
            &signature_bytes,
            &pubkey_bytes,
            max_ttl,
            &store_for_blocking,
        )
    })
    .await;
    let grant_outcome = match join_result {
        Ok(r) => r,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_GRANT_DELEGATION".to_owned(),
                detail: format!("grant_delegation spawn_blocking join failed: {e}"),
            }
        }
    };

    match grant_outcome {
        Ok(()) => OperatorResponse::DelegationGranted { delegation_id },
        Err(authority::keys::AuthorityError::DelegationAlreadyActive {
            existing_delegation_id,
        }) => OperatorResponse::Error {
            code: "FAIL_DELEGATION_ALREADY_ACTIVE".to_owned(),
            detail: format!("delegation {existing_delegation_id} already active"),
        },
        Err(e) => OperatorResponse::Error {
            code: "FAIL_GRANT_DELEGATION".to_owned(),
            detail: e.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Initiative lifecycle handlers
// ---------------------------------------------------------------------------

/// CreateInitiative — plan-bundle admission handler.
///
/// Spec: `plan-bundle-sealing.md §8.1`. Decodes the hex IPC envelope,
/// runs the §8.1 step ordering via `initiatives::v2_admission`,
/// projects the result onto an `OperatorResponse`. The decode +
/// admission both happen on a blocking pool because
/// `canonical_decode` + Ed25519 verify + SQLite commit are CPU/IO
/// heavy.
///
/// V2.5 collapsed the previous V1 `handle_create_initiative` (path-
/// based plan TOML + signature) into this one, leaving the sealed-
/// bundle pipeline as the sole admission path on the wire.
async fn handle_create_initiative(
    initiative_id: String,
    plan_bundle_hex: String,
    bundle_sha256_hex: String,
    signature_hex: String,
    signed_by_hex: String,
    ctx: &HandlerContext,
) -> OperatorResponse {
    // Step 1 — hex-decode the envelope. Errors here are
    // FAIL_PLAN_BUNDLE_DECODE_FAILED per §8.1; we surface them
    // before spawning a blocking task so the operator gets fast
    // structured feedback for trivially-malformed wire payloads.
    let plan_bundle = match hex::decode(&plan_bundle_hex) {
        Ok(b) => b,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_PLAN_BUNDLE_DECODE_FAILED".to_owned(),
                detail: format!("plan_bundle_hex: {e}"),
            }
        }
    };
    let bundle_sha256 = match hex::decode(&bundle_sha256_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            raxis_types::BundleSha256::new(arr)
        }
        Ok(b) => {
            return OperatorResponse::Error {
                code: "FAIL_PLAN_BUNDLE_DECODE_FAILED".to_owned(),
                detail: format!("bundle_sha256_hex: expected 32 bytes, got {}", b.len()),
            }
        }
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_PLAN_BUNDLE_DECODE_FAILED".to_owned(),
                detail: format!("bundle_sha256_hex: {e}"),
            }
        }
    };
    let signature = match hex::decode(&signature_hex) {
        Ok(b) if b.len() == 64 => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(b) => {
            return OperatorResponse::Error {
                code: "FAIL_PLAN_BUNDLE_DECODE_FAILED".to_owned(),
                detail: format!("signature_hex: expected 64 bytes, got {}", b.len()),
            }
        }
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_PLAN_BUNDLE_DECODE_FAILED".to_owned(),
                detail: format!("signature_hex: {e}"),
            }
        }
    };
    let signed_by = match hex::decode(&signed_by_hex) {
        Ok(b) if b.len() == 8 => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&b);
            raxis_types::OperatorFingerprint::new(arr)
        }
        Ok(b) => {
            return OperatorResponse::Error {
                code: "FAIL_PLAN_BUNDLE_DECODE_FAILED".to_owned(),
                detail: format!("signed_by_hex: expected 8 bytes, got {}", b.len()),
            }
        }
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_PLAN_BUNDLE_DECODE_FAILED".to_owned(),
                detail: format!("signed_by_hex: {e}"),
            }
        }
    };

    let req = initiatives::v2_admission::V2AdmissionRequest {
        initiative_id,
        plan_bundle,
        bundle_sha256,
        signature,
        signed_by,
    };

    // `unix_now_secs` returns u64; the admission handler takes i64
    // (because skew arithmetic needs signed semantics). Cast is
    // saturating-safe — the kernel cannot run past 2^63 Unix seconds.
    let now = raxis_types::unix_now_secs();

    let outcome = initiatives::v2_admission::create_initiative_v2_blocking(
        req,
        now,
        Arc::clone(&ctx.policy),
        Arc::clone(&ctx.store),
        Arc::clone(&ctx.audit),
    )
    .await;

    match outcome {
        Ok(result) => OperatorResponse::InitiativeCreated {
            initiative_id: result.initiative_id,
            status: result.status,
        },
        Err(e) => OperatorResponse::Error {
            code: e.fail_code().to_owned(),
            detail: e.to_string(),
        },
    }
}

/// ApprovePlan — verify Ed25519 sig, parse tasks, admit all, → Executing.
/// Spec: kernel-store.md §2.5.3 "approve_plan call path" + v1-review item #11.
///
/// Trust model — the operator pubkey comes from **policy, not the wire**.
///
///   The connected operator is authenticated by the challenge-response
///   handshake at connection time (`AuthenticatedOperator { fingerprint, .. }`).
///   The `ApprovePlan` request carries the `approving_operator`
///   fingerprint that the connected operator claims to be acting as.
///   Per `kernel-store.md` §2.5.3:
///
///   - `approving_operator` MUST equal the authenticated fingerprint
///     (no impersonation between operators on the wire).
///   - The pubkey used for signature verification MUST be looked up
///     from `policy.operator_entry(approving_operator).pubkey_hex`
///     — the wire request never carries an attacker-controlled
///     pubkey. The legacy `operator_pubkey_hex` wire field that
///     earlier V2 builds accepted-and-ignored has been removed in
///     V2.5; the kernel no longer participates in carrying it.
///
/// Only after the identity check passes do we resolve the policy pubkey,
/// hex-decode it, and hand the bytes to `lifecycle::approve_plan`, which
/// then performs canonical Ed25519 verification over the plan signing domain.
async fn handle_approve_plan(
    initiative_id: String,
    approving_operator: String,
    authenticated: &AuthenticatedOperator,
    ctx: &Arc<HandlerContext>,
) -> OperatorResponse {
    if approving_operator != authenticated.fingerprint {
        return OperatorResponse::Error {
            code: "FAIL_OPERATOR_IDENTITY_MISMATCH".to_owned(),
            detail: format!(
                "request.approving_operator='{approving_operator}' does not match \
                 authenticated operator '{}'",
                authenticated.fingerprint,
            ),
        };
    }

    // Single source of truth for trusted operators and their pubkeys.
    // Pin one snapshot so the pubkey lookup and the epoch read see the
    // same bundle.
    let policy_snapshot = ctx.policy.load_full();
    let entry = match policy_snapshot.operator_entry(&approving_operator) {
        Some(e) => e,
        None => {
            return OperatorResponse::Error {
                code: "FAIL_OPERATOR_UNKNOWN".to_owned(),
                detail: format!(
                    "approving_operator '{approving_operator}' has no entry in policy.operators",
                ),
            }
        }
    };

    let pubkey_bytes = match hex::decode(&entry.pubkey_hex) {
        Ok(b) => b,
        Err(e) => {
            return OperatorResponse::Error {
                // Policy validation should have caught this at load time; reaching
                // this branch indicates either a corrupted policy file accepted by
                // an older loader, or hand-editing of the in-memory bundle.
                code: "FAIL_POLICY_OPERATOR_PUBKEY_INVALID".to_owned(),
                detail: format!(
                    "policy entry for '{approving_operator}' has malformed pubkey_hex: {e}",
                ),
            };
        }
    };

    let policy_epoch = policy_snapshot.epoch();
    // §12.9 — snapshot the operator-side `[git]`
    // policy values from the same bundle we resolved the pubkey
    // from, so the per-initiative `target_ref` resolution happens
    // against the policy that was authoritative at approval time
    // (avoids a TOCTOU between policy reload and the spawn_blocking
    // hop into `approve_plan`).
    let policy_default_target_ref = policy_snapshot.git_default_target_ref().to_owned();
    let policy_target_ref_locked = policy_snapshot.git_target_ref_locked();
    // snapshot the operator-declared
    // `[environments.<label>]` map and `[[permitted_credentials]]`
    // list at approval time so the lifecycle validator can run
    // INV-ENV-01 (`environment-access-control.md §11`) against
    // the same epoch the plan was submitted under. Cloning the
    // small map+vec keeps the lifecycle entry point ownership-clean
    // (the kernel later runs the heavy work inside
    // `spawn_blocking`, so `'static` data avoids cross-thread
    // borrow gymnastics).
    let policy_environments_snapshot: std::collections::HashMap<
        String,
        raxis_policy::EnvironmentConfig,
    > = policy_snapshot.environments().clone();
    let policy_permitted_credentials_snapshot: Vec<raxis_policy::PermittedCredentialConfig> =
        policy_snapshot.permitted_credentials().to_vec();
    // (V2.5 BLOCKER) — snapshot the operator-published
    // `[[vm_images]]` registry under the same epoch the plan was
    // submitted against so `validate_task_vm_images` resolves
    // every alias against a stable view of the policy. The
    // `[default_executor_image]` snapshot rides alongside it so
    // the kernel-side back-fill (when an Executor task omits
    // `vm_image`) targets the same stable epoch view.
    let policy_vm_images_snapshot: Vec<raxis_policy::VmImageConfig> =
        policy_snapshot.vm_images().to_vec();
    let policy_default_executor_image_snapshot: Option<raxis_policy::DefaultExecutorImageConfig> =
        policy_snapshot.default_executor_image().cloned();
    // V2 `elastic-vm-scaling.md §2.1` — snapshot the operator
    // `[elastic]` block at the same epoch the plan was submitted
    // under so plan-narrows-policy (INV-ELASTIC-01) is evaluated
    // against a stable view. Cloned so the spawn_blocking hop
    // owns 'static data without cross-thread borrows.
    let policy_elastic_snapshot: raxis_policy::ElasticConfig = policy_snapshot.elastic().clone();
    // V2 §Step 28 + INV-SCHED-03 — snapshot the operator's
    // `[[lanes]]` registry at the same epoch the plan was
    // submitted against. Drives
    // `lifecycle::validate_workspace_lane_in_policy`: a plan whose
    // `[workspace] lane_id` does not match any declared
    // `[[lanes]] lane_id` is rejected at `approve_plan` time with
    // `LifecycleError::PlanLaneNotInPolicy`, BEFORE
    // `BEGIN TRANSACTION`. Without this check the budget gate
    // collapses to a wire-level `FailBudgetExceeded` only on the
    // first Phase-C handler (`SingleCommit` / `IntegrationMerge`),
    // which silently breaks the orchestrator's terminal-event
    // emission and surfaces as a harness deadline hang. Cloned so
    // the spawn_blocking hop owns 'static data.
    let policy_lanes_snapshot: Vec<raxis_policy::LaneEntry> = policy_snapshot.lanes().to_vec();
    // Snapshot the operator's display name from the same bundle we
    // resolved the pubkey from, so the audit event records the name
    // that was authoritative at approval time. See
    // `kernel-store.md` §2.5.2 "Operator display-name fields".
    let approving_op_display_name = Some(entry.display_name.clone());
    let store_for_blocking = Arc::clone(&ctx.store);
    let audit_for_blocking = Arc::clone(&ctx.audit);
    let plan_registry_for_blocking = Arc::clone(&ctx.plan_registry);
    let initiative_id_for_blocking = initiative_id.clone();
    let approving_op_for_blocking = approving_operator.clone();
    let artifact_store_for_blocking = ctx.artifact_store.as_ref().map(Arc::clone);
    let join_result = tokio::task::spawn_blocking(move || {
        lifecycle::approve_plan(
            &initiative_id_for_blocking,
            &approving_op_for_blocking,
            approving_op_display_name,
            &pubkey_bytes,
            policy_epoch,
            &policy_default_target_ref,
            policy_target_ref_locked,
            &policy_environments_snapshot,
            &policy_permitted_credentials_snapshot,
            &policy_vm_images_snapshot,
            policy_default_executor_image_snapshot.as_ref(),
            &policy_elastic_snapshot,
            &policy_lanes_snapshot,
            &store_for_blocking,
            &*audit_for_blocking,
            &plan_registry_for_blocking,
            artifact_store_for_blocking.as_deref(),
        )
    })
    .await;
    let outcome = match join_result {
        Ok(r) => r,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_APPROVE_PLAN".to_owned(),
                detail: format!("approve_plan spawn_blocking join failed: {e}"),
            }
        }
    };
    match outcome {
        Ok(result) => {
            // ── Post-commit orchestrator boot ─────────────────────
            //
            // The SQLite tx already committed (initiative ↔ tasks ↔
            // orchestrator session_id) and the audit chain landed
            // both `PlanApproved` and `SessionCreated`. Drive the
            // canonical Orchestrator VM through the trait surface
            // on `ctx.orchestrator_spawn`. Production wires
            // `LiveOrchestratorSpawn`; in-process unit tests wire
            // `NoopOrchestratorSpawn` (cfg-gated) which records the
            // call without booting a substrate.
            //
            // Failure here is **non-fatal to the response** —
            // PlanApproved already represents a committed,
            // operator-visible state mutation. A spawn failure
            // (canonical image missing on a half-installed kernel,
            // substrate refusal, etc.) is logged structurally so
            // recovery::reconcile / operator inspection can pick up
            // the gap; we still return PlanApproved so the operator
            // sees the SQL state honoured. The audit chain is the
            // source of truth: a missing `SessionVmSpawned` event
            // for the orchestrator session_id means the boot failed.
            if let Some(orch_session_id) = result.orchestrator_session_id.as_deref() {
                let allowlist = build_egress_allowlist_from_policy(&policy_snapshot);
                // clone the prompt
                // because the trait takes ownership; we log only
                // its byte length below (not the bytes themselves)
                // to keep operator-authored content out of stderr
                // while still letting an operator confirm delivery
                // size after a spawn. The validator guarantees
                // `task_prompt` is non-empty.
                let task_prompt = result.orchestrator_task_prompt.clone();
                let task_prompt_len = task_prompt.len();
                match ctx
                    .orchestrator_spawn
                    .spawn_for_initiative(
                        orch_session_id,
                        &result.initiative_id,
                        allowlist,
                        task_prompt,
                    )
                    .await
                {
                    Ok(mut handle) => {
                        eprintln!(
                            "{{\"level\":\"info\",\"event\":\"orchestrator_spawn_ok\",\
                             \"initiative_id\":\"{initiative_id}\",\
                             \"session_id\":\"{session_id}\",\
                             \"admission_loopback\":\"{admission}\",\
                             \"task_prompt_bytes\":{task_prompt_len},\
                             \"kernel_ipc_bridged\":{bridged}}}",
                            initiative_id = result.initiative_id,
                            session_id = handle.session_id,
                            admission = handle.admission_loopback,
                            bridged = handle.kernel_ipc_stream.is_some(),
                        );
                        // Hand the substrate-surrendered IPC stream
                        // (when one exists — microVM substrates only;
                        // see `Session::take_kernel_ipc_fd`) into the
                        // kernel's planner dispatch loop. No-op for
                        // subprocess substrate where the planner
                        // dials `planner.sock` directly.
                        crate::session_spawn_orchestrator::spawn_planner_dispatcher(
                            &mut handle,
                            Arc::clone(ctx),
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "{{\"level\":\"error\",\"event\":\"orchestrator_spawn_failed\",\
                             \"initiative_id\":\"{initiative_id}\",\
                             \"session_id\":\"{session_id}\",\
                             \"error\":\"{err}\",\
                             \"hint\":\"PlanApproved was committed; recovery::reconcile or \
                                       a follow-up operator command is needed to drive the \
                                       orchestrator boot once the substrate is available\"}}",
                            initiative_id = result.initiative_id,
                            session_id = orch_session_id,
                            err = e,
                        );
                    }
                }
            }

            OperatorResponse::PlanApproved {
                initiative_id: result.initiative_id,
                tasks_admitted: result.tasks_admitted,
            }
        }
        Err(e) => match &e {
            lifecycle::LifecycleError::PlanTaskIdAlreadyExists {
                task_id,
                existing_initiative_id,
            } => OperatorResponse::Error {
                code: "FAIL_PLAN_TASK_ID_ALREADY_EXISTS".to_owned(),
                detail: serde_json::json!({
                    "task_id": task_id,
                    "existing_initiative_id": existing_initiative_id,
                    "suggestion": "Choose task_id values that have never been used before, or clone the recurring plan with a fresh task-id prefix.",
                })
                .to_string(),
            },
            // §12.9 — surface the structured
            // locked-field / format-invalid rejections with their
            // dedicated wire codes so the CLI's diagnostic does not
            // bury the conflict under a generic FAIL_APPROVE_PLAN.
            lifecycle::LifecycleError::PlanTargetRefInvalid {
                rule,
                plan_value,
                policy_value,
                suggestion,
            } => {
                let code = match *rule {
                    "locked" => raxis_types::OperatorErrorCode::FailPolicyLockedField,
                    "invalid" => raxis_types::OperatorErrorCode::FailWorkspaceTargetRefInvalid,
                    // Future rules added to LifecycleError::PlanTargetRefInvalid
                    // should be wired here too; until then, fall back to the
                    // generic FAIL_APPROVE_PLAN so the operator still sees the
                    // diagnostic instead of silently 200-OK.
                    _ => {
                        return OperatorResponse::Error {
                            code: "FAIL_APPROVE_PLAN".to_owned(),
                            detail: e.to_string(),
                        }
                    }
                };
                let detail_json = serde_json::json!({
                    "rule":         rule,
                    "field":        "target_ref",
                    "plan_value":   plan_value,
                    "policy_value": policy_value,
                    "suggestion":   suggestion,
                })
                .to_string();
                OperatorResponse::Error {
                    code: code.to_string(),
                    detail: detail_json,
                }
            }
            _ => OperatorResponse::Error {
                code: "FAIL_APPROVE_PLAN".to_owned(),
                detail: e.to_string(),
            },
        },
    }
}

/// Lift the active policy bundle's egress allowlist into the wire
/// shape the per-session `PolicyAdmissionService` expects.
///
/// The `EgressAllowlist::credential_proxy_real_targets` field stays
/// empty here; the credential-proxy bypass-detection is keyed on the
/// per-session credential decls (which the kernel has already bound
/// listeners for at this point). The per-task `allowed_egress`
/// surface is folded in by the per-session admission service the
/// kernel constructs at executor-spawn time, not here.
///
/// V2 reviewer-egress-defaults-decision.md §5: feeds the EFFECTIVE
/// allowlist (operator `[egress] domains` ∪ implicit-provider FQDNs
/// derived from `[[providers]]`) so a Tier-1 transparent-proxy
/// admission decision matches the gateway URL allowlist; both
/// share one source of truth.
fn build_egress_allowlist_from_policy(
    policy: &raxis_policy::PolicyBundle,
) -> raxis_egress_admission::EgressAllowlist {
    raxis_egress_admission::EgressAllowlist {
        exact_hosts: policy.effective_egress_domains(),
        patterns: policy.effective_egress_patterns(),
        credential_proxy_real_targets: Default::default(),
    }
}

/// RejectPlan — set status = Rejected; initiative must be in PlanSubmitted.
async fn handle_reject_plan(
    initiative_id: String,
    rejected_by: String,
    reason: Option<String>,
    ctx: &HandlerContext,
) -> OperatorResponse {
    let store_for_blocking = Arc::clone(&ctx.store);
    let initiative_id_for_blocking = initiative_id.clone();
    let rejected_by_for_blocking = rejected_by.clone();
    let reason_for_blocking = reason.clone();
    let join_result = tokio::task::spawn_blocking(move || {
        lifecycle::reject_plan(
            &initiative_id_for_blocking,
            &rejected_by_for_blocking,
            reason_for_blocking.as_deref(),
            &store_for_blocking,
        )
    })
    .await;
    let outcome = match join_result {
        Ok(r) => r,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_REJECT_PLAN".to_owned(),
                detail: format!("reject_plan spawn_blocking join failed: {e}"),
            }
        }
    };
    match outcome {
        Ok(()) => OperatorResponse::Ack {
            message: format!("initiative {initiative_id} rejected"),
        },
        Err(e) => OperatorResponse::Error {
            code: "FAIL_REJECT_PLAN".to_owned(),
            detail: e.to_string(),
        },
    }
}

/// RetryTask — transition a Failed task back to Admitted.
/// Spec: "retry_task — transition a Failed task back to Admitted."
async fn handle_retry_task(task_id: String, ctx: &HandlerContext) -> OperatorResponse {
    let store_for_blocking = Arc::clone(&ctx.store);
    let task_id_for_blocking = task_id.clone();
    // `INV-DASHBOARD-PUSH-FSM-COMPLETENESS-01` — pass the audit
    // sink through so the operator-driven `Failed → Admitted` edge
    // surfaces on the dashboard's `SubscribeInitiative` push
    // stream. Pre-fix this transition only emitted a structured
    // log line and the dashboard never observed the retry.
    let audit_for_blocking: Arc<dyn raxis_audit_tools::AuditSink> = Arc::clone(&ctx.audit);
    let join_result = tokio::task::spawn_blocking(move || {
        lifecycle::retry_task(
            &task_id_for_blocking,
            &store_for_blocking,
            Some(audit_for_blocking.as_ref()),
        )
    })
    .await;
    let outcome = match join_result {
        Ok(r) => r,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_RETRY_TASK".to_owned(),
                detail: format!("retry_task spawn_blocking join failed: {e}"),
            }
        }
    };
    match outcome {
        Ok(()) => OperatorResponse::Ack {
            message: format!("task {task_id} retried (→ Admitted)"),
        },
        Err(e) => OperatorResponse::Error {
            code: "FAIL_RETRY_TASK".to_owned(),
            detail: e.to_string(),
        },
    }
}

/// ResumeTask — transition a BlockedRecoveryPending task → Admitted.
/// Spec: "BlockedRecoveryPending → Admitted (operator resume)".
/// Uses task_transitions directly: the FSM edge BlockedRecoveryPending→Admitted
/// is legal per the FSM table in task_transitions.rs.
async fn handle_resume_task(
    task_id: String,
    resumed_by: String,
    ctx: &HandlerContext,
) -> OperatorResponse {
    use crate::initiatives::task_transitions::{transition_task_with_audit, TransitionActor};
    use raxis_types::TaskState;

    let store_for_blocking = Arc::clone(&ctx.store);
    let task_id_for_blocking = task_id.clone();
    let resumed_by_for_blocking = resumed_by.clone();
    // `INV-DASHBOARD-PUSH-FSM-COMPLETENESS-01` — operator-driven
    // `BlockedRecoveryPending → Admitted` MUST surface on the
    // dashboard's `SubscribeInitiative` push stream. Use the
    // audit-aware `transition_task_with_audit` wrapper so the
    // paired-write fires post-commit.
    let audit_for_blocking: Arc<dyn raxis_audit_tools::AuditSink> = Arc::clone(&ctx.audit);
    let join_result = tokio::task::spawn_blocking(move || {
        let actor = TransitionActor::Operator {
            fingerprint: resumed_by_for_blocking,
        };
        transition_task_with_audit(
            &task_id_for_blocking,
            TaskState::Admitted,
            None,
            actor,
            &store_for_blocking,
            audit_for_blocking.as_ref(),
            None,
        )
    })
    .await;
    let outcome = match join_result {
        Ok(r) => r,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_RESUME_TASK".to_owned(),
                detail: format!("resume_task spawn_blocking join failed: {e}"),
            }
        }
    };
    match outcome {
        Ok(_record) => OperatorResponse::Ack {
            message: format!("task {task_id} resumed (→ Admitted)"),
        },
        Err(e) => OperatorResponse::Error {
            code: "FAIL_RESUME_TASK".to_owned(),
            detail: e.to_string(),
        },
    }
}

/// AbortTask — cancel a single non-terminal task.
async fn handle_abort_task(
    task_id: String,
    aborted_by: String,
    ctx: &HandlerContext,
) -> OperatorResponse {
    let store_for_blocking = Arc::clone(&ctx.store);
    let audit_for_blocking = Arc::clone(&ctx.audit);
    let task_id_for_blocking = task_id.clone();
    let aborted_by_for_blocking = aborted_by.clone();
    let join_result = tokio::task::spawn_blocking(move || {
        lifecycle::abort_task(
            &task_id_for_blocking,
            &aborted_by_for_blocking,
            &store_for_blocking,
            Some(audit_for_blocking.as_ref()),
        )
    })
    .await;
    let outcome = match join_result {
        Ok(r) => r,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_ABORT_TASK".to_owned(),
                detail: format!("abort_task spawn_blocking join failed: {e}"),
            }
        }
    };
    match outcome {
        Ok(()) => OperatorResponse::Ack {
            message: format!("task {task_id} aborted"),
        },
        Err(e) => OperatorResponse::Error {
            code: "FAIL_ABORT_TASK".to_owned(),
            detail: e.to_string(),
        },
    }
}

/// AbortInitiative — set status = Aborted; cancel all non-terminal tasks.
async fn handle_abort_initiative(
    initiative_id: String,
    aborted_by: String,
    ctx: &HandlerContext,
) -> OperatorResponse {
    let store_for_blocking = Arc::clone(&ctx.store);
    let audit_for_blocking = Arc::clone(&ctx.audit);
    let initiative_id_for_blocking = initiative_id.clone();
    let aborted_by_for_blocking = aborted_by.clone();
    let join_result = tokio::task::spawn_blocking(move || {
        lifecycle::abort_initiative(
            &initiative_id_for_blocking,
            &aborted_by_for_blocking,
            &store_for_blocking,
            Some(audit_for_blocking.as_ref()),
        )
    })
    .await;
    let outcome = match join_result {
        Ok(r) => r,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_ABORT_INITIATIVE".to_owned(),
                detail: format!("abort_initiative spawn_blocking join failed: {e}"),
            }
        }
    };
    match outcome {
        Ok(()) => OperatorResponse::Ack {
            message: format!("initiative {initiative_id} aborted"),
        },
        Err(e) => OperatorResponse::Error {
            code: "FAIL_ABORT_INITIATIVE".to_owned(),
            detail: e.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Quarantine handlers (kernel-store.md §2.5.8)
// ---------------------------------------------------------------------------
//
// Both handlers run their write through `tokio::task::spawn_blocking`
// because the storage helpers rely on `Store::lock_sync()` →
// `tokio::sync::Mutex::blocking_lock()` (panics on a tokio worker
// thread). This is the same pattern `handle_abort_initiative` uses
// above; `cap_reason` enforces the 512-byte ceiling on the operator-
// supplied reason string before any storage work begins.

const QUARANTINE_REASON_MAX_BYTES: usize = 512;

fn cap_reason(reason: Option<String>) -> Option<String> {
    reason.map(|s| {
        if s.len() <= QUARANTINE_REASON_MAX_BYTES {
            s
        } else {
            // UTF-8-aware truncation: walk back to the previous char
            // boundary so we never cut a multi-byte sequence in half.
            let mut end = QUARANTINE_REASON_MAX_BYTES;
            while !s.is_char_boundary(end) && end > 0 {
                end -= 1;
            }
            s[..end].to_owned()
        }
    })
}

/// QuarantineInitiative — insert one row into `initiative_quarantines`
/// (idempotent) + emit `InitiativeQuarantined` audit event on a fresh
/// insert.
async fn handle_quarantine_initiative(
    initiative_id: String,
    reason: Option<String>,
    operator: &AuthenticatedOperator,
    ctx: &HandlerContext,
) -> OperatorResponse {
    let reason_capped = cap_reason(reason);
    let store_arc = Arc::clone(&ctx.store);
    let initiative_clone = initiative_id.clone();
    let operator_fp = operator.fingerprint.clone();
    let now = raxis_types::unix_now_secs();
    let reason_for_blk = reason_capped.clone();
    // §2.5.2 "Operator display-name fields" — snapshot now, before
    // we cross the spawn_blocking boundary.
    let quarantined_by_display_name = ctx
        .policy
        .load_full()
        .operator_display_name(&operator.fingerprint);

    let join_result = tokio::task::spawn_blocking(move || {
        let mut conn = store_arc.lock_sync();
        let tx = conn.transaction()?;
        let was_new = raxis_store::views::initiative_quarantines::insert_single(
            &tx,
            &initiative_clone,
            &operator_fp,
            now,
            reason_for_blk.as_deref(),
        )?;
        tx.commit()?;
        Ok::<bool, QuarantineHandlerError>(was_new)
    })
    .await;

    let was_new = match join_result {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            return OperatorResponse::Error {
                code: "FAIL_QUARANTINE_INITIATIVE".to_owned(),
                detail: e.to_string(),
            }
        }
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_QUARANTINE_INITIATIVE".to_owned(),
                detail: format!("quarantine_initiative spawn_blocking join failed: {e}"),
            }
        }
    };

    if was_new {
        if let Err(e) = ctx.audit.emit(
            raxis_audit_tools::AuditEventKind::InitiativeQuarantined {
                initiative_id: initiative_id.clone(),
                quarantined_by: operator.fingerprint.clone(),
                reason: reason_capped,
                quarantined_by_display_name,
            },
            None,
            None,
            Some(initiative_id.as_str()),
        ) {
            // Audit emission is best-effort post-commit per
            // kernel-store.md §2.5.2 — log and proceed; the
            // reconciler will detect the gap on next boot.
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"InitiativeQuarantined\",\
                 \"audit_emit_failed\":\"{e}\",\"initiative_id\":\"{initiative_id}\"}}",
            );
        }
    }

    OperatorResponse::InitiativeQuarantined {
        initiative_id,
        quarantined_at: now,
        was_already_quarantined: !was_new,
    }
}

/// QuarantinePlansBy — sweep all initiatives whose plan was approved
/// by `target_fingerprint`, insert one row per initiative atomically,
/// and emit one `InitiativeQuarantined` per new row plus one rollup
/// `OperatorQuarantineSwept` event.
async fn handle_quarantine_plans_by(
    target_fingerprint: String,
    reason: Option<String>,
    operator: &AuthenticatedOperator,
    ctx: &HandlerContext,
) -> OperatorResponse {
    let reason_capped = cap_reason(reason);
    let store_arc = Arc::clone(&ctx.store);
    let target_clone = target_fingerprint.clone();
    let operator_fp = operator.fingerprint.clone();
    let now = raxis_types::unix_now_secs();
    let reason_for_blk = reason_capped.clone();
    // §2.5.2 "Operator display-name fields" — snapshot both
    // operator names from the same policy bundle. The *target*
    // operator may have already been removed from policy (this
    // sweep typically follows a `cert rotate-out` of the target),
    // in which case `target_display_name` is `None` and the CLI
    // render layer falls back to a historical lookup against the
    // `operator_certificates` view (which is also stale by then —
    // so the rendered name will be marked as historical, exactly
    // as `kernel-store.md` §2.5.2 prescribes).
    let policy_snapshot = ctx.policy.load_full();
    let quarantined_by_display_name = policy_snapshot.operator_display_name(&operator.fingerprint);
    let target_display_name = policy_snapshot.operator_display_name(&target_fingerprint);
    drop(policy_snapshot);

    let join_result = tokio::task::spawn_blocking(move || {
        let mut conn = store_arc.lock_sync();
        let tx = conn.transaction()?;
        let newly = raxis_store::views::initiative_quarantines::sweep_for_operator(
            &tx,
            &target_clone,
            &operator_fp,
            now,
            reason_for_blk.as_deref(),
        )?;
        tx.commit()?;
        Ok::<Vec<String>, QuarantineHandlerError>(newly)
    })
    .await;

    let newly_quarantined_ids = match join_result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return OperatorResponse::Error {
                code: "FAIL_QUARANTINE_PLANS_BY".to_owned(),
                detail: e.to_string(),
            }
        }
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_QUARANTINE_PLANS_BY".to_owned(),
                detail: format!("quarantine_plans_by spawn_blocking join failed: {e}"),
            }
        }
    };

    // One per-initiative event PLUS the rollup. Per-initiative
    // events let the audit chain answer "what did this command
    // touch?" without a join; the rollup answers "did the
    // operator press the big red button?".
    for id in &newly_quarantined_ids {
        if let Err(e) = ctx.audit.emit(
            raxis_audit_tools::AuditEventKind::InitiativeQuarantined {
                initiative_id: id.clone(),
                quarantined_by: operator.fingerprint.clone(),
                reason: reason_capped.clone(),
                quarantined_by_display_name: quarantined_by_display_name.clone(),
            },
            None,
            None,
            Some(id.as_str()),
        ) {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"InitiativeQuarantined\",\
                 \"audit_emit_failed\":\"{e}\",\"initiative_id\":\"{id}\"}}",
            );
        }
    }
    if let Err(e) = ctx.audit.emit(
        raxis_audit_tools::AuditEventKind::OperatorQuarantineSwept {
            target_fingerprint: target_fingerprint.clone(),
            quarantined_by: operator.fingerprint.clone(),
            count: newly_quarantined_ids.len() as u64,
            reason: reason_capped,
            quarantined_by_display_name,
            target_display_name,
        },
        None,
        None,
        None,
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"OperatorQuarantineSwept\",\
             \"audit_emit_failed\":\"{e}\",\"target\":\"{target_fingerprint}\"}}",
        );
    }

    OperatorResponse::QuarantineSwept {
        target_fingerprint,
        newly_quarantined_ids,
        quarantined_at: now,
    }
}

// SWEEP-IGNORE-BEGIN
/// Internal error shim for the quarantine handlers — collapses the
/// two distinct error sources (sqlite + the typed view-error) into
/// one Display-able value the dispatcher can surface verbatim in
/// `OperatorResponse::Error.detail`.
// SWEEP-IGNORE-END
#[derive(Debug)]
enum QuarantineHandlerError {
    Sqlite(rusqlite::Error),
    View(raxis_store::views::initiative_quarantines::QuarantineViewError),
}

impl std::fmt::Display for QuarantineHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "sqlite: {e}"),
            Self::View(e) => write!(f, "{e}"),
        }
    }
}
impl From<rusqlite::Error> for QuarantineHandlerError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}
impl From<raxis_store::views::initiative_quarantines::QuarantineViewError>
    for QuarantineHandlerError
{
    fn from(e: raxis_store::views::initiative_quarantines::QuarantineViewError) -> Self {
        Self::View(e)
    }
}

// ---------------------------------------------------------------------------
// Escalation review handlers (kernel-store.md §2.5.5)
// ---------------------------------------------------------------------------

/// `ApproveEscalation` — flips a `Pending` escalation to `Approved`,
/// inserts an `approval_tokens` row, and returns the high-entropy raw
/// token to the operator. The operator passes the token to the planner
/// out-of-band; subsequent intent submissions present the token and the
/// kernel re-derives `sha256(raw)` to look it up (kernel-core.md
/// §2.3 `validate_approval_token`).
///
/// The actual FSM call goes through `tokio::task::spawn_blocking`
/// because `authority::escalation::approve_escalation` reaches into
/// `Store::lock_sync()` (sync `tokio::sync::Mutex::blocking_lock`),
/// which panics if called directly from an async task. Same pattern
/// `main.rs` uses for `recovery::reconcile` and the verifier-token
/// issuance path in `gates::verifier_runner`.
async fn handle_approve_escalation(
    escalation_id: String,
    approval_scope: raxis_types::operator_wire::ApprovalScopeWire,
    operator_sig_hex: String,
    operator: &AuthenticatedOperator,
    ctx: &Arc<HandlerContext>,
) -> OperatorResponse {
    // `INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01` — pre-classify
    // the escalation by class + initiator. The kernel-initiated
    // `LogicalDeadlock` class follows a separate path: no
    // capability-class signature verification (the operator's
    // approval IS the action; nothing is bound for downstream
    // intent consumption), no `approval_tokens` row mint. Routed
    // to `approve_logical_deadlock_escalation_in_tx` and an
    // `OperatorApprovedRespawnEscalation` audit event in lieu of
    // the standard `EscalationApproved`.
    let class_lookup = lookup_escalation_class_initiator(&ctx.store, &escalation_id).await;
    if let Ok(Some((class, initiator))) = &class_lookup {
        if class == "LogicalDeadlock" && initiator == "Kernel" {
            return handle_approve_logical_deadlock(escalation_id, operator, ctx).await;
        }
    }

    let signature = match hex::decode(&operator_sig_hex) {
        Ok(b) => b,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_APPROVE_ESCALATION".to_owned(),
                detail: format!("operator_sig_hex is not valid hex: {e}"),
            }
        }
    };
    handle_approve_escalation_standard_path(escalation_id, approval_scope, signature, operator, ctx)
        .await
}

/// One-shot lookup of `(class, initiator)` for an `escalations`
/// row. Returns `Ok(None)` on missing-row so the caller can decide
/// whether to fall through to the standard not-found path; returns
/// `Err` on SQL failure (caller logs + falls through).
async fn lookup_escalation_class_initiator(
    store: &Arc<raxis_store::Store>,
    escalation_id: &str,
) -> Result<Option<(String, String)>, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    let store_for_blocking = Arc::clone(store);
    let escalation_id_for_blocking = escalation_id.to_owned();
    tokio::task::spawn_blocking(
        move || -> Result<Option<(String, String)>, rusqlite::Error> {
            let conn = store_for_blocking.lock_sync();
            let row: Option<(String, String)> = conn
                .query_row(
                    &format!(
                        "SELECT class, initiator FROM {ESCALATIONS}
                  WHERE escalation_id = ?1",
                        ESCALATIONS = raxis_store::Table::Escalations.as_str(),
                    ),
                    rusqlite::params![&escalation_id_for_blocking],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )
                .optional()?;
            Ok(row)
        },
    )
    .await
    .unwrap_or_else(|join_err| {
        Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
            std::io::Error::other(format!("join failed: {join_err}")),
        )))
    })
}

/// `INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01` — kernel-initiated
/// `LogicalDeadlock` approval path. Resets the orch-respawn
/// counter, transitions the initiative back to `Executing`, and
/// emits `OperatorApprovedRespawnEscalation` post-commit. The
/// caller (`handle_approve_escalation`) pre-classified the
/// escalation as LogicalDeadlock + initiator='Kernel' before
/// dispatching here.
async fn handle_approve_logical_deadlock(
    escalation_id: String,
    operator: &AuthenticatedOperator,
    ctx: &Arc<HandlerContext>,
) -> OperatorResponse {
    let store_for_blocking = Arc::clone(&ctx.store);
    let escalation_id_blocking = escalation_id.clone();
    let join_result = tokio::task::spawn_blocking(
        move || -> Result<
            Option<crate::orch_respawn_ceiling::ApproveLogicalDeadlockOutcome>,
            rusqlite::Error,
        > {
            let mut conn = store_for_blocking.lock_sync();
            let tx = conn.transaction()?;
            let outcome =
                crate::orch_respawn_ceiling::approve_logical_deadlock_escalation_in_tx(
                    &tx,
                    &escalation_id_blocking,
                    raxis_types::unix_now_secs(),
                )?;
            tx.commit()?;
            Ok(outcome)
        },
    )
    .await;

    let (initiative_id, transitioned_from_failed) = match join_result {
        Ok(Ok(Some(outcome))) => (outcome.initiative_id, outcome.transitioned_from_failed),
        Ok(Ok(None)) => {
            return OperatorResponse::Error {
                code:   "FAIL_APPROVE_ESCALATION".to_owned(),
                detail: format!(
                    "escalation {escalation_id} is not a Pending kernel-initiated LogicalDeadlock row"
                ),
            };
        }
        Ok(Err(e)) => {
            return OperatorResponse::Error {
                code: "FAIL_APPROVE_ESCALATION".to_owned(),
                detail: format!("approve_logical_deadlock SQL error: {e}"),
            };
        }
        Err(join_err) => {
            return OperatorResponse::Error {
                code: "FAIL_APPROVE_ESCALATION".to_owned(),
                detail: format!("approve_logical_deadlock join failed: {join_err}"),
            };
        }
    };

    if let Err(e) = ctx.audit.emit(
        raxis_audit_tools::AuditEventKind::OperatorApprovedRespawnEscalation {
            initiative_id: initiative_id.clone(),
            escalation_id: escalation_id.clone(),
            operator_id: operator.fingerprint.clone(),
        },
        None,
        None,
        Some(&initiative_id),
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"OperatorApprovedRespawnEscalation\",\
             \"audit_emit_failed\":\"{e}\",\"escalation_id\":\"{escalation_id}\"}}",
        );
    }

    // INV-AUDIT-OPERATOR-APPROVE-DEADLOCK-PAIRED-WRITE-01 — emit the
    // `InitiativeStateChanged` paired-write whenever the operator's
    // approval drove a real `Failed → Executing` FSM transition.
    // `transitioned_from_failed` is the row-count signal returned by
    // `approve_logical_deadlock_escalation_in_tx`; a `false` value
    // means the SQL UPDATE matched no row (rare race) and we MUST
    // skip the audit emit to keep the chain truthful per
    // `INV-AUDIT-TASK-STATE-CHANGED-PAIRED-WRITE-01`'s sibling rule
    // for initiatives.
    if transitioned_from_failed {
        if let Err(e) = ctx.audit.emit(
            raxis_audit_tools::AuditEventKind::InitiativeStateChanged {
                initiative_id: initiative_id.clone(),
                from_state: "Failed".to_owned(),
                to_state: "Executing".to_owned(),
            },
            None,
            None,
            Some(&initiative_id),
        ) {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"InitiativeStateChanged\",\
                 \"audit_emit_failed\":\"{e}\",\"initiative_id\":\"{initiative_id}\"}}",
            );
        }
    }

    // Schedule the orchestrator respawn so the operator's "approve
    // = retry" semantic actually fires a new orchestrator session.
    // The respawn driver's own ceiling check will run again on
    // entry, but starts fresh because we just reset the counter.
    let ctx_for_respawn = Arc::clone(ctx);
    let init_for_respawn = initiative_id.clone();
    tokio::spawn(async move {
        // `INV-ORCHESTRATOR-NNSP-COUNTER-EXCLUDES-CAPACITY-PRESSURE-01`
        // — operator-driven escalation-approval respawn. There is
        // no preceding capacity-pressure-rejected session here
        // (this is a fresh restart of the orchestrator after the
        // operator approved the LogicalDeadlock escalation); pass
        // `false`.
        let _ = crate::session_spawn_orchestrator::respawn_orchestrator_for_initiative(
            &init_for_respawn,
            ctx_for_respawn,
            false,
        )
        .await;
    });

    OperatorResponse::EscalationApproved {
        escalation_id,
        approval_token_id: String::new(),
        approval_token_raw: String::new(),
        expires_at: 0,
    }
}

async fn handle_approve_escalation_standard_path(
    escalation_id: String,
    approval_scope: raxis_types::operator_wire::ApprovalScopeWire,
    signature: Vec<u8>,
    operator: &AuthenticatedOperator,
    ctx: &Arc<HandlerContext>,
) -> OperatorResponse {
    // Pin one snapshot of the bundle: the FSM call below must run
    // against the same epoch we recorded in the audit metadata.
    let policy_snapshot = ctx.policy.load_full();
    // §2.5.2 "Operator display-name fields" — snapshot the
    // operator's display name from the same bundle the FSM call
    // will use. We resolve before `policy_snapshot` moves into
    // `spawn_blocking` so the audit emit (which runs after the
    // join) can use the cached value without re-loading the
    // ArcSwap (which might point at a newer epoch by then).
    let approved_by_display_name = policy_snapshot.operator_display_name(&operator.fingerprint);
    let store_for_blocking = Arc::clone(&ctx.store);
    let fp_for_blocking = operator.fingerprint.clone();
    let escalation_id_blocking = escalation_id.clone();
    let scope_for_blocking = approval_scope.clone();
    let policy_epoch = policy_snapshot.epoch();

    let join_result = tokio::task::spawn_blocking(move || {
        crate::authority::escalation::approve_escalation(
            &escalation_id_blocking,
            &scope_for_blocking,
            &signature,
            &fp_for_blocking,
            policy_epoch,
            &policy_snapshot,
            &store_for_blocking,
        )
    })
    .await;

    let approve_outcome = match join_result {
        Ok(r) => r,
        Err(join_err) => {
            return OperatorResponse::Error {
                code: "FAIL_APPROVE_ESCALATION".to_owned(),
                detail: format!("approve_escalation spawn_blocking join failed: {join_err}"),
            }
        }
    };

    match approve_outcome {
        Ok(result) => {
            // Audit emission MUST follow a successful SQLite commit
            // (kernel-store.md §2.5.2). `approve_escalation` already
            // returned Ok so the row is in place; failures here are
            // logged but do not propagate so the operator's intent is
            // still honoured (`recovery::reconcile` will detect any
            // §2.5.2 commit-vs-audit gap on next boot).
            // `approved_by_display_name` was snapshotted from the
            // same policy bundle the FSM ran against (see the pre-
            // spawn_blocking section above) so the audit row reflects
            // the operator's name at approval time, not whatever
            // the ArcSwap currently points at.
            if let Err(e) = ctx.audit.emit(
                raxis_audit_tools::AuditEventKind::EscalationApproved {
                    escalation_id: escalation_id.clone(),
                    approved_by: operator.fingerprint.clone(),
                    approved_by_display_name,
                },
                None,
                None,
                None,
            ) {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"EscalationApproved\",\
                     \"audit_emit_failed\":\"{e}\",\"escalation_id\":\"{escalation_id}\"}}",
                );
            }
            OperatorResponse::EscalationApproved {
                escalation_id,
                approval_token_id: result.approval_token_id,
                approval_token_raw: result.approval_token_raw,
                expires_at: result.expires_at,
            }
        }
        Err(e) => OperatorResponse::Error {
            code: e.error_code().to_owned(),
            detail: e.to_string(),
        },
    }
}

/// `INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01` — kernel-initiated
/// `LogicalDeadlock` deny path. Flips
/// `escalations.status = 'Denied'`, leaves the initiative `Failed`,
/// leaves the orch-respawn counter at its post-ceiling value, and
/// emits `OperatorDeniedRespawnEscalation` post-commit.
async fn handle_deny_logical_deadlock(
    escalation_id: String,
    reason: Option<String>,
    operator: &AuthenticatedOperator,
    ctx: &Arc<HandlerContext>,
) -> OperatorResponse {
    if let Some(r) = reason.as_ref() {
        if r.chars().count() > 512 {
            return OperatorResponse::Error {
                code: "FAIL_DENY_ESCALATION".to_owned(),
                detail: format!(
                    "reason exceeds 512-character limit (was {} chars)",
                    r.chars().count()
                ),
            };
        }
    }

    let store_for_blocking = Arc::clone(&ctx.store);
    let escalation_id_blocking = escalation_id.clone();
    let reason_for_blocking = reason.clone();
    let join_result =
        tokio::task::spawn_blocking(move || -> Result<Option<String>, rusqlite::Error> {
            let mut conn = store_for_blocking.lock_sync();
            let tx = conn.transaction()?;
            let initiative_id =
                crate::orch_respawn_ceiling::deny_logical_deadlock_escalation_in_tx(
                    &tx,
                    &escalation_id_blocking,
                    raxis_types::unix_now_secs(),
                    reason_for_blocking.as_deref(),
                )?;
            tx.commit()?;
            Ok(initiative_id)
        })
        .await;

    let initiative_id = match join_result {
        Ok(Ok(Some(id))) => id,
        Ok(Ok(None)) => {
            return OperatorResponse::Error {
                code:   "FAIL_DENY_ESCALATION".to_owned(),
                detail: format!(
                    "escalation {escalation_id} is not a Pending kernel-initiated LogicalDeadlock row"
                ),
            };
        }
        Ok(Err(e)) => {
            return OperatorResponse::Error {
                code: "FAIL_DENY_ESCALATION".to_owned(),
                detail: format!("deny_logical_deadlock SQL error: {e}"),
            };
        }
        Err(join_err) => {
            return OperatorResponse::Error {
                code: "FAIL_DENY_ESCALATION".to_owned(),
                detail: format!("deny_logical_deadlock join failed: {join_err}"),
            };
        }
    };

    if let Err(e) = ctx.audit.emit(
        raxis_audit_tools::AuditEventKind::OperatorDeniedRespawnEscalation {
            initiative_id: initiative_id.clone(),
            escalation_id: escalation_id.clone(),
            operator_id: operator.fingerprint.clone(),
        },
        None,
        None,
        Some(&initiative_id),
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"OperatorDeniedRespawnEscalation\",\
             \"audit_emit_failed\":\"{e}\",\"escalation_id\":\"{escalation_id}\"}}",
        );
    }

    let _ = operator;
    OperatorResponse::EscalationDenied {
        escalation_id,
        denied_at: raxis_types::unix_now_secs(),
    }
}

/// `DenyEscalation` — flips a `Pending` escalation to `Denied`. No
/// approval artifact is created (no `approval_tokens` row); the audit
/// event is the only durable record per kernel-store.md §2.5.5.
async fn handle_deny_escalation(
    escalation_id: String,
    reason: Option<String>,
    operator: &AuthenticatedOperator,
    ctx: &Arc<HandlerContext>,
) -> OperatorResponse {
    // `INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01` — pre-classify
    // and dispatch kernel-initiated `LogicalDeadlock` rows to the
    // dedicated deny path that emits
    // `OperatorDeniedRespawnEscalation` instead of the generic
    // `EscalationDenied`.
    let class_lookup = lookup_escalation_class_initiator(&ctx.store, &escalation_id).await;
    if let Ok(Some((class, initiator))) = &class_lookup {
        if class == "LogicalDeadlock" && initiator == "Kernel" {
            return handle_deny_logical_deadlock(escalation_id, reason, operator, ctx).await;
        }
    }

    if let Some(r) = reason.as_ref() {
        if r.chars().count() > 512 {
            return OperatorResponse::Error {
                code: "FAIL_DENY_ESCALATION".to_owned(),
                detail: format!(
                    "reason exceeds 512-character limit (was {} chars)",
                    r.chars().count()
                ),
            };
        }
    }
    // §2.5.2 "Operator display-name fields" — snapshot the
    // operator's display name from the live policy before doing
    // any blocking work. The deny path doesn't otherwise pin a
    // bundle (it has no FSM-vs-epoch coupling like approve does),
    // but we still want a consistent audit-emit name.
    let denied_by_display_name = ctx
        .policy
        .load_full()
        .operator_display_name(&operator.fingerprint);
    let store_for_blocking = Arc::clone(&ctx.store);
    let fp_for_blocking = operator.fingerprint.clone();
    let escalation_id_blocking = escalation_id.clone();
    let reason_for_blocking = reason.clone();
    let join_result = tokio::task::spawn_blocking(move || {
        crate::authority::escalation::deny_escalation(
            &escalation_id_blocking,
            reason_for_blocking.as_deref(),
            &fp_for_blocking,
            &store_for_blocking,
        )
    })
    .await;
    let deny_outcome = match join_result {
        Ok(r) => r,
        Err(join_err) => {
            return OperatorResponse::Error {
                code: "FAIL_DENY_ESCALATION".to_owned(),
                detail: format!("deny_escalation spawn_blocking join failed: {join_err}"),
            }
        }
    };
    match deny_outcome {
        Ok(result) => {
            if let Err(e) = ctx.audit.emit(
                raxis_audit_tools::AuditEventKind::EscalationDenied {
                    escalation_id: escalation_id.clone(),
                    denied_by: operator.fingerprint.clone(),
                    reason: reason.clone(),
                    denied_by_display_name,
                },
                None,
                None,
                None,
            ) {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"EscalationDenied\",\
                     \"audit_emit_failed\":\"{e}\",\"escalation_id\":\"{escalation_id}\"}}",
                );
            }
            OperatorResponse::EscalationDenied {
                escalation_id,
                denied_at: result.denied_at,
            }
        }
        Err(e) => OperatorResponse::Error {
            code: e.error_code().to_owned(),
            detail: e.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// RotateEpoch handler (kernel-core.md §`policy_manager.rs`)
// ---------------------------------------------------------------------------

/// `RotateEpoch` — operator-initiated in-process policy advance.
///
/// Pipeline (kernel-core.md §`policy_manager.rs`):
///   1. Canonicalise both paths and confirm they resolve under
///      `<data_dir>/policy/`. Out-of-tree paths are rejected with
///      `FAIL_POLICY_PATH_OUTSIDE_DATA_DIR` BEFORE either file is opened.
///   2. Run `policy_manager::advance_epoch` (Phase 0 verification +
///      Phase 1 SQL transaction + Phase 2 ArcSwap). The function is
///      synchronous and reaches `Store::lock_sync()`, so it MUST run
///      inside `tokio::task::spawn_blocking` to avoid panicking the
///      tokio runtime.
///   3. On `PolicyError` from Phase 0, emit `PolicyAdvanceRejected`
///      audit (the dispatcher's responsibility per the spec).
///      On `PolicyError` from Phase 1, emit `PolicyAdvanceFailed`
///      (the SQL transaction was rolled back; in-memory state
///      unchanged, but operator forensics need a marker).
///   4. On success, return `OperatorResponse::EpochAdvanced` with
///      sweep counts and the artifact identity.
///
/// **Phase 3 (gateway signal).** After a successful `advance_epoch`,
/// fire `ctx.gateway.notify_epoch_advanced(new_epoch_id)` to nudge the
/// gateway into reloading `policy.toml`. Per kernel-core.md
/// §`policy_manager.rs`, this is **best-effort** — if the gateway is
/// down, in respawn back-off, or the write fails mid-flight, we
/// emit `AuditEventKind::GatewaySignalFailed` and return success
/// anyway. The gateway's own failure-closed contract (returns
/// `PolicyReloadFailed` on its next request when its on-disk
/// allowlist is stale, peripherals.md §3.2) is the second line of
/// defence; the operator-visible epoch advance is committed and
/// readers already see the new bundle through the `ArcSwap`.
async fn handle_rotate_epoch(
    policy_path: String,
    sig_path: String,
    operator: &AuthenticatedOperator,
    ctx: &HandlerContext,
) -> OperatorResponse {
    use crate::policy_manager;

    let policy_path_buf = std::path::PathBuf::from(&policy_path);
    let sig_path_buf = std::path::PathBuf::from(&sig_path);

    // Step 1: path containment. Done before opening the files so a
    // non-existent path under data_dir surfaces as a `read failed`
    // (forensically distinct from a real path that escapes).
    let policy_dir = ctx.data_dir.join("policy");
    for (label, path) in [
        ("policy_path", &policy_path_buf),
        ("sig_path", &sig_path_buf),
    ] {
        if let Err(e) = policy_manager::canonicalize_under_data_dir(path, &policy_dir) {
            // Emit PolicyAdvanceRejected for forensic visibility, then
            // surface the typed error code on the wire.
            emit_policy_advance_rejected(ctx, &operator.fingerprint, &policy_path, &sig_path, &e);
            return OperatorResponse::Error {
                code: e.error_code().to_owned(),
                detail: format!("{label}: {e}"),
            };
        }
    }

    // Step 2: spawn_blocking around the synchronous advance pipeline.
    // We clone the Arcs we need into the closure; everything else
    // (KeyRegistry, Store, AuditSink, ArcSwap<PolicyBundle>) is
    // already an Arc on `ctx`.
    let registry_for_blocking = Arc::clone(&ctx.registry);
    let store_for_blocking = Arc::clone(&ctx.store);
    let audit_for_blocking = Arc::clone(&ctx.audit);
    let policy_for_blocking = Arc::clone(&ctx.policy);
    let binding_for_blocking = Arc::clone(&ctx.epoch_binding);
    let artifact_for_blocking = ctx.artifact_store.as_ref().map(Arc::clone);
    let triggered_by = operator.fingerprint.clone();
    let policy_path_blocking = policy_path_buf.clone();
    let sig_path_blocking = sig_path_buf.clone();

    let join_outcome = tokio::task::spawn_blocking(move || {
        policy_manager::advance_epoch(
            &policy_path_blocking,
            &sig_path_blocking,
            &triggered_by,
            &registry_for_blocking,
            &policy_for_blocking,
            &store_for_blocking,
            &audit_for_blocking,
            &binding_for_blocking,
            artifact_for_blocking.as_deref(),
        )
    })
    .await;

    let advance_result = match join_outcome {
        Ok(r) => r,
        Err(join_err) => {
            return OperatorResponse::Error {
                code: "FAIL_POLICY_STORE_WRITE".to_owned(),
                detail: format!("advance_epoch spawn_blocking join failed: {join_err}"),
            };
        }
    };

    match advance_result {
        Ok(outcome) => {
            // Phase 3: best-effort gateway signal. Per spec, must NOT
            // affect the response or roll back the advance — log the
            // outcome via `GatewaySignalFailed` and move on.
            if let Err(e) = ctx
                .gateway
                .notify_epoch_advanced(outcome.new_epoch_id)
                .await
            {
                emit_gateway_signal_failed(ctx, "EpochAdvanced", Some(outcome.new_epoch_id), &e);
            }
            OperatorResponse::EpochAdvanced {
                new_epoch_id: outcome.new_epoch_id,
                policy_sha256: outcome.policy_sha256,
                signed_by_authority: outcome.signed_by_authority,
                n_delegations_marked_stale: outcome.n_delegations_marked_stale,
                n_sessions_invalidated: outcome.n_sessions_invalidated,
                advanced_at: outcome.advanced_at_unix_secs,
            }
        }
        Err(e) => {
            // Phase-distinguished audit. Phase 0 failures
            // (signature, replay, malformed, path outside) get
            // `PolicyAdvanceRejected`; Phase 1 failures
            // (transactional SQL trouble after BEGIN succeeded) get
            // `PolicyAdvanceFailed`. The error variants line up
            // 1:1 with the Phase contract in
            // kernel-core.md §`policy_manager.rs`.
            match e {
                policy_manager::PolicyError::SignatureInvalid { .. }
                | policy_manager::PolicyError::EpochReplay { .. }
                | policy_manager::PolicyError::MalformedArtifact { .. }
                | policy_manager::PolicyError::PathOutsideDataDir { .. }
                | policy_manager::PolicyError::ArtifactReadFailed { .. } => {
                    emit_policy_advance_rejected(
                        ctx,
                        &operator.fingerprint,
                        &policy_path,
                        &sig_path,
                        &e,
                    );
                }
                policy_manager::PolicyError::PolicyArtifactAlreadyInstalled { .. }
                | policy_manager::PolicyError::StoreWriteFailed { .. } => {
                    emit_policy_advance_failed(ctx, &e);
                }
            }
            OperatorResponse::Error {
                code: e.error_code().to_owned(),
                detail: e.to_string(),
            }
        }
    }
}

/// Emit `AuditEventKind::PolicyAdvanceRejected`. Failures here are
/// logged to stderr — the operator already received the typed wire
/// error so the audit miss is forensic noise, not a correctness gap.
fn emit_policy_advance_rejected(
    ctx: &HandlerContext,
    triggered_by: &str,
    policy_path: &str,
    sig_path: &str,
    err: &crate::policy_manager::PolicyError,
) {
    use crate::policy_manager::PolicyError;

    // The audit event carries a structured `(reason, attempted_epoch,
    // current_epoch)` triple. We extract the epoch hint where it
    // is meaningful (EpochReplay knows both); for other variants we
    // pass `None` and `0` respectively.
    let (artifact_epoch, current_epoch) = match err {
        PolicyError::EpochReplay { attempted, current } => (Some(*attempted), *current),
        _ => (None, 0u64),
    };
    let reason = format!(
        "{err}; triggered_by={triggered_by} policy_path={policy_path} sig_path={sig_path}",
    );
    if let Err(e) = ctx.audit.emit(
        raxis_audit_tools::AuditEventKind::PolicyAdvanceRejected {
            reason,
            artifact_epoch,
            current_epoch,
        },
        None,
        None,
        None,
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"PolicyAdvanceRejected\",\
             \"audit_emit_failed\":\"{e}\"}}",
        );
    }
}

/// Emit `AuditEventKind::GatewaySignalFailed` for a Phase 3 failure
/// in `handle_rotate_epoch`. The reason string is stable
/// (`GatewayCallError::category()`) so forensic tooling can group by
/// failure mode without parsing free-form text.
fn emit_gateway_signal_failed(
    ctx: &HandlerContext,
    signal_kind: &str,
    new_epoch_id: Option<u64>,
    err: &crate::gateway::GatewayCallError,
) {
    if let Err(e) = ctx.audit.emit(
        raxis_audit_tools::AuditEventKind::GatewaySignalFailed {
            signal: signal_kind.to_owned(),
            new_epoch_id,
            reason: err.category().to_owned(),
        },
        None,
        None,
        None,
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"GatewaySignalFailed\",\
             \"audit_emit_failed\":\"{e}\",\"signal\":\"{signal_kind}\",\
             \"reason\":\"{}\"}}",
            err.category(),
        );
    }
}

/// Emit `AuditEventKind::PolicyAdvanceFailed`. Same logging
/// guarantees as `emit_policy_advance_rejected`.
fn emit_policy_advance_failed(ctx: &HandlerContext, err: &crate::policy_manager::PolicyError) {
    let reason = err.to_string();
    if let Err(e) = ctx.audit.emit(
        raxis_audit_tools::AuditEventKind::PolicyAdvanceFailed {
            reason,
            // Phase 1 is post-verification, but we don't have the
            // verified bundle in scope here. The audit event's
            // `new_epoch_id` field is best-effort and would need a
            // wider refactor to plumb through the verified epoch on
            // the failure path; pinned at 0 for now (operators read
            // the human reason for diagnostics).
            new_epoch_id: 0,
        },
        None,
        None,
        None,
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"PolicyAdvanceFailed\",\
             \"audit_emit_failed\":\"{e}\"}}",
        );
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn op_name(req: &OperatorRequest) -> &'static str {
    match req {
        OperatorRequest::CreateSession { .. } => "CreateSession",
        OperatorRequest::RevokeSession { .. } => "RevokeSession",
        OperatorRequest::GrantDelegation { .. } => "GrantDelegation",
        OperatorRequest::CreateInitiative { .. } => "CreateInitiative",
        OperatorRequest::ApprovePlan { .. } => "ApprovePlan",
        OperatorRequest::RejectPlan { .. } => "RejectPlan",
        OperatorRequest::RetryTask { .. } => "RetryTask",
        OperatorRequest::ResumeTask { .. } => "ResumeTask",
        OperatorRequest::AbortTask { .. } => "AbortTask",
        OperatorRequest::AbortInitiative { .. } => "AbortInitiative",
        OperatorRequest::ApproveEscalation { .. } => "ApproveEscalation",
        OperatorRequest::DenyEscalation { .. } => "DenyEscalation",
        OperatorRequest::RotateEpoch { .. } => "RotateEpoch",
        OperatorRequest::QuarantineInitiative { .. } => "QuarantineInitiative",
        OperatorRequest::QuarantinePlansBy { .. } => "QuarantinePlansBy",
        // operator-ergonomics stubs.
        OperatorRequest::ProposeDefaults { .. } => "ProposeDefaults",
        OperatorRequest::EstimateCost { .. } => "EstimateCost",
        OperatorRequest::DryRunAdmit { .. } => "DryRunAdmit",
        OperatorRequest::SubscribeInitiative { .. } => "SubscribeInitiative",
        OperatorRequest::DescribeInitiativePause { .. } => "DescribeInitiativePause",
        OperatorRequest::ListTaskOutputs { .. } => "ListTaskOutputs",
    }
}

// `write_response` was inlined into `dispatch_loop` once framing moved to
// `raxis_ipc::write_json_frame_async`. Kept this comment to explain the
// rename in case anyone diffs against the pre-PR-2 history.

// ---------------------------------------------------------------------------
// Tests — focused tests for the escalation dispatcher arms.
//
// The bulk of the FSM logic is unit-tested in
// `authority::escalation::tests`; what we cover here is the dispatcher-
// only behaviour:
//   * sig hex decoding,
//   * 512-char `reason` cap on DenyEscalation,
//   * `EscalationApproved` / `EscalationDenied` audit events fire after
//     a successful FSM transition, and
//   * `EscalationError` variants are mapped to the right operator
//     wire `code` strings.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod escalation_dispatch_tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    use ed25519_dalek::{Signer, SigningKey};
    use raxis_audit_tools::AuditEventKind;
    use raxis_policy::{OperatorEntry, PolicyBundle};
    use raxis_store::{Store, Table};
    use raxis_test_support::FakeAuditSink;
    use raxis_types::operator_wire::ApprovalScopeWire;
    use raxis_types::{EscalationClass, EscalationStatus};

    use crate::authority::escalation::approval_scope_signing_input;
    use crate::authority::keys::KeyRegistry;
    use crate::initiatives::PlanRegistry;
    use crate::ipc::auth::AuthenticatedOperator;

    // ── shared fixtures ───────────────────────────────────────────────

    const FP: &str = "op-prime";
    // INV-STORE-03: no raw SQL table-name literals in `kernel/src`.
    // The dispatcher tests below use these constants (and the various
    // `*State::as_sql_str()` methods) instead of inline string literals.
    const ESCALATIONS: &str = Table::Escalations.as_str();

    fn fixture_keypair() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn fixture_scope() -> ApprovalScopeWire {
        ApprovalScopeWire {
            capability_class: "WriteSecrets".into(),
            max_uses: 2,
            valid_for_seconds: 600,
        }
    }

    fn build_ctx(
        store: Arc<Store>,
        sink: Arc<FakeAuditSink>,
        sk: &SigningKey,
    ) -> Arc<HandlerContext> {
        let pubkey = hex::encode(sk.verifying_key().to_bytes());
        // Stub cert: this fixture exercises the operator IPC handlers
        // bypassing PolicyBundle::validate. See
        // `notifications::sink::tests::bundle` for the rationale.
        let cert = raxis_test_support::stub_cert_for_pubkey(pubkey.clone());
        let policy = PolicyBundle::for_tests_with_operators(vec![OperatorEntry {
            pubkey_fingerprint: FP.to_owned(),
            display_name: FP.to_owned(),
            pubkey_hex: pubkey,
            permitted_ops: vec![],
            cert,
            force_misconfig_bypass: false,
        }]);
        let data_dir = PathBuf::from("/tmp/raxis-test");
        let credentials =
            crate::ipc::context::build_default_test_credentials(&data_dir, sink.clone());
        let isolation = crate::ipc::context::build_fail_closed_test_isolation();
        let orchestrator_spawn = crate::ipc::context::build_test_orchestrator_spawn();
        let domain = crate::ipc::context::build_default_test_domain(&data_dir);
        Arc::new(HandlerContext::new(
            Arc::new(arc_swap::ArcSwap::from_pointee(policy)),
            Arc::new(KeyRegistry::stub_for_tests()),
            store,
            sink,
            data_dir,
            Arc::new(PlanRegistry::new()),
            Arc::new(crate::gateway::client::GatewayClient::new()),
            Arc::new(crate::prompt::EpochBinding::new()),
            credentials,
            isolation,
            orchestrator_spawn,
            crate::ipc::context::build_test_executor_spawn(),
            domain,
        ))
    }

    fn fixture_authenticated() -> AuthenticatedOperator {
        AuthenticatedOperator {
            fingerprint: FP.to_owned(),
            permitted_ops: vec!["ApproveEscalation".into(), "DenyEscalation".into()],
        }
    }

    /// Insert a Pending escalation row. We MUST use `tokio::task::spawn_blocking`
    /// because the dispatcher tests run under `#[tokio::test]`, where any
    /// synchronous `Store::lock_sync()` call from the runtime thread
    /// panics with "Cannot block the current thread from within a
    /// runtime" (kernel-store.md §2.5.1 sync-store contract).
    async fn insert_pending_escalation(store: Arc<Store>, escalation_id: &str) {
        let id = escalation_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = store.lock_sync();
            conn.execute("PRAGMA foreign_keys = OFF", []).unwrap();
            // The literal session/task/initiative/lineage values stay
            // inline here (no FK rows seeded — `PRAGMA foreign_keys = OFF`
            // above lets the test bypass referential integrity for the
            // dispatch path under test). Table name + escalation class
            // + status string come from typed sources per INV-STORE-03.
            let class = EscalationClass::CapabilityUpgrade.as_sql_str();
            let status = EscalationStatus::Pending.as_sql_str();
            conn.execute(
                &format!(
                    "INSERT INTO {ESCALATIONS} (
                        escalation_id, session_id, task_id, lineage_id, initiative_id,
                        class, requested_scope_json, justification, idempotency_key,
                        status, created_at, timeout_at
                     ) VALUES (?1, 'sess-1', 'task-1', 'lin-1', 'init-1',
                               ?2,
                               '{{\"kind\":\"CapabilityUpgrade\",\"capability\":\"WriteSecrets\"}}',
                               'unit-test', ?3, ?4, ?5, ?6)"
                ),
                rusqlite::params![
                    id,
                    class,
                    id,
                    status,
                    raxis_types::unix_now_secs(),
                    raxis_types::unix_now_secs() + 3600,
                ],
            )
            .unwrap();
            conn.execute("PRAGMA foreign_keys = ON", []).unwrap();
        })
        .await
        .unwrap();
    }

    /// Read a column from the escalations row from inside an async test.
    /// Same `spawn_blocking` requirement as `insert_pending_escalation`.
    async fn read_status(store: Arc<Store>, escalation_id: &str) -> String {
        let id = escalation_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = store.lock_sync();
            conn.query_row(
                &format!("SELECT status FROM {ESCALATIONS} WHERE escalation_id = ?1"),
                rusqlite::params![id],
                |r| r.get(0),
            )
            .unwrap()
        })
        .await
        .unwrap()
    }

    /// Force the escalation row's status (used to set up the
    /// "already-Approved" fixture for the NotPending error path).
    async fn force_status(store: Arc<Store>, escalation_id: &str, status: EscalationStatus) {
        let id = escalation_id.to_owned();
        let status_s = status.as_sql_str().to_owned();
        tokio::task::spawn_blocking(move || {
            store
                .lock_sync()
                .execute(
                    &format!("UPDATE {ESCALATIONS} SET status = ?1 WHERE escalation_id = ?2"),
                    rusqlite::params![status_s, id],
                )
                .unwrap();
        })
        .await
        .unwrap();
    }

    // ── ApproveEscalation ─────────────────────────────────────────────

    #[tokio::test]
    async fn approve_escalation_happy_path_returns_typed_response_and_emits_audit() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink = Arc::new(FakeAuditSink::new());
        let sk = fixture_keypair();
        let ctx = build_ctx(store.clone(), sink.clone(), &sk);
        let op = fixture_authenticated();
        let scope = fixture_scope();

        insert_pending_escalation(store.clone(), "esc-A").await;

        let sig = sk
            .sign(&approval_scope_signing_input("esc-A", &scope))
            .to_bytes()
            .to_vec();

        let resp =
            handle_approve_escalation("esc-A".into(), scope, hex::encode(&sig), &op, &ctx).await;

        match resp {
            OperatorResponse::EscalationApproved {
                escalation_id,
                approval_token_id,
                approval_token_raw,
                expires_at,
            } => {
                assert_eq!(escalation_id, "esc-A");
                assert!(uuid::Uuid::parse_str(&approval_token_id).is_ok());
                assert_eq!(approval_token_raw.len(), 64);
                assert!(expires_at > raxis_types::unix_now_secs());
            }
            other => panic!("expected EscalationApproved, got {other:?}"),
        }

        // Exactly one EscalationApproved audit event emitted.
        let kinds = sink.event_kinds();
        let approved_count = kinds.iter().filter(|k| **k == "EscalationApproved").count();
        assert_eq!(
            approved_count, 1,
            "exactly one EscalationApproved audit event must fire; got: {kinds:?}"
        );
        // Audit payload carries the right (escalation_id, approved_by) pair.
        let evt = sink
            .events()
            .into_iter()
            .find(|e| matches!(e.kind, AuditEventKind::EscalationApproved { .. }))
            .expect("EscalationApproved event present");
        match evt.kind {
            AuditEventKind::EscalationApproved {
                escalation_id,
                approved_by,
                approved_by_display_name,
            } => {
                assert_eq!(escalation_id, "esc-A");
                assert_eq!(approved_by, FP);
                // Display name should be populated when the operator's
                // fingerprint resolves in the test policy bundle, and
                // missing when the test harness doesn't seed an entry
                // for this fingerprint. Don't pin a specific value
                // here — the harness may grow operator entries in
                // future. Just assert the type round-trips.
                let _ = approved_by_display_name;
            }
            other => panic!("wrong event kind: {other:?}"),
        }
    }

    #[tokio::test]
    async fn approve_escalation_with_malformed_signature_hex_is_rejected() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink = Arc::new(FakeAuditSink::new());
        let ctx = build_ctx(store.clone(), sink.clone(), &fixture_keypair());
        let op = fixture_authenticated();
        insert_pending_escalation(store.clone(), "esc-1").await;

        let resp = handle_approve_escalation(
            "esc-1".into(),
            fixture_scope(),
            "ZZZ_not_hex".into(),
            &op,
            &ctx,
        )
        .await;

        match resp {
            OperatorResponse::Error { code, detail } => {
                assert_eq!(code, "FAIL_APPROVE_ESCALATION");
                assert!(
                    detail.contains("not valid hex"),
                    "detail must explain hex decode failure; got: {detail}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
        // No audit event fires when hex decode fails before the FSM call.
        assert!(!sink.event_kinds().contains(&"EscalationApproved"));
    }

    #[tokio::test]
    async fn approve_escalation_maps_not_pending_to_stable_error_code() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink = Arc::new(FakeAuditSink::new());
        let sk = fixture_keypair();
        let ctx = build_ctx(store.clone(), sink.clone(), &sk);
        let op = fixture_authenticated();
        let scope = fixture_scope();

        insert_pending_escalation(store.clone(), "esc-1").await;
        // Force the row to Approved so the second approve attempt fails.
        force_status(store.clone(), "esc-1", EscalationStatus::Approved).await;

        let sig = sk
            .sign(&approval_scope_signing_input("esc-1", &scope))
            .to_bytes()
            .to_vec();

        let resp =
            handle_approve_escalation("esc-1".into(), scope, hex::encode(&sig), &op, &ctx).await;

        match resp {
            OperatorResponse::Error { code, .. } => {
                assert_eq!(code, "FAIL_ESCALATION_NOT_PENDING");
            }
            other => panic!("expected NotPending Error, got {other:?}"),
        }
        // No audit event fires for failed approvals (the row never moved).
        assert!(!sink.event_kinds().contains(&"EscalationApproved"));
    }

    // ── DenyEscalation ────────────────────────────────────────────────

    #[tokio::test]
    async fn deny_escalation_happy_path_returns_typed_response_and_emits_audit() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink = Arc::new(FakeAuditSink::new());
        let ctx = build_ctx(store.clone(), sink.clone(), &fixture_keypair());
        let op = fixture_authenticated();
        insert_pending_escalation(store.clone(), "esc-D").await;

        let resp =
            handle_deny_escalation("esc-D".into(), Some("scope too broad".into()), &op, &ctx).await;

        match resp {
            OperatorResponse::EscalationDenied {
                escalation_id,
                denied_at,
            } => {
                assert_eq!(escalation_id, "esc-D");
                assert!(denied_at > 0);
            }
            other => panic!("expected EscalationDenied, got {other:?}"),
        }

        let evt = sink
            .events()
            .into_iter()
            .find(|e| matches!(e.kind, AuditEventKind::EscalationDenied { .. }))
            .expect("EscalationDenied event present");
        match evt.kind {
            AuditEventKind::EscalationDenied {
                escalation_id,
                denied_by,
                reason,
                denied_by_display_name,
            } => {
                assert_eq!(escalation_id, "esc-D");
                assert_eq!(denied_by, FP);
                assert_eq!(reason.as_deref(), Some("scope too broad"));
                let _ = denied_by_display_name;
            }
            other => panic!("wrong event kind: {other:?}"),
        }
    }

    #[tokio::test]
    async fn deny_escalation_rejects_reason_over_512_chars_before_touching_store() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink = Arc::new(FakeAuditSink::new());
        let ctx = build_ctx(store.clone(), sink.clone(), &fixture_keypair());
        let op = fixture_authenticated();
        insert_pending_escalation(store.clone(), "esc-1").await;

        let too_long: String = "x".repeat(513);
        let resp = handle_deny_escalation("esc-1".into(), Some(too_long), &op, &ctx).await;

        match resp {
            OperatorResponse::Error { code, detail } => {
                assert_eq!(code, "FAIL_DENY_ESCALATION");
                assert!(
                    detail.contains("512-character limit"),
                    "detail must call out the 512 cap; got: {detail}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
        // The escalation row MUST still be Pending — the cap fires
        // before any store write.
        assert_eq!(read_status(store.clone(), "esc-1").await, "Pending");
        // No audit event for a rejected denial.
        assert!(!sink.event_kinds().contains(&"EscalationDenied"));
    }

    // ── Regression: pre-existing handlers run under spawn_blocking (B.1) ─
    //
    // The 10 pre-existing operator handlers (CreateSession, RevokeSession,
    // GrantDelegation, CreateInitiative, ApprovePlan, RejectPlan,
    // RetryTask, ResumeTask, AbortTask, AbortInitiative) were calling
    // synchronous FSM functions directly inside `async fn` bodies. Those
    // FSMs use `Store::lock_sync()`, which calls
    // `tokio::sync::Mutex::blocking_lock()` and PANICS when invoked from
    // an async task ("Cannot block the current thread from within a
    // runtime"). Phase B.1 wrapped each handler's FSM call in
    // `tokio::task::spawn_blocking`. The tests below run a representative
    // handler (`handle_revoke_session`) end-to-end under `#[tokio::test]`
    // and assert it returns a structured response — which is impossible
    // unless the spawn_blocking wrapping is in place.
    //
    // We pick `handle_revoke_session` because it has the smallest input
    // surface: just a session_id. Hitting the not-found path forces the
    // FSM down to `lock_sync` even on the error side, so "no panic" is
    // the discriminator.
    //
    // V2.5 collapsed the V1 path-based `CreateInitiative` handler into
    // the sealed-bundle pipeline — the V1-shape spawn_blocking
    // regression test was removed alongside the handler, so the
    // `RevokeSession` test below carries the property on its own.

    #[tokio::test]
    async fn revoke_session_runs_under_tokio_without_panic() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink = Arc::new(FakeAuditSink::new());
        let ctx = build_ctx(store, sink, &fixture_keypair());

        let operator = AuthenticatedOperator {
            fingerprint: "test-revoke-fp".to_owned(),
            permitted_ops: vec!["RevokeSession".into()],
        };
        let resp = handle_revoke_session(
            "00000000-0000-4000-8000-000000000000".into(),
            &operator,
            &ctx,
        )
        .await;

        // Whatever the outcome, the test passing means the runtime did
        // not panic. The exact code is FAIL_REVOKE_SESSION because the
        // session row doesn't exist.
        match resp {
            OperatorResponse::Error { .. } | OperatorResponse::SessionRevoked { .. } => {}
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn deny_escalation_at_exactly_512_chars_is_accepted() {
        // Boundary: 512 is allowed, 513 is not (covered above).
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink = Arc::new(FakeAuditSink::new());
        let ctx = build_ctx(store.clone(), sink.clone(), &fixture_keypair());
        let op = fixture_authenticated();
        insert_pending_escalation(store.clone(), "esc-edge").await;

        let exactly_max: String = "x".repeat(512);
        let resp = handle_deny_escalation("esc-edge".into(), Some(exactly_max), &op, &ctx).await;
        assert!(matches!(resp, OperatorResponse::EscalationDenied { .. }));
    }

    // ─────────────────────────────────────────────────────────────────
    // End-to-end notification fanout (Phase B.4d).
    //
    // The dispatcher tests above use a bare `FakeAuditSink`. Production
    // wraps that sink with `NotifyingAuditSink` so every emit fans into
    // `notifications::dispatch`. The test below builds the *production*
    // sink shape, drives a real `handle_approve_escalation` end-to-end,
    // and asserts that the resulting JSONL line lands in the implicit
    // Shell channel inbox at `<data_dir>/notifications/inbox.jsonl`.
    //
    // Why this lives next to the dispatcher (and not in
    // `notifications::sink::tests`):
    //   - The unit test in `sink.rs` proves that `emit` fans out.
    //   - This test proves that the `handle_approve_escalation` wiring
    //     CALLS emit through the wrapping sink — i.e., that an operator
    //     dispatcher arm authored after the wrap-in still participates
    //     in the notification pipeline. Without this guard, a future
    //     refactor that bypasses `ctx.audit` (for example, hand-rolling
    //     a `FileAuditSink` inside the handler) would silently break
    //     operator notifications.
    // ─────────────────────────────────────────────────────────────────
    use crate::notifications::NotifyingAuditSink;
    use raxis_audit_tools::AuditSink;
    use std::time::Duration;

    /// Build a context whose `audit` field is the production
    /// `NotifyingAuditSink` wrapping a `FakeAuditSink`. The wrapping
    /// is what kicks the notification dispatcher; without it, no
    /// inbox line would be written even though the FSM transition
    /// committed cleanly.
    fn build_ctx_with_notifying_sink(
        store: Arc<Store>,
        data_dir: PathBuf,
        sk: &SigningKey,
    ) -> (Arc<HandlerContext>, Arc<FakeAuditSink>) {
        let pubkey = hex::encode(sk.verifying_key().to_bytes());
        let cert = raxis_test_support::stub_cert_for_pubkey(pubkey.clone());
        let policy_bundle = PolicyBundle::for_tests_with_operators(vec![OperatorEntry {
            pubkey_fingerprint: FP.to_owned(),
            display_name: FP.to_owned(),
            pubkey_hex: pubkey,
            permitted_ops: vec!["ApproveEscalation".into()],
            cert,
            force_misconfig_bypass: false,
        }]);
        let policy_swap = Arc::new(arc_swap::ArcSwap::from_pointee(policy_bundle));

        let inner: Arc<FakeAuditSink> = Arc::new(FakeAuditSink::new());
        let inner_dyn: Arc<dyn AuditSink> = Arc::clone(&inner) as Arc<dyn AuditSink>;
        let audit: Arc<dyn AuditSink> = Arc::new(NotifyingAuditSink::new(
            Arc::clone(&inner_dyn),
            Arc::clone(&policy_swap),
            data_dir.clone(),
        ));

        let credentials =
            crate::ipc::context::build_default_test_credentials(&data_dir, Arc::clone(&audit));
        let isolation = crate::ipc::context::build_fail_closed_test_isolation();
        let orchestrator_spawn = crate::ipc::context::build_test_orchestrator_spawn();
        let domain = crate::ipc::context::build_default_test_domain(&data_dir);
        let ctx = Arc::new(HandlerContext::new(
            policy_swap,
            Arc::new(KeyRegistry::stub_for_tests()),
            store,
            audit,
            data_dir,
            Arc::new(PlanRegistry::new()),
            Arc::new(crate::gateway::client::GatewayClient::new()),
            Arc::new(crate::prompt::EpochBinding::new()),
            credentials,
            isolation,
            orchestrator_spawn,
            crate::ipc::context::build_test_executor_spawn(),
            domain,
        ));
        (ctx, inner)
    }

    /// Poll `<inbox>` until at least `min` records are present or the
    /// deadline elapses. Returns the parsed JSONL records.
    async fn await_inbox_with_min(
        path: &std::path::Path,
        min: usize,
        deadline: Duration,
    ) -> Vec<serde_json::Value> {
        let start = std::time::Instant::now();
        loop {
            if let Ok(bytes) = tokio::fs::read(path).await {
                let parsed: Vec<serde_json::Value> = std::str::from_utf8(&bytes)
                    .unwrap_or("")
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .filter_map(|l| serde_json::from_str(l).ok())
                    .collect();
                if parsed.len() >= min {
                    return parsed;
                }
            }
            if start.elapsed() > deadline {
                return tokio::fs::read(path)
                    .await
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .map(|s| {
                        s.lines()
                            .filter_map(|l| serde_json::from_str(l).ok())
                            .collect()
                    })
                    .unwrap_or_default();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn approve_escalation_lands_inbox_line_via_notifying_sink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sk = fixture_keypair();
        let (ctx, _inner_sink) =
            build_ctx_with_notifying_sink(Arc::clone(&store), tmp.path().to_path_buf(), &sk);
        insert_pending_escalation(Arc::clone(&store), "esc-end-to-end").await;

        let scope = fixture_scope();
        let sig = sk
            .sign(&approval_scope_signing_input("esc-end-to-end", &scope))
            .to_bytes()
            .to_vec();

        let resp = handle_approve_escalation(
            "esc-end-to-end".into(),
            scope,
            hex::encode(&sig),
            &fixture_authenticated(),
            &ctx,
        )
        .await;
        assert!(
            matches!(resp, OperatorResponse::EscalationApproved { .. }),
            "expected EscalationApproved, got {resp:?}"
        );

        let inbox = PolicyBundle::inbox_path_for(tmp.path());
        let records = await_inbox_with_min(&inbox, 1, Duration::from_secs(2)).await;
        assert_eq!(
            records.len(),
            1,
            "exactly one inbox record expected; got {records:?}"
        );
        let r = &records[0];
        assert_eq!(r["event_kind"], "EscalationApproved");
        assert_eq!(r["payload"]["escalation_id"], "esc-end-to-end");
        assert_eq!(r["payload"]["approved_by"], FP);
        let summary = r["human_summary"].as_str().unwrap();
        assert!(
            summary.contains("APPROVED"),
            "summary should mention approval; got {summary:?}"
        );
        assert!(
            summary.contains("esc-end-to-end"),
            "summary should include escalation_id; got {summary:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deny_escalation_lands_inbox_line_via_notifying_sink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sk = fixture_keypair();
        let mut op = fixture_authenticated();
        op.permitted_ops.push("DenyEscalation".into());
        let (ctx, _inner_sink) =
            build_ctx_with_notifying_sink(Arc::clone(&store), tmp.path().to_path_buf(), &sk);
        insert_pending_escalation(Arc::clone(&store), "esc-deny").await;

        let resp =
            handle_deny_escalation("esc-deny".into(), Some("scope too broad".into()), &op, &ctx)
                .await;
        assert!(
            matches!(resp, OperatorResponse::EscalationDenied { .. }),
            "expected EscalationDenied, got {resp:?}"
        );

        let inbox = PolicyBundle::inbox_path_for(tmp.path());
        let records = await_inbox_with_min(&inbox, 1, Duration::from_secs(2)).await;
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r["event_kind"], "EscalationDenied");
        assert_eq!(r["payload"]["escalation_id"], "esc-deny");
        assert_eq!(r["payload"]["reason"], "scope too broad");
        let summary = r["human_summary"].as_str().unwrap();
        assert!(
            summary.contains("DENIED"),
            "summary should mention denial; got {summary:?}"
        );
        assert!(
            summary.contains("scope too broad"),
            "summary should echo the operator-supplied reason; got {summary:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests — RotateEpoch dispatcher (Phase 3 gateway-signal path).
//
// The bulk of the policy-advance state machine is covered by
// `policy_manager::tests` (Phases 0-2). What we cover here is the
// dispatcher's *Phase 3* responsibility introduced by B.3e:
//
//   * On successful advance, fire `GatewayClient::notify_epoch_advanced`.
//   * If that signal fails (typical: no gateway is connected at the
//     moment of advance), emit `AuditEventKind::GatewaySignalFailed`
//     **and still return `OperatorResponse::EpochAdvanced`**.
//   * If a gateway IS connected, the EpochAdvanced frame reaches the
//     gateway side and no GatewaySignalFailed audit is emitted.
//
// These tests share the signed-artifact builder pattern used by
// `policy_manager::tests` and the `KeyRegistry::for_tests_with_authority`
// helper so the kernel-side authority pubkey matches the signing key.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod rotate_epoch_dispatch_tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use ed25519_dalek::{Signer, SigningKey};
    use raxis_ipc::message::GatewayMessage;
    use raxis_ipc::{read_frame, write_frame};
    use raxis_policy::PolicyBundle;
    use raxis_store::Store;
    use raxis_test_support::FakeAuditSink;
    use tokio::net::UnixStream;

    use crate::authority::keys::KeyRegistry;
    use crate::gateway::client::GatewayClient;
    use crate::initiatives::PlanRegistry;
    use crate::ipc::auth::AuthenticatedOperator;
    use crate::policy_manager;

    /// Fixed authority seed → reproducible KeyRegistry across tests.
    /// Distinct from `escalation_dispatch_tests::fixture_keypair`'s seed
    /// to make grep-based test debugging unambiguous.
    const AUTHORITY_SEED: [u8; 32] = [0x42u8; 32];

    fn authority_keys() -> (Arc<KeyRegistry>, SigningKey) {
        let sk = SigningKey::from_bytes(&AUTHORITY_SEED);
        (
            Arc::new(KeyRegistry::for_tests_with_authority(sk.clone())),
            sk,
        )
    }

    /// Build a signed `policy.toml` artifact at the requested epoch and
    /// write it under `<data_dir>/policy/`. Returns `(policy_path, sig_path)`.
    /// Mirrors `policy_manager::tests::write_signed_policy_artifact`.
    ///
    /// Cert-mandatory (INV-CERT-01): the loader's `validate_operator_certs`
    /// step now rejects any `[[operators.entries]]` block missing a
    /// self-signed cert whose `pubkey_hex` matches the entry's
    /// `pubkey_hex`. We mint that cert here from a deterministic
    /// operator key so the artifact survives the strict deserialise +
    /// self-sig verification path even though the test code only
    /// exercises the rotate-epoch dispatcher.
    fn write_signed_policy_artifact(
        data_dir: &Path,
        epoch: u64,
        sk: &SigningKey,
    ) -> (PathBuf, PathBuf) {
        let policy_dir = data_dir.join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();
        let policy_path = policy_dir.join(format!("policy.epoch-{epoch}.toml"));
        let sig_path = policy_dir.join(format!("policy.epoch-{epoch}.sig"));

        let auth_hex = hex::encode(sk.verifying_key().to_bytes());
        let qual_hex = "b".repeat(64);
        // Real operator keypair for cert minting — the all-c
        // placeholder no longer works because the cert must self-verify
        // under the operator's pubkey.
        let op_key = raxis_test_support::ephemeral_signing_key([0xCCu8; 32]);
        let op_pk_hex = raxis_test_support::pubkey_hex(&op_key);
        let op_fp = raxis_policy::loader::operator_pubkey_fingerprint(&op_pk_hex).unwrap();
        let op_cert = raxis_test_support::ephemeral_cert_with_key(
            &op_key,
            raxis_test_support::CertOpts {
                display_name: "Chika".to_owned(),
                permitted_ops: vec!["RotateEpoch".into()],
                ..raxis_test_support::CertOpts::default()
            },
        );
        // Render the cert as an inline TOML sub-table the loader's
        // strict-deserialise path accepts.
        let cert_toml = toml::to_string(&op_cert).unwrap();
        let cert_block_indented = cert_toml
            .lines()
            .map(|l| format!("             {l}"))
            .collect::<Vec<_>>()
            .join("\n");

        let toml = format!(
            "[meta]\n\
             epoch     = {epoch}\n\
             signed_by = \"{op_fp}\"\n\
             signed_at = 1700000000\n\
             \n\
             [authority]\n\
             authority_pubkey = \"{auth_hex}\"\n\
             quality_pubkey   = \"{qual_hex}\"\n\
             \n\
             [escalation_policy]\n\
             timeout_secs         = 3600\n\
             window_secs          = 300\n\
             max_per_window       = 5\n\
             quarantine_threshold = 3\n\
             \n\
             [sessions]\n\
             default_ttl_secs       = 86400\n\
             max_ttl_secs           = 604800\n\
             allowed_worktree_roots = [\"/tmp/raxis-rotate-epoch-tests\"]\n\
             \n\
             [delegations]\n\
             max_ttl_secs = 86400\n\
             \n\
             [budget]\n\
             [budget.base_cost_per_intent_kind]\n\
             SingleCommit = 10\n\
             \n\
             [operators]\n\
             [[operators.entries]]\n\
             pubkey_fingerprint = \"{op_fp}\"\n\
             display_name       = \"Chika\"\n\
             pubkey_hex         = \"{op_pk_hex}\"\n\
             permitted_ops      = [\"RotateEpoch\"]\n\
             [operators.entries.cert]\n\
             {cert_block_indented}\n",
        );
        std::fs::write(&policy_path, toml.as_bytes()).unwrap();
        let sig = sk.sign(toml.as_bytes());
        std::fs::write(&sig_path, sig.to_bytes()).unwrap();
        (policy_path, sig_path)
    }

    /// Build a `HandlerContext` rooted at `data_dir` with the supplied
    /// `gateway`. Pre-installs the genesis policy_epoch_history row so
    /// `advance_epoch` can move us to epoch 2.
    ///
    /// `async` because the genesis-row install calls `store.lock_sync()`
    /// — synchronous DB work that would panic the tokio runtime if
    /// called directly from an `#[tokio::test]` body.
    async fn build_ctx(
        data_dir: &Path,
        sink: Arc<FakeAuditSink>,
        registry: Arc<KeyRegistry>,
        gateway: Arc<GatewayClient>,
    ) -> Arc<HandlerContext> {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let store_for_blocking = Arc::clone(&store);
        tokio::task::spawn_blocking(move || {
            // Genesis row writer test: the cert table receives 0 rows
            // because the bundle is empty (this fixture only exercises
            // the policy_epoch_history insert path).
            let empty_bundle = PolicyBundle::for_tests_with_operators(vec![]);
            policy_manager::install_genesis_policy_epoch(
                &store_for_blocking,
                "genesis-sha",
                "genesis-fp",
                1,
                &empty_bundle,
            )
            .unwrap();
        })
        .await
        .unwrap();

        let bundle = PolicyBundle::for_tests_with_operators(vec![]);
        let policy = Arc::new(arc_swap::ArcSwap::from_pointee(bundle));

        let credentials =
            crate::ipc::context::build_default_test_credentials(data_dir, sink.clone());
        let isolation = crate::ipc::context::build_fail_closed_test_isolation();
        let orchestrator_spawn = crate::ipc::context::build_test_orchestrator_spawn();
        let domain = crate::ipc::context::build_default_test_domain(data_dir);
        Arc::new(HandlerContext::new(
            policy,
            registry,
            store,
            sink,
            data_dir.to_path_buf(),
            Arc::new(PlanRegistry::new()),
            gateway,
            Arc::new(crate::prompt::EpochBinding::new()),
            credentials,
            isolation,
            orchestrator_spawn,
            crate::ipc::context::build_test_executor_spawn(),
            domain,
        ))
    }

    fn fixture_operator() -> AuthenticatedOperator {
        AuthenticatedOperator {
            fingerprint: "op-prime".to_owned(),
            permitted_ops: vec!["RotateEpoch".into()],
        }
    }

    // ── Phase 3 happy path: gateway IS connected ──────────────────────

    #[tokio::test]
    async fn rotate_epoch_dispatches_signal_to_connected_gateway() {
        let tmp = tempfile::tempdir().unwrap();
        let (registry, sk) = authority_keys();
        let sink = Arc::new(FakeAuditSink::new());

        // Install a fake gateway that reads the EpochAdvanced frame.
        let (kernel_side, mut gateway_side) = UnixStream::pair().unwrap();
        let gateway = Arc::new(GatewayClient::new());
        gateway.install_connection(kernel_side).await;
        let observer = tokio::spawn(async move {
            let msg: GatewayMessage = read_frame(&mut gateway_side).await.unwrap();
            match msg {
                GatewayMessage::EpochAdvanced { new_epoch_id } => new_epoch_id,
                other => panic!("expected EpochAdvanced, got {other:?}"),
            }
        });

        let ctx = build_ctx(tmp.path(), sink.clone(), registry, gateway).await;
        let (pp, sp) = write_signed_policy_artifact(tmp.path(), 2, &sk);
        let resp = handle_rotate_epoch(
            pp.to_string_lossy().into_owned(),
            sp.to_string_lossy().into_owned(),
            &fixture_operator(),
            &ctx,
        )
        .await;

        match resp {
            OperatorResponse::EpochAdvanced { new_epoch_id, .. } => {
                assert_eq!(new_epoch_id, 2);
            }
            other => panic!("expected EpochAdvanced, got {other:?}"),
        }
        assert_eq!(
            observer.await.unwrap(),
            2,
            "gateway must have observed EpochAdvanced frame for the new epoch"
        );

        // PolicyEpochAdvanced fires on success; GatewaySignalFailed
        // MUST NOT fire when the signal succeeded.
        let kinds = sink.event_kinds();
        assert!(
            kinds.contains(&"PolicyEpochAdvanced"),
            "PolicyEpochAdvanced absent: {kinds:?}"
        );
        assert!(
            !kinds.contains(&"GatewaySignalFailed"),
            "GatewaySignalFailed must NOT fire when signal delivered: {kinds:?}"
        );
    }

    // ── Phase 3 best-effort: gateway is NOT connected ─────────────────

    #[tokio::test]
    async fn rotate_epoch_emits_gateway_signal_failed_when_no_gateway_connected() {
        // Empty GatewayClient — `notify_epoch_advanced` returns
        // `Unavailable`. The advance MUST still succeed; the audit
        // event MUST be emitted.
        let tmp = tempfile::tempdir().unwrap();
        let (registry, sk) = authority_keys();
        let sink = Arc::new(FakeAuditSink::new());
        let gateway = Arc::new(GatewayClient::new()); // never connected
        let ctx = build_ctx(tmp.path(), sink.clone(), registry, gateway).await;

        let (pp, sp) = write_signed_policy_artifact(tmp.path(), 2, &sk);
        let resp = handle_rotate_epoch(
            pp.to_string_lossy().into_owned(),
            sp.to_string_lossy().into_owned(),
            &fixture_operator(),
            &ctx,
        )
        .await;

        assert!(
            matches!(
                resp,
                OperatorResponse::EpochAdvanced {
                    new_epoch_id: 2,
                    ..
                }
            ),
            "advance MUST NOT roll back when gateway is unreachable; got {resp:?}"
        );

        let events = sink.events();
        let signal_evt = events
            .iter()
            .find(|e| {
                matches!(
                    e.kind,
                    raxis_audit_tools::AuditEventKind::GatewaySignalFailed { .. }
                )
            })
            .expect("GatewaySignalFailed audit event must be emitted on Phase 3 failure");
        match &signal_evt.kind {
            raxis_audit_tools::AuditEventKind::GatewaySignalFailed {
                signal,
                new_epoch_id,
                reason,
            } => {
                assert_eq!(signal, "EpochAdvanced");
                assert_eq!(*new_epoch_id, Some(2));
                assert_eq!(
                    reason, "unavailable",
                    "category() must produce the stable wire string"
                );
            }
            other => panic!("wrong audit kind: {other:?}"),
        }
    }

    // ── Phase 0 failure: signal MUST NOT fire ─────────────────────────

    #[tokio::test]
    async fn rotate_epoch_signature_failure_does_not_signal_gateway() {
        // If Phase 0 rejects the artifact (here: signed by an
        // unrecognised key), neither PolicyEpochAdvanced nor any
        // gateway signal must fire — only PolicyAdvanceRejected.
        let tmp = tempfile::tempdir().unwrap();
        let (registry, _good_sk) = authority_keys();
        let other_sk = SigningKey::from_bytes(&[0x99u8; 32]);

        let (kernel_side, mut gateway_side) = UnixStream::pair().unwrap();
        let gateway = Arc::new(GatewayClient::new());
        gateway.install_connection(kernel_side).await;
        // Fail loudly if anything reaches the gateway side.
        let observer = tokio::spawn(async move {
            let _: Result<GatewayMessage, _> = read_frame(&mut gateway_side).await;
        });

        let sink = Arc::new(FakeAuditSink::new());
        let ctx = build_ctx(tmp.path(), sink.clone(), registry, gateway).await;

        let (pp, sp) = write_signed_policy_artifact(tmp.path(), 2, &other_sk);
        let resp = handle_rotate_epoch(
            pp.to_string_lossy().into_owned(),
            sp.to_string_lossy().into_owned(),
            &fixture_operator(),
            &ctx,
        )
        .await;

        match resp {
            OperatorResponse::Error { code, .. } => {
                assert_eq!(code, "FAIL_POLICY_SIGNATURE_INVALID");
            }
            other => panic!("expected Error, got {other:?}"),
        }
        let kinds = sink.event_kinds();
        assert!(kinds.contains(&"PolicyAdvanceRejected"));
        assert!(!kinds.contains(&"PolicyEpochAdvanced"));
        assert!(
            !kinds.contains(&"GatewaySignalFailed"),
            "no Phase 3 attempt → no GatewaySignalFailed; got: {kinds:?}"
        );

        // Best-effort: if the observer task is still pending, abort it.
        // We deliberately do NOT block on it — if a frame *had* been
        // sent, the assert above on `kinds` would already have failed.
        observer.abort();
    }

    // ── connection swap mid-advance ───────────────────────────────────

    #[tokio::test]
    async fn rotate_epoch_signal_failure_reason_is_dropped_when_gateway_disconnects_mid_advance() {
        // Connect a gateway, then drop the gateway-side socket BEFORE
        // running advance. The pump notices EOF; by the time
        // `notify_epoch_advanced` runs, `submit` may still be Some
        // (briefly) — surfacing as `Dropped` — or already None
        // (`Unavailable`). Both reasons are stable strings the audit
        // event records verbatim. We assert one of them appears.
        let tmp = tempfile::tempdir().unwrap();
        let (registry, sk) = authority_keys();
        let sink = Arc::new(FakeAuditSink::new());

        let (kernel_side, gateway_side) = UnixStream::pair().unwrap();
        let gateway = Arc::new(GatewayClient::new());
        gateway.install_connection(kernel_side).await;
        drop(gateway_side); // close gateway side immediately

        let ctx = build_ctx(tmp.path(), sink.clone(), registry, gateway).await;
        let (pp, sp) = write_signed_policy_artifact(tmp.path(), 2, &sk);
        let resp = handle_rotate_epoch(
            pp.to_string_lossy().into_owned(),
            sp.to_string_lossy().into_owned(),
            &fixture_operator(),
            &ctx,
        )
        .await;

        assert!(matches!(
            resp,
            OperatorResponse::EpochAdvanced {
                new_epoch_id: 2,
                ..
            }
        ));

        let events = sink.events();
        let evt = events
            .iter()
            .find(|e| {
                matches!(
                    e.kind,
                    raxis_audit_tools::AuditEventKind::GatewaySignalFailed { .. }
                )
            })
            .expect("GatewaySignalFailed must fire when gateway dropped");
        match &evt.kind {
            raxis_audit_tools::AuditEventKind::GatewaySignalFailed { reason, .. } => {
                assert!(
                    reason == "dropped" || reason == "unavailable",
                    "reason must be one of the stable failure categories; got {reason:?}"
                );
            }
            _ => unreachable!(),
        }
    }

    /// Smoke check that the helpers we imported actually round-trip
    /// frames — guards against the gateway-side observer test silently
    /// reading nothing.
    #[tokio::test]
    async fn unix_stream_pair_can_round_trip_a_gateway_message() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let h = tokio::spawn(async move {
            write_frame(&mut a, &GatewayMessage::EpochAdvanced { new_epoch_id: 99 }).await
        });
        let msg: GatewayMessage = read_frame(&mut b).await.unwrap();
        h.await.unwrap().unwrap();
        assert!(matches!(
            msg,
            GatewayMessage::EpochAdvanced { new_epoch_id: 99 }
        ));
    }
}

// ---------------------------------------------------------------------------
// Dispatcher logging tests.
//
// These pin the JSON shape of every line `dispatch_loop` emits to stderr,
// because that shape is the operator-runbook contract — operators grep
// stderr for `"event":"op_response","status":"error"` to find failed
// requests, and any drift in the field names breaks every downstream log
// pipeline. The tests assert against the **pure formatters**
// (`build_*_line`) so we never need to capture stderr.
//
// The four scenarios we cover map 1:1 to the four chokepoints in
// `dispatch_loop`:
//
//   1. Successful request log — `op_request` carries the op name,
//      operator fingerprint, and per-op context fields.
//   2. Error response log — `op_response { status:"error", code, detail }`
//      at WARN. THIS is the line the user's "FAIL_APPROVE_PLAN —
//      initiative not found: test-minimal-001" report was missing.
//   3. Success response log — `op_response { status:"ok", variant }`
//      at INFO, deliberately omitting the success payload's secrets
//      (we pin SessionCreated specifically because it carries
//      `session_token`, the most sensitive one).
//   4. Pre-handler error logs — `frame_decode_failed` and `unauthorized`
//      both at WARN.
//
// Plus two corner cases:
//
//   * Per-op `request_context_fields` extracts the right identifiers
//     for every variant — the user's failing flow needed `initiative_id`
//     in the `ApprovePlan` log line, and a future variant added without
//     a context-extractor arm is what would have masked it.
//   * `serde_json::to_string` escape-safety — a `detail` containing a
//     literal `"` (which the existing `eprintln!` format-string sites
//     would mangle) round-trips through `serde_json::from_str`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod dispatch_logging_tests {
    use super::*;
    use serde_json::Value;

    /// Parse a built log line and assert it is a JSON object whose
    /// constant fields are present with the spec-mandated values.
    fn parse_and_check_constants(line: &str, expected_event: &str, expected_level: &str) -> Value {
        let v: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("dispatch_log line is not valid JSON: {e}\nline: {line}"));
        assert_eq!(
            v.get("module").and_then(Value::as_str),
            Some("ipc.operator"),
            "every dispatch_log line MUST carry module=ipc.operator (operators grep on it); line: {line}",
        );
        assert_eq!(
            v.get("event").and_then(Value::as_str),
            Some(expected_event),
            "event field drifted; line: {line}",
        );
        assert_eq!(
            v.get("level").and_then(Value::as_str),
            Some(expected_level),
            "level field drifted; line: {line}",
        );
        assert!(
            v.get("ts_unix").and_then(Value::as_i64).is_some(),
            "every dispatch_log line MUST carry a numeric ts_unix; line: {line}",
        );
        v
    }

    #[test]
    fn op_request_line_carries_op_operator_fp_and_context_fields() {
        // The user-reported failure was `ApprovePlan` with an unknown
        // initiative_id. Pin that the request log contains the op name,
        // operator fingerprint, AND the initiative_id from the request —
        // grepping `"event":"op_request","initiative_id":"<id>"` is the
        // operator workflow this line exists to support.
        let fields = vec![
            ("initiative_id", "test-minimal-001".to_owned()),
            (
                "approving_operator",
                "abcd1234abcd1234abcd1234abcd1234".to_owned(),
            ),
        ];
        let line = dispatch_log::build_op_request_line(
            "ApprovePlan",
            "abcd1234abcd1234abcd1234abcd1234",
            Some("Chika"),
            &fields,
            1_700_000_000,
        );
        let v = parse_and_check_constants(&line, "op_request", "info");
        assert_eq!(v.get("op").and_then(Value::as_str), Some("ApprovePlan"));
        assert_eq!(
            v.get("operator_fp").and_then(Value::as_str),
            Some("abcd1234abcd1234abcd1234abcd1234"),
        );
        // §2.5.2 "Operator display-name fields" — the resolved
        // display name MUST appear on the same line as the
        // fingerprint when the dispatcher could resolve it.
        assert_eq!(
            v.get("operator_display").and_then(Value::as_str),
            Some("Chika"),
            "operator_display MUST be present on op_request lines when resolvable",
        );
        assert_eq!(
            v.get("initiative_id").and_then(Value::as_str),
            Some("test-minimal-001"),
        );
        assert_eq!(
            v.get("approving_operator").and_then(Value::as_str),
            Some("abcd1234abcd1234abcd1234abcd1234"),
        );
        assert_eq!(
            v.get("ts_unix").and_then(Value::as_i64),
            Some(1_700_000_000)
        );
    }

    /// The dispatcher MAY have no display-name (operator removed
    /// in flight, or kernel.db not yet bootstrapped). The line
    /// MUST still emit cleanly — just without the
    /// `operator_display` key — so existing log-grep recipes that
    /// match on `operator_fp` still work.
    #[test]
    fn op_request_line_omits_operator_display_when_unresolved() {
        let fields = vec![("initiative_id", "test-001".to_owned())];
        let line = dispatch_log::build_op_request_line(
            "ApprovePlan",
            "abcd1234abcd1234abcd1234abcd1234",
            None,
            &fields,
            1_700_000_000,
        );
        let v: Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(
            v.get("operator_display"),
            None,
            "operator_display MUST be omitted (not null) when unresolved",
        );
    }

    #[test]
    fn op_response_error_line_carries_code_and_detail_at_warn() {
        // The exact line that was missing from the user's report. After
        // this test passes, an operator running `raxis-kernel` and
        // greppping stderr for `FAIL_APPROVE_PLAN` will find this line
        // every time.
        let fields = vec![("initiative_id", "test-minimal-001".to_owned())];
        let response = OperatorResponse::Error {
            code: "FAIL_APPROVE_PLAN".to_owned(),
            detail: "initiative not found: test-minimal-001".to_owned(),
        };
        let line = dispatch_log::build_op_response_line(
            "ApprovePlan",
            "abcd1234abcd1234abcd1234abcd1234",
            Some("Chika"),
            &response,
            &fields,
            42,
            1_700_000_001,
        );
        let v = parse_and_check_constants(&line, "op_response", "warn");
        assert_eq!(v.get("status").and_then(Value::as_str), Some("error"));
        assert_eq!(v.get("op").and_then(Value::as_str), Some("ApprovePlan"));
        assert_eq!(
            v.get("code").and_then(Value::as_str),
            Some("FAIL_APPROVE_PLAN"),
        );
        assert_eq!(
            v.get("detail").and_then(Value::as_str),
            Some("initiative not found: test-minimal-001"),
        );
        assert_eq!(v.get("latency_ms").and_then(Value::as_u64), Some(42));
        assert_eq!(
            v.get("initiative_id").and_then(Value::as_str),
            Some("test-minimal-001"),
            "context field MUST be re-emitted on the response line so a single grep finds the failure",
        );
    }

    #[test]
    fn op_response_ok_line_omits_secret_payload() {
        // `SessionCreated` carries the most sensitive success payload:
        // `session_token` is the bearer token the planner uses to
        // authenticate every subsequent IPC. It MUST NOT appear in
        // operator-visible stderr — pin that.
        let response = OperatorResponse::SessionCreated {
            session_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            session_token: "SUPER_SECRET_BEARER_TOKEN_DO_NOT_LOG".to_owned(),
            // Lowercase per cli-ceremony.md §4.2 — matches what the
            // dispatcher actually emits via wire_role_str().
            role: "planner".to_owned(),
            worktree_root: Some("/tmp/wt".to_owned()),
            base_sha: Some("a".repeat(40)),
            lineage_id: "00000000-0000-4000-8000-00000000000a".to_owned(),
        };
        let line = dispatch_log::build_op_response_line(
            "CreateSession",
            "abcd1234abcd1234abcd1234abcd1234",
            Some("Chika"),
            &response,
            &[(
                "lineage_id",
                "00000000-0000-4000-8000-00000000000a".to_owned(),
            )],
            7,
            1_700_000_002,
        );
        let v = parse_and_check_constants(&line, "op_response", "info");
        assert_eq!(v.get("status").and_then(Value::as_str), Some("ok"));
        assert_eq!(
            v.get("variant").and_then(Value::as_str),
            Some("SessionCreated"),
        );
        assert_eq!(v.get("op").and_then(Value::as_str), Some("CreateSession"));
        assert!(
            !line.contains("SUPER_SECRET_BEARER_TOKEN_DO_NOT_LOG"),
            "session_token MUST NOT appear in operator-visible stderr; line: {line}",
        );
        assert!(
            !line.contains("session_token"),
            "session_token field MUST NOT be emitted at all (not even as an empty string); line: {line}",
        );
    }

    #[test]
    fn op_response_initiative_created_includes_id_for_correlation() {
        // V2 plan-bundle admission echoes back the operator-chosen
        // `initiative_id` from the request, but operators frequently
        // grep for the response line to confirm "the kernel committed
        // the row I asked for". Pin that the response log surfaces
        // `initiative_id` so a single grep on
        // `"event":"op_response","initiative_id":"<uuid>"` finds the
        // exact creation moment.
        let response = OperatorResponse::InitiativeCreated {
            initiative_id: "5c5a6cd4-95cd-47d1-a4cc-8b0ef46da235".to_owned(),
            status: "Draft".to_owned(),
        };
        let line = dispatch_log::build_op_response_line(
            "CreateInitiative",
            "abcd1234abcd1234abcd1234abcd1234",
            Some("Chika"),
            &response,
            &[(
                "initiative_id",
                "5c5a6cd4-95cd-47d1-a4cc-8b0ef46da235".to_owned(),
            )],
            5,
            1_700_000_003,
        );
        let v = parse_and_check_constants(&line, "op_response", "info");
        assert_eq!(
            v.get("variant").and_then(Value::as_str),
            Some("InitiativeCreated"),
        );
        assert_eq!(
            v.get("initiative_id").and_then(Value::as_str),
            Some("5c5a6cd4-95cd-47d1-a4cc-8b0ef46da235"),
            "the operator-chosen initiative_id MUST appear on the response line",
        );
    }

    #[test]
    fn frame_decode_failed_line_carries_operator_fp_and_detail_at_warn() {
        let line = dispatch_log::build_frame_decode_failed_line(
            "abcd1234abcd1234abcd1234abcd1234",
            Some("Chika"),
            "expected `,` or `}` at line 1 column 42",
            1_700_000_004,
        );
        let v = parse_and_check_constants(&line, "frame_decode_failed", "warn");
        assert_eq!(
            v.get("operator_fp").and_then(Value::as_str),
            Some("abcd1234abcd1234abcd1234abcd1234"),
        );
        assert!(
            v.get("detail")
                .and_then(Value::as_str)
                .unwrap_or("")
                .contains("expected"),
            "detail MUST be preserved verbatim so operators can debug malformed frames",
        );
    }

    #[test]
    fn unauthorized_line_carries_op_and_operator_fp_at_warn() {
        let line = dispatch_log::build_unauthorized_line(
            "RotateEpoch",
            "abcd1234abcd1234abcd1234abcd1234",
            Some("Chika"),
            1_700_000_005,
        );
        let v = parse_and_check_constants(&line, "unauthorized", "warn");
        assert_eq!(v.get("op").and_then(Value::as_str), Some("RotateEpoch"));
        assert_eq!(
            v.get("operator_fp").and_then(Value::as_str),
            Some("abcd1234abcd1234abcd1234abcd1234"),
        );
    }

    /// The cert-gate rejection line MUST carry `op`, `operator_fp`, AND
    /// the wire `code` so an operator scanning kernel stderr can grep
    /// for `"code":"FAIL_CERT_EXPIRED"` and immediately spot which
    /// operator hit the gate. Pinned at WARN level (same severity as
    /// `unauthorized`) so any log-routing config that filtered
    /// "unauthorized" already catches this too.
    #[test]
    fn cert_denied_line_carries_op_operator_fp_and_wire_code_at_warn() {
        let line = dispatch_log::build_cert_denied_line(
            "RotateEpoch",
            "abcd1234abcd1234abcd1234abcd1234",
            Some("Chika"),
            "FAIL_CERT_EXPIRED",
            1_700_000_006,
        );
        let v = parse_and_check_constants(&line, "cert_denied", "warn");
        assert_eq!(v.get("op").and_then(Value::as_str), Some("RotateEpoch"));
        assert_eq!(
            v.get("operator_fp").and_then(Value::as_str),
            Some("abcd1234abcd1234abcd1234abcd1234"),
        );
        assert_eq!(
            v.get("code").and_then(Value::as_str),
            Some("FAIL_CERT_EXPIRED")
        );
    }

    #[test]
    fn detail_strings_with_embedded_quotes_round_trip_through_json() {
        // The five existing `eprintln!(\"{{...{e}}}\")` call sites in
        // this file would corrupt the line if `e.to_string()` contained
        // a literal `\"`. Going through `serde_json::to_string` makes
        // the new helpers escape-safe — pin that with a detail that
        // contains every metacharacter we'd plausibly see in a SQL
        // error or a path string.
        let nasty = r#"sql error: 'col "x"' contains \\backslash and ' apostrophe and "quote""#;
        let response = OperatorResponse::Error {
            code: "FAIL_X".to_owned(),
            detail: nasty.to_owned(),
        };
        let line = dispatch_log::build_op_response_line(
            "ApprovePlan",
            "abcd1234abcd1234abcd1234abcd1234",
            Some("Chika"),
            &response,
            &[],
            0,
            1_700_000_006,
        );
        // The line MUST be parseable as JSON…
        let v: Value = serde_json::from_str(&line).expect(
            "escape safety: log line must be valid JSON even with quotes/backslashes in detail",
        );
        // …AND the round-tripped detail MUST be byte-identical.
        assert_eq!(
            v.get("detail").and_then(Value::as_str),
            Some(nasty),
            "detail MUST round-trip; mangled detail is the silent-corruption mode \
             this rewrite eliminates from the existing format-string sites",
        );
    }

    #[test]
    fn request_context_fields_extracts_initiative_id_for_approve_plan() {
        // The user-reported flow. Pin that the per-op extractor produces
        // the (initiative_id, approving_operator) pair so the dispatcher
        // log can route on initiative_id without re-pattern-matching the
        // whole request enum at every chokepoint.
        let req = OperatorRequest::ApprovePlan {
            initiative_id: "test-minimal-001".to_owned(),
            approving_operator: "abcd1234abcd1234abcd1234abcd1234".to_owned(),
        };
        let fields = request_context_fields(&req);
        assert_eq!(
            fields,
            vec![
                ("initiative_id", "test-minimal-001".to_owned()),
                (
                    "approving_operator",
                    "abcd1234abcd1234abcd1234abcd1234".to_owned()
                ),
            ],
        );
    }

    #[test]
    fn request_context_fields_covers_every_operator_request_variant() {
        // Compile-time guard: every variant in
        // `raxis_types::operator_wire::OperatorRequest` MUST have an arm
        // in `request_context_fields`. We exercise each variant with
        // dummy data and assert the result is non-empty (or, for
        // CreateInitiative which has no request-side identifier other
        // than `submitted_by`, that it produces at least the
        // submitted_by field).
        //
        // If a future variant is added without an extractor arm, the
        // exhaustive match in `request_context_fields` fails to compile;
        // this test is the runtime backstop that also pins each
        // variant's contribution.
        let cases: Vec<(OperatorRequest, &str)> = vec![
            (
                OperatorRequest::CreateSession {
                    // Lowercase per cli-ceremony.md §4.2 — the canonical
                    // wire shape the CLI actually puts on the wire.
                    role: "planner".to_owned(),
                    worktree_root: None,
                    base_sha: None,
                    base_tracking_ref: None,
                    lineage_id: "00000000-0000-4000-8000-000000000001".to_owned(),
                    task_id: None,
                },
                "lineage_id",
            ),
            (
                OperatorRequest::RevokeSession {
                    session_id: "00000000-0000-4000-8000-000000000002".to_owned(),
                },
                "session_id",
            ),
            (
                OperatorRequest::GrantDelegation {
                    session_id: "00000000-0000-4000-8000-000000000003".to_owned(),
                    delegation_id: "00000000-0000-4000-8000-000000000004".to_owned(),
                    capability_class: "ReadWorktree".to_owned(),
                    scope_json: None,
                    ttl_secs: 60,
                    max_uses: None,
                    signature_hex: "00".repeat(64),
                },
                "delegation_id",
            ),
            (
                OperatorRequest::CreateInitiative {
                    initiative_id: "0192a8f0-1234-7abc-9000-000000000001".to_owned(),
                    plan_bundle_hex: String::new(),
                    bundle_sha256_hex: String::new(),
                    signature_hex: String::new(),
                    signed_by_hex: String::new(),
                },
                "initiative_id",
            ),
            (
                OperatorRequest::ApprovePlan {
                    initiative_id: "i1".to_owned(),
                    approving_operator: "abcd1234abcd1234abcd1234abcd1234".to_owned(),
                },
                "initiative_id",
            ),
            (
                OperatorRequest::RejectPlan {
                    initiative_id: "i1".to_owned(),
                    rejected_by: "abcd1234abcd1234abcd1234abcd1234".to_owned(),
                    reason: None,
                },
                "initiative_id",
            ),
            (
                OperatorRequest::RetryTask {
                    task_id: "t1".to_owned(),
                },
                "task_id",
            ),
            (
                OperatorRequest::ResumeTask {
                    task_id: "t1".to_owned(),
                    resumed_by: "abcd1234abcd1234abcd1234abcd1234".to_owned(),
                },
                "task_id",
            ),
            (
                OperatorRequest::AbortTask {
                    task_id: "t1".to_owned(),
                    aborted_by: "abcd1234abcd1234abcd1234abcd1234".to_owned(),
                },
                "task_id",
            ),
            (
                OperatorRequest::AbortInitiative {
                    initiative_id: "i1".to_owned(),
                    aborted_by: "abcd1234abcd1234abcd1234abcd1234".to_owned(),
                },
                "initiative_id",
            ),
            (
                OperatorRequest::ApproveEscalation {
                    escalation_id: "e1".to_owned(),
                    approval_scope: raxis_types::operator_wire::ApprovalScopeWire {
                        capability_class: "WriteSecrets".to_owned(),
                        max_uses: 1,
                        valid_for_seconds: 60,
                    },
                    operator_sig_hex: String::new(),
                },
                "escalation_id",
            ),
            (
                OperatorRequest::DenyEscalation {
                    escalation_id: "e1".to_owned(),
                    reason: None,
                },
                "escalation_id",
            ),
            (
                OperatorRequest::RotateEpoch {
                    policy_path: "/tmp/p".to_owned(),
                    sig_path: "/tmp/s".to_owned(),
                },
                "policy_path",
            ),
        ];
        for (req, must_have_key) in cases {
            let op = op_name(&req);
            let fields = request_context_fields(&req);
            assert!(
                fields.iter().any(|(k, _)| *k == must_have_key),
                "op {op}: extractor must produce key {must_have_key:?}; got {fields:?}",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — parse_operator_creatable_role
//
// These tests pin the wire contract for the `role` field on
// `OperatorRequest::CreateSession`. The contract is normatively fixed
// in cli-ceremony.md §4.2 line 300 ("must be the literal string
// `planner`") and locked in the wire round-trip tests
// (`raxis_types::operator_wire::tests::create_session_wire_shape` and
// `raxis_cli::tests::operator_wire_shape::create_session_emits_null_for_unset_optionals`),
// both of which use lowercase `"planner"`.
//
// Pre-fix history: the dispatcher used to match PascalCase
// `"Planner"`/`"Gateway"`/`"Verifier"` here, which silently rejected
// every CLI-issued `session create` request with
// `FAIL_ROLE_NOT_OPERATOR_CREATABLE` because the CLI sends lowercase
// per the canonical wire shape. This module is the regression net.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod role_parser_tests {
    use super::*;
    use crate::authority::session::Role;

    /// **Regression**: the CLI sends `"role": "planner"` (lowercase) —
    /// the canonical wire shape. The dispatcher MUST accept it and
    /// resolve it to `Role::Planner`. Pre-fix, this test failed because
    /// the match arms were PascalCase.
    #[test]
    fn accepts_lowercase_planner_per_wire_contract() {
        let parsed = parse_operator_creatable_role("planner")
            .expect("lowercase 'planner' is the canonical wire shape per cli-ceremony.md §4.2");
        assert_eq!(parsed, Role::Planner);
    }

    /// PascalCase `"Planner"` is NOT the canonical wire shape and must
    /// be rejected. Accepting it would silently mask casing drift in
    /// future callers.
    #[test]
    fn rejects_pascal_case_planner() {
        let resp = parse_operator_creatable_role("Planner")
            .expect_err("PascalCase 'Planner' is not the wire shape; must be rejected");
        match resp {
            OperatorResponse::Error { code, detail } => {
                assert_eq!(code, "FAIL_ROLE_NOT_OPERATOR_CREATABLE");
                assert!(
                    detail.contains("'Planner'"),
                    "detail must echo the offending role string for debuggability; got {detail:?}",
                );
            }
            other => panic!("expected OperatorResponse::Error, got {other:?}"),
        }
    }

    /// Per spec (kernel-core.md §`handle_create_session` step 1):
    /// gateway and verifier sessions are minted by kernel-internal
    /// spawn paths (`spawn_gateway` / `spawn_verifier`) and MUST NOT be
    /// reachable through operator IPC, regardless of casing.
    #[test]
    fn rejects_gateway_role_even_in_lowercase() {
        let resp = parse_operator_creatable_role("gateway")
            .expect_err("'gateway' is kernel-spawned, never operator-creatable");
        match resp {
            OperatorResponse::Error { code, .. } => {
                assert_eq!(code, "FAIL_ROLE_NOT_OPERATOR_CREATABLE")
            }
            other => panic!("expected OperatorResponse::Error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_verifier_role_even_in_lowercase() {
        let resp = parse_operator_creatable_role("verifier")
            .expect_err("'verifier' is kernel-spawned, never operator-creatable");
        match resp {
            OperatorResponse::Error { code, .. } => {
                assert_eq!(code, "FAIL_ROLE_NOT_OPERATOR_CREATABLE")
            }
            other => panic!("expected OperatorResponse::Error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_role_string() {
        let resp = parse_operator_creatable_role("garbage")
            .expect_err("unknown role strings must be rejected");
        match resp {
            OperatorResponse::Error { code, detail } => {
                assert_eq!(code, "FAIL_ROLE_NOT_OPERATOR_CREATABLE");
                assert!(
                    detail.contains("'garbage'"),
                    "detail must echo the offending role string; got {detail:?}",
                );
            }
            other => panic!("expected OperatorResponse::Error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_role_string() {
        let resp =
            parse_operator_creatable_role("").expect_err("empty role string must be rejected");
        match resp {
            OperatorResponse::Error { code, .. } => {
                assert_eq!(code, "FAIL_ROLE_NOT_OPERATOR_CREATABLE")
            }
            other => panic!("expected OperatorResponse::Error, got {other:?}"),
        }
    }

    /// Pin the outbound wire shape for `OperatorResponse::SessionCreated`.
    /// The CLI doesn't currently read this field (it hardcodes `"planner"`
    /// in display), but the wire round-trip fixture in
    /// `raxis_types::operator_wire` uses lowercase, and any future
    /// consumer (including the SDK) that round-trips a captured response
    /// MUST see the canonical lowercase string.
    #[test]
    fn wire_role_str_emits_canonical_lowercase_for_planner() {
        assert_eq!(wire_role_str(&Role::Planner), "planner");
    }

    /// Defensive: gateway/verifier should never appear in a
    /// `SessionCreated` response (they aren't operator-creatable),
    /// but the helper must still emit the wire-canonical lowercase
    /// form if it ever gets called. This avoids any path where
    /// internal code accidentally reuses `Role::as_str()` (PascalCase
    /// SQL form) for a wire-shaped output.
    #[test]
    fn wire_role_str_emits_canonical_lowercase_for_gateway_and_verifier() {
        assert_eq!(wire_role_str(&Role::Gateway), "gateway");
        assert_eq!(wire_role_str(&Role::Verifier), "verifier");
    }

    /// Cross-shape invariant: whatever the inbound parser accepts,
    /// the outbound formatter must emit byte-for-byte. This pins
    /// "planner-in / planner-out" symmetry so a hypothetical future
    /// alias (e.g. accepting "Planner" for back-compat) cannot
    /// accidentally produce a different outbound string.
    #[test]
    fn wire_role_string_round_trips_through_parse_and_format() {
        let inbound = "planner";
        let parsed = parse_operator_creatable_role(inbound).expect("'planner' must parse");
        assert_eq!(
            wire_role_str(&parsed),
            inbound,
            "outbound wire string must equal the inbound canonical form",
        );
    }
}

// ---------------------------------------------------------------------------
// quarantine_dispatch_tests — exercises `handle_quarantine_initiative`
// and `handle_quarantine_plans_by` against an in-memory store.
//
// Wire-shape coverage lives in `raxis-types::operator_wire::tests`;
// storage semantics live in
// `raxis-store::views::initiative_quarantines::tests`. These tests
// pin the kernel-side glue: the handlers must (a) commit the row,
// (b) emit the right audit events, (c) be idempotent on re-runs.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod quarantine_dispatch_tests {
    use super::*;
    use std::path::Path;
    use std::sync::Arc;

    use raxis_policy::PolicyBundle;
    use raxis_store::Store;
    use raxis_test_support::FakeAuditSink;

    use crate::authority::keys::KeyRegistry;
    use crate::gateway::client::GatewayClient;
    use crate::initiatives::PlanRegistry;
    use crate::ipc::auth::AuthenticatedOperator;
    use crate::policy_manager;

    /// Minimal HandlerContext over an in-memory store; the quarantine
    /// handlers don't need a real gateway connection or signed policy
    /// artifact, just a writable Store + AuditSink.
    async fn build_ctx(data_dir: &Path) -> (Arc<HandlerContext>, Arc<FakeAuditSink>) {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let store_for_blocking = Arc::clone(&store);
        tokio::task::spawn_blocking(move || {
            let empty_bundle = PolicyBundle::for_tests_with_operators(vec![]);
            policy_manager::install_genesis_policy_epoch(
                &store_for_blocking,
                "genesis-sha",
                "genesis-fp",
                1,
                &empty_bundle,
            )
            .unwrap();
        })
        .await
        .unwrap();

        let bundle = PolicyBundle::for_tests_with_operators(vec![]);
        let policy = Arc::new(arc_swap::ArcSwap::from_pointee(bundle));
        let registry = Arc::new(KeyRegistry::stub_for_tests());
        let gateway = Arc::new(GatewayClient::new());
        let sink = Arc::new(FakeAuditSink::new());

        let credentials =
            crate::ipc::context::build_default_test_credentials(data_dir, sink.clone());
        let isolation = crate::ipc::context::build_fail_closed_test_isolation();
        let orchestrator_spawn = crate::ipc::context::build_test_orchestrator_spawn();
        let domain = crate::ipc::context::build_default_test_domain(data_dir);
        let ctx = Arc::new(HandlerContext::new(
            policy,
            registry,
            store,
            sink.clone(),
            data_dir.to_path_buf(),
            Arc::new(PlanRegistry::new()),
            gateway,
            Arc::new(crate::prompt::EpochBinding::new()),
            credentials,
            isolation,
            orchestrator_spawn,
            crate::ipc::context::build_test_executor_spawn(),
            domain,
        ));
        (ctx, sink)
    }

    fn fixture_operator(fp: &str) -> AuthenticatedOperator {
        AuthenticatedOperator {
            fingerprint: fp.to_owned(),
            permitted_ops: vec!["QuarantineInitiative".into(), "QuarantinePlansBy".into()],
        }
    }

    /// Insert a minimal `initiatives` row so the `initiative_quarantines`
    /// FK to `initiatives(initiative_id)` is satisfied. Schema mirrors
    /// `migration::render_migration_1_ddl::{initiatives}` (Table 2).
    ///
    /// `async` because `Store::lock_sync` panics on a tokio worker; we
    /// hop to the blocking pool exactly like every real handler does.
    async fn insert_initiative(ctx: Arc<HandlerContext>, initiative_id: &str) {
        const INITIATIVES: &str = raxis_store::Table::Initiatives.as_str();
        let id = initiative_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = ctx.store.lock_sync();
            conn.execute(
                &format!(
                    "INSERT INTO {INITIATIVES} \
                        (initiative_id, state, terminal_criteria_json, \
                         plan_artifact_sha256, created_at) \
                     VALUES (?1, 'ApprovedPlan', '{{}}', 'sha', 1700000000)"
                ),
                rusqlite::params![id],
            )
            .unwrap();
        })
        .await
        .unwrap();
    }

    /// Insert a `signed_plan_artifacts` row attributing approval to the
    /// given fingerprint. Mirrors what `lifecycle::approve_plan` writes
    /// once the step-10 column is wired in. Schema (Table 3 +
    /// migration 3 `signed_by_fingerprint` column):
    ///   (initiative_id PK, plan_bytes BLOB, plan_sig BLOB,
    ///    stored_at INTEGER, signed_by_fingerprint TEXT)
    async fn insert_signed_plan(ctx: Arc<HandlerContext>, initiative_id: &str, signed_by_fp: &str) {
        const SIGNED_PLAN_ARTIFACTS: &str = raxis_store::Table::SignedPlanArtifacts.as_str();
        let id = initiative_id.to_owned();
        let fp = signed_by_fp.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = ctx.store.lock_sync();
            conn.execute(
                &format!(
                    "INSERT INTO {SIGNED_PLAN_ARTIFACTS} \
                        (initiative_id, plan_bytes, plan_sig, stored_at, signed_by_fingerprint) \
                     VALUES (?1, x'00', x'00', 1700000000, ?2)"
                ),
                rusqlite::params![id, fp],
            )
            .unwrap();
        })
        .await
        .unwrap();
    }

    /// Read-side helper — hopped onto the blocking pool to match the
    /// `Store::lock_sync` rule that handlers obey in production.
    async fn is_quarantined_rw(ctx: Arc<HandlerContext>, initiative_id: &str) -> bool {
        let id = initiative_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = ctx.store.lock_sync();
            raxis_store::views::initiative_quarantines::is_quarantined_rw(&conn, &id).unwrap()
        })
        .await
        .unwrap()
    }

    // ── Handler 1: QuarantineInitiative ──────────────────────────────

    #[tokio::test]
    async fn quarantine_initiative_inserts_row_and_emits_audit_event() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, sink) = build_ctx(tmp.path()).await;
        insert_initiative(Arc::clone(&ctx), "init-1").await;

        let resp = handle_quarantine_initiative(
            "init-1".to_owned(),
            Some("leaked key".to_owned()),
            &fixture_operator("op-prime"),
            &ctx,
        )
        .await;

        match resp {
            OperatorResponse::InitiativeQuarantined {
                initiative_id,
                was_already_quarantined,
                ..
            } => {
                assert_eq!(initiative_id, "init-1");
                assert!(
                    !was_already_quarantined,
                    "first quarantine MUST report was_already_quarantined=false"
                );
            }
            other => panic!("expected InitiativeQuarantined, got {other:?}"),
        }

        let q = is_quarantined_rw(Arc::clone(&ctx), "init-1").await;
        assert!(
            q,
            "is_quarantined_rw must return true after handler commits"
        );

        // Exactly one InitiativeQuarantined audit event for the new row.
        let kinds = sink.event_kinds();
        let n_quarantined = kinds
            .iter()
            .filter(|k| **k == "InitiativeQuarantined")
            .count();
        assert_eq!(
            n_quarantined, 1,
            "expected exactly one InitiativeQuarantined audit event, got: {kinds:?}"
        );
    }

    #[tokio::test]
    async fn quarantine_initiative_is_idempotent_and_skips_duplicate_audit() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, sink) = build_ctx(tmp.path()).await;
        insert_initiative(Arc::clone(&ctx), "init-1").await;

        // First call: real insert.
        let _ = handle_quarantine_initiative(
            "init-1".to_owned(),
            None,
            &fixture_operator("op-prime"),
            &ctx,
        )
        .await;

        // Second call: duplicate — must be a no-op write AND no-op audit.
        let resp2 = handle_quarantine_initiative(
            "init-1".to_owned(),
            None,
            &fixture_operator("op-prime"),
            &ctx,
        )
        .await;

        match resp2 {
            OperatorResponse::InitiativeQuarantined {
                was_already_quarantined: true,
                ..
            } => { /* expected */ }
            other => {
                panic!("second quarantine MUST flag was_already_quarantined=true; got {other:?}")
            }
        }

        let kinds = sink.event_kinds();
        let n = kinds
            .iter()
            .filter(|k| **k == "InitiativeQuarantined")
            .count();
        assert_eq!(
            n, 1,
            "duplicate quarantine MUST NOT re-emit the audit event; got: {kinds:?}"
        );
    }

    // ── Handler 2: QuarantinePlansBy ─────────────────────────────────

    #[tokio::test]
    async fn quarantine_plans_by_sweeps_every_initiative_signed_by_target() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, sink) = build_ctx(tmp.path()).await;

        // Two initiatives signed by the compromised operator, one
        // signed by someone else (must NOT be swept).
        insert_initiative(Arc::clone(&ctx), "init-a").await;
        insert_initiative(Arc::clone(&ctx), "init-b").await;
        insert_initiative(Arc::clone(&ctx), "init-c").await;
        insert_signed_plan(Arc::clone(&ctx), "init-a", "compromised-fp").await;
        insert_signed_plan(Arc::clone(&ctx), "init-b", "compromised-fp").await;
        insert_signed_plan(Arc::clone(&ctx), "init-c", "honest-fp").await;

        let resp = handle_quarantine_plans_by(
            "compromised-fp".to_owned(),
            Some("rotated key".to_owned()),
            &fixture_operator("op-prime"),
            &ctx,
        )
        .await;

        let mut swept_ids = match resp {
            OperatorResponse::QuarantineSwept {
                newly_quarantined_ids,
                ..
            } => newly_quarantined_ids,
            other => panic!("expected QuarantineSwept, got {other:?}"),
        };
        swept_ids.sort();
        assert_eq!(swept_ids, vec!["init-a".to_owned(), "init-b".to_owned()]);

        // Audit: one per-initiative event PLUS one rollup.
        let kinds = sink.event_kinds();
        let n_per = kinds
            .iter()
            .filter(|k| **k == "InitiativeQuarantined")
            .count();
        let n_roll = kinds
            .iter()
            .filter(|k| **k == "OperatorQuarantineSwept")
            .count();
        assert_eq!(
            n_per, 2,
            "expected 2 per-initiative InitiativeQuarantined events, got: {kinds:?}"
        );
        assert_eq!(
            n_roll, 1,
            "expected exactly one OperatorQuarantineSwept rollup event, got: {kinds:?}"
        );

        let q = is_quarantined_rw(Arc::clone(&ctx), "init-c").await;
        assert!(
            !q,
            "initiatives signed by other operators MUST NOT be swept"
        );
    }

    #[tokio::test]
    async fn quarantine_plans_by_with_no_matching_plans_emits_rollup_only() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, sink) = build_ctx(tmp.path()).await;
        // No signed_plan_artifacts at all.

        let resp = handle_quarantine_plans_by(
            "nobody-fp".to_owned(),
            None,
            &fixture_operator("op-prime"),
            &ctx,
        )
        .await;

        match resp {
            OperatorResponse::QuarantineSwept {
                newly_quarantined_ids,
                ..
            } => {
                assert!(newly_quarantined_ids.is_empty());
            }
            other => panic!("expected QuarantineSwept, got {other:?}"),
        }

        // Per the design (kernel-store.md §2.5.8), an empty sweep STILL
        // emits the rollup so the audit chain shows the operator
        // attempted the action — forensic continuity matters even when
        // no rows changed.
        let kinds = sink.event_kinds();
        let n_per = kinds
            .iter()
            .filter(|k| **k == "InitiativeQuarantined")
            .count();
        let n_roll = kinds
            .iter()
            .filter(|k| **k == "OperatorQuarantineSwept")
            .count();
        assert_eq!(
            n_per, 0,
            "no per-initiative event should fire when nothing matched: {kinds:?}"
        );
        assert_eq!(n_roll, 1, "rollup must fire even on empty sweep: {kinds:?}");
    }
}
