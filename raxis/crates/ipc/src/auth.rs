// raxis-ipc::auth — Lightweight auth validation types shared by all sockets.
//
// Normative reference:
//   - kernel-store.md §2.5.1 Table 16 "nonce_cache" and the dispatcher sequence
//   - kernel-core.md §`ipc/auth.rs` handler description
//   - peripherals.md §3.1 field rules (sequence_number, envelope_nonce)
//
// This module defines the envelope fields the dispatcher validates on every
// inbound frame BEFORE routing to a domain handler. The actual DB lookups
// are in raxis-store; these are the pure data types.
//
// Auth flow (kernel-core.md §2.5.1 INV-01 dispatcher sequence):
//   1. Deserialise frame into IpcMessage.
//   2. Extract (session_token, sequence_number, envelope_nonce) from envelope.
//   3. Look up session row by token hash.
//   4. Check revoked_at IS NULL and not expired.
//   5. Atomically: UPDATE sessions SET sequence_number = sequence_number + 1
//      WHERE sequence_number = expected AND INSERT nonce INTO nonce_cache.
//      Failure → UNAUTHORIZED.
//   6. Route to domain handler.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// AuthEnvelope — the fields extracted from every inbound planner IPC frame
// for auth validation. Not a wire type itself — the dispatcher extracts
// these from the deserialized IpcMessage variants.
// ---------------------------------------------------------------------------

/// Auth fields present in every planner IntentRequest.
/// Extracted before domain routing; validated against the sessions table.
#[derive(Debug, Clone)]
pub struct AuthEnvelope {
    /// The 64-char hex session token (32 raw bytes). Kernel looks up by
    /// SHA-256(token_bytes) against sessions.session_token_hash.
    pub session_token: String,

    /// Must be exactly sessions.sequence_number + 1.
    pub sequence_number: u64,

    /// 32-char hex (16 random bytes). Must not appear in nonce_cache for
    /// this session within the cache TTL window.
    pub envelope_nonce: String,
}

// ---------------------------------------------------------------------------
// SocketKind — which of the three UDS sockets a connection arrived on.
// Used by the dispatcher to enforce socket-level message kind restrictions.
// ---------------------------------------------------------------------------

/// The UDS socket a connection was accepted on.
///
/// Each socket permits a different subset of IpcMessage variants:
/// - PlannerSocket: IntentRequest, EscalationRequest, WitnessSubmission
/// - OperatorSocket: OperatorRequest
/// - GatewaySocket: GatewayMessage (separate type; not IpcMessage)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    Planner,
    Operator,
    Gateway,
}

/// Validation result returned by the auth layer to the dispatcher.
#[derive(Debug)]
pub enum AuthResult {
    /// Frame passed all auth checks. Contains the resolved session ID.
    Ok { session_id: String },
    /// Frame failed auth. The dispatcher returns UNAUTHORIZED and closes.
    Unauthorized { reason: AuthFailReason },
}

/// Why authentication failed. Coarse — only logged in audit; never sent to planner.
/// INV-08: the planner receives only the UNAUTHORIZED error code, not this detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthFailReason {
    SessionNotFound,
    SessionRevoked,
    SessionExpired,
    SequenceMismatch { expected: u64, got: u64 },
    NonceReplay,
    TokenHashMismatch,
}
