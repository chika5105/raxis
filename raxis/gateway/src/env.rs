//! Environment-variable parser for the gateway subprocess.
//!
//! Normative reference: `peripherals.md` §3.2 "Spawn model" — the
//! kernel sets `RAXIS_GATEWAY_TOKEN` and `RAXIS_GATEWAY_SOCKET` at
//! spawn time; `RAXIS_DATA_DIR` is also passed so the gateway can
//! read policy.toml and the provider credentials directory.
//!
//! Why a dedicated module: `parse_gateway_env_from_process` is the
//! SOLE entry point that reads from `std::env::var`. Keeping the
//! read confined makes it trivial to test the rest of the crate by
//! constructing `GatewayEnv` literals directly. The `verifier-stub`
//! crate uses the same pattern (`parse_stub_env_from_process`), and
//! we mirror it here.
//!
//! # No `BackendKind`
//!
//! Earlier revisions parsed an optional `RAXIS_GATEWAY_BACKEND` env
//! var into a `Mock` / `Http` selector. That selector has been
//! removed: production gateways always use `HttpBackend`, and the
//! in-memory test fake (`MockBackend`) lives in `raxis-test-support`
//! where it is reachable only from `cargo test` builds. A binary
//! that picks its substrate at runtime depending on operator-supplied
//! env conflates "production behaviour" with "test scaffolding" —
//! the same anti-pattern the `RealClock` / `FakeClock` split avoids.

use std::path::PathBuf;
use thiserror::Error;

/// Validated env vars handed to a gateway process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayEnv {
    /// 64-char hex string — the kernel-issued process token. Echoed back
    /// in `GatewayMessage::GatewayReady` and on every `FetchRequest`.
    pub gateway_token: String,
    /// UDS path the gateway connects to (kernel side bound this with
    /// `UnixListener::bind` in `ipc/server.rs::start`).
    pub gateway_socket: PathBuf,
    /// Data dir root (e.g. `~/.raxis`). Used to resolve
    /// `<data_dir>/policy/policy.toml` and `<data_dir>/providers/...`.
    pub data_dir: PathBuf,
}

/// Why the env-var parse failed. Pinned by tests so the gateway's
/// `main.rs` can render predictable diagnostics on misconfiguration.
#[derive(Debug, Clone, Error)]
pub enum GatewayEnvError {
    /// A required env var was missing.
    #[error("missing required env var: {0}")]
    Missing(&'static str),

    /// `RAXIS_GATEWAY_TOKEN` was not 64 hex chars.
    #[error("invalid RAXIS_GATEWAY_TOKEN: {reason}")]
    InvalidToken { reason: String },

    /// `RAXIS_GATEWAY_SOCKET` was an empty / non-absolute path.
    #[error("invalid RAXIS_GATEWAY_SOCKET: {reason}")]
    InvalidSocket { reason: String },

    /// `RAXIS_DATA_DIR` was empty / non-absolute.
    #[error("invalid RAXIS_DATA_DIR: {reason}")]
    InvalidDataDir { reason: String },
}

/// Read the three env vars from the process and return a validated
/// [`GatewayEnv`]. This is the ONLY function in the crate that calls
/// `std::env::var` — every other module takes a `GatewayEnv` reference.
pub fn parse_gateway_env_from_process() -> Result<GatewayEnv, GatewayEnvError> {
    let token = read_required("RAXIS_GATEWAY_TOKEN")?;
    let socket = read_required("RAXIS_GATEWAY_SOCKET")?;
    let data_dir = read_required("RAXIS_DATA_DIR")?;

    parse_gateway_env(&token, &socket, &data_dir)
}

/// Pure parser. Tests call this directly with hand-crafted inputs.
pub fn parse_gateway_env(
    token: &str,
    socket: &str,
    data_dir: &str,
) -> Result<GatewayEnv, GatewayEnvError> {
    // Token: must be 64 hex chars (32 random bytes). Anything else is
    // either truncated (operator misconfig) or padded (attacker-supplied
    // env). We do not just `hex::decode` — empty strings would decode
    // to an empty Vec without erroring, masking the misconfiguration.
    if token.len() != 64 {
        return Err(GatewayEnvError::InvalidToken {
            reason: format!("expected 64 hex chars (32 raw bytes), got {} chars", token.len()),
        });
    }
    hex::decode(token).map_err(|e| GatewayEnvError::InvalidToken {
        reason: format!("hex decode failed: {e}"),
    })?;

    // Socket: must be a non-empty absolute path. Relative paths would
    // be interpreted against the gateway's CWD which the kernel does
    // not pin; we'd fail with a confusing ENOENT downstream.
    if socket.is_empty() {
        return Err(GatewayEnvError::InvalidSocket {
            reason: "empty path".to_owned(),
        });
    }
    let socket_path = PathBuf::from(socket);
    if !socket_path.is_absolute() {
        return Err(GatewayEnvError::InvalidSocket {
            reason: format!("must be absolute, got {socket:?}"),
        });
    }

    // Data dir: same constraints.
    if data_dir.is_empty() {
        return Err(GatewayEnvError::InvalidDataDir {
            reason: "empty path".to_owned(),
        });
    }
    let data_dir_path = PathBuf::from(data_dir);
    if !data_dir_path.is_absolute() {
        return Err(GatewayEnvError::InvalidDataDir {
            reason: format!("must be absolute, got {data_dir:?}"),
        });
    }

    Ok(GatewayEnv {
        gateway_token: token.to_owned(),
        gateway_socket: socket_path,
        data_dir: data_dir_path,
    })
}

fn read_required(var: &'static str) -> Result<String, GatewayEnvError> {
    std::env::var(var).map_err(|_| GatewayEnvError::Missing(var))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_token() -> String {
        "a".repeat(64)
    }

    #[test]
    fn happy_path() {
        let env = parse_gateway_env(&ok_token(), "/tmp/gw.sock", "/tmp/data").unwrap();
        assert_eq!(env.gateway_token, ok_token());
        assert_eq!(env.gateway_socket, PathBuf::from("/tmp/gw.sock"));
        assert_eq!(env.data_dir, PathBuf::from("/tmp/data"));
    }

    #[test]
    fn token_too_short_is_rejected_with_chars_count() {
        let err = parse_gateway_env("abcd", "/tmp/gw.sock", "/tmp/data").unwrap_err();
        match err {
            GatewayEnvError::InvalidToken { reason } => {
                assert!(reason.contains("64 hex chars"), "reason: {reason}");
                assert!(reason.contains("4 chars"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn token_with_non_hex_chars_is_rejected() {
        let bad = format!("{}", "Z".repeat(64));
        let err = parse_gateway_env(&bad, "/tmp/gw.sock", "/tmp/data").unwrap_err();
        assert!(matches!(err, GatewayEnvError::InvalidToken { .. }));
    }

    #[test]
    fn empty_token_is_rejected_as_length_mismatch() {
        let err = parse_gateway_env("", "/tmp/gw.sock", "/tmp/data").unwrap_err();
        match err {
            GatewayEnvError::InvalidToken { reason } => {
                assert!(reason.contains("0 chars"), "reason: {reason}");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn relative_socket_path_is_rejected() {
        let err = parse_gateway_env(&ok_token(), "gw.sock", "/tmp/data").unwrap_err();
        assert!(matches!(err, GatewayEnvError::InvalidSocket { .. }));
    }

    #[test]
    fn relative_data_dir_is_rejected() {
        let err = parse_gateway_env(&ok_token(), "/tmp/gw.sock", "raxis").unwrap_err();
        assert!(matches!(err, GatewayEnvError::InvalidDataDir { .. }));
    }
}
