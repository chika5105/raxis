// raxis-cli::errors — CLI error types.

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("usage: {0}")]
    Usage(String),

    #[error("socket not found: {path} (is the kernel running?)")]
    SocketNotFound { path: String },

    #[error("socket error: {0}")]
    Socket(#[from] std::io::Error),

    #[error("kernel responded with error: {code} — {detail}")]
    KernelError { code: String, detail: String },

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("policy error: {0}")]
    Policy(String),

    #[error("key error: {0}")]
    Key(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error on {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}
