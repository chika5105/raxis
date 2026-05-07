//! `shuttle` — bidirectional byte forwarding between the agent
//! socket and the kernel-tunnel socket once the kernel admits the
//! connection.
//!
//! The shuttle replays the bytes that `peek` already drained from
//! the agent (the TLS ClientHello / HTTP preamble) BEFORE pumping
//! further reads — otherwise the upstream sees a truncated flow.

use std::io;

use thiserror::Error;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite, AsyncWriteExt};

/// Errors from the byte-shuttle.
#[derive(Debug, Error)]
pub enum ShuttleError {
    /// I/O failure during the prelude replay or during
    /// `copy_bidirectional`.
    #[error("shuttle i/o: {0}")]
    Io(#[from] io::Error),
}

/// Replay `buffered` upstream, then bidirectionally forward bytes
/// between `agent` and `upstream` until either side closes.
///
/// Returns `(bytes_agent_to_upstream, bytes_upstream_to_agent)`
/// counts on success — handy for the per-connection byte audit
/// once the kernel is wired to record them.
pub async fn shuttle_with_prelude<A, U>(
    mut agent:    A,
    mut upstream: U,
    buffered:     &[u8],
) -> Result<(u64, u64), ShuttleError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    if !buffered.is_empty() {
        upstream.write_all(buffered).await?;
        upstream.flush().await?;
    }
    let prelude_len = buffered.len() as u64;
    let (a_to_u, u_to_a) = copy_bidirectional(&mut agent, &mut upstream).await?;
    Ok((prelude_len + a_to_u, u_to_a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn shuttle_replays_prelude_then_pumps_bytes_both_ways() {
        let (mut agent_kernel, mut agent_far) = tokio::io::duplex(4096);
        let (upstream_kernel, mut upstream_far) = tokio::io::duplex(4096);

        let buffered = b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec();
        let buffered_clone = buffered.clone();

        let shuttle_handle = tokio::spawn(async move {
            shuttle_with_prelude(&mut agent_kernel, upstream_kernel, &buffered_clone).await
        });

        let mut got_to_upstream = vec![0u8; buffered.len()];
        upstream_far.read_exact(&mut got_to_upstream).await.unwrap();
        assert_eq!(got_to_upstream, buffered);

        upstream_far.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        upstream_far.shutdown().await.unwrap();

        agent_far.write_all(b"more from agent").await.unwrap();
        agent_far.shutdown().await.unwrap();

        let mut got_back_to_agent = Vec::new();
        agent_far.read_to_end(&mut got_back_to_agent).await.unwrap();
        assert!(
            got_back_to_agent.starts_with(b"HTTP/1.1 200 OK"),
            "agent should receive upstream's response: {got_back_to_agent:?}",
        );

        let (a_to_u, u_to_a) = shuttle_handle.await.unwrap().unwrap();
        assert_eq!(
            a_to_u,
            (buffered.len() + b"more from agent".len()) as u64,
            "agent->upstream byte count must include prelude",
        );
        assert!(u_to_a > 0, "upstream->agent count should be non-zero");
    }
}
