//! Minimal RESP2 frame inspection helpers.
//!
//! We only need one operation: extract the uppercased verb (the
//! first array element of an array-form RESP request, or the
//! first whitespace-delimited token of an inline-form request)
//! so the restriction allowlist + audit chain can name the
//! command without re-parsing the whole frame.

/// Return the uppercased verb of one inbound RESP request frame,
/// or `None` if the bytes are not parseable as either array form
/// or inline form.
///
/// **Array form.**
/// ```text
/// *2\r\n
/// $3\r\nGET\r\n
/// $5\r\nmykey\r\n
/// ```
/// Returns `Some("GET")`.
///
/// **Inline form.**
/// ```text
/// PING\r\n
/// ```
/// Returns `Some("PING")`.
pub fn frame_verb_uppercased(frame: &[u8]) -> Option<String> {
    if frame.is_empty() {
        return None;
    }

    if frame[0] == b'*' {
        // Array form. Find the first bulk-string body.
        let after_array_header = match find_crlf(frame, 0) {
            Some(end) => end + 2,
            None => return None,
        };
        if after_array_header >= frame.len() || frame[after_array_header] != b'$' {
            return None;
        }
        let after_bulk_header = match find_crlf(frame, after_array_header) {
            Some(end) => end + 2,
            None => return None,
        };
        // Bulk body length is parseable but we just take whatever
        // is between after_bulk_header and the next CRLF (the
        // actual body bytes; assumes well-formed RESP).
        let body_end = match find_crlf(frame, after_bulk_header) {
            Some(end) => end,
            None => return None,
        };
        let body = &frame[after_bulk_header..body_end];
        return Some(String::from_utf8_lossy(body).to_ascii_uppercase());
    }

    // Inline form. Take the first whitespace-delimited token.
    let trimmed = trim_crlf(frame);
    let first_token: &[u8] = trimmed
        .split(|b| *b == b' ' || *b == b'\t')
        .next()
        .unwrap_or_default();
    if first_token.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(first_token).to_ascii_uppercase())
}

fn find_crlf(b: &[u8], start: usize) -> Option<usize> {
    if start >= b.len() {
        return None;
    }
    b[start..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|i| start + i)
}

fn trim_crlf(b: &[u8]) -> &[u8] {
    if b.ends_with(b"\r\n") {
        &b[..b.len() - 2]
    } else if b.ends_with(b"\n") {
        &b[..b.len() - 1]
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn array_form_get_yields_get() {
        let frame = b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
        assert_eq!(frame_verb_uppercased(frame).as_deref(), Some("GET"));
    }

    #[test]
    fn array_form_lowercase_verb_is_uppercased() {
        let frame = b"*1\r\n$4\r\nping\r\n";
        assert_eq!(frame_verb_uppercased(frame).as_deref(), Some("PING"));
    }

    #[test]
    fn inline_form_ping_yields_ping() {
        let frame = b"PING\r\n";
        assert_eq!(frame_verb_uppercased(frame).as_deref(), Some("PING"));
    }

    #[test]
    fn inline_form_with_args_takes_only_verb() {
        let frame = b"GET foo bar\r\n";
        assert_eq!(frame_verb_uppercased(frame).as_deref(), Some("GET"));
    }

    #[test]
    fn empty_frame_returns_none() {
        assert_eq!(frame_verb_uppercased(b""), None);
    }

    #[test]
    fn malformed_array_returns_none() {
        // No CRLFs.
        assert_eq!(frame_verb_uppercased(b"*1$3GET"), None);
    }
}
