//! Cursor-reply rewriter for the MongoDB `max_documents` streaming
//! cap. Per `proxy-table-allowlists.md §7.4`.
//!
//! The MongoDB cursor-reply doc has the shape:
//!
//! ```text
//! { cursor: {
//!     id:         <i64>,
//!     ns:         "<db>.<coll>",
//!     firstBatch: [ <doc>, <doc>, ... ],   // on find/aggregate
//!     // OR
//!     nextBatch:  [ <doc>, <doc>, ... ],   // on getMore
//!   },
//!   ok: 1.0,
//! }
//! ```
//!
//! `firstBatch` / `nextBatch` is a BSON **array** (type byte
//! `0x04`). Arrays in BSON are just documents with string keys
//! `"0"`, `"1"`, …
//!
//! Cap rules:
//!
//!   1. Walk the doc.
//!   2. Locate `cursor.firstBatch` or `cursor.nextBatch`.
//!   3. Count its elements; remember the count.
//!   4. If `previous + count <= max`, no rewrite needed.
//!   5. Otherwise, take the first `max - previous` elements,
//!      rebuild the cursor sub-doc with the truncated batch and
//!      `id = 0`, and emit the rewritten outer doc.
//!
//! The walker does NOT touch any field other than `id` and
//! `firstBatch`/`nextBatch`; every other field (`ns`, `ok`,
//! cluster time, etc.) is preserved bit-for-bit.

use crate::wire;

/// Outcome of [`apply_cap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorCapOutcome {
    /// The (possibly-rewritten) BSON document to emit to the
    /// agent. If `was_capped` is false this is identical to the
    /// input.
    pub bson_doc: Vec<u8>,
    /// Number of docs the upstream returned in `firstBatch` /
    /// `nextBatch` before truncation. `0` if no batch was found.
    pub upstream_docs: u32,
    /// Number of docs emitted after the cap. Equal to
    /// `upstream_docs` when not capped, otherwise the cap value.
    pub emitted_docs: u32,
    /// True if the cap fired and the batch was truncated.
    pub was_capped: bool,
    /// True if the doc contained a recognised cursor structure
    /// at all. False for non-cursor replies (e.g. `hello`'s
    /// reply, command errors, `insert` write-result replies).
    pub had_cursor: bool,
}

/// Apply `max_documents` to a reply BSON doc. `prior_emitted` is
/// the running count of documents already returned to the agent
/// on this cursor (across `firstBatch` + N `getMore`s).
///
/// `max` of `0` means "uncapped" and short-circuits with
/// `was_capped = false`.
pub fn apply_cap(reply_doc: &[u8], max: u64, prior_emitted: u64) -> CursorCapOutcome {
    if max == 0 {
        return CursorCapOutcome {
            bson_doc: reply_doc.to_vec(),
            upstream_docs: 0,
            emitted_docs: 0,
            was_capped: false,
            had_cursor: false,
        };
    }
    match find_cursor_batch(reply_doc) {
        Some(loc) => {
            let upstream_docs = loc.batch_count;
            let remaining_budget = max.saturating_sub(prior_emitted);
            let emit = std::cmp::min(upstream_docs as u64, remaining_budget) as u32;
            if (upstream_docs as u64) <= remaining_budget {
                CursorCapOutcome {
                    bson_doc: reply_doc.to_vec(),
                    upstream_docs,
                    emitted_docs: upstream_docs,
                    was_capped: false,
                    had_cursor: true,
                }
            } else {
                let rewritten = rewrite_truncated(reply_doc, &loc, emit as usize);
                CursorCapOutcome {
                    bson_doc: rewritten,
                    upstream_docs,
                    emitted_docs: emit,
                    was_capped: true,
                    had_cursor: true,
                }
            }
        }
        None => CursorCapOutcome {
            bson_doc: reply_doc.to_vec(),
            upstream_docs: 0,
            emitted_docs: 0,
            was_capped: false,
            had_cursor: false,
        },
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CursorBatchLocation {
    /// Range within the outer doc of the `cursor` element's
    /// **value bytes** (the embedded doc bytes, not including
    /// the type/name preamble).
    cursor_doc_start: usize,
    cursor_doc_end: usize,
    /// Range within the cursor doc of the batch element's name
    /// bytes (`firstBatch` or `nextBatch`).
    batch_name: String,
    /// Range within the cursor doc of the batch element's value
    /// bytes (the embedded array's full doc bytes).
    batch_doc_start: usize,
    batch_doc_end: usize,
    /// Per-element offsets within the batch's body (each is
    /// `(element_start, element_end)` relative to the batch
    /// document's start).
    elem_offsets: Vec<(usize, usize)>,
    /// Number of documents in the batch (same as
    /// `elem_offsets.len()`).
    batch_count: u32,
    /// `cursor.id` element location (relative to outer doc).
    /// Used to zero the id on truncation.
    id_value_start: Option<usize>,
}

fn find_cursor_batch(doc: &[u8]) -> Option<CursorBatchLocation> {
    let outer = parse_doc(doc)?;
    for el in &outer.elements {
        if el.name == "cursor" && el.type_byte == 0x03 {
            let cursor_doc = &doc[el.value_start..el.value_end];
            let inner = parse_doc(cursor_doc)?;
            let mut batch_loc: Option<(String, usize, usize)> = None;
            let mut id_loc: Option<usize> = None;
            for sub in &inner.elements {
                match (sub.name.as_str(), sub.type_byte) {
                    ("firstBatch", 0x04) | ("nextBatch", 0x04) => {
                        batch_loc = Some((sub.name.clone(), sub.value_start, sub.value_end));
                    }
                    ("id", 0x12) => {
                        id_loc = Some(el.value_start + sub.value_start);
                    }
                    _ => {}
                }
            }
            let (batch_name, bs, be) = batch_loc?;
            // Parse the array (= a doc with numeric keys).
            let batch_doc = &cursor_doc[bs..be];
            let arr = parse_doc(batch_doc)?;
            let mut elem_offsets = Vec::with_capacity(arr.elements.len());
            for arr_el in &arr.elements {
                if arr_el.type_byte != 0x03 {
                    continue;
                }
                elem_offsets.push((arr_el.element_start, arr_el.element_end));
            }
            return Some(CursorBatchLocation {
                cursor_doc_start: el.value_start,
                cursor_doc_end: el.value_end,
                batch_name,
                batch_doc_start: bs,
                batch_doc_end: be,
                elem_offsets,
                batch_count: arr.elements.len() as u32,
                id_value_start: id_loc,
            });
        }
    }
    None
}

/// Rebuild the outer doc with the cursor doc replaced — the
/// batch is truncated to `keep` docs, the `id` field set to 0,
/// every other field preserved.
fn rewrite_truncated(outer: &[u8], loc: &CursorBatchLocation, keep: usize) -> Vec<u8> {
    let cursor_doc = &outer[loc.cursor_doc_start..loc.cursor_doc_end];
    // Build truncated array as a fresh doc with numeric keys
    // "0", "1", ... (BSON array convention).
    let mut new_array_body = Vec::new();
    for (i, (es, ee)) in loc.elem_offsets.iter().take(keep).enumerate() {
        let elem_bytes = &outer[loc.cursor_doc_start + loc.batch_doc_start + *es
            ..loc.cursor_doc_start + loc.batch_doc_start + *ee];
        // The element bytes are `type_byte + cstring(name) + value`.
        // We rewrite the name to `i.to_string()` because element
        // names in arrays must be sequential "0", "1", "2", ...
        // (Mongo drivers DO validate this).
        if elem_bytes.is_empty() {
            continue;
        }
        let t = elem_bytes[0];
        let nul = elem_bytes[1..].iter().position(|&b| b == 0).unwrap_or(0);
        if 1 + nul + 1 > elem_bytes.len() {
            continue;
        }
        let value_bytes = &elem_bytes[1 + nul + 1..];
        new_array_body.push(t);
        new_array_body.extend_from_slice(i.to_string().as_bytes());
        new_array_body.push(0x00);
        new_array_body.extend_from_slice(value_bytes);
    }
    let new_array_doc = wrap_doc(&new_array_body);

    // Build new cursor doc preserving every element except the
    // batch (replaced) and `id` (zeroed).
    let mut new_cursor_body = Vec::new();
    let inner = parse_doc(cursor_doc).expect("cursor doc parsed earlier");
    for el in &inner.elements {
        match (el.name.as_str(), el.type_byte) {
            ("firstBatch", 0x04) | ("nextBatch", 0x04) => {
                new_cursor_body.push(0x04);
                new_cursor_body.extend_from_slice(loc.batch_name.as_bytes());
                new_cursor_body.push(0x00);
                new_cursor_body.extend_from_slice(&new_array_doc);
            }
            ("id", 0x12) => {
                new_cursor_body.push(0x12);
                new_cursor_body.extend_from_slice(b"id");
                new_cursor_body.push(0x00);
                new_cursor_body.extend_from_slice(&0i64.to_le_bytes());
            }
            _ => {
                let bytes = &cursor_doc[el.element_start..el.element_end];
                new_cursor_body.extend_from_slice(bytes);
            }
        }
    }
    // If `id` wasn't present at all (unusual but defensive),
    // inject it.
    if loc.id_value_start.is_none() {
        new_cursor_body.push(0x12);
        new_cursor_body.extend_from_slice(b"id");
        new_cursor_body.push(0x00);
        new_cursor_body.extend_from_slice(&0i64.to_le_bytes());
    }
    let new_cursor_doc = wrap_doc(&new_cursor_body);

    // Build new outer doc: preserve every element except `cursor`,
    // which we replace.
    let outer_parsed = parse_doc(outer).expect("outer doc parsed earlier");
    let mut new_outer_body = Vec::new();
    for el in &outer_parsed.elements {
        if el.name == "cursor" && el.type_byte == 0x03 {
            new_outer_body.push(0x03);
            new_outer_body.extend_from_slice(b"cursor");
            new_outer_body.push(0x00);
            new_outer_body.extend_from_slice(&new_cursor_doc);
        } else {
            new_outer_body.extend_from_slice(&outer[el.element_start..el.element_end]);
        }
    }
    wrap_doc(&new_outer_body)
}

fn wrap_doc(body: &[u8]) -> Vec<u8> {
    let total = (4 + body.len() + 1) as i32;
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.push(0x00);
    out
}

#[derive(Debug, Clone)]
struct ParsedDoc {
    elements: Vec<ParsedElement>,
}

#[derive(Debug, Clone)]
struct ParsedElement {
    type_byte: u8,
    name: String,
    /// Range of the entire element (type + name + value) within
    /// its parent doc.
    element_start: usize,
    element_end: usize,
    /// Range of the value bytes within the parent doc.
    value_start: usize,
    value_end: usize,
}

fn parse_doc(doc: &[u8]) -> Option<ParsedDoc> {
    if doc.len() < 5 {
        return None;
    }
    let total = i32::from_le_bytes(doc[..4].try_into().ok()?) as usize;
    if total < 5 || total > doc.len() {
        return None;
    }
    if doc[total - 1] != 0x00 {
        return None;
    }
    let mut p = 4;
    let mut elements = Vec::new();
    while p < total - 1 {
        let el_start = p;
        let type_byte = doc[p];
        p += 1;
        let nul = doc[p..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&doc[p..p + nul]).ok()?.to_owned();
        p += nul + 1;
        let value_start = p;
        let value_end = value_start + value_len(type_byte, &doc[value_start..])?;
        if value_end > total - 1 {
            return None;
        }
        elements.push(ParsedElement {
            type_byte,
            name,
            element_start: el_start,
            element_end: value_end,
            value_start,
            value_end,
        });
        p = value_end;
    }
    Some(ParsedDoc { elements })
}

fn value_len(type_byte: u8, data: &[u8]) -> Option<usize> {
    Some(match type_byte {
        0x01 => 8,
        0x02 => {
            if data.len() < 4 {
                return None;
            }
            let len = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if 4 + len > data.len() {
                return None;
            }
            4 + len
        }
        0x03 | 0x04 => {
            if data.len() < 4 {
                return None;
            }
            let total = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if total > data.len() {
                return None;
            }
            total
        }
        0x05 => {
            if data.len() < 5 {
                return None;
            }
            let len = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if 5 + len > data.len() {
                return None;
            }
            5 + len
        }
        0x06 => 0,
        0x07 => 12,
        0x08 => 1,
        0x09 => 8,
        0x0A => 0,
        0x0B => {
            let n1 = data.iter().position(|&b| b == 0)?;
            let after1 = &data[n1 + 1..];
            let n2 = after1.iter().position(|&b| b == 0)?;
            n1 + 1 + n2 + 1
        }
        0x0C => {
            if data.len() < 4 {
                return None;
            }
            let len = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if 4 + len + 12 > data.len() {
                return None;
            }
            4 + len + 12
        }
        0x0D | 0x0E => {
            if data.len() < 4 {
                return None;
            }
            let len = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if 4 + len > data.len() {
                return None;
            }
            4 + len
        }
        0x0F => {
            if data.len() < 4 {
                return None;
            }
            let total = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if total > data.len() {
                return None;
            }
            total
        }
        0x10 => 4,
        0x11 | 0x12 => 8,
        0x13 => 16,
        0xFF | 0x7F => 0,
        _ => return None,
    })
}

/// Rebuild an `OP_MSG` reply frame around a (possibly-rewritten)
/// BSON doc. The header fields (`request_id`, `response_to`,
/// `op_code`) are preserved from the input frame.
pub fn rebuild_op_msg_frame(original_frame: &[u8], new_bson_doc: &[u8]) -> Option<Vec<u8>> {
    if original_frame.len() < wire::HEADER_LEN {
        return None;
    }
    let header_bytes: [u8; wire::HEADER_LEN] =
        original_frame[..wire::HEADER_LEN].try_into().ok()?;
    let header = wire::MsgHeader::parse(header_bytes);
    Some(wire::build_op_msg_reply(
        header.request_id,
        header.response_to,
        new_bson_doc,
    ))
}

/// Extract the kind-0 BSON doc bytes from an `OP_MSG` reply
/// frame.
pub fn extract_reply_doc(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < wire::HEADER_LEN + 4 + 1 {
        return None;
    }
    let header_bytes: [u8; wire::HEADER_LEN] = frame[..wire::HEADER_LEN].try_into().ok()?;
    let header = wire::MsgHeader::parse(header_bytes);
    if header.op_code != wire::OP_MSG {
        return None;
    }
    let total = header.message_length as usize;
    if total > frame.len() {
        return None;
    }
    let body = &frame[wire::HEADER_LEN..total];
    // Skip the 4 flag_bits, then walk to the first kind-0 section.
    if body.len() < 4 {
        return None;
    }
    let mut i = 4;
    while i < body.len() {
        let kind = body[i];
        i += 1;
        if kind == 0 {
            // BSON doc starts at `i`. Its own length-prefix tells
            // us the doc length.
            if i + 4 > body.len() {
                return None;
            }
            let doc_total = i32::from_le_bytes(body[i..i + 4].try_into().ok()?) as usize;
            if i + doc_total > body.len() {
                return None;
            }
            return Some(&body[i..i + doc_total]);
        } else if kind == 1 {
            if i + 4 > body.len() {
                return None;
            }
            let section_size = i32::from_le_bytes(body[i..i + 4].try_into().ok()?) as usize;
            if section_size < 4 || i + section_size > body.len() {
                return None;
            }
            i += section_size;
        } else {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::BsonBuilder;

    /// Build a BSON array (= a doc with numeric keys "0", "1", ...)
    /// of `n` minimal documents `{ _id: i }`.
    fn build_batch_array(n: usize) -> Vec<u8> {
        let mut b = BsonBuilder::new();
        for i in 0..n {
            let inner = BsonBuilder::new().int32("_id", i as i32).finish();
            b = b.document(&i.to_string(), inner);
        }
        b.finish()
    }

    fn build_cursor_reply(batch_size: usize, cursor_id: i64, ns: &str) -> Vec<u8> {
        let arr = build_batch_array(batch_size);
        let cursor = BsonBuilder::new()
            .int64("id", cursor_id)
            .string("ns", ns)
            .array("firstBatch", arr)
            .finish();
        BsonBuilder::new()
            .document("cursor", cursor)
            .double("ok", 1.0)
            .finish()
    }

    #[test]
    fn no_cap_when_max_zero() {
        let doc = build_cursor_reply(5, 12345, "appdb.users");
        let out = apply_cap(&doc, 0, 0);
        assert!(!out.was_capped);
        assert_eq!(out.bson_doc, doc);
    }

    #[test]
    fn no_cap_when_under_budget() {
        let doc = build_cursor_reply(5, 12345, "appdb.users");
        let out = apply_cap(&doc, 100, 0);
        assert!(!out.was_capped);
        assert_eq!(out.upstream_docs, 5);
        assert_eq!(out.emitted_docs, 5);
        assert!(out.had_cursor);
    }

    #[test]
    fn cap_truncates_batch_and_zeros_id() {
        let doc = build_cursor_reply(10, 99999, "appdb.users");
        let out = apply_cap(&doc, 3, 0);
        assert!(out.was_capped);
        assert_eq!(out.upstream_docs, 10);
        assert_eq!(out.emitted_docs, 3);

        // After rewrite, the doc should parse and have a cursor
        // with id=0 and a batch of 3.
        let parsed = parse_doc(&out.bson_doc).expect("rewritten doc parses");
        let cursor_el = parsed
            .elements
            .iter()
            .find(|e| e.name == "cursor")
            .expect("cursor element present");
        let cursor_doc = &out.bson_doc[cursor_el.value_start..cursor_el.value_end];
        let cursor_parsed = parse_doc(cursor_doc).expect("cursor doc parses");
        let id_el = cursor_parsed
            .elements
            .iter()
            .find(|e| e.name == "id")
            .expect("id present");
        let id_bytes = &cursor_doc[id_el.value_start..id_el.value_end];
        let id = i64::from_le_bytes(id_bytes.try_into().unwrap());
        assert_eq!(id, 0, "cursor id must be zeroed on truncation");

        let batch_el = cursor_parsed
            .elements
            .iter()
            .find(|e| e.name == "firstBatch")
            .expect("firstBatch present");
        let batch_doc = &cursor_doc[batch_el.value_start..batch_el.value_end];
        let batch_parsed = parse_doc(batch_doc).expect("batch doc parses");
        assert_eq!(batch_parsed.elements.len(), 3, "batch truncated to 3");
    }

    #[test]
    fn cap_across_get_more_uses_prior_emitted() {
        // First batch returned 6 docs (already emitted),
        // getMore returns 5 more — total would be 11.
        let doc = build_cursor_reply(5, 99999, "appdb.users");
        let out = apply_cap(&doc, 8, 6);
        assert!(out.was_capped);
        assert_eq!(out.upstream_docs, 5);
        assert_eq!(out.emitted_docs, 2);
    }

    #[test]
    fn cap_with_no_cursor_doc_is_passthrough() {
        let doc = BsonBuilder::new().double("ok", 1.0).finish();
        let out = apply_cap(&doc, 100, 0);
        assert!(!out.was_capped);
        assert!(!out.had_cursor);
        assert_eq!(out.bson_doc, doc);
    }

    #[test]
    fn cap_caps_to_exact_budget() {
        let doc = build_cursor_reply(10, 99999, "appdb.users");
        let out = apply_cap(&doc, 5, 0);
        assert!(out.was_capped);
        assert_eq!(out.emitted_docs, 5);
    }

    #[test]
    fn extract_and_rebuild_round_trip() {
        let doc = build_cursor_reply(3, 12345, "appdb.users");
        let frame = wire::build_op_msg_reply(7, 3, &doc);
        let extracted = extract_reply_doc(&frame).expect("extracted");
        assert_eq!(extracted, doc.as_slice());
        let rebuilt = rebuild_op_msg_frame(&frame, &doc).expect("rebuilt");
        let header_ok = rebuilt.len() == frame.len();
        assert!(header_ok, "rebuilt frame same length as original");
    }
}
