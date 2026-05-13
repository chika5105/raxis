//! Walk a signed cpio.gz initramfs and yield the set of paths it
//! contains.
//!
//! ## Why this exists
//!
//! Iter-12 surfaced a class of failures where `BashTool` returned
//! `ENOENT` for every command inside the executor VM. The kernel's
//! manifest verification path was happy (the cpio was signed and
//! its `image_artefact_sha256` matched), but the cpio itself
//! contained nothing but the cross-compiled planner binary —
//! `bin/bash`, `usr/bin/python3`, `usr/bin/git` were all absent.
//!
//! The fix is twofold:
//!   1. Bake the rootfs from the canonical `images/<role>/Containerfile`
//!      via the new `cargo xtask images bake-rootfs` (Branch A,
//!      commit `015579e`).
//!   2. Strengthen the live-e2e preflight (`require_canonical_images`)
//!      so the test fails fast at boot time rather than 4 minutes in
//!      when the LLM tries to spawn `bash`.
//!
//! This module is the parser half of (2). It returns the set of
//! file / symlink paths inside the cpio.gz so callers can assert
//! per-role required-binary presence.
//!
//! ## What this is NOT
//!
//! * Not a general-purpose cpio library. We parse only the newc
//!   (`070701`) variant the Linux kernel's `init/initramfs.c`
//!   produces (and which `raxis-initramfs-builder` emits). We
//!   do NOT parse data — only headers, names, and symlink targets
//!   are returned. The data section is `seek`'d past.
//! * Not a verifier. Manifest signature / SHA-256 verification is
//!   the kernel's job (`canonical_images_preflight.rs`); this
//!   module assumes the bytes have already been trusted.

use std::collections::BTreeMap;
use std::io::{BufReader, Read};
use std::path::Path;

use flate2::read::GzDecoder;

/// One entry recovered from a cpio newc archive. Mirrors the slice
/// of the on-disk header `raxis-initramfs-builder::CpioEntry` writes,
/// minus the data bytes (we never need to look at file contents from
/// a preflight assertion).
#[derive(Debug, Clone)]
pub struct CpioEntry {
    /// Full path inside the archive, NOT including a leading `/`
    /// (matches `raxis-initramfs-builder`'s emitted shape).
    pub path: String,
    /// `c_mode` from the newc header. The high bits tell file vs dir
    /// vs symlink (S_IFREG / S_IFDIR / S_IFLNK); the low 12 bits are
    /// the permission triplets.
    pub mode: u32,
    /// Symlink target, in archive bytes. Populated only for
    /// `S_IFLNK` entries; `None` otherwise.
    pub symlink_target: Option<String>,
}

/// `S_IFLNK` mask matching what `raxis-initramfs-builder` emits.
const S_IFLNK: u32 = 0o120_000;

/// `c_mode` mask used by the kernel's `init/initramfs.c` to
/// extract the file-type nibble.
const S_IFMT:  u32 = 0o170_000;

/// Walk `cpio_gz_path` and return every entry the archive contains.
///
/// Returns a `BTreeMap` keyed by path so callers can do
/// containment checks and the test output is deterministic on
/// failure (random-order Vec output is a nightmare to diff in CI).
///
/// # Errors
///
/// * `std::io::Error` for I/O failures (file missing, gzip CRC
///   mismatch, truncated archive).
/// * Bails on a corrupted cpio header (bad magic, non-hex digits)
///   via `std::io::Error::other` — surfaces as a test panic with
///   the malformed offset in the message.
pub fn list_initramfs_paths(cpio_gz_path: &Path) -> std::io::Result<BTreeMap<String, CpioEntry>> {
    let f      = std::fs::File::open(cpio_gz_path)?;
    let reader = BufReader::new(f);
    let mut gz = GzDecoder::new(reader);
    let mut buf: Vec<u8> = Vec::new();
    gz.read_to_end(&mut buf)?;
    parse_newc_archive(&buf)
}

/// Parse a fully-decompressed cpio newc byte stream.
///
/// Newc archive layout (one entry):
///
/// ```text
/// magic         "070701"           6  bytes
/// c_ino         8 hex digits
/// c_mode        8 hex digits
/// c_uid         8 hex digits
/// c_gid         8 hex digits
/// c_nlink       8 hex digits
/// c_mtime       8 hex digits
/// c_filesize    8 hex digits
/// c_devmajor    8 hex digits
/// c_devminor    8 hex digits
/// c_rdevmajor   8 hex digits
/// c_rdevminor   8 hex digits
/// c_namesize    8 hex digits  (length of name including trailing NUL)
/// c_check       8 hex digits  (always "00000000" in newc)
/// path          c_namesize bytes (NUL-terminated)
/// pad           0..3 bytes so that (header+name) is 4-byte aligned
/// data          c_filesize bytes
/// pad           0..3 bytes so that data is 4-byte aligned
/// ```
///
/// The archive ends with a sentinel entry whose name is
/// `"TRAILER!!!"` and `c_filesize == 0`.
fn parse_newc_archive(bytes: &[u8]) -> std::io::Result<BTreeMap<String, CpioEntry>> {
    let mut out: BTreeMap<String, CpioEntry> = BTreeMap::new();
    let mut cursor: usize = 0;
    let total = bytes.len();

    while cursor < total {
        // ── Header ──
        if total - cursor < 110 {
            return Err(std::io::Error::other(format!(
                "truncated cpio: header at offset {cursor} would extend past end ({total})"
            )));
        }
        let header = &bytes[cursor..cursor + 110];
        if &header[0..6] != b"070701" {
            return Err(std::io::Error::other(format!(
                "bad cpio newc magic at offset {cursor}: {:?}",
                &header[0..6],
            )));
        }
        let mode      = parse_hex8(&header[14..22], cursor + 14)?;
        let filesize  = parse_hex8(&header[54..62], cursor + 54)?;
        let namesize  = parse_hex8(&header[94..102], cursor + 94)?;
        cursor += 110;

        // ── Path ──
        if total - cursor < namesize as usize {
            return Err(std::io::Error::other(format!(
                "truncated cpio: name at offset {cursor} (needs {} bytes)", namesize,
            )));
        }
        let raw_name = &bytes[cursor..cursor + namesize as usize];
        // Trim trailing NUL.
        let name_end = raw_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(raw_name.len());
        let path = String::from_utf8_lossy(&raw_name[..name_end]).into_owned();
        cursor += namesize as usize;

        // 4-byte-align: the header (110) + name (namesize) is padded
        // to a 4-byte boundary before the data starts.
        let header_and_name = 110 + namesize as usize;
        cursor += pad_to_4(header_and_name);

        // ── Sentinel ──
        if path == "TRAILER!!!" {
            break;
        }

        // ── Data ──
        let mut symlink_target: Option<String> = None;
        if total - cursor < filesize as usize {
            return Err(std::io::Error::other(format!(
                "truncated cpio: data at offset {cursor} (needs {} bytes)", filesize,
            )));
        }
        if mode & S_IFMT == S_IFLNK {
            // Symlink target IS the file body — capture it for
            // callers that need to chase `/usr/bin/python3 ->
            // python3.11` style indirection.
            let body = &bytes[cursor..cursor + filesize as usize];
            symlink_target = Some(String::from_utf8_lossy(body).into_owned());
        }
        cursor += filesize as usize;
        cursor += pad_to_4(filesize as usize);

        // Skip pseudo-entries the kernel ignores ("." entry, etc.) by
        // de-duping on path. We keep the LAST occurrence so a manifest
        // that re-emits a file later in the archive (theoretically
        // possible for newc) reflects the post-overwrite state.
        out.insert(path.clone(), CpioEntry { path, mode, symlink_target });
    }

    Ok(out)
}

fn parse_hex8(slice: &[u8], at: usize) -> std::io::Result<u32> {
    debug_assert_eq!(slice.len(), 8);
    let s = std::str::from_utf8(slice)
        .map_err(|e| std::io::Error::other(format!("non-utf8 cpio header at offset {at}: {e}")))?;
    u32::from_str_radix(s, 16)
        .map_err(|e| std::io::Error::other(format!("non-hex cpio header at offset {at}: {e}")))
}

fn pad_to_4(n: usize) -> usize {
    (4 - (n & 3)) & 3
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke: round-trip a hand-built cpio.gz through the parser and
    /// confirm every entry is recovered. Avoids dragging in
    /// `raxis-initramfs-builder` here (already tested by its own
    /// crate) — we hand-emit a minimal newc stream so any breakage
    /// in the producer-side encoder doesn't mask a parser bug.
    #[test]
    fn parser_recovers_entries_from_minimal_newc_stream() {
        // Two entries: a regular file and a symlink. Plus the
        // mandatory TRAILER!!! sentinel.
        let mut buf: Vec<u8> = Vec::new();
        write_newc_entry(&mut buf, "bin/bash", 0o100_755, b"BASH-EXEC");
        write_newc_entry(&mut buf, "usr/bin/python3", 0o120_777, b"python3.11");
        write_newc_entry(&mut buf, "TRAILER!!!", 0, &[]);

        // gzip the whole thing (the parser pulls through GzDecoder).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            use std::io::Write as _;
            let mut gz = GzEncoder::new(std::fs::File::create(tmp.path()).unwrap(), Compression::default());
            gz.write_all(&buf).unwrap();
            gz.finish().unwrap();
        }
        let entries = list_initramfs_paths(tmp.path()).unwrap();
        assert_eq!(entries.len(), 2, "got: {:?}", entries.keys().collect::<Vec<_>>());
        let bash = entries.get("bin/bash").expect("bash entry");
        assert_eq!(bash.mode & S_IFMT, 0o100_000);
        assert!(bash.symlink_target.is_none());
        let py = entries.get("usr/bin/python3").expect("python3 entry");
        assert_eq!(py.mode & S_IFMT, S_IFLNK);
        assert_eq!(py.symlink_target.as_deref(), Some("python3.11"));
    }

    fn write_newc_entry(buf: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
        let name_with_nul: Vec<u8> = name.bytes().chain([0u8]).collect();
        let namesize = name_with_nul.len() as u32;
        let filesize = data.len() as u32;

        buf.extend_from_slice(b"070701");
        buf.extend_from_slice(&hex8(0));         // c_ino
        buf.extend_from_slice(&hex8(mode));      // c_mode
        buf.extend_from_slice(&hex8(0));         // c_uid
        buf.extend_from_slice(&hex8(0));         // c_gid
        buf.extend_from_slice(&hex8(1));         // c_nlink
        buf.extend_from_slice(&hex8(0));         // c_mtime
        buf.extend_from_slice(&hex8(filesize));  // c_filesize
        buf.extend_from_slice(&hex8(0));         // c_devmajor
        buf.extend_from_slice(&hex8(0));         // c_devminor
        buf.extend_from_slice(&hex8(0));         // c_rdevmajor
        buf.extend_from_slice(&hex8(0));         // c_rdevminor
        buf.extend_from_slice(&hex8(namesize));  // c_namesize
        buf.extend_from_slice(&hex8(0));         // c_check
        buf.extend_from_slice(&name_with_nul);
        // 4-byte align (header + name).
        let header_and_name = 110 + namesize as usize;
        for _ in 0..pad_to_4(header_and_name) { buf.push(0); }
        buf.extend_from_slice(data);
        // 4-byte align (data).
        for _ in 0..pad_to_4(data.len()) { buf.push(0); }
    }

    fn hex8(v: u32) -> [u8; 8] {
        let s = format!("{v:08x}");
        let mut out = [0u8; 8];
        out.copy_from_slice(s.as_bytes());
        out
    }

    #[test]
    fn pad_to_4_table() {
        assert_eq!(pad_to_4(0),  0);
        assert_eq!(pad_to_4(1),  3);
        assert_eq!(pad_to_4(2),  2);
        assert_eq!(pad_to_4(3),  1);
        assert_eq!(pad_to_4(4),  0);
        assert_eq!(pad_to_4(5),  3);
        assert_eq!(pad_to_4(110), 2);
    }
}
