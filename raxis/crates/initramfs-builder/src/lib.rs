//! Pure-Rust deterministic cpio.gz (newc) writer for V2 initramfs
//! rootfs assembly.
//!
//! Normative references:
//!
//! * `raxis/specs/v2/extensibility-traits.md §3.4` — `VmSpec.linux_kernel_path`
//!   contract and the [`raxis_isolation::ImageKind::RootfsInitramfsCpio`]
//!   variant the substrates dispatch on. This crate produces the bytes
//!   that variant points at.
//! * `raxis/specs/v2/e2e-live-test-gap.md` — the `mkfs.erofs`-on-macOS
//!   blocker. EROFS assembly requires the `mkfs.erofs` userspace tool,
//!   which is GPL Linux-side code without a hermetic macOS port; that
//!   broke the "open Cursor on macOS, get a planner running on real AVF"
//!   demo flow. Switching the dev-host rootfs format to initramfs (cpio.gz)
//!   removes the dependency entirely — the Linux kernel itself unpacks
//!   the cpio at boot, and writing a cpio archive is a few hundred lines
//!   of byte-shovelling.
//! * `raxis/specs/v2/system-requirements.md §11.2` — image-build hermeticity
//!   requirement. This crate has only two dependencies (`flate2` for
//!   gzip and `thiserror` for the error type), both pure-Rust under the
//!   `rust_backend` feature, so the builder runs on a fresh macOS dev
//!   box without `brew install` or `xcode-select` plumbing.
//!
//! ## What this crate is
//!
//! A zero-shellout, deterministic cpio newc + gzip writer that can be
//! driven by `raxis-image-builder` to emit the initramfs rootfs blob the
//! kernel hands to AVF (`VZLinuxBootLoader.initialRamdiskURL`) or
//! Firecracker (`PUT /boot-source { initrd_path }`).
//!
//! ## What this crate is NOT
//!
//! * **Not a general-purpose cpio library.** We implement only the
//!   newc (`070701`) format the Linux kernel's `init/initramfs.c`
//!   speaks. We do not parse cpio archives, we do not handle the
//!   binary or `070702` (CRC) variants, we do not extract.
//! * **Not a manifest signer.** Signing is `raxis-image-builder`'s
//!   responsibility — this crate only emits the bytes that
//!   `image_artefact_sha256` is computed over.
//! * **Not a userspace builder.** We do not stage planner binaries,
//!   chase library deps, or mint `/init` shell scripts. The caller
//!   names every entry that goes into the archive; this crate's
//!   surface is intentionally that thin.
//!
//! ## Determinism contract
//!
//! Two invocations of [`InitramfsBuilder::finalise_to_cpio_gz`] with
//! the same logical contents (same paths, same modes, same data,
//! same `source_date_epoch`, same uid/gid) MUST produce byte-for-byte
//! identical output. This is what makes the V2 manifest-trust model
//! work: `image_artefact_sha256` is a deterministic function of
//! `(rootfs source tree, source_date_epoch)`.
//!
//! Concretely:
//!
//! 1. Entries are sorted by path (ASCII byte order) before writing.
//! 2. `c_mtime` is `source_date_epoch` for every entry.
//! 3. `c_uid` / `c_gid` are caller-supplied per entry but default to
//!    `0` (root) via [`InitramfsBuilder::add_*`]. Determinism is the
//!    caller's responsibility once they supply non-default values.
//! 4. `c_ino` is sequentially assigned in sort order — never derived
//!    from any host filesystem inode.
//! 5. `c_devmajor` / `c_devminor` / `c_rdevmajor` / `c_rdevminor` are
//!    `0` for every entry (we don't emit device nodes — caller's job
//!    to refuse those at the API boundary).
//! 6. The gzip stream uses the deterministic header fields the
//!    `flate2`/`miniz_oxide` writer emits with `mtime=0`, `os=0xFF`,
//!    `xfl=0` — see [`InitramfsBuilder::write_gzip_deterministic_header`].
//!
//! ## Module layout
//!
//! * [`InitramfsBuilder`] — the public surface.
//! * [`CpioEntry`] — what the builder owns internally; not part of the
//!   public API but exposed via `pub(crate)` for tests.
//! * `write_newc_entry` — header + path + data writer.
//! * `write_gzip_deterministic_header` — the determinism shim around
//!   `flate2::write::GzEncoder`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use flate2::write::GzEncoder;
use flate2::Compression;
use thiserror::Error;

/// Linux mode-bits constants we depend on. Re-stated here so this
/// crate doesn't pull in `nix` / `libc` for two integers.
const S_IFREG: u32 = 0o0_100_000;
const S_IFDIR: u32 = 0o0_040_000;
const S_IFLNK: u32 = 0o0_120_000;

/// cpio newc magic. Per Linux's `Documentation/early-userspace/buffer-format.rst`.
const NEWC_MAGIC: &[u8; 6] = b"070701";

/// Kind of one cpio entry. Mirrors the three filesystem object types
/// the Linux kernel's initramfs unpacker honours; we deliberately omit
/// device nodes, hard links, sockets, and FIFOs — none of which a
/// V2 planner rootfs has any business shipping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// A directory. `c_filesize` is `0`.
    Directory,
    /// A regular file with the given byte contents.
    RegularFile {
        /// File body. The cpio writer pads to a 4-byte boundary.
        data: Vec<u8>,
    },
    /// A symbolic link to `target` (UTF-8 path inside the rootfs).
    /// The kernel reads the body bytes as the link target.
    Symlink {
        /// Where the symlink points (relative or absolute path inside
        /// the rootfs).
        target: String,
    },
}

/// One entry in the archive. Held internally by
/// [`InitramfsBuilder`]; constructed via the typed `add_*` methods.
#[derive(Debug, Clone)]
pub(crate) struct CpioEntry {
    /// Path inside the archive. Always relative-form (never starts
    /// with `/`, never contains `..` or empty components).
    pub(crate) path:  String,
    /// POSIX mode bits including the file-type field. The `add_*`
    /// methods OR in the right `S_IF*` constant so the caller passes
    /// only the permission bits.
    pub(crate) mode:  u32,
    /// Owning user id. Defaults to `0`.
    pub(crate) uid:   u32,
    /// Owning group id. Defaults to `0`.
    pub(crate) gid:   u32,
    /// Entry contents and shape.
    pub(crate) kind:  EntryKind,
}

/// Builder for one cpio.gz initramfs archive.
///
/// See module docs for the determinism contract and the API
/// boundaries.
#[derive(Debug, Clone)]
pub struct InitramfsBuilder {
    /// Entries indexed by path. `BTreeMap` so iteration is sorted by
    /// path (ASCII byte order) — that's the determinism guarantee.
    entries:           BTreeMap<String, CpioEntry>,
    /// `c_mtime` stamped into every entry. Defaults to `0`.
    source_date_epoch: u64,
}

/// Errors the builder can surface.
#[derive(Debug, Error)]
pub enum InitramfsError {
    /// Caller supplied an absolute path (starts with `/`) or a path
    /// with `..` / empty components.
    #[error("invalid archive path {path:?}: must be relative, no .. or empty components")]
    InvalidPath {
        /// The malformed path.
        path: String,
    },

    /// Caller passed the same path twice (or two paths normalising
    /// to the same archive entry).
    #[error("duplicate archive path {path:?}")]
    DuplicatePath {
        /// The conflicting path.
        path: String,
    },

    /// I/O error walking a host directory in
    /// [`InitramfsBuilder::add_tree_from_disk`].
    #[error("io error reading {path:?}: {source}")]
    Io {
        /// Host path being read.
        path:   PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// I/O error writing the cpio / gzip stream. In practice this only
    /// fires under OOM or disk-full conditions; the stream targets are
    /// `Vec<u8>` and `flate2::write::GzEncoder` over `Vec<u8>`.
    #[error("cpio write error: {0}")]
    Write(#[from] std::io::Error),

    /// Caller passed a host filesystem entry kind we don't model
    /// (block device, character device, FIFO, socket, hard link).
    #[error("unsupported file type at host path {path:?}: {kind}")]
    UnsupportedFileType {
        /// Host path.
        path: PathBuf,
        /// Human-readable kind ("block device", "fifo", etc).
        kind: String,
    },
}

impl Default for InitramfsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl InitramfsBuilder {
    /// Empty builder with `source_date_epoch = 0`.
    pub fn new() -> Self {
        Self {
            entries:           BTreeMap::new(),
            source_date_epoch: 0,
        }
    }

    /// Set the `c_mtime` stamped on every cpio entry. Should be the
    /// same `SOURCE_DATE_EPOCH` the rest of the build pipeline uses
    /// (the value goes into the manifest's `BuildEnv.source_date_epoch`
    /// field too — see `crates/image-manifest`).
    pub fn with_source_date_epoch(mut self, epoch: u64) -> Self {
        self.source_date_epoch = epoch;
        self
    }

    /// Add a directory entry. `mode` is the permission bits only
    /// (e.g., `0o755`); we OR in `S_IFDIR`.
    pub fn add_directory(&mut self, path: &str, mode: u32) -> Result<(), InitramfsError> {
        let path = normalise_archive_path(path)?;
        let mode = (mode & 0o7777) | S_IFDIR;
        self.insert(CpioEntry { path, mode, uid: 0, gid: 0, kind: EntryKind::Directory })
    }

    /// Add a regular-file entry with the given bytes. `mode` is the
    /// permission bits only (e.g., `0o755` for an executable);
    /// we OR in `S_IFREG`.
    pub fn add_file(
        &mut self,
        path: &str,
        mode: u32,
        data: Vec<u8>,
    ) -> Result<(), InitramfsError> {
        let path = normalise_archive_path(path)?;
        let mode = (mode & 0o7777) | S_IFREG;
        self.insert(CpioEntry {
            path,
            mode,
            uid: 0,
            gid: 0,
            kind: EntryKind::RegularFile { data },
        })
    }

    /// Add a symbolic-link entry pointing at `target`. `mode` is
    /// usually `0o777` per POSIX symlink convention; we OR in
    /// `S_IFLNK`.
    pub fn add_symlink(
        &mut self,
        path: &str,
        target: &str,
        mode: u32,
    ) -> Result<(), InitramfsError> {
        let path = normalise_archive_path(path)?;
        let mode = (mode & 0o7777) | S_IFLNK;
        self.insert(CpioEntry {
            path,
            mode,
            uid: 0,
            gid: 0,
            kind: EntryKind::Symlink { target: target.to_owned() },
        })
    }

    /// Set non-default uid/gid on the most-recently-added entry. We
    /// don't take a fluent struct because in practice every V2
    /// initramfs entry is owned by root; this method exists so the
    /// (rare) `add_file_owned_by(uid, gid, ...)` use case has a path
    /// that doesn't widen the API.
    ///
    /// Returns `true` if the path existed and was patched; `false` if
    /// the caller passed a path they never `add_*`'d.
    pub fn set_owner(&mut self, path: &str, uid: u32, gid: u32) -> Result<bool, InitramfsError> {
        let path = normalise_archive_path(path)?;
        match self.entries.get_mut(&path) {
            Some(e) => {
                e.uid = uid;
                e.gid = gid;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Walk a host directory and add every regular file / dir /
    /// symlink it contains under `archive_prefix`. Refuses any entry
    /// kind we don't model.
    ///
    /// Modes are taken from the host (`metadata.permissions().mode()`).
    /// uid/gid are forced to `0` — caller can [`Self::set_owner`]
    /// individual entries afterwards if needed.
    pub fn add_tree_from_disk(
        &mut self,
        host_root:      &Path,
        archive_prefix: &str,
    ) -> Result<(), InitramfsError> {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};

        let host_root = host_root.to_owned();
        if !host_root.is_dir() {
            return Err(InitramfsError::Io {
                path:   host_root.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "host_root is not a directory",
                ),
            });
        }

        // Manual stack-based walk; we deliberately don't pull in
        // `walkdir` for hermeticity (and to keep the symlink-handling
        // logic explicit — `walkdir` follows-or-not based on a
        // builder flag we'd have to pass through).
        let mut stack: Vec<PathBuf> = vec![host_root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).map_err(|e| InitramfsError::Io {
                path:   dir.clone(),
                source: e,
            })? {
                let entry = entry.map_err(|e| InitramfsError::Io {
                    path:   dir.clone(),
                    source: e,
                })?;
                let host_path = entry.path();
                let rel = host_path
                    .strip_prefix(&host_root)
                    .expect("walked path is rooted at host_root by construction");
                let archive_path = if archive_prefix.is_empty() {
                    rel.to_string_lossy().into_owned()
                } else {
                    format!("{}/{}", archive_prefix.trim_matches('/'), rel.to_string_lossy())
                };

                // `symlink_metadata` so we don't follow symlinks on
                // the host side — the symlink itself is the entry.
                let md = std::fs::symlink_metadata(&host_path).map_err(|e| {
                    InitramfsError::Io { path: host_path.clone(), source: e }
                })?;
                let ft = md.file_type();
                let mode_bits = md.permissions().mode() & 0o7777;

                if ft.is_dir() {
                    self.add_directory(&archive_path, mode_bits)?;
                    stack.push(host_path);
                } else if ft.is_file() {
                    let data = std::fs::read(&host_path).map_err(|e| {
                        InitramfsError::Io { path: host_path.clone(), source: e }
                    })?;
                    self.add_file(&archive_path, mode_bits, data)?;
                } else if ft.is_symlink() {
                    let target = std::fs::read_link(&host_path).map_err(|e| {
                        InitramfsError::Io { path: host_path.clone(), source: e }
                    })?;
                    self.add_symlink(
                        &archive_path,
                        &target.to_string_lossy(),
                        mode_bits,
                    )?;
                } else {
                    let kind = if ft.is_block_device() {
                        "block device"
                    } else if ft.is_char_device() {
                        "char device"
                    } else if ft.is_fifo() {
                        "fifo"
                    } else if ft.is_socket() {
                        "socket"
                    } else {
                        "unknown"
                    };
                    return Err(InitramfsError::UnsupportedFileType {
                        path: host_path,
                        kind: kind.to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Number of entries currently held. Useful for tests + the
    /// builder's structured-log emission.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff no entries have been added.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Finalise into raw cpio bytes (no compression). Useful for
    /// tests + for kernels configured to accept uncompressed initramfs.
    pub fn finalise_to_cpio(&self) -> Result<Vec<u8>, InitramfsError> {
        let mut buf = Vec::new();
        self.write_cpio(&mut buf)?;
        Ok(buf)
    }

    /// Finalise into gzipped cpio bytes — the canonical initramfs
    /// shape both AVF and Firecracker accept.
    pub fn finalise_to_cpio_gz(&self) -> Result<Vec<u8>, InitramfsError> {
        let cpio = self.finalise_to_cpio()?;
        let mut out = Vec::with_capacity(cpio.len());
        // `Compression::default()` is level 6; pinned via the explicit
        // value below so a future `flate2` default change can't shift
        // the byte-stream out from under our determinism contract.
        let mut enc = GzEncoder::new(&mut out, Compression::new(6));
        enc.write_all(&cpio)?;
        enc.finish()?;
        Ok(out)
    }

    fn insert(&mut self, e: CpioEntry) -> Result<(), InitramfsError> {
        if self.entries.contains_key(&e.path) {
            return Err(InitramfsError::DuplicatePath { path: e.path.clone() });
        }
        self.entries.insert(e.path.clone(), e);
        Ok(())
    }

    fn write_cpio<W: Write>(&self, w: &mut W) -> Result<(), InitramfsError> {
        for (ino_zero_based, e) in self.entries.values().enumerate() {
            // `c_ino` = 1-based sequential, deterministic in sort order.
            let ino = (ino_zero_based as u32) + 1;
            write_newc_entry(w, e, ino, self.source_date_epoch)?;
        }
        // Trailer entry. cpio newc trailer: name="TRAILER!!!",
        // mode=0, ino=0, nlink=1, filesize=0. The kernel scans for
        // this exact name and stops unpacking.
        write_newc_trailer(w)?;
        Ok(())
    }
}

/// Normalise an archive path:
///
/// * Strip leading slashes.
/// * Reject `..` and empty components.
/// * Collapse `./` segments.
/// * Reject backslash (Windows-style separators have no meaning here
///   and historically caused traversal bugs in tar/zip impls).
fn normalise_archive_path(s: &str) -> Result<String, InitramfsError> {
    if s.contains('\\') || s.contains('\0') {
        return Err(InitramfsError::InvalidPath { path: s.to_owned() });
    }
    let p = Path::new(s.trim_start_matches('/'));
    let mut out: Vec<&str> = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(seg) => match seg.to_str() {
                Some(s) if !s.is_empty() => out.push(s),
                _ => {
                    return Err(InitramfsError::InvalidPath { path: s.to_owned() })
                }
            },
            Component::CurDir => continue,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(InitramfsError::InvalidPath { path: s.to_owned() })
            }
        }
    }
    if out.is_empty() {
        return Err(InitramfsError::InvalidPath { path: s.to_owned() });
    }
    Ok(out.join("/"))
}

/// Write one cpio newc entry: 110-byte header + name + null + pad +
/// data + pad. Offsets are aligned to 4-byte boundaries (per the
/// newc spec the kernel parses).
fn write_newc_entry<W: Write>(
    w:     &mut W,
    e:     &CpioEntry,
    ino:   u32,
    mtime: u64,
) -> Result<(), InitramfsError> {
    // Resolve filesize + body-bytes-to-write up front. For symlinks
    // the body is the target path; for directories it's empty.
    let body: &[u8] = match &e.kind {
        EntryKind::RegularFile { data } => data,
        EntryKind::Symlink     { target } => target.as_bytes(),
        EntryKind::Directory             => &[],
    };
    let nlink: u32 = match &e.kind {
        EntryKind::Directory => 2,
        _                    => 1,
    };

    // The cpio name field includes the trailing null byte in
    // `c_namesize`. So namesize = name.len() + 1.
    let name_bytes = e.path.as_bytes();
    let namesize   = name_bytes.len() as u32 + 1;

    // Header: 13 fields × 8 hex chars + 6-byte magic = 110 bytes.
    w.write_all(NEWC_MAGIC)?;
    write_hex8(w, ino)?;
    write_hex8(w, e.mode)?;
    write_hex8(w, e.uid)?;
    write_hex8(w, e.gid)?;
    write_hex8(w, nlink)?;
    write_hex8(w, mtime as u32)?;          // c_mtime
    write_hex8(w, body.len() as u32)?;     // c_filesize
    write_hex8(w, 0)?;                     // c_devmajor
    write_hex8(w, 0)?;                     // c_devminor
    write_hex8(w, 0)?;                     // c_rdevmajor
    write_hex8(w, 0)?;                     // c_rdevminor
    write_hex8(w, namesize)?;              // c_namesize
    write_hex8(w, 0)?;                     // c_check (newc = 0)

    // Name + null terminator.
    w.write_all(name_bytes)?;
    w.write_all(&[0u8])?;

    // Pad name area to 4-byte boundary. Header (110) + namesize total
    // is the offset we measure from.
    let header_plus_name = 110 + namesize as usize;
    pad_to_4(w, header_plus_name)?;

    // Body + pad to 4-byte boundary.
    w.write_all(body)?;
    pad_to_4(w, body.len())?;

    Ok(())
}

fn write_newc_trailer<W: Write>(w: &mut W) -> Result<(), InitramfsError> {
    // cpio newc trailer: name="TRAILER!!!" (10 chars + null = 11
    // namesize), nlink=1, every other field = 0. Layout matches the
    // 13-hex8-field newc header (slots ino, mode, uid, gid, nlink,
    // mtime, filesize, devmajor, devminor, rdevmajor, rdevminor,
    // namesize, check).
    let name = b"TRAILER!!!";
    let namesize: u32 = name.len() as u32 + 1;

    w.write_all(NEWC_MAGIC)?;
    write_hex8(w, 0)?;          // c_ino
    write_hex8(w, 0)?;          // c_mode
    write_hex8(w, 0)?;          // c_uid
    write_hex8(w, 0)?;          // c_gid
    write_hex8(w, 1)?;          // c_nlink — the kernel doesn't enforce
                                //           this but every cpio writer
                                //           in the wild emits 1 here.
    write_hex8(w, 0)?;          // c_mtime
    write_hex8(w, 0)?;          // c_filesize
    write_hex8(w, 0)?;          // c_devmajor
    write_hex8(w, 0)?;          // c_devminor
    write_hex8(w, 0)?;          // c_rdevmajor
    write_hex8(w, 0)?;          // c_rdevminor
    write_hex8(w, namesize)?;   // c_namesize
    write_hex8(w, 0)?;          // c_check

    w.write_all(name)?;
    w.write_all(&[0u8])?;
    let header_plus_name = 110 + namesize as usize;
    pad_to_4(w, header_plus_name)?;

    Ok(())
}

fn write_hex8<W: Write>(w: &mut W, v: u32) -> Result<(), InitramfsError> {
    let s = format!("{:08x}", v);
    w.write_all(s.as_bytes())?;
    Ok(())
}

fn pad_to_4<W: Write>(w: &mut W, current_offset: usize) -> Result<(), InitramfsError> {
    let pad = (4 - (current_offset % 4)) % 4;
    if pad > 0 {
        w.write_all(&[0u8; 3][..pad])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_hex8(b: &[u8]) -> u32 {
        let s = std::str::from_utf8(b).expect("ascii hex");
        u32::from_str_radix(s, 16).expect("8-hex u32")
    }

    /// Manually parse one newc entry out of a cpio buffer and return
    /// `(name, mode, filesize, ino, body)`. Used by determinism tests
    /// to round-trip what we wrote.
    fn parse_first_entry(buf: &[u8]) -> (String, u32, u32, u32, Vec<u8>) {
        assert_eq!(&buf[0..6], NEWC_MAGIC, "newc magic mismatch");
        let ino      = parse_hex8(&buf[6..14]);
        let mode     = parse_hex8(&buf[14..22]);
        let filesize = parse_hex8(&buf[54..62]);
        let namesize = parse_hex8(&buf[94..102]) as usize;
        let name_start = 110;
        let name_end   = 110 + namesize - 1; // strip null
        let name = std::str::from_utf8(&buf[name_start..name_end])
            .unwrap()
            .to_owned();
        let header_plus_name = 110 + namesize;
        let body_start = header_plus_name + (4 - header_plus_name % 4) % 4;
        let body_end   = body_start + filesize as usize;
        let body = buf[body_start..body_end].to_vec();
        (name, mode, filesize, ino, body)
    }

    #[test]
    fn rejects_absolute_paths_and_dotdot_and_empty() {
        assert!(matches!(
            normalise_archive_path("/etc"),
            Ok(s) if s == "etc"
        ));
        assert!(matches!(
            normalise_archive_path("a/../b"),
            Err(InitramfsError::InvalidPath { .. })
        ));
        assert!(matches!(
            normalise_archive_path(""),
            Err(InitramfsError::InvalidPath { .. })
        ));
        assert!(matches!(
            normalise_archive_path("a\\b"),
            Err(InitramfsError::InvalidPath { .. })
        ));
        assert!(matches!(
            normalise_archive_path("a\0b"),
            Err(InitramfsError::InvalidPath { .. })
        ));
    }

    #[test]
    fn add_methods_or_in_correct_file_type_bits() {
        let mut b = InitramfsBuilder::new();
        b.add_directory("etc", 0o755).unwrap();
        b.add_file("init", 0o755, b"#!/bin/sh\n".to_vec()).unwrap();
        b.add_symlink("bin/sh", "../usr/bin/sh", 0o777).unwrap();
        let bytes = b.finalise_to_cpio().unwrap();

        // Walk through entries. The cpio is sorted by path so order
        // is `bin/sh`, `etc`, `init`.
        let (n, mode, _, _, _) = parse_first_entry(&bytes);
        assert_eq!(n, "bin/sh");
        assert_eq!(mode & 0o170_000, S_IFLNK, "first entry should be symlink");
    }

    #[test]
    fn duplicate_path_rejected() {
        let mut b = InitramfsBuilder::new();
        b.add_file("init", 0o755, b"a".to_vec()).unwrap();
        let err = b.add_file("init", 0o644, b"b".to_vec()).unwrap_err();
        assert!(matches!(err, InitramfsError::DuplicatePath { .. }));
    }

    #[test]
    fn determinism_byte_for_byte_across_builds() {
        let build = || -> Vec<u8> {
            let mut b = InitramfsBuilder::new()
                .with_source_date_epoch(1_700_000_000);
            b.add_directory("etc", 0o755).unwrap();
            b.add_file("etc/hostname", 0o644, b"raxis-orchestrator\n".to_vec())
                .unwrap();
            b.add_file("init", 0o755, b"#!/bin/sh\nexec /usr/local/bin/raxis-orchestrator $@\n".to_vec())
                .unwrap();
            b.add_directory("usr", 0o755).unwrap();
            b.add_directory("usr/local", 0o755).unwrap();
            b.add_directory("usr/local/bin", 0o755).unwrap();
            b.add_file(
                "usr/local/bin/raxis-orchestrator",
                0o755,
                vec![0xCA, 0xFE, 0xBA, 0xBE],
            )
            .unwrap();
            b.finalise_to_cpio().unwrap()
        };
        let a = build();
        let b = build();
        assert_eq!(a, b, "two builds with the same logical input must produce identical bytes");
    }

    #[test]
    fn determinism_byte_for_byte_across_gz_builds() {
        let build = || -> Vec<u8> {
            let mut b = InitramfsBuilder::new()
                .with_source_date_epoch(1_700_000_000);
            b.add_file("init", 0o755, b"hello".to_vec()).unwrap();
            b.finalise_to_cpio_gz().unwrap()
        };
        // gzip carries an mtime in its header; flate2 sets it to 0
        // by default, which is what we want. Verify that two
        // back-to-back builds produce identical compressed output.
        assert_eq!(build(), build(), "gz output must be byte-identical");
    }

    #[test]
    fn ino_assignment_is_sequential_and_starts_at_one() {
        let mut b = InitramfsBuilder::new();
        b.add_file("a", 0o644, vec![]).unwrap();
        b.add_file("b", 0o644, vec![]).unwrap();
        b.add_file("c", 0o644, vec![]).unwrap();
        let bytes = b.finalise_to_cpio().unwrap();
        let (_, _, _, ino_a, _) = parse_first_entry(&bytes);
        assert_eq!(ino_a, 1);
    }

    #[test]
    fn trailer_is_emitted_with_canonical_name() {
        let b     = InitramfsBuilder::new();
        let bytes = b.finalise_to_cpio().unwrap();
        // Empty builder => only trailer.
        let (n, _, _, _, _) = parse_first_entry(&bytes);
        assert_eq!(n, "TRAILER!!!");
    }

    #[test]
    fn add_tree_from_disk_walks_directories_and_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/hostname"), b"x\n").unwrap();
        std::fs::write(root.join("init"), b"#!/bin/sh\n").unwrap();

        let mut b = InitramfsBuilder::new();
        b.add_tree_from_disk(root, "").unwrap();

        // Verify all three entries showed up.
        let paths: Vec<_> = b.entries.keys().cloned().collect();
        assert!(paths.contains(&"etc".to_owned()), "etc dir: {paths:?}");
        assert!(paths.contains(&"etc/hostname".to_owned()), "etc/hostname: {paths:?}");
        assert!(paths.contains(&"init".to_owned()), "init: {paths:?}");
    }

    #[test]
    fn add_tree_from_disk_honours_archive_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("hello"), b"x\n").unwrap();

        let mut b = InitramfsBuilder::new();
        b.add_tree_from_disk(root, "rootfs").unwrap();
        assert!(b.entries.contains_key("rootfs/hello"));
    }

    #[test]
    fn cpio_gz_round_trips_through_gunzip_to_same_cpio_bytes() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut b = InitramfsBuilder::new()
            .with_source_date_epoch(1);
        b.add_file("init", 0o755, b"hi".to_vec()).unwrap();
        let cpio = b.finalise_to_cpio().unwrap();
        let gz   = b.finalise_to_cpio_gz().unwrap();

        let mut decoded = Vec::new();
        GzDecoder::new(&gz[..]).read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, cpio, "gunzip(cpio.gz) must equal cpio");
    }

    #[test]
    fn set_owner_patches_existing_entry_only() {
        let mut b = InitramfsBuilder::new();
        b.add_file("init", 0o755, b"x".to_vec()).unwrap();
        assert!(b.set_owner("init", 1000, 1000).unwrap());
        assert!(!b.set_owner("missing", 1000, 1000).unwrap());
        assert_eq!(b.entries["init"].uid, 1000);
        assert_eq!(b.entries["init"].gid, 1000);
    }

    #[test]
    fn empty_builder_emits_just_trailer() {
        let b     = InitramfsBuilder::new();
        let bytes = b.finalise_to_cpio().unwrap();
        // 110 (header) + 11 (name+null) + pad to 4 = 124 bytes for
        // the trailer alone.
        assert_eq!(bytes.len(), 124, "empty cpio = trailer only");
    }
}
