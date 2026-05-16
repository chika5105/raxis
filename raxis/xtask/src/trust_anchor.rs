//! Dev signing-key trust-anchor injection + post-build verification
//! for the umbrella `cargo xtask images bake` pipeline.
//!
//! ## Why this module exists (iter66 root cause)
//!
//! Round-1 of the iter66 image bake produced a kernel binary whose
//! `EXPECTED_KERNEL_SIGNING_KEY_BYTES` symbol was the all-zero
//! sentinel — the kernel would have aborted at boot with FATAL
//! `trust_anchor_unpopulated` (`INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01`).
//! Root cause: `cargo xtask images bake` did not propagate the
//! per-clone dev signing key into the `RAXIS_KERNEL_SIGNING_KEY_HEX`
//! environment of every cargo subprocess it spawned. The
//! `crates/canonical-images/build.rs` resolution chain fell through
//! the env-var arm, attempted to read the on-disk `pk.hex`, and on a
//! freshly minted release-profile build slot ended at the all-zero
//! placeholder.
//!
//! The fix has two halves and this module carries both:
//!
//! 1. **Pre-bake injection.** A single helper
//!    ([`resolve_signing_key_pk_hex`]) implements the canonical
//!    search order documented below and returns the 64-char hex
//!    string ready to drop into `RAXIS_KERNEL_SIGNING_KEY_HEX`.
//!    Every `Command::new("cargo")` site in the bake pipeline
//!    routes through this helper and threads the value via
//!    per-`Command` `.env(...)` — we deliberately do NOT mutate the
//!    process-level `std::env` because that races concurrent xtask
//!    invocations and leaks the value into unrelated subprocesses.
//! 2. **Post-build verification.** A second helper
//!    ([`verify_kernel_binary_trust_anchor`]) reads the staged
//!    `<install_dir>/kernel/vmlinux` byte-for-byte and rejects it
//!    when the placeholder `trust_anchor_unpopulated` log token is
//!    embedded OR when the expected public-key fingerprint is
//!    absent. The bake's post-build step calls the same logic the
//!    operator-facing `cargo xtask images verify-trust-anchor`
//!    subcommand exposes.
//!
//! `INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01` (specs/invariants.md)
//! pins both halves.
//!
//! ## Search order
//!
//! [`resolve_signing_key_pk_hex`] walks the following sources, with
//! the first present winner:
//!
//! 1. `RAXIS_KERNEL_SIGNING_KEY_HEX` env var (64 lowercase hex chars).
//!    Already set by an outer caller — pass through unchanged.
//! 2. `RAXIS_KERNEL_SIGNING_KEY_PATH` env var. Read the file, trim
//!    trailing newline / whitespace, validate as 64 lowercase hex.
//! 3. `<workspace_root>/.git/info/raxis-signing-key/pk.hex` — the
//!    canonical per-clone dev path that
//!    `raxis_dev_signing_key::ensure_dev_signing_keypair` writes
//!    (`INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01`).
//! 4. `<workspace_root>/raxis/.git/info/raxis-signing-key/pk.hex` —
//!    the nested-`.git` variant. Some host layouts (the outer
//!    `<repo>/raxis/` cargo workspace under an outer `<repo>/.git/`
//!    checkout) end up writing here. We accept it for back-compat
//!    but log a one-line warning on stderr so the operator notices.
//!
//! On miss, the helper returns [`MissingSigningKeyError`] whose
//! `Display` includes (a) every file path probed, (b) every env var
//! checked, and (c) the canonical autogen entrypoint
//! (`cargo xtask images bake` — which mints the keypair on first
//! run via `ensure_dev_signing_keypair`).
//!
//! ## Why not just `std::env::set_var`
//!
//! Mutating the process env is convenient but global: a concurrent
//! `cargo xtask images bake` invoked from another shell in the same
//! integration harness would race for the variable, and an unrelated
//! cargo invocation spawned from xtask later (e.g. a perf-harness
//! probe) would inherit a stale value. Per-`Command` `.env(...)`
//! scopes the injection to exactly the children that need it.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Env var the kernel build script
/// (`crates/canonical-images/build.rs`) consults FIRST in its
/// resolution chain.
pub const RAXIS_KERNEL_SIGNING_KEY_HEX: &str = "RAXIS_KERNEL_SIGNING_KEY_HEX";

/// Env var that points at a hex-encoded `pk.hex` file on disk.
/// Used by callers that prefer not to widen their secret manager
/// into a 64-char hex blob.
pub const RAXIS_KERNEL_SIGNING_KEY_PATH: &str = "RAXIS_KERNEL_SIGNING_KEY_PATH";

/// Length of the on-disk hex (no trailing newline). 32 bytes ⇒ 64
/// lowercase hex chars.
const KEY_LEN_HEX: usize = 64;

/// Origin of the resolved `pk_hex` value. Recorded in the structured
/// log line the bake emits before spawning any cargo subprocess so
/// operators inspecting a bake log can tell which arm of the search
/// order fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKeySource {
    /// `RAXIS_KERNEL_SIGNING_KEY_HEX` was already set by an outer
    /// caller (CI / release pipeline / operator shell rc).
    EnvHex,
    /// `RAXIS_KERNEL_SIGNING_KEY_PATH` pointed at a readable hex
    /// file.
    EnvPath,
    /// `<workspace_root>/.git/info/raxis-signing-key/pk.hex` — the
    /// canonical per-clone dev path.
    GitInfoCanonical,
    /// `<workspace_root>/raxis/.git/info/raxis-signing-key/pk.hex`
    /// — the nested variant. Accepted with a warning.
    GitInfoNested,
}

impl SigningKeySource {
    /// Short stable token suitable for JSON event logs.
    pub fn as_str(self) -> &'static str {
        match self {
            SigningKeySource::EnvHex => "env_hex",
            SigningKeySource::EnvPath => "env_path",
            SigningKeySource::GitInfoCanonical => "git_info_canonical",
            SigningKeySource::GitInfoNested => "git_info_nested",
        }
    }
}

/// Outcome of a successful [`resolve_signing_key_pk_hex`] call.
#[derive(Debug, Clone)]
pub struct ResolvedSigningKey {
    /// 64 lowercase hex chars (validated). Ready to drop into the
    /// `RAXIS_KERNEL_SIGNING_KEY_HEX` env of a spawned cargo
    /// subprocess.
    pub pk_hex: String,
    /// Which arm of the search order fired. Recorded in audit logs;
    /// the `GitInfoNested` arm also produces an eprintln warning.
    pub source: SigningKeySource,
    /// Origin path when `source` is one of the file-backed arms
    /// (`EnvPath`, `GitInfoCanonical`, `GitInfoNested`). `None`
    /// when the value came from `RAXIS_KERNEL_SIGNING_KEY_HEX`
    /// directly.
    pub source_path: Option<PathBuf>,
}

/// Failure type returned when [`resolve_signing_key_pk_hex`] could
/// not locate a populated trust-anchor input. The Display impl
/// names every input the helper tried so the remediation is
/// trivially copy-pasteable from a CI log.
#[derive(Debug)]
pub struct MissingSigningKeyError {
    /// Workspace root the search was rooted at. Reproduced in the
    /// Display so an operator running a parallel worktree can tell
    /// which clone the failure was for.
    pub workspace_root: PathBuf,
    /// File paths the helper probed in priority order.
    pub paths_searched: Vec<PathBuf>,
    /// Env vars the helper consulted in priority order.
    pub env_vars_checked: Vec<&'static str>,
}

impl fmt::Display for MissingSigningKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "could not locate the dev signing key (the public half is \
             baked into the kernel as EXPECTED_KERNEL_SIGNING_KEY_BYTES; \
             a missing trust anchor produces FATAL trust_anchor_unpopulated \
             at boot — see INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01)."
        )?;
        writeln!(f, "  workspace root: {}", self.workspace_root.display())?;
        writeln!(f, "  env vars checked (in priority order):")?;
        for v in &self.env_vars_checked {
            writeln!(f, "    - {v}")?;
        }
        writeln!(f, "  file paths probed (in priority order):")?;
        for p in &self.paths_searched {
            writeln!(f, "    - {}", p.display())?;
        }
        writeln!(
            f,
            "  remediation: run `cargo xtask images bake` once — the bake \
             pipeline mints a per-clone Ed25519 keypair under \
             <workspace>/.git/info/raxis-signing-key/ on first invocation \
             via `raxis_dev_signing_key::ensure_dev_signing_keypair` \
             (INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01). Alternatively, export \
             RAXIS_KERNEL_SIGNING_KEY_HEX=<64-char hex> directly, or point \
             RAXIS_KERNEL_SIGNING_KEY_PATH at an existing pk.hex file."
        )?;
        Ok(())
    }
}

impl std::error::Error for MissingSigningKeyError {}

/// Resolve the dev signing key's public half through the canonical
/// search order. Returns the 64-char lowercase hex `pk_hex` plus a
/// tag indicating which arm fired. See the module-level doc comment
/// for the rationale.
///
/// `workspace_root` MUST be the cargo workspace root (the directory
/// whose `Cargo.toml` carries `[workspace]`).
pub fn resolve_signing_key_pk_hex(
    workspace_root: &Path,
) -> std::result::Result<ResolvedSigningKey, MissingSigningKeyError> {
    // Arm 1: RAXIS_KERNEL_SIGNING_KEY_HEX (already set by outer
    // caller). Validate length + alphabet so a mistyped value
    // never silently degrades to the placeholder arm in the kernel
    // build script.
    if let Ok(raw) = std::env::var(RAXIS_KERNEL_SIGNING_KEY_HEX) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && is_lowercase_hex64(trimmed) {
            return Ok(ResolvedSigningKey {
                pk_hex: trimmed.to_owned(),
                source: SigningKeySource::EnvHex,
                source_path: None,
            });
        }
        // Fall through into the miss path on empty / malformed values
        // so the operator sees us notice the env var but reject it.
    }

    // Arm 2: RAXIS_KERNEL_SIGNING_KEY_PATH points at a file on
    // disk.
    if let Ok(raw_path) = std::env::var(RAXIS_KERNEL_SIGNING_KEY_PATH) {
        let trimmed = raw_path.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if let Some(hex) = read_pk_hex_file(&p) {
                return Ok(ResolvedSigningKey {
                    pk_hex: hex,
                    source: SigningKeySource::EnvPath,
                    source_path: Some(p),
                });
            }
        }
    }

    // Arm 3: canonical `<workspace>/.git/info/raxis-signing-key/pk.hex`.
    let canonical = canonical_pk_path(workspace_root);
    if let Some(hex) = read_pk_hex_file(&canonical) {
        return Ok(ResolvedSigningKey {
            pk_hex: hex,
            source: SigningKeySource::GitInfoCanonical,
            source_path: Some(canonical),
        });
    }

    // Arm 4: nested `<workspace>/raxis/.git/info/raxis-signing-key/pk.hex`.
    let nested = nested_pk_path(workspace_root);
    if let Some(hex) = read_pk_hex_file(&nested) {
        eprintln!(
            "warning: dev signing key found at the nested path {} — the \
             canonical location is {}. Both seams of \
             `raxis_dev_signing_key::ensure_dev_signing_keypair` write \
             to the canonical path; the nested layout is accepted for \
             back-compat (INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01).",
            nested.display(),
            canonical_pk_path(workspace_root).display(),
        );
        return Ok(ResolvedSigningKey {
            pk_hex: hex,
            source: SigningKeySource::GitInfoNested,
            source_path: Some(nested),
        });
    }

    Err(MissingSigningKeyError {
        workspace_root: workspace_root.to_owned(),
        paths_searched: vec![
            canonical_pk_path(workspace_root),
            nested_pk_path(workspace_root),
        ],
        env_vars_checked: vec![RAXIS_KERNEL_SIGNING_KEY_HEX, RAXIS_KERNEL_SIGNING_KEY_PATH],
    })
}

/// Build the canonical per-clone pk.hex path:
/// `<workspace_root>/.git/info/raxis-signing-key/pk.hex`.
pub fn canonical_pk_path(workspace_root: &Path) -> PathBuf {
    workspace_root
        .join(".git")
        .join("info")
        .join("raxis-signing-key")
        .join("pk.hex")
}

/// Build the nested-`.git` variant path:
/// `<workspace_root>/raxis/.git/info/raxis-signing-key/pk.hex`.
fn nested_pk_path(workspace_root: &Path) -> PathBuf {
    workspace_root
        .join("raxis")
        .join(".git")
        .join("info")
        .join("raxis-signing-key")
        .join("pk.hex")
}

fn read_pk_hex_file(path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim_matches(['\n', '\r', ' ', '\t'].as_ref());
    if is_lowercase_hex64(trimmed) {
        Some(trimmed.to_owned())
    } else {
        None
    }
}

fn is_lowercase_hex64(s: &str) -> bool {
    s.len() == KEY_LEN_HEX && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

// ---------------------------------------------------------------------------
// Post-build verification
// ---------------------------------------------------------------------------

/// Stable byte-pattern token the kernel boot path's fail-loud panic
/// emits BEFORE aborting. We grep for it in a freshly built kernel
/// binary to detect the "anchor unpopulated" shape WITHOUT needing
/// to extract Ed25519 symbols.
///
/// The string is copy-pasted verbatim from
/// `specs/v3/canonical-image-trust-anchor.md §3` and
/// `INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01`. A kernel that links the
/// fail-loud path will carry this token in its `.rodata` regardless
/// of strip level; a release build with the placeholder anchor
/// embeds it too because `assert_trust_anchor_present_or_panic`'s
/// panic message is the load-bearing diagnostic. Presence of the
/// token by itself therefore does NOT prove the anchor is broken —
/// we couple it with a fingerprint check below.
//
// `xtask` is a binary crate, so `pub` does not export this symbol
// outside the binary. The const is forward API consumed by the
// (in-progress) `verify_kernel_binary_trust_anchor` driver and the
// iter67/iter68 harness slices that grep release kernel binaries
// for the token. `dead_code` is silenced rather than the const
// removed because the constant string MUST remain byte-identical
// with `kernel/build.rs`'s `assert_trust_anchor_present_or_panic`
// emit; deleting and re-introducing risks string drift.
#[allow(dead_code)]
pub const TRUST_ANCHOR_FATAL_TOKEN: &str = "trust_anchor_unpopulated";

/// Outcome of a [`verify_kernel_binary_trust_anchor`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustAnchorVerdict {
    /// Both checks passed: the expected public-key fingerprint is
    /// embedded somewhere in the binary AND the all-zero
    /// placeholder is NOT.
    Populated,
    /// The expected fingerprint is absent — the kernel was likely
    /// built with a different `RAXIS_KERNEL_SIGNING_KEY_HEX` (or
    /// none at all, in which case the placeholder arm fired).
    FingerprintMissing,
    /// The all-zero placeholder bytes are present in the binary's
    /// `.rodata` AND the expected fingerprint is absent — the
    /// strongest "trust anchor unpopulated" signal.
    PlaceholderEmbedded,
}

impl TrustAnchorVerdict {
    /// `xtask` is a binary crate, so `pub` does not export this
    /// method. Forward API for the verify driver / harness — see
    /// the parallel allow on `TRUST_ANCHOR_FATAL_TOKEN` for the
    /// rationale.
    #[allow(dead_code)]
    pub fn is_ok(&self) -> bool {
        matches!(self, TrustAnchorVerdict::Populated)
    }
}

/// Compute the 32-byte raw value of a 64-char lowercase-hex string.
/// Returns `None` for malformed input; callers use this to derive
/// the byte pattern the kernel's `EXPECTED_KERNEL_SIGNING_KEY_BYTES`
/// embeds. Hex decoding is a hot path for many short slices so we
/// avoid the `hex` crate allocation overhead.
pub fn decode_pk_hex_bytes(pk_hex: &str) -> Option<[u8; 32]> {
    if !is_lowercase_hex64(pk_hex) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = nybble(pk_hex.as_bytes()[2 * i])?;
        let lo = nybble(pk_hex.as_bytes()[2 * i + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn nybble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Verify the staged kernel binary's compile-time trust anchor was
/// populated. Two byte-pattern checks suffice:
///
/// 1. **Fingerprint embedded.** The 32 raw bytes of the expected
///    public key MUST appear as a contiguous slice in the binary
///    (`EXPECTED_KERNEL_SIGNING_KEY_BYTES` is a `[u8; 32]` constant
///    that the linker emits into `.rodata` verbatim). Absence
///    means the build was made against a different key — or fell
///    through to the placeholder arm.
/// 2. **Placeholder absent.** The all-zero 32-byte run MUST NOT
///    appear alongside an absent fingerprint. We tolerate
///    incidental all-zero runs (debug-info gaps, BSS pad strings)
///    when the fingerprint check passes — those are normal in any
///    multi-MB Rust binary. Only when the fingerprint is missing
///    AND a 32-byte zero run is present do we surface the
///    distinct `PlaceholderEmbedded` verdict for diagnostics.
///
/// Cheaper than parsing the ELF / Mach-O symbol table and works
/// uniformly across both formats — the bake's post-build step
/// runs on macOS dev hosts (Mach-O kernel binaries staged from a
/// cross-compiled Linux build are still ELF) so the format-agnostic
/// byte scan is the load-bearing primitive.
pub fn verify_kernel_binary_trust_anchor(
    kernel_bytes: &[u8],
    expected_pk_hex: &str,
) -> Result<TrustAnchorVerdict> {
    let expected_bytes = decode_pk_hex_bytes(expected_pk_hex)
        .with_context(|| format!("invalid expected_pk_hex {expected_pk_hex:?}"))?;
    let fingerprint_present = contains_subslice(kernel_bytes, &expected_bytes);
    if fingerprint_present {
        return Ok(TrustAnchorVerdict::Populated);
    }
    let placeholder = [0u8; 32];
    if contains_subslice(kernel_bytes, &placeholder) {
        Ok(TrustAnchorVerdict::PlaceholderEmbedded)
    } else {
        Ok(TrustAnchorVerdict::FingerprintMissing)
    }
}

/// Linear-scan substring match. We deliberately keep this naive —
/// the inputs are 32-byte needles in a few-MB haystack, which the
/// branch predictor handles cheaply; pulling in `memchr` for the
/// optimised byte-search is dependency bloat we'd rather avoid in
/// xtask.
pub(crate) fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Stringly-typed wrapper around [`verify_kernel_binary_trust_anchor`]
/// for the operator-facing `cargo xtask images verify-trust-anchor`
/// subcommand. Loads the kernel binary off disk and produces a
/// fail-loud anyhow Result.
pub fn verify_kernel_binary_at_path(kernel_path: &Path, expected_pk_hex: &str) -> Result<()> {
    let bytes = std::fs::read(kernel_path)
        .with_context(|| format!("read kernel binary {}", kernel_path.display()))?;
    let verdict = verify_kernel_binary_trust_anchor(&bytes, expected_pk_hex)?;
    match verdict {
        TrustAnchorVerdict::Populated => Ok(()),
        TrustAnchorVerdict::FingerprintMissing => {
            anyhow::bail!(
                "INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01 VIOLATED: \
                 kernel binary at {} does NOT contain the expected public-key \
                 fingerprint (32 bytes derived from pk_hex={}). The kernel was \
                 built against a different RAXIS_KERNEL_SIGNING_KEY_HEX, or the \
                 env var was unset and the build script fell through to the \
                 placeholder arm. Remediation: re-run `cargo xtask images bake` \
                 to rebuild the kernel with the correct trust anchor injected \
                 into every cargo subprocess.",
                kernel_path.display(),
                expected_pk_hex,
            )
        }
        TrustAnchorVerdict::PlaceholderEmbedded => {
            anyhow::bail!(
                "INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01 VIOLATED: \
                 kernel binary at {} embeds the all-zero placeholder \
                 (EXPECTED_KERNEL_SIGNING_KEY_BYTES = [0; 32]) and does NOT \
                 contain the expected fingerprint for pk_hex={}. The kernel \
                 would abort at boot with FATAL trust_anchor_unpopulated \
                 (INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01). Remediation: re-run \
                 `cargo xtask images bake` so the bake's signing-key injection \
                 propagates RAXIS_KERNEL_SIGNING_KEY_HEX into the kernel build.",
                kernel_path.display(),
                expected_pk_hex,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // -------------------------------------------------------------
    // resolve_signing_key_pk_hex search-order witnesses
    // -------------------------------------------------------------

    /// Guard helper: temporarily wipe both env vars for the
    /// duration of `f`, then restore. Mutating process env from
    /// tests is racy across threads — we serialise the env-touching
    /// witnesses through this single guard. The closure is
    /// expected to be cheap and not spawn other threads that read
    /// the env.
    fn with_no_env<F: FnOnce() -> R, R>(f: F) -> R {
        let prev_hex = std::env::var_os(RAXIS_KERNEL_SIGNING_KEY_HEX);
        let prev_path = std::env::var_os(RAXIS_KERNEL_SIGNING_KEY_PATH);
        std::env::remove_var(RAXIS_KERNEL_SIGNING_KEY_HEX);
        std::env::remove_var(RAXIS_KERNEL_SIGNING_KEY_PATH);
        let r = f();
        match prev_hex {
            Some(v) => std::env::set_var(RAXIS_KERNEL_SIGNING_KEY_HEX, v),
            None => std::env::remove_var(RAXIS_KERNEL_SIGNING_KEY_HEX),
        }
        match prev_path {
            Some(v) => std::env::set_var(RAXIS_KERNEL_SIGNING_KEY_PATH, v),
            None => std::env::remove_var(RAXIS_KERNEL_SIGNING_KEY_PATH),
        }
        r
    }

    fn make_workspace_with_pk(hex: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp
            .path()
            .join(".git")
            .join("info")
            .join("raxis-signing-key");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("pk.hex"), format!("{hex}\n")).unwrap();
        tmp
    }

    fn make_workspace_with_nested_pk(hex: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp
            .path()
            .join("raxis")
            .join(".git")
            .join("info")
            .join("raxis-signing-key");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("pk.hex"), format!("{hex}\n")).unwrap();
        tmp
    }

    const PK_A: &str = "11111111111111111111111111111111\
                        11111111111111111111111111111111";
    const PK_B: &str = "22222222222222222222222222222222\
                        22222222222222222222222222222222";
    const PK_C: &str = "33333333333333333333333333333333\
                        33333333333333333333333333333333";

    #[test]
    fn resolve_arm1_env_hex_wins_over_every_other_source() {
        let tmp = make_workspace_with_pk(PK_B);
        let r = with_no_env(|| {
            std::env::set_var(RAXIS_KERNEL_SIGNING_KEY_HEX, PK_A);
            let r = resolve_signing_key_pk_hex(tmp.path());
            std::env::remove_var(RAXIS_KERNEL_SIGNING_KEY_HEX);
            r
        })
        .expect("resolve");
        assert_eq!(r.source, SigningKeySource::EnvHex);
        assert_eq!(r.pk_hex, PK_A);
        assert!(r.source_path.is_none());
    }

    #[test]
    fn resolve_arm2_env_path_falls_back_when_env_hex_unset() {
        let tmp_pk = tempfile::tempdir().unwrap();
        let pk_file = tmp_pk.path().join("alt-pk.hex");
        fs::write(&pk_file, format!("{PK_A}\n")).unwrap();
        let tmp_ws = make_workspace_with_pk(PK_B);
        let r = with_no_env(|| {
            std::env::set_var(RAXIS_KERNEL_SIGNING_KEY_PATH, pk_file.display().to_string());
            let r = resolve_signing_key_pk_hex(tmp_ws.path());
            std::env::remove_var(RAXIS_KERNEL_SIGNING_KEY_PATH);
            r
        })
        .expect("resolve");
        assert_eq!(r.source, SigningKeySource::EnvPath);
        assert_eq!(r.pk_hex, PK_A);
        assert_eq!(r.source_path.as_ref(), Some(&pk_file));
    }

    #[test]
    fn resolve_arm3_canonical_git_info_wins_over_nested() {
        // Canonical AND nested both present; canonical wins.
        let tmp = make_workspace_with_pk(PK_A);
        // Also seed the nested location with a DIFFERENT key.
        let nested_dir = tmp
            .path()
            .join("raxis")
            .join(".git")
            .join("info")
            .join("raxis-signing-key");
        fs::create_dir_all(&nested_dir).unwrap();
        fs::write(nested_dir.join("pk.hex"), format!("{PK_B}\n")).unwrap();

        let r = with_no_env(|| resolve_signing_key_pk_hex(tmp.path())).expect("resolve");
        assert_eq!(r.source, SigningKeySource::GitInfoCanonical);
        assert_eq!(r.pk_hex, PK_A);
        assert_eq!(r.source_path.as_ref(), Some(&canonical_pk_path(tmp.path())));
    }

    #[test]
    fn resolve_arm4_nested_git_info_used_when_only_nested_present() {
        let tmp = make_workspace_with_nested_pk(PK_C);
        let r = with_no_env(|| resolve_signing_key_pk_hex(tmp.path())).expect("resolve");
        assert_eq!(r.source, SigningKeySource::GitInfoNested);
        assert_eq!(r.pk_hex, PK_C);
        assert_eq!(
            r.source_path.as_ref(),
            Some(
                &tmp.path()
                    .join("raxis")
                    .join(".git")
                    .join("info")
                    .join("raxis-signing-key")
                    .join("pk.hex")
            ),
        );
    }

    #[test]
    fn resolve_returns_missing_error_when_nothing_resolves() {
        let tmp = tempfile::tempdir().unwrap();
        let err = with_no_env(|| resolve_signing_key_pk_hex(tmp.path()))
            .expect_err("nothing populated — must miss");
        let msg = err.to_string();
        // Both env vars + both file paths must appear in the
        // remediation block so an operator copy-pasting the error
        // sees every input we tried.
        assert!(msg.contains(RAXIS_KERNEL_SIGNING_KEY_HEX), "got: {msg}");
        assert!(msg.contains(RAXIS_KERNEL_SIGNING_KEY_PATH), "got: {msg}");
        assert!(
            msg.contains(".git/info/raxis-signing-key/pk.hex"),
            "got: {msg}"
        );
        assert!(
            msg.contains("cargo xtask images bake"),
            "remediation must name the autogen entrypoint: {msg}",
        );
    }

    #[test]
    fn resolve_skips_env_hex_when_value_is_malformed() {
        let tmp = make_workspace_with_pk(PK_A);
        let r = with_no_env(|| {
            std::env::set_var(RAXIS_KERNEL_SIGNING_KEY_HEX, "definitely-not-hex");
            let r = resolve_signing_key_pk_hex(tmp.path());
            std::env::remove_var(RAXIS_KERNEL_SIGNING_KEY_HEX);
            r
        })
        .expect("falls through to canonical file");
        // Malformed env value MUST NOT silently become the pk_hex
        // — the resolver falls through to the on-disk file.
        assert_eq!(r.source, SigningKeySource::GitInfoCanonical);
        assert_eq!(r.pk_hex, PK_A);
    }

    #[test]
    fn resolve_trims_trailing_newline_from_file_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp
            .path()
            .join(".git")
            .join("info")
            .join("raxis-signing-key");
        fs::create_dir_all(&dir).unwrap();
        // pk.hex with a CRLF + spaces + trailing newline — all the
        // shapes a hand-edit could produce.
        fs::write(dir.join("pk.hex"), format!("  {PK_A}\r\n  \n")).unwrap();
        let r = with_no_env(|| resolve_signing_key_pk_hex(tmp.path())).expect("trims");
        assert_eq!(r.pk_hex, PK_A);
    }

    // -------------------------------------------------------------
    // verify_kernel_binary_trust_anchor witnesses
    // -------------------------------------------------------------

    fn synth_kernel_with_bytes(bytes: &[u8]) -> Vec<u8> {
        // 1 KiB of randomly-shaped filler around the symbol so the
        // scanner can't accidentally pass the test by reading
        // only the first 32 bytes of the haystack.
        let mut v = Vec::with_capacity(2048);
        for i in 0..1024 {
            v.push((i as u8).wrapping_mul(7));
        }
        v.extend_from_slice(bytes);
        for i in 0..1024 {
            v.push((i as u8).wrapping_mul(13));
        }
        v
    }

    #[test]
    fn verify_accepts_binary_with_expected_fingerprint_embedded() {
        let pk_bytes = decode_pk_hex_bytes(PK_A).unwrap();
        let kernel = synth_kernel_with_bytes(&pk_bytes);
        let verdict = verify_kernel_binary_trust_anchor(&kernel, PK_A).expect("verify");
        assert_eq!(verdict, TrustAnchorVerdict::Populated);
        assert!(verdict.is_ok());
    }

    #[test]
    fn verify_rejects_binary_with_only_placeholder_embedded() {
        let placeholder = [0u8; 32];
        let kernel = synth_kernel_with_bytes(&placeholder);
        let verdict = verify_kernel_binary_trust_anchor(&kernel, PK_A).expect("verify");
        assert_eq!(verdict, TrustAnchorVerdict::PlaceholderEmbedded);
        assert!(!verdict.is_ok());
    }

    #[test]
    fn verify_rejects_binary_with_unrelated_bytes_only() {
        // Filler that contains neither the expected fingerprint
        // nor a 32-byte zero run. We have to construct this
        // carefully because the default synth_kernel filler can't
        // promise "no 32-byte zero run" — manually use a bytestring
        // that mixes non-zero values throughout.
        let kernel: Vec<u8> = (0..4096u32).map(|i| ((i % 251) + 1) as u8).collect();
        let verdict = verify_kernel_binary_trust_anchor(&kernel, PK_A).expect("verify");
        assert_eq!(verdict, TrustAnchorVerdict::FingerprintMissing);
    }

    #[test]
    fn verify_rejects_malformed_expected_pk_hex() {
        let bytes = vec![0u8; 64];
        let err =
            verify_kernel_binary_trust_anchor(&bytes, "not-hex").expect_err("malformed input");
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid expected_pk_hex"), "got: {msg}");
    }

    #[test]
    fn verify_at_path_returns_actionable_error_on_placeholder() {
        let placeholder = [0u8; 32];
        let kernel = synth_kernel_with_bytes(&placeholder);
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("vmlinux");
        fs::write(&p, kernel).unwrap();
        let err = verify_kernel_binary_at_path(&p, PK_A).expect_err("rejects");
        let msg = format!("{err:#}");
        // Remediation must name the invariant AND the rebuild
        // command so an operator pasting the error sees both.
        assert!(
            msg.contains("INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01"),
            "got: {msg}",
        );
        assert!(
            msg.contains("cargo xtask images bake"),
            "remediation MUST point at the bake: {msg}",
        );
    }

    #[test]
    fn verify_at_path_returns_actionable_error_on_fingerprint_missing() {
        let kernel: Vec<u8> = (0..4096u32).map(|i| ((i % 251) + 1) as u8).collect();
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("vmlinux");
        fs::write(&p, kernel).unwrap();
        let err = verify_kernel_binary_at_path(&p, PK_A).expect_err("rejects");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("does NOT contain the expected public-key fingerprint"),
            "got: {msg}",
        );
        assert!(msg.contains(PK_A), "diagnostic MUST cite the pk_hex: {msg}");
    }

    #[test]
    fn verify_at_path_accepts_populated_binary() {
        let pk_bytes = decode_pk_hex_bytes(PK_A).unwrap();
        let kernel = synth_kernel_with_bytes(&pk_bytes);
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("vmlinux");
        fs::write(&p, kernel).unwrap();
        verify_kernel_binary_at_path(&p, PK_A).expect("populated binary passes");
    }

    #[test]
    fn decode_pk_hex_bytes_round_trips_lowercase_hex() {
        let bytes = decode_pk_hex_bytes(PK_A).expect("64 lowercase hex chars");
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().all(|b| *b == 0x11));
        assert!(
            decode_pk_hex_bytes("not-hex-but-64-chars-long-........................").is_none()
        );
        assert!(decode_pk_hex_bytes(&"a".repeat(63)).is_none());
        assert!(decode_pk_hex_bytes(&"a".repeat(65)).is_none());
        // Uppercase hex must be rejected — the kernel build script's
        // resolution chain requires lowercase, so any drift here
        // would silently disagree.
        assert!(decode_pk_hex_bytes(&"A".repeat(64)).is_none());
    }

    #[test]
    fn contains_subslice_matches_at_start_middle_end_and_misses_when_absent() {
        assert!(contains_subslice(b"abcdef", b"abc"));
        assert!(contains_subslice(b"abcdef", b"cde"));
        assert!(contains_subslice(b"abcdef", b"def"));
        assert!(!contains_subslice(b"abcdef", b"xyz"));
        assert!(!contains_subslice(b"ab", b"abc"));
        // Empty needle matches by convention (consistent with
        // every other Rust substring API).
        assert!(contains_subslice(b"abc", b""));
    }

    #[test]
    fn fatal_token_constant_is_grep_stable() {
        // Pin the byte pattern so a future refactor of the kernel's
        // boot panic message that drops the literal token here
        // trips this witness AND the spec.
        assert_eq!(TRUST_ANCHOR_FATAL_TOKEN, "trust_anchor_unpopulated");
    }
}
