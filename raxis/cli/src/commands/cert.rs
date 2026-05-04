// raxis-cli::commands::cert — Operator-cert ceremony surface.
//
// Normative reference (forthcoming): cli-ceremony.md §4.4 "Certificate
// ceremony" + §4.5 "Cert lifecycle commands" (added in step 12 of the
// operator-cert feature).
//
// Six sub-commands, all local-only EXCEPT `list` (which opens the
// kernel.db read-only view):
//
//   raxis cert mint           — mint a new Standard cert
//   raxis cert mint-emergency — mint a new EmergencyRecovery cert
//   raxis cert show <path>    — pretty-print a cert file
//   raxis cert verify <path>  — structural + self-sig + status check
//   raxis cert list           — read installed certs from kernel.db
//   raxis cert install <cert> — embed a cert into a policy.toml entry
//
// All cert minting goes through the canonical signing input in
// `raxis_crypto::cert::cert_canonical_signing_input` so the kernel
// verifies the same byte-exact representation the CLI signs. The
// CLI's only added value is ergonomics + file I/O; the cert format
// + signing scheme are wholly owned by `raxis-types::operator_cert`
// and `raxis-crypto::cert`.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;

use raxis_crypto::cert::{
    cert_status, sign_cert, validate_cert_structurally, verify_cert_self_signature,
    CertError, CertStatus,
};
use raxis_types::operator_cert::{CertKind, OperatorCert};

use crate::errors::CliError;
use crate::GlobalFlags;

// ---------------------------------------------------------------------------
// Default expiry / window values — match the design defaults the user
// approved during the cert spec review:
//   not_after = now + 1 year, warn_window = 30 days, grace_window = 7 days.
// ---------------------------------------------------------------------------

pub const DEFAULT_VALIDITY_DAYS: u32 = 365;
pub const DEFAULT_WARN_DAYS:     u32 = 30;
pub const DEFAULT_GRACE_DAYS:    u32 = 7;
pub const SECS_PER_DAY:          i64 = 86_400;

// ---------------------------------------------------------------------------
// Subcommand dispatch
// ---------------------------------------------------------------------------

pub fn run_mint(flags: &GlobalFlags, args: &[String])           -> Result<(), CliError> { mint::run(flags, args, CertKind::Standard) }
pub fn run_mint_emergency(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> { mint::run(flags, args, CertKind::EmergencyRecovery) }
pub fn run_show(flags: &GlobalFlags, args: &[String])           -> Result<(), CliError> { show::run(flags, args) }
pub fn run_verify(flags: &GlobalFlags, args: &[String])         -> Result<(), CliError> { verify::run(flags, args) }
pub fn run_list(flags: &GlobalFlags, args: &[String])           -> Result<(), CliError> { list::run(flags, args) }
pub fn run_install(flags: &GlobalFlags, args: &[String])        -> Result<(), CliError> { install::run(flags, args) }

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn parse_u32(name: &str, raw: &str) -> Result<u32, CliError> {
    raw.parse::<u32>()
        .map_err(|e| CliError::Usage(format!("--{name} expects an unsigned integer; got {raw:?}: {e}")))
}

fn parse_i64(name: &str, raw: &str) -> Result<i64, CliError> {
    raw.parse::<i64>()
        .map_err(|e| CliError::Usage(format!("--{name} expects a signed integer; got {raw:?}: {e}")))
}

fn write_cert_toml(out: &Path, cert: &OperatorCert) -> Result<(), CliError> {
    let s = toml::to_string(cert)
        .map_err(|e| CliError::Key(format!("cert TOML serialise failed: {e}")))?;
    fs::write(out, s.as_bytes()).map_err(|e| CliError::Io {
        path: out.display().to_string(),
        source: e,
    })
}

fn read_cert_toml(path: &Path) -> Result<OperatorCert, CliError> {
    let s = fs::read_to_string(path).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    toml::from_str::<OperatorCert>(&s)
        .map_err(|e| CliError::Key(format!("cert {} parse failed: {e}", path.display())))
}

fn pubkey_hex_of(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

fn fingerprint_of(pubkey_hex: &str) -> Result<String, CliError> {
    let bytes = hex::decode(pubkey_hex)
        .map_err(|e| CliError::Key(format!("decode pubkey hex: {e}")))?;
    Ok(crate::conn::pubkey_fingerprint(&bytes))
}

/// Pretty-print a cert in two stable, grep-friendly columns. Used by
/// both `show` and `verify`. Field order is the same as the on-disk
/// TOML for human cross-reference.
fn render_cert_human(cert: &OperatorCert, fingerprint: &str, status: Option<&CertStatus>) -> String {
    let mut out = String::new();
    out.push_str(&format!("kind                    {}\n", cert.kind.as_str()));
    out.push_str(&format!("display_name            {}\n", cert.display_name));
    out.push_str(&format!("pubkey_hex              {}\n", cert.pubkey_hex));
    out.push_str(&format!("pubkey_fingerprint      {fingerprint}\n"));
    out.push_str(&format!("not_before              {}\n", cert.not_before));
    out.push_str(&format!("not_after               {}\n", cert.not_after));
    out.push_str(&format!("warn_before_expiry_days {}\n", cert.warn_before_expiry_days));
    out.push_str(&format!("grace_period_days       {}\n", cert.grace_period_days));
    out.push_str(&format!("permitted_ops           [{}]\n", cert.permitted_ops.join(", ")));
    out.push_str(&format!("contact_info            {}\n", cert.contact_info.as_deref().unwrap_or("")));
    out.push_str(&format!("self_sig_hex            {}\n", cert.self_sig_hex));
    if let Some(s) = status {
        out.push_str(&format!("status                  {}\n", s.tag()));
    }
    out
}

// ---------------------------------------------------------------------------
// `raxis cert mint` / `mint-emergency`
// ---------------------------------------------------------------------------

mod mint {
    use super::*;

    pub fn run(flags: &GlobalFlags, args: &[String], kind: CertKind) -> Result<(), CliError> {
        let mut key_path:     Option<PathBuf> = None;
        let mut display_name: Option<String>  = None;
        let mut out_path:     Option<PathBuf> = None;
        let mut validity_days = DEFAULT_VALIDITY_DAYS;
        let mut warn_days     = DEFAULT_WARN_DAYS;
        let mut grace_days    = DEFAULT_GRACE_DAYS;
        let mut not_before:   Option<i64>     = None;
        let mut permitted_ops: Vec<String>    = Vec::new();
        let mut contact_info: Option<String>  = None;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--key"            => { i += 1; key_path     = Some(PathBuf::from(arg(args, i, "--key")?)); }
                "--display-name"   => { i += 1; display_name = Some(arg(args, i, "--display-name")?.to_owned()); }
                "--out"            => { i += 1; out_path     = Some(PathBuf::from(arg(args, i, "--out")?)); }
                "--validity-days"  => { i += 1; validity_days = parse_u32("validity-days", arg(args, i, "--validity-days")?)?; }
                "--warn-days"      => { i += 1; warn_days     = parse_u32("warn-days", arg(args, i, "--warn-days")?)?; }
                "--grace-days"     => { i += 1; grace_days    = parse_u32("grace-days", arg(args, i, "--grace-days")?)?; }
                "--not-before"     => { i += 1; not_before    = Some(parse_i64("not-before", arg(args, i, "--not-before")?)?); }
                "--ops"            => { i += 1; permitted_ops = arg(args, i, "--ops")?.split(',').filter(|s| !s.is_empty()).map(str::to_owned).collect(); }
                "--contact"        => { i += 1; contact_info  = Some(arg(args, i, "--contact")?.to_owned()); }
                other              => return Err(CliError::Usage(format!("unknown cert mint flag: {other:?}"))),
            }
            i += 1;
        }

        let key_path = key_path
            .or_else(|| flags.operator_key_path.clone())
            .ok_or_else(|| CliError::Usage("cert mint requires --key <path> or --operator-key global flag".to_owned()))?;
        let display_name = display_name
            .ok_or_else(|| CliError::Usage("cert mint requires --display-name <name>".to_owned()))?;
        let out_path = out_path
            .ok_or_else(|| CliError::Usage("cert mint requires --out <path>".to_owned()))?;

        let signing_key = crate::signing::load_operator_key(&key_path)?;
        let pubkey_hex  = pubkey_hex_of(&signing_key);

        // ── Build the cert per kind ──────────────────────────────────
        let cert = match kind {
            CertKind::Standard => {
                if permitted_ops.is_empty() {
                    return Err(CliError::Usage(
                        "cert mint requires --ops <op,op,...> for Standard certs".to_owned(),
                    ));
                }
                let nb = not_before.unwrap_or_else(now_unix_secs);
                let na = nb + (validity_days as i64) * SECS_PER_DAY;
                let mut c = OperatorCert {
                    kind: CertKind::Standard,
                    display_name,
                    pubkey_hex,
                    not_before:              nb,
                    not_after:               na,
                    warn_before_expiry_days: warn_days,
                    grace_period_days:       grace_days,
                    permitted_ops,
                    contact_info,
                    self_sig_hex:            String::new(),
                };
                c.self_sig_hex = sign_cert(&c, &signing_key);
                c
            }
            CertKind::EmergencyRecovery => {
                // Structural pin: --ops, --validity-days, --warn-days,
                // --grace-days, --not-before are all IGNORED for emergency
                // certs (and any operator-supplied values would trip the
                // EmergencyHasWrongPermissions / EmergencyHasValidityWindow
                // checks at policy load). We surface a hint if the operator
                // tried to set them rather than silently dropping.
                if !permitted_ops.is_empty() && permitted_ops.as_slice() != ["RotateEpoch".to_owned()].as_slice() {
                    return Err(CliError::Usage(format!(
                        "cert mint-emergency rejects --ops other than 'RotateEpoch'; \
                         the kernel structurally pins emergency certs to ['RotateEpoch']. \
                         Got: {permitted_ops:?}"
                    )));
                }
                if not_before.is_some() {
                    return Err(CliError::Usage(
                        "cert mint-emergency rejects --not-before; emergency certs are always Active".to_owned(),
                    ));
                }
                let mut c = OperatorCert {
                    kind: CertKind::EmergencyRecovery,
                    display_name,
                    pubkey_hex,
                    not_before:              0,
                    not_after:               0,
                    warn_before_expiry_days: 0,
                    grace_period_days:       0,
                    permitted_ops:           vec!["RotateEpoch".to_owned()],
                    contact_info,
                    self_sig_hex:            String::new(),
                };
                c.self_sig_hex = sign_cert(&c, &signing_key);
                c
            }
        };

        // Self-validate before emit so we never write a known-broken
        // cert to disk. A failure here is a kernel bug — round-tripping
        // a freshly-minted cert MUST produce a structurally valid cert.
        let violations = validate_cert_structurally(&cert);
        if !violations.is_empty() {
            return Err(CliError::Key(format!(
                "internal: minted cert failed structural validation: {violations:?}"
            )));
        }
        if let Err(e) = verify_cert_self_signature(&cert) {
            return Err(CliError::Key(format!(
                "internal: minted cert failed self-sig check: {e}"
            )));
        }

        write_cert_toml(&out_path, &cert)?;
        let fp = fingerprint_of(&cert.pubkey_hex)?;
        println!("✓ Minted {} cert → {}", cert.kind.as_str(), out_path.display());
        println!("  pubkey_fingerprint  {fp}");
        if cert.kind == CertKind::Standard {
            println!("  not_before          {}", cert.not_before);
            println!("  not_after           {}", cert.not_after);
        }
        Ok(())
    }

    fn arg<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str, CliError> {
        args.get(i)
            .map(|s| s.as_str())
            .ok_or_else(|| CliError::Usage(format!("{flag} requires a value")))
    }
}

// ---------------------------------------------------------------------------
// `raxis cert show`
// ---------------------------------------------------------------------------

mod show {
    use super::*;

    pub fn run(_flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
        let mut path: Option<PathBuf> = None;
        let mut json = false;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--json" => { json = true; }
                a if !a.starts_with('-') && path.is_none() => {
                    path = Some(PathBuf::from(a));
                }
                other => return Err(CliError::Usage(format!("unknown cert show flag: {other:?}"))),
            }
            i += 1;
        }
        let path = path.ok_or_else(|| CliError::Usage("cert show requires <cert.toml>".to_owned()))?;
        let cert = read_cert_toml(&path)?;
        let fp = fingerprint_of(&cert.pubkey_hex)?;
        if json {
            let payload = serde_json::json!({
                "kind":                    cert.kind.as_str(),
                "display_name":            cert.display_name,
                "pubkey_hex":              cert.pubkey_hex,
                "pubkey_fingerprint":      fp,
                "not_before":              cert.not_before,
                "not_after":               cert.not_after,
                "warn_before_expiry_days": cert.warn_before_expiry_days,
                "grace_period_days":       cert.grace_period_days,
                "permitted_ops":           cert.permitted_ops,
                "contact_info":            cert.contact_info,
                "self_sig_hex":            cert.self_sig_hex,
            });
            println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        } else {
            print!("{}", render_cert_human(&cert, &fp, None));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// `raxis cert verify`
// ---------------------------------------------------------------------------

mod verify {
    use super::*;

    pub fn run(_flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
        let mut path: Option<PathBuf> = None;
        let mut at_time: Option<i64>  = None;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--at-time" => { i += 1; at_time = Some(parse_i64("at-time", args.get(i).map(|s| s.as_str()).unwrap_or(""))?); }
                a if !a.starts_with('-') && path.is_none() => { path = Some(PathBuf::from(a)); }
                other => return Err(CliError::Usage(format!("unknown cert verify flag: {other:?}"))),
            }
            i += 1;
        }
        let path = path.ok_or_else(|| CliError::Usage("cert verify requires <cert.toml>".to_owned()))?;
        let cert = read_cert_toml(&path)?;
        let fp = fingerprint_of(&cert.pubkey_hex)?;

        // Structural — collect ALL violations rather than short-circuit.
        let violations = validate_cert_structurally(&cert);

        // Self-signature.
        let sig_check: Result<(), CertError> = verify_cert_self_signature(&cert);

        // Status.
        let now = at_time.unwrap_or_else(now_unix_secs);
        let status = cert_status(&cert, now);

        // Emit human report (status first, then any errors).
        print!("{}", render_cert_human(&cert, &fp, Some(&status)));

        let mut had_error = false;
        if !violations.is_empty() {
            had_error = true;
            eprintln!("\nstructural violations:");
            for v in &violations {
                eprintln!("  - {v}");
            }
        }
        if let Err(e) = &sig_check {
            had_error = true;
            eprintln!("\nself-signature: FAILED ({e})");
        } else {
            println!("self-signature           OK");
        }

        if had_error {
            Err(CliError::Key("cert verification failed".to_owned()))
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// `raxis cert list` — read-only kernel.db query.
// ---------------------------------------------------------------------------

mod list {
    use super::*;

    pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
        let mut json = false;
        for a in args {
            match a.as_str() {
                "--json" => { json = true; }
                other   => return Err(CliError::Usage(format!("unknown cert list flag: {other:?}"))),
            }
        }
        // `flags.data_dir` is non-optional in the global parser — `main.rs`
        // derives a default from `RAXIS_DATA_DIR` / `$HOME/.raxis`.
        let db_path = flags.data_dir.join("kernel.db");
        let conn = raxis_store::open_ro(&db_path)
            .map_err(|e| CliError::Key(format!("open {} read-only: {e}", db_path.display())))?;
        let rows = raxis_store::views::operator_certificates::list_all(&conn)
            .map_err(|e| CliError::Key(format!("list operator_certificates: {e}")))?;

        let now = now_unix_secs();
        if json {
            let arr: Vec<_> = rows.iter().map(|r| {
                let cert = r.clone().into_operator_cert();
                let status = cert_status(&cert, now);
                serde_json::json!({
                    "pubkey_fingerprint": r.pubkey_fingerprint,
                    "epoch_id":           r.epoch_id,
                    "kind":               r.kind.as_str(),
                    "display_name":       r.display_name,
                    "not_before":         r.not_before,
                    "not_after":          r.not_after,
                    "permitted_ops":      r.permitted_ops,
                    "force_misconfig_bypass": r.force_misconfig_bypass,
                    "installed_at":       r.installed_at,
                    "status":             status.tag(),
                })
            }).collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
            return Ok(());
        }

        if rows.is_empty() {
            println!("No operator certificates installed (this is the legacy / cert-less flow).");
            return Ok(());
        }
        // Header row pinned to a fixed column shape for grep-friendly output.
        println!(
            "{:<32}  {:<8}  {:<18}  {:<24}  {:<10}",
            "pubkey_fingerprint", "epoch", "kind", "display_name", "status",
        );
        for r in &rows {
            let cert = r.clone().into_operator_cert();
            let status = cert_status(&cert, now);
            println!(
                "{:<32}  {:<8}  {:<18}  {:<24}  {:<10}",
                r.pubkey_fingerprint, r.epoch_id, r.kind.as_str(), r.display_name, status.tag(),
            );
        }
        Ok(())
    }

}

// ---------------------------------------------------------------------------
// `raxis cert install` — embed a cert into a policy.toml entry.
// ---------------------------------------------------------------------------
//
// Locates the [[operators.entries]] block whose `pubkey_hex` matches
// the cert and rewrites it with the embedded `[operators.entries.cert]`
// sub-table. We use the typed `toml::Table` editor (rather than string
// splicing) so the rewrite is byte-stable for any policy that the
// `toml` crate can round-trip.
//
// **Important contract:** `install` MUST be followed by `raxis policy
// sign` because rewriting the file invalidates the existing
// `policy.sig`. The CLI prints that hint in its success line.

mod install {
    use super::*;

    pub fn run(_flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
        let mut cert_path:  Option<PathBuf> = None;
        let mut policy_path: Option<PathBuf> = None;
        let mut force_misconfig = false;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--policy" => { i += 1; policy_path = Some(PathBuf::from(arg(args, i, "--policy")?)); }
                "--force-misconfig" => { force_misconfig = true; }
                a if !a.starts_with('-') && cert_path.is_none() => {
                    cert_path = Some(PathBuf::from(a));
                }
                other => return Err(CliError::Usage(format!("unknown cert install flag: {other:?}"))),
            }
            i += 1;
        }
        let cert_path = cert_path
            .ok_or_else(|| CliError::Usage("cert install requires <cert.toml>".to_owned()))?;
        let policy_path = policy_path
            .ok_or_else(|| CliError::Usage("cert install requires --policy <policy.toml>".to_owned()))?;

        let cert = read_cert_toml(&cert_path)?;

        // Re-verify before installing so a tampered/expired cert never
        // makes it into a policy artifact.
        let violations = validate_cert_structurally(&cert);
        verify_cert_self_signature(&cert)
            .map_err(|e| CliError::Key(format!("cert {} failed self-sig check: {e}", cert_path.display())))?;
        if !violations.is_empty() && !force_misconfig {
            let joined = violations.iter().map(|e| format!("  - {e}")).collect::<Vec<_>>().join("\n");
            return Err(CliError::Usage(format!(
                "cert {} has structural violations:\n{joined}\n\
                 Re-run with --force-misconfig to set force_misconfig_bypass = true on the entry \
                 (the bypass will surface in the audit chain at boot).",
                cert_path.display()
            )));
        }

        let policy_bytes = fs::read_to_string(&policy_path).map_err(|e| CliError::Io {
            path: policy_path.display().to_string(),
            source: e,
        })?;
        let mut doc = policy_bytes.parse::<toml::Value>()
            .map_err(|e| CliError::Key(format!("parse policy {}: {e}", policy_path.display())))?;

        let entries = doc
            .get_mut("operators")
            .and_then(|o| o.get_mut("entries"))
            .and_then(|e| e.as_array_mut())
            .ok_or_else(|| CliError::Usage(format!(
                "policy {} has no [[operators.entries]] block; run `raxis genesis` first",
                policy_path.display()
            )))?;

        let mut matched = false;
        for entry in entries.iter_mut() {
            let pubkey_hex = entry.get("pubkey_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if pubkey_hex.eq_ignore_ascii_case(&cert.pubkey_hex) {
                let table = entry.as_table_mut().ok_or_else(|| CliError::Key(
                    "[[operators.entries]] entry is not a TOML table".to_owned(),
                ))?;
                let cert_value = toml::Value::try_from(&cert)
                    .map_err(|e| CliError::Key(format!("serialise cert: {e}")))?;
                table.insert("cert".to_owned(), cert_value);
                if force_misconfig {
                    table.insert("force_misconfig_bypass".to_owned(), toml::Value::Boolean(true));
                }
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(CliError::Usage(format!(
                "no [[operators.entries]] in {} matches cert pubkey_hex {}; \
                 add the operator entry first via `raxis genesis --operator-pubkey ...`",
                policy_path.display(), cert.pubkey_hex
            )));
        }

        let new_bytes = toml::to_string(&doc)
            .map_err(|e| CliError::Key(format!("serialise updated policy: {e}")))?;
        fs::write(&policy_path, new_bytes.as_bytes()).map_err(|e| CliError::Io {
            path: policy_path.display().to_string(),
            source: e,
        })?;

        let fp = fingerprint_of(&cert.pubkey_hex)?;
        println!("✓ Installed cert into {}", policy_path.display());
        println!("  operator: {fp}  ({})", cert.display_name);
        println!("  reminder: re-sign the policy → `raxis policy sign {} --key <op_key>`", policy_path.display());
        if force_misconfig {
            println!("  reminder: --force-misconfig set → `raxis policy sign --force-misconfig` is required");
        }
        Ok(())
    }

    fn arg<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str, CliError> {
        args.get(i)
            .map(|s| s.as_str())
            .ok_or_else(|| CliError::Usage(format!("{flag} requires a value")))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_seed() -> [u8; 32] { [0x77u8; 32] }
    fn fixture_key() -> SigningKey { SigningKey::from_bytes(&fixture_seed()) }

    fn write_seed_key_file(dir: &Path) -> PathBuf {
        // `load_operator_key` accepts a 64-char hex seed as a test
        // convenience — see `signing.rs`. Use that to keep the fixture
        // self-contained without cargo-installing openssl.
        let path = dir.join("op_seed.hex");
        fs::write(&path, hex::encode(fixture_seed())).unwrap();
        path
    }

    fn make_args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn empty_flags() -> GlobalFlags {
        GlobalFlags {
            data_dir:          PathBuf::from("/tmp/raxis-cert-tests-unused"),
            socket_path:       None,
            operator_key_path: None,
        }
    }

    // ── mint Standard ──────────────────────────────────────────────

    #[test]
    fn mint_standard_writes_self_signed_cert_round_trippable() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_seed_key_file(dir.path());
        let out = dir.path().join("alice.cert.toml");
        let args = make_args(&[
            "--key", key.to_str().unwrap(),
            "--display-name", "Alice",
            "--out", out.to_str().unwrap(),
            "--ops", "CreateInitiative,ApprovePlan",
            "--validity-days", "30",
            "--warn-days", "5",
            "--grace-days", "2",
        ]);
        run_mint(&empty_flags(), &args).unwrap();
        let cert = read_cert_toml(&out).unwrap();

        assert_eq!(cert.kind,         CertKind::Standard);
        assert_eq!(cert.display_name, "Alice");
        assert_eq!(cert.pubkey_hex,   pubkey_hex_of(&fixture_key()));
        assert_eq!(cert.permitted_ops,
            vec!["CreateInitiative".to_owned(), "ApprovePlan".to_owned()]);
        assert_eq!(cert.warn_before_expiry_days, 5);
        assert_eq!(cert.grace_period_days,        2);
        assert_eq!(cert.not_after - cert.not_before, 30 * SECS_PER_DAY);

        verify_cert_self_signature(&cert).unwrap();
        assert!(validate_cert_structurally(&cert).is_empty());
    }

    // ── mint EmergencyRecovery ─────────────────────────────────────

    #[test]
    fn mint_emergency_pins_permitted_ops_and_zero_validity() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_seed_key_file(dir.path());
        let out = dir.path().join("emerg.cert.toml");
        let args = make_args(&[
            "--key", key.to_str().unwrap(),
            "--display-name", "break-glass",
            "--out", out.to_str().unwrap(),
        ]);
        run_mint_emergency(&empty_flags(), &args).unwrap();
        let cert = read_cert_toml(&out).unwrap();

        assert_eq!(cert.kind, CertKind::EmergencyRecovery);
        assert_eq!(cert.permitted_ops, vec!["RotateEpoch".to_owned()]);
        assert_eq!(cert.not_before, 0);
        assert_eq!(cert.not_after,  0);
        assert_eq!(cert.warn_before_expiry_days, 0);
        assert_eq!(cert.grace_period_days,        0);
        verify_cert_self_signature(&cert).unwrap();
        assert!(validate_cert_structurally(&cert).is_empty());
    }

    #[test]
    fn mint_emergency_rejects_extra_permissions_at_cli_layer() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_seed_key_file(dir.path());
        let out = dir.path().join("emerg.cert.toml");
        let args = make_args(&[
            "--key", key.to_str().unwrap(),
            "--display-name", "break-glass",
            "--out", out.to_str().unwrap(),
            "--ops", "RotateEpoch,CreateInitiative",
        ]);
        let err = run_mint_emergency(&empty_flags(), &args).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)),
            "expected Usage error for extra emergency ops; got {err:?}");
    }

    #[test]
    fn mint_emergency_rejects_not_before_override() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_seed_key_file(dir.path());
        let out = dir.path().join("emerg.cert.toml");
        let args = make_args(&[
            "--key", key.to_str().unwrap(),
            "--display-name", "break-glass",
            "--out", out.to_str().unwrap(),
            "--not-before", "1700000000",
        ]);
        let err = run_mint_emergency(&empty_flags(), &args).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    // ── mint Standard requires --ops ──────────────────────────────

    #[test]
    fn mint_standard_requires_ops_flag() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_seed_key_file(dir.path());
        let out = dir.path().join("alice.cert.toml");
        let args = make_args(&[
            "--key", key.to_str().unwrap(),
            "--display-name", "Alice",
            "--out", out.to_str().unwrap(),
        ]);
        let err = run_mint(&empty_flags(), &args).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    // ── verify ─────────────────────────────────────────────────────

    #[test]
    fn verify_passes_for_freshly_minted_standard_cert_at_now() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_seed_key_file(dir.path());
        let out = dir.path().join("alice.cert.toml");
        run_mint(&empty_flags(), &make_args(&[
            "--key", key.to_str().unwrap(),
            "--display-name", "Alice",
            "--out", out.to_str().unwrap(),
            "--ops", "AbortTask",
            "--validity-days", "365",
        ])).unwrap();

        run_verify(&empty_flags(), &make_args(&[out.to_str().unwrap()])).unwrap();
    }

    #[test]
    fn verify_fails_on_tampered_self_sig() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_seed_key_file(dir.path());
        let out = dir.path().join("alice.cert.toml");
        run_mint(&empty_flags(), &make_args(&[
            "--key", key.to_str().unwrap(),
            "--display-name", "Alice",
            "--out", out.to_str().unwrap(),
            "--ops", "AbortTask",
        ])).unwrap();
        // Flip a hex char in the self_sig and rewrite — verification
        // MUST fail.
        let mut cert = read_cert_toml(&out).unwrap();
        let mut chars: Vec<char> = cert.self_sig_hex.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        cert.self_sig_hex = chars.into_iter().collect();
        write_cert_toml(&out, &cert).unwrap();

        let err = run_verify(&empty_flags(), &make_args(&[out.to_str().unwrap()])).unwrap_err();
        assert!(matches!(err, CliError::Key(_)));
    }

    #[test]
    fn verify_at_time_after_not_after_reports_expired_or_grace() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_seed_key_file(dir.path());
        let out = dir.path().join("alice.cert.toml");
        // Mint a cert valid for 30 days from a fixed point in the past
        // so we have a deterministic not_after to step beyond.
        run_mint(&empty_flags(), &make_args(&[
            "--key", key.to_str().unwrap(),
            "--display-name", "Alice",
            "--out", out.to_str().unwrap(),
            "--ops", "AbortTask",
            "--validity-days", "30",
            "--warn-days", "5",
            "--grace-days", "2",
            "--not-before", "1700000000",
        ])).unwrap();

        // 1 year past not_after → Expired. `verify` exits non-zero
        // ONLY on structural / sig errors; status alone is
        // informational and does NOT fail the command (otherwise CI
        // pipelines that exercise expired-cert paths would always
        // be red).
        let way_after_grace = 1700000000 + 30 * SECS_PER_DAY + 365 * SECS_PER_DAY;
        let res = run_verify(&empty_flags(),
            &make_args(&[out.to_str().unwrap(), "--at-time", &way_after_grace.to_string()]));
        assert!(res.is_ok(),
            "verify must succeed even on expired certs (status is informational); got {res:?}");
    }

    // ── install ────────────────────────────────────────────────────

    #[test]
    fn install_embeds_cert_into_matching_operator_entry() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_seed_key_file(dir.path());
        let cert_path = dir.path().join("alice.cert.toml");
        let policy_path = dir.path().join("policy.toml");

        // Mint a cert.
        run_mint(&empty_flags(), &make_args(&[
            "--key", key.to_str().unwrap(),
            "--display-name", "Alice",
            "--out", cert_path.to_str().unwrap(),
            "--ops", "AbortTask",
        ])).unwrap();
        let cert = read_cert_toml(&cert_path).unwrap();
        let fp = fingerprint_of(&cert.pubkey_hex).unwrap();

        // Hand-build a minimal policy.toml with an entry that already
        // claims `cert.pubkey_hex` (no embedded cert yet — that's what
        // `install` adds).
        let policy_toml = format!(
            r#"
[[operators.entries]]
pubkey_fingerprint = "{fp}"
display_name       = "Alice"
pubkey_hex         = "{}"
permitted_ops      = ["AbortTask"]
"#,
            cert.pubkey_hex
        );
        fs::write(&policy_path, policy_toml).unwrap();

        run_install(&empty_flags(), &make_args(&[
            cert_path.to_str().unwrap(),
            "--policy", policy_path.to_str().unwrap(),
        ])).unwrap();

        let after = fs::read_to_string(&policy_path).unwrap();
        assert!(after.contains("[operators.entries.cert]"),
            "expected [operators.entries.cert] sub-table; got:\n{after}");
        assert!(after.contains("kind = \"Standard\""));
    }

    #[test]
    fn install_rejects_when_no_entry_matches_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_seed_key_file(dir.path());
        let cert_path = dir.path().join("alice.cert.toml");
        let policy_path = dir.path().join("policy.toml");

        run_mint(&empty_flags(), &make_args(&[
            "--key", key.to_str().unwrap(),
            "--display-name", "Alice",
            "--out", cert_path.to_str().unwrap(),
            "--ops", "AbortTask",
        ])).unwrap();

        // Policy with a totally different pubkey.
        let other_pubkey = "ff".repeat(32);
        let policy_toml = format!(
            r#"
[[operators.entries]]
pubkey_fingerprint = "{}"
display_name       = "Bob"
pubkey_hex         = "{other_pubkey}"
permitted_ops      = ["AbortTask"]
"#,
            "ee".repeat(16)
        );
        fs::write(&policy_path, policy_toml).unwrap();

        let err = run_install(&empty_flags(), &make_args(&[
            cert_path.to_str().unwrap(),
            "--policy", policy_path.to_str().unwrap(),
        ])).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    // ── show ───────────────────────────────────────────────────────

    #[test]
    fn show_does_not_error_for_a_valid_cert_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_seed_key_file(dir.path());
        let out = dir.path().join("alice.cert.toml");
        run_mint(&empty_flags(), &make_args(&[
            "--key", key.to_str().unwrap(),
            "--display-name", "Alice",
            "--out", out.to_str().unwrap(),
            "--ops", "AbortTask",
        ])).unwrap();

        run_show(&empty_flags(), &make_args(&[out.to_str().unwrap()])).unwrap();
        run_show(&empty_flags(), &make_args(&[out.to_str().unwrap(), "--json"])).unwrap();
    }
}
