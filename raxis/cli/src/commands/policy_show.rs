//! `raxis policy show` — print the active policy bundle.
//!
//! Normative reference: cli-readonly.md §5.5.11.
//!
//! # Data sources (all read-only, no kernel IPC)
//!
//! * `<data_dir>/policy/policy.toml` — parsed and validated through
//!   `raxis_policy::load_policy`. We re-parse the file the kernel
//!   actually loaded; the SHA-256 in `views::policy_history` cross-
//!   checks that the on-disk bundle is the one the kernel committed.
//! * `<data_dir>/kernel.db` opened READ-ONLY via `raxis_store::open_ro`:
//!   - `views::policy_history::current_epoch` → epoch_id at HEAD.
//!   - `views::policy_history::list`         → optional `--history`.
//!
//! # Why we re-parse rather than dump the raw TOML bytes
//!
//! Two reasons:
//!
//!   1. **Correctness over fidelity.** A kernel that has rejected a
//!      malformed `policy.toml` will fail-close at boot; re-parsing
//!      surfaces the same `PolicyError` to the operator with the same
//!      diagnostic. Dumping raw bytes would print TOML the kernel
//!      cannot use.
//!   2. **Field redaction control.** The bundle's `signed_at`,
//!      `policy_sha256`, and the per-channel resolved targets are
//!      either computed or rewritten by `validate`; printing the
//!      validated form is what the operator actually needs to audit
//!      ("what did the kernel commit?").
//!
//! `--raw` dumps the on-disk `policy.toml` bytes verbatim — useful when
//! an operator wants to feed the active policy into `diff(1)` or pipe
//! it into another signing tool. The validated render is still the
//! default (it's what the kernel actually committed); `--raw` is the
//! opt-in for byte-fidelity workflows. Mutually exclusive with
//! `--json` and `--history`, both of which are about the *parsed*
//! projection of the bundle.
//!
//! # Exit code
//!
//! `0` on success; non-zero only when the bundle file or `kernel.db`
//! cannot be opened.

use std::io::Write;
use std::path::{Path, PathBuf};

use raxis_policy::{
    load_policy, GatewaySection, NotificationChannel, NotificationChannelKind, PolicyBundle,
};
use raxis_store::open_ro;
use raxis_store::views::policy_history;

use crate::errors::CliError;
use crate::operator_display::{format_operator_with_lookup, OperatorNameLookup};
use crate::GlobalFlags;

const POLICY_FILE_NAME: &str = "policy.toml";

// ────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    let policy_path = flags.data_dir().join("policy").join(POLICY_FILE_NAME);

    if opts.raw {
        // `--raw` is the byte-fidelity escape hatch — read the file
        // and pipe it to stdout untouched. We do NOT attempt to
        // parse or re-render: that's exactly what `--raw` is asking
        // us to skip. Combining it with `--json` or `--history`
        // would be nonsensical (both flags concern the parsed
        // projection); reject early with a clear Usage error.
        if opts.json || opts.with_history {
            return Err(CliError::Usage(
                "--raw is mutually exclusive with --json and --history \
                 (it dumps the on-disk policy.toml bytes verbatim, with \
                 no parsing or re-rendering)"
                    .to_owned(),
            ));
        }
        let bytes = std::fs::read(&policy_path).map_err(|e| CliError::Io {
            path: policy_path.display().to_string(),
            source: e,
        })?;
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        out.write_all(&bytes).map_err(|e| CliError::Io {
            path: "<stdout>".to_owned(),
            source: e,
        })?;
        out.flush().map_err(|e| CliError::Io {
            path: "<stdout>".to_owned(),
            source: e,
        })?;
        return Ok(());
    }

    let (bundle, _raw_bytes, on_disk_sha256) = load_policy(&policy_path).map_err(|e| {
        CliError::Policy(format!(
            "failed to load active policy from {:?}: {e}",
            policy_path,
        ))
    })?;

    // History lookup is best-effort. The CLI must not refuse to print
    // the active bundle just because kernel.db has not been opened
    // (e.g. the operator pointed --data-dir at a fresh genesis dir
    // before booting the kernel).
    let history_summary = read_history(flags, opts.with_history).ok();

    // Resolve fingerprints in the history rows to their current
    // display names per `kernel-store.md` §2.5.2 "Operator
    // display-name fields". `policy_epoch_history` only stores
    // the fingerprint of the triggering operator (no embedded
    // snapshot — pre-display-name plumbing); the renderer falls
    // back to a live `operator_certificates` lookup with the
    // historical-cert annotation when the row predates the
    // operator's current entry, and to the unknown-operator
    // annotation when the operator has been removed from policy
    // entirely. Cheap to load even when `--history` is off — the
    // empty-lookup branch returns immediately.
    let name_lookup = if opts.with_history {
        OperatorNameLookup::load_from_data_dir(flags.data_dir())
            .unwrap_or_else(|_| OperatorNameLookup::empty())
    } else {
        OperatorNameLookup::empty()
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    if opts.json {
        render_json(&mut out, &bundle, &on_disk_sha256, history_summary.as_ref());
    } else {
        render_human(
            &mut out,
            &bundle,
            &policy_path,
            &on_disk_sha256,
            history_summary.as_ref(),
            opts.with_history,
            &name_lookup,
        );
    }
    let _ = out.flush();
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Copy)]
struct PolicyShowOpts {
    json: bool,
    with_history: bool,
    raw: bool,
}

fn parse_args(args: &[String]) -> Result<PolicyShowOpts, CliError> {
    let mut opts = PolicyShowOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => opts.json = true,
            "--history" => opts.with_history = true,
            "--raw" => opts.raw = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown policy show flag: {other:?} \
                     (try --json, --history, --help)"
                )));
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn print_help() {
    println!(
        "raxis policy show — print the active policy bundle\n\
         \n\
         USAGE:\n\
         \traxis policy show [--json|--history|--raw]\n\
         \n\
         FLAGS:\n\
         \t--json      Emit one JSON object instead of human text.\n\
         \t--history   Append the policy_epoch_history table.\n\
         \t--raw       Dump <data_dir>/policy/policy.toml bytes verbatim\n\
         \t            (no parsing or re-rendering); mutually exclusive\n\
         \t            with --json and --history.\n\
         "
    );
}

// ────────────────────────────────────────────────────────────────────
// History lookup
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct HistorySummary {
    current_epoch: Option<u64>,
    rows: Vec<policy_history::PolicyEpochRow>,
}

fn read_history(flags: &GlobalFlags, with_full_list: bool) -> Result<HistorySummary, CliError> {
    let conn = open_ro(flags.data_dir())
        .map_err(|e| CliError::Policy(format!("kernel.db open failed: {e}")))?;
    let current_epoch = policy_history::current_epoch(&conn)
        .map_err(|e| CliError::Policy(format!("policy_history::current_epoch failed: {e}")))?;
    let rows = if with_full_list {
        // 1024 is comfortably more than any human-driven kernel will
        // ever rotate through; v2 may add paging once we ship a
        // long-running production environment.
        policy_history::list(&conn, /*limit=*/ 1024)
            .map_err(|e| CliError::Policy(format!("policy_history::list failed: {e}")))?
    } else {
        Vec::new()
    };
    Ok(HistorySummary {
        current_epoch,
        rows,
    })
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human
// ────────────────────────────────────────────────────────────────────

fn render_human<W: Write>(
    out: &mut W,
    bundle: &PolicyBundle,
    policy_path: &Path,
    on_disk_sha: &str,
    history: Option<&HistorySummary>,
    with_history: bool,
    name_lookup: &OperatorNameLookup,
) {
    let _ = writeln!(out, "Active policy:");
    let _ = writeln!(out, "  source:           {}", policy_path.display());
    let _ = writeln!(out, "  bundle_sha256:    {}", on_disk_sha);
    let _ = writeln!(out, "  bundle_signed_by: {}", bundle.signed_by());
    let _ = writeln!(out, "  bundle_epoch:     {}", bundle.epoch());

    match history {
        Some(h) => match h.current_epoch {
            Some(epoch) => {
                let _ = writeln!(out, "  kernel_epoch:     {epoch}");
                if epoch != bundle.epoch() {
                    let _ = writeln!(
                        out,
                        "  ⚠ DRIFT: bundle_epoch={} but kernel_epoch={} \
                         (kernel may need restart to load this bundle)",
                        bundle.epoch(),
                        epoch,
                    );
                }
            }
            None => {
                let _ = writeln!(out, "  kernel_epoch:     <kernel never bootstrapped>");
            }
        },
        None => {
            let _ = writeln!(out, "  kernel_epoch:     <kernel.db unavailable>");
        }
    }

    render_section_lanes(out, bundle);
    render_section_operators(out, bundle);
    render_section_gates(out, bundle);
    render_section_egress(out, bundle);
    render_section_gateway(out, bundle.gateway());
    render_section_providers(out, bundle);
    render_section_notifications(out, bundle);

    if with_history {
        if let Some(h) = history {
            render_section_history(out, &h.rows, name_lookup);
        }
    }
}

fn render_section_lanes<W: Write>(out: &mut W, bundle: &PolicyBundle) {
    let lanes = bundle.lanes();
    let _ = writeln!(out, "\nLanes ({n}):", n = lanes.len());
    for l in lanes {
        let _ = writeln!(
            out,
            "  - {id:<24} max_concurrent={mc:<3} priority={prio:<3} max_cost_per_epoch={mc2}",
            id = truncate(&l.lane_id, 24),
            mc = l.max_concurrent_tasks,
            prio = l.priority,
            mc2 = l.max_cost_per_epoch,
        );
    }
}

fn render_section_operators<W: Write>(out: &mut W, bundle: &PolicyBundle) {
    let ops = bundle.operators();
    let _ = writeln!(out, "\nOperators ({n}):", n = ops.len());
    for o in ops {
        let _ = writeln!(
            out,
            "  - {fp}  display={name:<24}  permitted_ops={count}",
            fp = truncate(&o.pubkey_fingerprint, 32),
            name = truncate(&o.display_name, 24),
            count = o.permitted_ops.len(),
        );
    }
}

fn render_section_gates<W: Write>(out: &mut W, bundle: &PolicyBundle) {
    let gates = bundle.gates();
    let _ = writeln!(out, "\nGates ({n}):", n = gates.len());
    for g in gates {
        let _ = writeln!(
            out,
            "  - {gt:<24} cmd={cmd}  wall={wall}s  mem={mem}B  network={net}",
            gt = truncate(&g.gate_type, 24),
            cmd = truncate(&g.verifier_command, 60),
            wall = g.max_wall_seconds,
            mem = g.max_memory_bytes,
            net = g.network_allowed,
        );
    }
}

fn render_section_egress<W: Write>(out: &mut W, bundle: &PolicyBundle) {
    let domains = bundle.egress_domains();
    let _ = writeln!(out, "\nEgress allowlist ({n}):", n = domains.len());
    for d in domains {
        let _ = writeln!(out, "  - {d}");
    }
}

fn render_section_gateway<W: Write>(out: &mut W, gw: Option<&GatewaySection>) {
    let _ = writeln!(out, "\nGateway:");
    match gw {
        None => {
            let _ = writeln!(
                out,
                "  (not configured — kernel runs with no inference / fetch)"
            );
        }
        Some(g) => {
            let _ = writeln!(out, "  binary_path:              {}", g.binary_path);
            let _ = writeln!(out, "  spawn_timeout_secs:       {}", g.spawn_timeout_secs);
            let _ = writeln!(out, "  respawn_backoff_ms:       {}", g.respawn_backoff_ms);
            let _ = writeln!(
                out,
                "  max_consecutive_respawns: {}",
                g.max_consecutive_respawns
            );
        }
    }
}

fn render_section_providers<W: Write>(out: &mut W, bundle: &PolicyBundle) {
    let providers = bundle.providers();
    let _ = writeln!(out, "\nProviders ({n}):", n = providers.len());
    for p in providers {
        let _ = writeln!(
            out,
            "  - {id:<24} kind={kind:<10} creds={creds:<32} \
             inf_to={inf}ms data_to={data}ms max_resp={mr}B",
            id = truncate(&p.provider_id, 24),
            kind = truncate(&p.kind, 10),
            creds = truncate(&p.credentials_file, 32),
            inf = p.inference_timeout_ms,
            data = p.data_fetch_timeout_ms,
            mr = p.max_response_bytes,
        );
    }
}

fn render_section_notifications<W: Write>(out: &mut W, bundle: &PolicyBundle) {
    let chans = bundle.notification_channels();
    let _ = writeln!(out, "\nNotification channels ({n}):", n = chans.len());
    for c in chans {
        let _ = writeln!(
            out,
            "  - {id:<16} kind={kind:<8} target={target}",
            id = truncate(&c.id, 16),
            kind = channel_kind_label(c.kind),
            target = truncate(&c.target, 80),
        );
    }
    let defaults = bundle.default_notification_channels();
    let _ = writeln!(out, "  default route channels: [{}]", defaults.join(", "),);
}

fn channel_kind_label(k: NotificationChannelKind) -> &'static str {
    match k {
        NotificationChannelKind::File => "File",
        NotificationChannelKind::Email => "Email",
        NotificationChannelKind::Sidecar => "Sidecar",
    }
}

fn render_section_history<W: Write>(
    out: &mut W,
    rows: &[policy_history::PolicyEpochRow],
    name_lookup: &OperatorNameLookup,
) {
    let _ = writeln!(
        out,
        "\nPolicy epoch history ({n} rows, newest first):",
        n = rows.len()
    );
    if rows.is_empty() {
        let _ = writeln!(out, "  (no rows)");
        return;
    }
    let _ = writeln!(
        out,
        "  {epoch:>5}  {sha:<16}  advanced_at  triggered_by",
        epoch = "epoch",
        sha = "sha256_prefix",
    );
    for r in rows {
        // §2.5.2 "Operator display-name fields" — the historical
        // row stores only the fingerprint (no embedded snapshot
        // because `policy_epoch_history` predates the
        // display-name plumbing). Resolve via the live cert
        // table; the renderer emits the historical-cert
        // annotation when the operator's current display_name is
        // shown for a row from a previous epoch (the cert may
        // have been re-installed with a different name since),
        // or the unknown-operator annotation when the operator
        // has been removed from policy entirely.
        let by = format_operator_with_lookup(&r.triggered_by_operator, None, name_lookup);
        let _ = writeln!(
            out,
            "  {epoch:>5}  {sha:<16}  {at:>11}  {by}",
            epoch = r.epoch_id,
            sha = truncate(&r.policy_sha256, 16),
            at = r.advanced_at,
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — JSON
// ────────────────────────────────────────────────────────────────────

fn render_json<W: Write>(
    out: &mut W,
    bundle: &PolicyBundle,
    on_disk: &str,
    history: Option<&HistorySummary>,
) {
    // Precompute every collection BEFORE the macro. The serde_json
    // `json!` macro is sensitive to inline blocks containing
    // `let` statements (it cannot match them as `expr` fragments),
    // so we keep each subtree as a plain expression.
    let lanes_v: Vec<serde_json::Value> = bundle
        .lanes()
        .iter()
        .map(|l| {
            serde_json::json!({
                "lane_id":              l.lane_id,
                "max_concurrent_tasks": l.max_concurrent_tasks,
                "max_cost_per_epoch":   l.max_cost_per_epoch,
                "priority":             l.priority,
            })
        })
        .collect();

    let ops_v: Vec<serde_json::Value> = bundle
        .operators()
        .iter()
        .map(|o| {
            serde_json::json!({
                "pubkey_fingerprint": o.pubkey_fingerprint,
                "display_name":       o.display_name,
                "permitted_ops":      o.permitted_ops,
            })
        })
        .collect();

    let gates_v: Vec<serde_json::Value> = bundle
        .gates()
        .iter()
        .map(|g| {
            serde_json::json!({
                "gate_type":        g.gate_type,
                "verifier_command": g.verifier_command,
                "max_wall_seconds": g.max_wall_seconds,
                "max_memory_bytes": g.max_memory_bytes,
                "network_allowed":  g.network_allowed,
            })
        })
        .collect();

    let gateway_v: serde_json::Value = match bundle.gateway() {
        Some(g) => serde_json::json!({
            "binary_path":              g.binary_path,
            "spawn_timeout_secs":       g.spawn_timeout_secs,
            "respawn_backoff_ms":       g.respawn_backoff_ms,
            "max_consecutive_respawns": g.max_consecutive_respawns,
        }),
        None => serde_json::Value::Null,
    };

    let providers_v: Vec<serde_json::Value> = bundle
        .providers()
        .iter()
        .map(|p| {
            serde_json::json!({
                "provider_id":           p.provider_id,
                "kind":                  p.kind,
                "credentials_file":      p.credentials_file,
                "inference_timeout_ms":  p.inference_timeout_ms,
                "data_fetch_timeout_ms": p.data_fetch_timeout_ms,
                "max_response_bytes":    p.max_response_bytes,
            })
        })
        .collect();

    let channels_v: Vec<serde_json::Value> = bundle
        .notification_channels()
        .iter()
        .map(channel_to_json)
        .collect();
    let default_channels_v: &[String] = bundle.default_notification_channels();

    let history_v: Vec<serde_json::Value> = history
        .map(|h| {
            h.rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "epoch_id":              r.epoch_id,
                        "policy_sha256":         r.policy_sha256,
                        "signed_by_authority":   r.signed_by_authority,
                        "triggered_by_operator": r.triggered_by_operator,
                        "advanced_at":           r.advanced_at,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let v = serde_json::json!({
        "bundle_sha256":    on_disk,
        "bundle_signed_by": bundle.signed_by(),
        "bundle_epoch":     bundle.epoch(),
        "kernel_epoch":     history.and_then(|h| h.current_epoch),
        "lanes":            lanes_v,
        "operators":        ops_v,
        "gates":            gates_v,
        "egress_domains":   bundle.egress_domains(),
        "gateway":          gateway_v,
        "providers":        providers_v,
        "notifications": {
            "channels":         channels_v,
            "default_channels": default_channels_v,
        },
        "policy_epoch_history": history_v,
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
}

fn channel_to_json(c: &NotificationChannel) -> serde_json::Value {
    serde_json::json!({
        "id":     c.id,
        "kind":   channel_kind_label(c.kind),
        "target": c.target,
    })
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

// We do not currently need an RAII PathBuf wrapper, but referencing
// PathBuf keeps the import obvious for future absolute-path
// resolution.
#[allow(dead_code)]
fn _ensure_pathbuf_in_scope() -> PathBuf {
    PathBuf::new()
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_defaults() {
        let o = parse_args(&[]).unwrap();
        assert!(!o.json);
        assert!(!o.with_history);
        assert!(!o.raw);
    }

    #[test]
    fn parse_args_accepts_combined_flags() {
        let o = parse_args(&["--json".to_owned(), "--history".to_owned()]).unwrap();
        assert!(o.json);
        assert!(o.with_history);
        assert!(!o.raw);
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(&["--bogus".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn run_raw_dumps_policy_file_bytes_verbatim() {
        // Seed a data_dir with a tiny bespoke policy.toml whose
        // bytes the run() loop must echo back unchanged. We verify
        // every-byte fidelity by including a comment + a trailing
        // newline that the validating loader would normalise away.
        let tmp = tempfile::TempDir::new().unwrap();
        let policy_dir = tmp.path().join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();
        let raw_bytes =
            b"# raxis policy show --raw fixture\n[meta]\nepoch = 7\n\n# trailing comment\n";
        std::fs::write(policy_dir.join("policy.toml"), raw_bytes).unwrap();

        // Spawn the CLI as a subprocess so we can inspect stdout
        // byte-for-byte. cargo's test binary doesn't currently
        // expose a stdout-capture handle for the command's own
        // Stdout lock, and the production code intentionally uses
        // std::io::stdout() so a unit-test that swaps it would be
        // exercising a different code path.
        //
        // Resolve the binary cargo just built. Walk up two levels
        // from the test executable to reach `target/debug/raxis`.
        let test_exe = std::env::current_exe().expect("test exe");
        let bin_dir = test_exe
            .parent()
            .expect("deps dir")
            .parent()
            .expect("debug dir");
        let raxis = bin_dir.join("raxis");
        assert!(
            raxis.exists(),
            "expected raxis binary at {}",
            raxis.display()
        );

        let out = std::process::Command::new(&raxis)
            .args([
                "--data-dir",
                tmp.path().to_str().unwrap(),
                "policy",
                "show",
                "--raw",
            ])
            .output()
            .expect("spawn raxis policy show --raw");
        assert!(
            out.status.success(),
            "raxis policy show --raw exited non-zero: {:?}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            out.stdout, raw_bytes,
            "stdout must be byte-for-byte identical to policy.toml"
        );
    }

    #[test]
    fn run_raw_rejects_combined_with_json_or_history() {
        let tmp = tempfile::TempDir::new().unwrap();
        let policy_dir = tmp.path().join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(policy_dir.join("policy.toml"), b"[meta]\nepoch = 1\n").unwrap();
        let flags = GlobalFlags {
            data_dir: tmp.path().to_path_buf(),
            socket_path: None,
            operator_key_path: None,
        };
        for combo in [
            vec!["--raw".to_owned(), "--json".to_owned()],
            vec!["--raw".to_owned(), "--history".to_owned()],
        ] {
            let err = run(&flags, &combo).unwrap_err();
            match err {
                CliError::Usage(msg) => {
                    assert!(msg.contains("mutually exclusive"), "got: {msg}");
                }
                other => panic!("expected Usage(mutually exclusive); got {other:?}"),
            }
        }
    }

    #[test]
    fn run_raw_returns_io_error_when_policy_file_missing() {
        // No policy.toml on disk → must surface a clean Io error
        // rather than panicking or fabricating bytes.
        let flags = GlobalFlags {
            data_dir: PathBuf::from("/nonexistent/raxis-policy-show-raw"),
            socket_path: None,
            operator_key_path: None,
        };
        let err = run(&flags, &["--raw".to_owned()]).unwrap_err();
        match err {
            CliError::Io { path, .. } => {
                assert!(path.contains("policy.toml"), "got path: {path}");
            }
            other => panic!("expected Io; got {other:?}"),
        }
    }

    #[test]
    fn truncate_short_strings_unchanged() {
        assert_eq!(truncate("abc", 5), "abc");
    }

    #[test]
    fn truncate_long_strings_get_ellipsised() {
        assert_eq!(truncate("abcdefghij", 5), "abcd…");
    }
}
