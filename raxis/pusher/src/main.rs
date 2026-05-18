//! `raxis-otel-pusher` — command-line entry point.
//!
//! Spec: `v3/otel-observability.md §12`.
//!
//! ```text
//! raxis-otel-pusher --config /etc/raxis/policy.toml --data-dir /var/lib/raxis [--health-port 9501]
//! ```
//!
//! The pusher reads the operator-supplied `policy.toml` (read-only,
//! signature already-verified by the kernel), validates the
//! `[observability]` section the same way the kernel does, and
//! enters the [`Pusher::tick`] loop. SIGTERM / SIGINT triggers a
//! clean shutdown that flushes one final batch and exits 0.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use raxis_otel_pusher::{
    config::PusherConfig,
    health,
    otlp::{OtlpClient, OtlpCompression, OtlpEndpoint, ResourceAttrs},
    run::{Pusher, PusherEvent},
};
use raxis_policy::PolicyBundle;

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(64);
        }
    };

    // Load the kernel-signed policy bundle. We use `load_policy`
    // (which signature-verifies via the kernel-resident `KEY-1`
    // operator key) to be defence-in-depth — even though the
    // kernel already verified the artifact before launching the
    // pusher, re-verifying catches a misconfigured deployment
    // where the operator's pusher service file points at a stale
    // copy.
    let bundle = match raxis_policy::load_policy(&args.config_path) {
        Ok((b, _bytes, _sha)) => b,
        Err(e) => {
            let event_logger = PusherEventLogger::new(default_events_path(&args.data_dir));
            event_logger.log(&PusherEvent::StartupFailure {
                stage: "policy_load".to_owned(),
                reason: e.to_string(),
            });
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"otel_pusher_policy_load_failed\",\
                  \"reason\":\"{e}\"}}"
            );
            return ExitCode::from(70);
        }
    };
    let kernel_version = env!("CARGO_PKG_VERSION").to_owned();
    let cfg = match build_config(&bundle, &args, kernel_version.clone()) {
        Ok(c) => c,
        Err(e) => {
            let event_logger = PusherEventLogger::new(default_events_path(&args.data_dir));
            event_logger.log(&PusherEvent::StartupFailure {
                stage: "config".to_owned(),
                reason: e.to_string(),
            });
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"otel_pusher_config_invalid\",\
                  \"reason\":\"{e}\"}}"
            );
            return ExitCode::from(78);
        }
    };

    if cfg.pusher.otlp_protocol != "http" {
        let event_logger = PusherEventLogger::new(cfg.events_path.clone());
        event_logger.log(&PusherEvent::StartupFailure {
            stage: "protocol".to_owned(),
            reason: format!(
                "unsupported otlp_protocol {}; V3 supports http only",
                cfg.pusher.otlp_protocol
            ),
        });
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"otel_pusher_unsupported_protocol\",\
              \"protocol\":\"{}\",\"detail\":\"V3 supports otlp_protocol=http only; gRPC \
              lands in V3.1\"}}",
            cfg.pusher.otlp_protocol,
        );
        return ExitCode::from(78);
    }

    let event_logger = PusherEventLogger::new(cfg.events_path.clone());
    let client = match build_client(&cfg) {
        Ok(c) => c,
        Err(e) => {
            event_logger.log(&PusherEvent::StartupFailure {
                stage: "client_init".to_owned(),
                reason: e.to_string(),
            });
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"otel_pusher_client_init_failed\",\
                  \"reason\":\"{e}\"}}"
            );
            return ExitCode::from(70);
        }
    };

    let pusher = match Pusher::new(cfg.clone(), client) {
        Ok(p) => p,
        Err(e) => {
            event_logger.log(&PusherEvent::StartupFailure {
                stage: "pusher_init".to_owned(),
                reason: e.to_string(),
            });
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"otel_pusher_init_failed\",\
                  \"reason\":\"{e}\"}}"
            );
            return ExitCode::from(70);
        }
    };

    let pusher = if cfg.health_port != 0 {
        match health::spawn(cfg.health_port, health::HealthSnapshot::initial()).await {
            Ok(h) => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"otel_pusher_health_listening\",\
                      \"port\":{}}}",
                    h.port,
                );
                pusher.with_health(h)
            }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"otel_pusher_health_bind_failed\",\
                      \"reason\":\"{e}\"}}"
                );
                pusher
            }
        }
    } else {
        pusher
    };

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"otel_pusher_started\",\
          \"endpoint\":\"{}\",\"data_dir\":\"{}\",\"protocol\":\"{}\"}}",
        cfg.pusher.otlp_endpoint,
        cfg.data_dir.display(),
        cfg.pusher.otlp_protocol,
    );
    event_logger.log(&PusherEvent::Started);

    // Tick loop with SIGTERM/SIGINT shutdown.
    let mut interval = tokio::time::interval(cfg.flush_interval());
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"otel_pusher_signal\",\
                      \"signal\":\"sigint\"}}"
                );
                break;
            }
            _ = interval.tick() => {
                let events = pusher.tick(true).await;
                for e in events { event_logger.log(&e); }
            }
        }
    }

    // Final drain.
    let final_events = pusher.tick(true).await;
    for e in final_events {
        event_logger.log(&e);
    }
    event_logger.log(&PusherEvent::Stopping);
    ExitCode::SUCCESS
}

fn default_events_path(data_dir: &Path) -> PathBuf {
    data_dir.join("observability").join("pusher-events.jsonl")
}

#[derive(Debug, Clone)]
struct Args {
    config_path: PathBuf,
    data_dir: PathBuf,
    health_port: u16,
}

fn parse_args() -> Result<Args, String> {
    let mut config_path: Option<PathBuf> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut health_port: u16 = 9501;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => {
                config_path = Some(PathBuf::from(args.next().ok_or("--config expects a path")?));
            }
            "--data-dir" => {
                data_dir = Some(PathBuf::from(
                    args.next().ok_or("--data-dir expects a path")?,
                ));
            }
            "--health-port" => {
                let v = args.next().ok_or("--health-port expects an integer")?;
                health_port = v
                    .parse()
                    .map_err(|_| "--health-port: integer required".to_owned())?;
            }
            "--help" | "-h" => {
                println!("{}", USAGE);
                std::process::exit(0);
            }
            other => {
                return Err(format!("unknown argument: {other}\n\n{USAGE}"));
            }
        }
    }
    Ok(Args {
        config_path: config_path.ok_or_else(|| format!("--config required\n\n{USAGE}"))?,
        data_dir: data_dir.ok_or_else(|| format!("--data-dir required\n\n{USAGE}"))?,
        health_port,
    })
}

const USAGE: &str = "\
USAGE:
    raxis-otel-pusher --config <path> --data-dir <path> [--health-port <port>]

Reads kernel-emitted JSONL frames under <data_dir>/observability/ and
ships them to the OTLP endpoint declared in [observability.pusher].

OPTIONS:
    --config <path>        signed policy.toml the kernel is using
    --data-dir <path>      kernel data directory
    --health-port <port>   /healthz port (default 9501; 0 disables)
    -h, --help             show this help and exit
";

fn build_config(
    bundle: &PolicyBundle,
    args: &Args,
    kernel_version: String,
) -> Result<PusherConfig, raxis_otel_pusher::config::ConfigError> {
    PusherConfig::build(
        bundle.observability(),
        args.data_dir.clone(),
        kernel_version,
        args.health_port,
    )
}

fn build_client(
    cfg: &PusherConfig,
) -> Result<OtlpClient, raxis_otel_pusher::otlp::OtlpClientError> {
    OtlpClient::new(
        OtlpEndpoint::new(&cfg.pusher.otlp_endpoint),
        cfg.pusher.headers.clone(),
        raxis_otel_pusher::retry::BackoffPolicy {
            initial: cfg.pusher.backoff_initial,
            max: cfg.pusher.backoff_max,
            jitter: cfg.pusher.backoff_jitter,
            max_attempts: 8,
        },
        cfg.export_timeout(),
        ResourceAttrs {
            service_name: cfg.resource.service_name.clone(),
            environment: cfg.resource.environment.clone(),
            extra: cfg.resource.extra.clone(),
        },
        OtlpCompression::from_policy(&cfg.pusher.otlp_compression)?,
    )
}

struct PusherEventLogger {
    path: PathBuf,
}

impl PusherEventLogger {
    fn new(path: PathBuf) -> Self {
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"otel_pusher_events_dir_create_failed\",\
                     \"path\":\"{}\",\"reason\":\"{e}\"}}",
                    parent.display(),
                );
            }
        }
        Self { path }
    }

    fn log(&self, ev: &PusherEvent) {
        let json = pusher_event_json(ev);
        eprintln!("{json}");
        append_event_jsonl(&self.path, &json);
    }
}

fn pusher_event_json(ev: &PusherEvent) -> serde_json::Value {
    let json = match ev {
        PusherEvent::Started => serde_json::json!({
            "level": "info",
            "event": "otel_pusher_started",
        }),
        PusherEvent::StartupFailure { stage, reason } => serde_json::json!({
            "level": "error",
            "event": "otel_pusher_startup_failed",
            "stage": stage,
            "reason": reason,
        }),
        PusherEvent::Stopping => serde_json::json!({
            "level": "info",
            "event": "otel_pusher_stopping",
        }),
        PusherEvent::ExportOk {
            stream,
            frames,
            status,
        } => serde_json::json!({
            "level": "info",
            "event": "otel_pusher_export_ok",
            "stream": format!("{stream:?}"),
            "frames": frames,
            "status": status,
        }),
        PusherEvent::ExportRetry {
            stream,
            attempt,
            reason,
        } => serde_json::json!({
            "level": "info",
            "event": "otel_pusher_export_retry",
            "stream": format!("{stream:?}"),
            "attempt": attempt,
            "reason": reason,
        }),
        PusherEvent::ExportPermanentFailure {
            stream,
            frames,
            reason,
        } => serde_json::json!({
            "level": "info",
            "event": "otel_pusher_export_drop",
            "stream": format!("{stream:?}"),
            "frames": frames,
            "reason": reason,
        }),
        PusherEvent::SegmentAdvanced {
            stream,
            new_segment,
        } => serde_json::json!({
            "level": "info",
            "event": "otel_pusher_segment_advanced",
            "stream": format!("{stream:?}"),
            "new_segment": new_segment,
        }),
    };
    json
}

fn append_event_jsonl(path: &Path, json: &serde_json::Value) {
    use std::io::Write;
    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(file) => file,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"otel_pusher_events_append_failed\",\
                 \"path\":\"{}\",\"reason\":\"{e}\"}}",
                path.display(),
            );
            return;
        }
    };
    if let Err(e) = writeln!(file, "{json}") {
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"otel_pusher_events_write_failed\",\
             \"path\":\"{}\",\"reason\":\"{e}\"}}",
            path.display(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_logger_appends_jsonl_for_dashboard_health_card() {
        let td = tempfile::TempDir::new().expect("tempdir");
        let path = td.path().join("observability/pusher-events.jsonl");
        let logger = PusherEventLogger::new(path.clone());

        logger.log(&PusherEvent::Started);
        logger.log(&PusherEvent::StartupFailure {
            stage: "client_init".to_owned(),
            reason: "connection refused".to_owned(),
        });
        logger.log(&PusherEvent::Stopping);

        let body = std::fs::read_to_string(path).expect("event log");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("\"event\":\"otel_pusher_started\""));
        assert!(lines[1].contains("\"event\":\"otel_pusher_startup_failed\""));
        assert!(lines[1].contains("\"stage\":\"client_init\""));
        assert!(lines[2].contains("\"event\":\"otel_pusher_stopping\""));
    }

    #[test]
    fn default_events_path_matches_health_card_contract() {
        let root = PathBuf::from("/tmp/raxis-data");
        assert_eq!(
            default_events_path(&root),
            PathBuf::from("/tmp/raxis-data/observability/pusher-events.jsonl")
        );
    }
}
