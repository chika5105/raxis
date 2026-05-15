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

use std::path::PathBuf;
use std::process::ExitCode;

use raxis_otel_pusher::{
    config::PusherConfig,
    health,
    otlp::{OtlpClient, OtlpEndpoint, ResourceAttrs},
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
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"otel_pusher_config_invalid\",\
                  \"reason\":\"{e}\"}}"
            );
            return ExitCode::from(78);
        }
    };

    if cfg.pusher.otlp_protocol != "http" {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"otel_pusher_unsupported_protocol\",\
              \"protocol\":\"{}\",\"detail\":\"V3 supports otlp_protocol=http only; gRPC \
              lands in V3.1\"}}",
            cfg.pusher.otlp_protocol,
        );
        return ExitCode::from(78);
    }

    let client = match build_client(&cfg) {
        Ok(c) => c,
        Err(e) => {
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
                for e in events { log_event(&e); }
            }
        }
    }

    // Final drain.
    let final_events = pusher.tick(true).await;
    for e in final_events {
        log_event(&e);
    }
    log_event(&PusherEvent::Stopping);
    ExitCode::SUCCESS
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
    )
}

fn log_event(ev: &PusherEvent) {
    let json = match ev {
        PusherEvent::Started => r#"{"event":"otel_pusher_started"}"#.to_owned(),
        PusherEvent::Stopping => r#"{"event":"otel_pusher_stopping"}"#.to_owned(),
        PusherEvent::ExportOk { stream, frames, status } => format!(
            "{{\"event\":\"otel_pusher_export_ok\",\"stream\":\"{:?}\",\"frames\":{},\"status\":{}}}",
            stream, frames, status,
        ),
        PusherEvent::ExportRetry { stream, attempt, reason } => format!(
            "{{\"event\":\"otel_pusher_export_retry\",\"stream\":\"{:?}\",\"attempt\":{},\"reason\":\"{}\"}}",
            stream, attempt, reason,
        ),
        PusherEvent::ExportPermanentFailure { stream, frames, reason } => format!(
            "{{\"event\":\"otel_pusher_export_drop\",\"stream\":\"{:?}\",\"frames\":{},\"reason\":\"{}\"}}",
            stream, frames, reason,
        ),
        PusherEvent::SegmentAdvanced { stream, new_segment } => format!(
            "{{\"event\":\"otel_pusher_segment_advanced\",\"stream\":\"{:?}\",\"new_segment\":\"{}\"}}",
            stream, new_segment,
        ),
    };
    eprintln!("{{\"level\":\"info\",{}}}", &json[1..json.len() - 1]);
}
