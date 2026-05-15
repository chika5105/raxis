// Fake kernel binary that sleeps forever. Used by
// `tests/supervisor_signal_witness.rs` to exercise the
// SIGTERM-respect path: the supervisor sends SIGTERM, this
// binary's `tokio::signal` handler observes it and exits 0.

fn main() {
    // Install a SIGTERM handler that exits cleanly. Without this
    // the default disposition is to terminate immediately
    // (which still produces a signaled exit; but having the
    // child cleanly exit makes the supervisor's
    // `intent_flag.set()` + `classify_signal(15, true)` =
    // `CleanExit{143}` test more deterministic).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    rt.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        let mut int_ = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("install SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = int_.recv() => {}
        }
    });
    // Graceful shutdown — exit 0. Mirrors what a real kernel
    // does in response to SIGTERM (per `kernel-lifecycle.md`):
    // tear down subsystems then `process::exit(0)`. The
    // supervisor classifies this as `CleanExit{0}` and MUST NOT
    // restart per `INV-SUPERVISOR-SIGTERM-RESPECT-01`.
    std::process::exit(0);
}
