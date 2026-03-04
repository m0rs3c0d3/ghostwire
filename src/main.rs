mod alerter;
mod collector;
mod models;
mod profiler;

use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use alerter::Alerter;
use models::UsbEvent;
use profiler::Profiler;

/// Default path for the persistent trust-store database.
const DEFAULT_DB_PATH: &str = "/var/lib/ghostwire/devices.db";

/// Default path for the JSON event log.
const DEFAULT_LOG_PATH: &str = "/var/log/ghostwire/events.log";

#[tokio::main]
async fn main() {
    // Initialise structured tracing to stderr / journald.
    // Override with RUST_LOG env var, e.g. RUST_LOG=ghostwire=debug
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("ghostwire=info,info")),
        )
        .with_target(false)
        .init();

    info!("ghostwire v{} starting", env!("CARGO_PKG_VERSION"));

    // --- Profiler (SQLite trust store) ---
    let mut profiler = init_profiler(DEFAULT_DB_PATH);

    // --- Alerter (log sink) ---
    let alerter = init_alerter(DEFAULT_LOG_PATH);

    // --- Event channel: collector → profiler ---
    let (tx, mut rx) = mpsc::channel::<UsbEvent>(256);

    // Spawn the blocking netlink listener in a dedicated OS thread
    collector::spawn_collector(tx);

    info!(
        db   = DEFAULT_DB_PATH,
        log  = DEFAULT_LOG_PATH,
        "Listening for USB events — plug in a device to test"
    );

    // Main processing loop
    while let Some(event) = rx.recv().await {
        // DB operations are synchronous (rusqlite is !Send); block_in_place
        // parks the current tokio thread so the runtime stays healthy.
        let result = tokio::task::block_in_place(|| profiler.process_event(&event));

        match result {
            Ok(anomaly_result) => alerter.handle(&anomaly_result),
            Err(e) => error!("Error processing USB event: {}", e),
        }
    }

    info!("ghostwire shutting down");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Try to open the on-disk trust store; fall back to an in-memory DB so the
/// daemon remains functional when run without root/write access during dev.
fn init_profiler(db_path: &str) -> Profiler {
    match Profiler::new(db_path) {
        Ok(p) => {
            info!(path = db_path, "Trust store opened");
            p
        }
        Err(e) => {
            error!(
                path = db_path,
                err  = %e,
                "Cannot open trust store — falling back to in-memory DB (events will not persist)"
            );
            Profiler::new(":memory:").expect("in-memory DB must not fail")
        }
    }
}

/// Try to create the JSON event log; fall back to logging-only mode.
fn init_alerter(log_path: &str) -> Alerter {
    match Alerter::new(Some(log_path.to_string())) {
        Ok(a) => {
            info!(path = log_path, "Event log opened");
            a
        }
        Err(e) => {
            error!(
                path = log_path,
                err  = %e,
                "Cannot open event log — falling back to tracing-only output"
            );
            Alerter::new(None).expect("alerter without log path must not fail")
        }
    }
}
