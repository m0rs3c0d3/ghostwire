mod alerter;
mod collector;
mod models;
mod profiler;

use clap::{Parser, Subcommand};
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use alerter::{Alerter, AlerterConfig};
use models::UsbEvent;
use profiler::Profiler;

const DEFAULT_DB_PATH: &str = "/var/lib/ghostwire/devices.db";
const DEFAULT_LOG_PATH: &str = "/var/log/ghostwire/events.log";

// =============================================================================
// CLI definition
// =============================================================================

#[derive(Parser)]
#[command(
    name = "ghostwire",
    version,
    about = "Passive USB anomaly detection daemon for Linux",
    long_about = "ghostwire monitors the USB bus via the kernel netlink uevent socket,\n\
                  builds behavioral trust profiles of known devices, and alerts when\n\
                  something anomalous connects. Requires root or CAP_NET_ADMIN."
)]
struct Cli {
    /// Path to the SQLite trust-store database
    #[arg(long, default_value = DEFAULT_DB_PATH, global = true)]
    db_path: String,

    /// Path to the JSON event log
    #[arg(long, default_value = DEFAULT_LOG_PATH, global = true)]
    log_path: String,

    /// Run in the foreground with human-readable log output (default: structured JSON)
    #[arg(long, short = 'f', global = true)]
    foreground: bool,

    /// Enable desktop notifications for high-risk events (requires desktop-notify feature)
    #[arg(long, global = true)]
    notify: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon (default when no subcommand is given)
    Daemon,

    /// Mark a device fingerprint as explicitly trusted
    Trust {
        /// SHA-256 fingerprint of the device (from `ghostwire list` or event log)
        fingerprint: String,
    },

    /// List all known device profiles in the trust store
    List,

    /// Show recent USB events with anomaly scores
    History {
        /// Number of most-recent events to display
        #[arg(short, long, default_value_t = 20)]
        limit: u32,
    },

    /// Export the full event log as JSON to stdout
    Export,
}

// =============================================================================
// Entry point
// =============================================================================

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    init_logging(cli.foreground);
    info!("ghostwire v{}", env!("CARGO_PKG_VERSION"));

    match cli.command {
        // ── One-shot management commands ──────────────────────────────────────
        Some(Command::Trust { fingerprint }) => cmd_trust(&cli.db_path, &fingerprint),
        Some(Command::List) => cmd_list(&cli.db_path),
        Some(Command::History { limit }) => cmd_history(&cli.db_path, limit),
        Some(Command::Export) => cmd_export(&cli.db_path),

        // ── Daemon mode (default) ─────────────────────────────────────────────
        None | Some(Command::Daemon) => {
            run_daemon(&cli.db_path, &cli.log_path, cli.notify).await
        }
    }
}

// =============================================================================
// Daemon
// =============================================================================

async fn run_daemon(db_path: &str, log_path: &str, notify: bool) {
    let mut profiler = init_profiler(db_path);

    let alerter = init_alerter(AlerterConfig {
        log_path: Some(log_path.to_string()),
        desktop_notify: notify,
    });

    let (tx, mut rx) = mpsc::channel::<UsbEvent>(256);
    collector::spawn_collector(tx);

    info!(
        db  = db_path,
        log = log_path,
        "Listening for USB events"
    );

    while let Some(event) = rx.recv().await {
        let result = tokio::task::block_in_place(|| profiler.process_event(&event));
        match result {
            Ok(r) => alerter.handle(&r),
            Err(e) => error!("Error processing USB event: {}", e),
        }
    }

    info!("ghostwire shutting down");
}

// =============================================================================
// Management subcommands
// =============================================================================

fn cmd_trust(db_path: &str, fingerprint: &str) {
    let mut profiler = match Profiler::new(db_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot open trust store at {}: {}", db_path, e);
            std::process::exit(1);
        }
    };
    match profiler.trust_device(fingerprint) {
        Ok(true) => println!("Marked {} as trusted.", fingerprint),
        Ok(false) => {
            eprintln!("error: fingerprint not found in trust store: {}", fingerprint);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_list(db_path: &str) {
    let profiler = match Profiler::new(db_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot open trust store at {}: {}", db_path, e);
            std::process::exit(1);
        }
    };
    let devices = match profiler.list_devices() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    };

    if devices.is_empty() {
        println!("No devices in trust store yet.");
        return;
    }

    println!(
        "{:<16}  {:<6}  {:<6}  {:<8}  {:<5}  {:<30}  {}",
        "FINGERPRINT", "VID", "PID", "SEEN", "TRUST", "PRODUCT", "LAST SEEN"
    );
    println!("{}", "-".repeat(110));

    for d in &devices {
        let fp_short = &d.fingerprint[..16];
        let product = d
            .product
            .as_deref()
            .or(d.manufacturer.as_deref())
            .unwrap_or("-");
        let trust = if d.trusted { "yes" } else { "no" };
        let last = d.last_seen.format("%Y-%m-%d %H:%M:%S").to_string();
        println!(
            "{:<16}  {:<6}  {:<6}  {:<8}  {:<5}  {:<30}  {}",
            fp_short, d.vid, d.pid, d.seen_count, trust, product, last
        );
    }
    println!("\n{} device(s) total.", devices.len());
}

fn cmd_history(db_path: &str, limit: u32) {
    let profiler = match Profiler::new(db_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot open trust store at {}: {}", db_path, e);
            std::process::exit(1);
        }
    };
    let rows = match profiler.recent_events(limit) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    };

    if rows.is_empty() {
        println!("No events recorded yet.");
        return;
    }

    println!(
        "{:>6}  {:<25}  {:<7}  {:<16}  {:>6}  {}",
        "ID", "TIMESTAMP", "ACTION", "FINGERPRINT", "SCORE", "FLAGS"
    );
    println!("{}", "-".repeat(100));

    for row in &rows {
        let fp_short = &row.fingerprint[..16];
        let flags = row
            .anomaly_flags
            .as_deref()
            .unwrap_or("[]")
            .trim_matches(|c| c == '[' || c == ']')
            .replace('"', "");
        println!(
            "{:>6}  {:<25}  {:<7}  {:<16}  {:>6}  {}",
            row.id, row.timestamp, row.action, fp_short, row.anomaly_score, flags
        );
    }
}

fn cmd_export(db_path: &str) {
    let profiler = match Profiler::new(db_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot open trust store at {}: {}", db_path, e);
            std::process::exit(1);
        }
    };
    let events = match profiler.export_events() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    };
    match serde_json::to_string_pretty(&events) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("error serializing events: {}", e);
            std::process::exit(1);
        }
    }
}

// =============================================================================
// Startup helpers
// =============================================================================

fn init_logging(foreground: bool) {
    if foreground {
        // Human-readable for interactive/debug use
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("ghostwire=debug,info")),
            )
            .with_target(false)
            .init();
    } else {
        // Structured compact output for journald / log aggregators
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("ghostwire=info,info")),
            )
            .with_target(false)
            .compact()
            .init();
    }
}

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

fn init_alerter(config: AlerterConfig) -> Alerter {
    match Alerter::new(config) {
        Ok(a) => a,
        Err(e) => {
            error!(err = %e, "Cannot initialise alerter — falling back to tracing-only output");
            Alerter::new(AlerterConfig::default()).expect("default alerter must not fail")
        }
    }
}
