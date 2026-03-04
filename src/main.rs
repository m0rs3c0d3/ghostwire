mod alerter;
mod collector;
mod models;
mod profiler;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use alerter::{Alerter, AlerterConfig};
use models::UsbEvent;
use profiler::Profiler;

const DEFAULT_DB_PATH: &str = "/var/lib/ghostwire/devices.db";
const DEFAULT_LOG_PATH: &str = "/var/log/ghostwire/events.log";

// =============================================================================
// Config file (Phase 5)
// =============================================================================

/// Persistent defaults loaded from `/etc/ghostwire/config.toml` and/or
/// `~/.config/ghostwire/config.toml`. CLI flags always override config values.
///
/// Example config.toml:
/// ```toml
/// db_path  = "/var/lib/ghostwire/devices.db"
/// log_path = "/var/log/ghostwire/events.log"
/// notify   = true
/// alert_threshold = 50
/// warn_threshold  = 20
/// ```
#[derive(Debug, Default, Deserialize)]
struct Config {
    db_path: Option<String>,
    log_path: Option<String>,
    notify: Option<bool>,
    alert_threshold: Option<u32>,
    warn_threshold: Option<u32>,
}

impl Config {
    /// Load config files in priority order: system → user (user wins).
    ///
    /// Silently skips missing or unreadable files.
    fn load() -> Self {
        let mut cfg = Config::default();

        let candidates: Vec<PathBuf> = vec![
            PathBuf::from("/etc/ghostwire/config.toml"),
            dirs_config_path(),
        ];

        for path in candidates {
            if !path.exists() {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(content) => match toml::from_str::<Config>(&content) {
                    Ok(parsed) => cfg.merge(parsed),
                    Err(e) => eprintln!(
                        "warning: failed to parse config at {}: {}",
                        path.display(),
                        e
                    ),
                },
                Err(e) => eprintln!(
                    "warning: cannot read config at {}: {}",
                    path.display(),
                    e
                ),
            }
        }

        cfg
    }

    /// Merge `other` on top of `self` — only overwrites fields that are `Some`
    /// in `other`.
    fn merge(&mut self, other: Config) {
        if other.db_path.is_some() {
            self.db_path = other.db_path;
        }
        if other.log_path.is_some() {
            self.log_path = other.log_path;
        }
        if other.notify.is_some() {
            self.notify = other.notify;
        }
        if other.alert_threshold.is_some() {
            self.alert_threshold = other.alert_threshold;
        }
        if other.warn_threshold.is_some() {
            self.warn_threshold = other.warn_threshold;
        }
    }
}

/// Resolve `~/.config/ghostwire/config.toml` portably.
fn dirs_config_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            PathBuf::from(home).join(".config")
        });
    base.join("ghostwire").join("config.toml")
}

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
    #[arg(long, global = true)]
    db_path: Option<String>,

    /// Path to the JSON event log
    #[arg(long, global = true)]
    log_path: Option<String>,

    /// Run in the foreground with human-readable log output (default: compact structured)
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

    /// List all known device profiles in the trust store
    List,

    /// Show full details for a single device profile
    Show {
        /// Fingerprint prefix or full SHA-256 fingerprint
        fingerprint: String,
    },

    /// Mark a device fingerprint as explicitly trusted
    Trust {
        /// SHA-256 fingerprint (from `ghostwire list`)
        fingerprint: String,
    },

    /// Remove the trusted flag from a device
    Untrust {
        /// SHA-256 fingerprint
        fingerprint: String,
    },

    /// Remove a device profile from the trust store entirely
    ///
    /// Historical events that reference this fingerprint are preserved.
    /// The device will be treated as unknown the next time it connects.
    Forget {
        /// SHA-256 fingerprint
        fingerprint: String,
    },

    /// Show recent USB events with anomaly scores
    History {
        /// Number of most-recent events to display
        #[arg(short, long, default_value_t = 20)]
        limit: u32,
    },

    /// Export the full event log as JSON to stdout
    Export,

    /// Verify the integrity of the tamper-evident event chain
    ///
    /// Exits with code 0 if the chain is intact, 1 if broken links are found.
    Verify,
}

// =============================================================================
// Entry point
// =============================================================================

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let file_cfg = Config::load();

    // Merge: config file defaults → CLI overrides
    let db_path = cli
        .db_path
        .or(file_cfg.db_path)
        .unwrap_or_else(|| DEFAULT_DB_PATH.to_string());
    let log_path = cli
        .log_path
        .or(file_cfg.log_path)
        .unwrap_or_else(|| DEFAULT_LOG_PATH.to_string());
    let notify = cli.notify || file_cfg.notify.unwrap_or(false);

    init_logging(cli.foreground);

    match cli.command {
        Some(Command::List) => cmd_list(&db_path),
        Some(Command::Show { fingerprint }) => cmd_show(&db_path, &fingerprint),
        Some(Command::Trust { fingerprint }) => cmd_trust(&db_path, &fingerprint),
        Some(Command::Untrust { fingerprint }) => cmd_untrust(&db_path, &fingerprint),
        Some(Command::Forget { fingerprint }) => cmd_forget(&db_path, &fingerprint),
        Some(Command::History { limit }) => cmd_history(&db_path, limit),
        Some(Command::Export) => cmd_export(&db_path),
        Some(Command::Verify) => cmd_verify(&db_path),
        None | Some(Command::Daemon) => {
            info!("ghostwire v{}", env!("CARGO_PKG_VERSION"));
            run_daemon(&db_path, &log_path, notify).await
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

    info!(db = db_path, log = log_path, "Listening for USB events");

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

fn cmd_list(db_path: &str) {
    let profiler = open_profiler_ro(db_path);
    let devices = unwrap_or_exit(profiler.list_devices(), "list devices");

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

fn cmd_show(db_path: &str, fingerprint: &str) {
    let profiler = open_profiler_ro(db_path);

    // Support prefix matching: collect all devices and filter
    let devices = unwrap_or_exit(profiler.list_devices(), "list devices");
    let matches: Vec<_> = devices
        .iter()
        .filter(|d| d.fingerprint.starts_with(fingerprint))
        .collect();

    match matches.len() {
        0 => {
            eprintln!("error: no device matching fingerprint prefix '{}'", fingerprint);
            std::process::exit(1);
        }
        n if n > 1 => {
            eprintln!(
                "error: ambiguous fingerprint prefix '{}' matches {} devices — be more specific",
                fingerprint, n
            );
            for d in &matches {
                eprintln!("  {}", d.fingerprint);
            }
            std::process::exit(1);
        }
        _ => {}
    }

    let d = matches[0];
    println!("Fingerprint  : {}", d.fingerprint);
    println!("VID / PID    : {} / {}", d.vid, d.pid);
    println!(
        "Manufacturer : {}",
        d.manufacturer.as_deref().unwrap_or("-")
    );
    println!("Product      : {}", d.product.as_deref().unwrap_or("-"));
    println!("Serial       : {}", d.serial.as_deref().unwrap_or("-"));
    println!(
        "Device class : {}",
        d.device_class.as_deref().unwrap_or("-")
    );
    println!(
        "Interfaces   : {}",
        d.interface_count
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!("Port path    : {}", d.port_path);
    println!("First seen   : {}", d.first_seen.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("Last seen    : {}", d.last_seen.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("Seen count   : {}", d.seen_count);
    println!("Trusted      : {}", if d.trusted { "yes" } else { "no" });
}

fn cmd_trust(db_path: &str, fingerprint: &str) {
    let mut profiler = open_profiler_rw(db_path);
    match unwrap_or_exit(profiler.trust_device(fingerprint), "trust device") {
        true => println!("Marked {} as trusted.", fingerprint),
        false => {
            eprintln!("error: fingerprint not found: {}", fingerprint);
            std::process::exit(1);
        }
    }
}

fn cmd_untrust(db_path: &str, fingerprint: &str) {
    let mut profiler = open_profiler_rw(db_path);
    match unwrap_or_exit(profiler.untrust_device(fingerprint), "untrust device") {
        true => println!("Removed trust from {}.", fingerprint),
        false => {
            eprintln!("error: fingerprint not found: {}", fingerprint);
            std::process::exit(1);
        }
    }
}

fn cmd_forget(db_path: &str, fingerprint: &str) {
    let mut profiler = open_profiler_rw(db_path);
    match unwrap_or_exit(profiler.forget_device(fingerprint), "forget device") {
        true => println!(
            "Removed {} from the trust store.\n\
             Historical events are preserved; the device will appear as UNKNOWN_DEVICE next time it connects.",
            fingerprint
        ),
        false => {
            eprintln!("error: fingerprint not found: {}", fingerprint);
            std::process::exit(1);
        }
    }
}

fn cmd_history(db_path: &str, limit: u32) {
    let profiler = open_profiler_ro(db_path);
    let rows = unwrap_or_exit(profiler.recent_events(limit), "read event history");

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
    let profiler = open_profiler_ro(db_path);
    let events = unwrap_or_exit(profiler.export_events(), "export events");
    let json = unwrap_or_exit(
        serde_json::to_string_pretty(&events).map_err(|e| e.into()),
        "serialize events",
    );
    println!("{}", json);
}

fn cmd_verify(db_path: &str) {
    let profiler = open_profiler_ro(db_path);
    let result = unwrap_or_exit(profiler.verify_chain(), "verify chain");

    println!(
        "Examined {} event rows.",
        result.total
    );

    if result.is_ok() {
        println!("Chain OK — no broken links found.");
    } else {
        eprintln!(
            "CHAIN BROKEN — {} broken link(s) detected:",
            result.broken.len()
        );
        for link in &result.broken {
            eprintln!("  event {:>6}: {}", link.event_id, link.reason);
        }
        std::process::exit(1);
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn open_profiler_ro(db_path: &str) -> Profiler {
    match Profiler::new(db_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot open trust store at {}: {}", db_path, e);
            std::process::exit(1);
        }
    }
}

fn open_profiler_rw(db_path: &str) -> Profiler {
    open_profiler_ro(db_path)
}

fn unwrap_or_exit<T>(result: Result<T, Box<dyn std::error::Error>>, ctx: &str) -> T {
    match result {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {}: {}", ctx, e);
            std::process::exit(1);
        }
    }
}

fn init_logging(foreground: bool) {
    if foreground {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("ghostwire=debug,info")),
            )
            .with_target(false)
            .init();
    } else {
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
