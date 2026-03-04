use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use tracing::{error, info, warn};

use crate::models::{AnomalyResult, AnomalyFlag};

/// Dispatches alerts based on the anomaly score of a processed USB event.
///
/// Phase 1/2 outputs:
///   - Structured `tracing` log to stderr / journald
///   - Newline-delimited JSON to a log file (if configured)
///
/// Phase 4 will add desktop notifications and webhook POSTs.
pub struct Alerter {
    log_path: Option<String>,
}

impl Alerter {
    /// Create an alerter. If `log_path` is `Some`, the parent directory is
    /// created automatically and all events are appended as JSON lines.
    pub fn new(log_path: Option<String>) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(ref path) = log_path {
            if let Some(parent) = Path::new(path).parent() {
                fs::create_dir_all(parent)?;
            }
        }
        Ok(Alerter { log_path })
    }

    /// Handle a single anomaly result: log via tracing and optionally write to
    /// the JSON event log.
    pub fn handle(&self, result: &AnomalyResult) {
        let score = result.score;
        let event = &result.event;
        let flag_strs: Vec<&str> = result.flags.iter().map(AnomalyFlag::as_str).collect();

        match score {
            // Log-only
            0..=20 => {
                info!(
                    action    = %event.action,
                    vid       = %event.vid,
                    pid       = %event.pid,
                    product   = ?event.product,
                    mfr       = ?event.manufacturer,
                    score     = score,
                    flags     = ?flag_strs,
                    port      = %event.port_path,
                    "USB event"
                );
            }
            // Log + notify
            21..=50 => {
                warn!(
                    action    = %event.action,
                    vid       = %event.vid,
                    pid       = %event.pid,
                    product   = ?event.product,
                    mfr       = ?event.manufacturer,
                    score     = score,
                    flags     = ?flag_strs,
                    port      = %event.port_path,
                    "USB anomaly detected"
                );
            }
            // Log + notify + flag for review
            _ => {
                error!(
                    action    = %event.action,
                    vid       = %event.vid,
                    pid       = %event.pid,
                    product   = ?event.product,
                    mfr       = ?event.manufacturer,
                    score     = score,
                    flags     = ?flag_strs,
                    port      = %event.port_path,
                    "HIGH-RISK USB device — flagged for review"
                );
            }
        }

        if let Some(ref path) = self.log_path {
            self.write_json_log(result, path);
        }
    }

    fn write_json_log(&self, result: &AnomalyResult, path: &str) {
        let line = match serde_json::to_string(result) {
            Ok(j) => j,
            Err(e) => {
                error!("Failed to serialize event for JSON log: {}", e);
                return;
            }
        };

        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{}", line) {
                    error!("Failed to write to event log {}: {}", path, e);
                }
            }
            Err(e) => {
                error!("Failed to open event log {}: {}", path, e);
            }
        }
    }
}
