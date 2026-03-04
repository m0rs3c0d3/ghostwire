use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use tracing::{error, info, warn};

use crate::models::{AnomalyFlag, AnomalyResult};

/// Score threshold above which a desktop notification is sent.
const NOTIFY_THRESHOLD: u32 = 50;

/// Score threshold above which an alert is promoted to ERROR severity.
const CRITICAL_THRESHOLD: u32 = 50;

/// Score threshold above which an alert is promoted to WARN severity.
const WARN_THRESHOLD: u32 = 20;

/// Configuration for the alerter.
pub struct AlerterConfig {
    /// Path to write newline-delimited JSON events. `None` disables file output.
    pub log_path: Option<String>,
    /// If true, send desktop notifications for high-score events (requires the
    /// `desktop-notify` Cargo feature and a running notification daemon).
    pub desktop_notify: bool,
}

impl Default for AlerterConfig {
    fn default() -> Self {
        AlerterConfig {
            log_path: None,
            desktop_notify: false,
        }
    }
}

/// Dispatches alerts based on the anomaly score of a processed USB event.
///
/// Outputs (Phase 4):
///   - Structured `tracing` log → stderr / journald (always)
///   - Newline-delimited JSON → log file (if configured)
///   - Desktop notification via libnotify (optional feature, score > 50)
pub struct Alerter {
    config: AlerterConfig,
}

impl Alerter {
    pub fn new(config: AlerterConfig) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(ref path) = config.log_path {
            if let Some(parent) = Path::new(path).parent() {
                fs::create_dir_all(parent)?;
            }
        }
        Ok(Alerter { config })
    }

    /// Handle a single anomaly result.
    pub fn handle(&self, result: &AnomalyResult) {
        let score = result.score;
        let event = &result.event;
        let flag_strs: Vec<&str> = result.flags.iter().map(AnomalyFlag::as_str).collect();

        // ── Tracing output ────────────────────────────────────────────────────
        if score > CRITICAL_THRESHOLD {
            error!(
                action  = %event.action,
                vid     = %event.vid,
                pid     = %event.pid,
                product = ?event.product,
                mfr     = ?event.manufacturer,
                serial  = ?event.serial,
                score   = score,
                flags   = ?flag_strs,
                port    = %event.port_path,
                "HIGH-RISK USB device — flagged for review"
            );
        } else if score > WARN_THRESHOLD {
            warn!(
                action  = %event.action,
                vid     = %event.vid,
                pid     = %event.pid,
                product = ?event.product,
                mfr     = ?event.manufacturer,
                score   = score,
                flags   = ?flag_strs,
                port    = %event.port_path,
                "USB anomaly detected"
            );
        } else {
            info!(
                action  = %event.action,
                vid     = %event.vid,
                pid     = %event.pid,
                product = ?event.product,
                mfr     = ?event.manufacturer,
                score   = score,
                flags   = ?flag_strs,
                port    = %event.port_path,
                "USB event"
            );
        }

        // ── JSON log ──────────────────────────────────────────────────────────
        if let Some(ref path) = self.config.log_path {
            self.write_json_log(result, path);
        }

        // ── Desktop notification (feature-gated) ──────────────────────────────
        if self.config.desktop_notify && score > NOTIFY_THRESHOLD {
            self.send_desktop_notification(result);
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
            Err(e) => error!("Failed to open event log {}: {}", path, e),
        }
    }

    #[cfg(feature = "desktop-notify")]
    fn send_desktop_notification(&self, result: &AnomalyResult) {
        use notify_rust::{Notification, Urgency};

        let event = &result.event;
        let label = event
            .product
            .as_deref()
            .or(event.manufacturer.as_deref())
            .unwrap_or("Unknown device");

        let flag_strs: Vec<&str> = result.flags.iter().map(AnomalyFlag::as_str).collect();
        let body = format!(
            "VID:{} PID:{} | Score: {} | Flags: {}",
            event.vid,
            event.pid,
            result.score,
            flag_strs.join(", ")
        );

        let urgency = if result.score > 70 {
            Urgency::Critical
        } else {
            Urgency::Normal
        };

        if let Err(e) = Notification::new()
            .summary(&format!("ghostwire — suspicious USB: {}", label))
            .body(&body)
            .icon("security-high")
            .urgency(urgency)
            .show()
        {
            // Non-fatal — logging already captured the event
            warn!("Desktop notification failed (is a notification daemon running?): {}", e);
        }
    }

    #[cfg(not(feature = "desktop-notify"))]
    fn send_desktop_notification(&self, _result: &AnomalyResult) {
        // No-op when feature is disabled
    }
}
