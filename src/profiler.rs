use chrono::{DateTime, Local, Timelike, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::models::{AnomalyFlag, AnomalyResult, DeviceProfile, UsbEvent};

/// Maintains the SQLite trust store and computes anomaly scores.
pub struct Profiler {
    conn: Connection,
}

impl Profiler {
    /// Open (or create) the trust store at `db_path`.
    ///
    /// Pass `":memory:"` for an ephemeral in-process database useful during
    /// testing without root privileges.
    pub fn new(db_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if db_path != ":memory:" {
            if let Some(parent) = std::path::Path::new(db_path).parent() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let conn = Connection::open(db_path)?;
        // WAL mode gives better concurrent read performance and crash safety
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        let profiler = Profiler { conn };
        profiler.init_schema()?;
        Ok(profiler)
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS devices (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint     TEXT    NOT NULL UNIQUE,
                vid             TEXT    NOT NULL,
                pid             TEXT    NOT NULL,
                manufacturer    TEXT,
                product         TEXT,
                serial          TEXT,
                device_class    TEXT,
                interface_count INTEGER,
                port_path       TEXT,
                first_seen      TEXT    NOT NULL,
                last_seen       TEXT    NOT NULL,
                trusted         INTEGER NOT NULL DEFAULT 0,
                seen_count      INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                action          TEXT    NOT NULL,
                fingerprint     TEXT    NOT NULL,
                raw_json        TEXT    NOT NULL,
                anomaly_score   INTEGER NOT NULL DEFAULT 0,
                anomaly_flags   TEXT,
                prev_hash       TEXT,
                row_hash        TEXT    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_devices_vid_pid
                ON devices (vid, pid);
            CREATE INDEX IF NOT EXISTS idx_events_fingerprint
                ON events (fingerprint);
            ",
        )?;
        Ok(())
    }

    /// Process an incoming USB event: look up trust store, score anomalies,
    /// update the profile database, and append a tamper-evident log entry.
    pub fn process_event(
        &mut self,
        event: &UsbEvent,
    ) -> Result<AnomalyResult, Box<dyn std::error::Error>> {
        // Remove events are logged but not scored
        if event.action == "remove" {
            let fingerprint = compute_fingerprint(event);
            let known = self.get_profile_by_fingerprint(&fingerprint)?;
            let result = AnomalyResult {
                event: event.clone(),
                score: 0,
                flags: vec![],
                known_profile: known,
            };
            self.append_event_log(event, &result)?;
            return Ok(result);
        }

        let fingerprint = compute_fingerprint(event);

        // Exact fingerprint match → known profile
        let exact_match = self.get_profile_by_fingerprint(&fingerprint)?;

        // If no exact match, look for VID+PID match (potential DESCRIPTOR_MISMATCH)
        let vid_pid_matches: Vec<DeviceProfile> = if exact_match.is_none() {
            self.get_profiles_by_vid_pid(&event.vid, &event.pid)?
        } else {
            vec![]
        };

        let (score, flags) =
            self.score_event(event, &exact_match, &vid_pid_matches);

        // The "known profile" surfaced to the alerter is whichever profile is
        // most relevant: the exact match, or the first VID/PID variant seen.
        let known_profile = exact_match
            .clone()
            .or_else(|| vid_pid_matches.into_iter().next());

        let result = AnomalyResult {
            event: event.clone(),
            score,
            flags,
            known_profile: known_profile.clone(),
        };

        // Persist or update device profile
        let now = Utc::now();
        if let Some(ref profile) = exact_match {
            self.conn.execute(
                "UPDATE devices
                    SET last_seen  = ?1,
                        seen_count = seen_count + 1,
                        port_path  = ?2
                  WHERE fingerprint = ?3",
                params![now.to_rfc3339(), event.port_path, fingerprint],
            )?;
            info!(
                fingerprint = %fingerprint,
                vid = %event.vid,
                pid = %event.pid,
                seen_count = profile.seen_count + 1,
                "Known device reconnected"
            );
        } else {
            // New fingerprint — insert a fresh profile
            self.conn.execute(
                "INSERT INTO devices
                     (fingerprint, vid, pid, manufacturer, product, serial,
                      device_class, interface_count, port_path,
                      first_seen, last_seen, trusted, seen_count)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0,1)",
                params![
                    fingerprint,
                    event.vid,
                    event.pid,
                    event.manufacturer,
                    event.product,
                    event.serial,
                    event.device_class,
                    event.interface_count.map(|c| c as i64),
                    event.port_path,
                    now.to_rfc3339(),
                    now.to_rfc3339(),
                ],
            )?;
            info!(
                fingerprint = %fingerprint,
                vid = %event.vid,
                pid = %event.pid,
                "New device fingerprint registered"
            );
        }

        self.append_event_log(event, &result)?;
        Ok(result)
    }

    // -------------------------------------------------------------------------
    // Trust store queries
    // -------------------------------------------------------------------------

    fn get_profile_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Option<DeviceProfile>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT fingerprint, vid, pid, manufacturer, product, serial,
                    device_class, interface_count, port_path,
                    first_seen, last_seen, trusted, seen_count
               FROM devices
              WHERE fingerprint = ?1",
        )?;

        let profile = stmt
            .query_row(params![fingerprint], row_to_profile)
            .optional()?;

        Ok(profile)
    }

    fn get_profiles_by_vid_pid(
        &self,
        vid: &str,
        pid: &str,
    ) -> Result<Vec<DeviceProfile>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT fingerprint, vid, pid, manufacturer, product, serial,
                    device_class, interface_count, port_path,
                    first_seen, last_seen, trusted, seen_count
               FROM devices
              WHERE vid = ?1 AND pid = ?2
              ORDER BY last_seen DESC",
        )?;

        let profiles = stmt
            .query_map(params![vid, pid], row_to_profile)?
            .filter_map(|r| r.ok())
            .collect();

        Ok(profiles)
    }

    // -------------------------------------------------------------------------
    // Anomaly scoring
    // -------------------------------------------------------------------------

    fn score_event(
        &self,
        event: &UsbEvent,
        exact_match: &Option<DeviceProfile>,
        vid_pid_matches: &[DeviceProfile],
    ) -> (u32, Vec<AnomalyFlag>) {
        let mut flags: Vec<AnomalyFlag> = Vec::new();

        // UNKNOWN_DEVICE — fingerprint has never been seen, no VID/PID history either
        if exact_match.is_none() && vid_pid_matches.is_empty() {
            flags.push(AnomalyFlag::UnknownDevice);
        }

        // DESCRIPTOR_MISMATCH — VID/PID seen before but descriptor strings differ
        if exact_match.is_none() && !vid_pid_matches.is_empty() {
            flags.push(AnomalyFlag::DescriptorMismatch);
        }

        if let Some(ref profile) = exact_match {
            // NEW_PORT — same fingerprint but different physical port
            if profile.port_path != event.port_path {
                flags.push(AnomalyFlag::NewPort);
            }

            // NEW_INTERFACE_COUNT — interface count changed from stored profile
            if let (Some(stored), Some(current)) =
                (profile.interface_count, event.interface_count)
            {
                if stored != current {
                    flags.push(AnomalyFlag::NewInterfaceCount);
                }
            }
        }

        // COMPOSITE_HID_STORAGE — both HID (03) and mass storage (08) interfaces
        let has_hid = event
            .interfaces
            .iter()
            .any(|i| i.class.trim_start_matches('0') == "3");
        let has_storage = event
            .interfaces
            .iter()
            .any(|i| i.class.trim_start_matches('0') == "8");
        if has_hid && has_storage {
            flags.push(AnomalyFlag::CompositeHidStorage);
        }

        // ODD_HOURS — 01:00–04:59 local time
        let local_hour = Local::now().hour();
        if (1..5).contains(&local_hour) {
            flags.push(AnomalyFlag::OddHours);
        }

        // SERIAL_MISSING — HID or storage device without a serial number
        let device_expects_serial = has_hid
            || has_storage
            || event
                .device_class
                .as_deref()
                .map(|c| {
                    let c = c.trim_start_matches('0');
                    c == "3" || c == "8"
                })
                .unwrap_or(false);
        if device_expects_serial && event.serial.is_none() {
            flags.push(AnomalyFlag::SerialMissing);
        }

        // HID_FAST_ENUM — requires inter-event timing; placeholder for Phase 3
        // (needs correlation of usb_device and usb_interface bind timestamps)

        let score: u32 = flags.iter().map(|f| f.score()).sum();

        debug!(
            score = score,
            flags = ?flags.iter().map(|f| f.as_str()).collect::<Vec<_>>(),
            "Anomaly score computed"
        );

        (score, flags)
    }

    // -------------------------------------------------------------------------
    // Tamper-evident event log
    // -------------------------------------------------------------------------

    fn append_event_log(
        &mut self,
        event: &UsbEvent,
        result: &AnomalyResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fingerprint = compute_fingerprint(event);
        let raw_json = serde_json::to_string(event)?;
        let flags_json = serde_json::to_string(
            &result
                .flags
                .iter()
                .map(|f| f.as_str())
                .collect::<Vec<_>>(),
        )?;

        // Retrieve hash of the most recent event row for the chain link
        let prev_hash: Option<String> = self
            .conn
            .query_row(
                "SELECT row_hash FROM events ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        let prev_hash_str = prev_hash.as_deref().unwrap_or("genesis");
        let row_hash = chain_hash(
            &event.timestamp.to_rfc3339(),
            &fingerprint,
            result.score,
            prev_hash_str,
        );

        self.conn.execute(
            "INSERT INTO events
                 (timestamp, action, fingerprint, raw_json,
                  anomaly_score, anomaly_flags, prev_hash, row_hash)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                event.timestamp.to_rfc3339(),
                event.action,
                fingerprint,
                raw_json,
                result.score as i64,
                flags_json,
                prev_hash,
                row_hash,
            ],
        )?;

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Public helpers
// -----------------------------------------------------------------------------

/// Compute the device fingerprint: SHA-256 of VID, PID, manufacturer, product,
/// device class, and interface count — serial intentionally excluded (spoofable).
pub fn compute_fingerprint(event: &UsbEvent) -> String {
    let mut h = Sha256::new();
    h.update(event.vid.as_bytes());
    h.update(b"\x00");
    h.update(event.pid.as_bytes());
    h.update(b"\x00");
    h.update(event.manufacturer.as_deref().unwrap_or("").as_bytes());
    h.update(b"\x00");
    h.update(event.product.as_deref().unwrap_or("").as_bytes());
    h.update(b"\x00");
    h.update(event.device_class.as_deref().unwrap_or("").as_bytes());
    h.update(b"\x00");
    h.update(
        event
            .interface_count
            .map(|c| c.to_string())
            .unwrap_or_default()
            .as_bytes(),
    );
    hex::encode(h.finalize())
}

// -----------------------------------------------------------------------------
// Private helpers
// -----------------------------------------------------------------------------

/// Compute the tamper-evident row hash: SHA-256(timestamp | fingerprint | score | prev_hash)
fn chain_hash(timestamp: &str, fingerprint: &str, score: u32, prev_hash: &str) -> String {
    let mut h = Sha256::new();
    h.update(timestamp.as_bytes());
    h.update(b"\x00");
    h.update(fingerprint.as_bytes());
    h.update(b"\x00");
    h.update(score.to_string().as_bytes());
    h.update(b"\x00");
    h.update(prev_hash.as_bytes());
    hex::encode(h.finalize())
}

/// Map a `rusqlite` row to a `DeviceProfile`.
fn row_to_profile(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceProfile> {
    let first_seen: String = row.get(9)?;
    let last_seen: String = row.get(10)?;

    let parse_dt = |s: &str| -> DateTime<Utc> {
        s.parse::<DateTime<Utc>>()
            .unwrap_or_else(|_| Utc::now())
    };

    Ok(DeviceProfile {
        fingerprint: row.get(0)?,
        vid: row.get(1)?,
        pid: row.get(2)?,
        manufacturer: row.get(3)?,
        product: row.get(4)?,
        serial: row.get(5)?,
        device_class: row.get(6)?,
        interface_count: row.get::<_, Option<i64>>(7)?.map(|c| c as u8),
        port_path: row.get(8)?,
        first_seen: parse_dt(&first_seen),
        last_seen: parse_dt(&last_seen),
        trusted: row.get::<_, i64>(11)? != 0,
        seen_count: row.get::<_, i64>(12)? as u32,
    })
}
