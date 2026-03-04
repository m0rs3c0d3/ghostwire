use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Local, Timelike, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::models::{AnomalyFlag, AnomalyResult, DeviceProfile, UsbEvent};

/// How long to keep a pending-add record before discarding it (stale guard).
const PENDING_ADD_TTL: Duration = Duration::from_secs(30);

/// A HID or storage device that enumerated faster than this is suspicious.
const HID_FAST_ENUM_THRESHOLD: Duration = Duration::from_millis(100);

/// Maintains the SQLite trust store and computes anomaly scores.
pub struct Profiler {
    conn: Connection,
    /// Maps devpath → Instant of the most recent `add` event for that path.
    /// Used to compute add→bind elapsed time for HID_FAST_ENUM detection.
    pending_adds: HashMap<String, Instant>,
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
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        let profiler = Profiler {
            conn,
            pending_adds: HashMap::new(),
        };
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

    // -------------------------------------------------------------------------
    // Main event processing
    // -------------------------------------------------------------------------

    /// Process an incoming USB event: look up trust store, score anomalies,
    /// update the profile database, and append a tamper-evident log entry.
    pub fn process_event(
        &mut self,
        event: &UsbEvent,
    ) -> Result<AnomalyResult, Box<dyn std::error::Error>> {
        // Track add timestamps for HID_FAST_ENUM (Phase 3)
        if event.action == "add" {
            self.pending_adds
                .insert(event.port_path.clone(), Instant::now());
            self.evict_stale_pending();
        }

        // For bind events, pull the elapsed time since the corresponding add
        let add_elapsed: Option<Duration> = if event.action == "bind" {
            self.pending_adds
                .remove(&event.port_path)
                .map(|t| t.elapsed())
        } else {
            None
        };

        // Remove events are logged but not scored
        if event.action == "remove" {
            self.pending_adds.remove(&event.port_path);
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
        let exact_match = self.get_profile_by_fingerprint(&fingerprint)?;

        // If no exact match, look for VID+PID match (potential DESCRIPTOR_MISMATCH)
        let vid_pid_matches: Vec<DeviceProfile> = if exact_match.is_none() {
            self.get_profiles_by_vid_pid(&event.vid, &event.pid)?
        } else {
            vec![]
        };

        let (score, flags) =
            score_event(event, &exact_match, &vid_pid_matches, add_elapsed);

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
    // Trust store management (Phase 4 CLI)
    // -------------------------------------------------------------------------

    /// Mark a fingerprint as explicitly trusted. Returns `true` if the
    /// fingerprint was found and updated, `false` if it doesn't exist.
    pub fn trust_device(
        &mut self,
        fingerprint: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let rows = self.conn.execute(
            "UPDATE devices SET trusted = 1 WHERE fingerprint = ?1",
            params![fingerprint],
        )?;
        Ok(rows > 0)
    }

    /// Return all known device profiles ordered by last seen (newest first).
    pub fn list_devices(&self) -> Result<Vec<DeviceProfile>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT fingerprint, vid, pid, manufacturer, product, serial,
                    device_class, interface_count, port_path,
                    first_seen, last_seen, trusted, seen_count
               FROM devices
              ORDER BY last_seen DESC",
        )?;
        let profiles = stmt
            .query_map([], row_to_profile)?
            .filter_map(|r| r.ok())
            .collect();
        Ok(profiles)
    }

    /// Mark a fingerprint as not trusted. Returns `true` if found and updated.
    pub fn untrust_device(
        &mut self,
        fingerprint: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let rows = self.conn.execute(
            "UPDATE devices SET trusted = 0 WHERE fingerprint = ?1",
            params![fingerprint],
        )?;
        Ok(rows > 0)
    }

    /// Remove a device profile entirely from the trust store.
    ///
    /// Historical events that reference this fingerprint are kept for audit
    /// purposes — only the profile row is deleted.
    ///
    /// Returns `true` if a row was deleted, `false` if the fingerprint was not
    /// found.
    pub fn forget_device(
        &mut self,
        fingerprint: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let rows = self.conn.execute(
            "DELETE FROM devices WHERE fingerprint = ?1",
            params![fingerprint],
        )?;
        Ok(rows > 0)
    }

    /// Walk every event row in order and verify the SHA-256 chain.
    ///
    /// Returns a `ChainVerifyResult` with a list of broken links (if any).
    /// An empty `broken` list means the log is intact.
    pub fn verify_chain(&self) -> Result<ChainVerifyResult, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, fingerprint, anomaly_score, prev_hash, row_hash
               FROM events
              ORDER BY id ASC",
        )?;

        let rows: Vec<(u64, String, String, u32, Option<String>, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get(1)?,
                    row.get(2)?,
                    row.get::<_, i64>(3)? as u32,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        let total = rows.len() as u64;
        let mut broken: Vec<BrokenLink> = Vec::new();
        let mut expected_prev: &str = "genesis";

        for (id, timestamp, fingerprint, score, prev_hash, row_hash) in &rows {
            // Check that prev_hash matches what we computed from the prior row
            let stored_prev = prev_hash.as_deref().unwrap_or("genesis");
            if stored_prev != expected_prev {
                broken.push(BrokenLink {
                    event_id: *id,
                    reason: format!(
                        "prev_hash mismatch: expected '{}', got '{}'",
                        expected_prev, stored_prev
                    ),
                });
            }

            // Recompute and verify the row's own hash
            let expected_hash =
                chain_hash(timestamp, fingerprint, *score, stored_prev);
            if &expected_hash != row_hash {
                broken.push(BrokenLink {
                    event_id: *id,
                    reason: format!(
                        "row_hash mismatch: expected '{}', stored '{}'",
                        expected_hash, row_hash
                    ),
                });
            }

            expected_prev = row_hash;
        }

        Ok(ChainVerifyResult { total, broken })
    }

    /// Return recent events from the log, newest first, limited to `limit` rows.
    pub fn recent_events(
        &self,
        limit: u32,
    ) -> Result<Vec<EventRow>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, action, fingerprint, anomaly_score, anomaly_flags
               FROM events
              ORDER BY id DESC
              LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok(EventRow {
                    id: row.get::<_, i64>(0)? as u64,
                    timestamp: row.get(1)?,
                    action: row.get(2)?,
                    fingerprint: row.get(3)?,
                    anomaly_score: row.get::<_, i64>(4)? as u32,
                    anomaly_flags: row.get(5)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Dump all events as JSON for export / SIEM ingestion.
    pub fn export_events(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT raw_json, anomaly_score, anomaly_flags, row_hash, prev_hash
               FROM events
              ORDER BY id ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(raw, score, flags, row_hash, prev_hash)| {
                let mut v: serde_json::Value = serde_json::from_str(&raw).ok()?;
                v["anomaly_score"] = serde_json::json!(score);
                v["anomaly_flags"] =
                    serde_json::from_str(flags.as_deref().unwrap_or("[]")).unwrap_or_default();
                v["row_hash"] = serde_json::json!(row_hash);
                v["prev_hash"] = serde_json::json!(prev_hash);
                Some(v)
            })
            .collect();
        Ok(rows)
    }

    // -------------------------------------------------------------------------
    // Trust store queries (private)
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

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// Remove pending-add entries that are older than PENDING_ADD_TTL.
    fn evict_stale_pending(&mut self) {
        self.pending_adds
            .retain(|_, t| t.elapsed() < PENDING_ADD_TTL);
    }
}

// =============================================================================
// Anomaly scoring (Phase 3 — all 8 flags)
// =============================================================================

fn score_event(
    event: &UsbEvent,
    exact_match: &Option<DeviceProfile>,
    vid_pid_matches: &[DeviceProfile],
    add_elapsed: Option<Duration>,
) -> (u32, Vec<AnomalyFlag>) {
    let mut flags: Vec<AnomalyFlag> = Vec::new();

    // ── UNKNOWN_DEVICE (+30) ─────────────────────────────────────────────────
    // Fingerprint never seen AND no VID/PID history at all.
    if exact_match.is_none() && vid_pid_matches.is_empty() {
        flags.push(AnomalyFlag::UnknownDevice);
    }

    // ── DESCRIPTOR_MISMATCH (+50) ────────────────────────────────────────────
    // VID/PID known before but this fingerprint (descriptor combo) is new.
    if exact_match.is_none() && !vid_pid_matches.is_empty() {
        flags.push(AnomalyFlag::DescriptorMismatch);
    }

    if let Some(ref profile) = exact_match {
        // ── NEW_PORT (+10) ───────────────────────────────────────────────────
        if profile.port_path != event.port_path {
            flags.push(AnomalyFlag::NewPort);
        }

        // ── NEW_INTERFACE_COUNT (+40) ────────────────────────────────────────
        if let (Some(stored), Some(current)) =
            (profile.interface_count, event.interface_count)
        {
            if stored != current {
                flags.push(AnomalyFlag::NewInterfaceCount);
            }
        }
    }

    // ── Interface class helpers ───────────────────────────────────────────────
    let has_hid = is_hid(event);
    let has_storage = is_storage(event);

    // ── COMPOSITE_HID_STORAGE (+60) ──────────────────────────────────────────
    if has_hid && has_storage {
        flags.push(AnomalyFlag::CompositeHidStorage);
    }

    // ── HID_FAST_ENUM (+40) ──────────────────────────────────────────────────
    // Only meaningful on `bind` events where we have an add→bind duration.
    // A HID device that goes from add to driver-bind in under 100 ms is
    // suspiciously fast — legitimate HIDs wait for host enumeration.
    if event.action == "bind" && has_hid {
        if let Some(elapsed) = add_elapsed {
            if elapsed < HID_FAST_ENUM_THRESHOLD {
                flags.push(AnomalyFlag::HidFastEnum);
            }
        }
    }

    // ── ODD_HOURS (+10) ──────────────────────────────────────────────────────
    let local_hour = Local::now().hour();
    if (1..5).contains(&local_hour) {
        flags.push(AnomalyFlag::OddHours);
    }

    // ── SERIAL_MISSING (+15) ─────────────────────────────────────────────────
    // HID and mass-storage devices are expected to carry a serial number.
    // Legitimate devices almost always have one; BadUSBs often don't bother.
    if (has_hid || has_storage) && event.serial.is_none() {
        flags.push(AnomalyFlag::SerialMissing);
    }

    let score: u32 = flags.iter().map(|f| f.score()).sum();

    debug!(
        action = %event.action,
        vid    = %event.vid,
        pid    = %event.pid,
        score  = score,
        flags  = ?flags.iter().map(|f| f.as_str()).collect::<Vec<_>>(),
        "Anomaly score computed"
    );

    (score, flags)
}

// =============================================================================
// Public helpers
// =============================================================================

/// Compute the device fingerprint: SHA-256 of VID, PID, manufacturer, product,
/// device class, and interface count — serial intentionally excluded (spoofable).
pub fn compute_fingerprint(event: &UsbEvent) -> String {
    let mut h = Sha256::new();
    for field in &[
        event.vid.as_str(),
        event.pid.as_str(),
        event.manufacturer.as_deref().unwrap_or(""),
        event.product.as_deref().unwrap_or(""),
        event.device_class.as_deref().unwrap_or(""),
    ] {
        h.update(field.as_bytes());
        h.update(b"\x00");
    }
    h.update(
        event
            .interface_count
            .map(|c| c.to_string())
            .unwrap_or_default()
            .as_bytes(),
    );
    hex::encode(h.finalize())
}

/// A lightweight summary row from the `events` table used by the `history` command.
#[derive(Debug)]
pub struct EventRow {
    pub id: u64,
    pub timestamp: String,
    pub action: String,
    pub fingerprint: String,
    pub anomaly_score: u32,
    pub anomaly_flags: Option<String>,
}

/// Result of a `verify_chain` run.
#[derive(Debug)]
pub struct ChainVerifyResult {
    /// Total number of event rows examined.
    pub total: u64,
    /// Any rows where the hash chain is broken. Empty means the log is intact.
    pub broken: Vec<BrokenLink>,
}

impl ChainVerifyResult {
    pub fn is_ok(&self) -> bool {
        self.broken.is_empty()
    }
}

/// Describes a single broken link in the event-chain.
#[derive(Debug)]
pub struct BrokenLink {
    pub event_id: u64,
    pub reason: String,
}

// =============================================================================
// Private helpers
// =============================================================================

/// True if the event's interface list or device class indicates HID (class 03).
fn is_hid(event: &UsbEvent) -> bool {
    event
        .interfaces
        .iter()
        .any(|i| i.class.trim_start_matches('0') == "3")
        || event
            .device_class
            .as_deref()
            .map(|c| c.trim_start_matches('0') == "3")
            .unwrap_or(false)
}

/// True if the event exposes a mass-storage interface (class 08).
fn is_storage(event: &UsbEvent) -> bool {
    event
        .interfaces
        .iter()
        .any(|i| i.class.trim_start_matches('0') == "8")
        || event
            .device_class
            .as_deref()
            .map(|c| c.trim_start_matches('0') == "8")
            .unwrap_or(false)
}

/// SHA-256(timestamp | fingerprint | score | prev_hash) for the event chain.
fn chain_hash(timestamp: &str, fingerprint: &str, score: u32, prev_hash: &str) -> String {
    let mut h = Sha256::new();
    for part in &[timestamp, fingerprint, &score.to_string(), prev_hash] {
        h.update(part.as_bytes());
        h.update(b"\x00");
    }
    hex::encode(h.finalize())
}

/// Map a `rusqlite` row to a `DeviceProfile`.
fn row_to_profile(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceProfile> {
    let first_seen: String = row.get(9)?;
    let last_seen: String = row.get(10)?;

    let parse_dt = |s: &str| -> DateTime<Utc> {
        s.parse::<DateTime<Utc>>().unwrap_or_else(|_| Utc::now())
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
