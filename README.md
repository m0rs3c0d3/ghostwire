# ghostwire

Passive USB device fingerprinting and anomaly detection daemon for Linux, written in Rust.

ghostwire runs silently in the background, builds behavioral trust profiles of every USB device it sees, and alerts when something anomalous connects — a rogue HID injector, a BadUSB impersonator, a composite HID+storage attack device, or anything that doesn't match an established fingerprint.

---

## Why

USB attacks are underrated and under-defended on Linux desktops. The OS blindly trusts whatever enumerates on the bus. Existing tools like USBGuard operate on static allow/blocklists — they can't tell you when a device you've seen before suddenly has a different descriptor, or when your keyboard appeared on a port it's never used, or when a device connected at 3 AM.

ghostwire is different:

- **Behavioral fingerprinting** — SHA-256 of VID, PID, manufacturer, product string, device class, and interface count. Each device gets a fingerprint; changes to that fingerprint trigger `DESCRIPTOR_MISMATCH`.
- **Tamper-evident event log** — every event row hashes the previous row's hash, making offline log tampering detectable.
- **No cloud, no telemetry** — fully local. The only network activity is an optional user-configured webhook (planned for Phase 5).
- **Complementary to USBGuard** — ghostwire detects; USBGuard blocks. Use both.

---

## Threat Scenarios Covered

| Attack | Detection |
|---|---|
| Rubber Ducky / USB HID injection | `HID_FAST_ENUM` + `UNKNOWN_DEVICE` |
| BadUSB (VID/PID spoofing with altered descriptors) | `DESCRIPTOR_MISMATCH` |
| Composite attack device (HID + mass storage) | `COMPOSITE_HID_STORAGE` |
| Rogue device on an unattended machine | `ODD_HOURS` + `UNKNOWN_DEVICE` |
| Known device moved to unfamiliar port | `NEW_PORT` |
| Firmware-modified trusted device | `DESCRIPTOR_MISMATCH` + `NEW_INTERFACE_COUNT` |

---

## Anomaly Flags

| Flag | Trigger | Score |
|---|---|---|
| `UNKNOWN_DEVICE` | Fingerprint never seen before | +30 |
| `DESCRIPTOR_MISMATCH` | Known VID/PID but different descriptor strings | +50 |
| `NEW_PORT` | Known device appearing on a new physical port | +10 |
| `HID_FAST_ENUM` | HID device bound in under 100 ms | +40 |
| `COMPOSITE_HID_STORAGE` | Both HID and mass-storage interfaces exposed | +60 |
| `NEW_INTERFACE_COUNT` | Interface count changed from known profile | +40 |
| `ODD_HOURS` | Event between 01:00–04:59 local time | +10 |
| `SERIAL_MISSING` | HID or storage device with no serial number | +15 |

**Score thresholds:**
- `0–20` → log only
- `21–50` → log + warn
- `51+` → log + error + desktop notification (if `--notify` is set)

---

## Requirements

- Linux (Ubuntu 22.04+, Debian 12+, other distros with udev)
- Rust stable toolchain (`rustup` recommended)
- Root or `CAP_NET_ADMIN` capability (required for the netlink uevent socket)
- `libnotify` / a running notification daemon (only if using `--features desktop-notify`)

---

## Build

```bash
git clone https://github.com/m0rs3c0d3/ghostwire
cd ghostwire

# Standard build
cargo build --release

# With desktop notifications
cargo build --release --features desktop-notify
```

The binary lands at `target/release/ghostwire`.

---

## Quick Start

```bash
# Run in the foreground (human-readable output, great for testing)
sudo ./target/release/ghostwire --foreground

# Plug in a USB device — you'll see something like:
#  INFO USB event action=add vid=05ac pid=12a8 product=Some("iPhone") score=30 flags=["UNKNOWN_DEVICE"]

# Second plug: fingerprint matches, score drops to 0
#  INFO USB event action=add vid=05ac pid=12a8 product=Some("iPhone") score=0 flags=[]
```

---

## Usage

```
ghostwire [OPTIONS] [COMMAND]

Options:
      --db-path <DB_PATH>    Path to the SQLite trust-store database
      --log-path <LOG_PATH>  Path to the JSON event log
  -f, --foreground           Human-readable log output (vs compact structured)
      --notify               Send desktop notifications for score > 50
  -h, --help                 Print help
  -V, --version              Print version

Commands:
  daemon   Run the daemon (default)
  list     List all known device profiles in the trust store
  show     Show full details for a single device profile
  trust    Mark a device fingerprint as explicitly trusted
  untrust  Remove the trusted flag from a device
  forget   Remove a device profile from the trust store entirely
  history  Show recent USB events with anomaly scores
  export   Export the full event log as JSON to stdout
  verify   Verify the integrity of the tamper-evident event chain
```

### Examples

```bash
# List all known devices
sudo ghostwire list

# Show full details for a device (supports fingerprint prefix matching)
sudo ghostwire show a3f1c2

# Mark a device as trusted
sudo ghostwire trust a3f1c2b9e8d74f50...

# Remove trust from a device without deleting its history
sudo ghostwire untrust a3f1c2b9e8d74f50...

# Remove a device from the trust store (will show as UNKNOWN_DEVICE on next plug)
sudo ghostwire forget a3f1c2b9e8d74f50...

# Show the last 50 events with scores
sudo ghostwire history --limit 50

# Export full event log as JSON
sudo ghostwire export > events.json

# Verify the tamper-evident event chain (exits 0 = intact, 1 = broken)
sudo ghostwire verify

# Run with desktop notifications enabled (requires desktop-notify feature)
sudo ghostwire --notify

# Custom database and log paths
sudo ghostwire --db-path /opt/ghostwire/db --log-path /opt/ghostwire/events.log
```

---

## Config File

ghostwire reads persistent defaults from these locations (user config takes priority over system config):

| Path | Scope |
|---|---|
| `/etc/ghostwire/config.toml` | System-wide |
| `~/.config/ghostwire/config.toml` | Per-user (XDG-aware) |

CLI flags always override config file values.

**Example `/etc/ghostwire/config.toml`:**

```toml
db_path  = "/var/lib/ghostwire/devices.db"
log_path = "/var/log/ghostwire/events.log"
notify   = false
```

All keys are optional. Unknown keys are silently ignored.

---

## Install as a systemd Service

```bash
# Copy binary
sudo cp target/release/ghostwire /usr/local/bin/ghostwire

# Install unit file
sudo cp ghostwire.service /etc/systemd/system/ghostwire.service

# Create data directories
sudo mkdir -p /var/lib/ghostwire /var/log/ghostwire

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now ghostwire

# Check status
sudo systemctl status ghostwire
sudo journalctl -u ghostwire -f
```

---

## Architecture

```
netlink uevent socket (kernel)
        │
        ▼
  collector.rs          — OS thread; binds NETLINK_KOBJECT_UEVENT, parses
                          null-delimited uevent messages, enriches from sysfs,
                          emits UsbEvent structs via tokio mpsc channel
        │
        ▼
  profiler.rs           — SQLite trust store; computes SHA-256 fingerprint;
                          tracks add→bind timing for HID_FAST_ENUM; scores
                          all 8 anomaly flags; writes tamper-evident event log
        │
        ▼
  alerter.rs            — Routes by score: tracing log, JSON file append,
                          optional desktop notification (libnotify)
        │
        ▼
  main.rs               — Tokio async runtime; clap CLI (daemon / list /
                          trust / history / export subcommands)
```

### SQLite Schema

**`devices`** — one row per unique device fingerprint:

| Column | Description |
|---|---|
| `fingerprint` | SHA-256(VID\|PID\|mfr\|product\|class\|iface_count) |
| `vid`, `pid` | USB vendor/product IDs in lowercase hex |
| `manufacturer`, `product`, `serial` | USB descriptor strings |
| `device_class` | bDeviceClass from sysfs |
| `interface_count` | bNumInterfaces |
| `port_path` | Physical port path from uevent devpath |
| `first_seen`, `last_seen` | RFC3339 timestamps |
| `trusted` | 1 = explicitly trusted via `ghostwire trust` |
| `seen_count` | Total plug events for this fingerprint |

**`events`** — tamper-evident log of every USB event:

| Column | Description |
|---|---|
| `fingerprint` | Device fingerprint at event time |
| `raw_json` | Full serialized `UsbEvent` |
| `anomaly_score`, `anomaly_flags` | Score and triggered flags |
| `prev_hash` | `row_hash` of the previous row |
| `row_hash` | SHA-256(timestamp\|fingerprint\|score\|prev_hash) |

The `prev_hash` chain means that deleting or modifying any historical row breaks all subsequent hashes — making log tampering detectable on export.

### Fingerprint Design

The fingerprint deliberately **excludes the serial number**. Serials can be spoofed or absent, making them unreliable as identity signals. Instead, the fingerprint captures the structural identity of the device: what it claims to be and how many interfaces it exposes. A BadUSB that changes its product string or adds a HID interface will generate a new fingerprint and trigger `DESCRIPTOR_MISMATCH` on the next plug.

---

## Development

```bash
# Run without root (falls back to in-memory DB, no netlink events)
cargo run -- --foreground

# Debug logging
RUST_LOG=ghostwire=debug cargo run -- --foreground

# Build with desktop notifications
cargo build --features desktop-notify
```

Kernel uevent events won't flow without root/`CAP_NET_ADMIN`, but the CLI subcommands (`list`, `history`, `export`, `trust`) work on any existing database without elevated privileges.

---

## Roadmap

| Phase | Status | Description |
|---|---|---|
| 1 | ✅ Done | Proof of life — netlink collector, structured USB event output |
| 2 | ✅ Done | Trust store — SQLite profiles, SHA-256 fingerprinting, tamper-evident log |
| 3 | ✅ Done | Full anomaly scoring — all 8 flags including `HID_FAST_ENUM` |
| 4 | ✅ Done | Daemon — CLI flags, desktop notifications, systemd unit |
| 5 | ✅ Done | Full management CLI (`show`, `untrust`, `forget`, `verify`), TOML config file |

---

## What ghostwire is NOT

- Not a firewall or blocking tool — use USBGuard for that
- Not a kernel module
- Not cloud-connected — there is no telemetry, no update check, no external calls
- Not a forensics tool, though the tamper-evident event log has forensic value

---

## License

MIT — see [LICENSE](LICENSE).
