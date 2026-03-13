# ghostwire

> **Passive USB device fingerprinting and anomaly detection daemon for Linux.**  
> You'll know what plugged in before your OS does.

---

## Threat Context

USB-based attacks are physical-layer threats that most endpoint security completely ignores. BadUSB firmware implants, HID injection devices, malicious charging cables — they all look like legitimate hardware to the kernel. By the time your EDR sees suspicious process activity, the payload has already run.

Ghostwire sits below that. It watches the hardware enumeration layer.

---

## What It Does

Ghostwire is a passive daemon written in Rust that fingerprints USB devices at enumeration time, builds a behavioral baseline of known-good devices, and triggers alerts when anomalous hardware appears. No kernel module required. No modification to your USB stack. Silent by default.

- **Passive fingerprinting** — captures device descriptors, vendor/product IDs, serial numbers, and enumeration timing
- **Behavioral baselining** — learns what "normal" looks like for your environment
- **Anomaly detection** — flags new devices, descriptor mismatches, and HID devices that appear in unexpected contexts
- **Rust daemon** — memory-safe, minimal attack surface, runs as an unprivileged service
- **Structured logging** — JSON output for SIEM ingestion or local alerting pipelines

---

## Attack Surface Coverage

| Attack Type | Example | Detection Signal |
|-------------|---------|-----------------|
| BadUSB / Firmware implant | Reprogrammed microcontroller spoofing HID | Descriptor fingerprint mismatch |
| HID Injection | USB Rubber Ducky, O.MG Cable | Unexpected HID device in known-clean context |
| Malicious charging cable | O.MG cable, OMG Plug | New device on trusted port profile |
| Device cloning | Spoofed serial + VID/PID | Timing anomaly on enumeration |
| Persistence via USB boot | Bootable implant hardware | Device class unexpected at runtime |

---

## Architecture

```
                    USB Bus Events
                         │
                    udev monitor
                         │
┌────────────────────────▼────────────────────────┐
│              ghostwire daemon (Rust)            │
│                                                  │
│  ┌──────────────┐      ┌──────────────────────┐ │
│  │  Fingerprint │      │   Baseline Store     │ │
│  │  Extractor   │─────▶│  (device profiles)   │ │
│  └──────────────┘      └──────────┬───────────┘ │
│                                   │ compare      │
│  ┌──────────────────────────────◄─┘             │
│  │       Anomaly Classifier                     │
│  │  (new device / mismatch / HID context)       │
│  └──────────────────┬───────────────────────────┘
│                     │                            │
└─────────────────────┼────────────────────────────┘
                      │
           ┌──────────┴──────────┐
           │                     │
      JSON Alert              syslog /
      (stdout)               webhook
```

---

## Quick Start

```bash
# Requirements: Rust stable, Linux, udev
git clone https://github.com/m0rs3c0d3/ghostwire
cd ghostwire
cargo build --release

# Enroll your known-good devices (builds baseline)
sudo ./target/release/ghostwire --enroll

# Run in detection mode
sudo ./target/release/ghostwire --watch
```

---

## Alert Format

```json
{
  "timestamp": "2026-03-12T04:22:11Z",
  "event": "anomaly_detected",
  "severity": "high",
  "device": {
    "vendor_id": "0x05ac",
    "product_id": "0x0259",
    "serial": "UNKNOWN",
    "class": "HID"
  },
  "reason": "HID device on port with no prior HID history",
  "action": "alert"
}
```

---

## Deployment

Ghostwire runs as a `systemd` service. A sample unit file is included. Alerts pipe to stdout (JSON) or syslog — feed directly into Wazuh, Elastic, or any webhook-capable SIEM.

## License

MIT

---

*Part of the [m0rs3c0d3](https://github.com/m0rs3c0d3) security tooling portfolio.*
