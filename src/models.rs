use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A raw USB event received from the kernel via netlink uevent socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbEvent {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub vid: String,
    pub pid: String,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    pub device_class: Option<String>,
    pub subclass: Option<String>,
    pub protocol: Option<String>,
    pub interface_count: Option<u8>,
    pub port_path: String,
    pub bus_num: Option<String>,
    pub dev_num: Option<String>,
    pub interfaces: Vec<InterfaceDescriptor>,
}

/// Per-interface descriptor, read from sysfs when available.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceDescriptor {
    pub class: String,
    pub subclass: String,
    pub protocol: String,
}

/// A trusted device profile stored in the SQLite trust store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub fingerprint: String,
    pub vid: String,
    pub pid: String,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    pub device_class: Option<String>,
    pub interface_count: Option<u8>,
    pub port_path: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub trusted: bool,
    pub seen_count: u32,
}

/// Output of the profiler for a single event: anomaly score, triggered flags,
/// and the closest matching known profile (if any).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    pub event: UsbEvent,
    pub score: u32,
    pub flags: Vec<AnomalyFlag>,
    pub known_profile: Option<DeviceProfile>,
}

/// All possible anomaly flags with their descriptions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnomalyFlag {
    /// Device has never been seen before. (+30)
    UnknownDevice,
    /// VID/PID is known but descriptor strings differ — possible BadUSB. (+50)
    DescriptorMismatch,
    /// Known device appeared on a different physical port. (+10)
    NewPort,
    /// HID device enumerated suspiciously fast (< 100 ms). (+40)
    HidFastEnum,
    /// Device exposes both HID and mass storage interfaces. (+60)
    CompositeHidStorage,
    /// Interface count changed from the known profile. (+40)
    NewInterfaceCount,
    /// Event occurred between 01:00–05:00 local time. (+10)
    OddHours,
    /// Device class expects a serial number but none was provided. (+15)
    SerialMissing,
}

impl AnomalyFlag {
    pub fn score(&self) -> u32 {
        match self {
            AnomalyFlag::UnknownDevice => 30,
            AnomalyFlag::DescriptorMismatch => 50,
            AnomalyFlag::NewPort => 10,
            AnomalyFlag::HidFastEnum => 40,
            AnomalyFlag::CompositeHidStorage => 60,
            AnomalyFlag::NewInterfaceCount => 40,
            AnomalyFlag::OddHours => 10,
            AnomalyFlag::SerialMissing => 15,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyFlag::UnknownDevice => "UNKNOWN_DEVICE",
            AnomalyFlag::DescriptorMismatch => "DESCRIPTOR_MISMATCH",
            AnomalyFlag::NewPort => "NEW_PORT",
            AnomalyFlag::HidFastEnum => "HID_FAST_ENUM",
            AnomalyFlag::CompositeHidStorage => "COMPOSITE_HID_STORAGE",
            AnomalyFlag::NewInterfaceCount => "NEW_INTERFACE_COUNT",
            AnomalyFlag::OddHours => "ODD_HOURS",
            AnomalyFlag::SerialMissing => "SERIAL_MISSING",
        }
    }
}

impl std::fmt::Display for AnomalyFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
