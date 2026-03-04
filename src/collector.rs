use std::collections::HashMap;
use std::fs;
use std::path::Path;

use chrono::Utc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::models::{InterfaceDescriptor, UsbEvent};

// NETLINK_KOBJECT_UEVENT = 15 (from <linux/netlink.h>)
const NETLINK_KOBJECT_UEVENT: isize = 15;

/// Spawn a background OS thread that binds a netlink uevent socket and
/// forwards structured `UsbEvent`s into the provided channel.
///
/// Requires `CAP_NET_ADMIN` or root. If the socket cannot be opened the
/// thread logs the error and exits silently — the channel will simply never
/// receive events.
pub fn spawn_collector(tx: mpsc::Sender<UsbEvent>) {
    std::thread::spawn(move || {
        use netlink_sys::{Socket, SocketAddr};

        let mut socket = match Socket::new(NETLINK_KOBJECT_UEVENT) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "Failed to create netlink uevent socket (are you running as root?): {}",
                    e
                );
                return;
            }
        };

        // pid = 0 lets the kernel assign one; groups = 1 = kernel uevent multicast
        let sa = SocketAddr::new(0, 1);
        if let Err(e) = socket.bind(&sa) {
            error!("Failed to bind netlink uevent socket: {}", e);
            return;
        }

        info!("USB event collector started — listening on netlink uevent socket");

        let mut buf = vec![0u8; 65_536];

        loop {
            match socket.recv_from(&mut buf, 0) {
                Ok((n, _)) => {
                    if let Some(event) = parse_uevent(&buf[..n]) {
                        if tx.blocking_send(event).is_err() {
                            warn!("Event channel closed — collector shutting down");
                            break;
                        }
                    }
                }
                Err(e) => {
                    error!("Netlink recv error: {}", e);
                }
            }
        }
    });
}

/// Parse a raw uevent message (null-byte-separated strings) into a `UsbEvent`.
///
/// Returns `None` if the message is not a USB device-level event or cannot be
/// parsed.
fn parse_uevent(buf: &[u8]) -> Option<UsbEvent> {
    // Messages are null-byte-delimited UTF-8 strings.
    // First record: "ACTION@DEVPATH"
    // Remaining records: "KEY=VALUE"
    let parts: Vec<&[u8]> = buf
        .split(|&b| b == 0)
        .filter(|p| !p.is_empty())
        .collect();

    if parts.is_empty() {
        return None;
    }

    // Parse the header: "add@/devices/..."
    let header = std::str::from_utf8(parts[0]).ok()?;
    let (action_raw, devpath) = header.split_once('@')?;
    let action = action_raw.to_lowercase();

    if !matches!(action.as_str(), "add" | "change" | "bind" | "remove") {
        return None;
    }

    // Parse remaining key=value pairs
    let mut kv: HashMap<&str, &str> = HashMap::new();
    for part in &parts[1..] {
        if let Ok(s) = std::str::from_utf8(part) {
            if let Some((k, v)) = s.split_once('=') {
                kv.insert(k, v);
            }
        }
    }

    // Only process USB subsystem, device-level events (not per-interface events)
    if kv.get("SUBSYSTEM").copied() != Some("usb") {
        return None;
    }
    if kv.get("DEVTYPE").copied() != Some("usb_device") {
        return None;
    }

    // PRODUCT="VID/PID/bcdDevice" — all values are hex without the 0x prefix
    let (vid, pid) = match kv.get("PRODUCT") {
        Some(product) => {
            let mut it = product.splitn(3, '/');
            let vid_raw = it.next().unwrap_or("0000");
            let pid_raw = it.next().unwrap_or("0000");
            let vid = format!(
                "{:04x}",
                u32::from_str_radix(vid_raw, 16).unwrap_or(0)
            );
            let pid = format!(
                "{:04x}",
                u32::from_str_radix(pid_raw, 16).unwrap_or(0)
            );
            (vid, pid)
        }
        None => return None,
    };

    // TYPE="class/subclass/protocol" — decimal values
    let (uevent_class, uevent_subclass, uevent_protocol) =
        match kv.get("TYPE") {
            Some(t) => {
                let mut it = t.splitn(3, '/');
                (
                    it.next().map(str::to_string),
                    it.next().map(str::to_string),
                    it.next().map(str::to_string),
                )
            }
            None => (None, None, None),
        };

    let sysfs_path = format!("/sys{}", devpath);

    // Enrich with sysfs attributes (more reliable than uevent strings alone)
    let manufacturer = read_sysfs(&sysfs_path, "manufacturer");
    let product_str = read_sysfs(&sysfs_path, "product");
    let serial = read_sysfs(&sysfs_path, "serial");

    let device_class = read_sysfs(&sysfs_path, "bDeviceClass").or(uevent_class);
    let subclass = read_sysfs(&sysfs_path, "bDeviceSubClass").or(uevent_subclass);
    let protocol = read_sysfs(&sysfs_path, "bDeviceProtocol").or(uevent_protocol);

    let interface_count = read_sysfs(&sysfs_path, "bNumInterfaces")
        .and_then(|s| s.trim().parse::<u8>().ok());

    let bus_num = read_sysfs(&sysfs_path, "busnum")
        .or_else(|| kv.get("BUSNUM").map(|s| s.to_string()));
    let dev_num = read_sysfs(&sysfs_path, "devnum")
        .or_else(|| kv.get("DEVNUM").map(|s| s.to_string()));

    let interfaces = if action != "remove" {
        read_interface_descriptors(&sysfs_path)
    } else {
        vec![]
    };

    debug!(
        action = %action,
        vid = %vid,
        pid = %pid,
        devpath = %devpath,
        "Parsed USB uevent"
    );

    Some(UsbEvent {
        timestamp: Utc::now(),
        action,
        vid,
        pid,
        manufacturer,
        product: product_str,
        serial,
        device_class,
        subclass,
        protocol,
        interface_count,
        port_path: devpath.to_string(),
        bus_num,
        dev_num,
        interfaces,
    })
}

/// Read a single sysfs attribute file, trimming whitespace.
fn read_sysfs(sysfs_path: &str, attr: &str) -> Option<String> {
    let path = Path::new(sysfs_path).join(attr);
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Enumerate interface descriptor sub-directories under a device's sysfs path.
///
/// Interface directories match the pattern `<bus>-<port>:<config>.<iface>`,
/// e.g., `1-1:1.0`, `2-3.1:1.0`. Each directory exposes `bInterfaceClass`,
/// `bInterfaceSubClass`, and `bInterfaceProtocol` files.
fn read_interface_descriptors(sysfs_path: &str) -> Vec<InterfaceDescriptor> {
    let mut interfaces = Vec::new();

    let dir = match fs::read_dir(sysfs_path) {
        Ok(d) => d,
        Err(_) => return interfaces,
    };

    for entry in dir.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Interface config directories contain both ':' and '.'
        // e.g. "1-1:1.0" — device dirs (e.g. "1-1") do not have a colon
        if !name_str.contains(':') || !name_str.contains('.') {
            continue;
        }

        let iface_path = entry.path().to_string_lossy().to_string();
        let class =
            read_sysfs(&iface_path, "bInterfaceClass").unwrap_or_else(|| "00".to_string());
        let subclass = read_sysfs(&iface_path, "bInterfaceSubClass")
            .unwrap_or_else(|| "00".to_string());
        let protocol = read_sysfs(&iface_path, "bInterfaceProtocol")
            .unwrap_or_else(|| "00".to_string());

        interfaces.push(InterfaceDescriptor {
            class,
            subclass,
            protocol,
        });
    }

    interfaces
}
