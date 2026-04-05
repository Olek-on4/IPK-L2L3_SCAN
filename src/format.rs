//! Formatting functions for more meaningful errors and correct format.
use std::net::IpAddr;
use pnet::util::MacAddr;

use crate::model::{ScanMatch, ScannerExitCode};

/// Format MAC address in the project output style.
pub fn format_mac(mac_addr: MacAddr) -> String {
    format!(
        "({:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x})",
        mac_addr.0, mac_addr.1, mac_addr.2, mac_addr.3, mac_addr.4, mac_addr.5
    )
}

/// Helper to keep formatters and tests in sync.
pub fn format_exit(code: ScannerExitCode, message: impl std::fmt::Display) -> String {
    format!("{}: {}", code.meaning(), message)
}

/// Format one scan result line.
pub fn format_scan_result(addr: &IpAddr, scan_match: Option<&ScanMatch>) -> String {
    let proto = if addr.is_ipv4() { "arp" } else { "ndp" };
    let icmp = if addr.is_ipv4() { "4" } else { "6" };

    match scan_match {
        Some(matched) => match matched.mac_addr {
            Some(mac) => format!(
                "{} {} OK {}, icmpv{} {}",
                addr,
                proto,
                format_mac(mac),
                icmp,
                if matched.icmp_responded { "OK" } else { "FAIL" }
            ),
            None => format!("{} {} FAIL, icmpv{} FAIL", addr, proto, icmp),
        },
        None => format!("{} {} FAIL, icmpv{} FAIL", addr, proto, icmp),
    }
}
