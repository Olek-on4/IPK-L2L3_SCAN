//! Formatting functions for more meaningful errors and correct format.
use pnet::util::MacAddr;
use std::net::IpAddr;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use pnet::util::MacAddr;

    use crate::model::ScanMatch;

    #[test]
    fn mac_format() {
        assert_eq!(format_mac(MacAddr::new(0, 1, 2, 10, 11, 12)), "(00-01-02-0a-0b-0c)");
        assert_eq!(format_mac(MacAddr::new(0xff, 0, 0x10, 0xab, 0xcd, 0xef)), "(ff-00-10-ab-cd-ef)");
    }

    #[test]
    fn scan_lines() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let scan_match = ScanMatch {
            mac_addr: Some(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff)),
            icmp_responded: true,
        };

        assert_eq!(
            format_scan_result(&ipv4, Some(&scan_match)),
            "192.168.1.10 arp OK (aa-bb-cc-dd-ee-ff), icmpv4 OK"
        );

        let ipv6 = IpAddr::V6(Ipv6Addr::from_str("fd00:cafe::1").unwrap());
        assert_eq!(format_scan_result(&ipv6, None), "fd00:cafe::1 ndp FAIL, icmpv6 FAIL");

        let ipv4_missing_mac = ScanMatch {
            mac_addr: None,
            icmp_responded: false,
        };
        assert_eq!(
            format_scan_result(&ipv4, Some(&ipv4_missing_mac)),
            "192.168.1.10 arp FAIL, icmpv4 FAIL"
        );
    }
}
