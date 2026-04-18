//! Linux route lookup for the scanner
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pnet::datalink::NetworkInterface;

use crate::model::{ScannerError, ScannerExitCode};

const ROUTE_V4_PATH: &str = "/proc/net/route";
const ROUTE_V6_PATH: &str = "/proc/net/ipv6_route";

/// Route reader tied to one iface
#[derive(Debug, Clone)]
pub struct RouteTable {
    interface_name: String,
}

/// One IPv4 route row from procfs
#[derive(Debug, Clone)]
struct RouteV4Entry {
    interface_name: String,
    destination: u32,
    gateway: Ipv4Addr,
    mask: u32,
}

/// One IPv6 route row from procfs
#[derive(Debug, Clone)]
struct RouteV6Entry {
    interface_name: String,
    destination: Ipv6Addr,
    next_hop: Ipv6Addr,
    prefix_len: u32,
}

/// Route lookup bits
impl RouteTable {
    /// Hook the reader to one iface name
    pub fn new(interface: &NetworkInterface) -> Self {
        Self {
            interface_name: interface.name.clone(),
        }
    }

    /// Get the next hop for one IP
    pub fn gateway_for(&self, target: IpAddr) -> Result<IpAddr, ScannerError> {
        match target {
            IpAddr::V4(target) => self.gateway_v4(target).map(IpAddr::V4),
            IpAddr::V6(target) => self.gateway_v6(target).map(IpAddr::V6),
        }
    }

    /// Pick the best IPv4 next hop for this iface
    fn gateway_v4(&self, target: Ipv4Addr) -> Result<Ipv4Addr, ScannerError> {
        // IPv4 routes live here on Linux
        let route_data = fs::read_to_string(ROUTE_V4_PATH).map_err(|err| ScannerError {
            code: ScannerExitCode::Os,
            message: format!("Failed to read IPv4 routing table: {err}"),
        })?;

        let target_u32 = u32::from(target).to_le();
        let mut best: Option<(u32, Ipv4Addr)> = None;

        for entry in route_data.lines().skip(1).filter_map(RouteV4Entry::parse) {
            if entry.interface_name != self.interface_name {
                continue;
            }

            if (target_u32 & entry.mask) != (entry.destination & entry.mask) {
                continue;
            }

            let prefix_len = entry.mask.count_ones();
            match best {
                Some((best_prefix, _)) if best_prefix >= prefix_len => {}
                _ => best = Some((prefix_len, entry.gateway)),
            }
        }

        best.map(|(_, gateway)| gateway).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Os,
            message: format!("No IPv4 route found for {} on {}", target, self.interface_name),
        })
    }

    /// Pick the best IPv6 next hop for this iface
    fn gateway_v6(&self, target: Ipv6Addr) -> Result<Ipv6Addr, ScannerError> {
        // IPv6 routes live here on Linux
        let route_data = fs::read_to_string(ROUTE_V6_PATH).map_err(|err| ScannerError {
            code: ScannerExitCode::Os,
            message: format!("Failed to read IPv6 routing table: {err}"),
        })?;

        let target_bytes = target.octets();
        let mut best: Option<(u32, Ipv6Addr)> = None;

        for entry in route_data.lines().filter_map(RouteV6Entry::parse) {
            if entry.interface_name != self.interface_name {
                continue;
            }

            if !Self::prefix_matches(&target_bytes, &entry.destination, entry.prefix_len) {
                continue;
            }

            match best {
                Some((best_prefix, _)) if best_prefix >= entry.prefix_len => {}
                _ => best = Some((entry.prefix_len, entry.next_hop)),
            }
        }

        best.map(|(_, gateway)| gateway).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Os,
            message: format!("No IPv6 route found for {} on {}", target, self.interface_name),
        })
    }

    /// Check if an IPv6 addr matches a prefix
    fn prefix_matches(target: &[u8; 16], prefix: &Ipv6Addr, prefix_len: u32) -> bool {
        let prefix = prefix.octets();
        let full_bytes = (prefix_len / 8) as usize;
        let remaining_bits = (prefix_len % 8) as u8;

        if target[..full_bytes] != prefix[..full_bytes] {
            return false;
        }

        if remaining_bits == 0 {
            return true;
        }

        let mask = !((1u8 << (8 - remaining_bits)) - 1);
        (target[full_bytes] & mask) == (prefix[full_bytes] & mask)
    }
}

/// IPv4 procfs parsing bits
impl RouteV4Entry {
    /// Parse one IPv4 route row
    fn parse(line: &str) -> Option<Self> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            return None;
        }

        let destination = u32::from_str_radix(fields[1], 16).ok()?;
        let gateway = u32::from_str_radix(fields[2], 16).ok()?;
        let mask = u32::from_str_radix(fields[7], 16).ok()?;

        Some(Self {
            interface_name: fields[0].to_string(),
            destination,
            gateway: Ipv4Addr::from(u32::from_le(gateway)),
            mask,
        })
    }
}

/// IPv6 procfs parsing bits
impl RouteV6Entry {
    /// Parse one IPv6 route row
    fn parse(line: &str) -> Option<Self> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            return None;
        }

        Some(Self {
            interface_name: fields[9].to_string(),
            destination: Self::hex_ipv6(fields[0]).ok()?,
            prefix_len: u32::from_str_radix(fields[1], 16).ok()?,
            next_hop: Self::hex_ipv6(fields[4]).ok()?,
        })
    }

    /// Turn 32 hex chars into one IPv6 addr
    fn hex_ipv6(hex: &str) -> Result<Ipv6Addr, ScannerError> {
        if hex.len() != 32 {
            return Err(ScannerError {
                code: ScannerExitCode::Os,
                message: format!("Invalid IPv6 hex address length: {hex}"),
            });
        }

        let mut bytes = [0u8; 16];
        for idx in 0..16 {
            bytes[idx] = u8::from_str_radix(&hex[idx * 2..idx * 2 + 2], 16).map_err(|err| ScannerError {
                code: ScannerExitCode::Os,
                message: format!("Failed to parse IPv6 route address: {err}"),
            })?;
        }

        Ok(Ipv6Addr::from(bytes))
    }
}