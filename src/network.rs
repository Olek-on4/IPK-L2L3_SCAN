//! Networking related helpers that are not strictly Scanner related.
use std::net::Ipv6Addr;
use std::sync::mpsc::Sender;
use std::thread;

use ipnet::IpNet;
use pnet::util::MacAddr;
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use crate::model::{ControlMessage, ScannerError, ScannerExitCode};

/// Construct new IPv6 NS multicast address from target.
pub fn new_ns_addr(target_ip: &Ipv6Addr) -> Ipv6Addr {
    let target_bytes = target_ip.octets();
    Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | target_bytes[13] as u16,
        ((target_bytes[14] as u16) << 8) | target_bytes[15] as u16,
    )
}

/// Construct new NS MAC address from target.
pub fn new_ns_mac(target_ip: &Ipv6Addr) -> MacAddr {
    let target = target_ip.octets();
    MacAddr::new(0x33, 0x33, 0xff, target[13], target[14], target[15])
}

/// Calculate scannable address count from network.
pub fn get_net_size(net: &IpNet) -> u128 {
    let host_bits: u32;

    match net {
        IpNet::V4(net) => {
            host_bits = 32 - net.prefix_len() as u32;
            let total = 1u128 << host_bits;
            if net.prefix_len() >= 31 {
                total
            } else {
                total.saturating_sub(2)
            }
        }
        IpNet::V6(net) => {
            let host_bits = 128u32 - net.prefix_len() as u32;
            if host_bits == 128 {
                u128::MAX
            } else {
                1u128 << host_bits
            }
        }
    }
}

/// Spawns a background thread that waits for SIGINT/SIGTERM and forwards shutdown to scanner.
pub fn spawn_listener(control_tx: Sender<ControlMessage>) -> Result<(), ScannerError> {
    let mut signals = Signals::new([SIGINT, SIGTERM]).map_err(|err| ScannerError {
        code: ScannerExitCode::Os,
        message: format!("Failed to register signal handlers: {err}"),
    })?;

    thread::Builder::new()
        .name("signal-listener".to_string())
        .spawn(move || {
            for signal in signals.forever() {
                let code = match signal {
                    SIGINT => ScannerExitCode::Interrupt,
                    SIGTERM => ScannerExitCode::TempFail,
                    _ => ScannerExitCode::Internal,
                };

                let _ = control_tx.send(ControlMessage::Shutdown(code));
                break;
            }
        })
        .map_err(|err| ScannerError {
            code: ScannerExitCode::Os,
            message: format!("Failed to spawn signal listener thread: {err}"),
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::str::FromStr;
    use std::sync::mpsc;

    use ipnet::IpNet;
    use pnet::util::MacAddr;

    #[test]
    fn ns_helpers() {
        let target = Ipv6Addr::from_str("fd00:cafe::1234:5678").unwrap();
        assert_eq!(new_ns_addr(&target), Ipv6Addr::from_str("ff02::1:ff34:5678").unwrap());
        assert_eq!(new_ns_mac(&target), MacAddr::new(0x33, 0x33, 0xff, 0x34, 0x56, 0x78));

        let second = Ipv6Addr::from_str("2001:db8::9abc:def0").unwrap();
        assert_eq!(new_ns_addr(&second), Ipv6Addr::from_str("ff02::1:ffbc:def0").unwrap());
        assert_eq!(new_ns_mac(&second), MacAddr::new(0x33, 0x33, 0xff, 0xbc, 0xde, 0xf0));

        let zero_tail = Ipv6Addr::from_str("fd00:cafe::").unwrap();
        assert_eq!(new_ns_addr(&zero_tail), Ipv6Addr::from_str("ff02::1:ff00:0").unwrap());
        assert_eq!(new_ns_mac(&zero_tail), MacAddr::new(0x33, 0x33, 0xff, 0x00, 0x00, 0x00));
    }

    #[test]
    fn net_size() {
        assert_eq!(get_net_size(&IpNet::from_str("192.168.1.0/30").unwrap()), 2);
        assert_eq!(get_net_size(&IpNet::from_str("192.168.1.0/31").unwrap()), 2);
        assert_eq!(get_net_size(&IpNet::from_str("192.168.1.0/32").unwrap()), 1);
        assert_eq!(get_net_size(&IpNet::from_str("10.0.0.0/24").unwrap()), 254);
        assert_eq!(get_net_size(&IpNet::from_str("0.0.0.0/0").unwrap()), 4_294_967_294);
        assert_eq!(get_net_size(&IpNet::from_str("1.2.3.4/1").unwrap()), 2_147_483_646);
        assert_eq!(get_net_size(&IpNet::from_str("fd00:cafe::/120").unwrap()), 256);
        assert_eq!(get_net_size(&IpNet::from_str("fd00:cafe::/128").unwrap()), 1);
        assert_eq!(get_net_size(&IpNet::from_str("fd00:cafe::/64").unwrap()), 1u128 << 64);
        assert_eq!(get_net_size(&IpNet::from_str("::/0").unwrap()), u128::MAX);
        assert_eq!(get_net_size(&IpNet::from_str("2001:db8::/1").unwrap()), 1u128 << 127);
    }

    #[test]
    fn listener_init() {
        let (control_tx, control_rx) = mpsc::channel();
        spawn_listener(control_tx).unwrap();

        assert!(control_rx.try_recv().is_err());
    }
}
