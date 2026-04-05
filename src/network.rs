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
