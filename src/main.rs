//! L2L3-scanner: Scans for available IPv4 and IPv6 addresses on a specified network interface.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use std::sync::mpsc::{self, Receiver, Sender};
use pnet::packet::icmpv6::echo_reply::Icmpv6Codes;
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use clap::Parser;

use ipnet::IpNet;
use pnet::datalink::{self, Channel::Ethernet, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EtherType, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmpv6::{
    echo_reply::EchoReplyPacket as EchoReplyPacketV6,
    echo_request::MutableEchoRequestPacket as MutableEchoRequestPacketV6,
    ndp::{MutableNeighborSolicitPacket, NeighborAdvertPacket},
    Icmpv6Code, Icmpv6Packet, Icmpv6Types
};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{
    MutablePacket, Packet,
    icmp::{self, IcmpTypes, IcmpPacket,
        echo_request::MutableEchoRequestPacket, echo_reply::EchoReplyPacket}};
use pnet::util::MacAddr;

const CHECK_INTERVAL: Duration = Duration::from_millis(20);

/// Exit codes for the scanner, following BSD sysexits and some custom codes.
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ScannerExitCode {
    Ok = 0,
    Cli = 64,
    Internal = 70,
    Os = 71,
    Io = 74,
    TempFail = 75,
    Protocol = 76,
    Perms = 77,
    Config = 78,
    Timeout = 124,
    Interrupt = 130,
}

impl ScannerExitCode {
    /// Returns a code 'meaning' string
    fn meaning(&self) -> &str {
        match self {
            ScannerExitCode::Ok => "OK",
            ScannerExitCode::Cli => "Command line interface error",
            ScannerExitCode::Internal => "Internal error",
            ScannerExitCode::Os => "Operating system error",
            ScannerExitCode::Io => "I/O error",
            ScannerExitCode::TempFail => "Temporary failure",
            ScannerExitCode::Protocol => "Protocol error",
            ScannerExitCode::Perms => "Permission denied",
            ScannerExitCode::Config => "Configuration error",
            ScannerExitCode::Timeout => "Timeout",
            ScannerExitCode::Interrupt => "Interrupted",
        }
    }
}

/// Scanner error containing custom exit code and formatted message
pub struct ScannerError {
    /// The exit code to return
    code: ScannerExitCode,
    /// Friendly error message
    message: String,
}

/// Runtime control messages sent from side threads (e.g. signal listener) to the scanner.
#[derive(Debug, Clone, Copy)]
enum ControlMessage {
    /// Request a graceful shutdown with a matching exit code.
    Shutdown(ScannerExitCode),
}

impl From<ScannerError> for ExitCode {
    fn from(value: ScannerError) -> Self {
        if value.code != ScannerExitCode::Ok {
            eprintln!("{}: {}", value.code.meaning(), value.message);
        }
        ExitCode::from(value.code as u8)
    }
}

/// Command Line Interface arguments for the Scanner
#[derive(Debug, clap::Parser)]
#[command(name = "l2l3-scanner")]
#[command(about = "Scans for available IpV4 and IpV6 addresses on provided interface", long_about = None)]
struct Cli {
    /// Available network interface to scan (e.g. 'wlan0'), or list interfaces if not provided
    #[arg(short, value_name = "INTERFACE", num_args = 0..=1)]
    interface: Option<Option<String>>,

    /// List of subnet values defining scanning ranges (e.g. '192.168.1.0/24')
    #[arg(short, value_name = "SUBNET")]
    subnets: Option<Vec<IpNet>>,

    /// Program timeout value in milliseconds
    #[arg(short, default_value_t = 1000)]
    timeout: u64,
}

/// Main scanner struct, holds configuration for a scan operation.
#[derive(Debug)]
struct Scanner {
    /// The network interface to scan
    interface: NetworkInterface,
    /// List of subnets to scan
    networks: Vec<IpNet>,
    /// Timeout for the scan
    timeout: Duration,
    /// Read handle of signal handling thread
    control_rx: Receiver<ControlMessage>,
}

/// IP address match pair.
#[derive(Debug, Clone, Copy)]
struct ScanMatch {
    mac_addr: Option<MacAddr>,
    icmp_responded: bool,
}

impl Default for ScanMatch {
    fn default() -> Self {
        Self {
            mac_addr: None,
            icmp_responded: false,
        }
    }
}


impl Scanner {
    /// Build scanner from CLI + control channel.
    fn try_new(value: Cli, control_rx: Receiver<ControlMessage>) -> Result<Self, ScannerError> {
        // No arguments, help not asked, exit with error
        if value.interface.is_none() && value.subnets.is_none() {
            return Err(ScannerError {
                code: ScannerExitCode::Cli,
                message: "No arguments provided".to_string(),
            });
        }

        // Used in several arms
        let interfaces = pnet::datalink::interfaces();
        match value.interface {
            // -i provided
            Some(iface) => match iface {
                // -i <iface>
                Some(iface) => {
                    let interface = interfaces
                        .into_iter()
                        .find(|inter| inter.name == iface)
                        .ok_or_else(|| ScannerError {
                            code: ScannerExitCode::Cli,
                            message: format!("Interface '{}' not found", iface),
                        })?;

                    match value.subnets {
                        // -s present, scanner config is complete
                        Some(subnets) => Ok(Self {
                            interface,
                            networks: subnets,
                            timeout: Duration::from_millis(value.timeout),
                            control_rx,
                        }),
                        // -s missing while interface was requested
                        None => Err(ScannerError {
                            code: ScannerExitCode::Cli,
                            message: "No subnets specified".to_string(),
                        }),
                    }
                }
                // -i used without value: list interfaces and exit successfully
                None => {
                    println!("Available interfaces:");
                    for iface in interfaces {
                        println!("{}", iface.name);
                    }

                    Err(ScannerError {
                        code: ScannerExitCode::Ok,
                        message: "Interface list generated".to_string(),
                    })
                }
            },
            // no -i: treat as CLI usage error
            None => Err(ScannerError {
                code: ScannerExitCode::Cli,
                message: "-i option was not used".to_string(),
            }),
        }
    }

    /// Perform shutdown request check on control handle.
    fn check_shutdown(&self) -> Result<(), ScannerError> {
        match self.control_rx.try_recv() {
            // signal thread requested stop
            Ok(ControlMessage::Shutdown(code)) => Err(ScannerError {
                code,
                message: "Graceful shutdown requested by signal".to_string(),
            }),
            Err(mpsc::TryRecvError::Empty) => Ok(()),
            Err(mpsc::TryRecvError::Disconnected) => Err(ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to check signal channel state".to_string()
            }),
        }
    }

    /// Get interface MAC address, or error if not found.
    fn get_iface_mac(interface: &NetworkInterface) -> Result<MacAddr, ScannerError> {
        interface.mac.ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to retrieve MAC address for the interface".to_string(),
        })
    }

    /// Get first available interface IP address.
    fn get_iface_ipv4(interface: &NetworkInterface) -> Result<Ipv4Addr, ScannerError> {
        interface
            .ips
            .iter()
            .find_map(|ipn| match ipn.ip() {
                IpAddr::V4(addr) => Some(addr),
                IpAddr::V6(_) => None,
            })
            .ok_or_else(|| ScannerError {
                code: ScannerExitCode::Config,
                message: "Interface has no IPv4 address".to_string(),
            })
    }

    /// Get first available interface IP address.
    fn get_iface_ipv6(interface: &NetworkInterface) -> Result<Ipv6Addr, ScannerError> {
        interface
            .ips
            .iter()
            .find_map(|ipn| match ipn.ip() {
                IpAddr::V4(_) => None,
                IpAddr::V6(addr) => Some(addr),
            })
            .ok_or_else(|| ScannerError {
                code: ScannerExitCode::Config,
                message: "Interface has no IPv6 address".to_string(),
            })
    }

    /// Construct new IPv6 NS multicast address from target.
    fn new_ns_addr(target_ip: &Ipv6Addr) -> Ipv6Addr {
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
    fn new_ns_mac(target_ip: &Ipv6Addr) -> MacAddr {
        let target = target_ip.octets();
        MacAddr::new(0x33, 0x33, 0xff, target[13], target[14], target[15])
    }

    /// Construct an Ethernet frame with the given parameters.
    fn make_ethernet(iface: &NetworkInterface,
        dest: MacAddr,
        ethertype: EtherType,
        payload_size: usize)
        -> Result<Vec<u8>, ScannerError>
    {
        let source = Self::get_iface_mac(iface)?;

        let mut buffer = vec![0u8; 14 + payload_size];
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create Ethernet frame".to_string(),
        })?;

        eth_packet.set_destination(dest);
        eth_packet.set_source(source);
        eth_packet.set_ethertype(ethertype);

        Ok(buffer)
    }

    /// Construct an ARP request packet for the given target IPv4 address.
    fn make_arp(&self, target_ip: &Ipv4Addr) -> Result<Vec<u8>, ScannerError> {
        // Unknown destination MAC, so broadcast is the correct L2 target.
        // ARP carries an IPv4 resolution request.
        // ARP Ethernet/IPv4 payload size is fixed at 28 bytes.
        let mut buffer = Self::make_ethernet(
            &self.interface,
            MacAddr::broadcast(),
            EtherTypes::Arp,
            MutableArpPacket::minimum_packet_size()
        )?;

        let mut arp_packet = MutableArpPacket::new(
            &mut buffer[MutableEthernetPacket::minimum_packet_size()..]
        ).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create ARP packet".to_string(),
        })?;

        let source_ip = Self::get_iface_ipv4(&self.interface)?;

        // Ethernet is the only hardware type relevant on this link.
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        // IPv4 is the protocol being resolved by ARP.
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        // Request opcode is mandatory for address discovery.
        arp_packet.set_operation(ArpOperations::Request);

        // Ethernet MAC addresses are 6 bytes.
        arp_packet.set_hw_addr_len(6);
        // IPv4 addresses are 4 bytes.
        arp_packet.set_proto_addr_len(4);

        // Sender MAC must be the interface MAC so replies can be routed back.
        arp_packet.set_sender_hw_addr(Self::get_iface_mac(&self.interface)?);
        // Sender IPv4 must be the interface IPv4 on the local subnet.
        arp_packet.set_sender_proto_addr(source_ip);
        // Target MAC is unknown in an ARP request, zero is the standard placeholder.
        arp_packet.set_target_hw_addr(MacAddr::zero());
        // Target IPv4 is the host we want to resolve.
        arp_packet.set_target_proto_addr(*target_ip);

        Ok(buffer)
    }

    /// Construct an NDP Neighbor Solicitation packet for the given target IPv6 address.
    fn make_ndp(&self, target_ip: &Ipv6Addr) -> Result<Vec<u8>, ScannerError> {
        let ndp_len = MutableNeighborSolicitPacket::minimum_packet_size();

        // Solicited-node multicast MAC keeps the request on the target neighborhood.
        // IPv6 EtherType marks the payload as IPv6.
        // NDP payload is the IPv6 header plus the Neighbor Solicitation body.
        let mut buffer = Self::make_ethernet(
            &self.interface,
            Self::new_ns_mac(target_ip),
            EtherTypes::Ipv6,
            MutableIpv6Packet::minimum_packet_size() + ndp_len
        )?;

        // Source IPv6 must be a local address on the selected interface.
        let source_ip = Self::get_iface_ipv6(&self.interface)?;
        // Destination IPv6 is the solicited-node multicast address for the target.
        let dest_ip = Self::new_ns_addr(target_ip);

        let mut eth_packet = MutableEthernetPacket::new(&mut buffer).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create Ethernet frame for NDP".to_string(),
        })?;

        let mut ipv6_packet = MutableIpv6Packet::new(eth_packet.payload_mut()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create IPv6 packet".to_string(),
        })?;

        // IPv6 version is 6
        ipv6_packet.set_version(6);
        // Neighbor Discovery is carried over ICMPv6
        ipv6_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
        // Hop limit 255 is required by RFC 4861
        ipv6_packet.set_hop_limit(255);
        // Payload length covers only the NDP body
        ipv6_packet.set_payload_length(ndp_len as u16);

        ipv6_packet.set_source(source_ip);
        ipv6_packet.set_destination(dest_ip);

        let mut ndp_packet = MutableNeighborSolicitPacket::new(ipv6_packet.payload_mut()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create NDP packet".to_string(),
        })?;

        ndp_packet.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
        ndp_packet.set_target_addr(*target_ip);

        let icmp_packet = Icmpv6Packet::new(ndp_packet.packet()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to view NDP packet as ICMPv6".to_string(),
        })?;

        // Includes body and IPv6 pseudo-header
        let checksum = pnet::packet::icmpv6::checksum(&icmp_packet, &source_ip, &dest_ip);
        ndp_packet.set_checksum(checksum);

        Ok(buffer)
    }

    /// Construct an IPv4 ICMP echo request packet for the given target address.
    fn make_icmpv4_echo_request(&self, target_ip: &Ipv4Addr, mac_addr: MacAddr,
        identifier: u16, sequence_number: u16)
        -> Result<Vec<u8>, ScannerError>
    {
        // Allocate space for IPv4 header + ICMP echo request packet
        let echo_len = MutableEchoRequestPacket::minimum_packet_size();

        let mut buffer = Self::make_ethernet(
            &self.interface,
            mac_addr,
            EtherTypes::Ipv4,
            MutableIpv4Packet::minimum_packet_size() + echo_len,
        )?;

        let source_ip = Self::get_iface_ipv4(&self.interface)?;

        let mut ipv4_packet = MutableIpv4Packet::new(
            &mut buffer[MutableEthernetPacket::minimum_packet_size()..]
        ).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create IPv4 packet for ICMP".to_string(),
        })?;

        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length((MutableIpv4Packet::minimum_packet_size() + echo_len) as u16);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ipv4_packet.set_source(source_ip);
        ipv4_packet.set_destination(*target_ip);

        // IPv4 header checksum must be calculated and set
        //ipv4_packet.set_checksum(0);
        let ipv4_checksum = pnet::packet::ipv4::checksum(&Ipv4Packet::new(ipv4_packet.packet()).unwrap());
        ipv4_packet.set_checksum(ipv4_checksum);

        let mut icmp_packet = MutableEchoRequestPacket::new(ipv4_packet.payload_mut()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create ICMPv4 echo request packet".to_string(),
        })?;

        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_sequence_number(sequence_number);
        icmp_packet.set_identifier(identifier);
        // ICMP checksum must be calculated on packet with checksum field zeroed
        //icmp_packet.set_checksum(0);
        let checksum_value = icmp::checksum(&IcmpPacket::new(icmp_packet.packet()).unwrap());
        icmp_packet.set_checksum(checksum_value);

        Ok(buffer)
    }

    /// Construct an IPv6 ICMP echo request packet for the given target address.
    fn make_icmpv6_echo_request(&self, target_ip: &Ipv6Addr, mac_addr: MacAddr,
        identifier: u16, sequence_number: u16)
        -> Result<Vec<u8>, ScannerError>
    {
        let echo_len = MutableEchoRequestPacketV6::minimum_packet_size();

        let mut buffer = Self::make_ethernet(
            &self.interface,
            mac_addr,
            EtherTypes::Ipv6,
            MutableIpv6Packet::minimum_packet_size() + echo_len,
        )?;

        let source_ip = Self::get_iface_ipv6(&self.interface)?;

        let mut eth_packet = MutableEthernetPacket::new(&mut buffer).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create Ethernet frame for ICMPv6".to_string(),
        })?;

        let mut ipv6_packet = MutableIpv6Packet::new(eth_packet.payload_mut()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create IPv6 packet for ICMPv6".to_string(),
        })?;

        ipv6_packet.set_version(6);
        ipv6_packet.set_source(source_ip);
        ipv6_packet.set_destination(*target_ip);
        ipv6_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
        // Frequent hop limit 
        ipv6_packet.set_hop_limit(64);
        ipv6_packet.set_payload_length(echo_len as u16);

        let mut icmpv6_packet = MutableEchoRequestPacketV6::new(ipv6_packet.payload_mut()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create ICMPv6 echo request packet".to_string(),
        })?;

        icmpv6_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
        // 0 required
        icmpv6_packet.set_icmpv6_code(Icmpv6Codes::NoCode);
        icmpv6_packet.set_identifier(identifier);
        icmpv6_packet.set_sequence_number(sequence_number);

        let icmp_packet = Icmpv6Packet::new(icmpv6_packet.packet()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to view ICMPv6 echo request as ICMPv6 packet".to_string(),
        })?;
        icmpv6_packet.set_checksum(pnet::packet::icmpv6::checksum(&icmp_packet, &source_ip, target_ip));

        Ok(buffer)
    }

    /// Perform ARP on IPV4, returns MAC address if found
    fn l2_scan_ipv4(&self, tx: & mut Box<dyn DataLinkSender>, rx: & mut Box<dyn DataLinkReceiver>, addr: &Ipv4Addr)
        -> Result<Option<MacAddr>, ScannerError>
    {
        let arp_request = self.make_arp(addr)?;
        // Try sending
        let send_result = tx.send_to(&arp_request, None).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Os,
            message: "Failed to queue ARP frame for sending".to_string(),
        })?;

        // Check how sending finished
        if send_result.is_err() {
            let error_message = format!("Failed to send ARP frame: {}", send_result.as_ref().err().unwrap());
            return Err(ScannerError {
                code: ScannerExitCode::Os,
                message: error_message,
            });
        }

        let deadline = Instant::now() + self.timeout;
        // Await response or end on timeout
        while Instant::now() < deadline {
            match rx.next() {
                Ok(frame) => { // Gradually check for valid format and data
                    // Try constructing Ethernet packet, on fail continue
                    let Some(eth_packet) = EthernetPacket::new(frame) else {
                        continue;
                    };
                    // Check for correct EtherType field
                    if eth_packet.get_ethertype() != EtherTypes::Arp {
                        continue;
                    }

                    // Try parsing as ARP packet, on fail continue
                    let Some(arp_packet) = ArpPacket::new(eth_packet.payload()) else {
                        continue;
                    };
                    // Check for ARP reply operation
                    if arp_packet.get_operation() != ArpOperations::Reply {
                        continue;
                    };
                    // Check if sender address matches target
                    if arp_packet.get_sender_proto_addr() == *addr {
                        return Ok(Some(eth_packet.get_source()));
                    }
                }
                Err(_) => break,
            }
        }

        Ok(None)
    }

    /// Perform NDP on IPv6, returns MAC address if found
    fn l2_scan_ipv6(&self, tx: & mut Box<dyn DataLinkSender>, rx: & mut Box<dyn DataLinkReceiver>, addr: &Ipv6Addr)
        -> Result<Option<MacAddr>, ScannerError>
    {
        let ndp_request = self.make_ndp(addr)?;
        let send_result = tx.send_to(&ndp_request, None).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Os,
            message: "Failed to queue NDP frame for sending".to_string(),
        })?;

        // Check how sending finished
        if send_result.is_err() {
            let error_message = format!("Failed to send NDP frame: {}", send_result.err().unwrap());
            return Err(ScannerError {
                code: ScannerExitCode::Os,
                message: error_message,
            });
        }

        let deadline = Instant::now() + self.timeout;
        // Await response or end on timeout
        while Instant::now() < deadline {
            match rx.next() {
                Ok(frame) => { // Gradually check for valid format and data
                    // Try constructing Ethernet packet, on fail continue
                    let Some(eth_packet) = EthernetPacket::new(frame) else {
                        continue;
                    };
                    // Check for correct EtherType field
                    if eth_packet.get_ethertype() != EtherTypes::Ipv6 {
                        continue;
                    }

                    // Try parsing as IPv6 packet
                    let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) else {
                        continue;
                    };
                    // Check the next_header field
                    if ipv6_packet.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
                        continue;
                    }
                    // Try parsing as advert packet
                    let Some(na_packet) = NeighborAdvertPacket::new(ipv6_packet.payload()) else {
                        continue;
                    };
                    if na_packet.get_target_addr() == *addr {
                        return Ok(Some(eth_packet.get_source()));
                    }
                }
                Err(_) => break,
            };
        };

        Ok(None)
    }

    /// Perform ping on IPv4, returns true if got response
    fn l3_scan_ipv4(&self, tx: &mut Box<dyn DataLinkSender>, rx: &mut Box<dyn DataLinkReceiver>, addr: &Ipv4Addr, mac_addr: MacAddr)
        -> Result<bool, ScannerError>
    {
        const SEQ_NUM: u16 = 1;
        const IDENTIFIER: u16 = 1;

        let buffer = self.make_icmpv4_echo_request(addr, mac_addr, IDENTIFIER, SEQ_NUM)?;

        let send_result = tx.send_to(&buffer, None).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Os,
            message: "Failed to queue ICMP frame for sending".to_string(),
        })?;

        if send_result.is_err() {
            let error_message = format!("Failed to send ICMP frame: {}", send_result.err().unwrap());
            return Err(ScannerError {
                code: ScannerExitCode::Os,
                message: error_message,
            });
        };

        let deadline = Instant::now() + self.timeout;
        // Await response or end on timeout
        while Instant::now() < deadline {
            match rx.next() {
                Ok(frame) => { // Gradually check for valid format and data
                    // Try constructing Ethernet packet, on fail continue
                    let Some(eth_packet) = EthernetPacket::new(frame) else {
                        continue;
                    };
                    // Check for correct EtherType field
                    if eth_packet.get_ethertype() != EtherTypes::Ipv4 {
                        continue;
                    };

                    // Try parsing as IPv4 packet, on fail continue
                    let Some(ipv4_packet) = Ipv4Packet::new(eth_packet.payload()) else {
                        continue;
                    };
                    // Check the next_header field
                    if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
                        continue;
                    };
                    // Check if source address matches target
                    if ipv4_packet.get_source() != *addr {
                        continue;
                    };

                    // Try parsing as echo reply packet, on fail continue
                    let Some(echo_reply) = EchoReplyPacket::new(ipv4_packet.payload()) else {
                        continue;
                    };

                    if echo_reply.get_icmp_type() != IcmpTypes::EchoReply {
                        continue;
                    }

                    // Check if identifier and sequence number match request
                    if echo_reply.get_identifier() == IDENTIFIER
                        && echo_reply.get_sequence_number() == SEQ_NUM
                    {
                        return Ok(true);
                    }
                },
                Err(_) => break,
            };
        };

        Ok(false)
    }

    /// Perform ping on IPv6, returns true if got response
    fn l3_scan_ipv6(&self, tx: &mut Box<dyn DataLinkSender>, rx: &mut Box<dyn DataLinkReceiver>,
        addr: &Ipv6Addr, mac_addr: MacAddr) 
        -> Result<bool, ScannerError>
    {
        const SEQ_NUM: u16 = 1;
        const IDENTIFIER: u16 = 1;

        let buffer = self.make_icmpv6_echo_request(addr, mac_addr, IDENTIFIER, SEQ_NUM)?;

        let send_result = tx.send_to(&buffer, None).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Os,
            message: "Failed to queue ICMPv6 frame for sending".to_string(),
        })?;

        if send_result.is_err() {
            let error_message = format!("Failed to send ICMPv6 frame: {}", send_result.err().unwrap());
            return Err(ScannerError {
                code: ScannerExitCode::Os,
                message: error_message,
            });
        }

        let deadline = Instant::now() + self.timeout;
        while Instant::now() < deadline {
            match rx.next() {
                Ok(frame) => {
                    // Construct Ethernet packet, on fail continue
                    let Some(eth_packet) = EthernetPacket::new(frame) else {
                        continue;
                    };
                    // Check for correct EtherType field
                    if eth_packet.get_ethertype() != EtherTypes::Ipv6 {
                        continue;
                    }

                    // Try parsing as IPv6 packet, on fail continue
                    let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) else {
                        continue;
                    };
                    // Check the next_header field
                    if ipv6_packet.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
                        continue;
                    }
                    // Check if source address matches target
                    if ipv6_packet.get_source() != *addr {
                        continue;
                    }

                    // Try parsing as echo reply packet, on fail continue
                    let Some(echo_reply) = EchoReplyPacketV6::new(ipv6_packet.payload()) else {
                        continue;
                    };
                    // Should be EchoReply, but for correctness we check
                    if echo_reply.get_icmpv6_type() != Icmpv6Types::EchoReply {
                        continue;
                    }
                    // Should be again 0
                    if echo_reply.get_icmpv6_code() != Icmpv6Code(0) {
                        continue;
                    }

                    // Check if identifier and sequence number match request
                    if echo_reply.get_identifier() == IDENTIFIER
                        && echo_reply.get_sequence_number() == SEQ_NUM
                    {
                        return Ok(true);
                    }
                }
                Err(_) => break,
            };
        }

        Ok(false)
    }

    /// Scan one subnet batch.
    fn scan_network(&self, network: &IpNet, tx: & mut Box<dyn DataLinkSender>, rx: & mut Box<dyn DataLinkReceiver>)
        -> Result<HashMap<IpAddr, ScanMatch>, ScannerError>
    {
        let mut discovered: HashMap<IpAddr, ScanMatch> = HashMap::new();

        let mut last_check_time = Instant::now();
        // println!("Interface subnets: {:?}", self.interface.ips);
        for addr in network.hosts() {
            // print!("Scanning {}: ", addr);
            let mut match_result = ScanMatch::default();
            let is_local = self.interface.ips.iter().any(|net| net.contains(addr));
            // println!("local: {}", is_local);

            // Scan L2 if in local segment
            if is_local {
                // Scan appropriate addres
                match_result.mac_addr = match addr {
                    IpAddr::V4(addr) => self.l2_scan_ipv4(tx, rx, &addr)?,
                    IpAddr::V6(addr) => self.l2_scan_ipv6(tx, rx, &addr)?,
                };

                // if match_result.mac_addr.is_some() {
                //     println!("L2 match found: {}", match_result.mac_addr.unwrap());
                // } else {
                //     println!("No L2 match");
                // }

                // Check for shutdown signals
                if Instant::now() - last_check_time >= CHECK_INTERVAL {
                    self.check_shutdown()?;
                    last_check_time = Instant::now();
                };
            }

            // Scan L3 if got Mac or not local
            if is_local && match_result.mac_addr.is_some() || !is_local {
                let mac_addr = match_result.mac_addr.unwrap_or(MacAddr::broadcast());
                match_result.icmp_responded = match addr {
                    IpAddr::V4(addr) => self.l3_scan_ipv4(tx, rx, &addr, mac_addr)?,
                    IpAddr::V6(addr) => self.l3_scan_ipv6(tx, rx, &addr, mac_addr)?,
                };

                // At least one layer succeeded, add to results
                discovered.insert(addr, match_result);
            }

        }

        Ok(discovered)
    }

    /// Calculate scannable address count from network.
    fn get_net_size(net: &IpNet) -> u128 {
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

    /// Print internal networks used for scanning.
    fn print_nets(&self) {
        for net in &self.networks {
            println!("{} {}", net, Self::get_net_size(net));
        }
    }

    /// Run the scan operation. Returns a HashMap of matches, if None,
    /// then assume fail. May return ScannerError.
    fn run(&self) -> Result<HashMap<IpAddr, ScanMatch>, ScannerError> {
        let mut discovered = HashMap::new();

        // Create interface channel config
        let config = datalink::Config {
            read_timeout: Some(Duration::from_millis(20)),
            ..Default::default()
        };

        // Try creating datalink channel and check if Ethernet
        let (mut tx, mut rx) = match datalink::channel(&self.interface, config).map_err(|err| ScannerError {
            code: ScannerExitCode::Os,
            message: format!("Failed to open datalink channel: {err}"),
        })? {
            Ethernet(tx, rx) => (tx, rx),
            _ => {
                return Err(ScannerError {
                    code: ScannerExitCode::Protocol,
                    message: "Unsupported datalink channel type, Ethernet expected".to_string(),
                });
            }
        };

        // Scan each network and aggregate results
        for network in &self.networks {
            let results = self.scan_network(network, & mut tx, & mut rx)?;
            discovered.extend(results);
        }

        Ok(discovered)
    }
}

/// Spawns a background thread that waits for SIGINT/SIGTERM and forwards shutdown to scanner.
fn spawn_listener(control_tx: Sender<ControlMessage>) -> Result<(), ScannerError> {
    let mut signals = Signals::new([SIGINT, SIGTERM]).map_err(|err| ScannerError {
        code: ScannerExitCode::Os,
        message: format!("Failed to register signal handlers: {err}"),
    })?;

    thread::Builder::new()
        .name("signal-listener".to_string())
        .spawn(move || {
            for signal in signals.forever() {
                let code = match signal {
                    // Ctrl+C
                    SIGINT => ScannerExitCode::Interrupt,
                    // kill -TERM
                    SIGTERM => ScannerExitCode::TempFail,
                    // fallback for any unexpected signal value
                    _ => ScannerExitCode::Internal,
                };

                // Scanner may have already finished, error not important
                let _ = control_tx.send(ControlMessage::Shutdown(code));
                break;
            }
        })
        .map_err(|err| ScannerError {
            code: ScannerExitCode::Internal,
            message: format!("Failed to spawn signal listener thread: {err}"),
        })?;

    Ok(())
}

// Print MAC address in required format.
fn print_mac(mac_addr: MacAddr) {
    print!("({:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x})",
        mac_addr.0, mac_addr.1, mac_addr.2, mac_addr.3, mac_addr.4, mac_addr.5);
}

/// Print scan result for each IP in requied format. If scan_match is None, assume fail and print accordingly.
fn print_scan_result(addr: &IpAddr, scan_match: Option<&ScanMatch>) {
    print!("{} {} ",
        addr,
        if addr.is_ipv4() {"arp"} else {"ndp"}
    );

    match scan_match {
        Some(matched) => {
            match matched.mac_addr {
                Some(mac) => {
                    print!("OK ");
                    print_mac(mac);
                },
                None => {
                    print!("FAIL");
                }
            }

            println!(", icmpv{} {}",
                if addr.is_ipv4() {"4"} else {"6"},
                if matched.icmp_responded {"OK"} else {"FAIL"}
            )
        },
        None => {
            println!("FAIL, icmpv{} FAIL",
                if addr.is_ipv4() {"4"} else {"6"}, 
            )
        },
    };
}

/// Entry point for the scanner application.
/// Parses CLI arguments, constructs the scanner, and runs the scan or lists interfaces.
fn main() -> ExitCode {
    let clint = Cli::parse();

    // Create channel for async signal handling
    let (control_tx, control_rx) = mpsc::channel::<ControlMessage>();
    if let Err(err) = spawn_listener(control_tx) {
        return err.into();
    }

    // Try creating Scanner from CLI args and reading handle
    match Scanner::try_new(clint, control_rx) {
        Ok(scanner) => {
            // Print netowkrs/subnets that are going to be scanned
            println!("Scanning ranges:");
            scanner.print_nets();
            println!();

            match scanner.run() {
                Ok(matches) => {
                    // Print all IPs and formatted results of their scan
                    for addr in scanner.networks.iter().flat_map(|net| net.hosts()) {
                        print_scan_result(&addr, matches.get(&addr));
                    }
                    
                    ExitCode::from(ScannerExitCode::Ok as u8)
                }
                Err(err) => err.into(),
            }
        },
        Err(err) => err.into(),
    }
}