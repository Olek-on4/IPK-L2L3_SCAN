//! L2L3-scanner: Scans for available IPv4 and IPv6 addresses on a specified network interface.
#![allow(non_snake_case)]

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use std::sync::mpsc::{self, Receiver, Sender};
use pnet::packet::icmp::echo_reply::IcmpCodes;
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
    ndp::{MutableNeighborSolicitPacket, NeighborAdvertPacket, NdpOption, NdpOptionTypes},
    Icmpv6Packet, Icmpv6Types
};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
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
    #[arg(short = 'w', default_value_t = 1000)]
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

/// IP address and MAC address pair for discovered hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AddressPair {
    ip: IpAddr,
    mac: MacAddr,
}

/// IP address match pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
                code: ScannerExitCode::Io,
                message: "Failed to check signal channel state".to_string()
            }),
        }
    }

    /// Check if address belongs to local segment of the interface.
    fn addr_is_local(&self, addr: IpAddr) -> bool {
        self.interface.ips.iter().any(|net| net.contains(addr))
    }

    /// Get interface MAC address, or error if not found.
    fn get_iface_mac(interface: &NetworkInterface) -> Result<MacAddr, ScannerError> {
        interface.mac.ok_or_else(|| ScannerError {
            code: ScannerExitCode::Os,
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

    /// Construct Ethernet with IPv6 headers and return buffer.
    fn make_ipv6(
        &self,
        dest_mac: MacAddr,
        source_ip: Ipv6Addr,
        dest_ip: Ipv6Addr,
        next_header: IpNextHeaderProtocol,
        hop_limit: u8,
        payload_len: usize,
    ) -> Result<Vec<u8>, ScannerError> {
        let mut buffer = Self::make_ethernet(
            &self.interface,
            dest_mac,
            EtherTypes::Ipv6,
            MutableIpv6Packet::minimum_packet_size() + payload_len,
        )?;

        let mut eth_packet = MutableEthernetPacket::new(&mut buffer).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create Ethernet frame for IPv6 payload".to_string(),
        })?;

        let mut ipv6_packet = MutableIpv6Packet::new(eth_packet.payload_mut()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create IPv6 packet".to_string(),
        })?;

        ipv6_packet.set_version(6);
        ipv6_packet.set_source(source_ip);
        ipv6_packet.set_destination(dest_ip);
        ipv6_packet.set_next_header(next_header);
        ipv6_packet.set_hop_limit(hop_limit);
        ipv6_packet.set_payload_length(payload_len as u16);

        Ok(buffer)
    }

    /// Construct Ethernet with IPv4 headers and return buffer.
    fn make_ipv4(
        &self,
        dest_mac: MacAddr,
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        next_header: IpNextHeaderProtocol,
        ttl: u8,
        payload_len: usize,
    ) -> Result<Vec<u8>, ScannerError> {
        let mut buffer = Self::make_ethernet(
            &self.interface,
            dest_mac,
            EtherTypes::Ipv4,
            MutableIpv4Packet::minimum_packet_size() + payload_len,
        )?;

        let mut eth_packet = MutableEthernetPacket::new(&mut buffer).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create Ethernet frame for IPv4 payload".to_string(),
        })?;

        let mut ipv4_packet = MutableIpv4Packet::new(eth_packet.payload_mut()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create IPv4 packet".to_string(),
        })?;

        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length((MutableIpv4Packet::minimum_packet_size() + payload_len) as u16);
        ipv4_packet.set_ttl(ttl);
        ipv4_packet.set_next_level_protocol(next_header);
        ipv4_packet.set_source(source_ip);
        ipv4_packet.set_destination(dest_ip);

        let ipv4_packet_imm = Ipv4Packet::new(ipv4_packet.packet()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to view IPv4 packet for checksum calculation".to_string(),
        })?;
        let ipv4_checksum = pnet::packet::ipv4::checksum(&ipv4_packet_imm);
        ipv4_packet.set_checksum(ipv4_checksum);

        Ok(buffer)
    }

    /// Construct an ARP request packet for the given target IPv4 address.
    fn make_arp(&self, target_ip: &Ipv4Addr) -> Result<Vec<u8>, ScannerError> {
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

        // Ethernet is the only hardware type relevant
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        // Request opcode required
        arp_packet.set_operation(ArpOperations::Request);

        // Ethernet MAC addresses are 6 bytes
        arp_packet.set_hw_addr_len(6);
        // IPv4 addresses are 4 bytes
        arp_packet.set_proto_addr_len(4);

        arp_packet.set_sender_hw_addr(Self::get_iface_mac(&self.interface)?);
        arp_packet.set_sender_proto_addr(source_ip);

        // Target MAC is unknown in an ARP request, set to zero
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(*target_ip);

        Ok(buffer)
    }

    /// Construct an NDP Neighbor Solicitation packet for the given target IPv6 address.
    fn make_ndp(&self, target_ip: &Ipv6Addr) -> Result<Vec<u8>, ScannerError> {
        let ndp_len = MutableNeighborSolicitPacket::minimum_packet_size() + 8; // 8 for Source MAC option

        let source_ip = Self::get_iface_ipv6(&self.interface)?;
        // Source MAC option is required
        let source_mac = Self::get_iface_mac(&self.interface)?;
        // Destination IPv6 is the solicited-node multicast address
        let dest_ip = Self::new_ns_addr(target_ip);

        // Solicited-node multicast MAC keeps the request on the target neighborhood
        // Hop limit 255 is required by RFC 4861
        let mut buffer = self.make_ipv6(
            Self::new_ns_mac(target_ip),
            source_ip,
            dest_ip,
            IpNextHeaderProtocols::Icmpv6,
            255,
            ndp_len,
        )?;

        let mut eth_packet = MutableEthernetPacket::new(&mut buffer).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create Ethernet frame for NDP".to_string(),
        })?;

        let mut ipv6_packet = MutableIpv6Packet::new(eth_packet.payload_mut()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create IPv6 packet".to_string(),
        })?;

        let mut ndp_packet = MutableNeighborSolicitPacket::new(ipv6_packet.payload_mut()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create NDP packet".to_string(),
        })?;

        ndp_packet.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
        ndp_packet.set_target_addr(*target_ip);

        // Add Source Link-Layer Address option
        let options = [NdpOption {
            option_type: NdpOptionTypes::SourceLLAddr,
            length: 1,
            data: vec![
                source_mac.0,
                source_mac.1,
                source_mac.2,
                source_mac.3,
                source_mac.4,
                source_mac.5,
            ],
        }];
        ndp_packet.set_options(&options);

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
    fn make_icmpv4_echo(&self, target_ip: &Ipv4Addr, mac_addr: MacAddr,
        identifier: u16, sequence_number: u16)
        -> Result<Vec<u8>, ScannerError>
    {
        // Allocate space for IPv4 header + ICMP echo request packet
        let echo_len = MutableEchoRequestPacket::minimum_packet_size();
        let source_ip = Self::get_iface_ipv4(&self.interface)?;

        let mut buffer = self.make_ipv4(
            mac_addr,
            source_ip,
            *target_ip,
            IpNextHeaderProtocols::Icmp,
            64, // Standard
            echo_len,
        )?;

        let mut ipv4_packet = MutableIpv4Packet::new(
            &mut buffer[MutableEthernetPacket::minimum_packet_size()..]
        ).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create IPv4 packet for ICMP".to_string(),
        })?;

        let mut icmp_packet = MutableEchoRequestPacket::new(ipv4_packet.payload_mut()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create ICMPv4 echo request packet".to_string(),
        })?;

        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        // Do not really care but srt something
        icmp_packet.set_sequence_number(sequence_number);
        icmp_packet.set_identifier(identifier);

        let icmp_packet_imm = IcmpPacket::new(icmp_packet.packet()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to view ICMPv4 echo request for checksum calculation".to_string(),
        })?;
        let checksum_value = icmp::checksum(&icmp_packet_imm);
        icmp_packet.set_checksum(checksum_value);

        Ok(buffer)
    }

    /// Construct an IPv6 ICMP echo request packet for the given target address.
    fn make_icmpv6_echo(&self, target_ip: &Ipv6Addr, mac_addr: MacAddr,
        identifier: u16, sequence_number: u16)
        -> Result<Vec<u8>, ScannerError>
    {
        let echo_len = MutableEchoRequestPacketV6::minimum_packet_size();
        let source_ip = Self::get_iface_ipv6(&self.interface)?;

        let mut buffer = self.make_ipv6(
            mac_addr,
            source_ip,
            *target_ip,
            IpNextHeaderProtocols::Icmpv6,
            64, // Standard
            echo_len,
        )?;

        let mut eth_packet = MutableEthernetPacket::new(&mut buffer).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create Ethernet frame for ICMPv6".to_string(),
        })?;

        let mut ipv6_packet = MutableIpv6Packet::new(eth_packet.payload_mut()).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Internal,
            message: "Failed to create IPv6 packet for ICMPv6".to_string(),
        })?;

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

    /// Parse ARP reply frame and extract (sender IPv4, sender MAC).
    fn parse_arp(packet: &[u8], source_ip: Ipv4Addr, source_mac: MacAddr) -> Option<AddressPair> {
        // Try constructing Ethernet packet, on fail continue
        let eth_packet = EthernetPacket::new(packet)?;
        // Check for correct EtherType field
        if eth_packet.get_ethertype() != EtherTypes::Arp {
            return None;
        }

        // Try parsing as ARP packet, on fail continue
        let arp_packet = ArpPacket::new(eth_packet.payload())?;
        // Check ARP header fields
        if arp_packet.get_hardware_type() != ArpHardwareTypes::Ethernet {
            return None;
        }
        if arp_packet.get_protocol_type() != EtherTypes::Ipv4 {
            return None;
        }
        if arp_packet.get_hw_addr_len() != 6 || arp_packet.get_proto_addr_len() != 4 {
            return None;
        }
        // Check for ARP reply operation
        if arp_packet.get_operation() != ArpOperations::Reply {
            return None;
        }
        // Addresses must match
        if arp_packet.get_target_proto_addr() != source_ip {
            return None;
        }
        if arp_packet.get_target_hw_addr() != source_mac {
            return None;
        }

        Some(AddressPair {
            ip: arp_packet.get_sender_proto_addr().into(),
            mac: arp_packet.get_sender_hw_addr(),
        })
    }

    /// Parse Neighbor Advertisement and extract (target IPv6, source MAC).
    fn parse_na(packet: &[u8], source_ip: Ipv6Addr) -> Option<AddressPair> {
        // Try constructing Ethernet packet, on fail continue
        let eth_packet = EthernetPacket::new(packet)?;
        // Check for correct EtherType field
        if eth_packet.get_ethertype() != EtherTypes::Ipv6 {
            return None;
        }

        // Try parsing as IPv6 packet, on fail continue
        let ipv6_packet = Ipv6Packet::new(eth_packet.payload())?;
        // Check the next_header field
        if ipv6_packet.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
            return None;
        }

        let icmpv6_packet = Icmpv6Packet::new(ipv6_packet.payload())?;
        if icmpv6_packet.get_icmpv6_type() != Icmpv6Types::NeighborAdvert {
            return None;
        }
        if icmpv6_packet.get_icmpv6_code() != Icmpv6Codes::NoCode {
            return None;
        }

        let na_packet = NeighborAdvertPacket::new(ipv6_packet.payload())?;
        // Address must match
        if ipv6_packet.get_source() != na_packet.get_target_addr() {
            return None;
        }
        if ipv6_packet.get_destination() != source_ip {
            return None;
        }

        Some(AddressPair {
            ip: na_packet.get_target_addr().into(),
            mac: eth_packet.get_source(),
        })
    }

    /// Parse ICMPv4 Echo Reply and extract source IPv4 for matching.
    fn parse_icmpv4_reply(packet: &[u8], source_ip: Ipv4Addr, identifier: u16, sequence_number: u16) -> Option<Ipv4Addr> {
        // Try constructing Ethernet packet, on fail continue
        let eth_packet = EthernetPacket::new(packet)?;
        // Check for correct EtherType field
        if eth_packet.get_ethertype() != EtherTypes::Ipv4 {
            return None;
        }

        // Try parsing as IPv4 packet, on fail continue
        let ipv4_packet = Ipv4Packet::new(eth_packet.payload())?;
        // Check the next_header field
        if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
            return None;
        }

        let icmp_packet = IcmpPacket::new(ipv4_packet.payload())?;
        // Check if type and code match EchoReply
        if icmp_packet.get_icmp_type() != IcmpTypes::EchoReply {
            return None;
        }
        if icmp_packet.get_icmp_code() != IcmpCodes::NoCode {
            return None;
        }

        // Try parsing as echo reply packet, on fail continue
        let echo_reply = EchoReplyPacket::new(ipv4_packet.payload())?;
        if ipv4_packet.get_destination() != source_ip {
            return None;
        }
        // Check if identifier and sequence number match request
        if echo_reply.get_identifier() != identifier || echo_reply.get_sequence_number() != sequence_number {
            return None;
        }

        Some(ipv4_packet.get_source())
    }

    /// Parse ICMPv6 Echo Reply and extract source IPv6 for matching.
    fn parse_icmpv6_reply(packet: &[u8], source_ip: Ipv6Addr, identifier: u16, sequence_number: u16) -> Option<Ipv6Addr> {
        // Try constructing Ethernet packet, on fail continue
        let eth_packet = EthernetPacket::new(packet)?;
        // Check for correct EtherType field
        if eth_packet.get_ethertype() != EtherTypes::Ipv6 {
            return None;
        }

        // Try parsing as IPv6 packet, on fail continue
        let ipv6_packet = Ipv6Packet::new(eth_packet.payload())?;
        // Check the next_header field
        if ipv6_packet.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
            return None;
        }

        let icmpv6_packet = Icmpv6Packet::new(ipv6_packet.payload())?;
        // Should be EchoReply, but for correctness we check
        if icmpv6_packet.get_icmpv6_type() != Icmpv6Types::EchoReply {
            return None;
        }
        // Should be again 0
        if icmpv6_packet.get_icmpv6_code() != Icmpv6Codes::NoCode {
            return None;
        }

        // Try parsing as echo reply packet, on fail continue
        let echo_reply = EchoReplyPacketV6::new(ipv6_packet.payload())?;
        if ipv6_packet.get_destination() != source_ip {
            return None;
        }
        // Check if identifier and sequence number match request
        if echo_reply.get_identifier() != identifier || echo_reply.get_sequence_number() != sequence_number {
            return None;
        }

        Some(ipv6_packet.get_source())
    }

    /// Scan one subnet batch.
    fn scan_network(&self, network: &IpNet, tx: & mut Box<dyn DataLinkSender>, rx: & mut Box<dyn DataLinkReceiver>)
        -> Result<HashMap<IpAddr, ScanMatch>, ScannerError>
    {
        // Fixed ID and Seq because we do not care much about these and send one request anyway
        const IDENTIFIER: u16 = 1;
        const SEQ_NUM: u16 = 1;

        // The final HashMap of non-full-FAIL matchs
        let mut discovered: HashMap<IpAddr, ScanMatch> = HashMap::new();

        // For control signal check
        let mut last_check = Instant::now();

        // Counter that confirms all packets arrived on 0, worst case we hit timeout
        let mut pending_l2 = 0usize;

        // Repeated piece of code very specific to this function, not worth to separate for others
        let mut send_packet = |packet: &[u8], queue_err: &str, send_err_prefix: &str| -> Result<(), ScannerError> {
            let send_result = tx.send_to(packet, None).ok_or_else(|| ScannerError {
                code: ScannerExitCode::Os,
                message: queue_err.to_string(), // Error when attempting to send
            })?;

            if let Err(err) = send_result {
                return Err(ScannerError {
                    code: ScannerExitCode::Os,
                    message: format!("{}: {}", send_err_prefix, err), // Error after send request performed
                });
            }

            Ok(())
        };

        let iface_ip = match network {
            IpNet::V4(_) => IpAddr::V4(Self::get_iface_ipv4(&self.interface)?),
            IpNet::V6(_) => IpAddr::V6(Self::get_iface_ipv6(&self.interface)?),
        };

        let iface_mac = Self::get_iface_mac(&self.interface)?;

        for addr in network.hosts() {
            // Scan L2 only if in local segment
            if !self.addr_is_local(addr) {
                continue;
            }

            if Instant::now() - last_check >= CHECK_INTERVAL {
                self.check_shutdown()?;
                last_check = Instant::now();
            }

            match addr {
                IpAddr::V4(addr) => {
                    // Scan ARP
                    let arp_packet = self.make_arp(&addr)?;
                    send_packet(&arp_packet, "Failed to queue ARP frame for sending", "Failed to send ARP frame")?;
                }
                IpAddr::V6(addr) => {
                    // Scan NDP
                    let ndp_packet = self.make_ndp(&addr)?;
                    send_packet(&ndp_packet, "Failed to queue NDP frame for sending", "Failed to send NDP frame")?;
                }
            }

            pending_l2 += 1;
        }

        // Collect replies with timeout
        let mut pending_l3 = 0usize;
        let l2_deadline = Instant::now() + self.timeout;
        while Instant::now() < l2_deadline && pending_l2 > 0 {
            if Instant::now() - last_check >= CHECK_INTERVAL {
                self.check_shutdown()?;
                last_check = Instant::now();
            }

            match rx.next() {
                Ok(frame) => {
                    // Try ARP reply parse first
                    if let IpAddr::V4(source_ip) = iface_ip {
                        if let Some(pair) = Self::parse_arp(frame, source_ip, iface_mac) {
                            discovered.insert(pair.ip, ScanMatch {
                                mac_addr: Some(pair.mac),
                                icmp_responded: false
                            });

                            pending_l2 -= 1;
                            continue;
                        }
                    }

                    // If not ARP, try NDP NA parse
                    if let IpAddr::V6(source_ip) = iface_ip {
                        if let Some(pair) = Self::parse_na(frame, source_ip) {
                            discovered.insert(pair.ip, ScanMatch {
                                mac_addr: Some(pair.mac),
                                icmp_responded: false
                            });

                            pending_l2 -= 1;
                        }
                    }
                }
                Err(err) => {
                    if err.kind() == ErrorKind::TimedOut {
                        continue;
                    }

                    return Err(ScannerError {
                        code: ScannerExitCode::Os,
                        message: format!("Failed to read L2 packet from datalink: {}", err),
                    });
                }
            }
        }

        // Send L3 requests
        for addr in network.hosts() {
            if Instant::now() - last_check >= CHECK_INTERVAL {
                self.check_shutdown()?;
                last_check = Instant::now();
            }

            let mac_addr = if self.addr_is_local(addr) {
                match discovered.get(&addr).and_then(|m| m.mac_addr) {
                    // No L2 match, cannot do L3 on local target
                    Some(mac) => mac,
                    None => continue,
                }
            } else {
                // No MAC known for remote target, set broadcast
                MacAddr::broadcast()
            };

            match addr {
                IpAddr::V4(v4) => {
                    // Scan ICMPv4
                    let frame = self.make_icmpv4_echo(&v4, mac_addr, IDENTIFIER, SEQ_NUM)?;
                    send_packet(&frame, "Failed to queue ICMP frame for sending", "Failed to send ICMP frame")?;
                }
                IpAddr::V6(v6) => {
                    // Scan ICMPv6
                    let frame = self.make_icmpv6_echo(&v6, mac_addr, IDENTIFIER, SEQ_NUM)?;
                    send_packet(&frame, "Failed to queue ICMPv6 frame for sending", "Failed to send ICMPv6 frame")?;
                }
            }

            pending_l3 += 1;
        }

        // Collect replies
        let l3_deadline = Instant::now() + self.timeout;
        while Instant::now() < l3_deadline && pending_l3 > 0 {
            if Instant::now() - last_check >= CHECK_INTERVAL {
                self.check_shutdown()?;
                last_check = Instant::now();
            }

            match rx.next() {
                Ok(frame) => {
                    // Try ICMPv4 reply parse first
                    if let IpAddr::V4(source_ip) = iface_ip {
                        if let Some(ip) = Self::parse_icmpv4_reply(frame, source_ip, IDENTIFIER, SEQ_NUM) {
                            // Get existing entry or make default all FAIL
                            let scan_match = discovered.entry(IpAddr::V4(ip)).or_default();
                            scan_match.icmp_responded = true;

                            pending_l3 -= 1;
                            continue;
                        }
                    }

                    // If not ICMPv4, try ICMPv6 reply parse
                    if let IpAddr::V6(source_ip) = iface_ip {
                        if let Some(ip) = Self::parse_icmpv6_reply(frame, source_ip, IDENTIFIER, SEQ_NUM) {
                            // Get existing entry or make default all FAIL
                            let scan_match = discovered.entry(IpAddr::V6(ip)).or_default();
                            scan_match.icmp_responded = true;

                            pending_l3 -= 1;
                        }
                    }
                }
                Err(err) => {
                    if err.kind() == ErrorKind::TimedOut {
                        continue;
                    }

                    return Err(ScannerError {
                        code: ScannerExitCode::Os,
                        message: format!("Failed to read L3 packet from datalink: {}", err),
                    });
                }
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
            code: ScannerExitCode::Os,
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