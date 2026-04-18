//! Main scan logic, packet build, send, collect, parse
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use pnet::datalink::{self, Channel::Ethernet, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::echo_reply::{EchoReplyPacket, IcmpCodes};
use pnet::packet::icmp::{self, echo_request::MutableEchoRequestPacket, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::echo_reply::{EchoReplyPacket as EchoReplyPacketV6, Icmpv6Codes};
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket as MutableEchoRequestPacketV6;
use pnet::packet::icmpv6::{
    ndp::{MutableNeighborSolicitPacket, NdpOption, NdpOptionTypes, NeighborAdvertPacket},
    Icmpv6Packet, Icmpv6Types,
};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

use crate::cli::Cli;
use crate::model::{AddressPair, ControlMessage, ScanMatch, ScannerError, ScannerExitCode};
use crate::network::{get_net_size, new_ns_addr, new_ns_mac};
use crate::route::RouteTable;

const CHECK_INTERVAL: Duration = Duration::from_millis(20);
const ETH_HEADER_LEN: usize = 14;
const NDP_SOURCE_LL_ADDR_LEN: usize = 8;
const ICMP_ECHO_IDENTIFIER: u16 = 1;
const ICMP_ECHO_SEQUENCE: u16 = 1;
const IPV4_DEFAULT_TTL: u8 = 64;
const IPV6_DEFAULT_HOP_LIMIT: u8 = 64;
const IPV6_NDP_HOP_LIMIT: u8 = 255;

/// Scanner config
#[derive(Debug)]
pub struct Scanner {
    /// Interface to scan
    interface: NetworkInterface,
    /// Subnets to scan
    networks: Vec<IpNet>,
    /// Scan timeout
    timeout: Duration,
    /// Signal channel
    control_rx: Receiver<ControlMessage>,
}

/// Scanner code
impl Scanner {
    /// Send one raw frame and clean up send errors
    fn send_frame(
        tx: &mut Box<dyn DataLinkSender>,
        packet: &[u8],
        queue_err: &str,
        send_err_prefix: &str,
    ) -> Result<(), ScannerError> {
        let send_result = tx.send_to(packet, None).ok_or_else(|| ScannerError {
            code: ScannerExitCode::Os,
            message: queue_err.to_string(),
        })?;

        if let Err(err) = send_result {
            return Err(ScannerError {
                code: ScannerExitCode::Os,
                message: format!("{}: {}", send_err_prefix, err),
            });
        }

        Ok(())
    }

    /// Check shutdown only when the interval hits
    fn poll_shutdown_if_due(&self, last_check: &mut Instant) -> Result<(), ScannerError> {
        if Instant::now() - *last_check >= CHECK_INTERVAL {
            self.check_shutdown()?;
            *last_check = Instant::now();
        }

        Ok(())
    }

    /// Build scanner from CLI and control channel
    pub fn try_new(value: Cli, control_rx: Receiver<ControlMessage>) -> Result<Self, ScannerError> {
        // No args and no help, so bail out
        if value.interface.is_none() && value.subnets.is_none() {
            return Err(ScannerError {
                code: ScannerExitCode::Cli,
                message: "No arguments provided".to_string(),
            });
        }

        // Used in a few branches
        let interfaces = pnet::datalink::interfaces();
        match value.interface {
            // -i given
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
                        // -s is there, config is done
                        Some(subnets) => Ok(Self {
                            interface,
                            networks: subnets,
                            timeout: Duration::from_millis(value.timeout),
                            control_rx,
                        }),
                        // -s missing, so stop here
                        None => Err(ScannerError {
                            code: ScannerExitCode::Cli,
                            message: "No subnets specified".to_string(),
                        }),
                    }
                }
                // -i without a value, list ifaces and exit
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
            // no -i, so that is a CLI error
            None => Err(ScannerError {
                code: ScannerExitCode::Cli,
                message: "-i option was not used".to_string(),
            }),
        }
    }

    /// Check if a shutdown was asked for
    fn check_shutdown(&self) -> Result<(), ScannerError> {
        match self.control_rx.try_recv() {
            // signal thread wants stop
            Ok(ControlMessage::Shutdown(code)) => Err(ScannerError {
                code,
                message: "Graceful shutdown requested by signal".to_string(),
            }),
            Err(mpsc::TryRecvError::Empty) => Ok(()),
            Err(mpsc::TryRecvError::Disconnected) => Err(ScannerError {
                code: ScannerExitCode::Io,
                message: "Failed to check signal channel state".to_string(),
            }),
        }
    }

    /// Check if addr is on the local link
    pub fn addr_is_local(&self, addr: IpAddr) -> bool {
        self.interface.ips.iter().any(|net| net.contains(addr))
    }

    /// Get iface MAC or fail
    fn get_iface_mac(interface: &NetworkInterface) -> Result<MacAddr, ScannerError> {
        interface.mac.ok_or_else(|| ScannerError {
            code: ScannerExitCode::Os,
            message: "Failed to retrieve MAC address for the interface".to_string(),
        })
    }

    /// Get the first IPv4 on the iface
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

    /// Get the IPv6 we want for NDP
    fn get_iface_ipv6_ndp(interface: &NetworkInterface) -> Result<Ipv6Addr, ScannerError> {
        interface
            .ips
            .iter()
            .find_map(|ipn| match ipn.ip() {
                IpAddr::V6(addr) if addr.is_unicast_link_local() => Some(addr),
                _ => None,
            })
            .or_else(|| {
                interface.ips.iter().find_map(|ipn| match ipn.ip() {
                    IpAddr::V4(_) => None,
                    IpAddr::V6(addr) => Some(addr),
                })
            })
            .ok_or_else(|| ScannerError {
                code: ScannerExitCode::Config,
                message: "Interface has no IPv6 address".to_string(),
            })
    }

    /// Get the IPv6 we want for echo
    fn get_iface_ipv6_echo(interface: &NetworkInterface) -> Result<Ipv6Addr, ScannerError> {
        interface
            .ips
            .iter()
            .find_map(|ipn| match ipn.ip() {
                IpAddr::V6(addr) if !addr.is_unicast_link_local() => Some(addr),
                _ => None,
            })
            .or_else(|| Self::get_iface_ipv6_ndp(interface).ok())
            .ok_or_else(|| ScannerError {
                code: ScannerExitCode::Config,
                message: "Interface has no IPv6 address".to_string(),
            })
    }

    /// Resolve one neighbor MAC with ARP or NDP
    fn resolve_neighbor_mac(
        &self,
        target: IpAddr,
        tx: &mut Box<dyn DataLinkSender>,
        rx: &mut Box<dyn DataLinkReceiver>,
    ) -> Result<MacAddr, ScannerError> {
        let mut last_check = Instant::now();
        let deadline = Instant::now() + self.timeout;
        let iface_mac = Self::get_iface_mac(&self.interface)?;

        match target {
            IpAddr::V4(v4) => {
                let source_ip = Self::get_iface_ipv4(&self.interface)?;
                let packet = self.make_arp(&v4)?;
                Self::send_frame(
                    tx,
                    &packet,
                    "Failed to queue ARP frame for gateway resolution",
                    "Failed to send ARP frame",
                )?;

                while Instant::now() < deadline {
                    if Instant::now() - last_check >= CHECK_INTERVAL {
                        self.check_shutdown()?;
                        last_check = Instant::now();
                    }

                    match rx.next() {
                        Ok(frame) => {
                            if let Some(pair) = Self::parse_arp(frame, source_ip, iface_mac) {
                                if pair.ip == target {
                                    return Ok(pair.mac);
                                }
                            }
                        }
                        Err(err) => {
                            if err.kind() == ErrorKind::TimedOut {
                                continue;
                            }

                            return Err(ScannerError {
                                code: ScannerExitCode::Os,
                                message: format!("Failed to read ARP reply from datalink: {}", err),
                            });
                        }
                    }
                }
            }
            IpAddr::V6(v6) => {
                let source_ip = Self::get_iface_ipv6_ndp(&self.interface)?;
                let packet = self.make_ndp(&v6)?;
                Self::send_frame(
                    tx,
                    &packet,
                    "Failed to queue NDP frame for gateway resolution",
                    "Failed to send NDP frame",
                )?;

                while Instant::now() < deadline {
                    if Instant::now() - last_check >= CHECK_INTERVAL {
                        self.check_shutdown()?;
                        last_check = Instant::now();
                    }

                    match rx.next() {
                        Ok(frame) => {
                            if let Some(pair) = Self::parse_na(frame, source_ip) {
                                if pair.ip == target {
                                    return Ok(pair.mac);
                                }
                            }
                        }
                        Err(err) => {
                            if err.kind() == ErrorKind::TimedOut {
                                continue;
                            }

                            return Err(ScannerError {
                                code: ScannerExitCode::Os,
                                message: format!("Failed to read NDP reply from datalink: {}", err),
                            });
                        }
                    }
                }
            }
        }

        Err(ScannerError {
            code: ScannerExitCode::Timeout,
            message: format!("Timed out resolving gateway MAC for {}", target),
        })
    }

    /// Build one Ethernet frame
    fn make_ethernet(
        iface: &NetworkInterface,
        dest: MacAddr,
        ethertype: EtherType,
        payload_size: usize,
    ) -> Result<Vec<u8>, ScannerError> {
        let source = Self::get_iface_mac(iface)?;

        // Ethernet header is 14 bytes
        let mut buffer = vec![0u8; ETH_HEADER_LEN + payload_size];
        let mut eth_packet =
            MutableEthernetPacket::new(&mut buffer).ok_or_else(|| ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to create Ethernet frame".to_string(),
            })?;

        eth_packet.set_destination(dest);
        eth_packet.set_source(source);
        eth_packet.set_ethertype(ethertype);

        Ok(buffer)
    }

    /// Build Ethernet plus IPv6
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

        let mut eth_packet =
            MutableEthernetPacket::new(&mut buffer).ok_or_else(|| ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to create Ethernet frame for IPv6 payload".to_string(),
            })?;

        let mut ipv6_packet =
            MutableIpv6Packet::new(eth_packet.payload_mut()).ok_or_else(|| ScannerError {
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

    /// Build Ethernet plus IPv4
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

        let mut eth_packet =
            MutableEthernetPacket::new(&mut buffer).ok_or_else(|| ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to create Ethernet frame for IPv4 payload".to_string(),
            })?;

        let mut ipv4_packet =
            MutableIpv4Packet::new(eth_packet.payload_mut()).ok_or_else(|| ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to create IPv4 packet".to_string(),
            })?;

        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet
            .set_total_length((MutableIpv4Packet::minimum_packet_size() + payload_len) as u16);
        ipv4_packet.set_ttl(ttl);
        ipv4_packet.set_next_level_protocol(next_header);
        ipv4_packet.set_source(source_ip);
        ipv4_packet.set_destination(dest_ip);

        let ipv4_packet_imm =
            Ipv4Packet::new(ipv4_packet.packet()).ok_or_else(|| ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to view IPv4 packet for checksum calculation".to_string(),
            })?;
        let ipv4_checksum = pnet::packet::ipv4::checksum(&ipv4_packet_imm);
        ipv4_packet.set_checksum(ipv4_checksum);

        Ok(buffer)
    }

    /// Build one ARP request
    fn make_arp(&self, target_ip: &Ipv4Addr) -> Result<Vec<u8>, ScannerError> {
        // ARP payload is fixed at 28 bytes
        let mut buffer = Self::make_ethernet(
            &self.interface,
            MacAddr::broadcast(),
            EtherTypes::Arp,
            MutableArpPacket::minimum_packet_size(),
        )?;

        let mut arp_packet =
            MutableArpPacket::new(&mut buffer[MutableEthernetPacket::minimum_packet_size()..])
                .ok_or_else(|| ScannerError {
                    code: ScannerExitCode::Internal,
                    message: "Failed to create ARP packet".to_string(),
                })?;

        let source_ip = Self::get_iface_ipv4(&self.interface)?;

        // Ethernet is the only hw type we need
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        // Request opcode
        arp_packet.set_operation(ArpOperations::Request);

        // MACs are 6 bytes
        arp_packet.set_hw_addr_len(6);
        // IPv4 addrs are 4 bytes
        arp_packet.set_proto_addr_len(4);

        arp_packet.set_sender_hw_addr(Self::get_iface_mac(&self.interface)?);
        arp_packet.set_sender_proto_addr(source_ip);

        // Target MAC is unknown here, use zero
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(*target_ip);

        Ok(buffer)
    }

    /// Build one NDP Neighbor Solicitation
    fn make_ndp(&self, target_ip: &Ipv6Addr) -> Result<Vec<u8>, ScannerError> {
        // NS body plus one source MAC option
        let ndp_len = MutableNeighborSolicitPacket::minimum_packet_size() + NDP_SOURCE_LL_ADDR_LEN;

        let source_ip = Self::get_iface_ipv6_ndp(&self.interface)?;
        // Need the source MAC option
        let source_mac = Self::get_iface_mac(&self.interface)?;
        // Dest IPv6 is the solicited-node multicast addr
        let dest_ip = new_ns_addr(target_ip);

        // Solicited-node MAC keeps it local
        // Hop limit 255 is the NDP rule
        let mut buffer = self.make_ipv6(
            new_ns_mac(target_ip),
            source_ip,
            dest_ip,
            IpNextHeaderProtocols::Icmpv6,
            IPV6_NDP_HOP_LIMIT,
            ndp_len,
        )?;

        let mut eth_packet =
            MutableEthernetPacket::new(&mut buffer).ok_or_else(|| ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to create Ethernet frame for NDP".to_string(),
            })?;

        let mut ipv6_packet =
            MutableIpv6Packet::new(eth_packet.payload_mut()).ok_or_else(|| ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to create IPv6 packet".to_string(),
            })?;

        let mut ndp_packet = MutableNeighborSolicitPacket::new(ipv6_packet.payload_mut())
            .ok_or_else(|| ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to create NDP packet".to_string(),
            })?;

        ndp_packet.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
        ndp_packet.set_target_addr(*target_ip);

        // Add the source link-layer option
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

        // Body plus IPv6 pseudo header
        let checksum = pnet::packet::icmpv6::checksum(&icmp_packet, &source_ip, &dest_ip);
        ndp_packet.set_checksum(checksum);

        Ok(buffer)
    }

    /// Build one IPv4 ICMP echo request
    fn make_icmpv4_echo(
        &self,
        target_ip: &Ipv4Addr,
        mac_addr: MacAddr,
        identifier: u16,
        sequence_number: u16,
    ) -> Result<Vec<u8>, ScannerError> {
        // Space for IPv4 header plus ICMP echo
        let echo_len = MutableEchoRequestPacket::minimum_packet_size();
        let source_ip = Self::get_iface_ipv4(&self.interface)?;

        let mut buffer = self.make_ipv4(
            mac_addr,
            source_ip,
            *target_ip,
            IpNextHeaderProtocols::Icmp,
            IPV4_DEFAULT_TTL,
            echo_len,
        )?;

        let mut ipv4_packet =
            MutableIpv4Packet::new(&mut buffer[MutableEthernetPacket::minimum_packet_size()..])
                .ok_or_else(|| ScannerError {
                    code: ScannerExitCode::Internal,
                    message: "Failed to create IPv4 packet for ICMP".to_string(),
                })?;

        let mut icmp_packet =
            MutableEchoRequestPacket::new(ipv4_packet.payload_mut()).ok_or_else(|| {
                ScannerError {
                    code: ScannerExitCode::Internal,
                    message: "Failed to create ICMPv4 echo request packet".to_string(),
                }
            })?;

        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        // Value does not matter much here
        icmp_packet.set_sequence_number(sequence_number);
        icmp_packet.set_identifier(identifier);

        let icmp_packet_imm =
            IcmpPacket::new(icmp_packet.packet()).ok_or_else(|| ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to view ICMPv4 echo request for checksum calculation".to_string(),
            })?;
        let checksum_value = icmp::checksum(&icmp_packet_imm);
        icmp_packet.set_checksum(checksum_value);

        Ok(buffer)
    }

    /// Build one IPv6 ICMP echo request
    fn make_icmpv6_echo(
        &self,
        target_ip: &Ipv6Addr,
        mac_addr: MacAddr,
        identifier: u16,
        sequence_number: u16,
    ) -> Result<Vec<u8>, ScannerError> {
        let echo_len = MutableEchoRequestPacketV6::minimum_packet_size();
        let source_ip = Self::get_iface_ipv6_echo(&self.interface)?;

        let mut buffer = self.make_ipv6(
            mac_addr,
            source_ip,
            *target_ip,
            IpNextHeaderProtocols::Icmpv6,
            IPV6_DEFAULT_HOP_LIMIT,
            echo_len,
        )?;

        let mut eth_packet =
            MutableEthernetPacket::new(&mut buffer).ok_or_else(|| ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to create Ethernet frame for ICMPv6".to_string(),
            })?;

        let mut ipv6_packet =
            MutableIpv6Packet::new(eth_packet.payload_mut()).ok_or_else(|| ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to create IPv6 packet for ICMPv6".to_string(),
            })?;

        let mut icmpv6_packet = MutableEchoRequestPacketV6::new(ipv6_packet.payload_mut())
            .ok_or_else(|| ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to create ICMPv6 echo request packet".to_string(),
            })?;

        icmpv6_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
        // Code is zero
        icmpv6_packet.set_icmpv6_code(Icmpv6Codes::NoCode);
        icmpv6_packet.set_identifier(identifier);
        icmpv6_packet.set_sequence_number(sequence_number);

        let icmp_packet =
            Icmpv6Packet::new(icmpv6_packet.packet()).ok_or_else(|| ScannerError {
                code: ScannerExitCode::Internal,
                message: "Failed to view ICMPv6 echo request as ICMPv6 packet".to_string(),
            })?;
        icmpv6_packet.set_checksum(pnet::packet::icmpv6::checksum(
            &icmp_packet,
            &source_ip,
            target_ip,
        ));

        Ok(buffer)
    }

    /// Parse ARP reply and get sender IP plus MAC
    fn parse_arp(packet: &[u8], source_ip: Ipv4Addr, source_mac: MacAddr) -> Option<AddressPair> {
        // Try Ethernet first, bail if it fails
        let eth_packet = EthernetPacket::new(packet)?;
        // Check EtherType
        if eth_packet.get_ethertype() != EtherTypes::Arp {
            return None;
        }

        // Try ARP next
        let arp_packet = ArpPacket::new(eth_packet.payload())?;
        // Check ARP header bits
        if arp_packet.get_hardware_type() != ArpHardwareTypes::Ethernet {
            return None;
        }
        if arp_packet.get_protocol_type() != EtherTypes::Ipv4 {
            return None;
        }
        if arp_packet.get_hw_addr_len() != 6 || arp_packet.get_proto_addr_len() != 4 {
            return None;
        }
        // Need a reply op
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

    /// Parse NA and get target IPv6 plus MAC
    fn parse_na(packet: &[u8], source_ip: Ipv6Addr) -> Option<AddressPair> {
        // Try Ethernet first, bail if it fails
        let eth_packet = EthernetPacket::new(packet)?;
        // Check EtherType
        if eth_packet.get_ethertype() != EtherTypes::Ipv6 {
            return None;
        }

        // Try IPv6 next
        let ipv6_packet = Ipv6Packet::new(eth_packet.payload())?;
        // Check next header
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

    /// Parse ICMPv4 echo reply and get the source IPv4
    fn parse_icmpv4_reply(
        packet: &[u8],
        source_ip: Ipv4Addr,
        identifier: u16,
        sequence_number: u16,
    ) -> Option<Ipv4Addr> {
        // Try Ethernet first, bail if it fails
        let eth_packet = EthernetPacket::new(packet)?;
        // Check EtherType
        if eth_packet.get_ethertype() != EtherTypes::Ipv4 {
            return None;
        }

        // Try IPv4 next
        let ipv4_packet = Ipv4Packet::new(eth_packet.payload())?;
        // Check next header
        if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
            return None;
        }

        let icmp_packet = IcmpPacket::new(ipv4_packet.payload())?;
        // Need echo reply type and code
        if icmp_packet.get_icmp_type() != IcmpTypes::EchoReply {
            return None;
        }
        if icmp_packet.get_icmp_code() != IcmpCodes::NoCode {
            return None;
        }

        // Try echo reply packet
        let echo_reply = EchoReplyPacket::new(ipv4_packet.payload())?;
        if ipv4_packet.get_destination() != source_ip {
            return None;
        }
        // id and seq must match
        if echo_reply.get_identifier() != identifier
            || echo_reply.get_sequence_number() != sequence_number
        {
            return None;
        }

        Some(ipv4_packet.get_source())
    }

    /// Parse ICMPv6 echo reply and get the source IPv6
    fn parse_icmpv6_reply(
        packet: &[u8],
        source_ip: Ipv6Addr,
        identifier: u16,
        sequence_number: u16,
    ) -> Option<Ipv6Addr> {
        // Try Ethernet first, bail if it fails
        let eth_packet = EthernetPacket::new(packet)?;
        // Check EtherType
        if eth_packet.get_ethertype() != EtherTypes::Ipv6 {
            return None;
        }

        // Try IPv6 next
        let ipv6_packet = Ipv6Packet::new(eth_packet.payload())?;
        // Check next header
        if ipv6_packet.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
            return None;
        }

        let icmpv6_packet = Icmpv6Packet::new(ipv6_packet.payload())?;
        // Need echo reply type
        if icmpv6_packet.get_icmpv6_type() != Icmpv6Types::EchoReply {
            return None;
        }
        // Code should be zero
        if icmpv6_packet.get_icmpv6_code() != Icmpv6Codes::NoCode {
            return None;
        }

        // Try echo reply packet
        let echo_reply = EchoReplyPacketV6::new(ipv6_packet.payload())?;
        if ipv6_packet.get_destination() != source_ip {
            return None;
        }
        // id and seq must match
        if echo_reply.get_identifier() != identifier
            || echo_reply.get_sequence_number() != sequence_number
        {
            return None;
        }

        Some(ipv6_packet.get_source())
    }

    /// Scan one subnet
    pub fn scan_network(
        &self,
        network: &IpNet,
        routes: &RouteTable,
        tx: &mut Box<dyn DataLinkSender>,
        rx: &mut Box<dyn DataLinkReceiver>,
    ) -> Result<HashMap<IpAddr, ScanMatch>, ScannerError> {
        // Fixed id and seq keep matching simple
        const IDENTIFIER: u16 = ICMP_ECHO_IDENTIFIER;
        const SEQ_NUM: u16 = ICMP_ECHO_SEQUENCE;

        // Final map of matches
        let mut discovered: HashMap<IpAddr, ScanMatch> = HashMap::new();

        // For signal checks
        let mut last_check = Instant::now();

        // Counts pending L2 replies
        let mut pending_l2 = 0usize;

        let iface_ip = match network {
            IpNet::V4(_) => IpAddr::V4(Self::get_iface_ipv4(&self.interface)?),
            IpNet::V6(_) => IpAddr::V6(Self::get_iface_ipv6_echo(&self.interface)?),
        };

        let ndp_source_ip = match network {
            IpNet::V4(_) => None,
            IpNet::V6(_) => Some(Self::get_iface_ipv6_ndp(&self.interface)?),
        };

        let iface_mac = Self::get_iface_mac(&self.interface)?;

        for addr in network.hosts() {
            // L2 only for local stuff
            if !self.addr_is_local(addr) {
                continue;
            }

            self.poll_shutdown_if_due(&mut last_check)?;

            match addr {
                IpAddr::V4(addr) => {
                    // Local IPv4 uses ARP
                    let arp_packet = self.make_arp(&addr)?;
                    Self::send_frame(
                        tx,
                        &arp_packet,
                        "Failed to queue ARP frame for sending",
                        "Failed to send ARP frame",
                    )?;
                }
                IpAddr::V6(addr) => {
                    // Local IPv6 uses NDP
                    let ndp_packet = self.make_ndp(&addr)?;
                    Self::send_frame(
                        tx,
                        &ndp_packet,
                        "Failed to queue NDP frame for sending",
                        "Failed to send NDP frame",
                    )?;
                }
            }

            pending_l2 += 1;
        }

        // Collect replies with a timeout
        let mut pending_l3 = 0usize;
        let l2_deadline = Instant::now() + self.timeout;
        while Instant::now() < l2_deadline && pending_l2 > 0 {
            self.poll_shutdown_if_due(&mut last_check)?;

            match rx.next() {
                Ok(frame) => {
                    // Try ARP first
                    if let IpAddr::V4(source_ip) = iface_ip {
                        if let Some(pair) = Self::parse_arp(frame, source_ip, iface_mac) {
                            discovered.insert(
                                pair.ip,
                                ScanMatch {
                                    mac_addr: Some(pair.mac),
                                    icmp_responded: false,
                                },
                            );

                            pending_l2 -= 1;
                            continue;
                        }
                    }

                    // If not ARP, try NDP NA
                    if let Some(source_ip) = ndp_source_ip {
                        if let Some(pair) = Self::parse_na(frame, source_ip) {
                            discovered.insert(
                                pair.ip,
                                ScanMatch {
                                    mac_addr: Some(pair.mac),
                                    icmp_responded: false,
                                },
                            );

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
        let mut remote_mac: Option<MacAddr> = None;

        for addr in network.hosts() {
            if Instant::now() - last_check >= CHECK_INTERVAL {
                self.check_shutdown()?;
                last_check = Instant::now();
            }

            let mac_addr = if self.addr_is_local(addr) {
                match discovered.get(&addr).and_then(|m| m.mac_addr) {
                    // No L2 match, so skip local L3
                    Some(mac) => mac,
                    None => continue,
                }
            } else {
                // Resolve the next hop once and reuse it
                match remote_mac {
                    Some(mac) => mac,
                    None => {
                        let gateway = routes.gateway_for(addr)?;
                        let mac = self.resolve_neighbor_mac(gateway, tx, rx)?;
                        remote_mac = Some(mac);
                        mac
                    }
                }
            };

            match addr {
                IpAddr::V4(v4) => {
                    // ICMPv4 checks IPv4 reachability
                    let frame = self.make_icmpv4_echo(&v4, mac_addr, IDENTIFIER, SEQ_NUM)?;
                    Self::send_frame(
                        tx,
                        &frame,
                        "Failed to queue ICMP frame for sending",
                        "Failed to send ICMP frame",
                    )?;
                }
                IpAddr::V6(v6) => {
                    // ICMPv6 checks IPv6 reachability
                    let frame = self.make_icmpv6_echo(&v6, mac_addr, IDENTIFIER, SEQ_NUM)?;
                    Self::send_frame(
                        tx,
                        &frame,
                        "Failed to queue ICMPv6 frame for sending",
                        "Failed to send ICMPv6 frame",
                    )?;
                }
            }

            pending_l3 += 1;
        }

        // Collect replies
        let l3_deadline = Instant::now() + self.timeout;
        while Instant::now() < l3_deadline && pending_l3 > 0 {
            self.poll_shutdown_if_due(&mut last_check)?;

            match rx.next() {
                Ok(frame) => {
                    // Try ICMPv4 first
                    if let IpAddr::V4(source_ip) = iface_ip {
                        if let Some(ip) =
                            Self::parse_icmpv4_reply(frame, source_ip, IDENTIFIER, SEQ_NUM)
                        {
                            // Get old entry or make a fail one
                            let scan_match = discovered.entry(IpAddr::V4(ip)).or_default();
                            scan_match.icmp_responded = true;

                            pending_l3 -= 1;
                            continue;
                        }
                    }

                    // If not ICMPv4, try ICMPv6
                    if let IpAddr::V6(source_ip) = iface_ip {
                        if let Some(ip) =
                            Self::parse_icmpv6_reply(frame, source_ip, IDENTIFIER, SEQ_NUM)
                        {
                            // Get old entry or make a fail one
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

    /// Print the networks we scan
    pub fn print_nets(&self) {
        for net in &self.networks {
            println!("{} {}", net, get_net_size(net));
        }
    }

    /// Borrow the configured networks
    pub fn networks(&self) -> &[IpNet] {
        &self.networks
    }

    /// Run the scan. None means fail. May return ScannerError
    pub fn run(&self) -> Result<HashMap<IpAddr, ScanMatch>, ScannerError> {
        let mut discovered = HashMap::new();

        // Build iface channel config
        let config = datalink::Config {
            read_timeout: Some(Duration::from_millis(20)),
            ..Default::default()
        };

        let routes = RouteTable::new(&self.interface);

        // Open the datalink channel and check for Ethernet
        let (mut tx, mut rx) =
            match datalink::channel(&self.interface, config).map_err(|err| ScannerError {
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

        // Scan each network and merge the results
        for network in &self.networks {
            let results = self.scan_network(network, &routes, &mut tx, &mut rx)?;
            discovered.extend(results);
        }

        Ok(discovered)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::time::Duration;

    use pnet::ipnetwork::IpNetwork;
    use pnet::packet::arp::{ArpOperations, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
    use pnet::packet::icmp::{self, IcmpPacket, IcmpTypes};
    use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket as MutableEchoRequestPacketV6;
    use pnet::packet::icmpv6::ndp::{MutableNeighborSolicitPacket, NeighborSolicitPacket};
    use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
    use pnet::util::MacAddr;

    const SOURCE_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
    const SOURCE_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const SOURCE_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xcafe, 0, 0, 0, 0, 0, 1);
    const TARGET_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 42);
    const TARGET_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xcafe, 0, 0, 0, 0, 0, 0x42);


    fn test_interface() -> NetworkInterface {
        NetworkInterface {
            name: "test0".to_string(),
            description: "test interface".to_string(),
            index: 1,
            mac: Some(SOURCE_MAC),
            ips: vec![
                IpNetwork::new(IpAddr::V4(SOURCE_V4), 24).unwrap(),
                IpNetwork::new(IpAddr::V6(SOURCE_V6), 64).unwrap(),
            ],
            flags: 0,
        }
    }

    fn test_scanner() -> Scanner {
        let (_control_tx, control_rx) = mpsc::channel();

        Scanner {
            interface: test_interface(),
            networks: vec![
                IpNet::from_str("10.0.0.0/24").unwrap(),
                IpNet::from_str("fd00:cafe::/120").unwrap(),
            ],
            timeout: Duration::from_millis(10),
            control_rx,
        }
    }

    // ===== Packet construction =====

    #[test]
    fn arp_frame() {
        let scanner = test_scanner();
        let frame = scanner.make_arp(&TARGET_V4).unwrap();

        let ethernet = EthernetPacket::new(&frame).unwrap();
        assert_eq!(ethernet.get_ethertype(), EtherTypes::Arp);

        let arp = pnet::packet::arp::ArpPacket::new(ethernet.payload()).unwrap();
        assert_eq!(arp.get_operation(), ArpOperations::Request);
        assert_eq!(arp.get_sender_proto_addr(), SOURCE_V4);
        assert_eq!(arp.get_target_proto_addr(), TARGET_V4);
        assert_eq!(arp.get_target_hw_addr(), MacAddr::zero());
    }

    #[test]
    fn ndp_frame() {
        let scanner = test_scanner();
        let frame = scanner.make_ndp(&TARGET_V6).unwrap();

        let ethernet = EthernetPacket::new(&frame).unwrap();
        assert_eq!(ethernet.get_ethertype(), EtherTypes::Ipv6);
        assert_eq!(ethernet.get_destination(), new_ns_mac(&TARGET_V6));

        let ipv6 = Ipv6Packet::new(ethernet.payload()).unwrap();
        assert_eq!(ipv6.get_next_header(), pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
        assert_eq!(ipv6.get_hop_limit(), 255);
        assert_eq!(ipv6.get_destination(), new_ns_addr(&TARGET_V6));

        let ndp = NeighborSolicitPacket::new(ipv6.payload()).unwrap();
        assert_eq!(ndp.get_icmpv6_type(), Icmpv6Types::NeighborSolicit);
        assert_eq!(ndp.get_target_addr(), TARGET_V6);
    }

    #[test]
    fn icmp4_frame() {
        let scanner = test_scanner();
        let frame = scanner.make_icmpv4_echo(&TARGET_V4, MacAddr::broadcast(), 7, 9).unwrap();

        let ethernet = EthernetPacket::new(&frame).unwrap();
        let ipv4 = Ipv4Packet::new(ethernet.payload()).unwrap();
        assert_eq!(ipv4.get_next_level_protocol(), pnet::packet::ip::IpNextHeaderProtocols::Icmp);
        assert_eq!(ipv4.get_destination(), TARGET_V4);

        let icmp = IcmpPacket::new(ipv4.payload()).unwrap();
        assert_eq!(icmp.get_icmp_type(), IcmpTypes::EchoRequest);
        assert_eq!(icmp.get_checksum(), icmp::checksum(&icmp));
    }

    #[test]
    fn icmp6_frame() {
        let scanner = test_scanner();
        let frame = scanner.make_icmpv6_echo(&TARGET_V6, MacAddr::broadcast(), 7, 9).unwrap();

        let ethernet = EthernetPacket::new(&frame).unwrap();
        let ipv6 = Ipv6Packet::new(ethernet.payload()).unwrap();
        assert_eq!(ipv6.get_next_header(), pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
        assert_eq!(ipv6.get_destination(), TARGET_V6);

        let icmpv6 = Icmpv6Packet::new(ipv6.payload()).unwrap();
        assert_eq!(icmpv6.get_icmpv6_type(), Icmpv6Types::EchoRequest);
    }

    // ===== Packet parsing =====

    #[test]
    fn arp_parse() {
        let scanner = test_scanner();
        let sender_mac = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x02);
        let sender_ip = TARGET_V4;
        let mut frame = scanner.make_arp(&sender_ip).unwrap();

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            ethernet.set_source(sender_mac);
            ethernet.set_destination(SOURCE_MAC);

            let mut arp = MutableArpPacket::new(ethernet.payload_mut()).unwrap();
            arp.set_operation(ArpOperations::Reply);
            arp.set_sender_hw_addr(sender_mac);
            arp.set_sender_proto_addr(sender_ip);
            arp.set_target_hw_addr(SOURCE_MAC);
            arp.set_target_proto_addr(SOURCE_V4);
        }

        let parsed = Scanner::parse_arp(&frame, SOURCE_V4, SOURCE_MAC).unwrap();
        assert_eq!(parsed.ip, IpAddr::V4(sender_ip));
        assert_eq!(parsed.mac, sender_mac);
    }

    #[test]
    fn arp_reject() {
        let scanner = test_scanner();
        let mut frame = scanner.make_arp(&TARGET_V4).unwrap();

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            let mut arp = MutableArpPacket::new(ethernet.payload_mut()).unwrap();
            arp.set_operation(ArpOperations::Reply);
            arp.set_target_proto_addr(Ipv4Addr::new(10, 0, 0, 99));
        }

        assert!(Scanner::parse_arp(&frame, SOURCE_V4, SOURCE_MAC).is_none());
    }

    #[test]
    fn arp_reject_ethertype() {
        let scanner = test_scanner();
        let mut frame = scanner.make_arp(&TARGET_V4).unwrap();

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            ethernet.set_ethertype(EtherTypes::Ipv6);
        }

        assert!(Scanner::parse_arp(&frame, SOURCE_V4, SOURCE_MAC).is_none());
    }

    #[test]
    fn ndp_parse() {
        let scanner = test_scanner();
        let mut frame = scanner.make_ndp(&TARGET_V6).unwrap();

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            ethernet.set_source(SOURCE_MAC);
            ethernet.set_destination(SOURCE_MAC);

            let mut ipv6 = MutableIpv6Packet::new(ethernet.payload_mut()).unwrap();
            ipv6.set_source(TARGET_V6);
            ipv6.set_destination(SOURCE_V6);

            let mut ndp = MutableNeighborSolicitPacket::new(ipv6.payload_mut()).unwrap();
            ndp.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
            ndp.set_target_addr(TARGET_V6);
            ndp.set_checksum(pnet::packet::icmpv6::checksum(
                &Icmpv6Packet::new(ndp.packet()).unwrap(),
                &TARGET_V6,
                &SOURCE_V6,
            ));
        }

        let parsed = Scanner::parse_na(&frame, SOURCE_V6).unwrap();
        assert_eq!(parsed.ip, IpAddr::V6(TARGET_V6));
        assert_eq!(parsed.mac, SOURCE_MAC);
    }

    #[test]
    fn ndp_reject() {
        let scanner = test_scanner();
        let mut frame = scanner.make_ndp(&TARGET_V6).unwrap();

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            let mut ipv6 = MutableIpv6Packet::new(ethernet.payload_mut()).unwrap();
            let mut ndp = MutableNeighborSolicitPacket::new(ipv6.payload_mut()).unwrap();
            ndp.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
        }

        assert!(Scanner::parse_na(&frame, SOURCE_V6).is_none());
    }

    #[test]
    fn ndp_reject_destination() {
        let scanner = test_scanner();
        let mut frame = scanner.make_ndp(&TARGET_V6).unwrap();

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            let mut ipv6 = MutableIpv6Packet::new(ethernet.payload_mut()).unwrap();
            ipv6.set_destination(Ipv6Addr::new(0xfd00, 0xcafe, 0, 0, 0, 0, 0, 0x43));
            let mut ndp = MutableNeighborSolicitPacket::new(ipv6.payload_mut()).unwrap();
            ndp.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
        }

        assert!(Scanner::parse_na(&frame, SOURCE_V6).is_none());
    }

    #[test]
    fn icmp4_parse() {
        let scanner = test_scanner();
        let mut frame = scanner.make_icmpv4_echo(&TARGET_V4, MacAddr::broadcast(), 7, 9).unwrap();

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            let mut ipv4 = MutableIpv4Packet::new(ethernet.payload_mut()).unwrap();
            ipv4.set_source(TARGET_V4);
            ipv4.set_destination(SOURCE_V4);
            let mut icmp = MutableEchoRequestPacket::new(ipv4.payload_mut()).unwrap();
            icmp.set_icmp_type(IcmpTypes::EchoReply);
            icmp.set_checksum(icmp::checksum(&IcmpPacket::new(icmp.packet()).unwrap()));
        }

        assert_eq!(Scanner::parse_icmpv4_reply(&frame, SOURCE_V4, 7, 9), Some(TARGET_V4));
    }

    #[test]
    fn icmp4_reject() {
        let scanner = test_scanner();
        let mut frame = scanner.make_icmpv4_echo(&TARGET_V4, MacAddr::broadcast(), 7, 9).unwrap();

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            let mut ipv4 = MutableIpv4Packet::new(ethernet.payload_mut()).unwrap();
            let mut icmp = MutableEchoRequestPacket::new(ipv4.payload_mut()).unwrap();
            icmp.set_icmp_type(IcmpTypes::EchoReply);
            icmp.set_identifier(99);
            icmp.set_checksum(icmp::checksum(&IcmpPacket::new(icmp.packet()).unwrap()));
        }

        assert!(Scanner::parse_icmpv4_reply(&frame, SOURCE_V4, 7, 9).is_none());
    }

    #[test]
    fn icmp4_reject_proto() {
        let scanner = test_scanner();
        let mut frame = scanner.make_icmpv4_echo(&TARGET_V4, MacAddr::broadcast(), 7, 9).unwrap();

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            let mut ipv4 = MutableIpv4Packet::new(ethernet.payload_mut()).unwrap();
            ipv4.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
            let mut icmp = MutableEchoRequestPacket::new(ipv4.payload_mut()).unwrap();
            icmp.set_icmp_type(IcmpTypes::EchoReply);
        }

        assert!(Scanner::parse_icmpv4_reply(&frame, SOURCE_V4, 7, 9).is_none());
    }

    #[test]
    fn icmp6_parse() {
        let scanner = test_scanner();
        let mut frame = scanner.make_icmpv6_echo(&TARGET_V6, MacAddr::broadcast(), 7, 9).unwrap();

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            let mut ipv6 = MutableIpv6Packet::new(ethernet.payload_mut()).unwrap();
            ipv6.set_source(TARGET_V6);
            ipv6.set_destination(SOURCE_V6);
            let mut icmpv6 = MutableEchoRequestPacketV6::new(ipv6.payload_mut()).unwrap();
            icmpv6.set_icmpv6_type(Icmpv6Types::EchoReply);
            icmpv6.set_checksum(pnet::packet::icmpv6::checksum(
                &Icmpv6Packet::new(icmpv6.packet()).unwrap(),
                &TARGET_V6,
                &SOURCE_V6,
            ));
        }

        assert_eq!(Scanner::parse_icmpv6_reply(&frame, SOURCE_V6, 7, 9), Some(TARGET_V6));
    }

    #[test]
    fn icmp6_reject() {
        let scanner = test_scanner();
        let mut frame = scanner.make_icmpv6_echo(&TARGET_V6, MacAddr::broadcast(), 7, 9).unwrap();

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            let mut ipv6 = MutableIpv6Packet::new(ethernet.payload_mut()).unwrap();
            let mut icmpv6 = MutableEchoRequestPacketV6::new(ipv6.payload_mut()).unwrap();
            icmpv6.set_icmpv6_type(Icmpv6Types::EchoReply);
            icmpv6.set_sequence_number(123);
            icmpv6.set_checksum(pnet::packet::icmpv6::checksum(
                &Icmpv6Packet::new(icmpv6.packet()).unwrap(),
                &TARGET_V6,
                &SOURCE_V6,
            ));
        }

        assert!(Scanner::parse_icmpv6_reply(&frame, SOURCE_V6, 7, 9).is_none());
    }

    #[test]
    fn icmp6_reject_proto() {
        let scanner = test_scanner();
        let mut frame = scanner.make_icmpv6_echo(&TARGET_V6, MacAddr::broadcast(), 7, 9).unwrap();

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            let mut ipv6 = MutableIpv6Packet::new(ethernet.payload_mut()).unwrap();
            ipv6.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Udp);
            let mut icmpv6 = MutableEchoRequestPacketV6::new(ipv6.payload_mut()).unwrap();
            icmpv6.set_icmpv6_type(Icmpv6Types::EchoReply);
        }

        assert!(Scanner::parse_icmpv6_reply(&frame, SOURCE_V6, 7, 9).is_none());
    }

}
