use std::collections::HashSet;
use std::fmt::Write as _;
#[cfg(target_os = "linux")]
use std::fs;
use std::net::IpAddr;

use anyhow::{Result, anyhow};
use etherparse::{EtherType, NetHeaders, PacketHeaders, TransportHeader};
use pcap::{Capture, Device};

use crate::stats::Direction;

/// 指定网卡的抓包源。
pub struct CaptureSource {
    cap: Capture<pcap::Active>,
    interface_name: String,
    link_type: pcap::Linktype,
    local_ips: HashSet<IpAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: String,
    pub is_default_route: bool,
}

// rust-pcap exposes normalized LINKTYPE_RAW (101), while live Linux handles use DLT_RAW (12).
const LINUX_DLT_RAW: pcap::Linktype = pcap::Linktype(12);

#[derive(Clone, Copy, Eq, PartialEq)]
enum PacketFormat {
    Ethernet,
    Raw,
    Ipv4,
    Ipv6,
    Null,
    Loop,
    LinuxSll,
    LinuxSll2,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum IpVersion {
    V4,
    V6,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SllPacketType {
    Host,
    Outgoing,
    Other,
}

struct IpPayload<'a> {
    packet: &'a [u8],
    expected_version: Option<IpVersion>,
    link_len: u64,
    sll_packet_type: Option<SllPacketType>,
}

/// 解析后的单向流量记录。
pub struct Flow {
    pub direction: Direction,
    /// 远端 IP（用于 IP 维度统计）。
    pub peer: IpAddr,
    pub bytes: u64,
    /// 本机 socket，仅 TCP/UDP 有；用于进程关联。
    pub local_socket: Option<LocalSocket>,
    /// 第二个本机 socket，仅当源和目标都属于本机时存在。
    pub peer_local_socket: Option<LocalSocket>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy)]
pub struct LocalSocket {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: TransportProtocol,
}

/// Determine the default route interface from /proc/net/route.
#[cfg(target_os = "linux")]
fn default_interface() -> Option<String> {
    let content = fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 11 {
            let dest = u32::from_str_radix(fields[1], 16).ok()?;
            if dest == 0 {
                return Some(fields[0].to_string());
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn default_interface() -> Option<String> {
    None
}

/// Return available interfaces with the default-route interface highlighted.
pub fn interface_catalog() -> Result<Vec<InterfaceInfo>> {
    let default = default_interface();
    let devices = Device::list()?;
    Ok(interface_catalog_from_devices(devices, default.as_deref()))
}

fn interface_catalog_from_devices(
    devices: Vec<Device>,
    default: Option<&str>,
) -> Vec<InterfaceInfo> {
    devices
        .into_iter()
        .map(|device| InterfaceInfo {
            is_default_route: default == Some(device.name.as_str()),
            description: device.desc.unwrap_or_else(|| "No description".to_string()),
            name: device.name,
        })
        .collect()
}

/// Print available interfaces with the default-route interface highlighted.
pub fn list_interfaces() -> Result<()> {
    print!("{}", format_interface_list(&interface_catalog()?));
    Ok(())
}

pub fn format_interface_list(interfaces: &[InterfaceInfo]) -> String {
    let mut output = String::from("Available interfaces:\n");
    for (index, interface) in interfaces.iter().enumerate() {
        let marker = if interface.is_default_route {
            "  [default route]"
        } else {
            ""
        };
        writeln!(output, "  {}. {}{marker}", index + 1, interface.description).unwrap();
        writeln!(output, "     Name: {}", interface.name).unwrap();
    }
    output.push_str("\nUsage: delray <interface-or-number> [OPTIONS]\n");
    output.push_str("Run delray --help for full usage\n");
    output
}

fn select_device(selector: &str, mut devices: Vec<Device>) -> Result<Device> {
    if let Some(index) = devices.iter().position(|device| device.name == selector) {
        return Ok(devices.remove(index));
    }

    if !selector.is_empty() && selector.bytes().all(|byte| byte.is_ascii_digit()) {
        let index = selector
            .parse::<usize>()
            .ok()
            .and_then(|number| number.checked_sub(1));
        if let Some(index) = index.filter(|index| *index < devices.len()) {
            return Ok(devices.remove(index));
        }
        if devices.is_empty() {
            return Err(anyhow!(
                "Invalid interface number: {selector} (no interfaces available)"
            ));
        }
        return Err(anyhow!(
            "Invalid interface number: {selector} (choose 1-{})",
            devices.len()
        ));
    }

    Err(anyhow!("Interface not found: {selector}"))
}

fn collect_local_ips(devices: &[Device]) -> HashSet<IpAddr> {
    devices
        .iter()
        .flat_map(|device| device.addresses.iter().map(|address| address.addr))
        .collect()
}

impl CaptureSource {
    /// 按网卡名打开实时抓包。
    pub fn open(selector: &str) -> Result<Self> {
        let devices = Device::list()?;
        let local_ips = collect_local_ips(&devices);
        let device = select_device(selector, devices)?;
        let interface_name = device.name.clone();

        let is_loopback = device.flags.is_loopback();
        let cap = Capture::from_device(device)?
            .timeout(150)
            .snaplen(65535)
            .buffer_size(2_000_000)
            .promisc(false)
            .open()?;
        if is_loopback {
            let _ = cap.direction(pcap::Direction::In);
        }
        let link_type = cap.get_datalink();
        packet_format(link_type)?;

        Ok(Self {
            cap,
            interface_name,
            link_type,
            local_ips,
        })
    }

    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    pub(crate) fn breakloop_handle(&mut self) -> pcap::BreakLoop {
        self.cap.breakloop_handle()
    }

    /// 读取下一个包；无包（读超时）返回 Ok(None)。
    pub fn next(&mut self) -> Result<Option<Flow>> {
        match self.cap.next_packet() {
            Ok(packet) => parse(self.link_type, packet.data, &self.local_ips),
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(anyhow::Error::from(e)),
        }
    }
}

/// 解析数据链路帧为单向流量记录；非 IP 或与本机无关返回 None。
fn parse(
    link_type: pcap::Linktype,
    data: &[u8],
    local_ips: &HashSet<IpAddr>,
) -> Result<Option<Flow>> {
    let format = packet_format(link_type)?;
    let (headers, link_len, sll_packet_type) = match format {
        PacketFormat::Ethernet => (PacketHeaders::from_ethernet_slice(data).ok(), 14, None),
        format => {
            let payload = match ip_payload(format, data) {
                Some(payload) => payload,
                None => return Ok(None),
            };
            if payload
                .expected_version
                .is_some_and(|expected| ip_version(payload.packet) != Some(expected))
            {
                return Ok(None);
            }
            (
                PacketHeaders::from_ip_slice(payload.packet).ok(),
                payload.link_len,
                payload.sll_packet_type,
            )
        }
    };

    let Some(headers) = headers else {
        return Ok(None);
    };
    let Some(net) = headers.net else {
        return Ok(None);
    };
    let (src, dst, ip_bytes) = match net {
        NetHeaders::Ipv4(ip, _) => (
            IpAddr::V4(ip.source.into()),
            IpAddr::V4(ip.destination.into()),
            u64::from(ip.total_len),
        ),
        NetHeaders::Ipv6(ip, _) => (
            IpAddr::V6(ip.source.into()),
            IpAddr::V6(ip.destination.into()),
            u64::from(ip.payload_length) + 40,
        ),
        _ => return Ok(None),
    };

    let link_ext_len = if format == PacketFormat::Ethernet {
        headers
            .link_exts
            .iter()
            .map(|header| header.header_len() as u64)
            .sum()
    } else {
        0
    };
    let bytes = link_len + link_ext_len + ip_bytes;

    let src_local = local_ips.contains(&src);
    let dst_local = local_ips.contains(&dst);
    if src_local && dst_local && sll_packet_type == Some(SllPacketType::Outgoing) {
        return Ok(None);
    }
    let (direction, local_ip, peer) = if src_local {
        (Direction::Outbound, src, dst)
    } else if dst_local {
        (Direction::Inbound, dst, src)
    } else {
        return Ok(None);
    };

    let (local_socket, peer_local_socket) = match &headers.transport {
        Some(TransportHeader::Tcp(tcp)) => {
            let port = if direction == Direction::Outbound {
                tcp.source_port
            } else {
                tcp.destination_port
            };
            let local_socket = LocalSocket {
                ip: local_ip,
                port,
                protocol: TransportProtocol::Tcp,
            };
            let peer_local_socket = (src_local && dst_local).then_some(LocalSocket {
                ip: dst,
                port: tcp.destination_port,
                protocol: TransportProtocol::Tcp,
            });
            (Some(local_socket), peer_local_socket)
        }
        Some(TransportHeader::Udp(udp)) => {
            let port = if direction == Direction::Outbound {
                udp.source_port
            } else {
                udp.destination_port
            };
            let local_socket = LocalSocket {
                ip: local_ip,
                port,
                protocol: TransportProtocol::Udp,
            };
            let peer_local_socket = (src_local && dst_local).then_some(LocalSocket {
                ip: dst,
                port: udp.destination_port,
                protocol: TransportProtocol::Udp,
            });
            (Some(local_socket), peer_local_socket)
        }
        _ => (None, None),
    };

    Ok(Some(Flow {
        direction,
        peer,
        bytes,
        local_socket,
        peer_local_socket,
    }))
}

fn packet_format(link_type: pcap::Linktype) -> Result<PacketFormat> {
    if link_type == pcap::Linktype::ETHERNET {
        Ok(PacketFormat::Ethernet)
    } else if matches!(link_type, pcap::Linktype::RAW | LINUX_DLT_RAW) {
        Ok(PacketFormat::Raw)
    } else if link_type == pcap::Linktype::IPV4 {
        Ok(PacketFormat::Ipv4)
    } else if link_type == pcap::Linktype::IPV6 {
        Ok(PacketFormat::Ipv6)
    } else if link_type == pcap::Linktype::NULL {
        Ok(PacketFormat::Null)
    } else if link_type == pcap::Linktype::LOOP {
        Ok(PacketFormat::Loop)
    } else if link_type == pcap::Linktype::LINUX_SLL {
        Ok(PacketFormat::LinuxSll)
    } else if link_type == pcap::Linktype::LINUX_SLL2 {
        Ok(PacketFormat::LinuxSll2)
    } else {
        Err(anyhow!("Unsupported data link type: {}", link_type.0))
    }
}

fn ip_payload(format: PacketFormat, data: &[u8]) -> Option<IpPayload<'_>> {
    match format {
        PacketFormat::Raw => Some(IpPayload {
            packet: data,
            expected_version: None,
            link_len: 0,
            sll_packet_type: None,
        }),
        PacketFormat::Ipv4 => Some(IpPayload {
            packet: data,
            expected_version: Some(IpVersion::V4),
            link_len: 0,
            sll_packet_type: None,
        }),
        PacketFormat::Ipv6 => Some(IpPayload {
            packet: data,
            expected_version: Some(IpVersion::V6),
            link_len: 0,
            sll_packet_type: None,
        }),
        PacketFormat::Null => {
            let family = ip_version_from_family_header(data.get(..4)?.try_into().ok()?)?;
            Some(IpPayload {
                packet: data.get(4..)?,
                expected_version: Some(family),
                link_len: 4,
                sll_packet_type: None,
            })
        }
        PacketFormat::Loop => {
            let family = ip_version_from_family_header(data.get(..4)?.try_into().ok()?)?;
            Some(IpPayload {
                packet: data.get(4..)?,
                expected_version: Some(family),
                link_len: 4,
                sll_packet_type: None,
            })
        }
        PacketFormat::LinuxSll => {
            let packet_type = u16::from_be_bytes(data.get(..2)?.try_into().ok()?);
            let ether_type = u16::from_be_bytes(data.get(14..16)?.try_into().ok()?);
            Some(IpPayload {
                packet: data.get(16..)?,
                expected_version: Some(ip_version_from_ether_type(ether_type)?),
                link_len: 16,
                sll_packet_type: Some(sll_packet_type(packet_type)),
            })
        }
        PacketFormat::LinuxSll2 => {
            let ether_type = u16::from_be_bytes(data.get(..2)?.try_into().ok()?);
            let packet_type = *data.get(10)?;
            Some(IpPayload {
                packet: data.get(20..)?,
                expected_version: Some(ip_version_from_ether_type(ether_type)?),
                link_len: 20,
                sll_packet_type: Some(sll_packet_type(u16::from(packet_type))),
            })
        }
        PacketFormat::Ethernet => None,
    }
}

fn sll_packet_type(packet_type: u16) -> SllPacketType {
    match packet_type {
        0 => SllPacketType::Host,
        4 => SllPacketType::Outgoing,
        _ => SllPacketType::Other,
    }
}

fn ip_version(data: &[u8]) -> Option<IpVersion> {
    match data.first()? >> 4 {
        4 => Some(IpVersion::V4),
        6 => Some(IpVersion::V6),
        _ => None,
    }
}

fn ip_version_from_ether_type(ether_type: u16) -> Option<IpVersion> {
    match EtherType(ether_type) {
        EtherType::IPV4 => Some(IpVersion::V4),
        EtherType::IPV6 => Some(IpVersion::V6),
        _ => None,
    }
}

fn ip_version_from_family_header(header: [u8; 4]) -> Option<IpVersion> {
    ip_version_from_address_family(u32::from_be_bytes(header))
        .or_else(|| ip_version_from_address_family(u32::from_le_bytes(header)))
}

fn ip_version_from_address_family(family: u32) -> Option<IpVersion> {
    match family {
        2 => Some(IpVersion::V4),
        10 | 23 | 24 | 28 | 30 => Some(IpVersion::V6),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use pcap::{Address, DeviceFlags};

    use super::*;
    use crate::stats::{ObservedProcess, Stats};

    #[derive(Clone, Copy)]
    struct ExpectedFlow {
        direction: Direction,
        peer: IpAddr,
        local_ip: IpAddr,
        local_port: u16,
        protocol: TransportProtocol,
        bytes: u64,
    }

    #[test]
    fn non_tcp_udp_flow_has_no_local_socket() {
        let local_ip = Ipv4Addr::new(192, 0, 2, 10);
        let local_ips = HashSet::from([IpAddr::V4(local_ip)]);

        let icmp = parse(
            pcap::Linktype::ETHERNET,
            &ipv4_frame(1, 28, &[8, 0, 0, 0, 0, 0, 0, 0]),
            &local_ips,
        )
        .expect("supported data link")
        .expect("outbound ICMP flow");

        assert!(icmp.local_socket.is_none());
    }

    #[test]
    fn unsupported_data_link_type_returns_an_error() {
        let error = match parse(pcap::Linktype(999), &[], &HashSet::new()) {
            Err(error) => error,
            Ok(_) => panic!("unsupported data link type was accepted"),
        };

        assert_eq!(error.to_string(), "Unsupported data link type: 999");
    }

    #[test]
    fn supported_link_types_parse_tcp_udp_ipv4_and_ipv6() {
        let local_v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let local_v6 = "2001:db8::10".parse::<IpAddr>().unwrap();
        let local_ips = HashSet::from([local_v4, local_v6]);
        let link_types = [
            (
                pcap::Linktype::ETHERNET,
                &[IpVersion::V4, IpVersion::V6][..],
            ),
            (pcap::Linktype::RAW, &[IpVersion::V4, IpVersion::V6][..]),
            (LINUX_DLT_RAW, &[IpVersion::V4, IpVersion::V6][..]),
            (pcap::Linktype::IPV4, &[IpVersion::V4][..]),
            (pcap::Linktype::IPV6, &[IpVersion::V6][..]),
            (pcap::Linktype::NULL, &[IpVersion::V4, IpVersion::V6][..]),
            (pcap::Linktype::LOOP, &[IpVersion::V4, IpVersion::V6][..]),
            (
                pcap::Linktype::LINUX_SLL,
                &[IpVersion::V4, IpVersion::V6][..],
            ),
            (
                pcap::Linktype::LINUX_SLL2,
                &[IpVersion::V4, IpVersion::V6][..],
            ),
        ];

        for (link_type, versions) in link_types {
            for version in versions {
                for protocol in [TransportProtocol::Tcp, TransportProtocol::Udp] {
                    let (ip_packet, mut expected) = fixed_ip_packet(*version, protocol);
                    let packet = add_link_header(link_type, *version, ip_packet);
                    expected.bytes = packet.len() as u64;

                    let flow = parse(link_type, &packet, &local_ips)
                        .expect("supported data link")
                        .expect("local flow");

                    assert_flow(flow, expected);
                }
            }
        }
    }

    #[test]
    fn parsed_packets_keep_network_direction_through_interface_and_process_stats() {
        let local = [192, 0, 2, 10];
        let inbound_peer = [198, 51, 100, 5];
        let outbound_peer = [203, 0, 113, 9];
        let inbound_transport = fixed_transport(TransportProtocol::Tcp, Direction::Inbound);
        let outbound_transport = fixed_transport(TransportProtocol::Tcp, Direction::Outbound);
        let inbound = add_link_header(
            pcap::Linktype::ETHERNET,
            IpVersion::V4,
            ipv4_packet_between(
                inbound_peer,
                local,
                ip_protocol(TransportProtocol::Tcp),
                (20 + inbound_transport.len()) as u16,
                &inbound_transport,
            ),
        );
        let outbound = add_link_header(
            pcap::Linktype::ETHERNET,
            IpVersion::V4,
            ipv4_packet_between(
                local,
                outbound_peer,
                ip_protocol(TransportProtocol::Tcp),
                (20 + outbound_transport.len()) as u16,
                &outbound_transport,
            ),
        );
        let local_ips = HashSet::from([IpAddr::V4(local.into())]);
        let process = ObservedProcess {
            pid: 7,
            name: Some(Arc::from("wget")),
            path: Some(Arc::from("/usr/bin/wget")),
        };
        let mut stats = Stats::default();

        let inbound_flow = parse(pcap::Linktype::ETHERNET, &inbound, &local_ips)
            .unwrap()
            .unwrap();
        let outbound_flow = parse(pcap::Linktype::ETHERNET, &outbound, &local_ips)
            .unwrap()
            .unwrap();
        assert!(matches!(inbound_flow.direction, Direction::Inbound));
        assert!(matches!(outbound_flow.direction, Direction::Outbound));

        let inbound_bytes = inbound_flow.bytes;
        let outbound_bytes = outbound_flow.bytes;
        stats.record_flow(inbound_flow, Some(process.clone()));
        stats.record_flow(outbound_flow, Some(process));
        let snapshot = stats.snapshot(10);
        let wget = snapshot
            .processes
            .iter()
            .find(|process| process.pid() == Some(7))
            .unwrap();

        assert_eq!(snapshot.in_bytes, inbound_bytes);
        assert_eq!(snapshot.out_bytes, outbound_bytes);
        assert_eq!(snapshot.inbound_ips[0].ip, IpAddr::V4(inbound_peer.into()));
        assert_eq!(
            snapshot.outbound_ips[0].ip,
            IpAddr::V4(outbound_peer.into())
        );
        assert_eq!((wget.recv, wget.sent), (inbound_bytes, outbound_bytes));
    }

    #[test]
    fn local_tcp_response_accounts_source_as_sent_and_destination_as_recv() {
        let local = [127, 0, 0, 1];
        let server_port = 18_765_u16;
        let client_port = 49_152_u16;
        let mut transport = Vec::new();
        transport.extend_from_slice(&server_port.to_be_bytes());
        transport.extend_from_slice(&client_port.to_be_bytes());
        transport.extend_from_slice(&[0; 8]);
        transport.extend_from_slice(&[0x50, 0x10, 0, 0, 0, 0, 0, 0]);
        let packet = add_link_header(
            pcap::Linktype::ETHERNET,
            IpVersion::V4,
            ipv4_packet_between(
                local,
                local,
                ip_protocol(TransportProtocol::Tcp),
                (20 + transport.len()) as u16,
                &transport,
            ),
        );
        let local_ips = HashSet::from([IpAddr::V4(local.into())]);

        let flow = parse(pcap::Linktype::ETHERNET, &packet, &local_ips)
            .unwrap()
            .expect("local loopback flow");
        let source = flow.local_socket.expect("source local socket");
        let destination = flow.peer_local_socket.expect("destination local socket");
        assert_eq!(source.port, server_port);
        assert_eq!(destination.port, client_port);

        let bytes = flow.bytes;
        let mut stats = Stats::default();
        stats.record_flow_processes_at(
            flow,
            Some(ObservedProcess {
                pid: 18765,
                name: Some(Arc::from("python")),
                path: Some(Arc::from("/usr/bin/python")),
            }),
            Some(ObservedProcess {
                pid: 49152,
                name: Some(Arc::from("curl")),
                path: Some(Arc::from("/usr/bin/curl")),
            }),
            "2026-07-15T08:00:00Z".parse().unwrap(),
        );

        let snapshot = stats.snapshot(10);
        let server = snapshot
            .processes
            .iter()
            .find(|process| process.pid() == Some(18765))
            .unwrap();
        let client = snapshot
            .processes
            .iter()
            .find(|process| process.pid() == Some(49152))
            .unwrap();

        assert_eq!(snapshot.in_bytes, bytes);
        assert_eq!(snapshot.out_bytes, bytes);
        assert_eq!((server.recv, server.sent), (0, bytes));
        assert_eq!((client.recv, client.sent), (bytes, 0));
    }

    #[test]
    fn linux_dlt_raw_12_parses_raw_ip() {
        let (packet, mut expected) = fixed_ip_packet(IpVersion::V4, TransportProtocol::Udp);
        expected.bytes = packet.len() as u64;
        let local_ips = HashSet::from([expected.local_ip]);

        let flow = parse(pcap::Linktype(12), &packet, &local_ips)
            .expect("Linux DLT_RAW is supported")
            .expect("local raw IP flow");

        assert_flow(flow, expected);
    }

    #[test]
    fn linux_sll_local_outgoing_copy_is_ignored() {
        let local = [127, 0, 0, 1];
        let transport = fixed_transport(TransportProtocol::Tcp, Direction::Outbound);
        let ip_packet = ipv4_packet_between(
            local,
            local,
            ip_protocol(TransportProtocol::Tcp),
            (20 + transport.len()) as u16,
            &transport,
        );
        let local_ips = HashSet::from([IpAddr::V4(local.into())]);

        for link_type in [pcap::Linktype::LINUX_SLL, pcap::Linktype::LINUX_SLL2] {
            let mut outgoing = add_link_header(link_type, IpVersion::V4, ip_packet.clone());
            set_sll_packet_type(&mut outgoing, link_type, 4);
            let outgoing_flow =
                parse(link_type, &outgoing, &local_ips).expect("supported data link");
            assert!(outgoing_flow.is_none());

            let mut host = add_link_header(link_type, IpVersion::V4, ip_packet.clone());
            set_sll_packet_type(&mut host, link_type, 0);
            let host_flow = parse(link_type, &host, &local_ips)
                .expect("supported data link")
                .expect("host copy is retained");
            assert!(host_flow.peer_local_socket.is_some());
        }
    }

    #[test]
    fn linux_sll_remote_outgoing_copy_is_retained() {
        let local_ips = HashSet::from(["192.0.2.10".parse::<IpAddr>().unwrap()]);

        for link_type in [pcap::Linktype::LINUX_SLL, pcap::Linktype::LINUX_SLL2] {
            let (payload, mut expected) = fixed_ip_packet(IpVersion::V4, TransportProtocol::Udp);
            let mut packet = add_link_header(link_type, IpVersion::V4, payload);
            set_sll_packet_type(&mut packet, link_type, 4);
            expected.bytes = packet.len() as u64;

            let flow = parse(link_type, &packet, &local_ips)
                .expect("supported data link")
                .expect("remote outgoing flow is retained");

            assert_flow(flow, expected);
        }
    }

    #[test]
    fn null_and_loop_accept_both_address_family_endiannesses() {
        let (payload, expected) = fixed_ip_packet(IpVersion::V4, TransportProtocol::Udp);
        let local_ips = HashSet::from([expected.local_ip]);

        for link_type in [pcap::Linktype::NULL, pcap::Linktype::LOOP] {
            for family in [
                address_family(IpVersion::V4).to_be_bytes(),
                address_family(IpVersion::V4).to_le_bytes(),
            ] {
                let mut packet = family.to_vec();
                packet.extend_from_slice(&payload);
                let mut expected = expected;
                expected.bytes = packet.len() as u64;

                let flow = parse(link_type, &packet, &local_ips)
                    .expect("supported data link")
                    .expect("address family endian is accepted");

                assert_flow(flow, expected);
            }
        }
    }

    #[test]
    fn bytes_ignore_padding_after_ip_packet() {
        let (payload, mut expected) = fixed_ip_packet(IpVersion::V4, TransportProtocol::Udp);
        let local_ips = HashSet::from([expected.local_ip]);
        let mut packet = add_link_header(pcap::Linktype::ETHERNET, IpVersion::V4, payload);
        expected.bytes = packet.len() as u64;
        packet.extend_from_slice(&[0; 16]);

        let flow = parse(pcap::Linktype::ETHERNET, &packet, &local_ips)
            .expect("supported data link")
            .expect("padded frame");

        assert_flow(flow, expected);
    }

    #[test]
    fn link_protocol_identifier_must_match_ip_payload() {
        let local_ips = HashSet::from([
            "192.0.2.10".parse::<IpAddr>().unwrap(),
            "2001:db8::10".parse::<IpAddr>().unwrap(),
        ]);
        let mismatches = [
            (pcap::Linktype::IPV4, IpVersion::V4, IpVersion::V6),
            (pcap::Linktype::IPV6, IpVersion::V6, IpVersion::V4),
            (pcap::Linktype::NULL, IpVersion::V4, IpVersion::V6),
            (pcap::Linktype::NULL, IpVersion::V6, IpVersion::V4),
            (pcap::Linktype::LOOP, IpVersion::V4, IpVersion::V6),
            (pcap::Linktype::LOOP, IpVersion::V6, IpVersion::V4),
            (pcap::Linktype::LINUX_SLL, IpVersion::V4, IpVersion::V6),
            (pcap::Linktype::LINUX_SLL, IpVersion::V6, IpVersion::V4),
            (pcap::Linktype::LINUX_SLL2, IpVersion::V4, IpVersion::V6),
            (pcap::Linktype::LINUX_SLL2, IpVersion::V6, IpVersion::V4),
        ];

        for (link_type, advertised_version, payload_version) in mismatches {
            let (payload, _) = fixed_ip_packet(payload_version, TransportProtocol::Udp);
            let packet = add_link_header(link_type, advertised_version, payload);

            let flow = parse(link_type, &packet, &local_ips).expect("supported data link");

            assert!(flow.is_none());
        }
    }

    #[test]
    fn unsupported_link_protocol_identifier_is_ignored() {
        let local_ips = HashSet::from(["192.0.2.10".parse::<IpAddr>().unwrap()]);
        let (payload, _) = fixed_ip_packet(IpVersion::V4, TransportProtocol::Udp);
        let mut null = 999_u32.to_ne_bytes().to_vec();
        null.extend_from_slice(&payload);
        let mut loop_packet = 999_u32.to_be_bytes().to_vec();
        loop_packet.extend_from_slice(&payload);
        let mut sll = vec![0, 0, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0, 0x08, 0x06];
        sll.extend_from_slice(&payload);
        let mut sll2 = vec![
            0x08, 0x06, 0, 0, 0, 0, 0, 1, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0,
        ];
        sll2.extend_from_slice(&payload);

        for (link_type, packet) in [
            (pcap::Linktype::NULL, null),
            (pcap::Linktype::LOOP, loop_packet),
            (pcap::Linktype::LINUX_SLL, sll),
            (pcap::Linktype::LINUX_SLL2, sll2),
        ] {
            let flow = parse(link_type, &packet, &local_ips).expect("supported data link");
            assert!(flow.is_none());
        }
    }

    #[test]
    fn traffic_not_belonging_to_the_host_is_ignored() {
        let packet = ipv4_packet_between(
            [198, 51, 100, 5],
            [203, 0, 113, 9],
            17,
            28,
            &[0, 53, 0x14, 0xe9, 0, 8, 0, 0],
        );
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);

        let flow =
            parse(pcap::Linktype::RAW, &packet, &local_ips).expect("supported raw data link");

        assert!(flow.is_none());
    }

    #[test]
    fn interface_list_has_numbers_descriptions_and_full_names() {
        let devices = vec![
            device("eth0", Some("Wired Ethernet")),
            device(r"\Device\NPF_{1234}", None),
        ];

        let rendered =
            format_interface_list(&interface_catalog_from_devices(devices, Some("eth0")));

        assert_eq!(
            rendered,
            concat!(
                "Available interfaces:\n",
                "  1. Wired Ethernet  [default route]\n",
                "     Name: eth0\n",
                "  2. No description\n",
                "     Name: \\Device\\NPF_{1234}\n",
                "\nUsage: delray <interface-or-number> [OPTIONS]\n",
                "Run delray --help for full usage\n",
            )
        );
    }

    #[test]
    fn interface_catalog_keeps_names_descriptions_and_default_marker() {
        let catalog = interface_catalog_from_devices(
            vec![device("eth0", Some("Wired Ethernet")), device("lo", None)],
            Some("eth0"),
        );

        assert_eq!(catalog.len(), 2);
        assert_eq!(catalog[0].name, "eth0");
        assert_eq!(catalog[0].description, "Wired Ethernet");
        assert!(catalog[0].is_default_route);
        assert_eq!(catalog[1].description, "No description");
        assert!(!catalog[1].is_default_route);
    }

    #[test]
    fn interface_selection_accepts_current_number_or_full_name() {
        let by_number = select_device(
            "2",
            vec![
                device("eth0", Some("Wired Ethernet")),
                device(r"\Device\NPF_{1234}", Some("Npcap Adapter")),
            ],
        )
        .expect("current interface number");
        assert_eq!(by_number.name, r"\Device\NPF_{1234}");

        let by_name = select_device(
            r"\Device\NPF_{1234}",
            vec![
                device("eth0", Some("Wired Ethernet")),
                device(r"\Device\NPF_{1234}", Some("Npcap Adapter")),
            ],
        )
        .expect("full pcap device name");
        assert_eq!(by_name.name, r"\Device\NPF_{1234}");

        let numeric_name = select_device(
            "2",
            vec![
                device("eth0", None),
                device("lo", None),
                device("2", Some("Numeric device name")),
            ],
        )
        .expect("numeric full pcap device name");
        assert_eq!(numeric_name.name, "2");
    }

    #[test]
    fn invalid_interface_selection_returns_clear_errors() {
        for number in ["0", "3"] {
            let error = select_device(number, vec![device("eth0", None), device("lo", None)])
                .expect_err("invalid interface number");
            assert_eq!(
                error.to_string(),
                format!("Invalid interface number: {number} (choose 1-2)")
            );
        }

        let error = select_device("missing", vec![device("eth0", None)])
            .expect_err("missing interface name");
        assert_eq!(error.to_string(), "Interface not found: missing");
    }

    #[test]
    fn local_ips_include_addresses_from_all_interfaces() {
        let mut eth0 = device("eth0", None);
        eth0.addresses.push(address("192.0.2.10"));
        let any = device("any", Some("All interfaces"));
        let mut lo = device("lo", None);
        lo.addresses.push(address("::1"));

        let local_ips = collect_local_ips(&[eth0, any, lo]);

        assert_eq!(
            local_ips,
            HashSet::from([
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "::1".parse::<IpAddr>().unwrap(),
            ])
        );
    }

    fn ipv4_frame(protocol: u8, total_length: u16, transport: &[u8]) -> Vec<u8> {
        let mut frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
        frame.extend_from_slice(&ipv4_packet_between(
            [192, 0, 2, 10],
            [198, 51, 100, 5],
            protocol,
            total_length,
            transport,
        ));
        frame
    }

    fn fixed_ip_packet(version: IpVersion, protocol: TransportProtocol) -> (Vec<u8>, ExpectedFlow) {
        let direction = if protocol == TransportProtocol::Tcp {
            Direction::Inbound
        } else {
            Direction::Outbound
        };
        let transport = fixed_transport(protocol, direction);
        let (packet, local_ip, peer) = match version {
            IpVersion::V4 => {
                let local = [192, 0, 2, 10];
                let remote = [198, 51, 100, 5];
                let (source, destination) = endpoints(direction, local, remote);
                (
                    ipv4_packet_between(
                        source,
                        destination,
                        ip_protocol(protocol),
                        (20 + transport.len()) as u16,
                        &transport,
                    ),
                    IpAddr::V4(local.into()),
                    IpAddr::V4(remote.into()),
                )
            }
            IpVersion::V6 => {
                let local = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
                let remote = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
                let (source, destination) = endpoints(direction, local, remote);
                (
                    ipv6_packet_between(source, destination, ip_protocol(protocol), &transport),
                    IpAddr::V6(local.into()),
                    IpAddr::V6(remote.into()),
                )
            }
        };
        let local_port = if protocol == TransportProtocol::Tcp {
            12_345
        } else {
            5_353
        };
        (
            packet,
            ExpectedFlow {
                direction,
                peer,
                local_ip,
                local_port,
                protocol,
                bytes: 0,
            },
        )
    }

    fn fixed_transport(protocol: TransportProtocol, direction: Direction) -> Vec<u8> {
        let local_port = if protocol == TransportProtocol::Tcp {
            12_345_u16
        } else {
            5_353_u16
        };
        let remote_port = if protocol == TransportProtocol::Tcp {
            443_u16
        } else {
            53_u16
        };
        let (source_port, destination_port) = endpoints(direction, local_port, remote_port);
        let mut transport = Vec::new();
        transport.extend_from_slice(&source_port.to_be_bytes());
        transport.extend_from_slice(&destination_port.to_be_bytes());
        match protocol {
            TransportProtocol::Tcp => {
                transport.extend_from_slice(&[0; 8]);
                transport.extend_from_slice(&[0x50, 2, 0, 0, 0, 0, 0, 0]);
            }
            TransportProtocol::Udp => transport.extend_from_slice(&[0, 8, 0, 0]),
        }
        transport
    }

    fn endpoints<T: Copy>(direction: Direction, local: T, remote: T) -> (T, T) {
        if direction == Direction::Outbound {
            (local, remote)
        } else {
            (remote, local)
        }
    }

    fn ip_protocol(protocol: TransportProtocol) -> u8 {
        match protocol {
            TransportProtocol::Tcp => 6,
            TransportProtocol::Udp => 17,
        }
    }

    fn ipv4_packet_between(
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
        total_length: u16,
        transport: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0x45, 0];
        packet.extend_from_slice(&total_length.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
        packet.extend_from_slice(&source);
        packet.extend_from_slice(&destination);
        packet.extend_from_slice(transport);
        packet
    }

    fn ipv6_packet_between(
        source: [u8; 16],
        destination: [u8; 16],
        next_header: u8,
        transport: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0x60, 0, 0, 0];
        packet.extend_from_slice(&(transport.len() as u16).to_be_bytes());
        packet.extend_from_slice(&[next_header, 64]);
        packet.extend_from_slice(&source);
        packet.extend_from_slice(&destination);
        packet.extend_from_slice(transport);
        packet
    }

    fn add_link_header(link_type: pcap::Linktype, version: IpVersion, packet: Vec<u8>) -> Vec<u8> {
        let ether_type = match version {
            IpVersion::V4 => [0x08, 0x00],
            IpVersion::V6 => [0x86, 0xdd],
        };
        let mut header = if link_type == pcap::Linktype::ETHERNET {
            let mut header = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
            header.extend_from_slice(&ether_type);
            header
        } else if link_type == pcap::Linktype::NULL {
            address_family(version).to_ne_bytes().to_vec()
        } else if link_type == pcap::Linktype::LOOP {
            address_family(version).to_be_bytes().to_vec()
        } else if link_type == pcap::Linktype::LINUX_SLL {
            let mut header = vec![0, 0, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0];
            header.extend_from_slice(&ether_type);
            header
        } else if link_type == pcap::Linktype::LINUX_SLL2 {
            let mut header = ether_type.to_vec();
            header.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0]);
            header
        } else {
            Vec::new()
        };
        header.extend_from_slice(&packet);
        header
    }

    fn set_sll_packet_type(packet: &mut [u8], link_type: pcap::Linktype, packet_type: u16) {
        if link_type == pcap::Linktype::LINUX_SLL {
            packet[..2].copy_from_slice(&packet_type.to_be_bytes());
        } else if link_type == pcap::Linktype::LINUX_SLL2 {
            packet[10] = packet_type as u8;
        }
    }

    fn address_family(version: IpVersion) -> u32 {
        match version {
            IpVersion::V4 => 2,
            IpVersion::V6 if cfg!(target_os = "windows") => 23,
            IpVersion::V6 => 10,
        }
    }

    fn assert_flow(flow: Flow, expected: ExpectedFlow) {
        assert!(flow.direction == expected.direction);
        assert_eq!(flow.peer, expected.peer);
        assert_eq!(flow.bytes, expected.bytes);
        let socket = flow.local_socket.expect("local socket");
        assert_eq!(socket.ip, expected.local_ip);
        assert_eq!(socket.port, expected.local_port);
        assert_eq!(socket.protocol, expected.protocol);
    }

    fn device(name: &str, desc: Option<&str>) -> Device {
        Device {
            name: name.to_string(),
            desc: desc.map(str::to_string),
            addresses: Vec::new(),
            flags: DeviceFlags::empty(),
        }
    }

    fn address(ip: &str) -> Address {
        Address {
            addr: ip.parse().unwrap(),
            netmask: None,
            broadcast_addr: None,
            dst_addr: None,
        }
    }
}
