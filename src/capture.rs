use std::collections::HashSet;
use std::fmt::Write as _;
#[cfg(target_os = "linux")]
use std::fs;
use std::net::IpAddr;

use anyhow::{Result, anyhow};
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use pcap::{Capture, Device};

use crate::stats::Direction;

/// 指定网卡的抓包源。
pub struct CaptureSource {
    cap: Capture<pcap::Active>,
    interface_name: String,
    link_type: pcap::Linktype,
    local_ips: HashSet<IpAddr>,
}

#[derive(Clone, Copy)]
enum PacketStart {
    Ethernet,
    Ip(usize),
}

/// 解析后的单向流量记录。
pub struct Flow {
    pub direction: Direction,
    /// 远端 IP（用于 IP 维度统计）。
    pub peer: IpAddr,
    pub bytes: u64,
    /// 本机 socket，仅 TCP/UDP 有；用于进程关联。
    pub local_socket: Option<LocalSocket>,
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

/// Print available interfaces with the default-route interface highlighted.
pub fn list_interfaces() -> Result<()> {
    let default = default_interface();
    let devices = Device::list()?;
    print!("{}", format_interface_list(&devices, default.as_deref()));
    Ok(())
}

fn format_interface_list(devices: &[Device], default: Option<&str>) -> String {
    let mut output = String::from("Available interfaces:\n");
    for (index, device) in devices.iter().enumerate() {
        let description = device.desc.as_deref().unwrap_or("No description");
        let marker = if default == Some(device.name.as_str()) {
            "  [default route]"
        } else {
            ""
        };
        writeln!(output, "  {}. {description}{marker}", index + 1).unwrap();
        writeln!(output, "     Name: {}", device.name).unwrap();
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

        let cap = Capture::from_device(device)?
            .timeout(150)
            .snaplen(65535)
            .buffer_size(2_000_000)
            .promisc(false)
            .open()?;
        let link_type = cap.get_datalink();
        packet_start(link_type)?;

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
    let headers = match packet_start(link_type)? {
        PacketStart::Ethernet => PacketHeaders::from_ethernet_slice(data).ok(),
        PacketStart::Ip(offset) => data
            .get(offset..)
            .and_then(|packet| PacketHeaders::from_ip_slice(packet).ok()),
    };

    let Some(headers) = headers else {
        return Ok(None);
    };
    let Some(net) = headers.net else {
        return Ok(None);
    };
    let (src, dst) = match net {
        NetHeaders::Ipv4(ip, _) => (
            IpAddr::V4(ip.source.into()),
            IpAddr::V4(ip.destination.into()),
        ),
        NetHeaders::Ipv6(ip, _) => (
            IpAddr::V6(ip.source.into()),
            IpAddr::V6(ip.destination.into()),
        ),
        _ => return Ok(None),
    };

    let bytes = data.len() as u64;

    let (direction, local_ip, peer) = if local_ips.contains(&src) {
        (Direction::Outbound, src, dst)
    } else if local_ips.contains(&dst) {
        (Direction::Inbound, dst, src)
    } else {
        return Ok(None);
    };

    let local_socket = match &headers.transport {
        Some(TransportHeader::Tcp(tcp)) => {
            let port = if direction == Direction::Outbound {
                tcp.source_port
            } else {
                tcp.destination_port
            };
            Some(LocalSocket {
                ip: local_ip,
                port,
                protocol: TransportProtocol::Tcp,
            })
        }
        Some(TransportHeader::Udp(udp)) => {
            let port = if direction == Direction::Outbound {
                udp.source_port
            } else {
                udp.destination_port
            };
            Some(LocalSocket {
                ip: local_ip,
                port,
                protocol: TransportProtocol::Udp,
            })
        }
        _ => None,
    };

    Ok(Some(Flow {
        direction,
        peer,
        bytes,
        local_socket,
    }))
}

fn packet_start(link_type: pcap::Linktype) -> Result<PacketStart> {
    if link_type == pcap::Linktype::ETHERNET {
        Ok(PacketStart::Ethernet)
    } else if matches!(
        link_type,
        pcap::Linktype::RAW | pcap::Linktype::IPV4 | pcap::Linktype::IPV6
    ) {
        Ok(PacketStart::Ip(0))
    } else if matches!(link_type, pcap::Linktype::NULL | pcap::Linktype::LOOP) {
        Ok(PacketStart::Ip(4))
    } else if link_type == pcap::Linktype::LINUX_SLL {
        Ok(PacketStart::Ip(16))
    } else if link_type == pcap::Linktype::LINUX_SLL2 {
        Ok(PacketStart::Ip(20))
    } else {
        Err(anyhow!("Unsupported data link type: {}", link_type.0))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pcap::{Address, DeviceFlags};

    use super::*;

    #[derive(Clone, Copy)]
    enum IpVersion {
        V4,
        V6,
    }

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

        let rendered = format_interface_list(&devices, Some("eth0"));

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
