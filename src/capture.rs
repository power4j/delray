use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;

use anyhow::{Result, anyhow};
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use pcap::{Capture, Device};

use crate::stats::Direction;

/// 指定网卡的抓包源。
pub struct CaptureSource {
    cap: Capture<pcap::Active>,
    local_ips: HashSet<IpAddr>,
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

/// Print available interfaces with the default-route interface highlighted.
pub fn list_interfaces() {
    let default = default_interface();
    match Device::list() {
        Ok(devs) => {
            println!("Available interfaces:");
            for d in devs {
                let highlight = default.as_deref() == Some(d.name.as_str());
                let marker = if highlight { "  [default route]" } else { "" };
                match d.desc {
                    Some(desc) => println!("  {}  ({}){}", d.name, desc, marker),
                    None => println!("  {}{}", d.name, marker),
                }
            }
            println!("\nUsage: delray <interface> [OPTIONS]");
            println!("Run delray --help for full usage");
        }
        Err(e) => eprintln!("Failed to enumerate interfaces: {e}"),
    }
}

impl CaptureSource {
    /// 按网卡名打开实时抓包。
    pub fn open(name: &str) -> Result<Self> {
        let device = Device::list()?
            .into_iter()
            .find(|d| d.name == name)
            .ok_or_else(|| anyhow!("Interface not found: {name}"))?;

        let local_ips = device
            .addresses
            .iter()
            .map(|a| a.addr)
            .collect::<HashSet<_>>();

        let cap = Capture::from_device(device)?
            .timeout(150)
            .snaplen(65535)
            .buffer_size(2_000_000)
            .promisc(false)
            .open()?;

        Ok(Self { cap, local_ips })
    }

    /// 读取下一个包；无包（读超时）返回 Ok(None)。
    pub fn next(&mut self) -> Result<Option<Flow>> {
        match self.cap.next_packet() {
            Ok(packet) => Ok(parse(packet.data, &self.local_ips)),
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(anyhow::Error::from(e)),
        }
    }
}

/// 解析以太网帧为单向流量记录；非 IP 或与本机无关返回 None。
fn parse(data: &[u8], local_ips: &HashSet<IpAddr>) -> Option<Flow> {
    let headers = PacketHeaders::from_ethernet_slice(data).ok()?;
    let (src, dst) = match headers.net? {
        NetHeaders::Ipv4(ip, _) => (
            IpAddr::V4(ip.source.into()),
            IpAddr::V4(ip.destination.into()),
        ),
        NetHeaders::Ipv6(ip, _) => (
            IpAddr::V6(ip.source.into()),
            IpAddr::V6(ip.destination.into()),
        ),
        _ => return None,
    };

    let bytes = data.len() as u64;

    let (direction, local_ip, peer) = if local_ips.contains(&src) {
        (Direction::Outbound, src, dst)
    } else if local_ips.contains(&dst) {
        (Direction::Inbound, dst, src)
    } else {
        return None;
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

    Some(Flow {
        direction,
        peer,
        bytes,
        local_socket,
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn parsed_flows_distinguish_tcp_udp_and_other_protocols() {
        let local_ip = Ipv4Addr::new(192, 0, 2, 10);
        let local_ips = HashSet::from([IpAddr::V4(local_ip)]);

        let tcp = parse(
            &ipv4_frame(
                6,
                40,
                &[
                    0x30, 0x39, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 2, 0, 0, 0, 0, 0, 0,
                ],
            ),
            &local_ips,
        )
        .expect("outbound TCP flow");
        let udp = parse(
            &ipv4_frame(17, 28, &[0x14, 0xe9, 0, 53, 0, 8, 0, 0]),
            &local_ips,
        )
        .expect("outbound UDP flow");
        let icmp = parse(&ipv4_frame(1, 28, &[8, 0, 0, 0, 0, 0, 0, 0]), &local_ips)
            .expect("outbound ICMP flow");

        let tcp_socket = tcp.local_socket.expect("TCP local socket");
        assert_eq!(tcp_socket.ip, IpAddr::V4(local_ip));
        assert_eq!(tcp_socket.port, 12_345);
        assert_eq!(tcp_socket.protocol, TransportProtocol::Tcp);

        let udp_socket = udp.local_socket.expect("UDP local socket");
        assert_eq!(udp_socket.ip, IpAddr::V4(local_ip));
        assert_eq!(udp_socket.port, 5_353);
        assert_eq!(udp_socket.protocol, TransportProtocol::Udp);

        assert!(icmp.local_socket.is_none());
    }

    fn ipv4_frame(protocol: u8, total_length: u16, transport: &[u8]) -> Vec<u8> {
        let mut frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0];
        frame.extend_from_slice(&total_length.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
        frame.extend_from_slice(&[192, 0, 2, 10]);
        frame.extend_from_slice(&[198, 51, 100, 5]);
        frame.extend_from_slice(transport);
        frame
    }
}
