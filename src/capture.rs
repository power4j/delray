use std::collections::HashSet;
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
    /// 本机 (IP, 端口)，仅 TCP/UDP 有；用于进程关联。
    pub local_socket: Option<(IpAddr, u16)>,
}

/// 打印可用网卡列表。
pub fn list_interfaces() {
    match Device::list() {
        Ok(devs) => {
            println!("请指定网卡，当前可用：");
            for d in devs {
                match d.desc {
                    Some(desc) => println!("  {}  ({desc})", d.name),
                    None => println!("  {}", d.name),
                }
            }
            println!("\n用法：delray <网卡> [--proc-refresh <秒>] [--output <文件>]");
            println!("运行 delray --help 查看完整用法");
        }
        Err(e) => eprintln!("无法枚举网卡：{e}"),
    }
}

impl CaptureSource {
    /// 按网卡名打开实时抓包。
    pub fn open(name: &str) -> Result<Self> {
        let device = Device::list()?
            .into_iter()
            .find(|d| d.name == name)
            .ok_or_else(|| anyhow!("网卡不存在：{name}"))?;

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

    let local_port = match &headers.transport {
        Some(TransportHeader::Tcp(tcp)) => {
            if direction == Direction::Outbound {
                Some(tcp.source_port)
            } else {
                Some(tcp.destination_port)
            }
        }
        Some(TransportHeader::Udp(udp)) => {
            if direction == Direction::Outbound {
                Some(udp.source_port)
            } else {
                Some(udp.destination_port)
            }
        }
        _ => None,
    };

    Some(Flow {
        direction,
        peer,
        bytes,
        local_socket: local_port.map(|p| (local_ip, p)),
    })
}
