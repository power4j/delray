use std::collections::HashMap;
use std::net::IpAddr;

/// 自启动以来的累计流量统计。
#[derive(Default)]
pub struct Stats {
    /// 入站总字节数。
    pub in_bytes: u64,
    /// 出站总字节数。
    pub out_bytes: u64,
    /// 按源 IP 聚合的入站字节（谁发来的流量）。
    in_by_ip: HashMap<IpAddr, u64>,
    /// 按目的 IP 聚合的出站字节（发给谁的流量）。
    out_by_ip: HashMap<IpAddr, u64>,
}

impl Stats {
    pub fn add_in(&mut self, source: IpAddr, bytes: u64) {
        self.in_bytes += bytes;
        *self.in_by_ip.entry(source).or_default() += bytes;
    }

    pub fn add_out(&mut self, destination: IpAddr, bytes: u64) {
        self.out_bytes += bytes;
        *self.out_by_ip.entry(destination).or_default() += bytes;
    }

    pub fn top_in(&self, n: usize) -> Vec<(IpAddr, u64)> {
        top_n(&self.in_by_ip, n)
    }

    pub fn top_out(&self, n: usize) -> Vec<(IpAddr, u64)> {
        top_n(&self.out_by_ip, n)
    }
}

fn top_n(map: &HashMap<IpAddr, u64>, n: usize) -> Vec<(IpAddr, u64)> {
    let mut entries: Vec<(IpAddr, u64)> = map.iter().map(|(ip, bytes)| (*ip, *bytes)).collect();
    entries.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
    entries.truncate(n);
    entries
}
