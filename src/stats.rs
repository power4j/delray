use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// 自启动以来的累计流量统计。
#[derive(Default)]
pub struct Stats {
    /// 入站总字节数。
    pub in_bytes: u64,
    /// 出站总字节数。
    pub out_bytes: u64,
    in_by_ip: HashMap<IpAddr, u64>,
    out_by_ip: HashMap<IpAddr, u64>,
    by_proc: HashMap<u32, ProcTraffic>,
    /// pid -> 进程展示名缓存，避免进程退出后名字丢失为 "?"。
    pid_names: HashMap<u32, String>,
}

/// 单个进程的收发流量。
#[derive(Default, Clone, Copy)]
pub struct ProcTraffic {
    /// 接收（入站）字节数。
    pub recv: u64,
    /// 发送（出站）字节数。
    pub sent: u64,
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

    pub fn add_proc(&mut self, pid: u32, name: Option<&str>, direction: Direction, bytes: u64) {
        let entry = self.by_proc.entry(pid).or_default();
        match direction {
            Direction::Inbound => entry.recv += bytes,
            Direction::Outbound => entry.sent += bytes,
        }
        if let Some(n) = name {
            self.pid_names.entry(pid).or_insert_with(|| n.to_string());
        }
    }

    pub fn top_in(&self, n: usize) -> Vec<(IpAddr, u64)> {
        top_n_ip(&self.in_by_ip, n)
    }

    pub fn top_out(&self, n: usize) -> Vec<(IpAddr, u64)> {
        top_n_ip(&self.out_by_ip, n)
    }

    pub fn top_procs(&self, n: usize) -> Vec<(u32, ProcTraffic)> {
        let mut entries: Vec<(u32, ProcTraffic)> =
            self.by_proc.iter().map(|(pid, t)| (*pid, *t)).collect();
        entries.sort_unstable_by_key(|(_, t)| std::cmp::Reverse(t.recv + t.sent));
        entries.truncate(n);
        entries
    }

    pub fn proc_name(&self, pid: u32) -> Option<&str> {
        self.pid_names.get(&pid).map(|s| s.as_str())
    }
}

fn top_n_ip(map: &HashMap<IpAddr, u64>, n: usize) -> Vec<(IpAddr, u64)> {
    let mut entries: Vec<(IpAddr, u64)> = map.iter().map(|(ip, bytes)| (*ip, *bytes)).collect();
    entries.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
    entries.truncate(n);
    entries
}
