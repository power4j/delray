use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::capture::Flow;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Proc traffic with recv/sent breakdown.
#[derive(Default, Clone, Copy)]
pub struct ProcTraffic {
    /// Recv (inbound) bytes.
    pub recv: u64,
    /// Sent (outbound) bytes.
    pub sent: u64,
}

#[derive(Clone)]
pub struct ObservedProcess {
    pub pid: u32,
    pub name: Option<Arc<str>>,
}

#[derive(Clone, Default)]
pub struct TrafficSnapshot {
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub processes: Arc<[ProcessSnapshot]>,
    pub inbound_ips: Arc<[IpSnapshot]>,
    pub outbound_ips: Arc<[IpSnapshot]>,
}

#[derive(Clone)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub name: Option<Arc<str>>,
    pub recv: u64,
    pub sent: u64,
}

#[derive(Clone)]
pub struct IpSnapshot {
    pub ip: IpAddr,
    pub bytes: u64,
}

/// Cumulative stats since start.
#[derive(Default)]
pub struct Stats {
    /// Total inbound bytes.
    pub in_bytes: u64,
    /// Total outbound bytes.
    pub out_bytes: u64,
    in_by_ip: HashMap<IpAddr, u64>,
    out_by_ip: HashMap<IpAddr, u64>,
    by_proc: HashMap<u32, ProcTraffic>,
    /// pid → display name cache, so exited processes don't show as "?".
    pid_names: HashMap<u32, Arc<str>>,
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

    pub fn add_proc(&mut self, pid: u32, name: Option<Arc<str>>, direction: Direction, bytes: u64) {
        let entry = self.by_proc.entry(pid).or_default();
        match direction {
            Direction::Inbound => entry.recv += bytes,
            Direction::Outbound => entry.sent += bytes,
        }
        if let Some(name) = name {
            self.pid_names.entry(pid).or_insert(name);
        }
    }

    pub fn record_flow(&mut self, flow: Flow, process: Option<ObservedProcess>) {
        match flow.direction {
            Direction::Inbound => self.add_in(flow.peer, flow.bytes),
            Direction::Outbound => self.add_out(flow.peer, flow.bytes),
        }
        if let Some(process) = process {
            self.add_proc(process.pid, process.name, flow.direction, flow.bytes);
        }
    }

    pub fn snapshot(&self, top_n: usize) -> TrafficSnapshot {
        let processes = self
            .top_procs(top_n)
            .into_iter()
            .map(|(pid, traffic)| ProcessSnapshot {
                pid,
                name: self.pid_names.get(&pid).cloned(),
                recv: traffic.recv,
                sent: traffic.sent,
            })
            .collect::<Vec<_>>()
            .into();
        let inbound_ips = self
            .top_in(top_n)
            .into_iter()
            .map(|(ip, bytes)| IpSnapshot { ip, bytes })
            .collect::<Vec<_>>()
            .into();
        let outbound_ips = self
            .top_out(top_n)
            .into_iter()
            .map(|(ip, bytes)| IpSnapshot { ip, bytes })
            .collect::<Vec<_>>()
            .into();

        TrafficSnapshot {
            in_bytes: self.in_bytes,
            out_bytes: self.out_bytes,
            processes,
            inbound_ips,
            outbound_ips,
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
        self.pid_names.get(&pid).map(|s| s.as_ref())
    }
}

fn top_n_ip(map: &HashMap<IpAddr, u64>, n: usize) -> Vec<(IpAddr, u64)> {
    let mut entries: Vec<(IpAddr, u64)> = map.iter().map(|(ip, bytes)| (*ip, *bytes)).collect();
    entries.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
    entries.truncate(n);
    entries
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use super::*;
    use crate::capture::Flow;

    #[test]
    fn snapshot_returns_ranked_top_n() {
        let mut stats = Stats::default();
        let process_name: Arc<str> = Arc::from("curl --silent");

        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 1], 40),
            Some(ObservedProcess {
                pid: 7,
                name: Some(process_name.clone()),
            }),
        );
        stats.record_flow(
            flow(Direction::Outbound, [10, 0, 0, 2], 60),
            Some(ObservedProcess {
                pid: 7,
                name: Some(process_name.clone()),
            }),
        );
        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 3], 30),
            Some(ObservedProcess { pid: 8, name: None }),
        );
        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 4], 10),
            Some(ObservedProcess { pid: 9, name: None }),
        );

        let snapshot = stats.snapshot(2);

        assert_eq!(snapshot.in_bytes, 80);
        assert_eq!(snapshot.out_bytes, 60);
        assert_eq!(snapshot.processes.len(), 2);
        assert_eq!(snapshot.processes[0].pid, 7);
        assert_eq!(snapshot.processes[0].name.as_deref(), Some("curl --silent"));
        assert_eq!(snapshot.processes[0].recv, 40);
        assert_eq!(snapshot.processes[0].sent, 60);
        assert_eq!(snapshot.processes[1].pid, 8);
        assert!(!snapshot.processes.iter().any(|process| process.pid == 9));
        assert_eq!(snapshot.inbound_ips.len(), 2);
        assert_eq!(snapshot.inbound_ips[0].ip, ip([10, 0, 0, 1]));
        assert_eq!(snapshot.inbound_ips[0].bytes, 40);
        assert!(
            !snapshot
                .inbound_ips
                .iter()
                .any(|entry| entry.ip == ip([10, 0, 0, 4]))
        );
        assert_eq!(snapshot.outbound_ips.len(), 1);
        assert_eq!(snapshot.outbound_ips[0].ip, ip([10, 0, 0, 2]));
        assert!(Arc::ptr_eq(
            snapshot.processes[0].name.as_ref().unwrap(),
            &process_name
        ));
    }

    #[test]
    fn add_proc_reuses_shared_name() {
        let mut stats = Stats::default();
        let name: Arc<str> = Arc::from("nginx");

        stats.add_proc(9, Some(name.clone()), Direction::Outbound, 50);
        let snapshot = stats.snapshot(1);

        assert!(Arc::ptr_eq(
            snapshot.processes[0].name.as_ref().unwrap(),
            &name
        ));
    }

    fn flow(direction: Direction, peer: [u8; 4], bytes: u64) -> Flow {
        Flow {
            direction,
            peer: ip(peer),
            bytes,
            local_socket: None,
        }
    }

    fn ip(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }
}
