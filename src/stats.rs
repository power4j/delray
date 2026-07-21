use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::capture::Flow;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
    pub path: Option<Arc<str>>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ProcessKey {
    pid: u32,
    path: Option<Arc<str>>,
}

#[derive(Clone, Default)]
pub struct TrafficSnapshot {
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub process_data_fresh: bool,
    pub processes: Arc<[ProcessSnapshot]>,
    pub inbound_ips: Arc<[IpSnapshot]>,
    pub outbound_ips: Arc<[IpSnapshot]>,
}

#[derive(Clone)]
pub struct ProcessSnapshot {
    identity: ProcessIdentity,
    pub recv: u64,
    pub sent: u64,
    last_seen: DateTime<Utc>,
}

#[derive(Clone)]
enum ProcessIdentity {
    Attributed {
        pid: u32,
        name: Option<Arc<str>>,
        path: Option<Arc<str>>,
    },
    Unattributed,
}

impl ProcessSnapshot {
    pub(crate) fn attributed(
        pid: u32,
        name: Option<Arc<str>>,
        path: Option<Arc<str>>,
        last_seen: DateTime<Utc>,
        recv: u64,
        sent: u64,
    ) -> Self {
        Self {
            identity: ProcessIdentity::Attributed { pid, name, path },
            recv,
            sent,
            last_seen,
        }
    }

    pub(crate) fn unattributed(recv: u64, sent: u64, last_seen: DateTime<Utc>) -> Self {
        Self {
            identity: ProcessIdentity::Unattributed,
            recv,
            sent,
            last_seen,
        }
    }

    pub(crate) fn pid(&self) -> Option<u32> {
        match self.identity {
            ProcessIdentity::Attributed { pid, .. } => Some(pid),
            ProcessIdentity::Unattributed => None,
        }
    }

    pub(crate) fn name(&self) -> Option<&str> {
        match &self.identity {
            ProcessIdentity::Attributed { name, .. } => name.as_deref(),
            ProcessIdentity::Unattributed => None,
        }
    }

    pub(crate) fn path(&self) -> Option<&str> {
        match &self.identity {
            ProcessIdentity::Attributed { path, .. } => path.as_deref(),
            ProcessIdentity::Unattributed => None,
        }
    }

    pub(crate) fn last_seen(&self) -> DateTime<Utc> {
        self.last_seen
    }

    pub(crate) fn is_unattributed(&self) -> bool {
        matches!(self.identity, ProcessIdentity::Unattributed)
    }

    pub(crate) fn display_name(&self) -> &str {
        match &self.identity {
            ProcessIdentity::Attributed { name, .. } => name.as_deref().unwrap_or("?"),
            ProcessIdentity::Unattributed => "<unattributed traffic>",
        }
    }

    pub(crate) fn total(&self) -> u64 {
        self.recv.saturating_add(self.sent)
    }

    pub(crate) fn same_identity_as(&self, other: &Self) -> bool {
        match (&self.identity, &other.identity) {
            (ProcessIdentity::Unattributed, ProcessIdentity::Unattributed) => true,
            (
                ProcessIdentity::Attributed {
                    pid: left_pid,
                    path: left_path,
                    ..
                },
                ProcessIdentity::Attributed {
                    pid: right_pid,
                    path: right_path,
                    ..
                },
            ) => left_pid == right_pid && left_path == right_path,
            _ => false,
        }
    }
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
    by_proc: HashMap<ProcessKey, ProcTraffic>,
    proc_last_seen: HashMap<ProcessKey, DateTime<Utc>>,
    unattributed: ProcTraffic,
    unattributed_last_seen: Option<DateTime<Utc>>,
    proc_names: HashMap<ProcessKey, Arc<str>>,
}

impl Stats {
    fn add_in(&mut self, source: IpAddr, bytes: u64) {
        self.in_bytes += bytes;
        *self.in_by_ip.entry(source).or_default() += bytes;
    }

    fn add_out(&mut self, destination: IpAddr, bytes: u64) {
        self.out_bytes += bytes;
        *self.out_by_ip.entry(destination).or_default() += bytes;
    }

    fn add_proc(
        &mut self,
        process: ObservedProcess,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
    ) {
        let key = ProcessKey {
            pid: process.pid,
            path: process.path,
        };
        let entry = self.by_proc.entry(key.clone()).or_default();
        match direction {
            Direction::Inbound => entry.recv += bytes,
            Direction::Outbound => entry.sent += bytes,
        }
        if let Some(name) = process.name {
            self.proc_names.entry(key.clone()).or_insert(name);
        }
        self.proc_last_seen.insert(key, observed_at);
    }

    #[cfg(test)]
    pub fn record_flow(&mut self, flow: Flow, process: Option<ObservedProcess>) {
        self.record_flow_at(flow, process, Utc::now());
    }

    #[cfg(test)]
    pub(crate) fn record_flow_at(
        &mut self,
        flow: Flow,
        process: Option<ObservedProcess>,
        observed_at: DateTime<Utc>,
    ) {
        self.record_flow_processes_at(flow, process, None, observed_at);
    }

    #[cfg(test)]
    pub(crate) fn record_flow_processes_at(
        &mut self,
        flow: Flow,
        process: Option<ObservedProcess>,
        peer_process: Option<ObservedProcess>,
        observed_at: DateTime<Utc>,
    ) {
        self.record_interface_flow(&flow);
        if flow.peer_local_socket.is_some() {
            self.record_process(process, Direction::Outbound, flow.bytes, observed_at);
            self.record_process(peer_process, Direction::Inbound, flow.bytes, observed_at);
            return;
        }

        self.record_process(process, flow.direction, flow.bytes, observed_at);
    }

    pub(crate) fn record_interface_flow(&mut self, flow: &Flow) {
        if flow.peer_local_socket.is_some() {
            self.add_out(flow.peer, flow.bytes);
            self.add_in(
                flow.local_socket
                    .map(|socket| socket.ip)
                    .unwrap_or(flow.peer),
                flow.bytes,
            );
            return;
        }

        match flow.direction {
            Direction::Inbound => self.add_in(flow.peer, flow.bytes),
            Direction::Outbound => self.add_out(flow.peer, flow.bytes),
        }
    }

    pub(crate) fn record_process(
        &mut self,
        process: Option<ObservedProcess>,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
    ) {
        self.add_process_or_unattributed(process, direction, bytes, observed_at);
    }

    fn add_process_or_unattributed(
        &mut self,
        process: Option<ObservedProcess>,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
    ) {
        match process {
            Some(process) => {
                self.add_proc(process, direction, bytes, observed_at);
            }
            None => {
                match direction {
                    Direction::Inbound => self.unattributed.recv += bytes,
                    Direction::Outbound => self.unattributed.sent += bytes,
                }
                self.unattributed_last_seen = Some(observed_at);
            }
        }
    }

    pub fn snapshot(&self, top_n: usize) -> TrafficSnapshot {
        let mut processes = self
            .top_procs(top_n)
            .into_iter()
            .map(|(key, traffic)| {
                let last_seen = self.proc_last_seen[&key];
                ProcessSnapshot::attributed(
                    key.pid,
                    self.proc_names.get(&key).cloned(),
                    key.path,
                    last_seen,
                    traffic.recv,
                    traffic.sent,
                )
            })
            .collect::<Vec<_>>();
        if self.unattributed.recv > 0 || self.unattributed.sent > 0 {
            processes.push(ProcessSnapshot::unattributed(
                self.unattributed.recv,
                self.unattributed.sent,
                self.unattributed_last_seen
                    .expect("unattributed traffic has an observation time"),
            ));
        }
        processes.sort_unstable_by_key(|process| std::cmp::Reverse(process.total()));
        processes.truncate(top_n);
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
            process_data_fresh: false,
            processes: processes.into(),
            inbound_ips,
            outbound_ips,
        }
    }

    fn top_in(&self, n: usize) -> Vec<(IpAddr, u64)> {
        top_n_ip(&self.in_by_ip, n)
    }

    fn top_out(&self, n: usize) -> Vec<(IpAddr, u64)> {
        top_n_ip(&self.out_by_ip, n)
    }

    fn top_procs(&self, n: usize) -> Vec<(ProcessKey, ProcTraffic)> {
        let mut entries: Vec<(ProcessKey, ProcTraffic)> = self
            .by_proc
            .iter()
            .map(|(key, traffic)| (key.clone(), *traffic))
            .collect();
        entries.sort_unstable_by_key(|(_, t)| std::cmp::Reverse(t.recv + t.sent));
        entries.truncate(n);
        entries
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
    fn unattributed_flow_appears_in_snapshot() {
        let mut stats = Stats::default();
        let observed_at = "2026-07-15T07:59:00Z".parse().unwrap();

        stats.record_flow_at(
            flow(Direction::Inbound, [10, 0, 0, 1], 40),
            None,
            observed_at,
        );
        let snapshot = stats.snapshot(10);

        assert_eq!(snapshot.processes.len(), 1);
        assert_eq!(snapshot.processes[0].pid(), None);
        assert!(snapshot.processes[0].name().is_none());
        assert!(snapshot.processes[0].path().is_none());
        assert_eq!(snapshot.processes[0].last_seen(), observed_at);
        assert_eq!(snapshot.processes[0].recv, 40);
        assert_eq!(snapshot.processes[0].sent, 0);
    }

    #[test]
    fn unattributed_flow_competes_for_top_n() {
        let mut stats = Stats::default();
        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 1], 10),
            Some(ObservedProcess {
                pid: 7,
                name: None,
                path: None,
            }),
        );
        stats.record_flow(flow(Direction::Inbound, [10, 0, 0, 2], 100), None);

        let snapshot = stats.snapshot(1);

        assert_eq!(snapshot.processes.len(), 1);
        assert_eq!(snapshot.processes[0].pid(), None);
        assert_eq!(snapshot.processes[0].recv, 100);
    }

    #[test]
    fn empty_snapshot_has_no_unattributed_process() {
        let snapshot = Stats::default().snapshot(10);

        assert!(snapshot.processes.is_empty());
    }

    #[test]
    fn same_pid_with_different_paths_has_distinct_traffic_history() {
        let mut stats = Stats::default();
        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 1], 40),
            Some(ObservedProcess {
                pid: 7,
                name: Some(Arc::from("old-curl")),
                path: Some(Arc::from("/opt/old/curl")),
            }),
        );
        stats.record_flow(
            flow(Direction::Outbound, [10, 0, 0, 2], 60),
            Some(ObservedProcess {
                pid: 7,
                name: Some(Arc::from("new-curl")),
                path: Some(Arc::from("/opt/new/curl")),
            }),
        );

        let snapshot = stats.snapshot(10);

        assert_eq!(snapshot.processes.len(), 2);
        let old = snapshot
            .processes
            .iter()
            .find(|process| process.path() == Some("/opt/old/curl"))
            .unwrap();
        let new = snapshot
            .processes
            .iter()
            .find(|process| process.path() == Some("/opt/new/curl"))
            .unwrap();
        assert_eq!((old.recv, old.sent), (40, 0));
        assert_eq!((new.recv, new.sent), (0, 60));
    }

    #[test]
    fn last_seen_advances_only_when_flow_is_recorded() {
        let mut stats = Stats::default();
        let first = "2026-07-15T08:00:00Z".parse().unwrap();
        let second = "2026-07-15T08:01:30Z".parse().unwrap();
        let process = ObservedProcess {
            pid: 7,
            name: Some(Arc::from("curl")),
            path: Some(Arc::from("/usr/bin/curl")),
        };

        stats.record_flow_at(
            flow(Direction::Inbound, [10, 0, 0, 1], 40),
            Some(process.clone()),
            first,
        );
        assert_eq!(stats.snapshot(10).processes[0].last_seen(), first);

        let unchanged = stats.snapshot(10);
        assert_eq!(unchanged.processes[0].last_seen(), first);

        stats.record_flow_at(
            flow(Direction::Outbound, [10, 0, 0, 2], 60),
            Some(process),
            second,
        );
        let updated = stats.snapshot(10);
        assert_eq!(
            (updated.processes[0].recv, updated.processes[0].sent),
            (40, 60)
        );
        assert_eq!(updated.processes[0].last_seen(), second);
    }

    #[test]
    fn process_buckets_partition_captured_traffic() {
        let mut stats = Stats::default();
        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 1], 40),
            Some(ObservedProcess {
                pid: 7,
                name: None,
                path: None,
            }),
        );
        stats.record_flow(
            flow(Direction::Outbound, [10, 0, 0, 2], 10),
            Some(ObservedProcess {
                pid: 7,
                name: None,
                path: None,
            }),
        );
        stats.record_flow(flow(Direction::Inbound, [10, 0, 0, 3], 30), None);
        stats.record_flow(flow(Direction::Outbound, [10, 0, 0, 4], 20), None);

        let snapshot = stats.snapshot(10);
        let process_in: u64 = snapshot.processes.iter().map(|process| process.recv).sum();
        let process_out: u64 = snapshot.processes.iter().map(|process| process.sent).sum();

        assert_eq!(snapshot.in_bytes, 70);
        assert_eq!(snapshot.out_bytes, 30);
        assert_eq!(process_in, snapshot.in_bytes);
        assert_eq!(process_out, snapshot.out_bytes);
    }

    #[test]
    fn snapshot_returns_ranked_top_n() {
        let mut stats = Stats::default();
        let process_name: Arc<str> = Arc::from("curl --silent");

        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 1], 40),
            Some(ObservedProcess {
                pid: 7,
                name: Some(process_name.clone()),
                path: None,
            }),
        );
        stats.record_flow(
            flow(Direction::Outbound, [10, 0, 0, 2], 60),
            Some(ObservedProcess {
                pid: 7,
                name: Some(process_name.clone()),
                path: None,
            }),
        );
        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 3], 30),
            Some(ObservedProcess {
                pid: 8,
                name: None,
                path: None,
            }),
        );
        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 4], 10),
            Some(ObservedProcess {
                pid: 9,
                name: None,
                path: None,
            }),
        );

        let snapshot = stats.snapshot(2);

        assert_eq!(snapshot.in_bytes, 80);
        assert_eq!(snapshot.out_bytes, 60);
        assert_eq!(snapshot.processes.len(), 2);
        assert_eq!(snapshot.processes[0].pid(), Some(7));
        assert_eq!(snapshot.processes[0].name(), Some("curl --silent"));
        assert_eq!(snapshot.processes[0].recv, 40);
        assert_eq!(snapshot.processes[0].sent, 60);
        assert_eq!(snapshot.processes[1].pid(), Some(8));
        assert!(snapshot.processes[1].name().is_none());
        assert!(snapshot.processes[1].path().is_none());
        assert!(
            !snapshot
                .processes
                .iter()
                .any(|process| process.pid() == Some(9))
        );
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
            match &snapshot.processes[0].identity {
                ProcessIdentity::Attributed {
                    name: Some(snapshot_name),
                    ..
                } => snapshot_name,
                _ => panic!("expected attributed process name"),
            },
            &process_name
        ));
    }

    #[test]
    fn add_proc_reuses_shared_name() {
        let mut stats = Stats::default();
        let name: Arc<str> = Arc::from("nginx");

        stats.add_proc(
            ObservedProcess {
                pid: 9,
                name: Some(name.clone()),
                path: None,
            },
            Direction::Outbound,
            50,
            Utc::now(),
        );
        let snapshot = stats.snapshot(1);

        assert!(Arc::ptr_eq(
            match &snapshot.processes[0].identity {
                ProcessIdentity::Attributed {
                    name: Some(snapshot_name),
                    ..
                } => snapshot_name,
                _ => panic!("expected attributed process name"),
            },
            &name
        ));
    }

    fn flow(direction: Direction, peer: [u8; 4], bytes: u64) -> Flow {
        Flow {
            direction,
            peer: ip(peer),
            peer_port: None,
            bytes,
            local_socket: None,
            peer_local_socket: None,
            domain: None,
        }
    }

    fn ip(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }
}
