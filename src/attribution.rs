use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::capture::{Flow, LocalSocket};
use crate::proc_table::{self, LookupOutcome, SharedProcTable};
use crate::stats::{Direction, ObservedProcess, Stats};

pub(crate) const PENDING_ATTRIBUTION_WINDOW: Duration = Duration::from_secs(1);
pub(crate) const PENDING_ATTRIBUTION_CAPACITY: usize = 1_024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PendingAttributionSnapshot {
    pub records: usize,
    pub bytes: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ConnectionKey {
    local_socket: LocalSocket,
    peer_ip: IpAddr,
    peer_port: u16,
    direction: Direction,
}

struct PendingAttribution {
    connection: ConnectionKey,
    socket: LocalSocket,
    direction: Direction,
    bytes: u64,
    observed_at: DateTime<Utc>,
    pending_since: Instant,
}

struct EndpointObservation {
    socket: Option<LocalSocket>,
    direction: Direction,
    peer_ip: IpAddr,
    peer_port: Option<u16>,
    bytes: u64,
    observed_at: DateTime<Utc>,
}

pub(crate) struct PendingAttributor {
    pending: VecDeque<PendingAttribution>,
    window: Duration,
    capacity: usize,
    last_generation: Option<u64>,
}

impl Default for PendingAttributor {
    fn default() -> Self {
        Self::new(PENDING_ATTRIBUTION_WINDOW, PENDING_ATTRIBUTION_CAPACITY)
    }
}

impl PendingAttributor {
    pub(crate) fn new(window: Duration, capacity: usize) -> Self {
        Self {
            pending: VecDeque::new(),
            window,
            capacity,
            last_generation: None,
        }
    }

    pub(crate) fn record_flow(
        &mut self,
        stats: &mut Stats,
        flow: Flow,
        proc_table: &SharedProcTable,
        now: Instant,
        observed_at: DateTime<Utc>,
    ) {
        self.advance(stats, proc_table, now);
        stats.record_interface_flow(&flow);

        self.record_endpoint(
            stats,
            EndpointObservation {
                socket: flow.local_socket,
                direction: flow.direction,
                peer_ip: flow.peer,
                peer_port: flow.peer_port,
                bytes: flow.bytes,
                observed_at,
            },
            proc_table,
            now,
        );

        if let (Some(peer_socket), Some(local_socket)) = (flow.peer_local_socket, flow.local_socket)
        {
            self.record_endpoint(
                stats,
                EndpointObservation {
                    socket: Some(peer_socket),
                    direction: Direction::Inbound,
                    peer_ip: local_socket.ip,
                    peer_port: Some(local_socket.port),
                    bytes: flow.bytes,
                    observed_at,
                },
                proc_table,
                now,
            );
        }
    }

    pub(crate) fn advance(
        &mut self,
        stats: &mut Stats,
        proc_table: &SharedProcTable,
        now: Instant,
    ) {
        self.finalize_expired(stats, now);

        let generation = proc_table.read().ok().map(|table| table.generation());
        if generation.is_none() || generation == self.last_generation {
            return;
        }
        self.last_generation = generation;

        while let Some(pending) = self.pending.pop_front() {
            match lookup_process(proc_table, pending.socket, None, false) {
                Some(process) => {
                    stats.record_process(
                        Some(process),
                        pending.direction,
                        pending.bytes,
                        pending.observed_at,
                    );
                }
                None => {
                    stats.record_process(
                        None,
                        pending.direction,
                        pending.bytes,
                        pending.observed_at,
                    );
                }
            }
        }
    }

    #[cfg(test)]
    fn pending_bytes(&self) -> u64 {
        self.snapshot().bytes
    }

    pub(crate) fn snapshot(&self) -> PendingAttributionSnapshot {
        PendingAttributionSnapshot {
            records: self.pending.len(),
            bytes: self.pending.iter().map(|pending| pending.bytes).sum(),
        }
    }

    fn record_endpoint(
        &mut self,
        stats: &mut Stats,
        observation: EndpointObservation,
        proc_table: &SharedProcTable,
        now: Instant,
    ) {
        let EndpointObservation {
            socket,
            direction,
            peer_ip,
            peer_port,
            bytes,
            observed_at,
        } = observation;
        let Some(socket) = socket else {
            proc_table::record_no_local_socket(proc_table);
            stats.record_process(None, direction, bytes, observed_at);
            return;
        };
        let Some(peer_port) = peer_port else {
            stats.record_process(None, direction, bytes, observed_at);
            return;
        };

        if let Some(process) = lookup_process(proc_table, socket, Some((peer_ip, peer_port)), true)
        {
            stats.record_process(Some(process), direction, bytes, observed_at);
            return;
        }

        self.push_pending(
            stats,
            PendingAttribution {
                connection: ConnectionKey {
                    local_socket: socket,
                    peer_ip,
                    peer_port,
                    direction,
                },
                socket,
                direction,
                bytes,
                observed_at,
                pending_since: now,
            },
        );
    }

    fn finalize_expired(&mut self, stats: &mut Stats, now: Instant) {
        while self.pending.front().is_some_and(|pending| {
            now.saturating_duration_since(pending.pending_since) >= self.window
        }) {
            self.finalize_oldest(stats);
        }
    }

    fn push_pending(&mut self, stats: &mut Stats, pending: PendingAttribution) {
        debug_assert_eq!(pending.connection.local_socket, pending.socket);
        debug_assert_eq!(pending.connection.direction, pending.direction);
        debug_assert!(matches!(
            pending.connection.peer_ip,
            IpAddr::V4(_) | IpAddr::V6(_)
        ));
        debug_assert_ne!(pending.connection.peer_port, 0);
        if self.capacity == 0 {
            stats.record_process(None, pending.direction, pending.bytes, pending.observed_at);
            return;
        }
        if let Some(existing) = self
            .pending
            .iter_mut()
            .find(|existing| existing.connection == pending.connection)
        {
            existing.bytes += pending.bytes;
            existing.observed_at = pending.observed_at;
            return;
        }
        if self.pending.len() == self.capacity {
            self.finalize_oldest(stats);
        }
        self.pending.push_back(pending);
    }

    fn finalize_oldest(&mut self, stats: &mut Stats) {
        if let Some(pending) = self.pending.pop_front() {
            stats.record_process(None, pending.direction, pending.bytes, pending.observed_at);
        }
    }
}

fn lookup_process(
    proc_table: &SharedProcTable,
    socket: LocalSocket,
    peer: Option<(IpAddr, u16)>,
    request_refresh: bool,
) -> Option<ObservedProcess> {
    let table = proc_table.read().ok()?;
    match table.lookup_outcome(socket.ip, socket.port, socket.protocol) {
        LookupOutcome::Hit { process, v4_mapped } => {
            table.record_lookup_hit();
            if v4_mapped {
                table.record_v4_mapped_lookup_hit();
            }
            Some(ObservedProcess {
                pid: process.pid,
                name: process.name.clone(),
                path: process.path.clone(),
            })
        }
        LookupOutcome::Miss(reason) => {
            table.record_lookup_miss(reason);
            if let Some((peer_ip, peer_port)) = peer {
                table.record_lookup_miss_sample(reason, socket, peer_ip, peer_port);
            }
            drop(table);
            if request_refresh {
                proc_table::request_refresh(proc_table);
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, RwLock};

    use super::*;
    use crate::capture::TransportProtocol;
    use crate::proc_table::ProcTable;

    fn socket_flow(local_ip: IpAddr, local_port: u16, peer_port: u16, bytes: u64) -> Flow {
        Flow {
            direction: Direction::Outbound,
            peer: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
            peer_port: Some(peer_port),
            bytes,
            local_socket: Some(LocalSocket {
                ip: local_ip,
                port: local_port,
                protocol: TransportProtocol::Tcp,
            }),
            peer_local_socket: None,
        }
    }

    fn observed_at() -> DateTime<Utc> {
        "2026-07-17T08:00:00Z".parse().unwrap()
    }

    #[test]
    fn continued_flow_is_pending_then_attributed_after_a_new_proc_table() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::default();
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        assert_eq!(stats.snapshot(10).out_bytes, 40);
        assert!(stats.snapshot(10).processes.is_empty());
        assert_eq!(attributor.pending_bytes(), 40);

        proc_table.write().unwrap().insert_for_test(
            local_ip,
            49_152,
            TransportProtocol::Tcp,
            7,
            Arc::from("curl"),
            Some(Arc::from("/usr/bin/curl")),
        );
        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 60),
            &proc_table,
            started + Duration::from_millis(10),
            observed_at() + chrono::Duration::milliseconds(10),
        );

        let snapshot = stats.snapshot(10);
        let process = snapshot
            .processes
            .iter()
            .find(|process| process.pid() == Some(7))
            .unwrap();
        assert_eq!(snapshot.out_bytes, 100);
        assert_eq!(process.sent, 100);
        assert_eq!(
            process.last_seen(),
            observed_at() + chrono::Duration::milliseconds(10)
        );
        assert_eq!(attributor.pending_bytes(), 0);
    }

    #[test]
    fn short_flow_times_out_to_unattributed() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::default();
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        attributor.advance(
            &mut stats,
            &proc_table,
            started + PENDING_ATTRIBUTION_WINDOW,
        );

        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.out_bytes, 40);
        assert!(snapshot.processes[0].is_unattributed());
        assert_eq!(snapshot.processes[0].sent, 40);
    }

    #[test]
    fn delayed_attribution_uses_the_original_observation_time_for_last_seen() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::default();
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        proc_table.write().unwrap().insert_for_test(
            local_ip,
            49_152,
            TransportProtocol::Tcp,
            7,
            Arc::from("curl"),
            None,
        );
        attributor.advance(
            &mut stats,
            &proc_table,
            started + Duration::from_millis(500),
        );

        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.processes[0].pid(), Some(7));
        assert_eq!(snapshot.processes[0].last_seen(), observed_at());
    }

    #[test]
    fn ambiguous_same_port_is_unattributed_when_pending_expires() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let mut table = ProcTable::default();
        for (pid, name) in [(7, "server-a"), (8, "server-b")] {
            table.insert_for_test(
                local_ip,
                443,
                TransportProtocol::Tcp,
                pid,
                Arc::from(name),
                None,
            );
        }
        let proc_table = Arc::new(RwLock::new(table));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::default();
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 443, 49_152, 40),
            &proc_table,
            started,
            observed_at(),
        );
        attributor.advance(
            &mut stats,
            &proc_table,
            started + PENDING_ATTRIBUTION_WINDOW,
        );

        let snapshot = stats.snapshot(10);
        assert!(snapshot.processes[0].is_unattributed());
        assert_eq!(snapshot.processes[0].sent, 40);
    }

    #[test]
    fn failed_refresh_and_stale_proc_table_do_not_falsely_attribute_pending_traffic() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let mut table = ProcTable::default();
        table.insert_for_test(
            local_ip,
            49_152,
            TransportProtocol::Tcp,
            7,
            Arc::from("curl"),
            None,
        );
        table.expire_for_test();
        table.fail_refresh_for_test();
        let proc_table = Arc::new(RwLock::new(table));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::default();
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        attributor.advance(
            &mut stats,
            &proc_table,
            started + PENDING_ATTRIBUTION_WINDOW,
        );

        let snapshot = stats.snapshot(10);
        assert!(snapshot.processes[0].is_unattributed());
        assert_eq!(snapshot.processes[0].sent, 40);
    }

    #[test]
    fn pending_capacity_overflow_finalizes_oldest_traffic_without_losing_totals() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::new(Duration::from_secs(1), 1);
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_153, 443, 60),
            &proc_table,
            started + Duration::from_millis(1),
            observed_at() + chrono::Duration::milliseconds(1),
        );

        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.out_bytes, 100);
        assert_eq!(snapshot.processes[0].sent, 40);
        assert_eq!(attributor.pending_bytes(), 60);
        attributor.advance(
            &mut stats,
            &proc_table,
            started + Duration::from_secs(1) + Duration::from_millis(1),
        );
        assert_eq!(stats.snapshot(10).processes[0].sent, 100);
    }

    #[test]
    fn same_connection_merges_pending_records_without_consuming_capacity() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::new(Duration::from_secs(1), 1);
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 60),
            &proc_table,
            started + Duration::from_millis(1),
            observed_at() + chrono::Duration::milliseconds(1),
        );

        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.out_bytes, 100);
        assert!(snapshot.processes.is_empty());
        assert_eq!(attributor.pending_bytes(), 100);
    }

    #[test]
    fn reused_local_port_with_a_different_peer_port_keeps_distinct_pending_records() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::new(Duration::from_secs(1), 1);
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 444, 60),
            &proc_table,
            started + Duration::from_millis(1),
            observed_at() + chrono::Duration::milliseconds(1),
        );

        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.out_bytes, 100);
        assert!(snapshot.processes[0].is_unattributed());
        assert_eq!(snapshot.processes[0].sent, 40);
        assert_eq!(attributor.pending_bytes(), 60);
    }
}
