use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::capture::TransportProtocol;

type SocketKey = (IpAddr, u16, TransportProtocol);

/// Process association table rebuilt periodically by a background thread.
#[derive(Default)]
pub struct ProcTable {
    entries: HashMap<SocketKey, HashMap<u32, ProcInfo>>,
    refreshed_at: Option<Instant>,
    max_age: Duration,
}

pub struct ProcInfo {
    pub pid: u32,
    pub name: Option<Arc<str>>,
    pub path: Option<Arc<str>>,
}

struct ListenerRecord {
    socket: SocketAddr,
    protocol: TransportProtocol,
    pid: u32,
    _name: String,
    path: String,
}

pub type SharedProcTable = Arc<RwLock<ProcTable>>;

impl ProcTable {
    pub(crate) fn is_fresh(&self) -> bool {
        self.is_fresh_at(Instant::now())
    }

    fn is_fresh_at(&self, now: Instant) -> bool {
        self.refreshed_at
            .is_some_and(|refreshed_at| now.saturating_duration_since(refreshed_at) <= self.max_age)
    }

    pub fn lookup(&self, ip: IpAddr, port: u16, protocol: TransportProtocol) -> Option<&ProcInfo> {
        self.lookup_at(ip, port, protocol, Instant::now())
    }

    fn lookup_at(
        &self,
        ip: IpAddr,
        port: u16,
        protocol: TransportProtocol,
        now: Instant,
    ) -> Option<&ProcInfo> {
        if self
            .refreshed_at
            .is_some_and(|refreshed_at| now.saturating_duration_since(refreshed_at) > self.max_age)
        {
            return None;
        }

        let candidates = self
            .entries
            .get(&(ip, port, protocol))
            .or_else(|| self.entries.get(&(wildcard_for(ip), port, protocol)))?;
        (candidates.len() == 1)
            .then(|| candidates.values().next())
            .flatten()
    }

    fn from_records(records: impl IntoIterator<Item = ListenerRecord>) -> Self {
        let mut entries: HashMap<SocketKey, HashMap<u32, ProcInfo>> = HashMap::new();
        for record in records {
            let key = (record.socket.ip(), record.socket.port(), record.protocol);
            entries
                .entry(key)
                .or_default()
                .entry(record.pid)
                .or_insert(ProcInfo {
                    pid: record.pid,
                    name: executable_name(&record.path).map(Arc::from),
                    path: (!record.path.is_empty()).then(|| Arc::from(record.path)),
                });
        }
        Self {
            entries,
            refreshed_at: None,
            max_age: Duration::ZERO,
        }
    }

    fn refresh_at(
        &mut self,
        result: Result<Vec<ListenerRecord>, String>,
        refreshed_at: Instant,
        refresh: Duration,
    ) -> Result<(), String> {
        let records = result?;
        let mut next = Self::from_records(records);
        next.refreshed_at = Some(refreshed_at);
        next.max_age = refresh.saturating_mul(2);
        *self = next;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn insert_for_test(
        &mut self,
        ip: IpAddr,
        port: u16,
        protocol: TransportProtocol,
        pid: u32,
        name: Arc<str>,
        path: Option<Arc<str>>,
    ) {
        self.refreshed_at = Some(Instant::now());
        self.max_age = Duration::MAX;
        self.entries
            .entry((ip, port, protocol))
            .or_default()
            .insert(
                pid,
                ProcInfo {
                    pid,
                    name: Some(name),
                    path,
                },
            );
    }
}

fn wildcard_for(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

impl From<listeners::Listener> for ListenerRecord {
    fn from(listener: listeners::Listener) -> Self {
        Self {
            socket: listener.socket,
            protocol: listener.protocol.into(),
            pid: listener.process.pid,
            _name: listener.process.name,
            path: listener.process.path,
        }
    }
}

impl From<listeners::Protocol> for TransportProtocol {
    fn from(protocol: listeners::Protocol) -> Self {
        match protocol {
            listeners::Protocol::TCP => Self::Tcp,
            listeners::Protocol::UDP => Self::Udp,
        }
    }
}

fn executable_name(path: &str) -> Option<&str> {
    Path::new(path)
        .file_name()?
        .to_str()
        .filter(|name| !name.is_empty())
}

/// Start rebuilding the process table on a background thread.
pub fn spawn(refresh: Duration) -> SharedProcTable {
    let table: SharedProcTable = Arc::new(RwLock::new(ProcTable::default()));
    let handle = table.clone();
    thread::spawn(move || {
        loop {
            let result = query();
            if let Err(error) = &result {
                eprintln!("Failed to refresh process table: {error}");
            }
            match handle.write() {
                Ok(mut table) => {
                    let _ = table.refresh_at(result, Instant::now(), refresh);
                }
                Err(error) => {
                    eprintln!("Failed to update process table: {error}");
                }
            }
            thread::sleep(refresh);
        }
    });
    table
}

fn query() -> Result<Vec<ListenerRecord>, String> {
    listeners::get_all()
        .map(|listeners| listeners.into_iter().map(ListenerRecord::from).collect())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Instant;

    use super::*;

    fn record(
        ip: IpAddr,
        port: u16,
        protocol: TransportProtocol,
        pid: u32,
        path: &str,
    ) -> ListenerRecord {
        record_with_name(ip, port, protocol, pid, "", path)
    }

    fn record_with_name(
        ip: IpAddr,
        port: u16,
        protocol: TransportProtocol,
        pid: u32,
        name: &str,
        path: &str,
    ) -> ListenerRecord {
        ListenerRecord {
            socket: SocketAddr::new(ip, port),
            protocol,
            pid,
            _name: name.to_string(),
            path: path.to_string(),
        }
    }

    #[test]
    fn injected_records_match_address_port_and_protocol() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let table = ProcTable::from_records([
            record(ip, 443, TransportProtocol::Tcp, 7, "/usr/bin/curl"),
            record(ip, 443, TransportProtocol::Udp, 8, "/usr/bin/quiche"),
        ]);

        assert_eq!(
            table.lookup(ip, 443, TransportProtocol::Tcp).map(|p| p.pid),
            Some(7)
        );
        assert_eq!(
            table.lookup(ip, 443, TransportProtocol::Udp).map(|p| p.pid),
            Some(8)
        );
        assert!(table.lookup(ip, 80, TransportProtocol::Tcp).is_none());
    }

    #[test]
    fn injected_records_support_ipv4_and_ipv6() {
        let ipv4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let table = ProcTable::from_records([
            record(ipv4, 8080, TransportProtocol::Tcp, 10, "/opt/server4"),
            record(ipv6, 5353, TransportProtocol::Udp, 11, "/opt/server6"),
        ]);

        assert_eq!(
            table
                .lookup(ipv4, 8080, TransportProtocol::Tcp)
                .map(|p| p.pid),
            Some(10)
        );
        assert_eq!(
            table
                .lookup(ipv6, 5353, TransportProtocol::Udp)
                .map(|p| p.pid),
            Some(11)
        );
    }

    #[test]
    fn ipv4_wildcard_listener_matches_concrete_address() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let table = ProcTable::from_records([record(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            8080,
            TransportProtocol::Tcp,
            7,
            "/opt/server",
        )]);

        assert_eq!(
            table
                .lookup(local_ip, 8080, TransportProtocol::Tcp)
                .map(|process| process.pid),
            Some(7)
        );
    }

    #[test]
    fn ipv6_wildcard_listener_matches_concrete_address() {
        let local_ip = IpAddr::V6("2001:db8::10".parse().unwrap());
        let table = ProcTable::from_records([record(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            8080,
            TransportProtocol::Tcp,
            7,
            "/opt/server",
        )]);

        assert_eq!(
            table
                .lookup(local_ip, 8080, TransportProtocol::Tcp)
                .map(|process| process.pid),
            Some(7)
        );
    }

    #[test]
    fn concrete_address_takes_priority_over_wildcard_listener() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let table = ProcTable::from_records([
            record(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                8080,
                TransportProtocol::Tcp,
                7,
                "/opt/wildcard-server",
            ),
            record(
                local_ip,
                8080,
                TransportProtocol::Tcp,
                8,
                "/opt/specific-server",
            ),
        ]);

        assert_eq!(
            table
                .lookup(local_ip, 8080, TransportProtocol::Tcp)
                .map(|process| process.pid),
            Some(8)
        );
    }

    #[test]
    fn duplicate_candidates_for_one_pid_are_attributed() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table = ProcTable::from_records([
            record(ip, 443, TransportProtocol::Tcp, 7, "/usr/bin/curl"),
            record(ip, 443, TransportProtocol::Tcp, 7, "/usr/bin/curl"),
        ]);

        assert_eq!(
            table.lookup(ip, 443, TransportProtocol::Tcp).map(|p| p.pid),
            Some(7)
        );
    }

    #[test]
    fn candidates_for_different_pids_are_ambiguous() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table = ProcTable::from_records([
            record(ip, 443, TransportProtocol::Tcp, 7, "/usr/bin/server-a"),
            record(ip, 443, TransportProtocol::Tcp, 8, "/usr/bin/server-b"),
        ]);

        assert!(table.lookup(ip, 443, TransportProtocol::Tcp).is_none());
    }

    #[test]
    fn process_display_name_uses_executable_file_name() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table = ProcTable::from_records([record_with_name(
            ip,
            443,
            TransportProtocol::Tcp,
            7,
            "backend-name",
            "/usr/bin/curl",
        )]);

        let process = table
            .lookup(ip, 443, TransportProtocol::Tcp)
            .expect("injected listener should match");
        assert_eq!(process.name.as_deref(), Some("curl"));
    }

    #[test]
    fn process_observation_includes_executable_path() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table =
            ProcTable::from_records([record(ip, 443, TransportProtocol::Tcp, 7, "/usr/bin/curl")]);

        let process = table
            .lookup(ip, 443, TransportProtocol::Tcp)
            .expect("injected listener should match");

        assert_eq!(process.path.as_deref(), Some("/usr/bin/curl"));
    }

    #[test]
    fn missing_process_name_uses_executable_file_name() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table = ProcTable::from_records([record_with_name(
            ip,
            443,
            TransportProtocol::Tcp,
            7,
            "",
            "/usr/bin/curl",
        )]);

        let process = table
            .lookup(ip, 443, TransportProtocol::Tcp)
            .expect("PID attribution should survive a missing process name");
        assert_eq!(process.name.as_deref(), Some("curl"));
    }

    #[test]
    fn missing_executable_path_does_not_invent_display_name() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table = ProcTable::from_records([record_with_name(
            ip,
            443,
            TransportProtocol::Tcp,
            7,
            "curl",
            "",
        )]);

        let process = table
            .lookup(ip, 443, TransportProtocol::Tcp)
            .expect("PID attribution should survive a missing executable path");
        assert!(process.name.is_none());
    }

    #[test]
    fn missing_executable_path_has_no_display_name() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table = ProcTable::from_records([record(ip, 443, TransportProtocol::Tcp, 7, "")]);

        let process = table
            .lookup(ip, 443, TransportProtocol::Tcp)
            .expect("PID attribution should survive a missing path");
        assert!(process.name.is_none());
        assert!(process.path.is_none());
    }

    #[test]
    fn failed_refresh_keeps_last_success_until_snapshot_expires() {
        let started_at = Instant::now();
        let refresh = Duration::from_secs(5);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut table = ProcTable::default();
        table
            .refresh_at(
                Ok(vec![record(
                    ip,
                    443,
                    TransportProtocol::Tcp,
                    7,
                    "/usr/bin/curl",
                )]),
                started_at,
                refresh,
            )
            .unwrap();

        let error = table
            .refresh_at(
                Err("listeners unavailable".to_string()),
                started_at + refresh,
                refresh,
            )
            .unwrap_err();
        table
            .refresh_at(
                Err("listeners still unavailable".to_string()),
                started_at + refresh * 2,
                refresh,
            )
            .unwrap_err();

        assert_eq!(error, "listeners unavailable");
        assert_eq!(
            table
                .lookup_at(ip, 443, TransportProtocol::Tcp, started_at + refresh * 2,)
                .map(|process| process.pid),
            Some(7)
        );
        assert!(
            table
                .lookup_at(
                    ip,
                    443,
                    TransportProtocol::Tcp,
                    started_at + refresh * 2 + Duration::from_nanos(1),
                )
                .is_none()
        );
    }

    #[test]
    fn process_data_freshness_uses_the_last_successful_refresh() {
        let started_at = Instant::now();
        let refresh = Duration::from_secs(5);
        let mut table = ProcTable::default();
        table
            .refresh_at(Ok(Vec::new()), started_at, refresh)
            .unwrap();

        assert!(table.is_fresh_at(started_at + refresh * 2));
        assert!(!table.is_fresh_at(started_at + refresh * 2 + Duration::from_nanos(1)));
    }

    #[test]
    fn successful_refresh_replaces_expired_snapshot() {
        let started_at = Instant::now();
        let refresh = Duration::from_secs(5);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut table = ProcTable::default();
        table
            .refresh_at(
                Ok(vec![record(
                    ip,
                    443,
                    TransportProtocol::Tcp,
                    7,
                    "/usr/bin/old-server",
                )]),
                started_at,
                refresh,
            )
            .unwrap();
        let recovered_at = started_at + refresh * 3;

        assert!(
            table
                .lookup_at(ip, 443, TransportProtocol::Tcp, recovered_at)
                .is_none()
        );

        table
            .refresh_at(
                Ok(vec![record(
                    ip,
                    443,
                    TransportProtocol::Tcp,
                    8,
                    "/usr/bin/new-server",
                )]),
                recovered_at,
                refresh,
            )
            .unwrap();

        assert_eq!(
            table
                .lookup_at(ip, 443, TransportProtocol::Tcp, recovered_at)
                .map(|process| process.pid),
            Some(8)
        );
    }
}
