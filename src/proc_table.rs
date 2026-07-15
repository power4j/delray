use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use crate::capture::TransportProtocol;

type SocketKey = (IpAddr, u16, TransportProtocol);

/// Process association table rebuilt periodically by a background thread.
#[derive(Default)]
pub struct ProcTable {
    entries: HashMap<SocketKey, ProcInfo>,
}

pub struct ProcInfo {
    pub pid: u32,
    pub name: Option<Arc<str>>,
}

struct ListenerRecord {
    socket: SocketAddr,
    protocol: TransportProtocol,
    pid: u32,
    path: String,
}

pub type SharedProcTable = Arc<RwLock<ProcTable>>;

impl ProcTable {
    pub fn lookup(&self, ip: IpAddr, port: u16, protocol: TransportProtocol) -> Option<&ProcInfo> {
        self.entries.get(&(ip, port, protocol))
    }

    fn from_records(records: impl IntoIterator<Item = ListenerRecord>) -> Self {
        let entries = records
            .into_iter()
            .map(|record| {
                let key = (record.socket.ip(), record.socket.port(), record.protocol);
                (
                    key,
                    ProcInfo {
                        pid: record.pid,
                        name: executable_name(&record.path).map(Arc::from),
                    },
                )
            })
            .collect();
        Self { entries }
    }

    #[cfg(test)]
    pub(crate) fn insert_for_test(
        &mut self,
        ip: IpAddr,
        port: u16,
        protocol: TransportProtocol,
        pid: u32,
        name: Arc<str>,
    ) {
        self.entries.insert(
            (ip, port, protocol),
            ProcInfo {
                pid,
                name: Some(name),
            },
        );
    }
}

impl From<listeners::Listener> for ListenerRecord {
    fn from(listener: listeners::Listener) -> Self {
        Self {
            socket: listener.socket,
            protocol: listener.protocol.into(),
            pid: listener.process.pid,
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
            let new_table = build();
            if let Ok(mut table) = handle.write() {
                *table = new_table;
            }
            thread::sleep(refresh);
        }
    });
    table
}

fn build() -> ProcTable {
    listeners::get_all()
        .map(|listeners| ProcTable::from_records(listeners.into_iter().map(ListenerRecord::from)))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn record(
        ip: IpAddr,
        port: u16,
        protocol: TransportProtocol,
        pid: u32,
        path: &str,
    ) -> ListenerRecord {
        ListenerRecord {
            socket: SocketAddr::new(ip, port),
            protocol,
            pid,
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
    fn process_display_name_uses_executable_file_name() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table =
            ProcTable::from_records([record(ip, 443, TransportProtocol::Tcp, 7, "/usr/bin/curl")]);

        let process = table
            .lookup(ip, 443, TransportProtocol::Tcp)
            .expect("injected listener should match");
        assert_eq!(process.name.as_deref(), Some("curl"));
    }

    #[test]
    fn missing_executable_path_has_no_display_name() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table = ProcTable::from_records([record(ip, 443, TransportProtocol::Tcp, 7, "")]);

        let process = table
            .lookup(ip, 443, TransportProtocol::Tcp)
            .expect("PID attribution should survive a missing path");
        assert!(process.name.is_none());
    }
}
