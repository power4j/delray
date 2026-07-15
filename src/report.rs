use std::process::Command;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::stats::Stats;

// ── shared helpers ──

pub fn hostname() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn fmt_elapsed(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

pub fn human_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * KB;
    const GB: f64 = 1024.0 * MB;
    const TB: f64 = 1024.0 * GB;
    let value = n as f64;
    if value >= TB {
        format!("{:.2} TB", value / TB)
    } else if value >= GB {
        format!("{:.2} GB", value / GB)
    } else if value >= MB {
        format!("{:.2} MB", value / MB)
    } else if value >= KB {
        format!("{:.2} KB", value / KB)
    } else {
        format!("{} B", n)
    }
}

pub fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let head: String = s.chars().take(max_chars).collect();
    format!("{head}…")
}

// ── plain file output (tab-separated, no table borders) ──

/// Render plain-text snapshot for background file output: section headers + tab-separated columns.
pub fn render_file(
    path: &str,
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &Stats,
    top_n: usize,
) -> std::io::Result<()> {
    std::fs::write(
        path,
        plain_snapshot(interface, started_wall, started_at, stats, top_n),
    )
}

fn plain_snapshot(
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &Stats,
    top_n: usize,
) -> String {
    let host = hostname();
    let now = chrono::Local::now();
    let snapshot = stats.snapshot(top_n);
    let mut out = String::new();

    out.push_str(&format!(
        "delray\t{interface}\thost: {host}\tstarted: {}\tuptime: {}\t{}\n\n",
        started_wall.format("%Y-%m-%d %H:%M:%S"),
        fmt_elapsed(started_at.elapsed()),
        now.format("%Y-%m-%d %H:%M:%S")
    ));

    out.push_str("Interface Traffic\n");
    out.push_str(&format!("Inbound\t{}\n", human_bytes(snapshot.in_bytes)));
    out.push_str(&format!(
        "Outbound\t{}\n\n",
        human_bytes(snapshot.out_bytes)
    ));

    out.push_str(&format!("Top Processes ({top_n})\n"));
    out.push_str("Process\tPID\tRecv\tSent\tTotal\n");
    for process in snapshot.processes.iter() {
        let name = process.display_name();
        let pid = process
            .pid()
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".to_string());
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            name,
            pid,
            human_bytes(process.recv),
            human_bytes(process.sent),
            human_bytes(process.total())
        ));
    }

    out.push_str(&format!("\nTop Inbound IPs ({top_n})\n"));
    out.push_str("IP\tBytes\n");
    for entry in snapshot.inbound_ips.iter() {
        out.push_str(&format!("{}\t{}\n", entry.ip, human_bytes(entry.bytes)));
    }

    out.push_str(&format!("\nTop Outbound IPs ({top_n})\n"));
    out.push_str("IP\tBytes\n");
    for entry in snapshot.outbound_ips.iter() {
        out.push_str(&format!("{}\t{}\n", entry.ip, human_bytes(entry.bytes)));
    }

    out
}

// ── JSON output ──

#[derive(Serialize)]
struct JsonFrame<'a> {
    interface: &'a str,
    host: String,
    started_at: String,
    now: String,
    uptime_secs: u64,
    totals: JsonTotals,
    top_processes: Vec<JsonProc>,
    top_inbound_ips: Vec<JsonIp>,
    top_outbound_ips: Vec<JsonIp>,
}

#[derive(Serialize)]
struct JsonTotals {
    in_bytes: u64,
    out_bytes: u64,
}

#[derive(Serialize)]
struct JsonProc {
    pid: Option<u32>,
    name: Option<String>,
    recv: u64,
    sent: u64,
    total: u64,
}

#[derive(Serialize)]
struct JsonIp {
    ip: String,
    bytes: u64,
}

fn build_json_frame<'a>(
    interface: &'a str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &'a Stats,
    top_n: usize,
) -> JsonFrame<'a> {
    let host = hostname();
    let now = chrono::Local::now();

    let snapshot = stats.snapshot(top_n);
    let top_processes = snapshot
        .processes
        .iter()
        .map(|process| JsonProc {
            pid: process.pid(),
            name: process.name().map(str::to_string),
            recv: process.recv,
            sent: process.sent,
            total: process.total(),
        })
        .collect();

    let top_inbound_ips = snapshot
        .inbound_ips
        .iter()
        .map(|entry| JsonIp {
            ip: entry.ip.to_string(),
            bytes: entry.bytes,
        })
        .collect();

    let top_outbound_ips = snapshot
        .outbound_ips
        .iter()
        .map(|entry| JsonIp {
            ip: entry.ip.to_string(),
            bytes: entry.bytes,
        })
        .collect();

    JsonFrame {
        interface,
        host: host.clone(),
        started_at: started_wall.to_rfc3339(),
        now: now.to_rfc3339(),
        uptime_secs: started_at.elapsed().as_secs(),
        totals: JsonTotals {
            in_bytes: snapshot.in_bytes,
            out_bytes: snapshot.out_bytes,
        },
        top_processes,
        top_inbound_ips,
        top_outbound_ips,
    }
}

/// stdout JSONL: one compact line per frame, no clear-screen.
pub fn render_jsonl(
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &Stats,
    top_n: usize,
) {
    let frame = build_json_frame(interface, started_wall, started_at, stats, top_n);
    if let Ok(line) = serde_json::to_string(&frame) {
        println!("{line}");
    }
}

/// File JSON: indented object overwritten each refresh.
pub fn render_file_json(
    path: &str,
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &Stats,
    top_n: usize,
) -> std::io::Result<()> {
    let frame = build_json_frame(interface, started_wall, started_at, stats, top_n);
    let json = serde_json::to_string_pretty(&frame).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::capture::Flow;
    use crate::stats::Direction;

    #[test]
    fn plain_snapshot_renders_unattributed_traffic() {
        let mut stats = Stats::default();
        stats.record_flow(flow(Direction::Inbound, 40), None);
        stats.record_flow(flow(Direction::Outbound, 60), None);

        let rendered = plain_snapshot("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);

        assert!(rendered.contains("<unattributed traffic>\t-\t40 B\t60 B\t100 B"));
    }

    #[test]
    fn json_snapshot_renders_unattributed_traffic_as_null_identity() {
        let mut stats = Stats::default();
        stats.record_flow(flow(Direction::Inbound, 40), None);
        stats.record_flow(flow(Direction::Outbound, 60), None);

        let frame = build_json_frame("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);
        let value = serde_json::to_value(frame).unwrap();
        let process = &value["top_processes"][0];

        assert!(process["pid"].is_null());
        assert!(process["name"].is_null());
        assert_eq!(process["recv"], 40);
        assert_eq!(process["sent"], 60);
        assert_eq!(process["total"], 100);
    }

    fn flow(direction: Direction, bytes: u64) -> Flow {
        Flow {
            direction,
            peer: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bytes,
            local_socket: None,
        }
    }
}
