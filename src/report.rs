use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::proc_table::ProcTable;
use crate::stats::{ProcTraffic, Stats};

/// 清屏并输出当前统计快照。
pub fn render(
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &Stats,
    proc_table: &ProcTable,
    top_n: usize,
) {
    print!("\x1b[2J\x1b[H");

    let host = hostname();
    let now = chrono::Local::now();
    println!("delray  接口 {interface}  主机 {host}");
    println!(
        "开始 {}  当前 {}  运行时长 {}",
        started_wall.format("%Y-%m-%d %H:%M:%S"),
        now.format("%Y-%m-%d %H:%M:%S"),
        fmt_elapsed(started_at.elapsed())
    );
    println!();
    println!(
        "网卡总流量  入站 {}  出站 {}",
        human_bytes(stats.in_bytes),
        human_bytes(stats.out_bytes)
    );
    println!();
    println!("进程流量（top {top_n}）");
    print_proc_list(&stats.top_procs(top_n), proc_table);
    println!();
    println!("入站 IP（top {top_n}）");
    print_ip_list(&stats.top_in(top_n));
    println!();
    println!("出站 IP（top {top_n}）");
    print_ip_list(&stats.top_out(top_n));
}

fn print_proc_list(list: &[(u32, ProcTraffic)], proc_table: &ProcTable) {
    if list.is_empty() {
        println!("  （暂无数据）");
        return;
    }
    for (pid, t) in list {
        let name = proc_table.names.get(pid).map(|s| s.as_str()).unwrap_or("?");
        println!(
            "  {name:<16} pid {pid:<7} 收 {} 发 {}",
            human_bytes(t.recv),
            human_bytes(t.sent)
        );
    }
}

fn print_ip_list(list: &[(IpAddr, u64)]) {
    if list.is_empty() {
        println!("  （暂无数据）");
        return;
    }
    for (ip, bytes) in list {
        println!("  {ip:<39} {}", human_bytes(*bytes));
    }
}

fn fmt_elapsed(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

fn human_bytes(n: u64) -> String {
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

fn hostname() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
