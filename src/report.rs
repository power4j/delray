use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::stats::{ProcTraffic, Stats};

/// 清屏并输出当前统计快照。
pub fn render(
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &Stats,
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
    print_proc_list(&stats.top_procs(top_n), stats);
    println!();
    println!("入站 IP（top {top_n}）");
    print_ip_list(&stats.top_in(top_n));
    println!();
    println!("出站 IP（top {top_n}）");
    print_ip_list(&stats.top_out(top_n));
}

fn print_proc_list(list: &[(u32, ProcTraffic)], stats: &Stats) {
    if list.is_empty() {
        println!("  （暂无数据）");
        return;
    }
    for (pid, t) in list {
        let raw = stats.proc_name(*pid).unwrap_or("?");
        let name = truncate(raw, 42);
        println!(
            "  {name:<44} pid {pid:<7} 收 {} 发 {}",
            human_bytes(t.recv),
            human_bytes(t.sent)
        );
    }
}

/// 超过 max_chars 个字符时截断并加省略号。
fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let head: String = s.chars().take(max_chars).collect();
    format!("{head}…")
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
