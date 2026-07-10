use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::stats::{ProcTraffic, Stats};

/// 生成纯文本统计快照（无 ANSI 控制字符），前台打印与后台写文件共用。
pub fn snapshot(
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &Stats,
    top_n: usize,
) -> String {
    let host = hostname();
    let now = chrono::Local::now();
    let mut out = String::new();
    out.push_str(&format!("delray  接口 {interface}  主机 {host}\n"));
    out.push_str(&format!(
        "开始 {}  当前 {}  运行时长 {}\n\n",
        started_wall.format("%Y-%m-%d %H:%M:%S"),
        now.format("%Y-%m-%d %H:%M:%S"),
        fmt_elapsed(started_at.elapsed())
    ));
    out.push_str(&format!(
        "网卡总流量  入站 {}  出站 {}\n\n",
        human_bytes(stats.in_bytes),
        human_bytes(stats.out_bytes)
    ));
    out.push_str(&format!("进程流量（top {top_n}）\n"));
    out.push_str(&fmt_proc_list(&stats.top_procs(top_n), stats));
    out.push_str(&format!("\n入站 IP（top {top_n}）\n"));
    out.push_str(&fmt_ip_list(&stats.top_in(top_n)));
    out.push_str(&format!("\n出站 IP（top {top_n}）\n"));
    out.push_str(&fmt_ip_list(&stats.top_out(top_n)));
    out
}

/// 前台：清屏后打印快照到终端。
pub fn render_terminal(
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &Stats,
    top_n: usize,
) {
    print!("\x1b[2J\x1b[H");
    print!(
        "{}",
        snapshot(interface, started_wall, started_at, stats, top_n)
    );
}

/// 后台：将快照覆盖写入文件（只留最后一次刷新结果）。
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
        snapshot(interface, started_wall, started_at, stats, top_n),
    )
}

fn fmt_proc_list(list: &[(u32, ProcTraffic)], stats: &Stats) -> String {
    if list.is_empty() {
        return "  （暂无数据）\n".to_string();
    }
    let mut out = String::new();
    for (pid, t) in list {
        let raw = stats.proc_name(*pid).unwrap_or("?");
        let name = truncate(raw, 42);
        out.push_str(&format!(
            "  {name:<44} pid {pid:<7} 收 {} 发 {}\n",
            human_bytes(t.recv),
            human_bytes(t.sent)
        ));
    }
    out
}

/// 超过 max_chars 个字符时截断并加省略号。
fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let head: String = s.chars().take(max_chars).collect();
    format!("{head}…")
}

fn fmt_ip_list(list: &[(IpAddr, u64)]) -> String {
    if list.is_empty() {
        return "  （暂无数据）\n".to_string();
    }
    let mut out = String::new();
    for (ip, bytes) in list {
        out.push_str(&format!("  {ip:<39} {}\n", human_bytes(*bytes)));
    }
    out
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
