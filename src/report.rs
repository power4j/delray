use std::process::Command;
use std::time::{Duration, Instant};

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Table};

use crate::stats::Stats;

/// Build a comfy-table with our default style preset.
fn table_base(styled: bool) -> Table {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);
    if styled {
        t.enforce_styling();
    } else {
        t.force_no_tty();
    }
    t
}

fn hdr(text: &str) -> Cell {
    Cell::new(text)
        .fg(Color::Cyan)
        .add_attribute(Attribute::Bold)
}

fn val(text: impl std::fmt::Display) -> Cell {
    Cell::new(text)
}

fn num(text: impl std::fmt::Display) -> Cell {
    Cell::new(text).set_alignment(CellAlignment::Right)
}

/// Apply terminal width to a styled table; no-op for narrow terminals or if TTY width unavailable.
fn set_terminal_width(t: &mut Table) {
    if let Some((w, _)) = terminal_size::terminal_size()
        && w.0 > 40
    {
        t.set_width(w.0);
    }
}

/// Apply table width: terminal-width for styled, fixed 120 for file output.
fn apply_width(t: &mut Table, styled: bool) {
    if styled {
        set_terminal_width(t);
    } else {
        t.set_width(120);
    }
}

/// Render plain-text snapshot — shared by terminal and file paths.
fn render_plain(
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &Stats,
    top_n: usize,
    styled: bool,
) -> String {
    let host = hostname();
    let now = chrono::Local::now();
    let mut out = String::new();

    // Title + info header
    if styled {
        out.push_str(&format!(
            "\x1b[1;36mdelray\x1b[0m  interface {interface}  host {host}\n"
        ));
    } else {
        out.push_str(&format!("delray  interface {interface}  host {host}\n"));
    }
    out.push_str(&format!(
        "Started {}  Now {}  Uptime {}\n",
        started_wall.format("%Y-%m-%d %H:%M:%S"),
        now.format("%Y-%m-%d %H:%M:%S"),
        fmt_elapsed(started_at.elapsed())
    ));

    // ---- Interface Traffic ----
    {
        let mut t = table_base(styled);
        apply_width(&mut t, styled);
        t.set_header(vec![hdr("Direction"), hdr("Bytes")]);
        t.add_row(vec![val("Inbound"), num(human_bytes(stats.in_bytes))]);
        t.add_row(vec![val("Outbound"), num(human_bytes(stats.out_bytes))]);
        out.push_str(&format!("\nInterface Traffic\n{}", t));
    }

    // ---- Top Processes ----
    {
        let procs = stats.top_procs(top_n);
        let mut t = table_base(styled);
        apply_width(&mut t, styled);
        t.set_header(vec![hdr("Process"), hdr("PID"), hdr("Recv"), hdr("Sent")]);
        if procs.is_empty() {
            out.push_str(&format!("\nTop Processes ({top_n})\n  (no data)\n"));
        } else {
            for (pid, traffic) in &procs {
                let name = stats.proc_name(*pid).unwrap_or("?");
                t.add_row(vec![
                    val(truncate(name, 60)),
                    val(pid),
                    num(human_bytes(traffic.recv)),
                    num(human_bytes(traffic.sent)),
                ]);
            }
            out.push_str(&format!("\nTop Processes ({top_n})\n{}", t));
        }
    }

    // ---- Top Inbound IPs ----
    {
        let ips = stats.top_in(top_n);
        let mut t = table_base(styled);
        apply_width(&mut t, styled);
        t.set_header(vec![hdr("IP"), hdr("Bytes")]);
        if ips.is_empty() {
            out.push_str(&format!("\nTop Inbound IPs ({top_n})\n  (no data)\n"));
        } else {
            for (ip, bytes) in &ips {
                t.add_row(vec![val(ip), num(human_bytes(*bytes))]);
            }
            out.push_str(&format!("\nTop Inbound IPs ({top_n})\n{}", t));
        }
    }

    // ---- Top Outbound IPs ----
    {
        let ips = stats.top_out(top_n);
        let mut t = table_base(styled);
        apply_width(&mut t, styled);
        t.set_header(vec![hdr("IP"), hdr("Bytes")]);
        if ips.is_empty() {
            out.push_str(&format!("\nTop Outbound IPs ({top_n})\n  (no data)\n"));
        } else {
            for (ip, bytes) in &ips {
                t.add_row(vec![val(ip), num(human_bytes(*bytes))]);
            }
            out.push_str(&format!("\nTop Outbound IPs ({top_n})\n{}", t));
        }
    }

    out
}

/// Foreground: clear screen then print styled snapshot.
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
        render_plain(interface, started_wall, started_at, stats, top_n, true)
    );
}

/// Background: write last snapshot to file without ANSI styling.
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
        render_plain(interface, started_wall, started_at, stats, top_n, false),
    )
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

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let head: String = s.chars().take(max_chars).collect();
    format!("{head}…")
}

// ── JSON rendering (one frame = cumulative snapshot) ──

use serde::Serialize;

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
    pid: u32,
    name: Option<String>,
    recv: u64,
    sent: u64,
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

    let top_processes = stats
        .top_procs(top_n)
        .iter()
        .map(|(pid, traffic)| JsonProc {
            pid: *pid,
            name: stats.proc_name(*pid).map(|s| s.to_string()),
            recv: traffic.recv,
            sent: traffic.sent,
        })
        .collect();

    let top_inbound_ips = stats
        .top_in(top_n)
        .iter()
        .map(|(ip, bytes)| JsonIp {
            ip: ip.to_string(),
            bytes: *bytes,
        })
        .collect();

    let top_outbound_ips = stats
        .top_out(top_n)
        .iter()
        .map(|(ip, bytes)| JsonIp {
            ip: ip.to_string(),
            bytes: *bytes,
        })
        .collect();

    JsonFrame {
        interface,
        host: host.clone(),
        started_at: started_wall.to_rfc3339(),
        now: now.to_rfc3339(),
        uptime_secs: started_at.elapsed().as_secs(),
        totals: JsonTotals {
            in_bytes: stats.in_bytes,
            out_bytes: stats.out_bytes,
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
    // Compact JSONL — no pretty-print, no clear-screen (it's a data stream).
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
