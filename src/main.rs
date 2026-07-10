mod capture;
mod proc_table;
mod report;
mod stats;

use std::env;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use capture::CaptureSource;
use stats::Direction;

const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const TOP_N: usize = 10;
const DEFAULT_PROC_REFRESH: u64 = 2;

fn main() -> ExitCode {
    let (interface, proc_refresh) = match parse_args() {
        Ok(v) => v,
        Err(()) => {
            capture::list_interfaces();
            return ExitCode::FAILURE;
        }
    };

    let started_wall = chrono::Local::now();
    let started_at = Instant::now();
    let mut source = match CaptureSource::open(&interface) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("打开网卡失败：{e}");
            return ExitCode::FAILURE;
        }
    };

    let proc_table = proc_table::spawn(Duration::from_secs(proc_refresh));

    let mut stats = stats::Stats::default();
    let mut next_refresh = Instant::now() + REFRESH_INTERVAL;

    loop {
        match source.next() {
            Ok(Some(flow)) => {
                match flow.direction {
                    Direction::Inbound => stats.add_in(flow.peer, flow.bytes),
                    Direction::Outbound => stats.add_out(flow.peer, flow.bytes),
                }
                if let Some((ip, port)) = flow.local_socket
                    && let Ok(table) = proc_table.read()
                    && let Some(pid) = table.lookup(ip, port)
                {
                    let name = table.names.get(&pid).cloned();
                    stats.add_proc(pid, name.as_deref(), flow.direction, flow.bytes);
                }
            }
            Ok(None) => {}
            Err(e) => eprintln!("抓包错误：{e}"),
        }

        if Instant::now() >= next_refresh {
            report::render(&interface, &started_wall, started_at, &stats, TOP_N);
            next_refresh = Instant::now() + REFRESH_INTERVAL;
        }
    }
}

/// 解析命令行：delray <网卡> [--proc-refresh <秒>]
fn parse_args() -> Result<(String, u64), ()> {
    let mut interface: Option<String> = None;
    let mut proc_refresh = DEFAULT_PROC_REFRESH;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--proc-refresh" {
            proc_refresh = args
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_PROC_REFRESH);
        } else if interface.is_none() {
            interface = Some(arg);
        }
    }
    interface.map(|i| (i, proc_refresh)).ok_or(())
}
