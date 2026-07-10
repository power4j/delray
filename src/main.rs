mod capture;
mod proc_table;
mod report;
mod stats;

use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;

use capture::CaptureSource;
use stats::Direction;

const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const TOP_N: usize = 10;
const DEFAULT_PROC_REFRESH: u64 = 2;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let Some(interface) = cli.interface else {
        capture::list_interfaces();
        return ExitCode::FAILURE;
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

    let proc_table = proc_table::spawn(Duration::from_secs(cli.proc_refresh));

    if let Some(path) = &cli.output {
        eprintln!(
            "后台运行：每 {} 秒刷新统计到 {path}",
            REFRESH_INTERVAL.as_secs()
        );
    }

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
            match &cli.output {
                Some(path) => {
                    if let Err(e) = report::render_file(
                        path,
                        &interface,
                        &started_wall,
                        started_at,
                        &stats,
                        TOP_N,
                    ) {
                        eprintln!("写入输出文件失败：{e}");
                    }
                }
                None => {
                    report::render_terminal(&interface, &started_wall, started_at, &stats, TOP_N);
                }
            }
            next_refresh = Instant::now() + REFRESH_INTERVAL;
        }
    }
}

/// 命令行参数。
#[derive(Parser)]
#[command(
    name = "delray",
    version,
    about = "面向资源受限 Linux 服务器的网络流量分析工具"
)]
struct Cli {
    /// 监听网卡名
    interface: Option<String>,
    /// 进程 inode 表重建间隔（秒）
    #[arg(long, default_value_t = DEFAULT_PROC_REFRESH, value_parser = positive_u64)]
    proc_refresh: u64,
    /// 后台模式输出文件（不指定则前台输出终端）
    #[arg(long)]
    output: Option<String>,
}

/// 校验 `--proc-refresh` 为大于 0 的整数。
fn positive_u64(s: &str) -> Result<u64, String> {
    match s.parse::<u64>() {
        Ok(v) if v > 0 => Ok(v),
        Ok(_) => Err(String::from("--proc-refresh 必须大于 0")),
        Err(_) => Err(String::from("--proc-refresh 需要正整数")),
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn parses_all_args() {
        let cli = Cli::try_parse_from([
            "delray",
            "eth0",
            "--proc-refresh",
            "5",
            "--output",
            "out.txt",
        ])
        .unwrap();
        assert_eq!(cli.interface.as_deref(), Some("eth0"));
        assert_eq!(cli.proc_refresh, 5);
        assert_eq!(cli.output.as_deref(), Some("out.txt"));
    }

    #[test]
    fn proc_refresh_defaults_to_two() {
        let cli = Cli::try_parse_from(["delray", "eth0"]).unwrap();
        assert_eq!(cli.proc_refresh, DEFAULT_PROC_REFRESH);
        assert!(cli.output.is_none());
    }

    #[test]
    fn proc_refresh_zero_rejected() {
        let result = Cli::try_parse_from(["delray", "eth0", "--proc-refresh", "0"]);
        assert!(result.is_err());
    }

    #[test]
    fn interface_optional() {
        let cli = Cli::try_parse_from(["delray"]).unwrap();
        assert!(cli.interface.is_none());
    }
}
