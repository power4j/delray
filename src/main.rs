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
const DEFAULT_TOP_N: u64 = 10;
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
            eprintln!("Failed to open interface: {e}");
            return ExitCode::FAILURE;
        }
    };

    let proc_table = proc_table::spawn(Duration::from_secs(cli.proc_refresh));

    if let Some(path) = &cli.output {
        eprintln!(
            "Background mode: refreshing stats to {path} every {}s",
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
            Err(e) => eprintln!("Capture error: {e}"),
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
                        cli.top_n as usize,
                    ) {
                        eprintln!("Failed to write output file: {e}");
                    }
                }
                None => {
                    report::render_terminal(
                        &interface,
                        &started_wall,
                        started_at,
                        &stats,
                        cli.top_n as usize,
                    );
                }
            }
            next_refresh = Instant::now() + REFRESH_INTERVAL;
        }
    }
}

/// CLI arguments.
#[derive(Parser)]
#[command(
    name = "delray",
    version,
    about = "Network traffic analyzer for resource-constrained Linux servers"
)]
struct Cli {
    /// Network interface to capture on (omit to list available interfaces)
    interface: Option<String>,
    /// /proc inode-table rebuild interval in seconds (must be > 0)
    #[arg(long, default_value_t = DEFAULT_PROC_REFRESH, value_parser = positive_u64)]
    proc_refresh: u64,
    /// Output file for background mode (omit for foreground terminal display)
    #[arg(long)]
    output: Option<String>,
    /// Output format: plain (default) or json
    #[arg(long = "format", short = 'f', default_value = "plain", value_parser = ["plain", "json"])]
    format: String,
    /// Number of entries per top-N list (default: 10, min: 1)
    #[arg(long = "top-n", short = 'n', default_value_t = DEFAULT_TOP_N, value_parser = clap::value_parser!(u64).range(1..))]
    top_n: u64,
}

fn positive_u64(s: &str) -> Result<u64, String> {
    match s.parse::<u64>() {
        Ok(v) if v > 0 => Ok(v),
        Ok(_) => Err(String::from("value must be greater than 0")),
        Err(_) => Err(String::from("value must be a positive integer")),
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

    #[test]
    fn proc_refresh_non_numeric_rejected() {
        let result = Cli::try_parse_from(["delray", "eth0", "--proc-refresh", "abc"]);
        assert!(result.is_err());
    }

    #[test]
    fn proc_refresh_negative_rejected() {
        let result = Cli::try_parse_from(["delray", "eth0", "--proc-refresh", "-5"]);
        assert!(result.is_err());
    }
}
