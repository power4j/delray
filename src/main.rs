mod capture;
mod pipeline;
mod proc_table;
mod report;
mod stats;
mod tui;

use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;

use capture::CaptureSource;
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

    let top_n = cli.top_n as usize;
    let is_json = cli.format == "json";

    match &cli.output {
        Some(path) => {
            // Background file mode: write snapshot each refresh tick.
            eprintln!(
                "Background mode: refreshing stats to {path} every {}s",
                REFRESH_INTERVAL.as_secs()
            );
            background_loop(
                &mut source,
                &proc_table,
                path,
                &interface,
                &started_wall,
                started_at,
                top_n,
                is_json,
            );
        }
        None => {
            // Foreground mode.
            if is_json {
                // JSON streams to stdout as a data source (no TUI).
                json_stdout_loop(
                    &mut source,
                    &proc_table,
                    &interface,
                    &started_wall,
                    started_at,
                    top_n,
                );
            } else {
                // Plain foreground = interactive TUI.
                let pipeline =
                    match pipeline::TrafficPipeline::spawn(source, proc_table.clone(), top_n) {
                        Ok(pipeline) => pipeline,
                        Err(e) => {
                            eprintln!("Failed to start traffic pipeline: {e}");
                            return ExitCode::FAILURE;
                        }
                    };
                if let Err(e) = tui::run(&interface, &pipeline) {
                    eprintln!("TUI error: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }

    ExitCode::SUCCESS
}

/// Background file loop: capture continuously, write snapshot every refresh interval.
#[allow(clippy::too_many_arguments)]
fn background_loop(
    source: &mut CaptureSource,
    proc_table: &proc_table::SharedProcTable,
    path: &str,
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    top_n: usize,
    is_json: bool,
) {
    let mut stats = stats::Stats::default();
    let mut next_refresh = Instant::now() + REFRESH_INTERVAL;
    loop {
        drain(source, proc_table, &mut stats);
        if Instant::now() >= next_refresh {
            let res = if is_json {
                report::render_file_json(path, interface, started_wall, started_at, &stats, top_n)
            } else {
                report::render_file(path, interface, started_wall, started_at, &stats, top_n)
            };
            if let Err(e) = res {
                eprintln!("Failed to write output file: {e}");
            }
            next_refresh = Instant::now() + REFRESH_INTERVAL;
        }
    }
}

/// JSON stdout loop: stream one compact JSON line per refresh interval.
#[allow(clippy::too_many_arguments)]
fn json_stdout_loop(
    source: &mut CaptureSource,
    proc_table: &proc_table::SharedProcTable,
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    top_n: usize,
) {
    let mut stats = stats::Stats::default();
    let mut next_refresh = Instant::now() + REFRESH_INTERVAL;
    loop {
        drain(source, proc_table, &mut stats);
        if Instant::now() >= next_refresh {
            report::render_jsonl(interface, started_wall, started_at, &stats, top_n);
            next_refresh = Instant::now() + REFRESH_INTERVAL;
        }
    }
}

/// Drain available packets from the capture source into stats.
fn drain(
    source: &mut CaptureSource,
    proc_table: &proc_table::SharedProcTable,
    stats: &mut stats::Stats,
) {
    loop {
        match source.next() {
            Ok(Some(flow)) => {
                let process = flow.local_socket.and_then(|socket| {
                    let table = proc_table.read().ok()?;
                    let process = table.lookup(socket.ip, socket.port, socket.protocol)?;
                    Some(stats::ObservedProcess {
                        pid: process.pid,
                        name: process.name.clone(),
                    })
                });
                stats.record_flow(flow, process);
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("Capture error: {e}");
                break;
            }
        }
    }
}

/// CLI arguments.
#[derive(Parser)]
#[command(name = "delray", version, about = "Network traffic analyzer")]
struct Cli {
    /// Network interface to capture on (omit to list available interfaces)
    interface: Option<String>,
    /// Process table refresh interval in seconds (must be > 0)
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
