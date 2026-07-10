mod capture;
mod report;
mod stats;

use std::env;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use capture::CaptureSource;

const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const TOP_N: usize = 10;

fn main() -> ExitCode {
    let interface = match env::args().nth(1) {
        Some(name) => name,
        None => {
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

    let mut stats = stats::Stats::default();
    let mut next_refresh = Instant::now() + REFRESH_INTERVAL;

    loop {
        match source.next() {
            Ok(Some(flow)) => match flow.direction {
                capture::Direction::Inbound => stats.add_in(flow.peer, flow.bytes),
                capture::Direction::Outbound => stats.add_out(flow.peer, flow.bytes),
            },
            Ok(None) => {}
            Err(e) => eprintln!("抓包错误：{e}"),
        }

        if Instant::now() >= next_refresh {
            report::render(&interface, &started_wall, started_at, &stats, TOP_N);
            next_refresh = Instant::now() + REFRESH_INTERVAL;
        }
    }
}
