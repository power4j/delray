use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::capture::{CaptureSource, Flow};
use crate::proc_table::SharedProcTable;
use crate::stats::{ObservedProcess, Stats, TrafficSnapshot};

const STOP_CHECK_INTERVAL: Duration = Duration::from_millis(100);
const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(5);
const FLOW_CHANNEL_CAPACITY: usize = 8192;
const SNAPSHOT_CHANNEL_CAPACITY: usize = 2;

type ThreadTask = Box<dyn FnOnce() + Send + 'static>;

fn spawn_named_thread(name: &'static str, task: ThreadTask) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new().name(name.to_string()).spawn(task)
}

#[derive(Clone, Debug)]
pub enum PipelineError {
    Capture(String),
    WorkerStopped(&'static str),
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capture(message) => write!(f, "capture failed: {message}"),
            Self::WorkerStopped(worker) => {
                write!(f, "traffic pipeline worker stopped unexpectedly: {worker}")
            }
        }
    }
}

impl std::error::Error for PipelineError {}

fn capture_loop<N, E>(
    mut next_flow: N,
    flow_tx: SyncSender<Flow>,
    stop: Arc<AtomicBool>,
    failure: Arc<OnceLock<PipelineError>>,
) where
    N: FnMut() -> Result<Option<Flow>, E>,
    E: fmt::Display,
{
    while !stop.load(Ordering::Acquire) {
        match next_flow() {
            Ok(Some(flow)) => {
                if flow_tx.send(flow).is_err() {
                    return;
                }
            }
            Ok(None) => {}
            Err(error) => {
                let _ = failure.set(PipelineError::Capture(error.to_string()));
                return;
            }
        }
    }
}

fn aggregate_loop(
    flow_rx: Receiver<Flow>,
    snapshot_tx: SyncSender<Arc<TrafficSnapshot>>,
    proc_table: SharedProcTable,
    top_n: usize,
    snapshot_interval: Duration,
    stop: Arc<AtomicBool>,
    failure: Arc<OnceLock<PipelineError>>,
) {
    let mut stats = Stats::default();
    let mut next_snapshot = Instant::now() + snapshot_interval;

    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }

        let now = Instant::now();
        if now >= next_snapshot {
            let snapshot = Arc::new(stats.snapshot(top_n));
            match snapshot_tx.try_send(snapshot) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => {
                    if !stop.load(Ordering::Acquire) {
                        let _ = failure.set(PipelineError::WorkerStopped("snapshot consumer"));
                    }
                    return;
                }
            }
            next_snapshot = Instant::now() + snapshot_interval;
            continue;
        }

        let wait = next_snapshot
            .saturating_duration_since(now)
            .min(STOP_CHECK_INTERVAL);
        match flow_rx.recv_timeout(wait) {
            Ok(flow) => {
                let process = resolve_process(&flow, &proc_table);
                stats.record_flow(flow, process);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                if !stop.load(Ordering::Acquire) && failure.get().is_none() {
                    let _ = failure.set(PipelineError::WorkerStopped("capture"));
                }
                return;
            }
        }
    }
}

fn resolve_process(flow: &Flow, proc_table: &SharedProcTable) -> Option<ObservedProcess> {
    let socket = flow.local_socket?;
    let table = proc_table.read().ok()?;
    let process = table.lookup(socket.ip, socket.port, socket.protocol)?;
    Some(ObservedProcess {
        pid: process.pid,
        name: process.name.clone(),
    })
}

pub struct TrafficPipeline {
    snapshot_rx: Receiver<Arc<TrafficSnapshot>>,
    failure: Arc<OnceLock<PipelineError>>,
    stop: Arc<AtomicBool>,
}

impl TrafficPipeline {
    pub fn spawn(
        mut source: CaptureSource,
        proc_table: SharedProcTable,
        top_n: usize,
    ) -> io::Result<Self> {
        Self::spawn_with_next(move || source.next(), proc_table, top_n)
    }

    fn spawn_with_next<N, E>(
        next_flow: N,
        proc_table: SharedProcTable,
        top_n: usize,
    ) -> io::Result<Self>
    where
        N: FnMut() -> Result<Option<Flow>, E> + Send + 'static,
        E: fmt::Display + Send + 'static,
    {
        Self::spawn_with_next_using(next_flow, proc_table, top_n, spawn_named_thread)
    }

    fn spawn_with_next_using<N, E, S>(
        next_flow: N,
        proc_table: SharedProcTable,
        top_n: usize,
        mut spawn_thread: S,
    ) -> io::Result<Self>
    where
        N: FnMut() -> Result<Option<Flow>, E> + Send + 'static,
        E: fmt::Display + Send + 'static,
        S: FnMut(&'static str, ThreadTask) -> io::Result<thread::JoinHandle<()>>,
    {
        let (flow_tx, flow_rx) = std::sync::mpsc::sync_channel(FLOW_CHANNEL_CAPACITY);
        let (snapshot_tx, snapshot_rx) = std::sync::mpsc::sync_channel(SNAPSHOT_CHANNEL_CAPACITY);
        snapshot_tx
            .try_send(Arc::new(TrafficSnapshot::default()))
            .expect("new snapshot channel has capacity");

        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let aggregate_stop = stop.clone();
        let aggregate_failure = failure.clone();
        let _aggregate_thread = spawn_thread(
            "delray-aggregate",
            Box::new(move || {
                aggregate_loop(
                    flow_rx,
                    snapshot_tx,
                    proc_table,
                    top_n,
                    SNAPSHOT_INTERVAL,
                    aggregate_stop,
                    aggregate_failure,
                );
            }),
        )?;

        let capture_stop = stop.clone();
        let capture_failure = failure.clone();
        if let Err(error) = spawn_thread(
            "delray-capture",
            Box::new(move || capture_loop(next_flow, flow_tx, capture_stop, capture_failure)),
        ) {
            stop.store(true, Ordering::Release);
            return Err(error);
        }

        Ok(Self {
            snapshot_rx,
            failure,
            stop,
        })
    }

    pub fn try_latest(&self) -> Result<Option<Arc<TrafficSnapshot>>, PipelineError> {
        let mut latest = None;
        loop {
            match self.snapshot_rx.try_recv() {
                Ok(snapshot) => latest = Some(snapshot),
                Err(TryRecvError::Empty) => {
                    return match self.failure.get() {
                        Some(failure) => Err(failure.clone()),
                        None => Ok(latest),
                    };
                }
                Err(TryRecvError::Disconnected) => {
                    return Err(self
                        .failure
                        .get()
                        .cloned()
                        .unwrap_or(PipelineError::WorkerStopped("aggregate")));
                }
            }
        }
    }

    #[cfg(test)]
    fn from_snapshot_receiver(snapshot_rx: Receiver<Arc<TrafficSnapshot>>) -> Self {
        Self {
            snapshot_rx,
            failure: Arc::new(OnceLock::new()),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(test)]
    fn from_parts(
        snapshot_rx: Receiver<Arc<TrafficSnapshot>>,
        failure: Arc<OnceLock<PipelineError>>,
    ) -> Self {
        Self {
            snapshot_rx,
            failure,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Drop for TrafficPipeline {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::OnceLock;
    use std::sync::RwLock;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::sync_channel;
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::capture::Flow;
    use crate::proc_table::ProcTable;
    use crate::stats::{Direction, Stats, TrafficSnapshot};

    #[test]
    fn try_latest_returns_newest_queued_snapshot() {
        let (tx, rx) = sync_channel(2);
        tx.send(snapshot(1)).unwrap();
        tx.send(snapshot(2)).unwrap();
        let pipeline = TrafficPipeline::from_snapshot_receiver(rx);

        let latest = pipeline.try_latest().unwrap().unwrap();

        assert_eq!(latest.in_bytes, 2);
        assert!(pipeline.try_latest().unwrap().is_none());
    }

    #[test]
    fn disconnected_snapshot_worker_takes_priority_over_queued_snapshot() {
        let (tx, rx) = sync_channel(2);
        tx.send(snapshot(3)).unwrap();
        drop(tx);
        let pipeline = TrafficPipeline::from_snapshot_receiver(rx);

        let error = match pipeline.try_latest() {
            Err(error) => error,
            Ok(_) => panic!("worker disconnect should take priority"),
        };

        assert!(matches!(error, PipelineError::WorkerStopped("aggregate")));
    }

    #[test]
    fn terminal_failure_takes_priority_over_queued_snapshot() {
        let (tx, rx) = sync_channel(2);
        tx.send(snapshot(7)).unwrap();
        let failure = Arc::new(OnceLock::new());
        failure
            .set(PipelineError::Capture("pcap failed".to_string()))
            .unwrap();
        let pipeline = TrafficPipeline::from_parts(rx, failure);

        let error = match pipeline.try_latest() {
            Err(error) => error,
            Ok(_) => panic!("terminal failure should take priority"),
        };

        assert!(matches!(error, PipelineError::Capture(message) if message == "pcap failed"));
    }

    #[test]
    fn capture_loop_continues_after_no_flow() {
        let (tx, rx) = sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_from_source = stop.clone();
        let failure = Arc::new(OnceLock::new());
        let mut calls = 0;

        capture_loop(
            || -> anyhow::Result<Option<Flow>> {
                calls += 1;
                match calls {
                    1 => Ok(None),
                    2 => Ok(Some(flow(99))),
                    _ => {
                        stop_from_source.store(true, Ordering::Release);
                        Ok(None)
                    }
                }
            },
            tx,
            stop,
            failure,
        );

        assert_eq!(calls, 3);
        assert_eq!(rx.recv().unwrap().bytes, 99);
    }

    #[test]
    fn aggregate_loop_publishes_snapshot_without_flow() {
        let (flow_tx, flow_rx) = sync_channel(1);
        let (snapshot_tx, snapshot_rx) = sync_channel(2);
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let worker_stop = stop.clone();
        let worker_failure = failure.clone();
        let worker = thread::spawn(move || {
            aggregate_loop(
                flow_rx,
                snapshot_tx,
                proc_table,
                10,
                Duration::from_millis(10),
                worker_stop,
                worker_failure,
            );
        });

        let snapshot = snapshot_rx
            .recv_timeout(Duration::from_millis(100))
            .unwrap();

        assert_eq!(snapshot.in_bytes, 0);
        stop.store(true, Ordering::Release);
        drop(flow_tx);
        worker.join().unwrap();
    }

    #[test]
    fn aggregate_loop_does_not_block_when_snapshot_channel_is_full() {
        let (flow_tx, flow_rx) = sync_channel(1);
        let (snapshot_tx, snapshot_rx) = sync_channel(1);
        snapshot_tx
            .send(Arc::new(TrafficSnapshot::default()))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let worker_stop = stop.clone();
        let worker_failure = failure.clone();
        let (done_tx, done_rx) = sync_channel(1);
        thread::spawn(move || {
            aggregate_loop(
                flow_rx,
                snapshot_tx,
                proc_table,
                10,
                Duration::from_millis(10),
                worker_stop,
                worker_failure,
            );
            done_tx.send(()).unwrap();
        });

        thread::sleep(Duration::from_millis(30));
        stop.store(true, Ordering::Release);
        drop(flow_tx);

        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_ok());
        drop(snapshot_rx);
    }

    #[test]
    fn aggregate_loop_resolves_process_before_snapshot() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let mut table = ProcTable::default();
        table.insert_for_test(
            local_ip,
            443,
            crate::capture::TransportProtocol::Tcp,
            7,
            Arc::from("curl"),
        );
        let proc_table = Arc::new(RwLock::new(table));
        let (flow_tx, flow_rx) = sync_channel(1);
        let (snapshot_tx, snapshot_rx) = sync_channel(2);
        flow_tx
            .send(Flow {
                direction: Direction::Outbound,
                peer: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
                bytes: 120,
                local_socket: Some(crate::capture::LocalSocket {
                    ip: local_ip,
                    port: 443,
                    protocol: crate::capture::TransportProtocol::Tcp,
                }),
            })
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let worker_stop = stop.clone();
        let worker_failure = failure.clone();
        let worker = thread::spawn(move || {
            aggregate_loop(
                flow_rx,
                snapshot_tx,
                proc_table,
                10,
                Duration::from_millis(10),
                worker_stop,
                worker_failure,
            );
        });

        let snapshot = snapshot_rx
            .recv_timeout(Duration::from_millis(100))
            .unwrap();

        assert_eq!(snapshot.processes.len(), 1);
        assert_eq!(snapshot.processes[0].pid(), Some(7));
        assert_eq!(snapshot.processes[0].name(), Some("curl"));
        assert_eq!(snapshot.processes[0].sent, 120);
        stop.store(true, Ordering::Release);
        drop(flow_tx);
        worker.join().unwrap();
    }

    #[test]
    fn missing_and_ambiguous_candidates_are_unattributed() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let mut table = ProcTable::default();
        table.insert_for_test(
            local_ip,
            443,
            crate::capture::TransportProtocol::Tcp,
            7,
            Arc::from("server-a"),
        );
        table.insert_for_test(
            local_ip,
            443,
            crate::capture::TransportProtocol::Tcp,
            8,
            Arc::from("server-b"),
        );
        let proc_table = Arc::new(RwLock::new(table));
        let mut stats = Stats::default();

        for flow in [
            socket_flow(local_ip, 443, 40),
            socket_flow(local_ip, 80, 60),
        ] {
            let process = resolve_process(&flow, &proc_table);
            stats.record_flow(flow, process);
        }

        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.processes.len(), 1);
        assert!(snapshot.processes[0].is_unattributed());
        assert_eq!(snapshot.processes[0].sent, 100);
    }

    #[test]
    fn recovered_resolution_does_not_reassign_historical_traffic() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let mut stats = Stats::default();
        let unresolved = socket_flow(local_ip, 443, 40);
        let process = resolve_process(&unresolved, &proc_table);
        stats.record_flow(unresolved, process);

        proc_table.write().unwrap().insert_for_test(
            local_ip,
            443,
            crate::capture::TransportProtocol::Tcp,
            7,
            Arc::from("curl"),
        );
        let resolved = socket_flow(local_ip, 443, 60);
        let process = resolve_process(&resolved, &proc_table);
        stats.record_flow(resolved, process);

        let snapshot = stats.snapshot(10);
        let unattributed = snapshot
            .processes
            .iter()
            .find(|process| process.is_unattributed())
            .unwrap();
        let attributed = snapshot
            .processes
            .iter()
            .find(|process| process.pid() == Some(7))
            .unwrap();
        assert_eq!(unattributed.sent, 40);
        assert_eq!(attributed.sent, 60);
    }

    #[test]
    fn spawn_makes_initial_snapshot_available_immediately() {
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let pipeline = TrafficPipeline::spawn_with_next(
            || -> anyhow::Result<Option<Flow>> {
                thread::sleep(Duration::from_millis(10));
                Ok(None)
            },
            proc_table,
            10,
        )
        .unwrap();

        let snapshot = pipeline.try_latest().unwrap().unwrap();

        assert_eq!(snapshot.in_bytes, 0);
        assert_eq!(snapshot.out_bytes, 0);
    }

    #[test]
    fn capture_spawn_failure_stops_started_aggregate_worker() {
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let (aggregate_stopped_tx, aggregate_stopped_rx) = sync_channel(1);

        let result = TrafficPipeline::spawn_with_next_using(
            || Ok::<_, io::Error>(None),
            proc_table,
            10,
            move |name, task| {
                if name == "delray-capture" {
                    return Err(io::Error::other("capture thread refused"));
                }

                let aggregate_stopped_tx = aggregate_stopped_tx.clone();
                thread::Builder::new()
                    .name(name.to_string())
                    .spawn(move || {
                        task();
                        aggregate_stopped_tx.send(()).unwrap();
                    })
            },
        );

        let error = result.err().expect("capture thread spawn should fail");
        assert_eq!(error.to_string(), "capture thread refused");
        assert!(
            aggregate_stopped_rx
                .recv_timeout(STOP_CHECK_INTERVAL * 2)
                .is_ok()
        );
    }

    fn snapshot(in_bytes: u64) -> Arc<TrafficSnapshot> {
        Arc::new(TrafficSnapshot {
            in_bytes,
            ..TrafficSnapshot::default()
        })
    }

    fn flow(bytes: u64) -> Flow {
        Flow {
            direction: Direction::Inbound,
            peer: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bytes,
            local_socket: None,
        }
    }

    fn socket_flow(local_ip: IpAddr, port: u16, bytes: u64) -> Flow {
        Flow {
            direction: Direction::Outbound,
            peer: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
            bytes,
            local_socket: Some(crate::capture::LocalSocket {
                ip: local_ip,
                port,
                protocol: crate::capture::TransportProtocol::Tcp,
            }),
        }
    }
}
