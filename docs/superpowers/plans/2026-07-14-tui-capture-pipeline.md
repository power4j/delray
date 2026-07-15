# TUI Capture Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move blocking capture, process lookup, cumulative aggregation, and top-N computation out of the TUI thread so page changes render within 100 ms under capture load.

**Architecture:** Add a deep `TrafficPipeline` module with a blocking capture worker, an aggregation worker, a bounded Flow channel, and a bounded latest-snapshot channel. The TUI owns only `AppState` and an immutable `Arc<TrafficSnapshot>`; background and JSON modes retain their current synchronous loops.

**Tech Stack:** Rust 2024, std threads and `sync_channel`, pcap 2.4, ratatui 0.29, crossterm 0.28.

---

### Task 1: Immutable Traffic Snapshots

**Files:**
- Modify: `src/stats.rs`
- Modify: `src/proc_table.rs`

- [x] **Step 1: Write the failing snapshot test**

Add a test that records known inbound, outbound, and process traffic, calls `snapshot(2)`, and asserts literal totals, descending order, truncation, PID, process name, recv, and sent values.

- [x] **Step 2: Run the test to verify RED**

Run: `LIBRARY_PATH=/tmp cargo test stats::tests::snapshot_returns_ranked_top_n -- --exact`

Expected: compilation fails because `TrafficSnapshot`, `ObservedProcess`, `record_flow()`, and `snapshot()` do not exist.

- [x] **Step 3: Implement the minimal snapshot model**

Add `TrafficSnapshot`, `ProcessSnapshot`, `IpSnapshot`, `ObservedProcess`, `Stats::record_flow()`, and `Stats::snapshot()`. Convert process name caches in `ProcTable` and `Stats` to `Arc<str>` so snapshots share names without copying command lines.

- [x] **Step 4: Run snapshot and existing tests to verify GREEN**

Run: `LIBRARY_PATH=/tmp cargo test stats::tests::snapshot_returns_ranked_top_n -- --exact`

Expected: one test passes.

Run: `LIBRARY_PATH=/tmp cargo test`

Expected: all existing and new tests pass.

### Task 2: Capture and Aggregation Pipeline

**Files:**
- Create: `src/pipeline.rs`
- Modify: `src/main.rs`

- [x] **Step 1: Write failing pipeline interface tests**

Add tests for these observable behaviors: initial empty snapshot is available immediately; multiple queued snapshots return only the latest; a full snapshot channel does not block aggregation; terminal failure takes priority over queued snapshots.

- [x] **Step 2: Run pipeline tests to verify RED**

Run: `LIBRARY_PATH=/tmp cargo test pipeline::tests -- --nocapture`

Expected: compilation fails because module `pipeline` and `TrafficPipeline` do not exist.

- [x] **Step 3: Implement minimal channels and `try_latest()`**

Create bounded Flow capacity 8192 and snapshot capacity 2 constants. Implement `TrafficPipeline`, `PipelineError`, an initial snapshot, non-blocking latest-snapshot drain, shared stop flag, and independent `OnceLock` failure state.

- [x] **Step 4: Run pipeline tests to verify GREEN**

Run: `LIBRARY_PATH=/tmp cargo test pipeline::tests -- --nocapture`

Expected: pipeline interface tests pass.

- [x] **Step 5: Write failing worker behavior tests**

Add tests proving: capture loop continues after `Ok(None)`; aggregation publishes on timeout with no Flow; process lookup is applied before snapshot; capture-spawn failure stops the already-started aggregation worker.

- [x] **Step 6: Run worker tests to verify RED**

Run: `LIBRARY_PATH=/tmp cargo test pipeline::tests -- --nocapture`

Expected: the new worker tests fail because worker loops and spawn cleanup are incomplete.

- [x] **Step 7: Implement both workers**

Implement private capture and aggregation loops, named thread startup in aggregation-then-capture order, `recv_timeout()` bounded by the next 5-second snapshot and 100 ms stop check, non-blocking snapshot `try_send()`, and drop without join.

- [x] **Step 8: Run pipeline tests and full tests to verify GREEN**

Run: `LIBRARY_PATH=/tmp cargo test pipeline::tests -- --nocapture`

Expected: all pipeline tests pass.

Run: `LIBRARY_PATH=/tmp cargo test`

Expected: full suite passes.

### Task 3: Snapshot-Only TUI

**Files:**
- Modify: `src/tui.rs`
- Modify: `src/main.rs`

- [x] **Step 1: Write failing TUI tests**

Add tests using ratatui `TestBackend` that render Overview, Processes, and IPs from literal `TrafficSnapshot` values. Add a scheduling test with injected event and snapshot closures that records the call order and asserts a page key causes draw before `try_latest()`.

- [x] **Step 2: Run TUI tests to verify RED**

Run: `LIBRARY_PATH=/tmp cargo test tui::tests -- --nocapture`

Expected: tests fail because draw functions still require mutable `Stats`, and no testable loop step exists.

- [x] **Step 3: Convert rendering and scrolling to snapshots**

Replace all `Stats` and `top_n` parameters in TUI rendering with `TrafficSnapshot`; use snapshot vector lengths for scrolling; remove `drain_capture()`, `CaptureSource`, and `SharedProcTable` imports.

- [x] **Step 4: Implement control-first event scheduling**

Make `tui::run()` accept a `TrafficPipeline`. Draw the initial snapshot, poll keyboard events for at most 50 ms, draw immediately on `Changed`, then call `try_latest()` and draw a new snapshot. Keep terminal cleanup around every loop result.

- [x] **Step 5: Move pipeline ownership into foreground dispatch**

In `main.rs`, construct `TrafficPipeline` only for plain foreground mode, before entering TUI raw mode. Keep background and JSON branches on the existing synchronous source.

- [x] **Step 6: Run TUI and full tests to verify GREEN**

Run: `LIBRARY_PATH=/tmp cargo test tui::tests -- --nocapture`

Expected: TUI tests pass.

Run: `LIBRARY_PATH=/tmp cargo test`

Expected: full suite passes.

### Task 4: Performance Regression Verification

**Files:**
- Modify only if a test seam requires it: `src/tui.rs`, `src/pipeline.rs`
- Create: `scripts/check-tui-latency.sh`

- [x] **Step 1: Build and lint**

Run: `LIBRARY_PATH=/tmp cargo fmt --check`

Run: `LIBRARY_PATH=/tmp cargo clippy -- -D warnings`

Run: `LIBRARY_PATH=/tmp cargo build`

Expected: all commands exit 0 with no warnings.

- [x] **Step 2: Restore capture capability**

Run: `sudo setcap cap_net_raw+ep target/debug/delray`

Expected: `getcap target/debug/delray` prints `cap_net_raw=ep`.

- [x] **Step 3: Run the 80x24 PTY latency harness**

Start `target/debug/delray eth0` in a fixed 80x24 pseudo-terminal, send page keys, and map timing log input records to page-title output records.

Expected: every page key renders its target title in less than 100 ms; 100 repeated switches have no sample above 200 ms.

- [x] **Step 4: Verify source boundaries**

Run: `rg -n 'CaptureSource|SharedProcTable|\bStats\b|next_packet|drain_capture' src/tui.rs`

Expected: no matches.

Run: `rg -n 'sync_channel|FLOW_CHANNEL_CAPACITY|SNAPSHOT_CHANNEL_CAPACITY|try_send|recv_timeout' src/pipeline.rs`

Expected: all bounded pipeline mechanisms are present.

- [x] **Step 5: Review the final diff**

Run: `git diff --check && git diff --stat && git diff`

Expected: planned pipeline/TUI changes and the latency harness contain no debug instrumentation; pre-existing working-tree changes remain untouched.
