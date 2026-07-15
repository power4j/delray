//! Terminal UI: tabbed pages with scrollable tables.
//!
//! The TUI owns only interaction state and the latest immutable traffic snapshot.
//! Capture and aggregation run in the traffic pipeline.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction as LayoutDir, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, Wrap};

use crate::pipeline::TrafficPipeline;
use crate::report::{fmt_elapsed, hostname, human_bytes, truncate};
use crate::stats::{ProcessSnapshot, TrafficSnapshot};

const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Which page is active.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Processes,
    Ips,
    About,
}

impl Page {
    const ALL: [Page; 4] = [Page::Overview, Page::Processes, Page::Ips, Page::About];

    fn index(self) -> usize {
        match self {
            Page::Overview => 0,
            Page::Processes => 1,
            Page::Ips => 2,
            Page::About => 3,
        }
    }
}

/// Focus within the IPs page (left/right split).
#[derive(Clone, Copy, PartialEq, Eq)]
enum IpFocus {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyOutcome {
    Quit,
    Changed,
    Ignored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrackingPause {
    OutsideTopN,
    Stale,
}

impl TrackingPause {
    fn message(self) -> &'static str {
        match self {
            Self::OutsideTopN => "Tracking paused: process is no longer in Top-N.",
            Self::Stale => "Tracking paused: process data is stale.",
        }
    }
}

struct ProcessDetail {
    process: ProcessSnapshot,
    paused: Option<TrackingPause>,
    pause_notice: Option<TrackingPause>,
}

impl ProcessDetail {
    fn pause(&mut self, reason: TrackingPause) {
        if self.paused != Some(reason) {
            self.pause_notice = Some(reason);
        }
        self.paused = Some(reason);
    }
}

/// Persistent UI state across refreshes.
struct AppState {
    page: Page,
    proc_scroll: usize,
    process_detail: Option<ProcessDetail>,
    ip_in_scroll: usize,
    ip_out_scroll: usize,
    ip_focus: IpFocus,
    /// Monotonic view height, updated each draw for clamping scrolls.
    proc_view_height: usize,
    ip_in_view_height: usize,
    ip_out_view_height: usize,
}

impl AppState {
    fn new() -> Self {
        Self {
            page: Page::Overview,
            proc_scroll: 0,
            process_detail: None,
            ip_in_scroll: 0,
            ip_out_scroll: 0,
            ip_focus: IpFocus::Inbound,
            proc_view_height: 1,
            ip_in_view_height: 1,
            ip_out_view_height: 1,
        }
    }

    fn update_process_detail(&mut self, snapshot: &TrafficSnapshot) {
        let Some(detail) = self.process_detail.as_mut() else {
            return;
        };
        let matching_process = snapshot
            .processes
            .iter()
            .find(|process| process.same_identity_as(&detail.process));
        if let Some(process) = matching_process {
            detail.process = process.clone();
        }
        if !snapshot.process_data_fresh {
            detail.pause(TrackingPause::Stale);
        } else if matching_process.is_some() {
            detail.paused = None;
            detail.pause_notice = None;
        } else {
            detail.pause(TrackingPause::OutsideTopN);
        }
    }
}

/// Run the TUI until the user quits.
pub fn run(interface: &str, pipeline: &TrafficPipeline) -> io::Result<()> {
    let started_at = Instant::now();
    let host = hostname();
    let mut snapshot = pipeline
        .try_latest()
        .map_err(io::Error::other)?
        .unwrap_or_else(|| Arc::new(TrafficSnapshot::default()));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new();
    let result = tui_loop(
        &mut terminal,
        &mut state,
        &mut snapshot,
        interface,
        &host,
        started_at,
        pipeline,
    );

    // Restore terminal regardless of how the event loop exited.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn tui_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut AppState,
    snapshot: &mut Arc<TrafficSnapshot>,
    interface: &str,
    host: &str,
    started_at: Instant,
    pipeline: &TrafficPipeline,
) -> io::Result<()> {
    terminal.draw(|f| draw(f, state, snapshot, interface, host, started_at))?;

    loop {
        let key = if event::poll(EVENT_POLL_INTERVAL)? {
            match event::read()? {
                Event::Key(key) => Some(key),
                _ => None,
            }
        } else {
            None
        };

        let quit = process_iteration(
            state,
            snapshot,
            key,
            |state, snapshot| {
                terminal
                    .draw(|f| draw(f, state, snapshot, interface, host, started_at))
                    .map(|_| ())
            },
            || pipeline.try_latest().map_err(io::Error::other),
        )?;
        if quit {
            return Ok(());
        }
    }
}

fn process_iteration<D, L, E>(
    state: &mut AppState,
    snapshot: &mut Arc<TrafficSnapshot>,
    key: Option<KeyEvent>,
    mut draw: D,
    mut try_latest: L,
) -> Result<bool, E>
where
    D: FnMut(&mut AppState, &TrafficSnapshot) -> Result<(), E>,
    L: FnMut() -> Result<Option<Arc<TrafficSnapshot>>, E>,
{
    if let Some(key) = key {
        match handle_key(state, key, snapshot) {
            KeyOutcome::Quit => return Ok(true),
            KeyOutcome::Changed => draw(state, snapshot)?,
            KeyOutcome::Ignored => {}
        }
    }

    if let Some(latest) = try_latest()? {
        *snapshot = latest;
        state.update_process_detail(snapshot);
        draw(state, snapshot)?;
    }

    Ok(false)
}

fn handle_key(state: &mut AppState, key: KeyEvent, snapshot: &TrafficSnapshot) -> KeyOutcome {
    match key.code {
        KeyCode::Char('q') => KeyOutcome::Quit,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => KeyOutcome::Quit,
        KeyCode::Esc if state.process_detail.is_some() => {
            state.process_detail = None;
            KeyOutcome::Changed
        }
        KeyCode::Esc => KeyOutcome::Quit,
        KeyCode::Enter if state.page == Page::Processes && state.process_detail.is_none() => {
            let Some(process) = snapshot.processes.get(state.proc_scroll) else {
                return KeyOutcome::Ignored;
            };
            let mut detail = ProcessDetail {
                process: process.clone(),
                paused: None,
                pause_notice: None,
            };
            if !snapshot.process_data_fresh {
                detail.pause(TrackingPause::Stale);
            }
            state.process_detail = Some(detail);
            KeyOutcome::Changed
        }
        _ if state.process_detail.is_some() => KeyOutcome::Ignored,
        KeyCode::Char('1') => {
            state.page = Page::Overview;
            KeyOutcome::Changed
        }
        KeyCode::Char('2') => {
            state.page = Page::Processes;
            KeyOutcome::Changed
        }
        KeyCode::Char('3') => {
            state.page = Page::Ips;
            KeyOutcome::Changed
        }
        KeyCode::Char('4') => {
            state.page = Page::About;
            KeyOutcome::Changed
        }
        KeyCode::Tab => {
            if state.page == Page::Ips {
                state.ip_focus = match state.ip_focus {
                    IpFocus::Inbound => IpFocus::Outbound,
                    IpFocus::Outbound => IpFocus::Inbound,
                };
                KeyOutcome::Changed
            } else {
                KeyOutcome::Ignored
            }
        }
        KeyCode::Left | KeyCode::Char('h') => {
            state.page = prev_page(state.page);
            KeyOutcome::Changed
        }
        KeyCode::Right | KeyCode::Char('l') => {
            state.page = next_page(state.page);
            KeyOutcome::Changed
        }
        KeyCode::Down | KeyCode::Char('j') => {
            scroll(state, 1);
            KeyOutcome::Changed
        }
        KeyCode::Up | KeyCode::Char('k') => {
            scroll(state, -1);
            KeyOutcome::Changed
        }
        KeyCode::PageDown => {
            scroll(state, state.current_view_height() as isize);
            KeyOutcome::Changed
        }
        KeyCode::PageUp => {
            scroll(state, -(state.current_view_height() as isize));
            KeyOutcome::Changed
        }
        KeyCode::Home => {
            scroll_to_top(state);
            KeyOutcome::Changed
        }
        KeyCode::End => {
            scroll_to_bottom(state, snapshot);
            KeyOutcome::Changed
        }
        _ => KeyOutcome::Ignored,
    }
}

fn prev_page(p: Page) -> Page {
    let idx = p.index();
    Page::ALL[(idx + Page::ALL.len() - 1) % Page::ALL.len()]
}

fn next_page(p: Page) -> Page {
    let idx = p.index();
    Page::ALL[(idx + 1) % Page::ALL.len()]
}

impl AppState {
    fn current_view_height(&self) -> usize {
        match self.page {
            Page::Processes => self.proc_view_height,
            Page::Ips => match self.ip_focus {
                IpFocus::Inbound => self.ip_in_view_height,
                IpFocus::Outbound => self.ip_out_view_height,
            },
            _ => 1,
        }
    }
}

fn scroll(state: &mut AppState, delta: isize) {
    match state.page {
        Page::Processes => {
            state.proc_scroll = (state.proc_scroll as isize + delta).max(0) as usize;
        }
        Page::Ips => match state.ip_focus {
            IpFocus::Inbound => {
                state.ip_in_scroll = (state.ip_in_scroll as isize + delta).max(0) as usize;
            }
            IpFocus::Outbound => {
                state.ip_out_scroll = (state.ip_out_scroll as isize + delta).max(0) as usize;
            }
        },
        _ => {}
    }
}

fn scroll_to_top(state: &mut AppState) {
    match state.page {
        Page::Processes => state.proc_scroll = 0,
        Page::Ips => match state.ip_focus {
            IpFocus::Inbound => state.ip_in_scroll = 0,
            IpFocus::Outbound => state.ip_out_scroll = 0,
        },
        _ => {}
    }
}

fn scroll_to_bottom(state: &mut AppState, snapshot: &TrafficSnapshot) {
    match state.page {
        Page::Processes => {
            let len = snapshot.processes.len();
            state.proc_scroll = len.saturating_sub(state.proc_view_height);
        }
        Page::Ips => match state.ip_focus {
            IpFocus::Inbound => {
                let len = snapshot.inbound_ips.len();
                state.ip_in_scroll = len.saturating_sub(state.ip_in_view_height);
            }
            IpFocus::Outbound => {
                let len = snapshot.outbound_ips.len();
                state.ip_out_scroll = len.saturating_sub(state.ip_out_view_height);
            }
        },
        _ => {}
    }
}

// ── drawing ──

fn draw(
    f: &mut ratatui::Frame,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    interface: &str,
    host: &str,
    started_at: Instant,
) {
    draw_at(
        f,
        state,
        snapshot,
        interface,
        host,
        started_at,
        chrono::Utc::now(),
    );
}

fn draw_at(
    f: &mut ratatui::Frame,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    interface: &str,
    host: &str,
    started_at: Instant,
    now: chrono::DateTime<chrono::Utc>,
) {
    let chunks = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    draw_title_bar(f, chunks[0], snapshot, interface, host, started_at);
    match state.page {
        Page::Overview => draw_overview(f, chunks[1], snapshot),
        Page::Processes => match state.process_detail.as_ref() {
            Some(detail) => draw_process_detail(f, chunks[1], detail, now),
            None => draw_processes(f, chunks[1], state, snapshot),
        },
        Page::Ips => draw_ips(f, chunks[1], state, snapshot),
        Page::About => draw_about(f, chunks[1]),
    }
    draw_status_bar(f, chunks[2], state);
}

fn draw_title_bar(
    f: &mut ratatui::Frame,
    area: Rect,
    snapshot: &TrafficSnapshot,
    interface: &str,
    host: &str,
    started_at: Instant,
) {
    let now = chrono::Local::now();
    let title = format!(
        " delray | {} | host: {} | uptime: {} | In: {} Out: {} | {} ",
        interface,
        host,
        fmt_elapsed(started_at.elapsed()),
        human_bytes(snapshot.in_bytes),
        human_bytes(snapshot.out_bytes),
        now.format("%Y-%m-%d %H:%M:%S")
    );
    let para = Paragraph::new(title).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(para, area);
}

fn draw_overview(f: &mut ratatui::Frame, area: Rect, snapshot: &TrafficSnapshot) {
    let chunks = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0)])
        .split(area);

    // In/Out bars
    let total = snapshot.in_bytes + snapshot.out_bytes;
    let in_ratio = if total > 0 {
        snapshot.in_bytes as f64 / total as f64
    } else {
        0.0
    };
    let out_ratio = if total > 0 {
        snapshot.out_bytes as f64 / total as f64
    } else {
        0.0
    };
    let bars = vec![
        Line::from(format!(
            "  Inbound  {}  ({:.1}%)",
            bar(in_ratio, 30),
            in_ratio * 100.0
        )),
        Line::from(format!(
            " Outbound  {}  ({:.1}%)",
            bar(out_ratio, 30),
            out_ratio * 100.0
        )),
        Line::from(format!(
            "   In: {}   Out: {}",
            human_bytes(snapshot.in_bytes),
            human_bytes(snapshot.out_bytes)
        )),
    ];
    f.render_widget(Paragraph::new(bars), chunks[0]);

    // Three preview columns
    let cols = Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(chunks[1]);

    let processes = snapshot.processes.as_ref();
    let process_items: Vec<ListItem> = processes
        .iter()
        .take(5)
        .map(|process| {
            let name = process_name_span(process, 18);
            ListItem::new(Line::from(vec![
                name,
                Span::raw(format!("  {}", human_bytes(process.total()))),
            ]))
        })
        .collect();
    let process_block = preview_block("Top Processes", processes.len(), 5, 2);
    f.render_widget(List::new(process_items).block(process_block), cols[0]);

    let inbound_ips = snapshot.inbound_ips.as_ref();
    let inbound_items: Vec<ListItem> = inbound_ips
        .iter()
        .take(5)
        .map(|entry| ListItem::new(format!("{}  {}", entry.ip, human_bytes(entry.bytes))))
        .collect();
    let inbound_block = preview_block("Top Inbound IPs", inbound_ips.len(), 5, 3);
    f.render_widget(List::new(inbound_items).block(inbound_block), cols[1]);

    let outbound_ips = snapshot.outbound_ips.as_ref();
    let outbound_items: Vec<ListItem> = outbound_ips
        .iter()
        .take(5)
        .map(|entry| ListItem::new(format!("{}  {}", entry.ip, human_bytes(entry.bytes))))
        .collect();
    let outbound_block = preview_block("Top Outbound IPs", outbound_ips.len(), 5, 3);
    f.render_widget(List::new(outbound_items).block(outbound_block), cols[2]);
}

fn preview_block(title: &str, total: usize, shown: usize, goto: usize) -> Block<'_> {
    let footer = if total > shown {
        format!("+{} more (press {})", total - shown, goto)
    } else {
        String::new()
    };
    Block::default()
        .borders(Borders::ALL)
        .title(format!(" {title} "))
        .title_bottom(Line::from(format!(" {footer} ")).alignment(Alignment::Center))
}

fn bar(ratio: f64, width: usize) -> String {
    let filled = ((ratio * width as f64).round() as usize).min(width);
    let empty = width - filled;
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

fn process_name_span(process: &ProcessSnapshot, max_chars: usize) -> Span<'static> {
    let name = if process.is_unattributed() {
        process.display_name().to_string()
    } else {
        truncate(process.display_name(), max_chars)
    };
    if process.is_unattributed() {
        Span::styled(
            name,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::ITALIC),
        )
    } else {
        Span::raw(name)
    }
}

fn draw_processes(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
) {
    let processes = snapshot.processes.as_ref();
    let rows: Vec<Row> = processes
        .iter()
        .map(|process| {
            let name = Cell::from(process_name_span(process, 40));
            Row::new(vec![
                name,
                Cell::from(
                    process
                        .pid()
                        .map(|pid| pid.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                Cell::from(human_bytes(process.recv)),
                Cell::from(human_bytes(process.sent)),
                Cell::from(human_bytes(process.total())),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(20),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(12),
        ],
    )
    .header(
        Row::new(vec!["Process", "PID", "Recv", "Sent", "Total"]).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED))
    .highlight_symbol("> ")
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Processes ({}) ", processes.len())),
    );

    let view_h = area.height.saturating_sub(4) as usize;
    state.proc_view_height = view_h.max(1);
    state.proc_scroll = state.proc_scroll.min(processes.len().saturating_sub(1));

    f.render_stateful_widget(
        table,
        area,
        &mut ratatui_state(processes.len(), state.proc_scroll),
    );
}

fn draw_process_detail(
    f: &mut ratatui::Frame,
    area: Rect,
    detail: &ProcessDetail,
    now: chrono::DateTime<chrono::Utc>,
) {
    let process = &detail.process;
    let mut lines = vec![
        Line::from(vec![
            Span::raw("Name: "),
            process_name_span(process, usize::MAX),
        ]),
        Line::from(format!(
            "PID: {}",
            process
                .pid()
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".to_string())
        )),
        Line::from(format!("Path: {}", process.path().unwrap_or("-"))),
        Line::from(""),
        Line::from(format!("Recv: {}", human_bytes(process.recv))),
        Line::from(format!("Sent: {}", human_bytes(process.sent))),
        Line::from(format!("Total: {}", human_bytes(process.total()))),
        Line::from(format!(
            "Last seen: {}",
            relative_last_seen(process.last_seen(), now)
        )),
    ];
    if detail.paused.is_some() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Tracking paused",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
    }
    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Process Details "),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

fn relative_last_seen(
    last_seen: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let seconds = now.signed_duration_since(last_seen).num_seconds().max(0);
    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 60 * 60 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 24 * 60 * 60 {
        format!("{}h ago", seconds / (60 * 60))
    } else {
        format!("{}d ago", seconds / (24 * 60 * 60))
    }
}

fn draw_ips(f: &mut ratatui::Frame, area: Rect, state: &mut AppState, snapshot: &TrafficSnapshot) {
    let cols = Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let inbound_ips = snapshot.inbound_ips.as_ref();
    let outbound_ips = snapshot.outbound_ips.as_ref();

    let inbound_block_style = if state.ip_focus == IpFocus::Inbound {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    let outbound_block_style = if state.ip_focus == IpFocus::Outbound {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let inbound_rows: Vec<Row> = inbound_ips
        .iter()
        .map(|entry| Row::new(vec![entry.ip.to_string(), human_bytes(entry.bytes)]))
        .collect();
    let inbound_table = Table::new(inbound_rows, [Constraint::Min(20), Constraint::Length(14)])
        .header(
            Row::new(vec!["IP", "Bytes"]).style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Inbound IPs ({}) ", inbound_ips.len()))
                .border_style(inbound_block_style),
        );

    let outbound_rows: Vec<Row> = outbound_ips
        .iter()
        .map(|entry| Row::new(vec![entry.ip.to_string(), human_bytes(entry.bytes)]))
        .collect();
    let outbound_table = Table::new(outbound_rows, [Constraint::Min(20), Constraint::Length(14)])
        .header(
            Row::new(vec!["IP", "Bytes"]).style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Outbound IPs ({}) ", outbound_ips.len()))
                .border_style(outbound_block_style),
        );

    let inbound_view_height = cols[0].height.saturating_sub(4) as usize;
    let outbound_view_height = cols[1].height.saturating_sub(4) as usize;
    state.ip_in_view_height = inbound_view_height.max(1);
    state.ip_out_view_height = outbound_view_height.max(1);
    state.ip_in_scroll = state.ip_in_scroll.min(inbound_ips.len().saturating_sub(1));
    state.ip_out_scroll = state
        .ip_out_scroll
        .min(outbound_ips.len().saturating_sub(1));

    f.render_stateful_widget(
        inbound_table,
        cols[0],
        &mut ratatui_state(inbound_ips.len(), state.ip_in_scroll),
    );
    f.render_stateful_widget(
        outbound_table,
        cols[1],
        &mut ratatui_state(outbound_ips.len(), state.ip_out_scroll),
    );
}

fn draw_about(f: &mut ratatui::Frame, area: Rect) {
    let version = env!("CARGO_PKG_VERSION");
    let lines = vec![
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            "delray",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Network Traffic Analyzer"),
        Line::from(""),
        Line::from(format!("Version {version}")),
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            "─────────────────────────────",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from("capture · analyze · locate"),
        Line::from("which process and IP consumes"),
        Line::from("your server's bandwidth"),
    ];
    let para = Paragraph::new(lines).alignment(Alignment::Center);
    f.render_widget(para, area);
}

fn draw_status_bar(f: &mut ratatui::Frame, area: Rect, state: &mut AppState) {
    let hint = if let Some(detail) = state.process_detail.as_ref() {
        match (detail.pause_notice, detail.paused) {
            (Some(reason), _) => format!("{}  Esc:back  q:quit", reason.message()),
            (None, Some(_)) => "Tracking paused  Esc:back  q:quit".to_string(),
            (None, None) => "Esc:back  q:quit".to_string(),
        }
    } else {
        match state.page {
            Page::Overview => "1-4:page  ←→/hl:switch  q:quit",
            Page::Processes => "Enter:details  1-4:page  ←→/hl:switch  ↑↓/jk:select  q:quit",
            Page::Ips => "1-4:page  ←→/hl:switch  Tab:panel  ↑↓/jk:scroll  PgUp/Dn:page  q:quit",
            Page::About => "1-4:page  ←→/hl:switch  q:quit",
        }
        .to_string()
    };
    let para = Paragraph::new(format!(" {hint} ")).style(Style::default().fg(Color::DarkGray));
    f.render_widget(para, area);
    if let Some(detail) = state.process_detail.as_mut() {
        detail.pause_notice = None;
    }
}

/// Build a ratatui TableState at the given offset.
fn ratatui_state(len: usize, scroll: usize) -> ratatui::widgets::TableState {
    let mut s = ratatui::widgets::TableState::default();
    if len > 0 {
        s.select(Some(scroll.min(len - 1)));
    }
    s
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::stats::{IpSnapshot, ProcessSnapshot, TrafficSnapshot};

    fn rendered_lines(terminal: &Terminal<TestBackend>) -> Vec<String> {
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    fn assert_unattributed_style(terminal: &Terminal<TestBackend>) {
        let rendered = rendered_lines(terminal).join("\n");
        assert!(rendered.contains("<unattributed traffic>"));
        let first_label_cell = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .find(|cell| cell.symbol() == "<")
            .expect("unattributed label cell");
        assert_eq!(first_label_cell.fg, Color::Yellow);
        assert!(first_label_cell.modifier.contains(Modifier::ITALIC));
    }

    #[test]
    fn processes_page_renders_from_snapshot() {
        let snapshot = TrafficSnapshot {
            in_bytes: 40,
            out_bytes: 60,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("curl --silent")),
                None,
                chrono::Utc::now(),
                40,
                60,
            )]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| {
                draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now());
            })
            .unwrap();

        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("curl --silent"));
        assert!(rendered.contains("100 B"));
    }

    #[test]
    fn processes_page_marks_the_selected_row() {
        let snapshot = TrafficSnapshot {
            processes: vec![
                ProcessSnapshot::attributed(
                    7,
                    Some(Arc::from("curl")),
                    Some(Arc::from("/usr/bin/curl")),
                    chrono::Utc::now(),
                    40,
                    60,
                ),
                ProcessSnapshot::attributed(
                    8,
                    Some(Arc::from("ssh")),
                    Some(Arc::from("/usr/bin/ssh")),
                    chrono::Utc::now(),
                    10,
                    20,
                ),
            ]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        assert!(matches!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
                &snapshot,
            ),
            KeyOutcome::Changed
        ));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("> ssh"));
        assert!(rendered.contains("Process"));
        assert!(rendered.contains("PID"));
        assert!(rendered.contains("Recv"));
        assert!(rendered.contains("Sent"));
        assert!(rendered.contains("Total"));
        assert!(rendered.contains("Enter:details"));
        assert!(rendered.contains("q:quit"));
        assert!(!rendered.contains("/usr/bin/ssh"));
    }

    #[test]
    fn unattributed_process_row_uses_special_label_and_style() {
        let snapshot = TrafficSnapshot {
            processes: vec![ProcessSnapshot::unattributed(40, 60, chrono::Utc::now())].into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| {
                draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now());
            })
            .unwrap();

        assert_unattributed_style(&terminal);
    }

    #[test]
    fn overview_page_renders_from_snapshot() {
        let snapshot = TrafficSnapshot {
            in_bytes: 1024,
            out_bytes: 2048,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("curl --silent")),
                Some(Arc::from("/usr/bin/curl")),
                chrono::Utc::now(),
                1024,
                2048,
            )]
            .into(),
            inbound_ips: vec![IpSnapshot {
                ip: "192.0.2.10".parse().unwrap(),
                bytes: 1024,
            }]
            .into(),
            outbound_ips: vec![IpSnapshot {
                ip: "198.51.100.20".parse().unwrap(),
                bytes: 2048,
            }]
            .into(),
            process_data_fresh: false,
        };
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("curl --silent"));
        assert!(rendered.contains("192.0.2.10"));
        assert!(rendered.contains("198.51.100.20"));
        assert!(rendered.contains("Top Processes"));
        assert!(!rendered.contains("/usr/bin/curl"));
    }

    #[test]
    fn overview_uses_special_style_for_unattributed_traffic() {
        let snapshot = TrafficSnapshot {
            processes: vec![ProcessSnapshot::unattributed(40, 60, chrono::Utc::now())].into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| {
                draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now());
            })
            .unwrap();

        assert_unattributed_style(&terminal);
    }

    #[test]
    fn ips_page_renders_from_snapshot() {
        let snapshot = TrafficSnapshot {
            inbound_ips: vec![IpSnapshot {
                ip: "192.0.2.10".parse().unwrap(),
                bytes: 1024,
            }]
            .into(),
            outbound_ips: vec![IpSnapshot {
                ip: "198.51.100.20".parse().unwrap(),
                bytes: 2048,
            }]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Ips;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("192.0.2.10"));
        assert!(rendered.contains("1.00 KB"));
        assert!(rendered.contains("198.51.100.20"));
        assert!(rendered.contains("2.00 KB"));
    }

    #[test]
    fn page_key_reports_changed() {
        let mut state = AppState::new();
        let snapshot = TrafficSnapshot::default();

        let outcome = handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE),
            &snapshot,
        );

        assert!(matches!(outcome, KeyOutcome::Changed));
        assert!(state.page == Page::Processes);
    }

    #[test]
    fn page_key_draws_before_checking_for_snapshot_update() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let draw_calls = calls.clone();
        let latest_calls = calls.clone();
        let mut state = AppState::new();
        let mut snapshot = Arc::new(TrafficSnapshot::default());

        let quit = process_iteration(
            &mut state,
            &mut snapshot,
            Some(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE)),
            |_, _| {
                draw_calls.borrow_mut().push("draw");
                Ok::<_, ()>(())
            },
            || {
                latest_calls.borrow_mut().push("latest");
                Ok::<_, ()>(None)
            },
        )
        .unwrap();

        assert!(!quit);
        assert_eq!(*calls.borrow(), vec!["draw", "latest"]);
    }

    #[test]
    fn selected_process_opens_in_details_and_escape_returns_to_list() {
        let snapshot = TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![
                ProcessSnapshot::attributed(
                    7,
                    Some(Arc::from("curl")),
                    Some(Arc::from("/usr/bin/curl")),
                    "2026-07-15T08:00:00Z".parse().unwrap(),
                    40,
                    60,
                ),
                ProcessSnapshot::attributed(
                    8,
                    Some(Arc::from("ssh")),
                    Some(Arc::from("/usr/bin/ssh")),
                    "2026-07-15T08:01:00Z".parse().unwrap(),
                    10,
                    20,
                ),
            ]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        state.proc_scroll = 1;

        let outcome = handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );

        assert!(matches!(outcome, KeyOutcome::Changed));
        assert_eq!(
            state.process_detail.as_ref().unwrap().process.pid(),
            Some(8)
        );

        let outcome = handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            &snapshot,
        );

        assert!(matches!(outcome, KeyOutcome::Changed));
        assert!(state.process_detail.is_none());

        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        assert!(matches!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                &snapshot,
            ),
            KeyOutcome::Quit
        ));
        assert!(matches!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                &snapshot,
            ),
            KeyOutcome::Quit
        ));
    }

    #[test]
    fn process_details_render_all_fields_at_eighty_columns() {
        let path = "/opt/services/payments/releases/2026-07-15/production/workers/payment-processing/payment-worker";
        let snapshot = TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("payment-worker")),
                Some(Arc::from(path)),
                "2026-07-15T08:00:00Z".parse().unwrap(),
                1024,
                2048,
            )]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| {
                draw_at(
                    frame,
                    &mut state,
                    &snapshot,
                    "eth0",
                    "host",
                    Instant::now(),
                    "2026-07-15T08:02:00Z".parse().unwrap(),
                );
            })
            .unwrap();

        let lines = rendered_lines(&terminal);
        let rendered = lines.join("\n");
        assert!(rendered.contains("Process Details"));
        assert!(rendered.contains("Name: payment-worker"));
        assert!(rendered.contains("PID: 7"));
        assert!(rendered.contains("Recv: 1.00 KB"));
        assert!(rendered.contains("Sent: 2.00 KB"));
        assert!(rendered.contains("Total: 3.00 KB"));
        assert!(rendered.contains("Last seen: 2m ago"));
        assert!(rendered.contains("Esc:back"));
        let inner_lines = lines
            .iter()
            .map(|line| line.chars().skip(1).take(78).collect::<String>())
            .collect::<Vec<_>>();
        let path_line = inner_lines
            .iter()
            .position(|line| line.starts_with("Path: "))
            .unwrap();
        let mut displayed_path = inner_lines[path_line]
            .trim_end()
            .strip_prefix("Path:")
            .unwrap()
            .trim_start()
            .to_string();
        for continuation in &inner_lines[path_line + 1..] {
            if continuation.trim().is_empty() {
                break;
            }
            displayed_path.push_str(continuation.trim_end());
        }
        assert_eq!(displayed_path, path);
        for line in lines {
            let field_count = [
                "Name:",
                "PID:",
                "Path:",
                "Recv:",
                "Sent:",
                "Total:",
                "Last seen:",
            ]
            .iter()
            .filter(|field| line.contains(**field))
            .count();
            assert!(field_count <= 1, "detail fields overlap: {line}");
        }
    }

    #[test]
    fn details_update_when_the_same_identity_arrives() {
        let selected = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("curl")),
            None,
            "2026-07-15T08:00:00Z".parse().unwrap(),
            40,
            60,
        );
        let latest = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("renamed-curl")),
            None,
            "2026-07-15T08:01:00Z".parse().unwrap(),
            140,
            160,
        );
        let mut snapshot = Arc::new(TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![selected].into(),
            ..TrafficSnapshot::default()
        });
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );

        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |_, _| Ok::<_, ()>(()),
            || {
                Ok::<_, ()>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: true,
                    processes: vec![latest.clone()].into(),
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();

        let detail = &state.process_detail.as_ref().unwrap().process;
        assert_eq!((detail.recv, detail.sent), (140, 160));
        assert_eq!(detail.name(), Some("renamed-curl"));
        assert!(detail.path().is_none());
        assert_eq!(
            detail.last_seen(),
            "2026-07-15T08:01:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
        );
    }

    #[test]
    fn same_pid_with_a_different_path_does_not_update_details() {
        let mut snapshot = Arc::new(TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("old-curl")),
                Some(Arc::from("/opt/old/curl")),
                "2026-07-15T08:00:00Z".parse().unwrap(),
                40,
                60,
            )]
            .into(),
            ..TrafficSnapshot::default()
        });
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );

        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |_, _| Ok::<_, ()>(()),
            || {
                Ok::<_, ()>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: true,
                    processes: vec![ProcessSnapshot::attributed(
                        7,
                        Some(Arc::from("new-curl")),
                        Some(Arc::from("/opt/new/curl")),
                        "2026-07-15T08:01:00Z".parse().unwrap(),
                        140,
                        160,
                    )]
                    .into(),
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();

        let detail = state.process_detail.as_ref().unwrap();
        assert_eq!(detail.process.path(), Some("/opt/old/curl"));
        assert_eq!((detail.process.recv, detail.process.sent), (40, 60));
        assert_eq!(detail.paused, Some(TrackingPause::OutsideTopN));
    }

    #[test]
    fn top_n_pause_notice_is_drawn_once_while_paused_details_persist() {
        let mut snapshot = Arc::new(TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("curl")),
                Some(Arc::from("/usr/bin/curl")),
                "2026-07-15T08:00:00Z".parse().unwrap(),
                40,
                60,
            )]
            .into(),
            ..TrafficSnapshot::default()
        });
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let now = "2026-07-15T08:05:00Z".parse().unwrap();

        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |state, snapshot| {
                terminal
                    .draw(|frame| {
                        draw_at(frame, state, snapshot, "eth0", "host", Instant::now(), now);
                    })
                    .map(|_| ())
            },
            || {
                Ok::<_, io::Error>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: true,
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();

        let first_draw = rendered_lines(&terminal).join("\n");
        assert!(first_draw.contains("Tracking paused: process is no longer in Top-N."));
        assert!(first_draw.contains("Total: 100 B"));
        assert!(first_draw.contains("Last seen: 5m ago"));

        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |state, snapshot| {
                terminal
                    .draw(|frame| {
                        draw_at(frame, state, snapshot, "eth0", "host", Instant::now(), now);
                    })
                    .map(|_| ())
            },
            || {
                Ok::<_, io::Error>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: true,
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();

        let second_draw = rendered_lines(&terminal).join("\n");
        assert!(!second_draw.contains("process is no longer in Top-N"));
        assert!(second_draw.contains("Tracking paused"));
        assert!(second_draw.contains("Total: 100 B"));
        assert!(second_draw.contains("Last seen: 5m ago"));
    }

    #[test]
    fn stale_process_data_pauses_details_without_claiming_process_exit() {
        let mut snapshot = Arc::new(TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("curl")),
                Some(Arc::from("/usr/bin/curl")),
                "2026-07-15T08:00:00Z".parse().unwrap(),
                40,
                60,
            )]
            .into(),
            ..TrafficSnapshot::default()
        });
        let stale_process = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("curl")),
            Some(Arc::from("/usr/bin/curl")),
            "2026-07-15T08:01:00Z".parse().unwrap(),
            140,
            160,
        );
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |state, snapshot| {
                terminal
                    .draw(|frame| {
                        draw_at(
                            frame,
                            state,
                            snapshot,
                            "eth0",
                            "host",
                            Instant::now(),
                            "2026-07-15T08:02:00Z".parse().unwrap(),
                        );
                    })
                    .map(|_| ())
            },
            || {
                Ok::<_, io::Error>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: false,
                    processes: vec![stale_process.clone()].into(),
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();

        let detail = state.process_detail.as_ref().unwrap();
        assert_eq!(detail.paused, Some(TrackingPause::Stale));
        assert_eq!((detail.process.recv, detail.process.sent), (140, 160));
        assert_eq!(
            detail.process.last_seen(),
            "2026-07-15T08:01:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
        );
        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Tracking paused: process data is stale."));
        assert!(rendered.contains("Total: 300 B"));
        assert!(rendered.contains("Last seen: 1m ago"));
        assert!(!rendered.contains("exited"));
    }

    #[test]
    fn details_resume_when_the_same_identity_returns_to_top_n() {
        let selected = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("curl")),
            Some(Arc::from("/usr/bin/curl")),
            "2026-07-15T08:00:00Z".parse().unwrap(),
            40,
            60,
        );
        let mut snapshot = Arc::new(TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![selected].into(),
            ..TrafficSnapshot::default()
        });
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |_, _| Ok::<_, ()>(()),
            || {
                Ok::<_, ()>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: true,
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();
        assert_eq!(
            state.process_detail.as_ref().unwrap().paused,
            Some(TrackingPause::OutsideTopN)
        );

        let resumed = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("curl")),
            Some(Arc::from("/usr/bin/curl")),
            "2026-07-15T08:03:00Z".parse().unwrap(),
            140,
            160,
        );
        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |_, _| Ok::<_, ()>(()),
            || {
                Ok::<_, ()>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: true,
                    processes: vec![resumed.clone()].into(),
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();

        let detail = state.process_detail.as_ref().unwrap();
        assert_eq!(detail.paused, None);
        assert_eq!(detail.pause_notice, None);
        assert_eq!((detail.process.recv, detail.process.sent), (140, 160));
    }

    #[test]
    fn unattributed_traffic_details_keep_missing_fields_and_special_style() {
        let snapshot = TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![ProcessSnapshot::unattributed(
                40,
                60,
                "2026-07-15T08:00:00Z".parse().unwrap(),
            )]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| {
                draw_at(
                    frame,
                    &mut state,
                    &snapshot,
                    "eth0",
                    "host",
                    Instant::now(),
                    "2026-07-15T08:01:00Z".parse().unwrap(),
                );
            })
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Name: <unattributed traffic>"));
        assert!(rendered.contains("PID: -"));
        assert!(rendered.contains("Path: -"));
        assert_unattributed_style(&terminal);
    }
}
