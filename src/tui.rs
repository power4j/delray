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
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table};

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

/// Persistent UI state across refreshes.
struct AppState {
    page: Page,
    proc_scroll: usize,
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
            ip_in_scroll: 0,
            ip_out_scroll: 0,
            ip_focus: IpFocus::Inbound,
            proc_view_height: 1,
            ip_in_view_height: 1,
            ip_out_view_height: 1,
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
        draw(state, snapshot)?;
    }

    Ok(false)
}

fn handle_key(state: &mut AppState, key: KeyEvent, snapshot: &TrafficSnapshot) -> KeyOutcome {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => KeyOutcome::Quit,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => KeyOutcome::Quit,
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
        Page::Processes => draw_processes(f, chunks[1], state, snapshot),
        Page::Ips => draw_ips(f, chunks[1], state, snapshot),
        Page::About => draw_about(f, chunks[1]),
    }
    draw_status_bar(f, chunks[2], state.page);
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

fn draw_status_bar(f: &mut ratatui::Frame, area: Rect, page: Page) {
    let hint = match page {
        Page::Overview => "1-4:page  ←→/hl:switch  q:quit",
        Page::Processes => "1-4:page  ←→/hl:switch  ↑↓/jk:scroll  PgUp/Dn:page  Home/End  q:quit",
        Page::Ips => "1-4:page  ←→/hl:switch  Tab:panel  ↑↓/jk:scroll  PgUp/Dn:page  q:quit",
        Page::About => "1-4:page  ←→/hl:switch  q:quit",
    };
    let para = Paragraph::new(format!(" {hint} ")).style(Style::default().fg(Color::DarkGray));
    f.render_widget(para, area);
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
    fn unattributed_process_row_uses_special_label_and_style() {
        let snapshot = TrafficSnapshot {
            processes: vec![ProcessSnapshot::unattributed(40, 60)].into(),
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
    }

    #[test]
    fn overview_uses_special_style_for_unattributed_traffic() {
        let snapshot = TrafficSnapshot {
            processes: vec![ProcessSnapshot::unattributed(40, 60)].into(),
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
}
