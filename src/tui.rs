//! Terminal UI: tabbed pages with scrollable tables.
//!
//! Architecture: the capture loop runs in the main thread, feeding a shared `Stats`.
//! The TUI polls keyboard events and redraws on a 5s refresh tick, keeping scroll
//! state across frames.

use std::io::{self, Stdout};
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
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table};

use crate::capture::CaptureSource;
use crate::proc_table::SharedProcTable;
use crate::report::{fmt_elapsed, hostname, human_bytes, truncate};
use crate::stats::{Direction, Stats};

const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const DRAIN_MAX_PER_TICK: usize = 256;

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

/// Run the TUI until the user quits. Owns the capture loop + event loop.
pub fn run(
    interface: &str,
    source: &mut CaptureSource,
    proc_table: &SharedProcTable,
    top_n: usize,
) -> io::Result<()> {
    let started_at = Instant::now();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new();
    let mut stats = Stats::default();
    let mut next_refresh = Instant::now();

    let result = tui_loop(
        &mut terminal,
        &mut state,
        &mut stats,
        interface,
        started_at,
        source,
        proc_table,
        top_n,
        &mut next_refresh,
    );

    // Restore terminal regardless of how we exited.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

#[allow(clippy::too_many_arguments)]
fn tui_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &mut AppState,
    stats: &mut Stats,
    interface: &str,
    started_at: Instant,
    source: &mut CaptureSource,
    proc_table: &SharedProcTable,
    top_n: usize,
    next_refresh: &mut Instant,
) -> io::Result<()> {
    loop {
        // Drain at most N packets per tick so the event loop stays responsive.
        drain_capture(source, proc_table, stats, DRAIN_MAX_PER_TICK);

        // Redraw.
        terminal.draw(|f| draw(f, state, stats, interface, started_at, top_n))?;

        // Wait for either a key event or the refresh tick.
        while Instant::now() < *next_refresh {
            if event::poll(Duration::from_millis(50))?
                && let Event::Key(key) = event::read()?
            {
                if handle_key(state, key, stats, top_n) {
                    return Ok(());
                }
                // Any key: redraw immediately so the user sees the change.
                drain_capture(source, proc_table, stats, DRAIN_MAX_PER_TICK);
                terminal.draw(|f| draw(f, state, stats, interface, started_at, top_n))?;
            }
        }
        *next_refresh = Instant::now() + REFRESH_INTERVAL;
    }
}

fn drain_capture(
    source: &mut CaptureSource,
    proc_table: &SharedProcTable,
    stats: &mut Stats,
    max: usize,
) {
    for _ in 0..max {
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
            Ok(None) => break,
            Err(_) => break,
        }
    }
}

/// Handle a key. Returns true if the app should quit.
fn handle_key(state: &mut AppState, key: KeyEvent, stats: &Stats, top_n: usize) -> bool {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
        KeyCode::Char('1') => {
            state.page = Page::Overview;
            false
        }
        KeyCode::Char('2') => {
            state.page = Page::Processes;
            false
        }
        KeyCode::Char('3') => {
            state.page = Page::Ips;
            false
        }
        KeyCode::Char('4') => {
            state.page = Page::About;
            false
        }
        KeyCode::Tab => {
            if state.page == Page::Ips {
                state.ip_focus = match state.ip_focus {
                    IpFocus::Inbound => IpFocus::Outbound,
                    IpFocus::Outbound => IpFocus::Inbound,
                };
            }
            false
        }
        KeyCode::Left | KeyCode::Char('h') => {
            state.page = prev_page(state.page);
            false
        }
        KeyCode::Right | KeyCode::Char('l') => {
            state.page = next_page(state.page);
            false
        }
        KeyCode::Down | KeyCode::Char('j') => {
            scroll(state, 1);
            false
        }
        KeyCode::Up | KeyCode::Char('k') => {
            scroll(state, -1);
            false
        }
        KeyCode::PageDown => {
            scroll(state, state.current_view_height() as isize);
            false
        }
        KeyCode::PageUp => {
            scroll(state, -(state.current_view_height() as isize));
            false
        }
        KeyCode::Home => {
            scroll_to_top(state);
            false
        }
        KeyCode::End => {
            scroll_to_bottom(state, stats, top_n);
            false
        }
        _ => false,
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

fn scroll_to_bottom(state: &mut AppState, stats: &Stats, top_n: usize) {
    match state.page {
        Page::Processes => {
            let len = stats.top_procs(top_n).len();
            state.proc_scroll = len.saturating_sub(state.proc_view_height);
        }
        Page::Ips => match state.ip_focus {
            IpFocus::Inbound => {
                let len = stats.top_in(top_n).len();
                state.ip_in_scroll = len.saturating_sub(state.ip_in_view_height);
            }
            IpFocus::Outbound => {
                let len = stats.top_out(top_n).len();
                state.ip_out_scroll = len.saturating_sub(state.ip_out_view_height);
            }
        },
        _ => {}
    }
}

// ── drawing ──

#[allow(clippy::too_many_arguments)]
fn draw(
    f: &mut ratatui::Frame,
    state: &mut AppState,
    stats: &Stats,
    interface: &str,
    started_at: Instant,
    top_n: usize,
) {
    let chunks = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    draw_title_bar(f, chunks[0], stats, interface, started_at);
    match state.page {
        Page::Overview => draw_overview(f, chunks[1], stats, top_n),
        Page::Processes => draw_processes(f, chunks[1], state, stats, top_n),
        Page::Ips => draw_ips(f, chunks[1], state, stats, top_n),
        Page::About => draw_about(f, chunks[1]),
    }
    draw_status_bar(f, chunks[2], state.page);
}

fn draw_title_bar(
    f: &mut ratatui::Frame,
    area: Rect,
    stats: &Stats,
    interface: &str,
    started_at: Instant,
) {
    let host = hostname();
    let now = chrono::Local::now();
    let title = format!(
        " delray | {} | host: {} | uptime: {} | In: {} Out: {} | {} ",
        interface,
        host,
        fmt_elapsed(started_at.elapsed()),
        human_bytes(stats.in_bytes),
        human_bytes(stats.out_bytes),
        now.format("%Y-%m-%d %H:%M:%S")
    );
    let para = Paragraph::new(title).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(para, area);
}

fn draw_overview(f: &mut ratatui::Frame, area: Rect, stats: &Stats, top_n: usize) {
    let chunks = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0)])
        .split(area);

    // In/Out bars
    let total = stats.in_bytes + stats.out_bytes;
    let in_ratio = if total > 0 {
        stats.in_bytes as f64 / total as f64
    } else {
        0.0
    };
    let out_ratio = if total > 0 {
        stats.out_bytes as f64 / total as f64
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
            human_bytes(stats.in_bytes),
            human_bytes(stats.out_bytes)
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

    let procs = stats.top_procs(top_n);
    let proc_items: Vec<ListItem> = procs
        .iter()
        .take(5)
        .map(|(pid, t)| {
            let name = stats.proc_name(*pid).unwrap_or("?");
            ListItem::new(format!(
                "{}  {}",
                truncate(name, 18),
                human_bytes(t.recv + t.sent)
            ))
        })
        .collect();
    let proc_block = preview_block("Top Processes", procs.len(), 5, 2);
    f.render_widget(List::new(proc_items).block(proc_block), cols[0]);

    let in_ips = stats.top_in(top_n);
    let in_items: Vec<ListItem> = in_ips
        .iter()
        .take(5)
        .map(|(ip, bytes)| ListItem::new(format!("{ip}  {}", human_bytes(*bytes))))
        .collect();
    let in_block = preview_block("Top Inbound IPs", in_ips.len(), 5, 3);
    f.render_widget(List::new(in_items).block(in_block), cols[1]);

    let out_ips = stats.top_out(top_n);
    let out_items: Vec<ListItem> = out_ips
        .iter()
        .take(5)
        .map(|(ip, bytes)| ListItem::new(format!("{ip}  {}", human_bytes(*bytes))))
        .collect();
    let out_block = preview_block("Top Outbound IPs", out_ips.len(), 5, 3);
    f.render_widget(List::new(out_items).block(out_block), cols[2]);
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

fn draw_processes(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &mut AppState,
    stats: &Stats,
    top_n: usize,
) {
    let procs = stats.top_procs(top_n);
    let rows: Vec<Row> = procs
        .iter()
        .map(|(pid, t)| {
            let name = stats.proc_name(*pid).unwrap_or("?");
            Row::new(vec![
                truncate(name, 40).to_string(),
                pid.to_string(),
                human_bytes(t.recv),
                human_bytes(t.sent),
                human_bytes(t.recv + t.sent),
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
            .title(format!(" Processes ({}) ", procs.len())),
    );

    let view_h = area.height.saturating_sub(4) as usize; // borders + header + padding
    state.proc_view_height = view_h.max(1);
    state.proc_scroll = state.proc_scroll.min(procs.len().saturating_sub(1));

    f.render_stateful_widget(
        table,
        area,
        &mut ratatui_state(procs.len(), state.proc_scroll),
    );
}

fn draw_ips(f: &mut ratatui::Frame, area: Rect, state: &mut AppState, stats: &Stats, top_n: usize) {
    let cols = Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let in_ips = stats.top_in(top_n);
    let out_ips = stats.top_out(top_n);

    let in_block_style = if state.ip_focus == IpFocus::Inbound {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    let out_block_style = if state.ip_focus == IpFocus::Outbound {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let in_rows: Vec<Row> = in_ips
        .iter()
        .map(|(ip, bytes)| Row::new(vec![ip.to_string(), human_bytes(*bytes)]))
        .collect();
    let in_table = Table::new(in_rows, [Constraint::Min(20), Constraint::Length(14)])
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
                .title(format!(" Inbound IPs ({}) ", in_ips.len()))
                .border_style(in_block_style),
        );

    let out_rows: Vec<Row> = out_ips
        .iter()
        .map(|(ip, bytes)| Row::new(vec![ip.to_string(), human_bytes(*bytes)]))
        .collect();
    let out_table = Table::new(out_rows, [Constraint::Min(20), Constraint::Length(14)])
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
                .title(format!(" Outbound IPs ({}) ", out_ips.len()))
                .border_style(out_block_style),
        );

    let in_vh = cols[0].height.saturating_sub(4) as usize;
    let out_vh = cols[1].height.saturating_sub(4) as usize;
    state.ip_in_view_height = in_vh.max(1);
    state.ip_out_view_height = out_vh.max(1);
    state.ip_in_scroll = state.ip_in_scroll.min(in_ips.len().saturating_sub(1));
    state.ip_out_scroll = state.ip_out_scroll.min(out_ips.len().saturating_sub(1));

    f.render_stateful_widget(
        in_table,
        cols[0],
        &mut ratatui_state(in_ips.len(), state.ip_in_scroll),
    );
    f.render_stateful_widget(
        out_table,
        cols[1],
        &mut ratatui_state(out_ips.len(), state.ip_out_scroll),
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
