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
use ratatui::layout::{Alignment, Constraint, Direction as LayoutDir, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use crate::pipeline::TrafficPipeline;
use crate::report::{fmt_elapsed, hostname, human_bytes, truncate};
use crate::stats::{IpSnapshot, TrafficSnapshot};

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
enum LayoutMode {
    Compact,
    Standard,
    Wide,
}

impl LayoutMode {
    fn from_area(area: Rect) -> Self {
        match area.width {
            120.. => Self::Wide,
            80.. => Self::Standard,
            _ => Self::Compact,
        }
    }
}

const MIN_TERMINAL_WIDTH: u16 = 60;
const MIN_TERMINAL_HEIGHT: u16 = 16;

const COLOR_BG: Color = Color::Rgb(9, 13, 20);
const COLOR_TEXT: Color = Color::Rgb(216, 224, 232);
const COLOR_STRONG: Color = Color::Rgb(244, 247, 250);
const COLOR_MUTED: Color = Color::Rgb(116, 129, 145);
const COLOR_BORDER: Color = Color::Rgb(37, 53, 68);
const COLOR_ACCENT: Color = Color::Rgb(255, 183, 3);
const COLOR_ACCENT_DIM: Color = Color::Rgb(154, 111, 8);
const COLOR_INBOUND: Color = Color::Rgb(255, 191, 36);
const COLOR_OUTBOUND: Color = Color::Rgb(41, 197, 246);
const COLOR_VIOLET: Color = Color::Rgb(167, 139, 250);
const COLOR_CORAL: Color = Color::Rgb(251, 113, 133);
const COLOR_SELECTION: Color = Color::Rgb(23, 43, 60);
const COLOR_INBOUND_BORDER: Color = Color::Rgb(102, 80, 30);
const COLOR_OUTBOUND_BORDER: Color = Color::Rgb(29, 86, 108);
const COLOR_VIOLET_BORDER: Color = Color::Rgb(76, 65, 111);

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

#[allow(clippy::too_many_arguments)]
fn draw(
    f: &mut ratatui::Frame,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    interface: &str,
    host: &str,
    started_at: Instant,
) {
    let area = f.area();
    f.render_widget(
        Block::default().style(Style::default().fg(COLOR_TEXT).bg(COLOR_BG)),
        area,
    );

    if area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT {
        draw_too_small(f, area);
        return;
    }

    let mode = LayoutMode::from_area(area);
    let chunks = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(f, chunks[0], state.page, interface, host, started_at, mode);
    let body = chunks[1].inner(Margin {
        horizontal: 1,
        vertical: 1,
    });
    match state.page {
        Page::Overview => draw_overview(f, body, snapshot, mode),
        Page::Processes => draw_processes(f, body, state, snapshot, mode),
        Page::Ips => draw_ips(f, body, state, snapshot, mode),
        Page::About => draw_about(f, body),
    }
    draw_status_bar(f, chunks[2], state.page, mode);
}

fn draw_too_small(f: &mut ratatui::Frame, area: Rect) {
    let message_area = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(3),
            Constraint::Fill(1),
        ])
        .split(area)[1];
    let lines = vec![
        Line::from(Span::styled(
            "delray",
            Style::default()
                .fg(COLOR_ACCENT)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("Terminal too small (minimum {MIN_TERMINAL_WIDTH}x{MIN_TERMINAL_HEIGHT})"),
            Style::default().fg(COLOR_MUTED),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center),
        message_area,
    );
}

fn draw_header(
    f: &mut ratatui::Frame,
    area: Rect,
    page: Page,
    interface: &str,
    host: &str,
    started_at: Instant,
    mode: LayoutMode,
) {
    let navigation = navigation_line(page, mode);
    if page == Page::About {
        f.render_widget(Paragraph::new(navigation), area);
        return;
    }

    let runtime = runtime_line(interface, host, started_at, mode);
    let runtime_width = (runtime.width() as u16).min(area.width / 2);
    let chunks = Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(runtime_width)])
        .split(area);
    f.render_widget(Paragraph::new(navigation), chunks[0]);
    f.render_widget(
        Paragraph::new(runtime).alignment(Alignment::Right),
        chunks[1],
    );
}

fn navigation_line(page: Page, mode: LayoutMode) -> Line<'static> {
    let mut spans = vec![Span::styled(
        " delray ",
        Style::default()
            .fg(COLOR_ACCENT)
            .add_modifier(Modifier::BOLD),
    )];
    for candidate in Page::ALL {
        let label = match (candidate, mode) {
            (Page::Overview, LayoutMode::Compact) => " 1 ".to_string(),
            (Page::Processes, LayoutMode::Compact) => " 2 ".to_string(),
            (Page::Ips, LayoutMode::Compact) => " 3 ".to_string(),
            (Page::About, LayoutMode::Compact) => " 4 ".to_string(),
            (Page::Overview, _) => " 1 Overview ".to_string(),
            (Page::Processes, _) => " 2 Processes ".to_string(),
            (Page::Ips, _) => " 3 IPs ".to_string(),
            (Page::About, _) => " 4 About ".to_string(),
        };
        let style = if candidate == page {
            Style::default()
                .fg(COLOR_STRONG)
                .bg(Color::Rgb(43, 37, 15))
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(COLOR_MUTED)
        };
        spans.push(Span::styled(label, style));
    }
    Line::from(spans)
}

fn runtime_line(
    interface: &str,
    host: &str,
    started_at: Instant,
    mode: LayoutMode,
) -> Line<'static> {
    let mut spans = vec![
        Span::styled(" ", Style::default()),
        Span::styled(interface.to_string(), Style::default().fg(COLOR_STRONG)),
    ];
    if mode == LayoutMode::Wide {
        spans.push(Span::styled("  ", Style::default()));
        spans.push(Span::styled(
            host.to_string(),
            Style::default().fg(COLOR_STRONG),
        ));
    }
    spans.push(Span::styled("  up ", Style::default().fg(COLOR_MUTED)));
    spans.push(Span::styled(
        fmt_elapsed(started_at.elapsed()),
        Style::default().fg(COLOR_STRONG),
    ));
    if mode != LayoutMode::Compact {
        spans.push(Span::styled(
            format!("  {}", chrono::Local::now().format("%H:%M:%S")),
            Style::default().fg(COLOR_MUTED),
        ));
    }
    Line::from(spans)
}

fn draw_overview(f: &mut ratatui::Frame, area: Rect, snapshot: &TrafficSnapshot, mode: LayoutMode) {
    match mode {
        LayoutMode::Wide => {
            let columns = Layout::default()
                .direction(LayoutDir::Horizontal)
                .constraints([
                    Constraint::Percentage(42),
                    Constraint::Length(1),
                    Constraint::Percentage(58),
                ])
                .split(area);
            let left = Layout::default()
                .direction(LayoutDir::Vertical)
                .constraints([
                    Constraint::Length(6),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                ])
                .split(columns[0]);
            draw_traffic(f, left[0], snapshot);
            draw_ip_preview(f, left[2], snapshot, true);
            draw_ip_preview(f, left[4], snapshot, false);
            draw_process_preview(f, columns[2], snapshot, mode);
        }
        LayoutMode::Standard => {
            let rows = Layout::default()
                .direction(LayoutDir::Vertical)
                .constraints([
                    Constraint::Length(6),
                    Constraint::Length(1),
                    Constraint::Fill(2),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                ])
                .split(area);
            let ips = Layout::default()
                .direction(LayoutDir::Horizontal)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Length(1),
                    Constraint::Percentage(50),
                ])
                .split(rows[4]);
            draw_traffic(f, rows[0], snapshot);
            draw_process_preview(f, rows[2], snapshot, mode);
            draw_ip_preview(f, ips[0], snapshot, true);
            draw_ip_preview(f, ips[2], snapshot, false);
        }
        LayoutMode::Compact => {
            let rows = Layout::default()
                .direction(LayoutDir::Vertical)
                .constraints([
                    Constraint::Length(6),
                    Constraint::Length(1),
                    Constraint::Fill(2),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                ])
                .split(area);
            draw_traffic(f, rows[0], snapshot);
            draw_process_preview(f, rows[2], snapshot, mode);
            draw_ip_preview(f, rows[4], snapshot, true);
        }
    }
}

fn draw_traffic(f: &mut ratatui::Frame, area: Rect, snapshot: &TrafficSnapshot) {
    let block = panel_block(
        "net",
        "Traffic",
        None,
        COLOR_VIOLET,
        COLOR_VIOLET_BORDER,
        None,
    );
    let inner = block.inner(area);
    f.render_widget(block, area);

    let total = snapshot.in_bytes.saturating_add(snapshot.out_bytes);
    let inbound_ratio = ratio(snapshot.in_bytes, total);
    let outbound_ratio = ratio(snapshot.out_bytes, total);
    let lines = vec![
        traffic_line(
            "IN total",
            COLOR_INBOUND,
            inbound_ratio,
            &human_bytes(snapshot.in_bytes),
            inner.width,
        ),
        traffic_line(
            "OUT total",
            COLOR_OUTBOUND,
            outbound_ratio,
            &human_bytes(snapshot.out_bytes),
            inner.width,
        ),
        traffic_line(
            "Combined",
            COLOR_ACCENT_DIM,
            if total > 0 { 1.0 } else { 0.0 },
            &human_bytes(total),
            inner.width,
        ),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn ratio(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        value as f64 / total as f64
    }
}

fn traffic_line(label: &str, color: Color, ratio: f64, value: &str, width: u16) -> Line<'static> {
    const LABEL_WIDTH: usize = 10;
    let value_width = value.chars().count();
    let bar_width = (width as usize).saturating_sub(LABEL_WIDTH + value_width + 2);
    let filled = ((bar_width as f64 * ratio).round() as usize).min(bar_width);
    Line::from(vec![
        Span::styled(format!("{label:<LABEL_WIDTH$}"), Style::default().fg(color)),
        Span::styled("█".repeat(filled), Style::default().fg(color)),
        Span::styled(
            "─".repeat(bar_width.saturating_sub(filled)),
            Style::default().fg(COLOR_BORDER),
        ),
        Span::styled(format!("  {value}"), Style::default().fg(COLOR_STRONG)),
    ])
}

fn panel_block(
    prefix: &str,
    title: &str,
    count: Option<usize>,
    prefix_color: Color,
    border_color: Color,
    footer: Option<String>,
) -> Block<'static> {
    let mut title_spans = vec![
        Span::styled(
            format!(" {prefix} "),
            Style::default()
                .fg(prefix_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            title.to_string(),
            Style::default()
                .fg(COLOR_STRONG)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(count) = count {
        title_spans.push(Span::styled(
            format!(" {count} "),
            Style::default().fg(COLOR_MUTED),
        ));
    } else {
        title_spans.push(Span::raw(" "));
    }

    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(Line::from(title_spans));
    if let Some(footer) = footer {
        block = block.title_bottom(
            Line::from(Span::styled(
                format!(" {footer} "),
                Style::default().fg(COLOR_MUTED),
            ))
            .alignment(Alignment::Right),
        );
    }
    block
}

fn draw_processes(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
) {
    let view_h = area.height.saturating_sub(3) as usize;
    state.proc_view_height = view_h.max(1);
    state.proc_scroll = state
        .proc_scroll
        .min(snapshot.processes.len().saturating_sub(1));

    let footer = selected_position(state.proc_scroll, snapshot.processes.len());
    let block = panel_block(
        "proc",
        "Processes",
        Some(snapshot.processes.len()),
        COLOR_CORAL,
        COLOR_CORAL,
        Some(footer),
    );
    let table = process_table(snapshot, mode, block)
        .row_highlight_style(
            Style::default()
                .fg(COLOR_STRONG)
                .bg(COLOR_SELECTION)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    f.render_stateful_widget(
        table,
        area,
        &mut ratatui_state(snapshot.processes.len(), state.proc_scroll),
    );
}

fn draw_process_preview(
    f: &mut ratatui::Frame,
    area: Rect,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
) {
    let footer = preview_position(snapshot.processes.len(), area.height);
    let block = panel_block(
        "proc",
        "Top Processes",
        Some(snapshot.processes.len()),
        COLOR_CORAL,
        COLOR_CORAL,
        Some(footer),
    );
    let table = process_table(snapshot, mode, block)
        .row_highlight_style(
            Style::default()
                .fg(COLOR_STRONG)
                .bg(COLOR_SELECTION)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    f.render_stateful_widget(table, area, &mut ratatui_state(snapshot.processes.len(), 0));
}

fn process_table(
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    block: Block<'static>,
) -> Table<'static> {
    let compact = mode == LayoutMode::Compact;
    let rows = process_rows(snapshot, compact);
    let header_style = Style::default().fg(COLOR_MUTED);
    let table = if compact {
        Table::new(
            rows,
            [
                Constraint::Min(18),
                Constraint::Length(12),
                Constraint::Length(12),
            ],
        )
        .header(Row::new(vec!["Process", "Sent", "Total"]).style(header_style))
    } else {
        Table::new(
            rows,
            [
                Constraint::Min(20),
                Constraint::Length(10),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(12),
            ],
        )
        .header(Row::new(vec!["Process", "PID", "Recv", "Sent", "Total"]).style(header_style))
    };
    table.column_spacing(1).block(block)
}

fn process_rows(snapshot: &TrafficSnapshot, compact: bool) -> Vec<Row<'static>> {
    if snapshot.processes.is_empty() {
        let cells = if compact {
            vec![
                Cell::from("No traffic observed"),
                Cell::from(""),
                Cell::from(""),
            ]
        } else {
            vec![
                Cell::from("No traffic observed"),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ]
        };
        return vec![Row::new(cells).style(Style::default().fg(COLOR_MUTED))];
    }

    snapshot
        .processes
        .iter()
        .map(|process| {
            let name = truncate(process.name.as_deref().unwrap_or("?"), 40).to_string();
            let total = process.recv.saturating_add(process.sent);
            if compact {
                Row::new(vec![
                    Cell::from(name),
                    Cell::from(human_bytes(process.sent))
                        .style(Style::default().fg(COLOR_OUTBOUND)),
                    Cell::from(human_bytes(total)).style(Style::default().fg(COLOR_STRONG)),
                ])
            } else {
                Row::new(vec![
                    Cell::from(name),
                    Cell::from(process.pid.to_string()),
                    Cell::from(human_bytes(process.recv)).style(Style::default().fg(COLOR_INBOUND)),
                    Cell::from(human_bytes(process.sent))
                        .style(Style::default().fg(COLOR_OUTBOUND)),
                    Cell::from(human_bytes(total)).style(Style::default().fg(COLOR_STRONG)),
                ])
            }
        })
        .collect()
}

fn selected_position(selected: usize, len: usize) -> String {
    if len == 0 {
        "0/0".to_string()
    } else {
        format!("{}/{}", selected.min(len - 1) + 1, len)
    }
}

fn preview_position(len: usize, height: u16) -> String {
    if len == 0 {
        return "0/0".to_string();
    }
    let shown = len.min(height.saturating_sub(3) as usize);
    format!("1-{shown}/{len}")
}

fn draw_ips(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
) {
    let panes = if mode == LayoutMode::Compact {
        Layout::default()
            .direction(LayoutDir::Vertical)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Length(1),
                Constraint::Percentage(50),
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(LayoutDir::Horizontal)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Length(1),
                Constraint::Percentage(50),
            ])
            .split(area)
    };

    let inbound_area = panes[0];
    let outbound_area = panes[2];
    let in_vh = inbound_area.height.saturating_sub(3) as usize;
    let out_vh = outbound_area.height.saturating_sub(3) as usize;
    state.ip_in_view_height = in_vh.max(1);
    state.ip_out_view_height = out_vh.max(1);
    state.ip_in_scroll = state
        .ip_in_scroll
        .min(snapshot.inbound_ips.len().saturating_sub(1));
    state.ip_out_scroll = state
        .ip_out_scroll
        .min(snapshot.outbound_ips.len().saturating_sub(1));

    draw_ip_table(
        f,
        inbound_area,
        snapshot.inbound_ips.as_ref(),
        true,
        state.ip_focus == IpFocus::Inbound,
        state.ip_in_scroll,
    );
    draw_ip_table(
        f,
        outbound_area,
        snapshot.outbound_ips.as_ref(),
        false,
        state.ip_focus == IpFocus::Outbound,
        state.ip_out_scroll,
    );
}

fn draw_ip_preview(f: &mut ratatui::Frame, area: Rect, snapshot: &TrafficSnapshot, inbound: bool) {
    let entries = if inbound {
        snapshot.inbound_ips.as_ref()
    } else {
        snapshot.outbound_ips.as_ref()
    };
    let (prefix, title, color, border) = ip_theme(inbound);
    let block = panel_block(
        prefix,
        title,
        Some(entries.len()),
        color,
        border,
        Some(preview_position(entries.len(), area.height)),
    );
    let table = ip_table(entries, color, block);
    f.render_widget(table, area);
}

fn draw_ip_table(
    f: &mut ratatui::Frame,
    area: Rect,
    entries: &[IpSnapshot],
    inbound: bool,
    focused: bool,
    selected: usize,
) {
    let (prefix, title, color, border) = ip_theme(inbound);
    let block = panel_block(
        prefix,
        title,
        Some(entries.len()),
        color,
        if focused { COLOR_CORAL } else { border },
        Some(selected_position(selected, entries.len())),
    );
    let table = ip_table(entries, color, block)
        .row_highlight_style(if focused {
            Style::default()
                .fg(COLOR_STRONG)
                .bg(COLOR_SELECTION)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        })
        .highlight_symbol(if focused { "> " } else { "  " });
    f.render_stateful_widget(table, area, &mut ratatui_state(entries.len(), selected));
}

fn ip_theme(inbound: bool) -> (&'static str, &'static str, Color, Color) {
    if inbound {
        ("in", "Inbound IPs", COLOR_INBOUND, COLOR_INBOUND_BORDER)
    } else {
        ("out", "Outbound IPs", COLOR_OUTBOUND, COLOR_OUTBOUND_BORDER)
    }
}

fn ip_table(entries: &[IpSnapshot], color: Color, block: Block<'static>) -> Table<'static> {
    let rows = if entries.is_empty() {
        vec![Row::new(vec!["No traffic observed", ""]).style(Style::default().fg(COLOR_MUTED))]
    } else {
        entries
            .iter()
            .map(|entry| {
                Row::new(vec![
                    Cell::from(entry.ip.to_string()),
                    Cell::from(human_bytes(entry.bytes)).style(Style::default().fg(color)),
                ])
            })
            .collect()
    };
    Table::new(rows, [Constraint::Min(20), Constraint::Length(14)])
        .header(Row::new(vec!["Remote address", "Bytes"]).style(Style::default().fg(COLOR_MUTED)))
        .column_spacing(1)
        .block(block)
}

fn draw_about(f: &mut ratatui::Frame, area: Rect) {
    let version = env!("CARGO_PKG_VERSION");
    let frame_width = area.width.saturating_sub(4).min(62);
    let horizontal = Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(frame_width),
            Constraint::Fill(1),
        ])
        .split(area)[1];
    let frame_area = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(7),
            Constraint::Fill(1),
        ])
        .split(horizontal)[1];
    let frame = Block::default()
        .borders(Borders::TOP | Borders::BOTTOM)
        .border_style(Style::default().fg(COLOR_BORDER));
    let content_area = frame.inner(frame_area);
    f.render_widget(frame, frame_area);

    let lines = vec![
        Line::from(Span::styled(
            "delray",
            Style::default()
                .fg(COLOR_ACCENT)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Network Traffic Analyzer",
            Style::default().fg(COLOR_STRONG),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("Version {version}"),
            Style::default().fg(COLOR_MUTED),
        )),
    ];
    let para = Paragraph::new(lines).alignment(Alignment::Center);
    f.render_widget(para, content_area);
}

fn draw_status_bar(f: &mut ratatui::Frame, area: Rect, page: Page, mode: LayoutMode) {
    let mut spans = Vec::new();
    push_hint(&mut spans, "1-4", "page");
    push_hint(&mut spans, "h/l", "switch");
    if page == Page::Ips {
        push_hint(&mut spans, "Tab", "panel");
    }
    if matches!(page, Page::Processes | Page::Ips) {
        push_hint(&mut spans, "j/k", "scroll");
        if mode != LayoutMode::Compact {
            push_hint(&mut spans, "PgUp/PgDn", "page");
            push_hint(&mut spans, "Home/End", "jump");
        }
    }

    let chunks = Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(8)])
        .split(area);
    f.render_widget(Paragraph::new(Line::from(spans)), chunks[0]);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "q",
                Style::default()
                    .fg(COLOR_CORAL)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" quit ", Style::default().fg(COLOR_MUTED)),
        ]))
        .alignment(Alignment::Right),
        chunks[1],
    );
}

fn push_hint(spans: &mut Vec<Span<'static>>, key: &str, action: &str) {
    if !spans.is_empty() {
        spans.push(Span::raw("  "));
    } else {
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(
        key.to_string(),
        Style::default()
            .fg(COLOR_ACCENT)
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::styled(
        format!(" {action}"),
        Style::default().fg(COLOR_MUTED),
    ));
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

    #[test]
    fn layout_mode_uses_three_width_breakpoints() {
        assert_eq!(
            LayoutMode::from_area(Rect::new(0, 0, 72, 24)),
            LayoutMode::Compact
        );
        assert_eq!(
            LayoutMode::from_area(Rect::new(0, 0, 80, 24)),
            LayoutMode::Standard
        );
        assert_eq!(
            LayoutMode::from_area(Rect::new(0, 0, 119, 30)),
            LayoutMode::Standard
        );
        assert_eq!(
            LayoutMode::from_area(Rect::new(0, 0, 120, 30)),
            LayoutMode::Wide
        );
    }

    #[test]
    fn processes_page_renders_from_snapshot() {
        let snapshot = TrafficSnapshot {
            in_bytes: 40,
            out_bytes: 60,
            processes: vec![ProcessSnapshot {
                pid: 7,
                name: Some(Arc::from("curl --silent")),
                recv: 40,
                sent: 60,
            }]
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
    fn overview_page_renders_from_snapshot() {
        let snapshot = TrafficSnapshot {
            in_bytes: 1024,
            out_bytes: 2048,
            processes: vec![ProcessSnapshot {
                pid: 7,
                name: Some(Arc::from("curl --silent")),
                recv: 1024,
                sent: 2048,
            }]
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
        assert!(rendered.contains("3.00 KB"));
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
    fn compact_processes_hide_lower_priority_columns() {
        let snapshot = TrafficSnapshot {
            processes: vec![ProcessSnapshot {
                pid: 7,
                name: Some(Arc::from("curl")),
                recv: 40,
                sent: 60,
            }]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        let mut terminal = Terminal::new(TestBackend::new(72, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Process"));
        assert!(rendered.contains("Sent"));
        assert!(rendered.contains("Total"));
        assert!(!rendered.contains("PID"));
        assert!(!rendered.contains("Recv"));
    }

    #[test]
    fn about_page_does_not_render_capture_context() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        state.page = Page::About;
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();

        terminal
            .draw(|frame| {
                draw(
                    frame,
                    &mut state,
                    &snapshot,
                    "private-interface",
                    "private-host",
                    Instant::now(),
                )
            })
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Network Traffic Analyzer"));
        assert!(rendered.contains("Version"));
        assert!(!rendered.contains("private-interface"));
        assert!(!rendered.contains("private-host"));
        assert!(!rendered.contains("uptime"));
    }

    #[test]
    fn about_page_frames_identity_with_horizontal_rules() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        state.page = Page::About;
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let lines = rendered_lines(&terminal);
        let identity_row = lines
            .iter()
            .rposition(|line| line.contains("delray"))
            .expect("about identity");
        assert!(
            lines[..identity_row]
                .iter()
                .any(|line| line.contains("────────"))
        );
        assert!(
            lines[identity_row + 1..]
                .iter()
                .any(|line| line.contains("────────"))
        );
    }

    #[test]
    fn compact_layout_prioritizes_panels_by_page() {
        let snapshot = TrafficSnapshot::default();
        let mut terminal = Terminal::new(TestBackend::new(72, 24)).unwrap();
        let mut state = AppState::new();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();
        let overview = rendered_lines(&terminal).join("\n");
        assert!(overview.contains("Inbound IPs"));
        assert!(!overview.contains("Outbound IPs"));

        state.page = Page::Ips;
        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();
        let ips = rendered_lines(&terminal).join("\n");
        assert!(ips.contains("Inbound IPs"));
        assert!(ips.contains("Outbound IPs"));
    }

    #[test]
    fn undersized_terminal_shows_minimum_size_message() {
        let snapshot = TrafficSnapshot::default();
        let mut terminal = Terminal::new(TestBackend::new(59, 15)).unwrap();
        let mut state = AppState::new();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Terminal too small"));
        assert!(!rendered.contains("eth0"));
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
