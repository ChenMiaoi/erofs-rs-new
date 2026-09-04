use std::{
    collections::VecDeque,
    io::{self, IsTerminal},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use erofs_lab::campaign::{
    CampaignCaseReport, CampaignPhase, CampaignProgress, CampaignSummary, PublishedCampaign,
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Gauge, Paragraph, Row, Sparkline, Table, Wrap},
};

const RECENT_CASE_LIMIT: usize = 200;
const THROUGHPUT_BUCKETS: usize = 120;
const REDRAW_INTERVAL: Duration = Duration::from_millis(100);
const COMPACT_WIDTH: u16 = 76;
const COMPACT_HEIGHT: u16 = 18;

/// Visual severity of a recent-case log line or outcome panel.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tone {
    Normal,
    Muted,
    Warning,
    Error,
}

impl Tone {
    fn style(self) -> Style {
        match self {
            Self::Normal => Style::default(),
            Self::Muted => Style::default().fg(Color::DarkGray),
            Self::Warning => Style::default().fg(Color::Yellow),
            Self::Error => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        }
    }
}

struct LogEntry {
    text: String,
    tone: Tone,
}

/// Running counts of oracle verdicts, used by the distribution panel.
#[derive(Default)]
struct OracleTally {
    accepted: u64,
    rejected: u64,
    crashed: u64,
    timeouts: u64,
    resource_exhausted: u64,
    harness_errors: u64,
    other: u64,
}

impl OracleTally {
    fn add(&mut self, status: &str) {
        match status {
            "accepted" => self.accepted += 1,
            "rejected" => self.rejected += 1,
            "crashed" => self.crashed += 1,
            "timed_out" | "timeout" => self.timeouts += 1,
            "resource_exhausted" => self.resource_exhausted += 1,
            "harness_error" => self.harness_errors += 1,
            _ => self.other += 1,
        }
    }
}

/// Everything the draw routine needs; shared with the input listener so key
/// presses (scroll, help) repaint immediately instead of waiting for the next
/// campaign progress update.
struct SharedState {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    total_cases: usize,
    completed_cases: usize,
    samples_materialized: u64,
    oracle_runs: u64,
    duplicate_bytes: usize,
    planning_errors: usize,
    interesting_results: usize,
    expected_accepted: usize,
    expected_rejected: usize,
    expectation_mismatches: usize,
    oracle: OracleTally,
    elapsed: Duration,
    wall_time_budget: Duration,
    phase: CampaignPhase,
    current_expectation: String,
    current_mismatch: bool,
    current_finding: String,
    case_id: String,
    generator: String,
    mutation_count: usize,
    last_outcome: String,
    last_outcome_tone: Tone,
    completion_mode: bool,
    show_help: bool,
    /// Lines the recent-case log is scrolled up from the latest entry.
    scroll_offset: u64,
    recent: VecDeque<LogEntry>,
    /// Cases-per-second samples, one per second, newest last.
    throughput: VecDeque<u64>,
    last_throughput_sample: (Instant, usize),
    last_draw: Instant,
}

/// AFL-style live view for one deterministic EROFS mutation campaign.
pub struct CampaignDashboard {
    shared: Arc<Mutex<SharedState>>,
    stop_listener: Arc<AtomicBool>,
    listener: Option<thread::JoinHandle<()>>,
    acknowledged: Arc<AtomicBool>,
}

pub fn is_supported() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn lock(shared: &Arc<Mutex<SharedState>>) -> MutexGuard<'_, SharedState> {
    shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl CampaignDashboard {
    pub fn start(control: erofs_lab::campaign::CampaignControl) -> Result<Self> {
        if !is_supported() {
            bail!("interactive dashboard requires a terminal");
        }
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, cursor::Hide) {
            let _ = disable_raw_mode();
            return Err(error.into());
        }
        let shared = Arc::new(Mutex::new(SharedState {
            terminal: Terminal::new(CrosstermBackend::new(stdout))?,
            total_cases: 0,
            completed_cases: 0,
            samples_materialized: 0,
            oracle_runs: 0,
            duplicate_bytes: 0,
            planning_errors: 0,
            interesting_results: 0,
            expected_accepted: 0,
            expected_rejected: 0,
            expectation_mismatches: 0,
            oracle: OracleTally::default(),
            elapsed: Duration::ZERO,
            wall_time_budget: Duration::ZERO,
            phase: CampaignPhase::Planning,
            case_id: "waiting for generated recipe".into(),
            generator: "not started".into(),
            mutation_count: 0,
            current_expectation: "exploratory".into(),
            current_mismatch: false,
            current_finding: "no oracle result yet".into(),
            last_outcome: "No completed cases yet".into(),
            last_outcome_tone: Tone::Normal,
            completion_mode: false,
            show_help: false,
            scroll_offset: 0,
            recent: VecDeque::new(),
            throughput: VecDeque::new(),
            last_throughput_sample: (Instant::now(), 0),
            last_draw: Instant::now() - Duration::from_secs(1),
        }));
        let stop_listener = Arc::new(AtomicBool::new(false));
        let acknowledged = Arc::new(AtomicBool::new(false));
        let listener_stop = Arc::clone(&stop_listener);
        let listener_acknowledged = Arc::clone(&acknowledged);
        let listener_shared = Arc::clone(&shared);
        let control = Arc::new(control);
        let listener = thread::spawn(move || {
            while !listener_stop.load(Ordering::Relaxed) {
                if matches!(event::poll(Duration::from_millis(100)), Ok(true))
                    && let Ok(Event::Key(key)) = event::read()
                {
                    if key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        control.cancel();
                        continue;
                    }
                    let mut state = lock(&listener_shared);
                    if state.completion_mode
                        && matches!(key.code, KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q'))
                    {
                        listener_acknowledged.store(true, Ordering::Relaxed);
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('?') | KeyCode::Char('h') => {
                            state.show_help = !state.show_help;
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            state.scroll_offset = state.scroll_offset.saturating_add(1);
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            state.scroll_offset = state.scroll_offset.saturating_sub(1);
                        }
                        KeyCode::PageUp => {
                            state.scroll_offset = state.scroll_offset.saturating_add(10);
                        }
                        KeyCode::PageDown => {
                            state.scroll_offset = state.scroll_offset.saturating_sub(10);
                        }
                        KeyCode::End | KeyCode::Char('G') => {
                            state.scroll_offset = 0;
                        }
                        _ => continue,
                    }
                    let _ = state.render();
                }
            }
        });
        let dashboard = Self {
            shared,
            stop_listener,
            listener: Some(listener),
            acknowledged,
        };
        lock(&dashboard.shared).render()?;
        Ok(dashboard)
    }

    pub fn set_status(&self, phase: &str, detail: &str) -> Result<()> {
        let mut state = lock(&self.shared);
        state.case_id = phase.into();
        state.generator = detail.into();
        state.last_outcome = detail.into();
        state.last_outcome_tone = Tone::Normal;
        state.render()
    }

    #[allow(clippy::significant_drop_tightening)]
    pub fn update(&self, progress: CampaignProgress<'_>) -> Result<()> {
        let mut state = lock(&self.shared);
        state.total_cases = progress.total_cases;
        state.completed_cases = progress.completed_cases;
        state.samples_materialized = progress.samples_materialized;
        state.oracle_runs = progress.oracle_runs;
        state.elapsed = progress.elapsed;
        state.wall_time_budget = progress.wall_time_budget;
        state.phase = progress.phase;
        state.current_expectation = match progress.expectation {
            erofs_lab::campaign::SeedExpectation::Accepted => "expected accepted",
            erofs_lab::campaign::SeedExpectation::Rejected => "expected rejected",
            erofs_lab::campaign::SeedExpectation::Exploratory => "exploratory",
        }
        .into();
        state.current_mismatch = progress.expectation_mismatch;
        state.current_finding = if progress.expectation_mismatch {
            "EXPECTATION MISMATCH".into()
        } else if let Some(case) = progress.completed_case {
            case.oracle_results
                .iter()
                .find(|result| !matches!(result.status.as_str(), "accepted" | "rejected"))
                .map(|result| format!("{}: {}", result.profile, result.status))
                .unwrap_or_else(|| "no finding".into())
        } else {
            "awaiting oracle result".into()
        };
        state.case_id = progress.case_id.to_owned();
        state.generator = progress.generator.to_owned();
        state.mutation_count = progress.mutation_count;
        if let Some(case) = progress.completed_case {
            state.duplicate_bytes += usize::from(case.duplicate_bytes);
            state.planning_errors += usize::from(case.planning_error.is_some());
            state.interesting_results += case
                .oracle_results
                .iter()
                .filter(|result| !matches!(result.status.as_str(), "accepted" | "rejected"))
                .count();
            for result in &case.oracle_results {
                state.oracle.add(result.status.as_str());
            }
            let tone = case_tone(case);
            state.recent.push_back(LogEntry {
                text: case_outcome(case),
                tone,
            });
            while state.recent.len() > RECENT_CASE_LIMIT {
                state.recent.pop_front();
            }
            state.last_outcome = case_outcome(case);
            state.last_outcome_tone = tone;
            match case.expectation {
                erofs_lab::campaign::SeedExpectation::Accepted => state.expected_accepted += 1,
                erofs_lab::campaign::SeedExpectation::Rejected => state.expected_rejected += 1,
                erofs_lab::campaign::SeedExpectation::Exploratory => {}
            }
            state.expectation_mismatches += usize::from(case.expectation_mismatch);
        }
        let now = Instant::now();
        let (sampled_at, sampled_cases) = state.last_throughput_sample;
        let sample_window = now.duration_since(sampled_at).as_secs_f64();
        if sample_window >= 1.0 {
            let rate = (state.completed_cases - sampled_cases) as f64 / sample_window;
            state.throughput.push_back(rate.round() as u64);
            while state.throughput.len() > THROUGHPUT_BUCKETS {
                state.throughput.pop_front();
            }
            state.last_throughput_sample = (now, state.completed_cases);
        }
        if state.last_draw.elapsed() >= REDRAW_INTERVAL
            || matches!(state.phase, CampaignPhase::Complete)
        {
            state.render()?;
        }
        Ok(())
    }

    pub fn finish(&self, published: &PublishedCampaign) -> Result<()> {
        {
            let mut state = lock(&self.shared);
            let summary = CampaignSummary::from_report(&published.result);
            state.completion_mode = true;
            state.last_outcome_tone = if summary.expectation_mismatches > 0 || summary.crashes > 0 {
                Tone::Error
            } else {
                Tone::Normal
            };
            state.last_outcome = format!(
                "Stop: {}  |  completed: {}  |  materialized: {}  |  duplicate bytes: {}  |  planning errors: {}\nExpected: accepted {}  rejected {}  |  expectation mismatches: {}\nOracle outcomes: accepted {}  rejected {}  crashes {}  timeouts {}  resource exhausted {}  harness errors {}\nRecipe: {}\nReport: {}\nNovelty: {}",
                published.result.stopped_reason,
                summary.cases_completed,
                summary.samples_materialized,
                summary.duplicate_bytes,
                summary.planning_errors,
                summary.expected_accepted,
                summary.expected_rejected,
                summary.expectation_mismatches,
                summary.accepted,
                summary.rejected,
                summary.crashes,
                summary.timeouts,
                summary.resource_exhausted,
                summary.harness_errors,
                published.recipe.display(),
                published.report.display(),
                published.novelty.display(),
            );
            state.render()?;
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.acknowledged.load(Ordering::Relaxed) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }
}

impl SharedState {
    fn render(&mut self) -> Result<()> {
        let percent = percent(self.completed_cases, self.total_cases);
        let pending = self.total_cases.saturating_sub(self.completed_cases);
        let elapsed = duration(self.elapsed);
        let budget = duration(self.wall_time_budget);
        let rate = if self.elapsed.is_zero() {
            0.0
        } else {
            self.completed_cases as f64 / self.elapsed.as_secs_f64()
        };
        let eta = if rate == 0.0 {
            "estimating".into()
        } else {
            duration(Duration::from_secs_f64(pending as f64 / rate))
        };
        let status_color = if self.planning_errors + self.interesting_results == 0 {
            Color::Green
        } else {
            Color::Red
        };
        let phase_color = phase_color(self.phase);
        let phase = self.phase.name();
        let completion_mode = self.completion_mode;
        let show_help = self.show_help;
        let scroll_offset = self.scroll_offset as usize;
        let header = Line::from(vec![
            Span::styled(
                " EROFS campaign ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!(" {phase} "),
                Style::default()
                    .fg(Color::Black)
                    .bg(phase_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {elapsed} elapsed / {budget} budget"),
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        let rows = vec![
            Row::new(vec!["Generator".to_owned(), self.generator.clone()]),
            Row::new(vec![
                "Mutations / case".to_owned(),
                self.mutation_count.to_string(),
            ]),
            Row::new(vec!["Queue".to_owned(), format!("{pending} remaining")]),
            Row::new(vec![
                "Throughput".to_owned(),
                format!("{rate:.2} cases/sec"),
            ]),
            Row::new(vec![
                "Time".to_owned(),
                format!("{elapsed} elapsed / {budget} budget; ETA {eta}"),
            ]),
            Row::new(vec![
                "Corpus".to_owned(),
                format!(
                    "{} unique samples; {} duplicate bytes",
                    self.samples_materialized, self.duplicate_bytes
                ),
            ]),
            Row::new(vec![
                "Current expectation".to_owned(),
                if self.current_mismatch {
                    format!("{} — MISMATCH", self.current_expectation)
                } else {
                    self.current_expectation.clone()
                },
            ])
            .style(Style::default().fg(if self.current_mismatch {
                Color::Red
            } else {
                Color::Yellow
            })),
            Row::new(vec![
                "Observed expectations".to_owned(),
                format!(
                    "accepted {}  rejected {}  mismatches {}",
                    self.expected_accepted, self.expected_rejected, self.expectation_mismatches
                ),
            ])
            .style(Style::default().fg(if self.expectation_mismatches == 0 {
                Color::Green
            } else {
                Color::Red
            })),
            Row::new(vec![
                "Oracle funnel".to_owned(),
                format!("{} executions", self.oracle_runs),
            ]),
            Row::new(vec![
                "Findings".to_owned(),
                format!(
                    "{} planning errors; {} abnormal oracle results",
                    self.planning_errors, self.interesting_results
                ),
            ])
            .style(Style::default().fg(status_color)),
            Row::new(vec![
                "Current finding".to_owned(),
                self.current_finding.clone(),
            ])
            .style(
                Style::default().fg(if self.current_finding == "no finding" {
                    Color::Green
                } else {
                    Color::Yellow
                }),
            ),
        ];
        let mut tally_ok = vec![
            count_span("accepted", self.oracle.accepted, Color::Green),
            Span::raw("   "),
            count_span("rejected", self.oracle.rejected, Color::Cyan),
        ];
        if self.oracle.other > 0 {
            tally_ok.push(Span::raw("   "));
            tally_ok.push(count_span("other", self.oracle.other, Color::DarkGray));
        }
        let tally_alert = Line::from(vec![
            count_span("crashed", self.oracle.crashed, Color::Red),
            Span::raw("   "),
            count_span("timeout", self.oracle.timeouts, Color::Yellow),
            Span::raw("   "),
            count_span("resource", self.oracle.resource_exhausted, Color::Yellow),
            Span::raw("   "),
            count_span("harness", self.oracle.harness_errors, Color::Red),
        ]);
        let tally_lines = vec![Line::from(tally_ok), tally_alert];
        let log_lines: Vec<Line> = self
            .recent
            .iter()
            .map(|entry| Line::from(Span::styled(entry.text.clone(), entry.tone.style())))
            .collect();
        let throughput: Vec<u64> = self.throughput.iter().copied().collect();
        let compact_info = vec![
            Line::from(vec![
                Span::styled(
                    phase,
                    Style::default()
                        .fg(phase_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(" · {}", self.generator)),
            ]),
            Line::from(format!(
                "queue {pending} · {rate:.2} cases/s · ETA {eta} · {elapsed} / {budget}"
            )),
            Line::from(format!(
                "corpus {} samples · {} dup bytes · {} oracle runs",
                self.samples_materialized, self.duplicate_bytes, self.oracle_runs
            )),
            Line::from(vec![
                Span::styled(
                    format!(
                        "expect a{} r{} mm{}",
                        self.expected_accepted, self.expected_rejected, self.expectation_mismatches
                    ),
                    Style::default().fg(if self.expectation_mismatches == 0 {
                        Color::Green
                    } else {
                        Color::Red
                    }),
                ),
                Span::raw("  "),
                Span::styled(
                    format!(
                        "findings pe{} ab{}",
                        self.planning_errors, self.interesting_results
                    ),
                    Style::default().fg(status_color),
                ),
            ]),
        ];
        let active = format!(
            "case {}/{}  id={}  {}",
            self.completed_cases + usize::from(self.phase != CampaignPhase::Complete),
            self.total_cases,
            short_id(&self.case_id),
            phase
        );
        let gauge_label = format!(
            "{} / {} cases ({}%)",
            self.completed_cases, self.total_cases, percent
        );
        let outcome = self.last_outcome.clone();
        let outcome_tone = self.last_outcome_tone;
        let footer = if completion_mode {
            (
                "Campaign complete — press Enter, Esc, or q to return to the terminal.",
                Style::default().fg(Color::Green),
            )
        } else if show_help {
            (
                "Ctrl-C stop · ↑/↓ or j/k scroll log · PgUp/PgDn page · End jump to latest · h/? close help",
                Style::default().fg(Color::Cyan),
            )
        } else {
            (
                "h/? keys · Ctrl-C stops · recipe, report, corpus, and novelty index are written atomically on completion",
                Style::default().fg(Color::DarkGray),
            )
        };
        self.terminal.draw(|frame| {
            let area = frame.area();
            let compact = area.width < COMPACT_WIDTH || area.height < COMPACT_HEIGHT;
            let gauge = Gauge::default()
                .block(panel(active.clone()))
                .gauge_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .label(gauge_label.clone())
                .percent(percent);
            let detail_title = if completion_mode {
                ("Campaign summary", Color::Green)
            } else {
                ("Last completed case", Color::Cyan)
            };
            let detail = Paragraph::new(outcome.clone())
                .style(outcome_tone.style())
                .wrap(Wrap { trim: true })
                .block(panel_styled(detail_title.0, detail_title.1));
            let footer_widget = Paragraph::new(footer.0)
                .style(footer.1)
                .block(panel("Controls"));
            if compact {
                let chunks = Layout::vertical([
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Min(4),
                    Constraint::Length(if completion_mode { 8 } else { 4 }),
                    Constraint::Length(3),
                ])
                .split(area);
                frame.render_widget(
                    Paragraph::new(header.clone()).block(panel("Dashboard")),
                    chunks[0],
                );
                frame.render_widget(gauge, chunks[1]);
                frame.render_widget(
                    Paragraph::new(compact_info.clone()).block(panel("Campaign activity")),
                    chunks[2],
                );
                frame.render_widget(detail, chunks[3]);
                frame.render_widget(footer_widget, chunks[4]);
            } else {
                let chunks = Layout::vertical([
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Min(12),
                    Constraint::Length(if completion_mode { 9 } else { 5 }),
                    Constraint::Length(3),
                ])
                .margin(1)
                .split(area);
                let middle =
                    Layout::horizontal([Constraint::Percentage(52), Constraint::Percentage(48)])
                        .split(chunks[2]);
                let right = Layout::vertical([
                    Constraint::Length(3),
                    Constraint::Length(4),
                    Constraint::Min(5),
                ])
                .split(middle[1]);
                frame.render_widget(Paragraph::new(header.clone()).block(panel("")), chunks[0]);
                frame.render_widget(gauge, chunks[1]);
                frame.render_widget(
                    Table::new(rows, [Constraint::Length(20), Constraint::Min(24)])
                        .header(
                            Row::new(["What is happening", "Current state"]).style(
                                Style::default()
                                    .fg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            ),
                        )
                        .column_spacing(2)
                        .block(panel("Campaign activity")),
                    middle[0],
                );
                frame.render_widget(
                    Sparkline::default()
                        .block(panel("Throughput · cases/sec"))
                        .data(&throughput)
                        .style(Style::default().fg(Color::Cyan)),
                    right[0],
                );
                frame.render_widget(
                    Paragraph::new(tally_lines.clone()).block(panel("Oracle verdicts")),
                    right[1],
                );
                let view_height = right[2].height.saturating_sub(2) as usize;
                let skip = log_lines.len().saturating_sub(view_height + scroll_offset);
                frame.render_widget(
                    Paragraph::new(log_lines.clone())
                        .block(panel("Recent cases · ↑/↓ scroll"))
                        .scroll((skip as u16, 0)),
                    right[2],
                );
                frame.render_widget(detail, chunks[3]);
                frame.render_widget(footer_widget, chunks[4]);
            }
        })?;
        self.last_draw = Instant::now();
        Ok(())
    }
}

impl Drop for CampaignDashboard {
    fn drop(&mut self) {
        self.stop_listener.store(true, Ordering::Relaxed);
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
        let mut state = lock(&self.shared);
        let _ = state.terminal.show_cursor();
        let _ = execute!(
            state.terminal.backend_mut(),
            LeaveAlternateScreen,
            cursor::Show
        );
        let _ = disable_raw_mode();
    }
}

fn panel(title: impl Into<Line<'static>>) -> Block<'static> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
}

fn panel_styled(title: &'static str, color: Color) -> Block<'static> {
    Block::default()
        .title(Span::styled(
            title,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
}

fn count_span(label: &'static str, count: u64, alert: Color) -> Span<'static> {
    let style = if count == 0 {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(alert).add_modifier(Modifier::BOLD)
    };
    Span::styled(format!("{label} {count}"), style)
}

fn phase_color(phase: CampaignPhase) -> Color {
    match phase {
        CampaignPhase::Planning => Color::Yellow,
        CampaignPhase::Materializing => Color::Cyan,
        CampaignPhase::RustOracle | CampaignPhase::FsckOracle => Color::Magenta,
        CampaignPhase::LinuxOracle => Color::Blue,
        CampaignPhase::Complete => Color::Green,
    }
}

fn case_tone(case: &CampaignCaseReport) -> Tone {
    if case.expectation_mismatch || case.planning_error.is_some() {
        Tone::Error
    } else if case
        .oracle_results
        .iter()
        .any(|result| !matches!(result.status.as_str(), "accepted" | "rejected"))
    {
        Tone::Warning
    } else if case.duplicate_bytes {
        Tone::Muted
    } else {
        Tone::Normal
    }
}

fn case_outcome(case: &CampaignCaseReport) -> String {
    let expectation = match case.expectation {
        erofs_lab::campaign::SeedExpectation::Exploratory => "exploratory",
        erofs_lab::campaign::SeedExpectation::Accepted => "expect accepted",
        erofs_lab::campaign::SeedExpectation::Rejected => "expect rejected",
    };
    if let Some(error) = &case.planning_error {
        return format!(
            "{} ({expectation}): planning error: {error}",
            short_id(&case.case_id)
        );
    }
    if case.duplicate_bytes {
        return format!(
            "{} ({expectation}): duplicate bytes; oracle execution skipped",
            short_id(&case.case_id)
        );
    }
    if case.oracle_results.is_empty() {
        return format!(
            "{} ({expectation}): materialized; no oracle funnel selected",
            short_id(&case.case_id)
        );
    }
    let results = case
        .oracle_results
        .iter()
        .map(|result| format!("{} {} / {}", result.profile, result.status, result.phase))
        .collect::<Vec<_>>()
        .join("; ");
    let mismatch = if case.expectation_mismatch {
        " — EXPECTATION MISMATCH"
    } else {
        ""
    };
    format!(
        "{} ({expectation}): {results}{mismatch}",
        short_id(&case.case_id)
    )
}

fn percent(numerator: usize, denominator: usize) -> u16 {
    u16::try_from(
        numerator
            .saturating_mul(100)
            .checked_div(denominator)
            .unwrap_or(0),
    )
    .unwrap_or(100)
}
fn duration(value: Duration) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        value.as_secs() / 3600,
        (value.as_secs() / 60) % 60,
        value.as_secs() % 60
    )
}
fn short_id(value: &str) -> &str {
    value.get(..16).unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::OracleTally;

    #[test]
    fn tally_counts_library_status_names() {
        let mut tally = OracleTally::default();
        tally.add("accepted");
        tally.add("rejected");
        tally.add("crashed");
        tally.add("timed_out");
        tally.add("resource_exhausted");
        tally.add("harness_error");
        assert_eq!(tally.accepted, 1);
        assert_eq!(tally.rejected, 1);
        assert_eq!(tally.crashed, 1);
        assert_eq!(tally.timeouts, 1);
        assert_eq!(tally.resource_exhausted, 1);
        assert_eq!(tally.harness_errors, 1);
        assert_eq!(tally.other, 0);
    }

    #[test]
    fn tally_accepts_legacy_timeout_alias() {
        let mut tally = OracleTally::default();
        tally.add("timeout");
        assert_eq!(tally.timeouts, 1);
        assert_eq!(tally.other, 0);
    }

    #[test]
    fn tally_keeps_unknown_statuses_in_other() {
        let mut tally = OracleTally::default();
        tally.add("cancelled");
        tally.add("unsupported");
        assert_eq!(tally.other, 2);
        assert_eq!(tally.timeouts, 0);
    }
}
