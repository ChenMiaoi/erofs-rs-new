use std::{
    io::{self, IsTerminal},
    sync::{
        Arc,
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
use erofs_lab::campaign::{CampaignPhase, CampaignProgress, CampaignSummary, PublishedCampaign};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Gauge, Paragraph, Row, Table, Wrap},
};

/// AFL-style live view for one deterministic EROFS mutation campaign.
pub struct CampaignDashboard {
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
    stop_listener: Arc<AtomicBool>,
    listener: Option<thread::JoinHandle<()>>,
    completion_mode: Arc<AtomicBool>,
    acknowledged: Arc<AtomicBool>,
    last_draw: Instant,
}

pub fn is_supported() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
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
        let stop_listener = Arc::new(AtomicBool::new(false));
        let completion_mode = Arc::new(AtomicBool::new(false));
        let acknowledged = Arc::new(AtomicBool::new(false));
        let listener_stop = Arc::clone(&stop_listener);
        let listener_completion = Arc::clone(&completion_mode);
        let listener_acknowledged = Arc::clone(&acknowledged);
        let control = Arc::new(control);
        let listener = thread::spawn(move || {
            while !listener_stop.load(Ordering::Relaxed) {
                if matches!(event::poll(Duration::from_millis(100)), Ok(true)) {
                    match event::read() {
                        Ok(Event::Key(key))
                            if key.code == KeyCode::Char('c')
                                && key.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            control.cancel()
                        }
                        Ok(Event::Key(key))
                            if listener_completion.load(Ordering::Relaxed)
                                && matches!(
                                    key.code,
                                    KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q')
                                ) =>
                        {
                            listener_acknowledged.store(true, Ordering::Relaxed)
                        }
                        Ok(_) | Err(_) => {}
                    }
                }
            }
        });
        let mut dashboard = Self {
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
            stop_listener,
            listener: Some(listener),
            completion_mode,
            acknowledged,
            last_draw: Instant::now() - Duration::from_secs(1),
        };
        dashboard.render()?;
        Ok(dashboard)
    }

    pub fn set_status(&mut self, phase: &str, detail: &str) -> Result<()> {
        self.case_id = phase.into();
        self.generator = detail.into();
        self.last_outcome = detail.into();
        self.render()
    }

    pub fn update(&mut self, progress: CampaignProgress<'_>) -> Result<()> {
        self.total_cases = progress.total_cases;
        self.completed_cases = progress.completed_cases;
        self.samples_materialized = progress.samples_materialized;
        self.oracle_runs = progress.oracle_runs;
        self.elapsed = progress.elapsed;
        self.wall_time_budget = progress.wall_time_budget;
        self.phase = progress.phase;
        self.current_expectation = match progress.expectation {
            erofs_lab::campaign::SeedExpectation::Accepted => "expected accepted",
            erofs_lab::campaign::SeedExpectation::Rejected => "expected rejected",
            erofs_lab::campaign::SeedExpectation::Exploratory => "exploratory",
        }
        .into();
        self.current_mismatch = progress.expectation_mismatch;
        self.current_finding = if progress.expectation_mismatch {
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
        self.case_id = progress.case_id.to_owned();
        self.generator = progress.generator.to_owned();
        self.mutation_count = progress.mutation_count;
        if let Some(case) = progress.completed_case {
            self.duplicate_bytes += usize::from(case.duplicate_bytes);
            self.planning_errors += usize::from(case.planning_error.is_some());
            self.interesting_results += case
                .oracle_results
                .iter()
                .filter(|result| !matches!(result.status.as_str(), "accepted" | "rejected"))
                .count();
            self.last_outcome = case_outcome(case);
            match case.expectation {
                erofs_lab::campaign::SeedExpectation::Accepted => self.expected_accepted += 1,
                erofs_lab::campaign::SeedExpectation::Rejected => self.expected_rejected += 1,
                erofs_lab::campaign::SeedExpectation::Exploratory => {}
            }
            self.expectation_mismatches += usize::from(case.expectation_mismatch);
        }
        if self.last_draw.elapsed() >= Duration::from_millis(100)
            || matches!(self.phase, CampaignPhase::Complete)
        {
            self.render()?;
        }
        Ok(())
    }

    pub fn finish(&mut self, published: &PublishedCampaign) -> Result<()> {
        let summary = CampaignSummary::from_report(&published.result);
        self.completion_mode.store(true, Ordering::Relaxed);
        self.last_outcome = format!(
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
        self.render()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.acknowledged.load(Ordering::Relaxed) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

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
        let case_id = short_id(&self.case_id).to_owned();
        let phase = self.phase.name();
        let completion_mode = self.completion_mode.load(Ordering::Relaxed);
        let detail_title = if completion_mode {
            "Campaign summary"
        } else {
            "Last completed case"
        };
        let footer = if completion_mode {
            "Campaign complete. Press Enter, Esc, or q to return to the terminal."
        } else {
            "Recipe, report, corpus, and novelty index are written atomically after campaign completion."
        };
        let rows = vec![
            Row::new(vec!["Current phase".to_owned(), phase.to_owned()])
                .style(Style::default().fg(Color::Yellow)),
            Row::new(vec!["Generator".to_owned(), self.generator.clone()]),
            Row::new(vec![
                "Mutations / case".to_owned(),
                self.mutation_count.to_string(),
            ]),
            Row::new(vec!["Queue".to_owned(), format!("{} remaining", pending)]),
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
        let active = format!(
            "case {}/{}  id={}  {}",
            self.completed_cases + usize::from(self.phase != CampaignPhase::Complete),
            self.total_cases,
            case_id,
            phase
        );
        let outcome = self.last_outcome.clone();
        self.terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Min(10),
                    Constraint::Length(if completion_mode { 8 } else { 4 }),
                    Constraint::Length(3),
                ])
                .split(frame.area());
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(
                        "EROFS campaign fuzzing dashboard",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  •  deterministic metadata mutations  •  Ctrl-C stops"),
                ]))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded),
                ),
                chunks[0],
            );
            frame.render_widget(
                Gauge::default()
                    .block(Block::default().title(active).borders(Borders::ALL))
                    .gauge_style(
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                    .label(format!(
                        "{} / {} cases ({}%)",
                        self.completed_cases, self.total_cases, percent
                    ))
                    .percent(percent),
                chunks[1],
            );
            frame.render_widget(
                Table::new(rows, [Constraint::Length(19), Constraint::Min(30)])
                    .header(
                        Row::new(["What is happening", "Current state"])
                            .style(Style::default().add_modifier(Modifier::BOLD)),
                    )
                    .column_spacing(2)
                    .block(
                        Block::default()
                            .title("Campaign activity")
                            .borders(Borders::ALL),
                    ),
                chunks[2],
            );
            frame.render_widget(
                Paragraph::new(outcome)
                    .wrap(Wrap { trim: true })
                    .block(Block::default().title(detail_title).borders(Borders::ALL)),
                chunks[3],
            );
            frame.render_widget(
                Paragraph::new(footer)
                    .style(Style::default().fg(if completion_mode {
                        Color::Green
                    } else {
                        Color::DarkGray
                    }))
                    .block(Block::default().title("Controls").borders(Borders::ALL)),
                chunks[4],
            );
        })?;
        self.last_draw = Instant::now();
        Ok(())
    }
}

fn case_outcome(case: &erofs_lab::campaign::CampaignCaseReport) -> String {
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

impl Drop for CampaignDashboard {
    fn drop(&mut self) {
        self.stop_listener.store(true, Ordering::Relaxed);
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
        let _ = self.terminal.show_cursor();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            cursor::Show
        );
        let _ = disable_raw_mode();
    }
}
