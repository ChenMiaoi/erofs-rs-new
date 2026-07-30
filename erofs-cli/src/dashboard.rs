use std::io::{self, IsTerminal, Write};

use anyhow::{Result, bail};
use crossterm::{
    cursor, execute, queue,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use erofs_lab::campaign::{CampaignCaseReport, CampaignProgress};

/// Minimal AFL-style live view for a deterministic campaign.
pub struct CampaignDashboard {
    stdout: io::Stdout,
    total_cases: usize,
    completed_cases: usize,
    samples_materialized: u64,
    oracle_runs: u64,
    duplicate_bytes: usize,
    planning_errors: usize,
    interesting_results: usize,
    last_case: String,
}

pub fn is_supported() -> bool {
    io::stdout().is_terminal()
}

impl CampaignDashboard {
    pub fn start() -> Result<Self> {
        if !is_supported() {
            bail!("interactive dashboard requires a terminal");
        }
        terminal::enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, cursor::Hide) {
            let _ = terminal::disable_raw_mode();
            return Err(error.into());
        }
        Ok(Self {
            stdout,
            total_cases: 0,
            completed_cases: 0,
            samples_materialized: 0,
            oracle_runs: 0,
            duplicate_bytes: 0,
            planning_errors: 0,
            interesting_results: 0,
            last_case: "waiting for first case".into(),
        })
    }

    pub fn update(&mut self, progress: CampaignProgress<'_>) -> Result<()> {
        self.total_cases = progress.total_cases;
        self.completed_cases = progress.completed_cases;
        self.samples_materialized = progress.samples_materialized;
        self.oracle_runs = progress.oracle_runs;
        self.record_case(progress.current_case);
        self.render()
    }

    fn record_case(&mut self, case: &CampaignCaseReport) {
        self.duplicate_bytes += usize::from(case.duplicate_bytes);
        self.planning_errors += usize::from(case.planning_error.is_some());
        self.interesting_results += case
            .oracle_results
            .iter()
            .filter(|result| !matches!(result.status.as_str(), "accepted" | "rejected"))
            .count();
        self.last_case.clone_from(&case.case_id);
    }

    fn render(&mut self) -> Result<()> {
        let progress = if self.total_cases == 0 {
            0
        } else {
            self.completed_cases * 100 / self.total_cases
        };
        let bar_width = 48;
        let filled = bar_width * progress / 100;
        let bar = format!("{}{}", "#".repeat(filled), "-".repeat(bar_width - filled));
        queue!(
            self.stdout,
            cursor::MoveTo(0, 0),
            Clear(ClearType::All),
            SetForegroundColor(Color::Cyan),
            Print("erofs-cli campaign fuzzing dashboard\n"),
            ResetColor,
            Print("────────────────────────────────────────────────────────────────\n"),
            Print(format!(
                " cases       : {:>6} / {:<6}  [{}] {:>3}%\n",
                self.completed_cases, self.total_cases, bar, progress
            )),
            Print(format!(
                " queue       : {:>6} pending\n",
                self.total_cases.saturating_sub(self.completed_cases)
            )),
            Print(format!(
                " corpus      : {:>6} materialized samples\n",
                self.samples_materialized
            )),
            Print(format!(
                " executions  : {:>6} oracle runs\n",
                self.oracle_runs
            )),
            SetForegroundColor(Color::Yellow),
            Print(format!(
                " duplicates  : {:>6} byte-identical cases\n",
                self.duplicate_bytes
            )),
            ResetColor,
            SetForegroundColor(if self.planning_errors + self.interesting_results == 0 {
                Color::Green
            } else {
                Color::Red
            }),
            Print(format!(
                " findings    : {:>6} planning errors, {:>6} abnormal oracle results\n",
                self.planning_errors, self.interesting_results
            )),
            ResetColor,
            Print("────────────────────────────────────────────────────────────────\n"),
            Print(format!(" last case   : {}\n", self.last_case)),
            Print(" progress updates after each completed case; Ctrl-C stops the process.\n"),
        )?;
        self.stdout.flush()?;
        Ok(())
    }
}

impl Drop for CampaignDashboard {
    fn drop(&mut self) {
        let _ = execute!(self.stdout, cursor::Show, LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}
