//! The Agent pane's Assessment tab: starting an AAVR run in opencode, and
//! the run as it stands in `.aavr/` (phases, candidates, attack surfaces,
//! fuzzing, crashes, report), read again every few seconds while shown.
//! A click on anything with a place goes there.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use egui::{Color32, RichText};

use super::aavr_run::{self, AavrRun, Classification, PhaseStatus};
use super::background::BackgroundJob;
use super::visible::visible;

/// How often the run is read again while shown.
const REFRESH: Duration = Duration::from_secs(5);
const DONE_COLOR: Color32 = Color32::from_rgb(0x6A, 0xBE, 0x6A);
const NEXT_COLOR: Color32 = Color32::from_rgb(0x5A, 0xA0, 0xF0);
const BLOCKED_COLOR: Color32 = Color32::from_rgb(0xE0, 0x9A, 0x4C);

/// What starting a run needs: opencode, and SrcWranglr in its config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Launcher {
    pub opencode: Option<PathBuf>,
    pub is_connected: bool,
    /// What `connect` runs, to show before it's run.
    pub connect_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AavrAction {
    GoTo { file: String, line: u32 },
    FindSymbol(String),
    Start,
    RunInApp,
    Connect,
    OpenReport(String),
}

#[derive(Default)]
pub struct AavrView {
    run: Option<AavrRun>,
    has_read: bool,
    job: Option<BackgroundJob<Option<AavrRun>>>,
    read_at: Option<Instant>,
    /// The folder read from, so another project's run isn't shown.
    read_for: Option<PathBuf>,
    /// What the last start or connect said.
    pub message: Option<Result<String, String>>,
    /// opencode's `mcp add`, while it runs.
    connecting: Option<BackgroundJob<String>>,
    /// Whether a connect finished since last asked (opencode's config may
    /// list SrcWranglr now).
    has_connected: bool,
}

impl AavrView {
    /// Forgets the run, for another project.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Shows `job` (opencode's `mcp add`) running, then what it said.
    pub fn connect(&mut self, job: BackgroundJob<String>) {
        self.connecting = Some(job);
        self.message = Some(Ok("Connecting SrcWranglr to opencode…".into()));
    }

    /// Whether a connect finished since last asked.
    pub fn take_connected(&mut self) -> bool {
        std::mem::take(&mut self.has_connected)
    }

    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        root: Option<&Path>,
        launcher: &Launcher,
    ) -> Option<AavrAction> {
        self.refresh(ui.ctx(), root);
        if let Some(result) = self.connecting.as_ref().and_then(BackgroundJob::poll) {
            self.connecting = None;
            self.has_connected = true;
            self.message = Some(result);
        }
        let mut action = launch_buttons(ui, root.is_some(), launcher);
        match &self.message {
            Some(Ok(said)) => {
                ui.weak(visible(said));
            }
            Some(Err(why)) => {
                ui.colored_label(BLOCKED_COLOR, visible(why));
            }
            None => {}
        }
        ui.separator();
        let Some(run) = &self.run else {
            match self.has_read {
                true => ui.weak("No AAVR run here yet. Start one above: opencode runs the aavr-orchestrate skill, which keeps its work in .aavr/."),
                false => ui.weak("Reading .aavr/…"),
            };
            return action;
        };
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if let Some(picked) = run_contents(ui, run) {
                    action = Some(picked);
                }
            });
        action
    }

    /// Reads the run again in the background if it's time to.
    fn refresh(&mut self, ctx: &egui::Context, root: Option<&Path>) {
        if self.read_for.as_deref() != root {
            let message = self.message.take();
            self.reset();
            self.message = message;
            self.read_for = root.map(Path::to_path_buf);
        }
        if let Some(job) = &self.job {
            if let Some(result) = job.poll() {
                self.run = result.ok().flatten();
                self.has_read = true;
                self.job = None;
                self.read_at = Some(Instant::now());
            }
            return;
        }
        let Some(root) = root else {
            self.has_read = true;
            return;
        };
        if self.read_at.is_some_and(|at| at.elapsed() < REFRESH) {
            ctx.request_repaint_after(REFRESH);
            return;
        }
        let root = root.to_path_buf();
        self.job = Some(BackgroundJob::spawn(
            "Reading the AAVR run",
            move |_| Ok(aavr_run::read(&root)),
            ctx.clone(),
        ));
    }
}

/// Start, and Connect when opencode doesn't list SrcWranglr yet.
fn launch_buttons(ui: &mut egui::Ui, has_folder: bool, launcher: &Launcher) -> Option<AavrAction> {
    let mut action = None;
    let can_start = has_folder && launcher.opencode.is_some();
    ui.horizontal_wrapped(|ui| {
        let start = ui
            .add_enabled(can_start, egui::Button::new("Start Assessment in opencode"))
            .on_hover_text("Opens opencode on this project in a terminal and asks it to run the aavr-orchestrate skill, with SrcWranglr's tools");
        if start.clicked() {
            action = Some(AavrAction::Start);
        }
        let run_in_app = ui
            .add_enabled(has_folder, egui::Button::new("Run in SrcWranglr"))
            .on_hover_text("Runs the agent loop inside SrcWranglr using the model set in Settings — no opencode. It builds and runs with your approval; watch the Agent pane.");
        if run_in_app.clicked() {
            action = Some(AavrAction::RunInApp);
        }
        if launcher.opencode.is_some() && !launcher.is_connected {
            let connect = ui
                .button("Connect SrcWranglr to opencode")
                .on_hover_text(format!("Runs: {}", launcher.connect_command));
            if connect.clicked() {
                action = Some(AavrAction::Connect);
            }
        }
    });
    if launcher.opencode.is_none() {
        ui.weak("opencode wasn't found: install it, or add its folder in Settings → Tools.");
    } else if !has_folder {
        ui.weak("Open a project folder to assess it.");
    } else if !launcher.is_connected {
        ui.weak(
            "opencode's config doesn't list SrcWranglr yet: Connect adds it, for every project.",
        );
    }
    action
}

fn run_contents(ui: &mut egui::Ui, run: &AavrRun) -> Option<AavrAction> {
    let mut action = None;
    match run.revision.is_empty() {
        true => ui.strong("AAVR run"),
        false => ui.strong(format!("AAVR run · revision {}", visible(&run.revision))),
    };
    phases(ui, run);
    for blocker in &run.blocked_on {
        ui.colored_label(BLOCKED_COLOR, format!("Blocked on: {}", visible(blocker)));
    }
    ui.add_space(4.0);
    action = action.or(candidates(ui, run));
    action = action.or(surfaces(ui, run));
    action = action.or(fuzzing(ui, run));
    if let Some(report) = &run.report {
        if ui
            .button("Open the Report")
            .on_hover_text(report.as_str())
            .clicked()
        {
            action = Some(AavrAction::OpenReport(report.clone()));
        }
    }
    for problem in &run.problems {
        ui.weak(format!("Couldn't read {}", visible(problem)));
    }
    action
}

/// The phases in a wrapped row: ✓ done, → next, ⏸ blocked, · not yet.
fn phases(ui: &mut egui::Ui, run: &AavrRun) {
    ui.horizontal_wrapped(|ui| {
        for (label, status) in &run.phases {
            let text = match status {
                PhaseStatus::Done => RichText::new(format!("✓ {label}")).color(DONE_COLOR),
                PhaseStatus::Next => RichText::new(format!("→ {label}"))
                    .color(NEXT_COLOR)
                    .strong(),
                PhaseStatus::Blocked => RichText::new(format!("⏸ {label}"))
                    .color(BLOCKED_COLOR)
                    .strong(),
                PhaseStatus::Pending => RichText::new(format!("· {label}")).weak(),
            };
            ui.label(text);
        }
    });
}

/// The candidates by classification, the strongest open.
fn candidates(ui: &mut egui::Ui, run: &AavrRun) -> Option<AavrAction> {
    let mut action = None;
    ui.strong(format!(
        "Candidates: {} triaged, {} from scanners",
        run.candidates.len(),
        run.raw_candidates
    ));
    for class in Classification::ALL {
        let items: Vec<_> = run
            .candidates
            .iter()
            .filter(|c| c.classification == class)
            .collect();
        if items.is_empty() {
            continue;
        }
        let is_open = matches!(class, Classification::Confirmed | Classification::Likely);
        let header = egui::CollapsingHeader::new(format!("{} ({})", class.label(), items.len()))
            .id_salt(("aavr-class", class.label()))
            .default_open(is_open)
            .show(ui, |ui| {
                items.iter().find_map(|c| {
                    let grade = [c.severity.as_str(), c.confidence.as_str()]
                        .into_iter()
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(" · ");
                    let text = format!(
                        "{}  {}  {}",
                        visible(&c.id),
                        visible(&c.title),
                        visible(&grade)
                    );
                    place_row(ui, &text, c.place.as_ref())
                })
            });
        action = action.or(header.body_returned.flatten());
    }
    action
}

fn surfaces(ui: &mut egui::Ui, run: &AavrRun) -> Option<AavrAction> {
    if run.surfaces.is_empty() {
        return None;
    }
    ui.strong(format!("Attack surfaces ({})", run.surfaces.len()));
    run.surfaces.iter().find_map(|s| {
        let detail = match s.detail.is_empty() {
            true => String::new(),
            false => format!("  → {}", visible(&s.detail)),
        };
        let priority = match s.priority.is_empty() {
            true => String::new(),
            false => format!("  ({})", visible(&s.priority)),
        };
        let text = format!("{}{detail}{priority}", visible(&s.title));
        place_row(ui, &text, s.place.as_ref())
    })
}

fn fuzzing(ui: &mut egui::Ui, run: &AavrRun) -> Option<AavrAction> {
    let mut action = None;
    if let Some(pick) = &run.harness {
        let text = format!(
            "Fuzz target: {} ({})",
            visible(&pick.target),
            visible(&pick.engine)
        );
        action = symbol_row(ui, &text, &pick.target);
    }
    if !run.crashes.is_empty() {
        let reproduced = run
            .crashes
            .iter()
            .filter(|c| c.is_reproducible == Some(true))
            .count();
        ui.strong(format!(
            "Crashes ({}, {reproduced} reproduced)",
            run.crashes.len()
        ));
        let picked = run.crashes.iter().find_map(|c| {
            let text = format!("{}  {}", visible(&c.id), visible(&c.classification));
            place_row(ui, &text, c.place.as_ref())
        });
        action = action.or(picked);
    }
    action
}

/// A row that goes to `place` when clicked, if it has one.
fn place_row(ui: &mut egui::Ui, text: &str, place: Option<&(String, u32)>) -> Option<AavrAction> {
    let Some((file, line)) = place else {
        ui.label(RichText::new(text).monospace());
        return None;
    };
    let row = ui
        .selectable_label(false, RichText::new(text).monospace())
        .on_hover_text(format!("Go to {}:{line}", visible(file)));
    row.clicked().then(|| AavrAction::GoTo {
        file: file.clone(),
        line: *line,
    })
}

/// A row that finds `name` when clicked.
fn symbol_row(ui: &mut egui::Ui, text: &str, name: &str) -> Option<AavrAction> {
    let row = ui
        .selectable_label(false, RichText::new(text).monospace())
        .on_hover_text(format!("Go to {}", visible(name)));
    (row.clicked() && !name.trim().is_empty()).then(|| AavrAction::FindSymbol(name.trim().into()))
}

#[cfg(test)]
#[path = "aavr_view_tests.rs"]
mod tests;
