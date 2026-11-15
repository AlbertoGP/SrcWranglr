//! The Agent pane: what an agent served this project has asked, newest
//! first, each with the first line of its answer. A click on a call goes
//! where it was looking; with "Follow the agent", each call goes there as
//! it comes.

use std::collections::VecDeque;
use std::path::Path;
use std::time::{Duration, Instant};

use egui::RichText;

use super::aavr_view::{AavrAction, AavrView, Launcher};
use super::agent_bridge::{AgentEvent, Serving};
use super::layout::Layout;
use super::pane_bar::{self, Edge};
use crate::mcp::dispatch::Place;
use crate::mcp::tools::verdicts::VerdictChange;

/// Calls kept; older ones give way.
const MAX_EVENTS: usize = 500;
const DEFAULT_WIDTH: f32 = 380.0;
/// Risky verdicts awaiting approval kept at most. High enough that a busy
/// session won't hit it; the agent is told if it does.
const MAX_PENDING: usize = 1000;
const ERROR_COLOR: egui::Color32 = egui::Color32::from_rgb(0xE0, 0x6C, 0x6C);
const PENDING_COLOR: egui::Color32 = egui::Color32::from_rgb(0xE0, 0x9A, 0x4C);
/// How often ages are redrawn while calls are shown.
const AGE_REFRESH: Duration = Duration::from_secs(10);

#[derive(Default)]
pub struct AgentPanel {
    is_open: bool,
    /// Newest first.
    events: VecDeque<AgentEvent>,
    /// All calls since the project opened, kept or not.
    calls: usize,
    is_following: bool,
    tab: Tab,
    /// Risky writes the agent asked for, waiting for the user's yes/no.
    pending: Vec<VerdictChange>,
    pub assessment: AavrView,
    /// opencode and whether it lists SrcWranglr, once looked for.
    launcher: Option<Launcher>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Tab {
    #[default]
    Calls,
    Assessment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentPanelAction {
    GoTo(Place),
    Assessment(AavrAction),
    /// The user approved these agent verdicts: apply them.
    ApplyVerdicts(Vec<VerdictChange>),
    /// The user rejected this many (for the status bar).
    RejectVerdicts(usize),
}

impl AgentPanel {
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    pub fn set_open(&mut self, is_open: bool) {
        self.is_open = is_open;
    }

    /// Whether each call should be shown as it comes.
    pub fn is_following(&self) -> bool {
        self.is_following
    }

    pub fn push(&mut self, event: AgentEvent) {
        self.calls += 1;
        self.events.push_front(event);
        self.events.truncate(MAX_EVENTS);
    }

    /// Queues a risky verdict for the user to approve. False if the queue
    /// is full (so the agent can be told, not left thinking it's queued).
    pub fn queue_approval(&mut self, change: VerdictChange) -> bool {
        if self.pending.len() >= MAX_PENDING {
            return false;
        }
        self.pending.push(change);
        true
    }

    /// Forgets the calls, pending approvals and the run, for another project.
    pub fn reset(&mut self) {
        self.events.clear();
        self.calls = 0;
        self.pending.clear();
        self.assessment.reset();
    }

    /// Whether the Assessment tab is shown without knowing about opencode.
    pub fn needs_launcher(&self) -> bool {
        self.is_open && self.tab == Tab::Assessment && self.launcher.is_none()
    }

    pub fn set_launcher(&mut self, launcher: Launcher) {
        self.launcher = Some(launcher);
    }

    /// Draws the pane (while open) at the right of `ui`. `command` is what
    /// an agent's client runs to reach this app.
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        layout: Layout,
        serving: &Serving,
        (command, root): (&str, Option<&Path>),
    ) -> Option<AgentPanelAction> {
        if self.assessment.take_connected() {
            self.launcher = None;
        }
        let mut is_open = self.is_open;
        let shown = pane_bar::right_pane(layout.pane_id("agent_panel"), DEFAULT_WIDTH)
            .show_collapsible(ui, &mut is_open, |ui| {
                self.contents(ui, serving, (command, root))
            });
        self.is_open = is_open && self.is_open;
        shown.and_then(|shown| shown.inner)
    }

    /// The pending approvals, each with Approve/Reject. Returns the user's
    /// choice on the first they act on.
    fn approvals(&mut self, ui: &mut egui::Ui) -> Option<AgentPanelAction> {
        if self.pending.is_empty() {
            return None;
        }
        ui.separator();
        let n = self.pending.len();
        let injections = self.pending.iter().filter(|c| c.is_injection).count();
        ui.label(
            RichText::new(format!("{} waiting for you", plural(n, "agent verdict")))
                .color(PENDING_COLOR)
                .strong(),
        );
        // Clear the whole queue in one click.
        if let Some(batch) = self.batch_buttons(ui, n, injections) {
            return Some(batch);
        }
        // Or decide them one at a time.
        let mut resolved = None;
        self.pending.retain(|change| {
            if resolved.is_some() {
                return true;
            }
            let mut keep = true;
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(format!("Mark {}", change.summary())).monospace());
                if change.is_injection {
                    ui.label(
                        RichText::new("· prompt injection")
                            .color(PENDING_COLOR)
                            .small(),
                    );
                }
                if ui.button("Approve").clicked() {
                    resolved = Some(AgentPanelAction::ApplyVerdicts(vec![change.clone()]));
                    keep = false;
                }
                if ui.button("Reject").clicked() {
                    resolved = Some(AgentPanelAction::RejectVerdicts(1));
                    keep = false;
                }
            });
            keep
        });
        resolved
    }

    /// Approve all, approve all but the prompt-injection ones, or reject
    /// all; whichever is clicked drains the queue accordingly.
    fn batch_buttons(
        &mut self,
        ui: &mut egui::Ui,
        n: usize,
        injections: usize,
    ) -> Option<AgentPanelAction> {
        let (mut all, mut safe, mut reject) = (false, false, false);
        ui.horizontal_wrapped(|ui| {
            all = ui.button(format!("Approve all ({n})")).clicked();
            if injections > 0 && injections < n {
                safe = ui
                    .button(format!("Approve all but {injections} injection"))
                    .on_hover_text("Apply every verdict except those on possible prompt injections, which stay for you to review")
                    .clicked();
            }
            reject = ui.button(format!("Reject all ({n})")).clicked();
        });
        if all {
            return Some(AgentPanelAction::ApplyVerdicts(std::mem::take(
                &mut self.pending,
            )));
        }
        if safe {
            let (apply, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending)
                .into_iter()
                .partition(|c| !c.is_injection);
            self.pending = keep;
            return Some(AgentPanelAction::ApplyVerdicts(apply));
        }
        if reject {
            let count = self.pending.len();
            self.pending.clear();
            return Some(AgentPanelAction::RejectVerdicts(count));
        }
        None
    }

    fn contents(
        &mut self,
        ui: &mut egui::Ui,
        serving: &Serving,
        (command, root): (&str, Option<&Path>),
    ) -> Option<AgentPanelAction> {
        let plural = if self.calls == 1 { "" } else { "s" };
        if pane_bar::heading(
            ui,
            format!("Agent ({} call{plural})", self.calls),
            Edge::Right,
        ) {
            self.is_open = false;
        }
        match serving {
            Serving::On { .. } => ui.weak("Serving this project to agents."),
            Serving::Off(why) => ui.label(RichText::new(why).color(ERROR_COLOR)),
        };
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Calls, "Calls");
            ui.selectable_value(&mut self.tab, Tab::Assessment, "Assessment");
        });
        if self.tab == Tab::Assessment {
            let launcher = self.launcher.clone().unwrap_or_default();
            return self
                .assessment
                .show(ui, root, &launcher)
                .map(AgentPanelAction::Assessment);
        }
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.is_following, "Follow the agent")
                .on_hover_text("Show in the source what each call looks at, as it comes");
            if ui
                .add_enabled(!self.events.is_empty(), egui::Button::new("Clear"))
                .clicked()
            {
                self.events.clear();
            }
        });
        if let Some(action) = self.approvals(ui) {
            return Some(action);
        }
        ui.separator();
        if self.events.is_empty() {
            how_to_connect(ui, command);
            return None;
        }
        ui.ctx().request_repaint_after(AGE_REFRESH);
        let now = Instant::now();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                self.events
                    .iter()
                    .filter_map(|event| call_row(ui, event, now))
                    .last()
            })
            .inner
    }
}

fn how_to_connect(ui: &mut egui::Ui, command: &str) {
    ui.label("No agent has asked anything yet. Add SrcWranglr to your agent's MCP servers as a local server that runs:");
    ui.label(RichText::new(command).monospace());
    ui.label("For opencode, run this once in a terminal:");
    ui.label(
        RichText::new(format!("opencode mcp add --global srcwranglr -- {command}")).monospace(),
    );
    ui.weak("Then open this project in opencode. The guide's Agents section has the details.");
}

/// One call: when, what and with what, then its answer. Returns where to
/// go if it was clicked.
fn call_row(ui: &mut egui::Ui, event: &AgentEvent, now: Instant) -> Option<AgentPanelAction> {
    let asked = format!(
        "{:>7}  {}  {}",
        age(now.saturating_duration_since(event.at)),
        event.tool,
        event.asked
    );
    let asked = RichText::new(asked).monospace();
    let clicked = match &event.place {
        Some(place) => {
            let row = ui
                .selectable_label(false, asked)
                .on_hover_text(format!("Go to {}:{}", place.file, place.line));
            row.clicked().then(|| AgentPanelAction::GoTo(place.clone()))
        }
        None => {
            ui.label(asked);
            None
        }
    };
    let answer = RichText::new(format!("→ {}", event.answer)).small();
    match event.is_error {
        true => ui.label(answer.color(ERROR_COLOR)),
        false => ui.label(answer.weak()),
    };
    clicked
}

/// `1 agent verdict` / `2 agent verdicts`.
fn plural(n: usize, thing: &str) -> String {
    format!("{n} {thing}{}", if n == 1 { "" } else { "s" })
}

/// `now`, `42 s`, `2 min`, `3 h`.
fn age(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    match seconds {
        0..=4 => "now".into(),
        5..=59 => format!("{seconds} s"),
        60..=3_599 => format!("{} min", seconds / 60),
        _ => format!("{} h", seconds / 3_600),
    }
}

#[cfg(test)]
#[path = "agent_panel_tests.rs"]
mod tests;
