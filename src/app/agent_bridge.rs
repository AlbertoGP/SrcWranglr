//! The open project, served to agents. An agent's client (opencode, Claude
//! Code) starts `srcwranglr --mcp <folder>`, which asks this app instead of
//! indexing the folder again; each call shows in the Agent pane, and a
//! note the agent adds goes into the app's notes, so it shows at once.
//! The index is arranged for agents when the first call comes, so a
//! session without an agent costs nothing.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use super::project::Project;
use crate::mcp::args::{AddNoteArgs, ImportSarifArgs, JournalArgs};
use crate::mcp::dispatch::{asked, dispatch, parsed, place_of, Place};
use crate::mcp::format::{shown, MAX_TEXT_CHARS};
use crate::mcp::state::State;
use crate::mcp::tools::notes::{note_change, NoteChange};
use crate::mcp::tools::records::{journal_change, sarif_file};
use crate::mcp::tools::verdicts::{verdict_change, VerdictChange};
use crate::mcp::workspace::Workspace;
use crate::model::CodeGraph;
use crate::notes::journal::Entry;

/// How long a call waits for the index to be arranged for agents: under
/// the 5 seconds opencode waits for an answer by default.
const WAIT_FOR_WORKSPACE: Duration = Duration::from_secs(4);
/// How long a call waits for the app to save the agent's note.
const WAIT_FOR_NOTE: Duration = Duration::from_secs(10);
/// Notes waiting for the app; more and the agent is told to try again.
const MAX_WAITING_NOTES: usize = 16;

/// One call an agent made.
#[derive(Debug, Clone)]
pub struct AgentEvent {
    pub at: Instant,
    pub tool: String,
    /// Its arguments in a line.
    pub asked: String,
    /// The answer's first line, or why there was none.
    pub answer: String,
    pub is_error: bool,
    /// Where in the project it was looking.
    pub place: Option<Place>,
}

/// What the agent asked to add, for the app to keep (it holds the notes,
/// the journal and Findings).
#[derive(Debug, Clone)]
pub enum AgentWrite {
    Note(NoteChange),
    Journal(Entry),
    /// A SARIF report inside the project, for Findings.
    Sarif(PathBuf),
    /// A verdict on a finding.
    Verdict(VerdictChange),
}

/// A write the agent asked for, and where to answer it.
pub struct NoteRequest {
    pub write: AgentWrite,
    pub reply: SyncSender<Result<String, String>>,
    asked_at: Instant,
}

/// A write this close to the agent giving up isn't made: it would be told
/// it wasn't, and ask again.
const NOTE_MARGIN: Duration = Duration::from_secs(2);

impl NoteRequest {
    /// Whether the agent has (nearly) stopped waiting for it.
    pub fn is_stale(&self) -> bool {
        self.asked_at.elapsed() + NOTE_MARGIN >= WAIT_FOR_NOTE
    }
}

/// Whether the project is served to agents, and how to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Serving {
    /// `--mcp` with this folder reaches it.
    On { folder: PathBuf },
    /// Why not.
    Off(String),
}

pub struct AgentBridge {
    serving: Serving,
    events: Receiver<AgentEvent>,
    notes: Receiver<NoteRequest>,
    #[cfg(unix)]
    _host: Option<crate::mcp::bridge::Host>,
}

impl Default for AgentBridge {
    fn default() -> Self {
        Self::off("Open a project folder to serve it to agents.".into())
    }
}

impl AgentBridge {
    fn off(why: String) -> Self {
        let (_, events) = mpsc::channel();
        let (_, notes) = mpsc::sync_channel(0);
        Self {
            serving: Serving::Off(why),
            events,
            notes,
            #[cfg(unix)]
            _host: None,
        }
    }

    /// Serves `project` (if it has a folder) until dropped; `ctx` is woken
    /// for each call.
    #[cfg(unix)]
    pub fn start(project: &Project, ctx: &egui::Context) -> Self {
        match crate::mcp::bridge::socket_dir() {
            Some(sockets) => Self::start_in(project, ctx, &sockets),
            None => Self::off("No home folder to keep the agent socket in.".into()),
        }
    }

    /// Serves `project` with its socket in `sockets`.
    #[cfg(unix)]
    fn start_in(project: &Project, ctx: &egui::Context, sockets: &std::path::Path) -> Self {
        let Some(root) = project.root.as_deref() else {
            return Self::default();
        };
        // `--mcp` names the socket from the folder's canonical path too.
        let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        let (event_tx, events) = mpsc::channel();
        let (note_tx, notes) = mpsc::sync_channel(MAX_WAITING_NOTES);
        let calls = Calls {
            name: project.name.clone(),
            root: root.clone(),
            graph: Arc::clone(&project.graph),
            state: OnceLock::new(),
            events: event_tx,
            notes: note_tx,
            ctx: ctx.clone(),
        };
        let answer: Arc<crate::mcp::bridge::Answerer> =
            Arc::new(move |tool: &str, args: Value| calls.answer(tool, args));
        match crate::mcp::bridge::Host::start(sockets, &root, answer) {
            Ok(host) => Self {
                serving: Serving::On { folder: root },
                events,
                notes,
                _host: Some(host),
            },
            Err(why) => Self::off(format!("Not serving agents: {why}.")),
        }
    }

    #[cfg(not(unix))]
    pub fn start(_project: &Project, _ctx: &egui::Context) -> Self {
        Self::off("Serving agents needs macOS or Linux.".into())
    }

    pub fn serving(&self) -> &Serving {
        &self.serving
    }

    /// The calls made, and notes asked for, since last time.
    pub fn drain(&self) -> (Vec<AgentEvent>, Vec<NoteRequest>) {
        (
            self.events.try_iter().collect(),
            self.notes.try_iter().collect(),
        )
    }
}

/// What answers each call, on the bridge's threads.
struct Calls {
    name: String,
    root: PathBuf,
    graph: Arc<CodeGraph>,
    /// The index arranged for agents, from the first call on.
    state: OnceLock<Arc<State>>,
    events: Sender<AgentEvent>,
    notes: SyncSender<NoteRequest>,
    ctx: egui::Context,
}

impl Calls {
    fn answer(&self, tool: &str, args: Value) -> Result<String, String> {
        let at = Instant::now();
        let state = self.state.get_or_init(|| {
            let (name, root, graph) = (
                self.name.clone(),
                self.root.clone(),
                Arc::clone(&self.graph),
            );
            State::preparing(move || Workspace::from_shared(&name, Some(root), graph))
        });
        let workspace = state.workspace(WAIT_FOR_WORKSPACE);
        let (result, place) = match &workspace {
            Ok(ws) => (self.run(ws, tool, args.clone()), place_of(ws, tool, &args)),
            Err(why) => (Err(why.clone()), None),
        };
        let first_line = match &result {
            Ok(text) | Err(text) => text.lines().next().unwrap_or(""),
        };
        let event = AgentEvent {
            at,
            tool: shown(tool, MAX_TEXT_CHARS),
            asked: asked(&args),
            answer: shown(first_line, MAX_TEXT_CHARS),
            is_error: result.is_err(),
            place,
        };
        // The app may have closed; the agent still gets its answer.
        let _ = self.events.send(event);
        self.ctx.request_repaint();
        result
    }

    fn run(&self, ws: &Workspace, tool: &str, args: Value) -> Result<String, String> {
        // The app keeps notes, the journal and Findings, so it makes these.
        let write = match tool {
            "add_note" => AgentWrite::Note(note_change(ws, &parsed::<AddNoteArgs>(args)?)?),
            "journal_entry" => {
                let args: JournalArgs = parsed(args)?;
                AgentWrite::Journal(journal_change(ws, &args, unix_now())?)
            }
            "import_sarif" => {
                let args: ImportSarifArgs = parsed(args)?;
                AgentWrite::Sarif(sarif_file(ws, &args.file)?)
            }
            "set_verdict" => AgentWrite::Verdict(verdict_change(ws, &parsed(args)?)?),
            _ => return dispatch(ws, tool, args, unix_now()),
        };
        let (reply, answer) = mpsc::sync_channel(1);
        self.notes
            .try_send(NoteRequest {
                write,
                reply,
                asked_at: Instant::now(),
            })
            .map_err(|_| "SrcWranglr is busy with other writes; try again.".to_string())?;
        self.ctx.request_repaint();
        answer
            .recv_timeout(WAIT_FOR_NOTE)
            .map_err(|_| "SrcWranglr didn't get to it in time; try again.".to_string())?
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(all(test, unix))]
#[path = "agent_bridge_tests.rs"]
mod tests;
