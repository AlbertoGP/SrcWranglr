//! Running the agent loop inside SrcWranglr: how one tool call the model
//! makes is carried out. A read runs against the index; a write (notes,
//! journal, Findings) goes through the app, which seeks approval for a
//! risky one; a run_command goes through the user's approval, then the
//! shell. The loop, threads and pane that drive this come next; this is
//! the routing they share, kept testable on its own.
//
// Consumed by the agent pane (next); keep until it lands.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::agent_bridge::{agent_write_for, AgentWrite, WRITE_TOOLS};
use crate::agent::exec::{self, RunCommandArgs, DEFAULT_TIMEOUT, MAX_OUTPUT};
use crate::agent::llm::{LlmClient, Message, Reply, ToolCall, ToolSpec};
use crate::agent::session::{Event, Session};
use crate::agent::{prompt, tools};
use crate::mcp::dispatch::{dispatch, parsed};
use crate::mcp::workspace::Workspace;
use crate::model::CodeGraph;

/// A command may run at most this long, whatever it asks for.
const MAX_COMMAND_SECONDS: u32 = 3600;

/// Carries out one tool call. `make_write` applies an app-owned write
/// (seeking the user's approval for a risky one); `approve` asks the user
/// before a command runs. `now` is Unix seconds.
pub fn run_tool(
    ws: &Workspace,
    root: Option<&Path>,
    call: &ToolCall,
    now: u64,
    cancel: &AtomicBool,
    mut make_write: impl FnMut(AgentWrite) -> Result<String, String>,
    mut approve: impl FnMut(&str) -> bool,
) -> Result<String, String> {
    let tool = call.name.as_str();
    if tool == "run_command" {
        let root = root.ok_or("There is no project folder to run a command in.")?;
        let args: RunCommandArgs = parsed(call.arguments.clone())?;
        if !approve(&args.command) {
            return Ok("The user declined to run that command.".into());
        }
        let timeout = args
            .timeout_seconds
            .map(|s| Duration::from_secs(u64::from(s.clamp(1, MAX_COMMAND_SECONDS))))
            .unwrap_or(DEFAULT_TIMEOUT);
        return exec::run_command(root, &args.command, timeout, MAX_OUTPUT, cancel);
    }
    if WRITE_TOOLS.contains(&tool) {
        let write = agent_write_for(ws, tool, call.arguments.clone(), now)?;
        return make_write(write);
    }
    dispatch(ws, tool, call.arguments.clone(), now)
}

/// The first message that kicks off an in-app assessment.
pub const START_PROMPT: &str = "Assess this C/C++ project for memory-safety vulnerabilities. \
Work through the phases, confirm leads by building and fuzzing, and record what you find with \
verdicts and journal entries.";

/// Model calls allowed in one run, a backstop against a loop that never
/// settles.
const MAX_TURNS: usize = 400;
/// How long a write waits for the app to make it.
const WRITE_WAIT: Duration = Duration::from_secs(30);
/// How long a command waits for the user to approve it before it's taken
/// as declined.
const APPROVAL_WAIT: Duration = Duration::from_secs(30 * 60);

/// Something the running loop needs the app (its thread) to do.
pub enum ToMain {
    /// Make an app-owned write; the reply is what the agent is told.
    Write {
        write: AgentWrite,
        reply: SyncSender<Result<String, String>>,
    },
    /// Ask the user to approve a command; the reply is their yes/no.
    Command {
        command: String,
        reply: SyncSender<bool>,
    },
}

/// A run of the in-app agent on its own thread.
pub struct InAppRun {
    events: Receiver<Event>,
    to_main: Receiver<ToMain>,
    done: Arc<Mutex<Option<Result<String, String>>>>,
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl InAppRun {
    /// Starts the loop with `client` driving it over the project `graph`,
    /// from the user's first message. `ctx` is woken as it progresses.
    pub fn start(
        client: Box<dyn LlmClient>,
        name: String,
        root: Option<PathBuf>,
        graph: Arc<CodeGraph>,
        user: String,
        ctx: egui::Context,
    ) -> Self {
        let (event_tx, events) = mpsc::channel();
        let (to_main_tx, to_main) = mpsc::channel();
        let done = Arc::new(Mutex::new(None));
        let cancel = Arc::new(AtomicBool::new(false));
        let shared_done = Arc::clone(&done);
        let stop = Arc::clone(&cancel);
        let thread = std::thread::Builder::new()
            .name("in-app-agent".into())
            .spawn(move || {
                let outcome = run(
                    &*client,
                    &name,
                    root,
                    graph,
                    &user,
                    &stop,
                    &to_main_tx,
                    &event_tx,
                    &ctx,
                );
                *shared_done.lock().unwrap_or_else(PoisonError::into_inner) = Some(outcome);
                ctx.request_repaint();
            })
            .ok();
        Self {
            events,
            to_main,
            done,
            cancel,
            thread,
        }
    }

    /// The events and requests since last time.
    pub fn drain(&self) -> (Vec<Event>, Vec<ToMain>) {
        (
            self.events.try_iter().collect(),
            self.to_main.try_iter().collect(),
        )
    }

    /// The final answer once the run is over.
    pub fn result(&self) -> Option<Result<String, String>> {
        self.done
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Asks the run to stop at its next step.
    pub fn stop(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl Drop for InAppRun {
    fn drop(&mut self) {
        // Ask it to stop and let the thread wind down on its own; don't
        // join, so the window never freezes waiting on a model call.
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// The loop body: build the workspace, drive the model, route each call.
#[allow(clippy::too_many_arguments)]
fn run(
    client: &dyn LlmClient,
    name: &str,
    root: Option<PathBuf>,
    graph: Arc<CodeGraph>,
    user: &str,
    cancel: &AtomicBool,
    to_main: &Sender<ToMain>,
    events: &Sender<Event>,
    ctx: &egui::Context,
) -> Result<String, String> {
    let ws = Workspace::from_shared(name, root.clone(), graph);
    let client = Cancellable {
        inner: client,
        cancel,
    };
    let specs = tools::specs();
    let mut session = Session::new(prompt::SYSTEM, user);
    session.run(
        &client,
        &specs,
        MAX_TURNS,
        |call| {
            run_tool(
                &ws,
                root.as_deref(),
                call,
                unix_now(),
                cancel,
                |write| {
                    ask_main(
                        to_main,
                        ctx,
                        |reply| ToMain::Write { write, reply },
                        WRITE_WAIT,
                    )
                    .unwrap_or_else(|| Err("SrcWranglr didn't make the change in time.".into()))
                },
                |command| {
                    ask_main(
                        to_main,
                        ctx,
                        |reply| ToMain::Command {
                            command: command.to_string(),
                            reply,
                        },
                        APPROVAL_WAIT,
                    )
                    .unwrap_or(false)
                },
            )
        },
        |event| {
            let _ = events.send(event);
            ctx.request_repaint();
        },
    )
}

/// Sends a request to the app thread and waits for its reply.
fn ask_main<T>(
    to_main: &Sender<ToMain>,
    ctx: &egui::Context,
    make: impl FnOnce(SyncSender<T>) -> ToMain,
    wait: Duration,
) -> Option<T> {
    let (reply, answer) = mpsc::sync_channel(1);
    to_main.send(make(reply)).ok()?;
    ctx.request_repaint();
    answer.recv_timeout(wait).ok()
}

/// A client that stops the loop once the run is cancelled.
struct Cancellable<'a> {
    inner: &'a dyn LlmClient,
    cancel: &'a AtomicBool,
}

impl LlmClient for Cancellable<'_> {
    fn reply(&self, messages: &[Message], tools: &[ToolSpec]) -> Result<Reply, String> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err("stopped by the user".into());
        }
        self.inner.reply(messages, tools)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::index::graph_of_files;

    fn call(name: &str, arguments: serde_json::Value) -> ToolCall {
        ToolCall {
            id: "c".into(),
            name: name.into(),
            arguments,
        }
    }

    fn workspace() -> Workspace {
        let source = "int helper(int x) { return x; }\n";
        Workspace::new("t", None, graph_of_files(&[("m.c", source)]))
    }

    #[test]
    fn a_read_runs_against_the_index() {
        let ws = workspace();
        let out = run_tool(
            &ws,
            None,
            &call("find_symbol", json!({"query": "helper"})),
            0,
            &AtomicBool::new(false),
            |_| panic!("not a write"),
            |_| panic!("not a command"),
        )
        .expect("read");
        assert!(out.contains("helper  m.c:1"), "{out}");
    }

    #[test]
    fn a_write_goes_through_make_write() {
        let dir = tempfile::tempdir().expect("dir");
        let ws = Workspace::new(
            "t",
            Some(dir.path().to_path_buf()),
            graph_of_files(&[("m.c", "int helper(int x) { return x; }\n")]),
        );
        let mut got = None;
        let out = run_tool(
            &ws,
            Some(dir.path()),
            &call("add_note", json!({"target": "helper", "text": "look here"})),
            0,
            &AtomicBool::new(false),
            |write| {
                got = Some(write);
                Ok("noted".into())
            },
            |_| panic!("not a command"),
        )
        .expect("write");
        assert_eq!(out, "noted");
        assert!(matches!(got, Some(AgentWrite::Note(_))));
    }

    #[test]
    fn a_command_runs_only_after_approval() {
        let dir = tempfile::tempdir().expect("dir");
        let ws = workspace();
        // Declined: nothing runs.
        let out = run_tool(
            &ws,
            Some(dir.path()),
            &call("run_command", json!({"command": "echo ran > out.txt"})),
            0,
            &AtomicBool::new(false),
            |_| panic!("not a write"),
            |_| false,
        )
        .expect("declined");
        assert!(out.contains("declined"), "{out}");
        assert!(!dir.path().join("out.txt").exists(), "nothing ran");
        // Approved: it runs in the folder.
        let out = run_tool(
            &ws,
            Some(dir.path()),
            &call("run_command", json!({"command": "echo hi"})),
            0,
            &AtomicBool::new(false),
            |_| panic!("not a write"),
            |cmd| {
                assert_eq!(cmd, "echo hi");
                true
            },
        )
        .expect("ran");
        assert!(out.contains("hi") && out.contains("exit 0"), "{out}");
    }

    use std::collections::VecDeque;
    use std::sync::Mutex;

    use crate::agent::llm::{LlmClient, Message, Reply, ToolSpec};

    struct Scripted(Mutex<VecDeque<Reply>>);
    impl LlmClient for Scripted {
        fn reply(&self, _m: &[Message], _t: &[ToolSpec]) -> Result<Reply, String> {
            self.0.lock().unwrap().pop_front().ok_or("ran out".into())
        }
    }

    fn tool_reply(name: &str, args: serde_json::Value) -> Reply {
        Reply {
            content: String::new(),
            tool_calls: vec![ToolCall {
                id: name.into(),
                name: name.into(),
                arguments: args,
            }],
        }
    }

    #[test]
    fn the_runner_drives_the_loop_routing_writes_and_commands_to_the_app() {
        let dir = tempfile::tempdir().expect("dir");
        let graph = std::sync::Arc::new(graph_of_files(&[(
            "m.c",
            "int helper(int x) { return x; }\n",
        )]));
        let model = Scripted(Mutex::new(
            vec![
                tool_reply("find_symbol", json!({"query": "helper"})),
                tool_reply("add_note", json!({"target": "helper", "text": "look"})),
                tool_reply("run_command", json!({"command": "echo hi"})),
                Reply {
                    content: "All done.".into(),
                    tool_calls: vec![],
                },
            ]
            .into(),
        ));
        let run = InAppRun::start(
            Box::new(model),
            "p".into(),
            Some(dir.path().to_path_buf()),
            graph,
            "assess this".into(),
            egui::Context::default(),
        );

        let (mut wrote, mut ran) = (false, false);
        let mut events = Vec::new();
        for _ in 0..600 {
            let (evs, requests) = run.drain();
            events.extend(evs);
            for request in requests {
                match request {
                    ToMain::Write { write, reply } => {
                        assert!(matches!(write, AgentWrite::Note(_)));
                        wrote = true;
                        let _ = reply.send(Ok("noted".into()));
                    }
                    ToMain::Command { command, reply } => {
                        assert_eq!(command, "echo hi");
                        ran = true;
                        let _ = reply.send(true);
                    }
                }
            }
            if let Some(result) = run.result() {
                assert_eq!(result, Ok("All done.".into()));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(wrote, "the note was routed to the app");
        assert!(ran, "the command asked for approval");
        events.extend(run.drain().0);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Running { name, .. } if name == "find_symbol")),
            "{events:?}"
        );
        assert!(events
            .iter()
            .any(|e| matches!(e, Event::Done(s) if s == "All done.")));
    }
}
