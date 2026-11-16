//! Running the agent loop inside SrcWranglr: how one tool call the model
//! makes is carried out. A read runs against the index; a write (notes,
//! journal, Findings) goes through the app, which seeks approval for a
//! risky one; a run_command goes through the user's approval, then the
//! shell. The loop, threads and pane that drive this come next; this is
//! the routing they share, kept testable on its own.
//
// Consumed by the agent pane (next); keep until it lands.
#![allow(dead_code)]

use std::path::Path;
use std::time::Duration;

use super::agent_bridge::{agent_write_for, AgentWrite, WRITE_TOOLS};
use crate::agent::exec::{self, RunCommandArgs, DEFAULT_TIMEOUT, MAX_OUTPUT};
use crate::agent::llm::ToolCall;
use crate::mcp::dispatch::{dispatch, parsed};
use crate::mcp::workspace::Workspace;

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
        return exec::run_command(root, &args.command, timeout, MAX_OUTPUT);
    }
    if WRITE_TOOLS.contains(&tool) {
        let write = agent_write_for(ws, tool, call.arguments.clone(), now)?;
        return make_write(write);
    }
    dispatch(ws, tool, call.arguments.clone(), now)
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
            |_| panic!("not a write"),
            |cmd| {
                assert_eq!(cmd, "echo hi");
                true
            },
        )
        .expect("ran");
        assert!(out.contains("hi") && out.contains("exit 0"), "{out}");
    }
}
