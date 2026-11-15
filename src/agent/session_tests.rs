use std::sync::Mutex;

use serde_json::json;

use super::*;
use crate::agent::llm::{LlmClient, Reply, Role, ToolCall, ToolSpec};
use crate::index::graph_of_files;
use crate::mcp::dispatch::dispatch;
use crate::mcp::workspace::Workspace;

/// A model scripted to give these replies in order.
struct Scripted(Mutex<std::collections::VecDeque<Reply>>);

impl Scripted {
    fn new(replies: Vec<Reply>) -> Self {
        Self(Mutex::new(replies.into_iter().collect()))
    }
}

impl LlmClient for Scripted {
    fn reply(&self, _messages: &[Message], _tools: &[ToolSpec]) -> Result<Reply, String> {
        self.0
            .lock()
            .unwrap()
            .pop_front()
            .ok_or("script ran out".into())
    }
}

fn workspace() -> Workspace {
    let source = "int helper(int x) { return x; }\nint main(void) { return helper(1); }\n";
    Workspace::new("t", None, graph_of_files(&[("m.c", source)]))
}

#[test]
fn the_loop_runs_a_tool_and_feeds_the_result_back() {
    let ws = workspace();
    // First the model asks for find_symbol, then (seeing the result) it stops.
    let client = Scripted::new(vec![
        Reply {
            content: "Let me look.".into(),
            tool_calls: vec![ToolCall {
                id: "c1".into(),
                name: "find_symbol".into(),
                arguments: json!({"query": "helper"}),
            }],
        },
        Reply {
            content: "Found helper at m.c:1.".into(),
            tool_calls: vec![],
        },
    ]);
    let mut session = Session::new("You audit C.", "Find helper.");
    let mut events = Vec::new();
    let answer = session
        .run(
            &client,
            &[],
            8,
            |call| dispatch(&ws, &call.name, call.arguments.clone(), 0),
            |event| events.push(event),
        )
        .expect("finished");
    assert_eq!(answer, "Found helper at m.c:1.");
    assert!(matches!(&events[0], Event::Said(s) if s == "Let me look."));
    assert!(matches!(&events[1], Event::Running { name, .. } if name == "find_symbol"));
    let ran = events
        .iter()
        .find_map(|e| match e {
            Event::Result {
                name,
                is_error,
                text,
            } if name == "find_symbol" => Some((is_error, text)),
            _ => None,
        })
        .expect("a result");
    assert!(!ran.0, "{}", ran.1);
    assert!(ran.1.contains("helper  m.c:1"), "{}", ran.1);
    assert!(matches!(events.last(), Some(Event::Done(s)) if s.contains("Found helper")));
    // The tool result was fed back into the conversation.
    assert!(session
        .messages()
        .iter()
        .any(|m| m.role == Role::Tool && m.content.contains("helper")));
}

#[test]
fn a_tools_error_is_fed_back_not_fatal() {
    let ws = workspace();
    let client = Scripted::new(vec![
        Reply {
            content: String::new(),
            tool_calls: vec![ToolCall {
                id: "c1".into(),
                name: "function_source".into(),
                arguments: json!({"name": "nope"}),
            }],
        },
        Reply {
            content: "No such function; done.".into(),
            tool_calls: vec![],
        },
    ]);
    let mut session = Session::new("sys", "go");
    let mut errored = false;
    session
        .run(
            &client,
            &[],
            8,
            |call| dispatch(&ws, &call.name, call.arguments.clone(), 0),
            |event| {
                if let Event::Result { is_error, .. } = &event {
                    errored |= *is_error;
                }
            },
        )
        .expect("finishes despite the tool error");
    assert!(errored, "the tool error should surface as an error result");
}

#[test]
fn the_step_limit_stops_a_runaway_loop() {
    let ws = workspace();
    // Always asks for another tool call: never finishes on its own.
    let forever = Scripted::new(
        (0..100)
            .map(|i| Reply {
                content: String::new(),
                tool_calls: vec![ToolCall {
                    id: format!("c{i}"),
                    name: "overview".into(),
                    arguments: json!({}),
                }],
            })
            .collect(),
    );
    let mut session = Session::new("sys", "go");
    let error = session
        .run(
            &forever,
            &[],
            3,
            |call| dispatch(&ws, &call.name, call.arguments.clone(), 0),
            |_| {},
        )
        .expect_err("hits the limit");
    assert!(error.contains("3 steps"), "{error}");
}
