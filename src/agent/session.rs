//! The agent loop: ask the model, run the tool calls it asks for through
//! SrcWranglr's own tools (`mcp::dispatch`), feed the results back, and
//! repeat until it answers with no more calls. The loop doesn't talk to
//! the network or the window; the caller passes a model client, a function
//! that runs one tool call (which may wait for the user to approve a risky
//! one), and a sink for the events a pane shows.

use super::llm::{LlmClient, Message, ToolCall};

/// What happened, for the pane to show as it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The model said something (its reasoning or narration).
    Said(String),
    /// A tool is about to run.
    Running { name: String, arguments: String },
    /// A tool answered (or refused).
    Result {
        name: String,
        is_error: bool,
        text: String,
    },
    /// The model finished, with its closing message.
    Done(String),
}

/// A conversation the loop drives.
pub struct Session {
    messages: Vec<Message>,
}

impl Session {
    /// Starts from the system prompt and the first user message.
    pub fn new(system: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            messages: vec![Message::system(system), Message::user(user)],
        }
    }

    /// The conversation so far.
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// Runs the loop: at most `max_turns` model calls, `run_tool` for each
    /// tool call, `on_event` for the pane. Returns the model's final text.
    pub fn run(
        &mut self,
        client: &dyn LlmClient,
        tools: &[super::llm::ToolSpec],
        max_turns: usize,
        mut run_tool: impl FnMut(&ToolCall) -> Result<String, String>,
        mut on_event: impl FnMut(Event),
    ) -> Result<String, String> {
        for _ in 0..max_turns {
            let reply = client.reply(&self.messages, tools)?;
            if !reply.content.trim().is_empty() {
                on_event(Event::Said(reply.content.clone()));
            }
            if reply.tool_calls.is_empty() {
                on_event(Event::Done(reply.content.clone()));
                self.messages
                    .push(Message::assistant(reply.content.clone(), Vec::new()));
                return Ok(reply.content);
            }
            self.messages.push(Message::assistant(
                reply.content.clone(),
                reply.tool_calls.clone(),
            ));
            for call in &reply.tool_calls {
                on_event(Event::Running {
                    name: call.name.clone(),
                    arguments: call.arguments.to_string(),
                });
                let (is_error, text) = match run_tool(call) {
                    Ok(text) => (false, text),
                    Err(text) => (true, text),
                };
                on_event(Event::Result {
                    name: call.name.clone(),
                    is_error,
                    text: text.clone(),
                });
                self.messages.push(Message::tool(&call.id, text));
            }
        }
        Err(format!(
            "The agent stopped after {max_turns} steps without finishing."
        ))
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
