//! The model, abstracted: the messages a conversation is made of, the
//! tools offered to the model, and the one call the loop makes — given the
//! conversation and the tools, return the model's reply (text and any tool
//! calls). A real client talks to a provider over HTTP; tests use a
//! scripted one. Nothing here is tied to a provider's wire format; the
//! client maps these types to and from it.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

/// One call the model asked to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    /// The provider's id, echoed back with the result.
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub role: Role,
    pub content: String,
    /// On an assistant message, the tool calls it made.
    pub tool_calls: Vec<ToolCall>,
    /// On a tool message, the call it answers.
    pub tool_call_id: Option<String>,
}

impl Message {
    pub fn system(content: impl Into<String>) -> Self {
        Self::text(Role::System, content)
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self::text(Role::User, content)
    }

    /// An assistant turn: what it said, and any tool calls it made.
    pub fn assistant(content: impl Into<String>, tool_calls: Vec<ToolCall>) -> Self {
        Self {
            role: Role::Assistant,
            content: content.into(),
            tool_calls,
            tool_call_id: None,
        }
    }

    /// A tool result answering `call_id`.
    pub fn tool(call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: Role::Tool,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: Some(call_id.into()),
        }
    }

    fn text(role: Role, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }
}

/// A tool offered to the model: its name, what it does, and the JSON
/// schema of its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

/// The model's reply: what it said, and any tool calls it wants run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reply {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
}

/// One round-trip to the model.
pub trait LlmClient: Send + Sync {
    /// The model's reply to `messages`, with `tools` on offer.
    fn reply(&self, messages: &[Message], tools: &[ToolSpec]) -> Result<Reply, String>;
}
