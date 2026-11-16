//! An OpenAI-compatible model client: chat completions with tool calling,
//! which z.ai (GLM), OpenRouter, OpenAI and most local servers speak. The
//! request and response mapping are pure functions, tested without the
//! network; the client wraps them around one HTTP POST.

use std::time::Duration;

use serde_json::{json, Value};

use super::llm::{LlmClient, Message, Reply, Role, ToolCall, ToolSpec};

/// How long one model call may take (a tool-choosing turn, not a stream).
const TIMEOUT: Duration = Duration::from_secs(180);

/// Where the model is and how to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    /// The API root, e.g. `https://api.z.ai/api/coding/paas/v4`.
    pub base_url: String,
    /// `provider/model` or a bare model id, as the endpoint expects.
    pub model: String,
    pub api_key: String,
}

impl Provider {
    /// Whether it's configured enough to try.
    pub fn is_ready(&self) -> bool {
        !self.base_url.trim().is_empty()
            && !self.model.trim().is_empty()
            && !self.api_key.trim().is_empty()
    }
}

pub struct OpenAiClient {
    provider: Provider,
    http: reqwest::blocking::Client,
}

impl OpenAiClient {
    pub fn new(provider: Provider) -> Result<Self, String> {
        let http = reqwest::blocking::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| format!("couldn't start the HTTP client: {e}"))?;
        Ok(Self { provider, http })
    }

    fn endpoint(&self) -> String {
        format!(
            "{}/chat/completions",
            self.provider.base_url.trim_end_matches('/')
        )
    }
}

impl LlmClient for OpenAiClient {
    fn reply(&self, messages: &[Message], tools: &[ToolSpec]) -> Result<Reply, String> {
        let body = request_body(&self.provider.model, messages, tools);
        let response = self
            .http
            .post(self.endpoint())
            .bearer_auth(&self.provider.api_key)
            .json(&body)
            .send()
            .map_err(|e| format!("the model request failed: {e}"))?;
        let status = response.status();
        let value: Value = response
            .json()
            .map_err(|e| format!("the model's reply wasn't JSON ({e})"))?;
        if !status.is_success() {
            let hint = match status.as_u16() {
                401 | 403 => " — check the API key in Settings → Agent",
                429 => " — the provider rate-limited or the plan quota is spent",
                _ => "",
            };
            return Err(format!(
                "the model returned {status}: {}{hint}",
                error_text(&value)
            ));
        }
        parse_reply(&value)
    }
}

/// The chat-completions request body for `model`.
fn request_body(model: &str, messages: &[Message], tools: &[ToolSpec]) -> Value {
    let mut body = json!({
        "model": model,
        "messages": messages.iter().map(message_json).collect::<Vec<_>>(),
    });
    if !tools.is_empty() {
        body["tools"] = tools.iter().map(tool_json).collect::<Vec<_>>().into();
        body["tool_choice"] = "auto".into();
    }
    body
}

fn message_json(message: &Message) -> Value {
    let role = match message.role {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    };
    let mut value = json!({ "role": role, "content": message.content });
    if !message.tool_calls.is_empty() {
        value["tool_calls"] = message
            .tool_calls
            .iter()
            .map(|call| {
                json!({
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": call.arguments.to_string(),
                    },
                })
            })
            .collect::<Vec<_>>()
            .into();
    }
    if let Some(id) = &message.tool_call_id {
        value["tool_call_id"] = id.clone().into();
    }
    value
}

fn tool_json(tool: &ToolSpec) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters,
        },
    })
}

/// The reply in the first choice of a chat-completions response.
fn parse_reply(value: &Value) -> Result<Reply, String> {
    let message = value
        .pointer("/choices/0/message")
        .ok_or_else(|| format!("no choices in the model's reply: {}", error_text(value)))?;
    let content = message
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let tool_calls = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .map(|calls| calls.iter().filter_map(tool_call_of).collect())
        .unwrap_or_default();
    Ok(Reply {
        content,
        tool_calls,
    })
}

fn tool_call_of(value: &Value) -> Option<ToolCall> {
    let function = value.get("function")?;
    let name = function.get("name").and_then(Value::as_str)?.to_string();
    // Arguments come as a JSON string; an empty or broken one means no args.
    let arguments = function
        .get("arguments")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| json!({}));
    Some(ToolCall {
        id: value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("call")
            .to_string(),
        name,
        arguments,
    })
}

/// A provider's error message, if the body carries one.
fn error_text(value: &Value) -> String {
    value
        .pointer("/error/message")
        .or_else(|| value.get("error"))
        .or_else(|| value.get("message"))
        .and_then(|v| {
            v.as_str()
                .map(str::to_string)
                .or_else(|| Some(v.to_string()))
        })
        .unwrap_or_else(|| "no message".into())
}

#[cfg(test)]
#[path = "openai_tests.rs"]
mod tests;
