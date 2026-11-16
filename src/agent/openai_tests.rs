use serde_json::json;

use super::*;
use crate::agent::llm::{Message, ToolCall, ToolSpec};

#[test]
fn the_request_carries_messages_and_tools_in_openai_shape() {
    let messages = vec![
        Message::system("audit"),
        Message::user("find bugs"),
        Message::assistant(
            "looking",
            vec![ToolCall {
                id: "c1".into(),
                name: "overview".into(),
                arguments: json!({"k": 1}),
            }],
        ),
        Message::tool("c1", "the overview"),
    ];
    let tools = vec![ToolSpec {
        name: "overview".into(),
        description: "start here".into(),
        parameters: json!({"type": "object"}),
    }];
    let body = request_body("glm-5.3", &messages, &tools);
    assert_eq!(body["model"], "glm-5.3");
    assert_eq!(body["tool_choice"], "auto");
    assert_eq!(body["messages"][0]["role"], "system");
    // An assistant tool call: arguments are a JSON string.
    assert_eq!(
        body["messages"][2]["tool_calls"][0]["function"]["name"],
        "overview"
    );
    assert_eq!(
        body["messages"][2]["tool_calls"][0]["function"]["arguments"],
        "{\"k\":1}"
    );
    // A tool result references its call.
    assert_eq!(body["messages"][3]["role"], "tool");
    assert_eq!(body["messages"][3]["tool_call_id"], "c1");
    assert_eq!(body["tools"][0]["function"]["name"], "overview");
}

#[test]
fn no_tools_means_no_tools_field() {
    let body = request_body("m", &[Message::user("hi")], &[]);
    assert!(body.get("tools").is_none());
    assert!(body.get("tool_choice").is_none());
}

#[test]
fn a_reply_with_text_and_tool_calls_is_parsed() {
    let value = json!({
        "choices": [{
            "message": {
                "content": "I'll look.",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "find_symbol", "arguments": "{\"query\": \"parse\"}"}
                }]
            }
        }]
    });
    let reply = parse_reply(&value).expect("parsed");
    assert_eq!(reply.content, "I'll look.");
    assert_eq!(reply.tool_calls.len(), 1);
    assert_eq!(reply.tool_calls[0].name, "find_symbol");
    assert_eq!(reply.tool_calls[0].arguments, json!({"query": "parse"}));
    assert_eq!(reply.tool_calls[0].id, "call_1");
}

#[test]
fn a_final_message_has_no_tool_calls() {
    let value = json!({"choices": [{"message": {"content": "done", "tool_calls": null}}]});
    let reply = parse_reply(&value).expect("parsed");
    assert_eq!(reply.content, "done");
    assert!(reply.tool_calls.is_empty());
}

#[test]
fn broken_or_empty_tool_arguments_dont_crash() {
    let value = json!({
        "choices": [{"message": {"tool_calls": [
            {"id": "a", "function": {"name": "overview", "arguments": ""}},
            {"id": "b", "function": {"name": "overview", "arguments": "not json"}}
        ]}}]
    });
    let reply = parse_reply(&value).expect("parsed");
    assert_eq!(reply.tool_calls.len(), 2);
    assert_eq!(reply.tool_calls[0].arguments, json!({}));
    assert_eq!(reply.tool_calls[1].arguments, json!({}));
}

#[test]
fn an_error_body_is_reported() {
    let value = json!({"error": {"message": "bad key"}});
    let error = parse_reply(&value).expect_err("no choices");
    assert!(error.contains("bad key"), "{error}");
}

#[test]
fn a_provider_is_ready_only_when_filled_in() {
    let mut p = Provider {
        base_url: "https://api.z.ai/api/coding/paas/v4".into(),
        model: "glm-5.3".into(),
        api_key: "k".into(),
    };
    assert!(p.is_ready());
    p.api_key = "  ".into();
    assert!(!p.is_ready());
}
