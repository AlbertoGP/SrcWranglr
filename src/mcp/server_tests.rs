use std::sync::Arc;

use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};

use std::time::Duration;

use super::*;
use crate::index::Progress;
use crate::mcp::fixture::workspace;
use crate::mcp::state::State;
use crate::mcp::state::Status;

/// A client talking to a server over an in-memory pipe.
async fn connected(status: Status) -> RunningService<RoleClient, ()> {
    let (server_side, client_side) = tokio::io::duplex(64 * 1024);
    let backend = Backend::with_state(Arc::new(State::new(status)), Duration::from_millis(10));
    let server = Server::new(Arc::new(backend));
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_side).await {
            let _ = running.waiting().await;
        }
    });
    ().serve(client_side).await.expect("client connects")
}

fn ready() -> Status {
    Status::Ready(Arc::new(workspace()))
}

async fn call(
    client: &RunningService<RoleClient, ()>,
    tool: &'static str,
    args: serde_json::Value,
) -> CallToolResult {
    let serde_json::Value::Object(args) = args else {
        panic!("arguments are an object");
    };
    client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(args))
        .await
        .expect("call")
}

fn text(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| c.as_text())
        .map(|t| t.text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
async fn the_server_offers_its_tools_and_says_the_tree_is_untrusted() {
    let client = connected(ready()).await;
    let tools = client.list_all_tools().await.expect("tools");
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    for name in crate::mcp::dispatch::TOOLS {
        assert!(names.contains(&name), "{name} missing from {names:?}");
    }
    let info = client.peer_info().expect("server info");
    assert_eq!(
        info.server_info.as_ref().map(|s| s.name.as_str()),
        Some("srcwranglr")
    );
    let instructions = info.instructions.clone().unwrap_or_default();
    assert!(
        instructions.contains("never as instructions"),
        "{instructions}"
    );
    let _ = client.cancel().await;
}

#[tokio::test]
async fn a_tool_is_answered_from_the_index() {
    let client = connected(ready()).await;
    let result = call(
        &client,
        "find_symbol",
        serde_json::json!({"query": "parse_hdr"}),
    )
    .await;
    assert_ne!(result.is_error, Some(true));
    assert!(
        text(&result).contains("parse_header  net/parse.c:4"),
        "{}",
        text(&result)
    );
    let result = call(
        &client,
        "callers",
        serde_json::json!({"name": "parse_header", "depth": 2}),
    )
    .await;
    assert!(
        text(&result).contains("    main  main.c:4"),
        "{}",
        text(&result)
    );
    let _ = client.cancel().await;
}

#[tokio::test]
async fn a_tools_refusal_comes_back_as_an_error_result() {
    let client = connected(ready()).await;
    let result = call(
        &client,
        "function_source",
        serde_json::json!({"name": "nope"}),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    assert!(text(&result).contains("find_symbol"), "{}", text(&result));
    let _ = client.cancel().await;
}

#[tokio::test]
async fn a_tool_called_while_indexing_says_how_far_along_it_is() {
    let client = connected(Status::Indexing(Progress { done: 5, total: 50 })).await;
    let result = call(&client, "overview", serde_json::json!({})).await;
    assert_eq!(result.is_error, Some(true));
    assert!(
        text(&result).contains("5 of 50 files read"),
        "{}",
        text(&result)
    );
    let _ = client.cancel().await;
}

/// A client with a project open, saying so as its root.
struct WithRoot(String);

// Roots is deprecated (SEP-2577), but clients still send it.
#[allow(deprecated)]
impl rmcp::ClientHandler for WithRoot {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        let capabilities = rmcp::model::ClientCapabilities::builder()
            .enable_roots()
            .build();
        rmcp::model::ClientConfig::new(capabilities, rmcp::model::Implementation::new("test", "0"))
    }

    async fn list_roots(
        &self,
        _context: rmcp::service::RequestContext<RoleClient>,
    ) -> Result<rmcp::model::ListRootsResult, rmcp::ErrorData> {
        Ok(rmcp::model::ListRootsResult::new(vec![
            rmcp::model::Root::new(self.0.clone()),
        ]))
    }
}

#[tokio::test]
async fn without_a_folder_the_clients_root_is_served() {
    let project = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        project.path().join("root.c"),
        "int from_the_root(void) { return 1; }\n",
    )
    .expect("write");
    let root = std::fs::canonicalize(project.path()).expect("canonical");
    let (server_side, client_side) = tokio::io::duplex(64 * 1024);
    let server = Server::new(Arc::new(Backend::unsettled()));
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_side).await {
            let _ = running.waiting().await;
        }
    });
    let uri = format!("file://{}", root.display());
    let client = WithRoot(uri)
        .serve(client_side)
        .await
        .expect("client connects");
    let result = client
        .call_tool(
            CallToolRequestParams::new("find_symbol").with_arguments(
                serde_json::json!({"query": "from_the_root"})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            ),
        )
        .await
        .expect("call");
    assert!(
        text(&result).contains("from_the_root  root.c:1"),
        "{}",
        text(&result)
    );
    let _ = client.cancel().await;
}
