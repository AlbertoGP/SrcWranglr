//! The MCP server: each tool hands its arguments to the backend (the
//! running app, or an index of its own) on a worker thread, since some
//! walk a whole kernel's graph.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::service::NotificationContext;
use rmcp::{tool, tool_handler, tool_router, Peer, RoleServer, ServerHandler};

use super::args::{
    AddNoteArgs, CallArgs, DraftRuleArgs, FindSymbolArgs, FindingsArgs, FuzzTargetsArgs,
    HarnessArgs, ImportSarifArgs, InputPathsArgs, JournalArgs, LibraryArgs, NotesArgs,
    ReadSourceArgs, StringsArgs, SymbolArgs, TraceArgs, VerdictArgs, XrefsArgs,
};
use super::backend::Backend;
use super::folder;
use super::format::UNTRUSTED;

const INSTRUCTIONS: &str = "\
SrcWranglr has indexed this C/C++ project: its symbols, call graph, cross references, \
risky calls (findings) and string literals. Ask it instead of grepping or reading whole files.
- Start with overview.
- find_symbol finds a name from part of it; function_source shows just that function.
- callers and callees follow the call graph; xrefs lists every use of a name, including calls to \
library functions such as system or memcpy.
- findings lists what is already flagged; strings finds literals.
- Names are qualified (Foo::bar) or short (bar). When several files define a name, pass file.
- add_note leaves a note the user sees in SrcWranglr; record what you find there.
For vulnerability research (AAVR's phases):
- attack surface: input_paths shows where outside input comes in and the findings it reaches.
- triage: trace follows a value back to its source, forward to risky calls, or to one call.
- fuzzing: fuzz_targets ranks functions worth a harness; fuzz_harness drafts one (libFuzzer or \
AFL++) with its dictionary and Makefile, to save under .aavr/harnesses/.
- variants: draft_rule writes a semgrep rule from code, to search for more like it.
- recording: journal_entry logs each phase's summary in the user's Journal; import_sarif brings \
your own scanners' SARIF results into the user's Findings; set_verdict marks a finding confirmed, \
false_positive, reviewed or clear (the user approves dismissing one or any on a prompt injection).
SrcWranglr never builds or runs the project; you do, with its harnesses and rules.
";

/// How long to wait for the client to say which folder it has open.
const ROOTS_WAIT: Duration = Duration::from_secs(3);
/// A tool waits a margin longer than the roots lookup, so a slow client's
/// roots still win over the folder started in.
const SETTLE_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct Server {
    backend: Arc<Backend>,
    tool_router: ToolRouter<Self>,
}

impl Server {
    pub fn new(backend: Arc<Backend>) -> Self {
        Self {
            backend,
            tool_router: Self::tool_router(),
        }
    }

    /// Asks the backend `tool` with `args`, off the async runtime.
    async fn call(
        &self,
        tool: &'static str,
        args: impl serde::Serialize,
    ) -> Result<String, String> {
        let args = serde_json::to_value(args).map_err(|e| e.to_string())?;
        let backend = Arc::clone(&self.backend);
        tokio::task::spawn_blocking(move || {
            // The client's roots may still be on their way.
            backend.settle_within(SETTLE_WAIT);
            backend.call(tool, args)
        })
        .await
        .unwrap_or_else(|error| Err(format!("The tool failed unexpectedly: {error}")))
    }
}

#[tool_router]
impl Server {
    #[tool(
        description = "Start here: the project's size and folders, entry points, most complex functions, most called library functions and what the findings are about.",
        annotations(read_only_hint = true)
    )]
    async fn overview(&self) -> Result<String, String> {
        self.call("overview", serde_json::json!({})).await
    }

    #[tool(
        description = "Find functions, types and variables by part of their name (fuzzy): kind, file:line and prototype. Use it to get a name right before the other tools.",
        annotations(read_only_hint = true)
    )]
    async fn find_symbol(
        &self,
        Parameters(args): Parameters<FindSymbolArgs>,
    ) -> Result<String, String> {
        self.call("find_symbol", args).await
    }

    #[tool(
        description = "The source of one function, with line numbers, without reading its whole file. For a type or variable, the lines from its declaration.",
        annotations(read_only_hint = true)
    )]
    async fn function_source(
        &self,
        Parameters(args): Parameters<SymbolArgs>,
    ) -> Result<String, String> {
        self.call("function_source", args).await
    }

    #[tool(
        description = "Lines of an indexed file, with line numbers, at most 200 a call: for code outside functions, such as macros, globals and struct bodies.",
        annotations(read_only_hint = true)
    )]
    async fn read_source(
        &self,
        Parameters(args): Parameters<ReadSourceArgs>,
    ) -> Result<String, String> {
        self.call("read_source", args).await
    }

    #[tool(
        description = "The functions that call a function, as a tree depth levels up. Follows resolved calls, so comments and strings that mention the name don't show up.",
        annotations(read_only_hint = true)
    )]
    async fn callers(&self, Parameters(args): Parameters<CallArgs>) -> Result<String, String> {
        self.call("callers", args).await
    }

    #[tool(
        description = "What a function calls: the project's functions as a tree depth levels down, and the library functions each one calls.",
        annotations(read_only_hint = true)
    )]
    async fn callees(&self, Parameters(args): Parameters<CallArgs>) -> Result<String, String> {
        self.call("callees", args).await
    }

    #[tool(
        description = "Every reference to a symbol, or every call to a library function the project calls (system, memcpy): file:line, kind, the function it is in, and the code. Narrow with path.",
        annotations(read_only_hint = true)
    )]
    async fn xrefs(&self, Parameters(args): Parameters<XrefsArgs>) -> Result<String, String> {
        self.call("xrefs", args).await
    }

    #[tool(
        description = "Library functions the project calls but doesn't define (libc, the OS, third-party APIs), with how many calls, most called first; or those matching a query.",
        annotations(read_only_hint = true)
    )]
    async fn library_calls(
        &self,
        Parameters(args): Parameters<LibraryArgs>,
    ) -> Result<String, String> {
        self.call("library_calls", args).await
    }

    #[tool(
        description = "Risky calls and other findings SrcWranglr flagged, most severe first, with the user's verdicts. Narrow by severity, path or rule.",
        annotations(read_only_hint = true)
    )]
    async fn findings(&self, Parameters(args): Parameters<FindingsArgs>) -> Result<String, String> {
        self.call("findings", args).await
    }

    #[tool(
        description = "String literals containing some text (ignoring case): where each is and the function it is in.",
        annotations(read_only_hint = true)
    )]
    async fn strings(&self, Parameters(args): Parameters<StringsArgs>) -> Result<String, String> {
        self.call("strings", args).await
    }

    #[tool(
        description = "The notes the user and agents left on symbols and lines.",
        annotations(read_only_hint = true)
    )]
    async fn notes(&self, Parameters(args): Parameters<NotesArgs>) -> Result<String, String> {
        self.call("notes", args).await
    }

    #[tool(
        description = "Leave the user a note on a symbol or a file:line; they see it in SrcWranglr. Record findings and reasoning worth keeping. It goes below any note already there."
    )]
    async fn add_note(&self, Parameters(args): Parameters<AddNoteArgs>) -> Result<String, String> {
        self.call("add_note", args).await
    }

    #[tool(
        description = "Where outside input comes in (recv, read, fgets, getenv, argv…) and the findings it may reach, each with its call path; or, given a name, how input reaches that function.",
        annotations(read_only_hint = true)
    )]
    async fn input_paths(
        &self,
        Parameters(args): Parameters<InputPathsArgs>,
    ) -> Result<String, String> {
        self.call("input_paths", args).await
    }

    #[tool(
        description = "Functions worth fuzzing, best first, with the score's reasons (what they parse, risky calls, how easy a harness is).",
        annotations(read_only_hint = true)
    )]
    async fn fuzz_targets(
        &self,
        Parameters(args): Parameters<FuzzTargetsArgs>,
    ) -> Result<String, String> {
        self.call("fuzz_targets", args).await
    }

    #[tool(
        description = "A fuzz harness for one function (libFuzzer or AFL++ persistent mode), with a dictionary of its constants and a Makefile with sanitizers, as files to save (default under .aavr/harnesses/). Fill in its TODOs, then build it yourself.",
        annotations(read_only_hint = true)
    )]
    async fn fuzz_harness(
        &self,
        Parameters(args): Parameters<HarnessArgs>,
    ) -> Result<String, String> {
        self.call("fuzz_harness", args).await
    }

    #[tool(
        description = "Follow a value: back to where it comes from (outside input, a constant, a parameter), forward to the risky calls it reaches, or to one call you name. Without a name, traces back the risky call's arguments on that line.",
        annotations(read_only_hint = true)
    )]
    async fn trace(&self, Parameters(args): Parameters<TraceArgs>) -> Result<String, String> {
        self.call("trace", args).await
    }

    #[tool(
        description = "A semgrep rule finding code like some lines of the project, for variant analysis: save it and run semgrep with it yourself.",
        annotations(read_only_hint = true)
    )]
    async fn draft_rule(
        &self,
        Parameters(args): Parameters<DraftRuleArgs>,
    ) -> Result<String, String> {
        self.call("draft_rule", args).await
    }

    #[tool(
        description = "Write an entry (Markdown) in the user's Journal, marked as yours: what a phase did, found or ruled out, with an optional file:line it's about."
    )]
    async fn journal_entry(
        &self,
        Parameters(args): Parameters<JournalArgs>,
    ) -> Result<String, String> {
        self.call("journal_entry", args).await
    }

    #[tool(
        description = "Bring a SARIF report you wrote inside the project (semgrep --sarif, CodeQL) into the user's Findings, each tool's results under its name. Needs the SrcWranglr app open on the project."
    )]
    async fn import_sarif(
        &self,
        Parameters(args): Parameters<ImportSarifArgs>,
    ) -> Result<String, String> {
        self.call("import_sarif", args).await
    }

    #[tool(
        description = "Mark a finding (named by its file, line and rule, as findings lists them): confirmed, false_positive, reviewed or clear. The user sees it in Findings; dismissing one or any verdict on a prompt injection waits for the user's approval."
    )]
    async fn set_verdict(
        &self,
        Parameters(args): Parameters<VerdictArgs>,
    ) -> Result<String, String> {
        self.call("set_verdict", args).await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("srcwranglr", env!("CARGO_PKG_VERSION")))
            .with_instructions(format!("{INSTRUCTIONS}{UNTRUSTED}"))
    }

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        if self.backend.is_settled() {
            return;
        }
        let (backend, peer) = (Arc::clone(&self.backend), context.peer.clone());
        tokio::spawn(async move {
            let folder = client_folder(&peer).await;
            // Settling may start an index or ask the app: not on the runtime.
            let settled = tokio::task::spawn_blocking(move || backend.settle(folder)).await;
            if let Err(error) = settled {
                eprintln!("srcwranglr --mcp: couldn't settle the project folder: {error}");
            }
        });
    }
}

/// The folder the client has open (its first `file://` root), else the
/// one `--mcp` was started in.
// Roots is deprecated (SEP-2577), but clients still answer it, and here
// it's only a hint: the folder started in is the fallback.
#[allow(deprecated)]
async fn client_folder(peer: &Peer<RoleServer>) -> Result<PathBuf, String> {
    let offers_roots = peer
        .peer_info()
        .is_some_and(|info| info.capabilities.roots.is_some());
    if offers_roots {
        if let Ok(Ok(listed)) = tokio::time::timeout(ROOTS_WAIT, peer.list_roots()).await {
            let named = listed
                .roots
                .iter()
                .find_map(|root| folder::from_root_uri(&root.uri));
            if let Some(path) = named {
                return folder::checked(&path, folder::home().as_deref());
            }
        }
    }
    folder::started_in()
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
