//! The tools the in-app agent offers the model, and running one. Every
//! schema is generated from the argument type the MCP server already uses,
//! so there's one source for the shapes; the descriptions mirror the
//! server's. A call runs through the same `mcp::dispatch` the MCP server
//! uses, so the in-app agent and an external one behave the same.

use schemars::JsonSchema;
use serde_json::{json, Value};

use super::llm::ToolSpec;
use crate::mcp::args::{
    AddNoteArgs, CallArgs, DraftRuleArgs, FindSymbolArgs, FindingsArgs, FuzzTargetsArgs,
    HarnessArgs, ImportSarifArgs, InputPathsArgs, JournalArgs, LibraryArgs, NotesArgs,
    ReadSourceArgs, StringsArgs, SymbolArgs, TraceArgs, VerdictArgs, XrefsArgs,
};

/// The schema of an argument type, as the model reads it.
fn schema<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).unwrap_or_else(|_| json!({"type": "object"}))
}

fn spec(name: &str, description: &str, parameters: Value) -> ToolSpec {
    ToolSpec {
        name: name.into(),
        description: description.into(),
        parameters,
    }
}

fn typed<T: JsonSchema>(name: &str, description: &str) -> ToolSpec {
    spec(name, description, schema::<T>())
}

fn no_args(name: &str, description: &str) -> ToolSpec {
    spec(
        name,
        description,
        json!({"type": "object", "properties": {}}),
    )
}

/// The tools on offer, in a sensible reading order. The names and order
/// match `mcp::dispatch::TOOLS`; the descriptions mirror the MCP server's.
pub fn specs() -> Vec<ToolSpec> {
    vec![
        no_args(
            "overview",
            "Start here: size and folders, entry points, most complex functions, most called library functions, what the findings are about, and how many possible prompt injections.",
        ),
        typed::<FindSymbolArgs>(
            "find_symbol",
            "Find functions, types and variables by part of their name (fuzzy): kind, file:line and prototype.",
        ),
        typed::<SymbolArgs>(
            "function_source",
            "One function's source, numbered, without reading its whole file.",
        ),
        typed::<ReadSourceArgs>(
            "read_source",
            "Lines of an indexed file (at most 200 a call), for code outside functions: macros, globals, struct bodies.",
        ),
        typed::<CallArgs>(
            "callers",
            "The functions that call a function, as a tree, depth levels up. Follows resolved calls only.",
        ),
        typed::<CallArgs>(
            "callees",
            "What a function calls: project functions as a tree, and the library functions each calls.",
        ),
        typed::<XrefsArgs>(
            "xrefs",
            "Every reference to a symbol, or every call to a library function (system, memcpy): file:line, kind, enclosing function, code.",
        ),
        typed::<LibraryArgs>(
            "library_calls",
            "Library functions the project calls but doesn't define, with how many calls, most called first.",
        ),
        typed::<FindingsArgs>(
            "findings",
            "Risky calls and other findings, most severe first, with the user's verdicts. Narrow by severity, path or rule.",
        ),
        typed::<StringsArgs>(
            "strings",
            "String literals containing some text, where each is and the function it is in.",
        ),
        typed::<NotesArgs>("notes", "The notes the user and agents left on symbols and lines."),
        typed::<AddNoteArgs>(
            "add_note",
            "Leave the user a note on a symbol or file:line; record findings and reasoning worth keeping. It goes below any note already there.",
        ),
        typed::<InputPathsArgs>(
            "input_paths",
            "Where outside input comes in (recv, read, fgets, getenv, argv) and the findings it may reach, each with its call path; or, given a name, how input reaches that function.",
        ),
        typed::<FuzzTargetsArgs>(
            "fuzz_targets",
            "Functions worth fuzzing, best first, with the reasons (what they parse, risky calls, how easy a harness is).",
        ),
        typed::<HarnessArgs>(
            "fuzz_harness",
            "A fuzz harness for one function (libFuzzer or AFL++), with a dictionary and a Makefile, as files to save (default under .aavr/harnesses/). You build and run it; SrcWranglr does not.",
        ),
        typed::<TraceArgs>(
            "trace",
            "Follow a value: back to where it comes from, forward to the risky calls it reaches, or to one call you name. Without a name, traces back the risky call's arguments on that line.",
        ),
        typed::<DraftRuleArgs>(
            "draft_rule",
            "A semgrep rule finding code like some lines, for variant analysis. You run semgrep with it.",
        ),
        typed::<JournalArgs>(
            "journal_entry",
            "Write an entry in the user's Journal (Markdown), marked as yours: what a phase did, found or ruled out, with an optional file:line.",
        ),
        typed::<ImportSarifArgs>(
            "import_sarif",
            "Bring a SARIF report you wrote inside the project (your semgrep or CodeQL run) into the user's Findings.",
        ),
        typed::<VerdictArgs>(
            "set_verdict",
            "Mark a finding (by its file, line and rule, as findings lists them): confirmed, false_positive, reviewed or clear. Dismissing one, or any verdict on a prompt injection, waits for the user's approval.",
        ),
        typed::<crate::agent::exec::RunCommandArgs>(
            "run_command",
            "Run a shell command in the project's folder (sh -c): build a harness, run a fuzzer for a fixed time, reproduce a crash, run semgrep. The user approves each command before it runs; output is capped and it is killed at its time limit.",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_dispatch_tool_has_a_spec_with_a_schema() {
        let specs = specs();
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        for tool in crate::mcp::dispatch::TOOLS {
            assert!(names.contains(&tool), "{tool} has no spec");
        }
        // Every dispatch tool, plus run_command (in-app only).
        assert_eq!(specs.len(), crate::mcp::dispatch::TOOLS.len() + 1);
        assert!(names.contains(&"run_command"));
        // Schemas are real objects, and a tool with args describes them.
        let find = specs
            .iter()
            .find(|s| s.name == "find_symbol")
            .expect("find_symbol");
        assert_eq!(find.parameters["type"], "object");
        assert!(
            find.parameters["properties"].get("query").is_some(),
            "{}",
            find.parameters
        );
    }
}
