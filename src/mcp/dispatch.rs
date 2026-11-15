//! One way into the tools for every caller (the MCP server answering from
//! its own index, and the app answering for a running agent): a tool by
//! name, its arguments as JSON. Also what a call was about, for the app's
//! Agent pane.

use serde::de::DeserializeOwned;
use serde_json::Value;

use super::args::ImportSarifArgs;
use super::args::{AddNoteArgs, ReadSourceArgs};
use super::format::{shown, MAX_CODE_CHARS};
use super::resolve;
use super::tools::{flow, graph, lists, notes, overview, records, research, symbols, verdicts};
use super::workspace::Workspace;
use crate::model::SymbolId;
use crate::notes::NoteTarget;

/// Every tool, by the name agents call it.
#[cfg(test)]
pub const TOOLS: [&str; 20] = [
    "overview",
    "find_symbol",
    "function_source",
    "read_source",
    "callers",
    "callees",
    "xrefs",
    "library_calls",
    "findings",
    "strings",
    "notes",
    "add_note",
    "input_paths",
    "fuzz_targets",
    "fuzz_harness",
    "trace",
    "draft_rule",
    "journal_entry",
    "import_sarif",
    "set_verdict",
];

/// The answer of `tool` called with `args`, by the workspace as it is now
/// (your verdicts read again if they changed). `now` is in Unix seconds.
pub fn dispatch(ws: &Workspace, tool: &str, args: Value, now: u64) -> Result<String, String> {
    ws.refresh_verdicts();
    match tool {
        "overview" => Ok(overview::overview(ws)),
        "find_symbol" => symbols::find_symbol(ws, &parsed(args)?),
        "function_source" => symbols::function_source(ws, &parsed(args)?),
        "read_source" => symbols::read_source(ws, &parsed(args)?),
        "callers" => graph::callers(ws, &parsed(args)?),
        "callees" => graph::callees(ws, &parsed(args)?),
        "xrefs" => graph::xrefs(ws, &parsed(args)?),
        "library_calls" => graph::library_calls(ws, &parsed(args)?),
        "findings" => lists::findings(ws, &parsed(args)?),
        "strings" => lists::strings(ws, &parsed(args)?),
        "notes" => notes::notes(ws, &parsed(args)?),
        "add_note" => notes::add_note(ws, &parsed(args)?, now),
        "input_paths" => research::input_paths(ws, &parsed(args)?),
        "fuzz_targets" => research::fuzz_targets(ws, &parsed(args)?),
        "fuzz_harness" => research::fuzz_harness(ws, &parsed(args)?),
        "trace" => flow::trace(ws, &parsed(args)?),
        "draft_rule" => flow::draft_rule(ws, &parsed(args)?),
        "journal_entry" => records::journal_entry(ws, &parsed(args)?, now),
        "import_sarif" => {
            let args: ImportSarifArgs = parsed(args)?;
            records::sarif_file(ws, &args.file)?;
            Err("Importing into Findings needs the SrcWranglr app open on this project: the user sees them there. Ask the user to open it, then call again.".into())
        }
        "set_verdict" => {
            // Validate the finding, then say it needs the app (the user
            // sees verdicts in Findings and approves the risky ones).
            verdicts::verdict_change(ws, &parsed(args)?)?;
            Err("Marking findings needs the SrcWranglr app open on this project: the user sees the verdicts in Findings and approves the risky ones. Ask the user to open it, then call again.".into())
        }
        other => Err(format!(
            "SrcWranglr has no tool `{}`.",
            shown(other, MAX_CODE_CHARS)
        )),
    }
}

/// `args` as the tool's arguments. No arguments read as none given.
pub fn parsed<T: DeserializeOwned>(args: Value) -> Result<T, String> {
    let args = match args {
        Value::Null => Value::Object(serde_json::Map::new()),
        args => args,
    };
    serde_json::from_value(args).map_err(|e| format!("Those arguments don't fit the tool: {e}"))
}

/// Where in the project a call was looking, for going there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    pub symbol: Option<SymbolId>,
    pub file: String,
    pub line: u32,
}

/// The place `tool` called with `args` is about, if it is about one.
pub fn place_of(ws: &Workspace, tool: &str, args: &Value) -> Option<Place> {
    let text = |key: &str| args.get(key).and_then(Value::as_str);
    match tool {
        "function_source" | "callers" | "callees" | "xrefs" | "fuzz_harness" | "input_paths" => {
            symbol_place(ws, resolve::symbol(ws, text("name")?, text("file")).ok()?)
        }
        "set_verdict" => {
            let line = args.get("line").and_then(Value::as_u64)?;
            Some(Place {
                symbol: None,
                file: text("file")?.to_string(),
                line: u32::try_from(line).ok()?.max(1),
            })
        }
        "trace" | "draft_rule" => {
            let file = text("file")?;
            let line = ["line", "first_line"]
                .iter()
                .find_map(|key| args.get(*key).and_then(Value::as_u64))?;
            let line = u32::try_from(line).ok()?.max(1);
            ws.line(file, line).map(|_| Place {
                symbol: None,
                file: file.to_string(),
                line,
            })
        }
        "read_source" => {
            let args: ReadSourceArgs = parsed(args.clone()).ok()?;
            ws.graph()
                .file_contents
                .contains_key(&args.file)
                .then(|| Place {
                    symbol: None,
                    file: args.file,
                    line: args.start_line.max(1),
                })
        }
        "add_note" => {
            let args: AddNoteArgs = parsed(args.clone()).ok()?;
            match notes::target_of(ws, &args.target).ok()?.0 {
                NoteTarget::Line { file, line } => Some(Place {
                    symbol: None,
                    file,
                    line,
                }),
                NoteTarget::Symbol(_) => {
                    symbol_place(ws, resolve::symbol(ws, &args.target, None).ok()?)
                }
            }
        }
        _ => None,
    }
}

/// Where a symbol is defined (or declared, if it has no body).
fn symbol_place(ws: &Workspace, id: SymbolId) -> Option<Place> {
    let (file, line) = match ws.definitions(id).first() {
        Some(definition) => (definition.file.clone(), definition.line),
        None => {
            let symbol = ws.graph().symbols.get(&id)?;
            (symbol.file.clone(), symbol.line)
        }
    };
    Some(Place {
        symbol: Some(id),
        file,
        line,
    })
}

/// `args` in a line: `name=parse_header depth=2`, shown safely.
pub fn asked(args: &Value) -> String {
    let Some(object) = args.as_object() else {
        return String::new();
    };
    let pairs: Vec<String> = object
        .iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| match v {
            Value::String(s) => format!("{k}={s}"),
            other => format!("{k}={other}"),
        })
        .collect();
    shown(&pairs.join(" "), MAX_CODE_CHARS)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::mcp::fixture::workspace;

    #[test]
    fn a_tool_is_called_by_name_with_json_arguments() {
        let ws = workspace();
        let found = dispatch(&ws, "find_symbol", json!({"query": "parse_hdr"}), 0).expect("found");
        assert!(found.contains("parse_header  net/parse.c:4"), "{found}");
        assert!(dispatch(&ws, "overview", Value::Null, 0).is_ok());
        let error = dispatch(&ws, "find_symbol", json!({"query": 3}), 0).expect_err("bad");
        assert!(error.contains("don't fit"), "{error}");
        let error = dispatch(&ws, "rm_rf", json!({}), 0).expect_err("no such tool");
        assert!(error.contains("no tool `rm_rf`"), "{error}");
    }

    #[test]
    fn every_tool_named_is_one_dispatch_knows() {
        let ws = workspace();
        for tool in TOOLS {
            let answer = dispatch(&ws, tool, json!({}), 0);
            assert!(
                !answer.as_ref().is_err_and(|e| e.contains("no tool")),
                "{tool}: {answer:?}"
            );
        }
    }

    #[test]
    fn a_call_says_where_it_was_looking() {
        let ws = workspace();
        let place = place_of(&ws, "callers", &json!({"name": "parse_header"})).expect("place");
        assert_eq!((place.file.as_str(), place.line), ("net/parse.c", 4));
        assert!(place.symbol.is_some());
        let place = place_of(
            &ws,
            "read_source",
            &json!({"file": "main.c", "start_line": 6}),
        );
        assert_eq!(place.map(|p| p.line), Some(6));
        assert_eq!(place_of(&ws, "overview", &json!({})), None);
        assert_eq!(
            place_of(
                &ws,
                "read_source",
                &json!({"file": "nope.c", "start_line": 1})
            ),
            None
        );
    }

    #[test]
    fn arguments_read_as_one_line() {
        assert_eq!(asked(&json!({"name": "f", "depth": 2})), "depth=2 name=f");
        assert_eq!(asked(&json!({"file": "a\u{202E}b.c"})), "file=a‹U+202E›b.c");
    }
}
