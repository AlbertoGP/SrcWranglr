//! Tools for vulnerability research workflows (AAVR's attack-surface,
//! target-selection and harness phases): where outside input comes in and
//! what it reaches, the functions worth fuzzing, and a harness for one,
//! with its dictionary and Makefile.

use std::path::{Component, Path};

use crate::analysis::fuzz::harness::{self, Engine};
use crate::analysis::fuzz::{dictionary, makefile};
use crate::analysis::reach::describe;
use crate::mcp::args::{FuzzTargetsArgs, Fuzzer, HarnessArgs, InputPathsArgs};
use crate::mcp::format::{
    count, is_under, limit, more, name_of, place, shown, shown_file, MAX_CODE_CHARS,
    MAX_TEXT_CHARS, UNTRUSTED,
};
use crate::mcp::resolve;
use crate::mcp::tools::symbols::definition_of;
use crate::mcp::workspace::Workspace;

const DEFAULT_TARGETS: usize = 20;
const MAX_TARGETS: usize = 100;
/// Reasons shown per fuzz target.
const REASONS_SHOWN: usize = 3;
const DEFAULT_REACHED: usize = 50;
const MAX_REACHED: usize = 500;
/// Where harnesses go, as AAVR lays out its files.
const HARNESS_FOLDER: &str = ".aavr/harnesses";

/// The functions worth fuzzing, best first, each with what its score is
/// made of.
pub fn fuzz_targets(ws: &Workspace, args: &FuzzTargetsArgs) -> Result<String, String> {
    let limit = limit(args.limit, DEFAULT_TARGETS, MAX_TARGETS);
    let targets: Vec<_> = ws
        .fuzz_targets()
        .iter()
        .filter(|t| is_under(&t.file, args.path.as_deref()))
        .collect();
    if targets.is_empty() {
        return Ok("No function here looks worth fuzzing: none takes data to parse.".into());
    }
    let mut lines = vec![format!(
        "{} worth fuzzing, best first (score = worth to fuzz + ease of a harness):",
        count(targets.len(), "function")
    )];
    lines.extend(targets.iter().take(limit).map(|t| {
        let reasons: Vec<String> = t
            .reasons
            .iter()
            .take(REASONS_SHOWN)
            .map(|r| format!("{:+} {}", r.points, shown(&r.text, MAX_CODE_CHARS)))
            .collect();
        format!(
            "{:>4}  {}  {}  {}  │ {}",
            t.score,
            shown(&t.name, MAX_CODE_CHARS),
            place(&t.file, t.line),
            t.ease.label(),
            reasons.join("; ")
        )
    }));
    lines.extend(more(
        limit,
        targets.len(),
        "narrow with path, or raise limit",
    ));
    lines.push(format!("\n{UNTRUSTED}"));
    Ok(lines.join("\n"))
}

/// A harness for one function, its dictionary and its Makefile, to save
/// in a folder of the project (AAVR's by default).
pub fn fuzz_harness(ws: &Workspace, args: &HarnessArgs) -> Result<String, String> {
    let function = definition_of(ws, &args.name, args.file.as_deref())?;
    let graph = ws.graph();
    let engine = match args.fuzzer {
        Some(Fuzzer::Afl) => Engine::Afl,
        Some(Fuzzer::Libfuzzer) | None => Engine::LibFuzzer,
    };
    let fail = || "SrcWranglr couldn't draft a harness for it.".to_string();
    let harness = harness::draft(graph, function, engine).ok_or_else(fail)?;
    let dictionary = dictionary::draft(graph, function);
    let makefile = makefile::draft(graph, function, dictionary.is_some()).ok_or_else(fail)?;
    let name = name_of(ws, function.symbol);
    let stem = harness::stem_for(&name);
    let folder = match args.folder.as_deref().map(str::trim) {
        Some(folder) if !folder.is_empty() => inside_project(folder)?,
        _ => format!("{HARNESS_FOLDER}/{stem}"),
    };
    let depth = Path::new(&folder)
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count();
    let root = vec![".."; depth.max(1)].join("/");
    let todos = harness::todo_count(&harness.code);
    let mut text = vec![
        format!(
            "Harness for {name} ({}), to save in {}/ (the Makefile's paths are written for there).",
            engine.label(),
            shown(&folder, MAX_CODE_CHARS)
        ),
        format!(
            "{} to fill in before building. Build and run with: make -f {}",
            count(todos, "TODO"),
            makefile.file_name
        ),
        String::new(),
        format!("=== {}", harness.file_name),
        shown_file(&harness.code),
    ];
    if let Some(dictionary) = &dictionary {
        text.push(format!(
            "=== {} ({})",
            dictionary.file_name,
            count(dictionary.token_count, "token")
        ));
        text.push(shown_file(&dictionary.text));
    }
    text.push(format!("=== {}", makefile.file_name));
    text.push(shown_file(&makefile::with_root(&makefile.text, &root)));
    // The dictionary and declaration come from the tree: data, not orders.
    text.push(format!("\n{UNTRUSTED}"));
    Ok(text.join("\n"))
}

/// `folder`, if it's a project-relative folder that stays inside.
fn inside_project(folder: &str) -> Result<String, String> {
    let is_inside = Path::new(folder)
        .components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
    match is_inside {
        true => Ok(folder.trim_end_matches('/').to_string()),
        false => Err(format!(
            "{} isn't a folder inside the project; give a project-relative one such as {HARNESS_FOLDER}/fuzz_parse.",
            shown(folder, MAX_CODE_CHARS)
        )),
    }
}

/// Where outside input comes in and the findings it reaches, or how it
/// reaches one function.
pub fn input_paths(ws: &Workspace, args: &InputPathsArgs) -> Result<String, String> {
    let reach = ws.reach();
    let graph = ws.graph();
    if let Some(name) = args.name.as_deref() {
        let id = resolve::symbol(ws, name, args.file.as_deref())?;
        return Ok(match reach.path_to(id) {
            Some(path) => format!(
                "Input reaches {}: {}",
                name_of(ws, id),
                shown(&describe(&path, graph), MAX_TEXT_CHARS)
            ),
            None => format!(
                "No direct call path from input to {} was found. Function pointers, callbacks and virtual calls aren't followed, so that doesn't prove it unreachable.",
                name_of(ws, id)
            ),
        });
    }
    let sources = reach.sources();
    if sources.is_empty() {
        return Ok("SrcWranglr found no place outside input comes in (recv, read, fgets, getenv, scanf, main's command line and the like).".into());
    }
    let sources: Vec<String> = sources.iter().map(|s| shown(s, MAX_CODE_CHARS)).collect();
    let mut lines = vec![format!(
        "Input comes in through {}, and reaches {}. Only direct calls are followed: a prioritizer, not proof.",
        sources.join(", "),
        count(reach.len(), "function")
    )];
    let findings = ws.findings();
    let reached: Vec<_> = findings
        .all()
        .iter()
        .filter(|f| reach.reaches_finding(f))
        .collect();
    if reached.is_empty() {
        lines.push("No finding is on the way.".into());
        return Ok(lines.join("\n"));
    }
    let limit = limit(args.limit, DEFAULT_REACHED, MAX_REACHED);
    lines.push(format!(
        "{} input may reach, most severe first:",
        count(reached.len(), "finding")
    ));
    lines.extend(reached.iter().take(limit).map(|f| {
        let path = reach
            .finding_path(f)
            .map(|p| shown(&describe(&p, graph), MAX_TEXT_CHARS))
            .unwrap_or_default();
        let function = f
            .symbol
            .map(|id| format!("  in {}", name_of(ws, id)))
            .unwrap_or_default();
        format!(
            "{}  {}  {}{function}  │ {path}",
            f.severity.label(),
            shown(&f.rule, MAX_CODE_CHARS),
            place(&f.file, f.line)
        )
    }));
    lines.extend(more(limit, reached.len(), "raise limit"));
    lines.push(format!("\n{UNTRUSTED}"));
    Ok(lines.join("\n"))
}

#[cfg(test)]
#[path = "research_tests.rs"]
mod tests;
