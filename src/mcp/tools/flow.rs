//! Following values and finding look-alikes (AAVR's triage and variant
//! phases): a value traced back to where it comes from, forward to the
//! risky calls it reaches, or to one call; and a semgrep rule drafted from
//! code, to search for more like it.

use crate::analysis::similar::{draft_from, Example, Looseness};
use crate::analysis::trace::{self, Sink, Trace};
use crate::mcp::args::{DraftRuleArgs, TraceArgs, TraceDirection};
use crate::mcp::format::{
    code_at, count, name_of, place, shown, shown_file, MAX_CODE_CHARS, MAX_TEXT_CHARS, UNTRUSTED,
};
use crate::mcp::resolve;
use crate::mcp::workspace::Workspace;

/// Paths listed at most, and steps per path.
const MAX_PATHS: usize = 10;
/// Lines a drafted rule may span.
const MAX_RULE_LINES: u32 = 50;
const MAX_STEPS: usize = 30;

/// Where a value comes from or goes, every step on the way.
pub fn trace(ws: &Workspace, args: &TraceArgs) -> Result<String, String> {
    let graph = ws.graph();
    let file = resolve::file(ws, &args.file)?;
    let text = ws
        .line(&file, args.line)
        .ok_or_else(|| no_line(ws, &file))?;
    let column = match args.name.as_deref().map(str::trim) {
        Some(name) if !name.is_empty() => column_of(text, name).ok_or_else(|| {
            format!(
                "`{}` isn't on {}; give a variable written on that line.",
                shown(name, MAX_CODE_CHARS),
                place(&file, args.line)
            )
        })?,
        _ => 0,
    };
    let has_name = args.name.as_deref().is_some_and(|n| !n.trim().is_empty());
    let (file, line) = (file.as_str(), args.line);
    let traced = match (args.direction.unwrap_or(TraceDirection::Back), has_name) {
        (TraceDirection::Back, true) => trace::trace_variable(graph, file, line, column),
        (TraceDirection::Back, false) => trace::trace_call(graph, file, line, column),
        (_, false) => return Err("Name the variable to follow forward.".into()),
        (TraceDirection::Forward, true) => {
            let sinks = trace::sinks_of(ws.findings().all());
            trace::trace_forward(graph, &sinks, file, line, column)
        }
        (TraceDirection::To, true) => {
            let sink = sink_of(args)?;
            trace::trace_between(graph, file, line, column, &sink)
        }
    };
    let traced = traced.ok_or("Nothing on that line to trace: give a variable written there, or (tracing back) a line with a call.")?;
    Ok(render(ws, &traced))
}

/// The call a value should reach, from `sink_file`, `sink_line` and
/// `sink_call`.
fn sink_of(args: &TraceArgs) -> Result<Sink, String> {
    match (&args.sink_file, args.sink_line, &args.sink_call) {
        (Some(file), Some(line), Some(call)) if !call.trim().is_empty() => {
            Ok(Sink::picked(file, line, call.trim()))
        }
        _ => Err("Tracing to a call needs sink_file, sink_line and sink_call.".into()),
    }
}

/// The trace, each path's steps numbered under how it ends.
fn render(ws: &Workspace, traced: &Trace) -> String {
    let way = match traced.direction {
        trace::Direction::Back => "back from",
        trace::Direction::Forward => "forward from",
        trace::Direction::Between => "from",
    };
    let mut lines = vec![format!(
        "Traced {way} {} at {} ({}):",
        shown(&traced.subject, MAX_CODE_CHARS),
        place(&traced.file, traced.line),
        count(traced.paths.len(), "path")
    )];
    for (i, path) in traced.paths.iter().take(MAX_PATHS).enumerate() {
        lines.push(format!(
            "{}. {}",
            i + 1,
            shown(&path.endpoint.label(), MAX_TEXT_CHARS)
        ));
        for step in path.steps.iter().take(MAX_STEPS) {
            let function = step
                .symbol
                .map(|id| format!("  in {}", name_of(ws, id)))
                .unwrap_or_default();
            lines.push(format!(
                "   {}{function}  │ {}  — {}",
                place(&step.file, step.line),
                code_at(ws, &step.file, step.line),
                shown(&step.note, MAX_TEXT_CHARS)
            ));
        }
        if path.steps.len() > MAX_STEPS {
            lines.push(format!("   … {} more steps", path.steps.len() - MAX_STEPS));
        }
    }
    if traced.paths.len() > MAX_PATHS {
        lines.push(format!("… {} more paths", traced.paths.len() - MAX_PATHS));
    }
    if traced.is_cut_short {
        lines.push("The trace hit a limit, so there may be more paths.".into());
    }
    lines.push(format!("\n{UNTRUSTED}"));
    lines.join("\n")
}

/// The byte column where `name` is written on `line`, as a whole word.
fn column_of(line: &str, name: &str) -> Option<u32> {
    let is_word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    let at = line.match_indices(name).map(|(at, _)| at).find(|&at| {
        !is_word(line[..at].chars().next_back()) && !is_word(line[at + name.len()..].chars().next())
    })?;
    u32::try_from(at).ok()
}

fn no_line(ws: &Workspace, file: &str) -> String {
    match ws.graph().file_contents.get(file) {
        Some(text) => format!(
            "{} has {}.",
            shown(file, MAX_CODE_CHARS),
            count(text.lines().count(), "line")
        ),
        None => format!(
            "{} is not an indexed file. Files are project-relative, as other tools list them.",
            shown(file, MAX_CODE_CHARS)
        ),
    }
}

/// A semgrep rule finding code like lines `first_line..=last_line`.
pub fn draft_rule(ws: &Workspace, args: &DraftRuleArgs) -> Result<String, String> {
    let file = resolve::file(ws, &args.file)?;
    let text = ws
        .graph()
        .file_contents
        .get(&file)
        .ok_or_else(|| no_line(ws, &file))?;
    let first = args.first_line.max(1);
    let last = args
        .last_line
        .unwrap_or(first)
        .max(first)
        .min(first.saturating_add(MAX_RULE_LINES - 1));
    ws.line(&file, last).ok_or_else(|| no_line(ws, &file))?;
    let example = Example::lines(&file, first, last);
    let draft = draft_from(&[(example.clone(), text.as_str())], false)?;
    let looseness = match args.any_values.unwrap_or(false) && draft.any_values.is_some() {
        true => Looseness::AnyValues,
        false => Looseness::SameShape,
    };
    let yaml = draft.yaml(looseness, &[]);
    Ok(format!(
        "A semgrep rule finding code like {} ({}). Save it as {}.yaml, then run: semgrep --config {}.yaml .\n\n{}\n\n{UNTRUSTED}",
        shown(&example.place(), MAX_CODE_CHARS),
        looseness.label().to_lowercase(),
        draft.id,
        draft.id,
        shown_file(&yaml)
    ))
}

#[cfg(test)]
#[path = "flow_tests.rs"]
mod tests;
