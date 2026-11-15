//! Finding symbols and reading code: a fuzzy name search, one function's
//! source, and a range of lines of an indexed file.

use crate::app::palette::{search, Candidates, Entry};
use crate::mcp::args::{FindSymbolArgs, ReadSourceArgs, SymbolArgs};
use crate::mcp::format::{count, limit, place, shown, MAX_CODE_CHARS};
use crate::mcp::resolve;
use crate::mcp::workspace::Workspace;
use crate::model::{FunctionMetrics, SymbolId};

const DEFAULT_MATCHES: usize = 20;
const MAX_MATCHES: usize = 100;
/// A function's source is cut after this many lines.
const MAX_FUNCTION_LINES: u32 = 300;
/// Lines shown from a type or variable's declaration.
const DECLARATION_LINES: u32 = 40;
const DEFAULT_READ_LINES: u32 = 80;
const MAX_READ_LINES: u32 = 200;

/// Symbols (and library functions named exactly) matching `query`.
pub fn find_symbol(ws: &Workspace, args: &FindSymbolArgs) -> Result<String, String> {
    let query = args.query.trim();
    if query.is_empty() {
        return Err("Give part of a name to search for.".into());
    }
    let limit = limit(args.limit, DEFAULT_MATCHES, MAX_MATCHES);
    let candidates = Candidates {
        symbols: ws.project.search_candidates(),
        notes: &[],
        library: ws.project.library_candidates(),
    };
    // The palette's prefixes aren't for the agent: `>quit` is a name here.
    let query = query.trim_start_matches(['>', '#', '!']);
    let found = search(&candidates, query, limit);
    if found.is_empty() {
        return Ok(format!(
            "No symbol matches `{}`. For a function the project calls but doesn't define, try library_calls.",
            shown(query, MAX_CODE_CHARS)
        ));
    }
    let lines: Vec<String> = found.iter().filter_map(|e| entry_line(ws, *e)).collect();
    Ok(lines.join("\n"))
}

fn entry_line(ws: &Workspace, entry: Entry) -> Option<String> {
    match entry {
        Entry::Symbol(id) => Some(symbol_line(ws, id)),
        Entry::LibraryFunction(i) => ws.project.library_functions().get(i).map(|f| {
            format!(
                "library  {}()  {}  (not defined in the project; xrefs lists the calls)",
                shown(&f.name, MAX_CODE_CHARS),
                count(f.calls, "call")
            )
        }),
        Entry::Command(_) | Entry::Note(_) => None,
    }
}

/// `function  name  file:line  prototype`.
fn symbol_line(ws: &Workspace, id: SymbolId) -> String {
    let Some(symbol) = ws.graph().symbols.get(&id) else {
        return "?".into();
    };
    let definitions = ws.definitions(id);
    let mut line = format!(
        "{}  {}  {}",
        symbol.kind.label(),
        shown(&symbol.qualified_name, MAX_CODE_CHARS),
        place(&symbol.file, symbol.line)
    );
    let prototype = definitions
        .first()
        .map(|d| d.signature.prototype.as_str())
        .filter(|p| !p.is_empty());
    if let Some(prototype) = prototype {
        line.push_str("  ");
        line.push_str(&shown(prototype, MAX_CODE_CHARS));
    }
    if definitions.len() > 1 {
        line.push_str(&format!(
            "  (defined in {}; pass file to function_source)",
            count(definitions.len(), "place")
        ));
    }
    line
}

/// One function's definition, numbered; a type or variable's
/// declaration and the lines after it.
pub fn function_source(ws: &Workspace, args: &SymbolArgs) -> Result<String, String> {
    let file = args
        .file
        .as_deref()
        .map(str::trim)
        .filter(|f| !f.is_empty());
    let id = resolve::symbol(ws, &args.name, file)?;
    let symbol = ws.graph().symbols.get(&id).ok_or("That symbol is gone.")?;
    let definitions: Vec<&FunctionMetrics> = ws
        .definitions(id)
        .into_iter()
        .filter(|d| file.is_none_or(|f| d.file == f))
        .collect();
    match definitions.as_slice() {
        [] => declaration(ws, id),
        [one] => definition(ws, symbol.qualified_name.as_str(), one),
        several => Err(several_places(ws, id, several)),
    }
}

/// The one definition of the function `name` (in `file`, if given).
pub fn definition_of<'w>(
    ws: &'w Workspace,
    name: &str,
    file: Option<&str>,
) -> Result<&'w FunctionMetrics, String> {
    let file = file.map(str::trim).filter(|f| !f.is_empty());
    let id = resolve::symbol(ws, name, file)?;
    let definitions: Vec<&FunctionMetrics> = ws
        .definitions(id)
        .into_iter()
        .filter(|d| file.is_none_or(|f| d.file == f))
        .collect();
    match definitions.as_slice() {
        [one] => Ok(one),
        [] => Err(format!(
            "{} has no function body in the index.",
            crate::mcp::format::name_of(ws, id)
        )),
        several => Err(several_places(ws, id, several)),
    }
}

/// `name is defined in 3 places; pass file to pick one:` and the places.
fn several_places(ws: &Workspace, id: SymbolId, places: &[&FunctionMetrics]) -> String {
    let mut lines = vec![format!(
        "{} is defined in {}; pass file to pick one:",
        crate::mcp::format::name_of(ws, id),
        count(places.len(), "place")
    )];
    lines.extend(
        places
            .iter()
            .map(|d| format!("  {}", place(&d.file, d.line))),
    );
    lines.join("\n")
}

/// A symbol with no function body: lines from its declaration.
fn declaration(ws: &Workspace, id: SymbolId) -> Result<String, String> {
    let symbol = ws.graph().symbols.get(&id).ok_or("That symbol is gone.")?;
    let last = symbol.line.saturating_add(DECLARATION_LINES - 1);
    let header = format!(
        "{} {} (no function body indexed; {} from its declaration)",
        symbol.kind.label(),
        shown(&symbol.qualified_name, MAX_CODE_CHARS),
        count(DECLARATION_LINES as usize, "line")
    );
    let (_, body) = numbered(ws, &symbol.file, symbol.line, last)?;
    Ok(format!("{header}\n{body}"))
}

/// A function's definition, numbered, cut if very long.
fn definition(ws: &Workspace, name: &str, metrics: &FunctionMetrics) -> Result<String, String> {
    let last = metrics.line.saturating_add(metrics.lines.saturating_sub(1));
    let cut = metrics
        .line
        .saturating_add(MAX_FUNCTION_LINES - 1)
        .min(last);
    let title = match metrics.signature.prototype.as_str() {
        "" => shown(name, MAX_CODE_CHARS),
        prototype => shown(prototype, MAX_CODE_CHARS),
    };
    let header = format!(
        "{title}  {}-{last}  ({}, complexity {})",
        place(&metrics.file, metrics.line),
        count(metrics.lines as usize, "line"),
        metrics.complexity
    );
    let (_, body) = numbered(ws, &metrics.file, metrics.line, cut)?;
    let mut text = format!("{header}\n{body}");
    if cut < last {
        text.push_str(&format!(
            "\n… cut at {MAX_FUNCTION_LINES} lines; read_source {} from line {} for the rest",
            shown(&metrics.file, MAX_CODE_CHARS),
            cut + 1
        ));
    }
    Ok(text)
}

/// Lines `start_line..=end_line` of an indexed file, numbered.
pub fn read_source(ws: &Workspace, args: &ReadSourceArgs) -> Result<String, String> {
    let start = args.start_line.max(1);
    let wanted = args
        .end_line
        .unwrap_or_else(|| start.saturating_add(DEFAULT_READ_LINES - 1));
    let end = wanted
        .max(start)
        .min(start.saturating_add(MAX_READ_LINES - 1));
    let (total, body) = numbered(ws, &args.file, start, end)?;
    let last = end.min(total);
    Ok(format!(
        "{}-{last} of {}\n{body}",
        place(&args.file, start),
        count(total as usize, "line")
    ))
}

/// The file's line count, and its lines `first..=last` (kept inside the
/// file) as `    4  code`, hidden characters marked.
fn numbered(ws: &Workspace, file: &str, first: u32, last: u32) -> Result<(u32, String), String> {
    let text = ws.graph().file_contents.get(file).ok_or_else(|| {
        format!(
            "{} is not an indexed file. Files are project-relative, as other tools list them (net/parse.c).",
            shown(file, MAX_CODE_CHARS)
        )
    })?;
    let total = u32::try_from(text.lines().count()).unwrap_or(u32::MAX);
    if first > total {
        return Err(format!(
            "{} has {}.",
            shown(file, MAX_CODE_CHARS),
            count(total as usize, "line")
        ));
    }
    let skip = usize::try_from(first - 1).unwrap_or(usize::MAX);
    let take = usize::try_from(last.min(total) - first + 1).unwrap_or(0);
    let guard = ws.guard();
    let lines: Vec<String> = text
        .lines()
        .skip(skip)
        .take(take)
        .zip(first..)
        .map(|(code, n)| format!("{n:>5}  {}", guard.line(file, n, code, MAX_LINE_CHARS)))
        .collect();
    Ok((total, lines.join("\n")))
}

/// A source line is cut to this many characters (minified code).
const MAX_LINE_CHARS: usize = 400;

#[cfg(test)]
#[path = "symbols_tests.rs"]
mod tests;
