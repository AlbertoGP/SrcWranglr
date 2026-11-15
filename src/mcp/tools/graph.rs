//! Following the code: who calls a function and what it calls (levels
//! deep, as a tree), every reference to a name, and the library functions
//! the project calls.

use std::collections::{BTreeMap, HashSet};

use crate::app::palette::{search, Candidates, Entry, LIBRARY_PREFIX};
use crate::app::xrefs::{name_of, xrefs as all_xrefs};
use crate::code_view::Referenced;
use crate::mcp::args::{CallArgs, LibraryArgs, XrefsArgs};
use crate::mcp::format::{
    code_at, count, is_under, limit, more, name_and_place, name_of as symbol_name, place, shown,
    MAX_CODE_CHARS,
};
use crate::mcp::resolve;
use crate::mcp::workspace::Workspace;
use crate::model::SymbolId;

const DEFAULT_DEPTH: u32 = 1;
const MAX_DEPTH: u32 = 4;
/// A call tree is cut after this many lines.
const MAX_TREE_LINES: usize = 200;
const DEFAULT_XREFS: usize = 100;
const MAX_XREFS: usize = 500;
const DEFAULT_LIBRARY: usize = 50;
const MAX_LIBRARY: usize = 500;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Callers,
    Callees,
}

/// The functions calling `name`, and theirs, `depth` levels up.
pub fn callers(ws: &Workspace, args: &CallArgs) -> Result<String, String> {
    call_tree(ws, args, Direction::Callers)
}

/// The functions `name` calls, and theirs, `depth` levels down, with the
/// library functions each calls.
pub fn callees(ws: &Workspace, args: &CallArgs) -> Result<String, String> {
    call_tree(ws, args, Direction::Callees)
}

fn call_tree(ws: &Workspace, args: &CallArgs, direction: Direction) -> Result<String, String> {
    let root = resolve::symbol(ws, &args.name, args.file.as_deref())?;
    let depth = args.depth.unwrap_or(DEFAULT_DEPTH).clamp(1, MAX_DEPTH);
    let mut tree = Tree {
        ws,
        direction,
        lines: Vec::new(),
        seen: HashSet::from([root]),
        is_cut: false,
    };
    tree.walk(root, 1, depth);
    let name = symbol_name(ws, root);
    if tree.lines.is_empty() {
        return Ok(match direction {
            Direction::Callers => format!("Nothing in the project calls {name}."),
            Direction::Callees => {
                format!("{name} calls nothing in the project and no library functions.")
            }
        });
    }
    let title = match direction {
        Direction::Callers => "Callers of",
        Direction::Callees => "Callees of",
    };
    let mut text = format!(
        "{title} {}\n{}",
        name_and_place(ws, root),
        tree.lines.join("\n")
    );
    if tree.is_cut {
        text.push_str(&format!(
            "\n… cut at {MAX_TREE_LINES} lines; ask for less depth or start lower in the tree"
        ));
    }
    Ok(text)
}

struct Tree<'w> {
    ws: &'w Workspace,
    direction: Direction,
    lines: Vec<String>,
    /// Functions already listed, which aren't followed again.
    seen: HashSet<SymbolId>,
    is_cut: bool,
}

impl Tree<'_> {
    fn walk(&mut self, id: SymbolId, level: usize, depth: u32) {
        let indent = "  ".repeat(level);
        if self.direction == Direction::Callees {
            let library = self.ws.library_calls_of(id);
            if !library.is_empty() {
                let names: Vec<String> = library.iter().map(|n| shown(n, MAX_CODE_CHARS)).collect();
                self.push(format!("{indent}library: {}", names.join(", ")));
            }
        }
        for next in self.next_of(id) {
            if self.is_cut {
                return;
            }
            let is_new = self.seen.insert(next);
            let suffix = if is_new { "" } else { "  (listed above)" };
            self.push(format!("{indent}{}{suffix}", name_and_place(self.ws, next)));
            if is_new && level < depth as usize {
                self.walk(next, level + 1, depth);
            }
        }
    }

    /// Callers or callees of `id`, by name.
    fn next_of(&self, id: SymbolId) -> Vec<SymbolId> {
        let mut next = match self.direction {
            Direction::Callers => self.ws.callers_of(id).to_vec(),
            Direction::Callees => self.ws.callees_of(id).to_vec(),
        };
        next.sort_by_cached_key(|id| symbol_name(self.ws, *id));
        next
    }

    fn push(&mut self, line: String) {
        if self.lines.len() >= MAX_TREE_LINES {
            self.is_cut = true;
            return;
        }
        self.lines.push(line);
    }
}

/// Every reference to a symbol or call to a library function: where, what
/// kind, in which function, and the code.
pub fn xrefs(ws: &Workspace, args: &XrefsArgs) -> Result<String, String> {
    let target = resolve::referenced(ws, &args.name, args.file.as_deref())?;
    let limit = limit(args.limit, DEFAULT_XREFS, MAX_XREFS);
    let (found, _) = all_xrefs(ws.graph(), &target);
    let found: Vec<_> = found
        .into_iter()
        .filter(|x| is_under(&x.file, args.path.as_deref()))
        .collect();
    let name = shown(&name_of(ws.graph(), &target), MAX_CODE_CHARS);
    let within = args
        .path
        .as_deref()
        .map(|p| format!(" in {}", shown(p, MAX_CODE_CHARS)))
        .unwrap_or_default();
    if found.is_empty() {
        return Ok(format!("No references to {name}{within}."));
    }
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    for xref in &found {
        *kinds.entry(xref.kind).or_default() += 1;
    }
    let summary: Vec<String> = kinds.iter().map(|(k, n)| count(*n, k)).collect();
    let mut lines = vec![format!(
        "{} to {name}{within}: {}",
        count(found.len(), "reference"),
        summary.join(", ")
    )];
    lines.extend(found.iter().take(limit).map(|x| {
        let function = x
            .function
            .map(|id| format!("  in {}", symbol_name(ws, id)))
            .unwrap_or_default();
        format!(
            "{}  {}{function}  │ {}",
            place(&x.file, x.span.line),
            x.kind,
            code_at(ws, &x.file, x.span.line)
        )
    }));
    lines.extend(more(limit, found.len(), "narrow with path, or raise limit"));
    if matches!(target, Referenced::Symbol(_))
        && kinds.len() == 1
        && kinds.contains_key("declaration")
    {
        lines.push("Only declared here: nothing in the project uses it.".into());
    }
    Ok(lines.join("\n"))
}

/// The library functions the project calls, most called first, or those
/// matching `query`.
pub fn library_calls(ws: &Workspace, args: &LibraryArgs) -> Result<String, String> {
    let functions = ws.project.library_functions();
    if functions.is_empty() {
        return Ok("The project calls no library functions.".into());
    }
    let limit = limit(args.limit, DEFAULT_LIBRARY, MAX_LIBRARY);
    let query = args.query.as_deref().map(str::trim).unwrap_or_default();
    let indices: Vec<usize> = if query.is_empty() {
        (0..functions.len().min(limit)).collect()
    } else {
        let candidates = Candidates {
            symbols: &[],
            notes: &[],
            library: ws.project.library_candidates(),
        };
        search(&candidates, &format!("{LIBRARY_PREFIX}{query}"), limit)
            .into_iter()
            .filter_map(|e| match e {
                Entry::LibraryFunction(i) => Some(i),
                _ => None,
            })
            .collect()
    };
    if indices.is_empty() {
        return Ok(format!(
            "No library function the project calls matches `{}`.",
            shown(query, MAX_CODE_CHARS)
        ));
    }
    let mut lines: Vec<String> = indices
        .iter()
        .filter_map(|i| functions.get(*i))
        .map(|f| {
            format!(
                "{}  {}",
                shown(&f.name, MAX_CODE_CHARS),
                count(f.calls, "call")
            )
        })
        .collect();
    if query.is_empty() {
        lines.extend(more(limit, functions.len(), "pass query to search them"));
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
#[path = "graph_tests.rs"]
mod tests;
