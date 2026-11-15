//! What the names an agent passes refer to: a symbol by qualified name
//! (`Foo::bar`) or short name (`bar`), narrowed to a file when several
//! share it, or a library function the project calls.

use crate::analysis::risky::bare_library_name;
use crate::code_view::Referenced;
use crate::model::SymbolId;

use super::format::{count, name_and_place};
use super::workspace::Workspace;

/// Candidates listed when a name is ambiguous.
const MAX_CANDIDATES: usize = 20;

/// The one symbol `name` names (in `file`, if given).
pub fn symbol(ws: &Workspace, name: &str, file: Option<&str>) -> Result<SymbolId, String> {
    let name = cleaned(name);
    if name.is_empty() {
        return Err("Give a name, such as `parse_header` or `Foo::bar`.".into());
    }
    let mut found = named(ws, name);
    if let Some(file) = file.map(str::trim).filter(|f| !f.is_empty()) {
        found.retain(|id| is_in_file(ws, *id, file));
    }
    // A definition wins over declarations of the same name.
    let defined: Vec<SymbolId> = found
        .iter()
        .copied()
        .filter(|id| ws.is_defined(*id))
        .collect();
    let found = if defined.len() == 1 { defined } else { found };
    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err(not_found(name, file)),
        several => Err(ambiguous(ws, name, several)),
    }
}

/// Whether `id` is declared or defined in `file`.
fn is_in_file(ws: &Workspace, id: SymbolId, file: &str) -> bool {
    ws.graph().symbols.get(&id).is_some_and(|s| s.file == file)
        || ws.definitions(id).iter().any(|d| d.file == file)
}

/// The symbol `name` names, or the library function the project calls by
/// that name if none does, for cross references.
pub fn referenced(ws: &Workspace, name: &str, file: Option<&str>) -> Result<Referenced, String> {
    let cleaned = cleaned(name);
    let library = bare_library_name(cleaned).filter(|bare| {
        named(ws, cleaned).is_empty()
            && ws
                .project
                .library_functions()
                .iter()
                .any(|f| f.name == *bare)
    });
    match library {
        Some(bare) => Ok(Referenced::Library(bare.to_string())),
        None => symbol(ws, name, file).map(Referenced::Symbol),
    }
}

/// `name` without surrounding space or a trailing `()`.
fn cleaned(name: &str) -> &str {
    name.trim().trim_end_matches("()").trim()
}

/// Symbols with exactly this qualified name, else this short name.
fn named(ws: &Workspace, name: &str) -> Vec<SymbolId> {
    let exact = ws.project.ids_named(name);
    if !exact.is_empty() {
        return exact.to_vec();
    }
    ws.project
        .symbols_by_name()
        .filter(|s| s.name == name)
        .map(|s| s.id)
        .collect()
}

fn not_found(name: &str, file: Option<&str>) -> String {
    let shown = crate::app::visible::visible(name);
    match file {
        Some(file) => format!(
            "No symbol `{shown}` in {}. Try find_symbol, or leave out file.",
            crate::app::visible::visible(file)
        ),
        None => format!(
            "No symbol `{shown}`. Try find_symbol for a partial name, or library_calls for a function the project calls but doesn't define."
        ),
    }
}

fn ambiguous(ws: &Workspace, name: &str, ids: &[SymbolId]) -> String {
    let mut lines = vec![format!(
        "`{}` names {}; pass file to pick one:",
        crate::app::visible::visible(name),
        count(ids.len(), "symbol")
    )];
    lines.extend(
        ids.iter()
            .take(MAX_CANDIDATES)
            .map(|id| format!("  {}", name_and_place(ws, *id))),
    );
    if ids.len() > MAX_CANDIDATES {
        lines.push(format!("  … {} more", ids.len() - MAX_CANDIDATES));
    }
    lines.join("\n")
}
