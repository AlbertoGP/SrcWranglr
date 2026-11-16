//! What the names an agent passes refer to: a symbol by qualified name
//! (`Foo::bar`) or short name (`bar`), narrowed to a file when several
//! share it, or a library function the project calls.

use crate::analysis::risky::bare_library_name;
use crate::code_view::Referenced;
use crate::model::SymbolId;

use super::format::{count, name_and_place, shown, MAX_CODE_CHARS};
use super::workspace::Workspace;

/// Candidates listed when a name is ambiguous.
const MAX_CANDIDATES: usize = 20;

/// The indexed file `given` names: its exact project-relative path, or —
/// when that is not indexed — the one indexed file whose path ends in that
/// name, so a bare `parse.c` resolves to `net/parse.c` when it is the only
/// file with that name. An unknown or ambiguous name is an error. Agents
/// often pass a basename, which other tools print with its folder.
pub fn file(ws: &Workspace, given: &str) -> Result<String, String> {
    let files = &ws.graph().file_contents;
    let given = given.trim().trim_start_matches("./");
    if files.contains_key(given) {
        return Ok(given.to_string());
    }
    let suffix = format!("/{given}");
    let mut matches: Vec<&str> = files
        .keys()
        .map(String::as_str)
        .filter(|k| k.ends_with(suffix.as_str()))
        .collect();
    matches.sort_unstable();
    match matches.as_slice() {
        [one] => Ok((*one).to_string()),
        [] => Err(not_indexed(given)),
        several => Err(format!(
            "{} matches {} indexed files ({}); give the project-relative path.",
            shown(given, MAX_CODE_CHARS),
            several.len(),
            several
                .iter()
                .take(MAX_CANDIDATES)
                .copied()
                .collect::<Vec<_>>()
                .join(", "),
        )),
    }
}

/// The message shown when `file` is not an indexed path.
pub fn not_indexed(file: &str) -> String {
    format!(
        "{} is not an indexed file. Files are project-relative, as other tools list them (net/parse.c).",
        shown(file, MAX_CODE_CHARS)
    )
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::graph_of_files;
    use crate::mcp::fixture::workspace;

    #[test]
    fn an_exact_project_relative_path_resolves() {
        let ws = workspace();
        assert_eq!(file(&ws, "net/parse.c").unwrap(), "net/parse.c");
        assert_eq!(file(&ws, "./net/parse.c").unwrap(), "net/parse.c");
    }

    #[test]
    fn a_bare_basename_resolves_to_the_unique_indexed_file() {
        let ws = workspace();
        // The agent writes `parse.c`; it is indexed under `net/parse.c`.
        assert_eq!(file(&ws, "parse.c").unwrap(), "net/parse.c");
        assert_eq!(file(&ws, "a.c").unwrap(), "drivers/a.c");
    }

    #[test]
    fn an_unknown_file_is_refused() {
        let ws = workspace();
        assert!(file(&ws, "nope.c")
            .unwrap_err()
            .contains("not an indexed file"));
    }

    #[test]
    fn an_ambiguous_basename_lists_the_matches() {
        let graph = graph_of_files(&[("a/dup.c", "int a;\n"), ("b/dup.c", "int b;\n")]);
        let ws = crate::mcp::workspace::Workspace::new("t", None, graph);
        let err = file(&ws, "dup.c").unwrap_err();
        assert!(
            err.contains("matches") && err.contains("indexed files"),
            "{err}"
        );
        assert!(err.contains("a/dup.c") && err.contains("b/dup.c"), "{err}");
    }
}
