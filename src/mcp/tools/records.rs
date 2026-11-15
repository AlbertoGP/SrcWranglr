//! What an agent may add besides notes, so a research run is recorded
//! where you work: journal entries (each phase's summary, say) and the
//! results of its own scanners, as a SARIF report imported into Findings.
//! Like notes, journal entries are marked as the agent's. With the app
//! open, both go through it (see `app::agent_bridge`).

use std::path::{Component, Path, PathBuf};

use crate::mcp::args::JournalArgs;
use crate::mcp::format::{count, shown, MAX_CODE_CHARS};
use crate::mcp::tools::notes::{target_of, AGENT_MARK};
use crate::mcp::workspace::Workspace;
use crate::notes::journal::{self, Entry, Place};
use crate::notes::NoteTarget;

const NO_FOLDER: &str = "This project has no folder to keep a journal in.";

/// The journal entry `args` asks for, checked against the index.
pub fn journal_change(ws: &Workspace, args: &JournalArgs, now: u64) -> Result<Entry, String> {
    let text = args.text.trim();
    if text.is_empty() {
        return Err("The entry is empty.".into());
    }
    let place = match args.place.as_deref().map(str::trim) {
        Some(place) if !place.is_empty() => Some(place_of(ws, place)?),
        _ => None,
    };
    let entry = Entry::new(&format!("{AGENT_MARK}{text}"), place, now);
    journal::check_entry(&entry)?;
    Ok(entry)
}

/// The line `place` (`file:line`) names, in the function it's in.
fn place_of(ws: &Workspace, place: &str) -> Result<Place, String> {
    match target_of(ws, place)?.0 {
        NoteTarget::Line { file, line } => {
            let symbol = crate::index::functions_holding_lines(ws.graph(), &[(&file, line)])
                .into_iter()
                .flatten()
                .next()
                .and_then(|id| ws.graph().symbols.get(&id))
                .map(|s| s.qualified_name.clone());
            Ok(Place { file, line, symbol })
        }
        NoteTarget::Symbol(_) => Err(format!(
            "Give the place as file:line, not {}.",
            shown(place, MAX_CODE_CHARS)
        )),
    }
}

/// Adds the agent's entry to the journal file. `now` is in Unix seconds.
pub fn journal_entry(ws: &Workspace, args: &JournalArgs, now: u64) -> Result<String, String> {
    let root = ws.root.as_deref().ok_or(NO_FOLDER)?;
    let entry = journal_change(ws, args, now)?;
    let journal = journal::load(root).map_err(|e| format!("The journal couldn't be read: {e}"))?;
    let journal = journal.with_added(entry)?;
    journal::save(root, &journal)?;
    Ok(written(journal.entries().len()))
}

/// What the agent is told once its entry is in.
pub fn written(entries: usize) -> String {
    format!(
        "Written in the journal ({} in all). The user reads it in SrcWranglr's Notes pane, Journal tab.",
        count(entries, "entry")
    )
}

/// The report at `file`, if it's a file inside the project (through no
/// symlink out of it).
pub fn sarif_file(ws: &Workspace, file: &str) -> Result<PathBuf, String> {
    let root = ws.root.as_deref().ok_or("This project has no folder.")?;
    let relative = Path::new(file.trim());
    let is_relative = relative
        .components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
    if !is_relative || relative.as_os_str().is_empty() {
        return Err(format!(
            "{} isn't inside the project: give the report's project-relative path.",
            shown(file, MAX_CODE_CHARS)
        ));
    }
    let real = |p: &Path| std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()));
    let (root, path) = (real(root)?, real(&root.join(relative))?);
    if !path.starts_with(&root) {
        return Err(format!(
            "{} leads outside the project.",
            shown(file, MAX_CODE_CHARS)
        ));
    }
    if !path.is_file() {
        return Err(format!("{} isn't a file.", shown(file, MAX_CODE_CHARS)));
    }
    Ok(path)
}

#[cfg(test)]
#[path = "records_tests.rs"]
mod tests;
