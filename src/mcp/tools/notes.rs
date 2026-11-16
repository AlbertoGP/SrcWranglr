//! The project's notes: listing them, and adding the agent's. An agent's
//! note is marked as such and goes below any note already on that symbol
//! or line, so it never replaces or removes yours. Notes are read from
//! and written to disk on each call, so the app's and the agent's don't
//! overwrite each other.

use std::path::Path;

use crate::analysis::injection::cues::cue_in;
use crate::mcp::args::{AddNoteArgs, NotesArgs};
use crate::mcp::format::{count, is_under, place, shown, MAX_CODE_CHARS, MAX_TEXT_CHARS};
use crate::mcp::guard::WARNING;
use crate::mcp::resolve;
use crate::mcp::workspace::Workspace;
use crate::notes::store::{self, MAX_NOTES};
use crate::notes::{Note, NoteTarget, Notes};

/// What starts each note the agent writes.
pub const AGENT_MARK: &str = "[agent] ";
const NO_FOLDER: &str = "This project has no folder to keep notes in.";

/// The notes, symbol notes and line notes alike.
pub fn notes(ws: &Workspace, args: &NotesArgs) -> Result<String, String> {
    let root = ws.root.as_deref().ok_or(NO_FOLDER)?;
    let notes = load(root)?;
    let path = args.path.as_deref();
    let listed: Vec<String> = notes
        .iter()
        .filter(|note| is_in(ws, note, path))
        .map(note_line)
        .collect();
    if listed.is_empty() {
        return Ok("No notes yet.".into());
    }
    // The notes file is in the project's folder, which may have come with
    // notes of its own.
    let whose = match ws.is_trusted {
        true => "",
        false => " (kept in the project's folder, which the user hasn't trusted, so some may not be the user's)",
    };
    Ok(format!(
        "{}{whose}:\n{}",
        count(listed.len(), "note"),
        listed.join("\n")
    ))
}

fn is_in(ws: &Workspace, note: &Note, path: Option<&str>) -> bool {
    match &note.target {
        NoteTarget::Line { file, .. } => is_under(file, path),
        NoteTarget::Symbol(name) => {
            path.is_none()
                || ws.project.ids_named(name).iter().any(|id| {
                    ws.graph()
                        .symbols
                        .get(id)
                        .is_some_and(|s| is_under(&s.file, path))
                })
        }
    }
}

/// `target  ★ text`, the text's lines joined, with a warning if it reads
/// like instructions to an AI.
fn note_line(note: &Note) -> String {
    let star = if note.is_starred { "★ " } else { "" };
    let text: Vec<&str> = note.text.lines().filter(|l| !l.trim().is_empty()).collect();
    let warning = match cue_in(&note.text) {
        Some(_) => format!("   {WARNING}"),
        None => String::new(),
    };
    format!(
        "{}  {star}{}{warning}",
        target_label(&note.target),
        shown(&text.join(" ⏎ "), MAX_TEXT_CHARS)
    )
}

fn target_label(target: &NoteTarget) -> String {
    match target {
        NoteTarget::Symbol(name) => shown(name, MAX_CODE_CHARS),
        NoteTarget::Line { file, line } => place(file, *line),
    }
}

/// A note the agent asked to add, checked: where it goes and its text,
/// marked as the agent's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteChange {
    pub target: NoteTarget,
    /// For a line: its text, to find it again after the file changes.
    pub anchor: Option<String>,
    pub added: String,
}

impl NoteChange {
    /// The note's text and star with this added below `existing`.
    pub fn applied_to(&self, existing: Option<&Note>) -> Result<(String, bool), String> {
        let (text, is_starred) = match existing {
            Some(note) if !note.text.trim().is_empty() => (
                format!("{}\n\n{}", note.text.trim_end(), self.added),
                note.is_starred,
            ),
            Some(note) => (self.added.clone(), note.is_starred),
            None => (self.added.clone(), false),
        };
        store::check_text(&text, "The note")?;
        Ok((text, is_starred))
    }

    /// What the agent is told once it's saved.
    pub fn saved(&self) -> String {
        format!(
            "Noted on {}. The user sees it in SrcWranglr's Notes pane.",
            target_label(&self.target)
        )
    }
}

/// The note `args` asks for, checked against the index.
pub fn note_change(ws: &Workspace, args: &AddNoteArgs) -> Result<NoteChange, String> {
    let text = args.text.trim();
    if text.is_empty() {
        return Err("The note is empty.".into());
    }
    let (target, anchor) = target_of(ws, &args.target)?;
    store::check_target(&target)?;
    Ok(NoteChange {
        target,
        anchor,
        added: format!("{AGENT_MARK}{text}"),
    })
}

/// Adds the agent's note on a symbol or `file:line` to the notes file,
/// below any note there. `now` is in Unix seconds.
pub fn add_note(ws: &Workspace, args: &AddNoteArgs, now: u64) -> Result<String, String> {
    let root = ws.root.as_deref().ok_or(NO_FOLDER)?;
    let change = note_change(ws, args)?;
    let mut notes = load(root)?;
    let existing = notes.get(&change.target);
    if existing.is_none() && notes.len() >= MAX_NOTES {
        return Err(format!("The project already has {MAX_NOTES} notes."));
    }
    let (text, is_starred) = change.applied_to(existing)?;
    notes.set(
        change.target.clone(),
        &text,
        is_starred,
        change.anchor.clone(),
        now,
    );
    store::save(root, &notes).map_err(|e| format!("The note couldn't be saved: {e}"))?;
    Ok(change.saved())
}

/// A `file:line` of an indexed file (with that line's text, to find it
/// again), else a symbol by name.
pub fn target_of(ws: &Workspace, target: &str) -> Result<(NoteTarget, Option<String>), String> {
    let target = target.trim();
    let line_target = target
        .rsplit_once(':')
        .and_then(|(file, line)| Some((file, line.trim().parse::<u32>().ok()?)));
    let Some((file, line)) = line_target else {
        let id = resolve::symbol(ws, target, None)?;
        let name = ws
            .graph()
            .symbols
            .get(&id)
            .map(|s| s.qualified_name.clone())
            .ok_or("That symbol is gone.")?;
        return Ok((NoteTarget::Symbol(name), None));
    };
    let file = resolve::file(ws, file)?;
    let anchor = ws.line(&file, line).ok_or_else(|| {
        let lines = ws
            .graph()
            .file_contents
            .get(&file)
            .map_or(0, |c| c.lines().count());
        format!(
            "{} has {}.",
            shown(&file, MAX_CODE_CHARS),
            count(lines, "line")
        )
    })?;
    let target = NoteTarget::Line { file, line };
    Ok((target, Some(anchor.trim().to_string())))
}

fn load(root: &Path) -> Result<Notes, String> {
    store::load(root).map_err(|e| format!("The notes couldn't be read: {e}"))
}

#[cfg(test)]
#[path = "notes_tests.rs"]
mod tests;
