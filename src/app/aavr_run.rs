//! An AAVR run as it stands, read from the project's `.aavr/` folder (the
//! files AAVR's skills keep there): which phases are done, next or
//! blocked, the candidates by classification, the attack surfaces, the
//! harness picked, the crashes and the report. The folder is in the
//! audited tree and written by an agent, so it is read like any file from
//! the tree: nothing followed through a symlink, sizes and counts capped.
//! Its strings are shown with hidden characters marked, by the pane.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::safe_fs::{is_real_dir, read_regular_file};

pub const AAVR_DIR: &str = ".aavr";
/// AAVR's phases in order: the name its state uses, and a short label.
pub const PHASES: [(&str, &str); 13] = [
    ("repository-recon", "Recon"),
    ("build-baseline", "Build"),
    ("attack-surface", "Attack surface"),
    ("static-analysis", "Static analysis"),
    ("semgrep-database", "Semgrep corpus"),
    ("finding-triage", "Triage"),
    ("sanitizer-validation", "Sanitizers"),
    ("fuzz-target-selection", "Fuzz targets"),
    ("harness-generation", "Harness"),
    ("fuzz-campaign", "Campaign"),
    ("crash-triage", "Crashes"),
    ("variant-analysis", "Variants"),
    ("report", "Report"),
];
/// A JSON file read at most this big.
const MAX_FILE_BYTES: usize = 128 * 1024;
/// The candidates file is only counted, over at most this much.
const MAX_CANDIDATES_BYTES: usize = 2 * 1024 * 1024;
/// All of `.aavr/`'s JSON files are read within this budget each refresh,
/// so a tree stuffed with them can't bog the app down.
const READ_BUDGET: usize = 6 * 1024 * 1024;
/// Findings, surfaces and crashes kept at most.
const MAX_ITEMS: usize = 200;
/// A string kept at most this many characters.
const MAX_TEXT_CHARS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseStatus {
    Done,
    Next,
    Blocked,
    Pending,
}

/// What AAVR's triage made of a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Classification {
    Confirmed,
    Likely,
    Speculative,
    Rejected,
    Blocked,
    Unclassified,
}

impl Classification {
    pub const ALL: [Classification; 6] = [
        Classification::Confirmed,
        Classification::Likely,
        Classification::Speculative,
        Classification::Rejected,
        Classification::Blocked,
        Classification::Unclassified,
    ];

    fn of(text: &str) -> Self {
        match text.trim().to_ascii_lowercase().as_str() {
            "confirmed" => Self::Confirmed,
            "likely" => Self::Likely,
            "speculative" => Self::Speculative,
            "rejected" => Self::Rejected,
            "blocked" => Self::Blocked,
            _ => Self::Unclassified,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Confirmed => "Confirmed",
            Self::Likely => "Likely",
            Self::Speculative => "Speculative",
            Self::Rejected => "Rejected",
            Self::Blocked => "Blocked",
            Self::Unclassified => "Not classified",
        }
    }
}

/// A place in the project a file points at.
pub type Spot = (String, u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    pub title: String,
    pub classification: Classification,
    pub severity: String,
    pub confidence: String,
    pub place: Option<Spot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Surface {
    pub id: String,
    pub origin: String,
    /// A function, usually.
    pub entry_point: String,
    pub priority: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessPick {
    pub target: String,
    pub engine: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crash {
    pub id: String,
    pub classification: String,
    pub is_reproducible: Option<bool>,
    pub place: Option<Spot>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AavrRun {
    pub revision: String,
    /// Each phase's label and status, in order.
    pub phases: Vec<(&'static str, PhaseStatus)>,
    pub blocked_on: Vec<String>,
    /// Triaged findings, by classification then id.
    pub candidates: Vec<Candidate>,
    /// Raw scanner candidates waiting in `findings/candidates.jsonl`.
    pub raw_candidates: usize,
    pub surfaces: Vec<Surface>,
    pub harness: Option<HarnessPick>,
    pub crashes: Vec<Crash>,
    /// The report, project-relative, once written.
    pub report: Option<String>,
    /// Files that couldn't be read, and why.
    pub problems: Vec<String>,
}

/// The run in `root`'s `.aavr/` folder; `None` if there is none.
pub fn read(root: &Path) -> Option<AavrRun> {
    let dir = root.join(AAVR_DIR);
    match is_real_dir(&dir) {
        Ok(true) => {}
        Ok(false) => return None,
        Err(error) => {
            return Some(AavrRun {
                problems: vec![format!("{AAVR_DIR}: {error}")],
                ..AavrRun::default()
            })
        }
    }
    let mut problems = Vec::new();
    let mut budget = READ_BUDGET;
    let state = json_at(&dir.join("state.json"), &mut budget, &mut problems);
    let (revision, phases, blocked_on) = phases_of(state.as_ref());
    let mut candidates = findings(&dir.join("findings"), &mut budget, &mut problems);
    candidates.sort_by(|a, b| (a.classification, &a.id).cmp(&(b.classification, &b.id)));
    let raw_candidates = read_regular_file(
        &dir.join("findings").join("candidates.jsonl"),
        MAX_CANDIDATES_BYTES,
    )
    .ok()
    .flatten()
    .map_or(0, |text| {
        text.lines().filter(|l| !l.trim().is_empty()).count()
    });
    let surfaces = json_at(
        &dir.join("surfaces").join("map.json"),
        &mut budget,
        &mut problems,
    )
    .map(|map| surfaces_of(&map))
    .unwrap_or_default();
    let harness = json_at(
        &dir.join("harnesses").join("selection.json"),
        &mut budget,
        &mut problems,
    )
    .and_then(|pick| harness_of(&pick));
    let crashes = crashes(&dir.join("crashes"), &mut budget, &mut problems);
    // A symlinked reports/ folder isn't followed.
    let reports = dir.join("reports");
    let report = is_real_dir(&reports).unwrap_or(false)
        && std::fs::symlink_metadata(reports.join("aavr-report.md"))
            .is_ok_and(|m| m.file_type().is_file());
    let report = report.then(|| format!("{AAVR_DIR}/reports/aavr-report.md"));
    Some(AavrRun {
        revision,
        phases,
        blocked_on,
        candidates,
        raw_candidates,
        surfaces,
        harness,
        crashes,
        report,
        problems,
    })
}

/// The JSON in `path`, if there is a readable file within `budget`; why
/// not in `problems`.
fn json_at(path: &Path, budget: &mut usize, problems: &mut Vec<String>) -> Option<Value> {
    if *budget == 0 {
        return None;
    }
    let cap = MAX_FILE_BYTES.min(*budget);
    let text = match read_regular_file(path, cap) {
        Ok(text) => text?,
        Err(error) => {
            problems.push(format!("{}: {error}", short(path)));
            return None;
        }
    };
    *budget = budget.saturating_sub(text.len());
    match serde_json::from_str(&text) {
        Ok(value) => Some(value),
        Err(error) => {
            problems.push(format!("{}: not JSON ({error})", short(path)));
            None
        }
    }
}

/// `path` from `.aavr` on, for messages.
fn short(path: &Path) -> String {
    let text = path.to_string_lossy();
    match text.find(AAVR_DIR) {
        Some(at) => text[at..].to_string(),
        None => text.into_owned(),
    }
}

type Phases = (String, Vec<(&'static str, PhaseStatus)>, Vec<String>);

/// The revision assessed, each phase's status, and what blocks the run.
fn phases_of(state: Option<&Value>) -> Phases {
    let names = |key: &str| -> Vec<String> {
        state
            .and_then(|s| s.get(key))
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .map(normalized)
                    .collect()
            })
            .unwrap_or_default()
    };
    let done = names("completed_phases");
    let blocked_on: Vec<String> = state
        .and_then(|s| s.get("blocked_on"))
        .and_then(Value::as_array)
        .map(|list| list.iter().take(MAX_ITEMS).filter_map(text_of).collect())
        .unwrap_or_default();
    let next = state
        .and_then(|s| s.get("next_phase"))
        .and_then(Value::as_str)
        .map(normalized);
    let phases = PHASES
        .iter()
        .map(|(name, label)| {
            let status = match (
                done.iter().any(|d| d == name),
                next.as_deref() == Some(*name),
            ) {
                (true, _) => PhaseStatus::Done,
                (false, true) if !blocked_on.is_empty() => PhaseStatus::Blocked,
                (false, true) => PhaseStatus::Next,
                (false, false) => PhaseStatus::Pending,
            };
            (*label, status)
        })
        .collect();
    let revision = state
        .and_then(|s| s.get("target_revision"))
        .and_then(text_of)
        .unwrap_or_default();
    (revision, phases, blocked_on)
}

/// `aavr-repository-recon` or `Repository_Recon` as `repository-recon`.
fn normalized(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase().replace('_', "-");
    lower.strip_prefix("aavr-").unwrap_or(&lower).to_string()
}

/// The triaged findings in `findings/<id>.json`.
fn findings(dir: &Path, budget: &mut usize, problems: &mut Vec<String>) -> Vec<Candidate> {
    json_files(dir, budget, problems)
        .into_iter()
        .filter_map(|(name, value)| {
            let id = field(&value, "id").unwrap_or(name);
            Some(Candidate {
                title: field(&value, "title").unwrap_or_default(),
                classification: Classification::of(&field(&value, "classification")?),
                severity: field(&value, "severity").unwrap_or_default(),
                confidence: field(&value, "confidence").unwrap_or_default(),
                place: ["sink", "source", "path", "evidence"]
                    .iter()
                    .find_map(|key| value.get(*key).and_then(spot_in)),
                id,
            })
        })
        .collect()
}

fn surfaces_of(map: &Value) -> Vec<Surface> {
    let list = map
        .as_array()
        .or_else(|| map.get("surfaces").and_then(Value::as_array));
    list.into_iter()
        .flatten()
        .take(MAX_ITEMS)
        .map(|s| Surface {
            id: field(s, "id").unwrap_or_default(),
            origin: field(s, "origin").unwrap_or_default(),
            entry_point: field(s, "entry_point").unwrap_or_default(),
            priority: field(s, "priority").unwrap_or_default(),
        })
        .collect()
}

fn harness_of(pick: &Value) -> Option<HarnessPick> {
    let target = field(pick, "selected_target")
        .or_else(|| field(pick, "symbol_or_entry"))
        .filter(|t| !t.is_empty())?;
    Some(HarnessPick {
        target,
        engine: field(pick, "engine").unwrap_or_default(),
    })
}

/// Each `crashes/<id>/analysis.json`.
fn crashes(dir: &Path, budget: &mut usize, problems: &mut Vec<String>) -> Vec<Crash> {
    let mut found: Vec<Crash> = sub_dirs(dir)
        .into_iter()
        .filter_map(|(name, path)| {
            let analysis = json_at(&path.join("analysis.json"), budget, problems)?;
            Some(Crash {
                id: name,
                classification: field(&analysis, "classification")
                    .or_else(|| field(&analysis, "category"))
                    .unwrap_or_default(),
                is_reproducible: analysis.get("reproducible").and_then(Value::as_bool),
                place: analysis.get("root_cause_location").and_then(spot_in),
            })
        })
        .collect();
    found.sort_by(|a, b| a.id.cmp(&b.id));
    found
}

/// The `.json` files directly in `dir`, by name, parsed; at most
/// `MAX_ITEMS`.
fn json_files(dir: &Path, budget: &mut usize, problems: &mut Vec<String>) -> Vec<(String, Value)> {
    let mut names: Vec<String> = entries(dir)
        .into_iter()
        .filter(|name| name.ends_with(".json"))
        .collect();
    names.sort();
    names.truncate(MAX_ITEMS);
    names
        .into_iter()
        .filter_map(|name| {
            let value = json_at(&dir.join(&name), budget, problems)?;
            let id = name.trim_end_matches(".json").to_string();
            Some((cut(&id), value))
        })
        .collect()
}

/// The real folders directly in `dir`, by name; at most `MAX_ITEMS`.
fn sub_dirs(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut names: Vec<String> = entries(dir)
        .into_iter()
        .filter(|name| is_real_dir(&dir.join(name)).unwrap_or(false))
        .collect();
    names.sort();
    names.truncate(MAX_ITEMS);
    names
        .into_iter()
        .map(|name| (cut(&name), dir.join(&name)))
        .collect()
}

/// The names in `dir`, if it's a real folder; a capped number.
fn entries(dir: &Path) -> Vec<String> {
    if !is_real_dir(dir).unwrap_or(false) {
        return Vec::new();
    }
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .take(MAX_ITEMS * 4)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect()
}

/// `value[key]` as text, cut short.
fn field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(text_of)
}

fn text_of(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(cut(s)),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn cut(text: &str) -> String {
    match text.char_indices().nth(MAX_TEXT_CHARS) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_string(),
    }
}

/// A `file` and `line` in `value`: its own fields, its first item's, or a
/// `file:line` written in it.
fn spot_in(value: &Value) -> Option<Spot> {
    match value {
        Value::Object(fields) => {
            let file = fields
                .get("file")
                .or_else(|| fields.get("path"))
                .and_then(Value::as_str)?;
            let line = fields.get("line").and_then(Value::as_u64)?;
            Some((cut(file), u32::try_from(line).ok()?))
        }
        Value::Array(items) => items.iter().take(MAX_ITEMS).find_map(spot_in),
        Value::String(text) => spot_written(text),
        _ => None,
    }
}

/// `net/parse.c:14` (or `net/parse.c:14:3`) in `text`.
fn spot_written(text: &str) -> Option<Spot> {
    text.split_whitespace().find_map(|word| {
        let word = word.trim_matches(|c: char| "()[]{},;'\"`".contains(c));
        let mut parts = word.split(':');
        let file = parts.next()?;
        let line: u32 = parts.next()?.parse().ok()?;
        let is_source = [".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"]
            .iter()
            .any(|ext| file.ends_with(ext));
        (is_source && line > 0).then(|| (cut(file), line))
    })
}

#[cfg(test)]
#[path = "aavr_run_tests.rs"]
mod tests;
