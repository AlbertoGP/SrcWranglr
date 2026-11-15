//! What the agent's tools read: the indexed project, its findings (with
//! your verdicts, if you trust the project's own), what to hide or flag as
//! a possible prompt injection, and the call graph arranged for walking
//! both ways, built once when the index is done. Your verdicts are read
//! again whenever their file changes, so one you give in the app applies
//! to the agent's next call.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::SystemTime;

use crate::analysis::fuzz::{fuzz_targets, FuzzTarget};
use crate::analysis::reach::Reach;
use crate::analysis::risky::bare_library_name;
use crate::app::dangerous_lists::DangerousLists;
use crate::app::findings::Findings;
use crate::app::project::Project;
use crate::app::trust;
use crate::model::{CodeGraph, EdgeKind, FunctionMetrics, SymbolId};
use crate::notes::store::NOTES_DIR;
use crate::notes::triage::{self, Triage, TriageStatus, TRIAGE_FILE};

use super::guard::Guard;

pub struct Workspace {
    pub project: Project,
    /// The folder indexed; `None` only in tests.
    pub root: Option<PathBuf>,
    /// The findings without verdicts, for attaching them anew.
    unjudged: Findings,
    verdicts: RwLock<Verdicts>,
    /// Lists that couldn't be read, for the overview.
    pub problems: Vec<String>,
    /// Whether you trust the project's own verdicts and lists.
    pub is_trusted: bool,
    /// Indices into `graph.functions`, per defined function: several when
    /// files each define a `static` function of one name.
    definitions: HashMap<SymbolId, Vec<usize>>,
    /// Who calls each function, and what each calls, deduplicated.
    callers: HashMap<SymbolId, Vec<SymbolId>>,
    callees: HashMap<SymbolId, Vec<SymbolId>>,
    /// The library functions each function calls, by bare name, sorted.
    library_by_caller: HashMap<SymbolId, Vec<String>>,
    /// Where each line starts, for files read lately.
    line_starts: Mutex<HashMap<String, Arc<Vec<usize>>>>,
    /// Where outside input reaches, and the functions worth fuzzing: worked
    /// out when first asked (each walks the whole project).
    reach: OnceLock<Reach>,
    fuzz_targets: OnceLock<Vec<FuzzTarget>>,
}

/// Files whose line starts are kept; more and they're all let go.
const MAX_LINE_INDEXES: usize = 512;

/// The findings with your verdicts, and what they make of possible
/// prompt injections, as of when the verdicts file was last read.
struct Verdicts {
    /// The verdicts file's modification time and size when read; `None`
    /// if there was none.
    stamp: Option<(SystemTime, u64)>,
    findings: Arc<Findings>,
    guard: Arc<Guard>,
    /// Why the verdicts couldn't be read, if they couldn't.
    problem: Option<String>,
}

impl Workspace {
    pub fn new(name: &str, root: Option<PathBuf>, graph: CodeGraph) -> Self {
        Self::from_shared(name, root, Arc::new(graph))
    }

    /// The workspace of a graph shared with others (the app's).
    pub fn from_shared(name: &str, root: Option<PathBuf>, graph: Arc<CodeGraph>) -> Self {
        let is_trusted = root.as_deref().is_some_and(trust::is_trusted);
        let lists = DangerousLists::load(root.as_deref(), is_trusted);
        let problems: Vec<String> = lists.problems().to_vec();
        let unjudged = Findings::for_graph(&graph, lists.merged());
        let verdicts = judged(&unjudged, &graph, root.as_deref(), is_trusted);
        let mut definitions: HashMap<SymbolId, Vec<usize>> = HashMap::new();
        for (i, function) in graph.functions.iter().enumerate() {
            definitions.entry(function.symbol).or_default().push(i);
        }
        let (callers, callees) = call_maps(&graph);
        let library_by_caller = library_by_caller(&graph);
        Self {
            project: Project::from_shared(name, root.clone(), graph),
            root,
            unjudged,
            verdicts: RwLock::new(verdicts),
            problems,
            is_trusted,
            definitions,
            callers,
            callees,
            library_by_caller,
            line_starts: Mutex::new(HashMap::new()),
            reach: OnceLock::new(),
            fuzz_targets: OnceLock::new(),
        }
    }

    /// This workspace, saying how many files indexing had to skip.
    pub fn with_index_warnings(self, warnings: &[String]) -> Self {
        if warnings.is_empty() {
            return self;
        }
        let mut problems = self.problems.clone();
        problems.push(format!(
            "{} while indexing (files skipped or not parsed); the first: {}",
            crate::mcp::format::count(warnings.len(), "warning"),
            warnings[0]
        ));
        Self { problems, ..self }
    }

    /// The findings, with your verdicts as last read.
    pub fn findings(&self) -> Arc<Findings> {
        Arc::clone(&self.read_verdicts().findings)
    }

    /// How possible prompt injections are shown, by your verdicts.
    pub fn guard(&self) -> Arc<Guard> {
        Arc::clone(&self.read_verdicts().guard)
    }

    /// Why your verdicts couldn't be read, if they couldn't.
    pub fn verdicts_problem(&self) -> Option<String> {
        self.read_verdicts().problem.clone()
    }

    /// Your verdict on finding `index` of `findings`, if you trust the
    /// project's.
    pub fn verdict(&self, findings: &Findings, index: usize) -> Option<TriageStatus> {
        self.is_trusted.then(|| findings.verdict(index)).flatten()
    }

    /// Reads your verdicts again if their file changed since last time.
    pub fn refresh_verdicts(&self) {
        let Some(root) = self.root.as_deref() else {
            return;
        };
        if self.read_verdicts().stamp == stamp_of(root) {
            return;
        }
        let fresh = judged(&self.unjudged, self.graph(), Some(root), self.is_trusted);
        *self
            .verdicts
            .write()
            .unwrap_or_else(PoisonError::into_inner) = fresh;
    }

    fn read_verdicts(&self) -> std::sync::RwLockReadGuard<'_, Verdicts> {
        self.verdicts.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn graph(&self) -> &CodeGraph {
        &self.project.graph
    }

    /// Each definition's place, size and signature, for a defined
    /// function, in file order.
    pub fn definitions(&self, id: SymbolId) -> Vec<&FunctionMetrics> {
        let mut found: Vec<&FunctionMetrics> = self
            .definitions
            .get(&id)
            .into_iter()
            .flatten()
            .filter_map(|i| self.graph().functions.get(*i))
            .collect();
        found.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
        found
    }

    pub fn is_defined(&self, id: SymbolId) -> bool {
        self.definitions.contains_key(&id)
    }

    pub fn callers_of(&self, id: SymbolId) -> &[SymbolId] {
        self.callers.get(&id).map_or(&[], Vec::as_slice)
    }

    pub fn callees_of(&self, id: SymbolId) -> &[SymbolId] {
        self.callees.get(&id).map_or(&[], Vec::as_slice)
    }

    pub fn library_calls_of(&self, id: SymbolId) -> &[String] {
        self.library_by_caller.get(&id).map_or(&[], Vec::as_slice)
    }

    /// The functions outside input reaches, and how.
    pub fn reach(&self) -> &Reach {
        self.reach.get_or_init(|| Reach::of(self.graph()))
    }

    /// The functions worth fuzzing, best first.
    pub fn fuzz_targets(&self) -> &[FuzzTarget] {
        self.fuzz_targets
            .get_or_init(|| fuzz_targets(self.graph(), self.unjudged.all()))
    }

    /// Line `line` (1-based) of `file`, if indexed, as `str::lines` has it.
    pub fn line(&self, file: &str, line: u32) -> Option<&str> {
        let text = self.graph().file_contents.get(file)?;
        let starts = self.line_starts_of(file, text);
        let index = usize::try_from(line.checked_sub(1)?).ok()?;
        let start = *starts.get(index)?;
        let end = starts.get(index + 1).map_or(text.len(), |next| next - 1);
        let found = text.get(start..end)?;
        let found = found.strip_suffix('\n').unwrap_or(found);
        Some(found.strip_suffix('\r').unwrap_or(found))
    }

    fn line_starts_of(&self, file: &str, text: &str) -> Arc<Vec<usize>> {
        let mut cache = self
            .line_starts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(starts) = cache.get(file) {
            return Arc::clone(starts);
        }
        if cache.len() >= MAX_LINE_INDEXES {
            cache.clear();
        }
        let starts = Arc::new(line_starts(text));
        cache.insert(file.to_string(), Arc::clone(&starts));
        starts
    }
}

/// `unjudged` with the verdicts in `root` attached. They're read even
/// when untrusted: a confirmed prompt injection is withheld either way,
/// while other verdicts are shown only when trusted.
fn judged(
    unjudged: &Findings,
    graph: &CodeGraph,
    root: Option<&Path>,
    is_trusted: bool,
) -> Verdicts {
    let stamp = root.and_then(stamp_of);
    let (triage, problem) = match root.map(triage::load) {
        Some(Ok(triage)) => (triage, None),
        Some(Err(error)) => (
            Triage::default(),
            Some(format!("Your verdicts couldn't be read: {error}")),
        ),
        None => (Triage::default(), None),
    };
    let findings = unjudged.clone().with_triage(&triage, graph, is_trusted);
    let guard = Guard::new(graph, &findings, is_trusted);
    Verdicts {
        stamp,
        findings: Arc::new(findings),
        guard: Arc::new(guard),
        problem,
    }
}

/// Where each of `text`'s lines starts, as `str::lines` splits them.
fn line_starts(text: &str) -> Vec<usize> {
    if text.is_empty() {
        return Vec::new();
    }
    let after_breaks = text
        .match_indices('\n')
        .map(|(at, _)| at + 1)
        .filter(|start| *start < text.len());
    std::iter::once(0).chain(after_breaks).collect()
}

/// When the verdicts file was last changed, and its size.
fn stamp_of(root: &Path) -> Option<(SystemTime, u64)> {
    let metadata = fs::symlink_metadata(root.join(NOTES_DIR).join(TRIAGE_FILE)).ok()?;
    Some((metadata.modified().ok()?, metadata.len()))
}

/// Call edges, both ways, without repeats or self-calls.
type CallMap = HashMap<SymbolId, Vec<SymbolId>>;

fn call_maps(graph: &CodeGraph) -> (CallMap, CallMap) {
    let mut callers: CallMap = HashMap::new();
    let mut callees: CallMap = HashMap::new();
    for edge in graph
        .edges
        .iter()
        .filter(|e| e.kind == EdgeKind::Calls && e.from != e.to)
    {
        callers.entry(edge.to).or_default().push(edge.from);
        callees.entry(edge.from).or_default().push(edge.to);
    }
    for list in callers.values_mut().chain(callees.values_mut()) {
        list.sort_unstable();
        list.dedup();
    }
    (callers, callees)
}

fn library_by_caller(graph: &CodeGraph) -> HashMap<SymbolId, Vec<String>> {
    let mut by_caller: HashMap<SymbolId, Vec<String>> = HashMap::new();
    for call in graph.external_calls.values().flatten() {
        if let Some(name) = bare_library_name(&call.name) {
            by_caller
                .entry(call.caller)
                .or_default()
                .push(name.to_string());
        }
    }
    for names in by_caller.values_mut() {
        names.sort_unstable();
        names.dedup();
    }
    by_caller
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::graph_of_files;

    #[test]
    fn lines_read_as_str_lines_splits_them() {
        for text in ["a\nbb\n", "a\r\nb", "one", "\n\nx\n", "x\n\n"] {
            let ws = Workspace::new("t", None, graph_of_files(&[("f.c", text)]));
            let expected: Vec<&str> = text.lines().collect();
            let found: Vec<&str> = (1..=u32::try_from(expected.len() + 1).expect("small"))
                .map_while(|n| ws.line("f.c", n))
                .collect();
            assert_eq!(found, expected, "{text:?}");
        }
        let ws = Workspace::new("t", None, graph_of_files(&[("f.c", "x\n")]));
        assert_eq!(ws.line("f.c", 0), None);
        assert_eq!(ws.line("nope.c", 1), None);
    }
}
