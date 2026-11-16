//! The agent's confirmed AAVR candidates, as Findings, so the agent's
//! confirmed bugs sit in the Findings window next to the scanners' results
//! — one unified list. Only candidates the agent marked **confirmed** and
//! gave a place come in; rejected, speculative and unclassified ones stay in
//! the Assessment tab. The id, title and place come from the audited tree
//! (via the agent), untrusted like any finding's text, and are shown through
//! the Findings list's usual `visible()` rendering.

use crate::analysis::{Finding, Severity};
use crate::index::functions_holding_lines;
use crate::model::CodeGraph;

use super::aavr_run::{AavrRun, Candidate, Classification};

/// The tool name these findings carry, so `with_tool_results` replaces them
/// as a set and the Findings list shows where they came from.
pub const TOOL: &str = "AAVR agent";

/// Confirmed candidates that point at a place.
fn confirmed(run: &AavrRun) -> impl Iterator<Item = &Candidate> {
    run.candidates
        .iter()
        .filter(|c| c.classification == Classification::Confirmed && c.place.is_some())
}

/// A signature of the confirmed candidates, so the Findings list is rebuilt
/// only when they actually change (the run is re-read every few seconds).
pub fn key(run: &AavrRun) -> String {
    let mut parts = vec![run.revision.clone()];
    parts.extend(confirmed(run).map(|c| {
        let (file, line) = c.place.as_ref().expect("confirmed has a place");
        format!("{}|{}|{file}:{line}", c.id, c.severity)
    }));
    parts.join("\n")
}

/// The confirmed candidates as Findings, each with its enclosing function
/// resolved so it reads and navigates like a scanner's finding.
pub fn findings(run: &AavrRun, graph: &CodeGraph) -> Vec<Finding> {
    let confirmed: Vec<&Candidate> = confirmed(run).collect();
    let places: Vec<(&str, u32)> = confirmed
        .iter()
        .map(|c| {
            let (file, line) = c.place.as_ref().expect("confirmed has a place");
            (file.as_str(), *line)
        })
        .collect();
    let symbols = functions_holding_lines(graph, &places);
    confirmed
        .iter()
        .zip(symbols)
        .map(|(c, symbol)| {
            let (file, line) = c.place.as_ref().expect("confirmed has a place");
            Finding {
                tool: TOOL.to_string(),
                rule: c.id.clone(),
                severity: severity_of(&c.severity),
                message: c.title.clone(),
                fix: None,
                cwe: None,
                file: file.clone(),
                line: *line,
                columns: None,
                symbol,
            }
        })
        .collect()
}

/// The agent's severity word as a band; anything unrecognised is medium, so
/// a confirmed bug is never silently hidden in the low tier.
fn severity_of(word: &str) -> Severity {
    match word.trim().to_ascii_lowercase().as_str() {
        "high" | "critical" => Severity::High,
        "low" | "info" | "informational" => Severity::Low,
        _ => Severity::Medium,
    }
}

#[cfg(test)]
#[path = "agent_findings_tests.rs"]
mod tests;
