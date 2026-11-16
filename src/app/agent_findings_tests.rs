use super::*;
use crate::analysis::Severity;
use crate::app::aavr_run::{AavrRun, Candidate, Classification};
use crate::index::graph_of_files;

fn candidate(
    id: &str,
    class: Classification,
    severity: &str,
    place: Option<(&str, u32)>,
) -> Candidate {
    Candidate {
        id: id.into(),
        title: format!("bug in {id}"),
        classification: class,
        severity: severity.into(),
        confidence: "high".into(),
        place: place.map(|(f, l)| (f.into(), l)),
    }
}

fn run() -> AavrRun {
    AavrRun {
        revision: "abc123".into(),
        candidates: vec![
            candidate(
                "CAND-1",
                Classification::Confirmed,
                "high",
                Some(("m.c", 1)),
            ),
            candidate("CAND-2", Classification::Rejected, "high", Some(("m.c", 1))),
            candidate("CAND-3", Classification::Confirmed, "low", None),
            candidate(
                "CAND-4",
                Classification::Speculative,
                "medium",
                Some(("m.c", 1)),
            ),
        ],
        ..AavrRun::default()
    }
}

#[test]
fn only_placed_confirmed_candidates_become_findings() {
    let graph = graph_of_files(&[("m.c", "int helper(int x) { return x; }\n")]);
    let found = findings(&run(), &graph);
    let rules: Vec<&str> = found.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rules, ["CAND-1"], "only confirmed + placed");
}

#[test]
fn a_finding_carries_the_candidate_and_the_agent_tool() {
    let graph = graph_of_files(&[("m.c", "int helper(int x) { return x; }\n")]);
    let found = findings(&run(), &graph);
    let finding = &found[0];
    assert_eq!(finding.tool, TOOL);
    assert_eq!(finding.rule, "CAND-1");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.message, "bug in CAND-1");
    assert_eq!((finding.file.as_str(), finding.line), ("m.c", 1));
    assert!(finding.symbol.is_some(), "enclosing function resolved");
}

#[test]
fn an_unknown_severity_word_is_medium_not_low() {
    let graph = graph_of_files(&[("m.c", "x")]);
    let mut run = run();
    run.candidates[0].severity = "spicy".into();
    assert_eq!(findings(&run, &graph)[0].severity, Severity::Medium);
}

#[test]
fn the_key_changes_when_a_confirmed_candidate_changes() {
    let before = key(&run());
    let mut changed = run();
    changed.candidates[0].severity = "low".into();
    assert_ne!(before, key(&changed));
    // A change to a rejected candidate does not touch the key.
    let mut rejected = run();
    rejected.candidates[1].title = "different".into();
    assert_eq!(before, key(&rejected));
}
