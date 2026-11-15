use super::*;
use crate::mcp::args::TraceDirection;
use crate::mcp::workspace::Workspace;

const SOURCE: &str = "\
#include <string.h>
#include <stdio.h>
void load(void) {
    char raw[64];
    fgets(raw, sizeof raw, stdin);
    char buf[16];
    strcpy(buf, raw);
}
";

fn ws() -> Workspace {
    Workspace::new("t", None, crate::index::graph_of_files(&[("m.c", SOURCE)]))
}

fn traced(
    line: u32,
    name: Option<&str>,
    direction: Option<TraceDirection>,
) -> Result<String, String> {
    let args = TraceArgs {
        file: "m.c".into(),
        line,
        name: name.map(Into::into),
        direction,
        ..Default::default()
    };
    trace(&ws(), &args)
}

#[test]
fn a_risky_calls_arguments_are_traced_back_to_where_they_come_from() {
    let shown = traced(7, None, None).expect("trace");
    assert!(shown.contains("from fgets()"), "{shown}");
    assert!(
        shown.contains("m.c:5  in load  │ fgets(raw, sizeof raw, stdin);"),
        "{shown}"
    );
}

#[test]
fn a_variable_is_traced_back_and_forward() {
    let back = traced(7, Some("raw"), Some(TraceDirection::Back)).expect("back");
    assert!(back.contains("from fgets()"), "{back}");
    let forward = traced(5, Some("raw"), Some(TraceDirection::Forward)).expect("forward");
    assert!(forward.contains("reaches `strcpy()`"), "{forward}");
}

#[test]
fn a_value_is_traced_to_a_call_named() {
    let args = TraceArgs {
        file: "m.c".into(),
        line: 5,
        name: Some("raw".into()),
        direction: Some(TraceDirection::To),
        sink_file: Some("m.c".into()),
        sink_line: Some(7),
        sink_call: Some("strcpy".into()),
    };
    let shown = trace(&ws(), &args).expect("to");
    assert!(shown.contains("strcpy"), "{shown}");
    let error = trace(
        &ws(),
        &TraceArgs {
            sink_call: None,
            ..args
        },
    )
    .expect_err("needs the call");
    assert!(error.contains("sink_call"), "{error}");
}

#[test]
fn a_name_not_on_the_line_is_refused() {
    let error = traced(7, Some("nope"), None).expect_err("not there");
    assert!(error.contains("`nope` isn't on m.c:7"), "{error}");
    let error = traced(70, Some("raw"), None).expect_err("no such line");
    assert!(error.contains("has 8 lines"), "{error}");
}

#[test]
fn a_rule_is_drafted_from_code_to_find_more_like_it() {
    let args = DraftRuleArgs {
        file: "m.c".into(),
        first_line: 7,
        ..Default::default()
    };
    let rule = draft_rule(&ws(), &args).expect("rule");
    assert!(rule.contains("rules:"), "{rule}");
    assert!(rule.contains("strcpy"), "{rule}");
    assert!(rule.contains("semgrep --config"), "{rule}");
}
