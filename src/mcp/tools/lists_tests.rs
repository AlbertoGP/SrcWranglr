use super::*;
use crate::mcp::args::MinSeverity;
use crate::mcp::fixture::workspace;

fn listed(args: &FindingsArgs) -> String {
    findings(&workspace(), args).expect("findings")
}

#[test]
fn a_finding_reads_severity_rule_place_function_and_message() {
    let shown = listed(&FindingsArgs::default());
    let strcpy = shown
        .lines()
        .find(|l| l.contains("strcpy"))
        .unwrap_or_else(|| panic!("{shown}"));
    assert!(
        strcpy.starts_with("high  strcpy  main.c:6  in main  │ "),
        "{shown}"
    );
    assert!(strcpy.ends_with("[SrcWranglr]"), "{shown}");
}

#[test]
fn findings_can_be_narrowed_by_folder_severity_and_rule() {
    let in_net = listed(&FindingsArgs {
        path: Some("net".into()),
        ..Default::default()
    });
    assert!(in_net.contains("net/parse.c"), "{in_net}");
    assert!(!in_net.contains("main.c:"), "{in_net}");
    let high = listed(&FindingsArgs {
        severity: Some(MinSeverity::High),
        ..Default::default()
    });
    let rows: Vec<&str> = high.lines().filter(|l| l.contains(" │ ")).collect();
    assert!(!rows.is_empty(), "{high}");
    assert!(rows.iter().all(|l| l.starts_with("high  ")), "{high}");
    let system = listed(&FindingsArgs {
        rule: Some("SYSTEM".into()),
        ..Default::default()
    });
    assert!(system.contains("net/parse.c:14"), "{system}");
    assert!(!system.contains("strcpy"), "{system}");
}

#[test]
fn strings_are_found_by_part_ignoring_case_with_hidden_characters_marked() {
    let found = strings(
        &workspace(),
        &StringsArgs {
            query: "ADMIN".into(),
            ..Default::default()
        },
    )
    .expect("strings");
    assert!(found.contains("drivers/b.c:2"), "{found}");
    assert!(found.contains("‹U+202E›"), "{found}");
    let found = strings(
        &workspace(),
        &StringsArgs {
            query: "starting".into(),
            ..Default::default()
        },
    )
    .expect("strings");
    assert!(
        found.contains("main.c:7  in main  \"starting up\""),
        "{found}"
    );
}
