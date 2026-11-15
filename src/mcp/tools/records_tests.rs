use super::*;
use crate::mcp::fixture::{workspace, workspace_in};
use crate::notes::journal;

fn entry(text: &str, place: Option<&str>) -> JournalArgs {
    JournalArgs {
        text: text.into(),
        place: place.map(Into::into),
    }
}

#[test]
fn a_journal_entry_is_saved_marked_as_the_agents() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ws = workspace_in(dir.path());
    let said = journal_entry(
        &ws,
        &entry("Recon done: 2 input surfaces.", Some("main.c:6")),
        100,
    )
    .expect("written");
    assert!(said.contains("journal"), "{said}");
    let saved = journal::load(dir.path()).expect("load");
    let written = saved.entries().last().expect("an entry");
    assert_eq!(written.text, "[agent] Recon done: 2 input surfaces.");
    assert_eq!(written.place(), Some(("main.c", 6)));
}

#[test]
fn a_journal_entry_must_say_something_about_somewhere_indexed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ws = workspace_in(dir.path());
    assert!(journal_entry(&ws, &entry("  ", None), 1).is_err());
    let error = journal_entry(&ws, &entry("x", Some("nope.c:1")), 1).expect_err("not indexed");
    assert!(error.contains("not an indexed file"), "{error}");
    let error = journal_entry(&workspace(), &entry("x", None), 1).expect_err("no folder");
    assert!(error.contains("no folder"), "{error}");
}

#[test]
fn a_report_to_import_must_be_a_file_inside_the_project() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ws = workspace_in(dir.path());
    let runs = dir.path().join(".aavr/runs");
    std::fs::create_dir_all(&runs).expect("mkdir");
    std::fs::write(runs.join("r.sarif"), "{}").expect("write");
    let found = sarif_file(&ws, ".aavr/runs/r.sarif").expect("inside");
    assert!(found.ends_with(".aavr/runs/r.sarif"), "{}", found.display());
    for outside in [
        "../r.sarif",
        "/etc/passwd",
        ".aavr/runs/missing.sarif",
        ".aavr/runs",
    ] {
        assert!(sarif_file(&ws, outside).is_err(), "{outside}");
    }
    let elsewhere = tempfile::tempdir().expect("tempdir");
    std::fs::write(elsewhere.path().join("x.sarif"), "{}").expect("write");
    std::os::unix::fs::symlink(elsewhere.path().join("x.sarif"), runs.join("link.sarif"))
        .expect("symlink");
    let error = sarif_file(&ws, ".aavr/runs/link.sarif").expect_err("symlink out");
    assert!(error.contains("outside"), "{error}");
}
