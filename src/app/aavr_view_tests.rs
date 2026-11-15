use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;

use super::*;

struct State {
    view: AavrView,
    root: Option<PathBuf>,
    launcher: Launcher,
    action: Option<AavrAction>,
}

fn harness(root: Option<PathBuf>, launcher: Launcher) -> Harness<'static, State> {
    let mut harness = crate::app::fonts::test_harness()
        .with_size(egui::vec2(700.0, 800.0))
        .build_ui_state(
            |ui, state: &mut State| {
                if let Some(action) = state.view.show(ui, state.root.as_deref(), &state.launcher) {
                    state.action = Some(action);
                }
            },
            State {
                view: AavrView::default(),
                root,
                launcher,
                action: None,
            },
        );
    harness.step();
    harness
}

fn ready() -> Launcher {
    Launcher {
        opencode: Some("/opt/homebrew/bin/opencode".into()),
        is_connected: true,
        connect_command: "opencode mcp add --global srcwranglr -- srcwranglr --mcp".into(),
    }
}

/// Steps until the run has been read.
fn read_run(harness: &mut Harness<'static, State>) {
    for _ in 0..400 {
        harness.step();
        if harness.state().view.has_read {
            harness.run();
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("never read");
}

fn project_with_a_run() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let aavr = dir.path().join(".aavr");
    std::fs::create_dir_all(aavr.join("findings")).expect("mkdir");
    std::fs::write(
        aavr.join("state.json"),
        r#"{"completed_phases": ["repository-recon"], "next_phase": "build-baseline", "blocked_on": []}"#,
    )
    .expect("write");
    std::fs::write(
        aavr.join("findings/AAVR-1.json"),
        r#"{"id": "AAVR-1", "title": "system on packet", "classification": "confirmed",
            "severity": "high", "sink": {"file": "net/parse.c", "line": 14}}"#,
    )
    .expect("write");
    dir
}

#[test]
fn a_run_shows_its_phases_and_a_candidate_goes_to_its_code() {
    let dir = project_with_a_run();
    let mut harness = harness(Some(dir.path().to_path_buf()), ready());
    read_run(&mut harness);
    harness.get_by_label("✓ Recon");
    harness.get_by_label("→ Build");
    harness.get_by_label("Confirmed (1)");
    harness
        .get_by_label_contains("AAVR-1  system on packet")
        .click();
    harness.run();
    assert_eq!(
        harness.state().action,
        Some(AavrAction::GoTo {
            file: "net/parse.c".into(),
            line: 14
        })
    );
}

#[test]
fn without_a_run_it_says_how_to_start_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut harness = harness(Some(dir.path().to_path_buf()), ready());
    read_run(&mut harness);
    harness.get_by_label_contains("No AAVR run here yet");
    harness.get_by_label("Start Assessment in opencode").click();
    harness.run();
    assert_eq!(harness.state().action, Some(AavrAction::Start));
}

#[test]
fn connecting_is_offered_until_opencode_lists_srcwranglr() {
    let dir = tempfile::tempdir().expect("tempdir");
    let launcher = Launcher {
        is_connected: false,
        ..ready()
    };
    let mut harness = harness(Some(dir.path().to_path_buf()), launcher);
    read_run(&mut harness);
    harness
        .get_by_label("Connect SrcWranglr to opencode")
        .click();
    harness.run();
    assert_eq!(harness.state().action, Some(AavrAction::Connect));
}

#[test]
fn without_opencode_starting_is_off_and_says_why() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut harness = harness(Some(dir.path().to_path_buf()), Launcher::default());
    read_run(&mut harness);
    harness.get_by_label_contains("opencode wasn't found");
    assert!(harness
        .query_by_label("Connect SrcWranglr to opencode")
        .is_none());
}
