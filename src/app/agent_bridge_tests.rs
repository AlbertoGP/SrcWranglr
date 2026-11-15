use serde_json::json;

use super::*;
use crate::index::graph_of_files;
use crate::mcp::bridge;

const SOURCE: &str = "int helper(int x) { return x; }\nint main(void) { return helper(1); }\n";

struct Setup {
    _project_dir: tempfile::TempDir,
    _short: tempfile::TempDir,
    root: PathBuf,
    sockets: PathBuf,
    bridge: AgentBridge,
}

/// A project in a folder of its own, served from a short socket folder.
fn served() -> Setup {
    let project_dir = tempfile::tempdir().expect("tempdir");
    let root = std::fs::canonicalize(project_dir.path()).expect("canonical");
    let short = tempfile::Builder::new()
        .prefix("swb")
        .tempdir_in("/tmp")
        .expect("tempdir");
    let sockets = short.path().join("agents");
    let project = Project::new("p", Some(root.clone()), graph_of_files(&[("x.c", SOURCE)]));
    let bridge = AgentBridge::start_in(&project, &egui::Context::default(), &sockets);
    Setup {
        _project_dir: project_dir,
        _short: short,
        root,
        sockets,
        bridge,
    }
}

#[test]
fn an_agents_call_is_answered_and_shown_as_an_event() {
    let setup = served();
    assert_eq!(
        setup.bridge.serving(),
        &Serving::On {
            folder: setup.root.clone()
        }
    );
    let answer = bridge::call(
        &setup.sockets,
        &setup.root,
        "callers",
        &json!({"name": "helper"}),
    )
    .expect("served")
    .expect("answered");
    assert!(answer.contains("main  x.c:2"), "{answer}");
    let (events, notes) = setup.bridge.drain();
    assert!(notes.is_empty());
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(
        (event.tool.as_str(), event.asked.as_str()),
        ("callers", "name=helper")
    );
    assert_eq!(event.answer, "Callers of helper  x.c:1");
    assert!(!event.is_error);
    assert_eq!(
        event.place.as_ref().map(|p| (p.file.as_str(), p.line)),
        Some(("x.c", 1))
    );
}

#[test]
fn an_agents_note_waits_for_the_app_to_save_it() {
    let setup = served();
    let (sockets, root) = (setup.sockets.clone(), setup.root.clone());
    let agent = std::thread::spawn(move || {
        bridge::call(
            &sockets,
            &root,
            "add_note",
            &json!({"target": "x.c:2", "text": "called once"}),
        )
    });
    let request = loop {
        if let Some(request) = setup.bridge.drain().1.into_iter().next() {
            break request;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let AgentWrite::Note(change) = &request.write else {
        panic!("a note");
    };
    assert_eq!(change.added, "[agent] called once");
    request.reply.send(Ok(change.saved())).expect("reply");
    let answer = agent.join().expect("join").expect("served");
    assert_eq!(
        answer,
        Ok("Noted on x.c:2. The user sees it in SrcWranglr's Notes pane.".into())
    );
}

#[test]
fn a_project_without_a_folder_isnt_served() {
    let project = Project::demo().expect("demo");
    let bridge = AgentBridge::start(&project, &egui::Context::default());
    assert!(matches!(bridge.serving(), Serving::Off(_)));
}
