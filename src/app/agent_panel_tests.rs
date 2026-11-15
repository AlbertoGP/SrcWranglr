use std::time::{Duration, Instant};

use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;

use super::*;
use crate::mcp::dispatch::Place;

struct State {
    panel: AgentPanel,
    serving: Serving,
    action: Option<AgentPanelAction>,
}

fn event(tool: &str, place: Option<Place>, is_error: bool) -> AgentEvent {
    AgentEvent {
        at: Instant::now() - Duration::from_secs(90),
        tool: tool.into(),
        asked: "name=helper".into(),
        answer: if is_error {
            "No symbol `helper`.".into()
        } else {
            "Callers of helper  x.c:1".into()
        },
        is_error,
        place,
    }
}

fn harness(panel: AgentPanel) -> Harness<'static, State> {
    let mut panel = panel;
    panel.set_open(true);
    let mut harness = crate::app::fonts::test_harness()
        .with_size(egui::vec2(900.0, 600.0))
        .build_ui_state(
            |ui, state: &mut State| {
                let command = "srcwranglr --mcp";
                if let Some(action) =
                    state
                        .panel
                        .show(ui, Layout::default(), &state.serving, (command, None))
                {
                    state.action = Some(action);
                }
            },
            State {
                panel,
                serving: Serving::On {
                    folder: "/p".into(),
                },
                action: None,
            },
        );
    harness.run();
    harness
}

#[test]
fn before_any_call_it_says_how_to_connect_an_agent() {
    let harness = harness(AgentPanel::default());
    harness.get_by_label("Agent (0 calls)");
    harness.get_by_label_contains("No agent has asked anything yet");
    harness.get_by_label("srcwranglr --mcp");
    harness.get_by_label("opencode mcp add --global srcwranglr -- srcwranglr --mcp");
}

#[test]
fn calls_are_listed_newest_first_and_a_click_goes_where_it_looked() {
    let mut panel = AgentPanel::default();
    let place = Place {
        symbol: Some(3),
        file: "x.c".into(),
        line: 1,
    };
    panel.push(event("callers", Some(place.clone()), false));
    panel.push(event("function_source", None, true));
    let mut harness = harness(panel);
    harness.get_by_label("Agent (2 calls)");
    harness.get_by_label_contains("→ No symbol `helper`.");
    harness
        .get_by_label("  1 min  callers  name=helper")
        .click();
    harness.run();
    assert_eq!(harness.state().action, Some(AgentPanelAction::GoTo(place)));
}

#[test]
fn following_the_agent_is_a_choice() {
    let mut harness = harness(AgentPanel::default());
    assert!(!harness.state().panel.is_following());
    harness.get_by_label("Follow the agent").click();
    harness.run();
    assert!(harness.state().panel.is_following());
}

#[test]
fn not_serving_says_why() {
    let mut panel = AgentPanel::default();
    panel.set_open(true);
    let mut harness = crate::app::fonts::test_harness()
        .with_size(egui::vec2(900.0, 600.0))
        .build_ui_state(
            |ui, state: &mut State| {
                state
                    .panel
                    .show(ui, Layout::default(), &state.serving, ("x", None));
            },
            State {
                panel,
                serving: Serving::Off("Not serving agents: another window does.".into()),
                action: None,
            },
        );
    harness.run();
    harness.get_by_label("Not serving agents: another window does.");
}

#[test]
fn old_calls_give_way_to_new_ones() {
    let mut panel = AgentPanel::default();
    for _ in 0..(MAX_EVENTS + 5) {
        panel.push(event("overview", None, false));
    }
    assert_eq!(panel.events.len(), MAX_EVENTS);
    assert_eq!(panel.calls, MAX_EVENTS + 5);
}

#[test]
fn ages_read_plainly() {
    assert_eq!(age(Duration::from_secs(3)), "now");
    assert_eq!(age(Duration::from_secs(42)), "42 s");
    assert_eq!(age(Duration::from_secs(150)), "2 min");
    assert_eq!(age(Duration::from_secs(7_300)), "2 h");
}
