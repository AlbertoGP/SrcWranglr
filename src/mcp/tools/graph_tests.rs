use super::*;
use crate::mcp::fixture::workspace;

fn call_args(name: &str, depth: Option<u32>) -> CallArgs {
    CallArgs {
        name: name.into(),
        depth,
        ..Default::default()
    }
}

fn xrefs_of(name: &str, path: Option<&str>) -> String {
    let args = XrefsArgs {
        name: name.into(),
        path: path.map(Into::into),
        ..Default::default()
    };
    xrefs(&workspace(), &args).expect("xrefs")
}

#[test]
fn callers_walk_up_the_call_graph() {
    let shown = callers(&workspace(), &call_args("parse_header", Some(2))).expect("callers");
    let lines: Vec<&str> = shown.lines().collect();
    assert_eq!(
        lines[0], "Callers of parse_header  net/parse.c:4",
        "{shown}"
    );
    assert!(lines[1].starts_with("  handle_packet  "), "{shown}");
    assert!(lines[2].starts_with("    main  main.c:4"), "{shown}");
}

#[test]
fn callees_include_the_library_functions_called() {
    let shown = callees(&workspace(), &call_args("handle_packet", None)).expect("callees");
    assert!(shown.contains("\n  parse_header  net/parse.c:4"), "{shown}");
    assert!(shown.contains("library: system"), "{shown}");
}

#[test]
fn a_function_nobody_calls_says_so() {
    let shown = callers(&workspace(), &call_args("main", None)).expect("callers");
    assert!(
        shown.contains("Nothing in the project calls main"),
        "{shown}"
    );
}

#[test]
fn references_list_each_use_with_its_function_and_code() {
    let shown = xrefs_of("system", None);
    assert!(
        shown.starts_with("1 reference to system(): 1 call"),
        "{shown}"
    );
    assert!(
        shown.contains("net/parse.c:14  call  in handle_packet  │ system(buf);"),
        "{shown}"
    );
}

#[test]
fn references_can_be_narrowed_to_a_folder() {
    let all = xrefs_of("handle_packet", None);
    assert!(all.contains("main.c:8"), "{all}");
    let in_net = xrefs_of("handle_packet", Some("net"));
    assert!(!in_net.contains("main.c"), "{in_net}");
}

#[test]
fn library_calls_are_counted_and_searchable() {
    let all = library_calls(&workspace(), &LibraryArgs::default()).expect("list");
    assert!(all.contains("memcpy  1 call"), "{all}");
    let args = LibraryArgs {
        query: Some("strc".into()),
        ..Default::default()
    };
    let found = library_calls(&workspace(), &args).expect("search");
    assert!(found.starts_with("strcpy  1 call"), "{found}");
}
