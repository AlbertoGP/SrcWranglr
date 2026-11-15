use super::*;
use crate::mcp::fixture::workspace;

fn find(query: &str) -> String {
    let args = FindSymbolArgs {
        query: query.into(),
        ..Default::default()
    };
    find_symbol(&workspace(), &args).expect("find")
}

fn source(name: &str, file: Option<&str>) -> Result<String, String> {
    let args = SymbolArgs {
        name: name.into(),
        file: file.map(Into::into),
    };
    function_source(&workspace(), &args)
}

fn read(file: &str, start_line: u32, end_line: Option<u32>) -> Result<String, String> {
    let args = ReadSourceArgs {
        file: file.into(),
        start_line,
        end_line,
    };
    read_source(&workspace(), &args)
}

#[test]
fn a_symbol_is_found_by_part_of_its_name_with_its_place_and_prototype() {
    let found = find("parse_hdr");
    let first = found.lines().next().expect("a line");
    assert!(
        first.starts_with("function  parse_header  net/parse.c:4"),
        "{found}"
    );
    assert!(
        first.contains("static int parse_header(char *dst, const char *src, int len)"),
        "{found}"
    );
}

#[test]
fn a_library_function_named_exactly_is_listed_first() {
    let found = find("system");
    assert!(found.starts_with("library  system()  1 call"), "{found}");
}

#[test]
fn nothing_found_says_where_else_to_look() {
    let found = find("zzqqxx");
    assert!(found.contains("No symbol matches"), "{found}");
    assert!(found.contains("library_calls"), "{found}");
}

#[test]
fn a_functions_source_is_just_that_function_numbered() {
    let shown = source("handle_packet", None).expect("source");
    let header = shown.lines().next().expect("header");
    assert!(header.contains("net/parse.c:9-16"), "{shown}");
    assert!(header.contains("complexity 2"), "{shown}");
    assert!(shown.contains("\n   14      system(buf);\n"), "{shown}");
    assert!(!shown.contains("memcpy"), "{shown}");
}

#[test]
fn a_name_in_two_files_asks_which_then_takes_the_file() {
    let error = source("probe", None).expect_err("ambiguous");
    assert!(error.contains("drivers/a.c:1"), "{error}");
    assert!(error.contains("drivers/b.c:1"), "{error}");
    let shown = source("probe", Some("drivers/b.c")).expect("source");
    assert!(shown.contains("return 2;"), "{shown}");
}

#[test]
fn an_unknown_name_points_to_the_search_tools() {
    let error = source("nope", None).expect_err("unknown");
    assert!(error.contains("find_symbol"), "{error}");
}

#[test]
fn source_lines_are_read_by_range_with_numbers() {
    let shown = read("main.c", 4, Some(5)).expect("read");
    assert_eq!(
        shown,
        "main.c:4-5 of 9 lines\n    4  int main(int argc, char **argv) {\n    5      char line[64];"
    );
}

#[test]
fn only_indexed_files_and_their_lines_can_be_read() {
    let error = read("../etc/passwd", 1, None).expect_err("outside");
    assert!(error.contains("not an indexed file"), "{error}");
    let error = read("main.c", 50, None).expect_err("past the end");
    assert!(error.contains("has 9 lines"), "{error}");
    let shown = read("main.c", 8, Some(500)).expect("read");
    assert!(shown.starts_with("main.c:8-9 of 9 lines"), "{shown}");
}

#[test]
fn hidden_characters_in_source_are_marked() {
    let shown = read("drivers/b.c", 2, None).expect("read");
    assert!(shown.contains("‹U+202E›"), "{shown}");
    assert!(!shown.contains('\u{202E}'), "{shown}");
}
