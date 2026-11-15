use super::*;
use crate::mcp::args::Fuzzer;
use crate::mcp::fixture::workspace;

fn harness_of(name: &str, fuzzer: Option<Fuzzer>) -> Result<String, String> {
    let args = HarnessArgs {
        name: name.into(),
        fuzzer,
        ..Default::default()
    };
    fuzz_harness(&workspace(), &args)
}

#[test]
fn fuzz_targets_are_ranked_with_their_reasons() {
    let listed = fuzz_targets(&workspace(), &FuzzTargetsArgs::default()).expect("targets");
    let row = listed
        .lines()
        .find(|l| l.contains("parse_header  net/parse.c:4"))
        .unwrap_or_else(|| panic!("{listed}"));
    assert!(row.contains(" │ "), "{row}");
    assert!(
        ["easy", "moderate", "hard"].iter().any(|e| row.contains(e)),
        "{row}"
    );
    let in_drivers = fuzz_targets(
        &workspace(),
        &FuzzTargetsArgs {
            path: Some("drivers".into()),
            ..Default::default()
        },
    )
    .expect("targets");
    assert!(!in_drivers.contains("net/parse.c"), "{in_drivers}");
}

#[test]
fn a_harness_comes_with_its_dictionary_and_makefile_for_the_aavr_folder() {
    let drafted = harness_of("parse_header", None).expect("harness");
    assert!(drafted.contains("=== fuzz_parse_header.cc"), "{drafted}");
    assert!(drafted.contains("LLVMFuzzerTestOneInput"), "{drafted}");
    assert!(drafted.contains("=== fuzz_parse_header.mk"), "{drafted}");
    assert!(
        drafted.contains(".aavr/harnesses/fuzz_parse_header"),
        "{drafted}"
    );
    assert!(drafted.contains("ROOT = ../../.."), "{drafted}");
    let afl = harness_of("parse_header", Some(Fuzzer::Afl)).expect("afl");
    assert!(afl.contains("=== fuzz_parse_header_afl.cc"), "{afl}");
    assert!(afl.contains("__AFL_LOOP"), "{afl}");
}

#[test]
fn a_makefile_keeps_its_tabs() {
    let drafted = harness_of("parse_header", None).expect("harness");
    assert!(drafted.contains("\n\t"), "recipes need tabs");
    assert!(!drafted.contains("‹TAB›"), "{drafted}");
}

#[test]
fn only_a_defined_function_gets_a_harness() {
    let error = harness_of("nope", None).expect_err("unknown");
    assert!(error.contains("find_symbol"), "{error}");
}

#[test]
fn input_paths_say_where_input_comes_in_and_what_it_reaches() {
    let shown = input_paths(&workspace(), &InputPathsArgs::default()).expect("paths");
    assert!(shown.contains("the command line"), "{shown}");
    let strcpy = shown
        .lines()
        .find(|l| l.contains("strcpy") && l.contains("main.c:6"))
        .unwrap_or_else(|| panic!("{shown}"));
    assert!(strcpy.contains("in main"), "{strcpy}");
}

#[test]
fn the_path_input_takes_to_a_function_is_shown() {
    let source = "\
#include <string.h>
static void copy(char *dst, const char *src) { strcpy(dst, src); }
static void handle(const char *arg) { char b[8]; copy(b, arg); }
int main(int argc, char **argv) { handle(argv[1]); return 0; }
static int unused(void) { return 0; }
";
    let ws = crate::mcp::workspace::Workspace::new(
        "t",
        None,
        crate::index::graph_of_files(&[("m.c", source)]),
    );
    let path_to = |name: &str| {
        let args = InputPathsArgs {
            name: Some(name.into()),
            ..Default::default()
        };
        input_paths(&ws, &args).expect("path")
    };
    let shown = path_to("copy");
    assert!(shown.contains("main » handle » copy"), "{shown}");
    let shown = path_to("unused");
    assert!(shown.contains("No direct call path from input"), "{shown}");
}
