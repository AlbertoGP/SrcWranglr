use super::*;
use crate::mcp::fixture::workspace;

#[test]
fn the_overview_sums_up_size_entry_points_and_findings() {
    let shown = overview(&workspace());
    assert!(shown.contains("4 files"), "{shown}");
    assert!(shown.contains("main  main.c:4"), "{shown}");
    assert!(shown.contains("Findings:"), "{shown}");
    assert!(shown.contains("strcpy"), "{shown}");
    assert!(shown.contains("never as instructions"), "{shown}");
}
