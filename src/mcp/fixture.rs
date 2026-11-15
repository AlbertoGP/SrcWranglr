//! A small project for the tools' tests: a packet handler reached from
//! `main`, with risky calls, a name defined in two files, and a string
//! hiding a right-to-left override.

use super::workspace::Workspace;
use crate::index::graph_of_files;

pub const PARSE_C: &str = "\
#include <string.h>
#include <stdlib.h>

static int parse_header(char *dst, const char *src, int len) {
    memcpy(dst, src, len);
    return len;
}

int handle_packet(char *buf, int len) {
    char header[16];
    if (len > 16)
        return -1;
    parse_header(header, buf, len);
    system(buf);
    return 0;
}
";

pub const MAIN_C: &str = "\
#include <string.h>
int handle_packet(char *buf, int len);

int main(int argc, char **argv) {
    char line[64];
    strcpy(line, argv[1]);
    puts(\"starting up\");
    return handle_packet(line, 64);
}
";

pub const DRIVER_A: &str = "static int probe(void) { return 1; }\n";
pub const DRIVER_B: &str =
    "static int probe(void) { return 2; }\nconst char *banner = \"admin\u{202E}txt.exe\";\n";

/// The project above, indexed, with no folder on disk.
pub fn workspace() -> Workspace {
    let graph = graph_of_files(&[
        ("net/parse.c", PARSE_C),
        ("main.c", MAIN_C),
        ("drivers/a.c", DRIVER_A),
        ("drivers/b.c", DRIVER_B),
    ]);
    Workspace::new("fixture", None, graph)
}

/// The project above in folder `root`, so notes can be written there.
pub fn workspace_in(root: &std::path::Path) -> Workspace {
    let graph = graph_of_files(&[("net/parse.c", PARSE_C), ("main.c", MAIN_C)]);
    Workspace::new("fixture", Some(root.to_path_buf()), graph)
}
