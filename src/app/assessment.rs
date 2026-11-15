//! Starting an AAVR assessment from the app: opencode opened on the
//! project in a terminal and asked to run AAVR's orchestrator with
//! SrcWranglr's tools; and, once, connecting SrcWranglr to opencode, by
//! running opencode's own `mcp add` for you.

use std::path::{Path, PathBuf};

use super::aavr_view::Launcher;
use super::editor::{in_new_terminal, spawn_detached, this_os, Launch};
use crate::programs::SearchPath;

/// What opencode is asked when an assessment starts.
pub const PROMPT: &str =
    "Run an AAVR assessment of this repository: load the aavr-orchestrate skill \
and follow its phases, keeping your work in .aavr/. Start by reading the current findings (the \
findings tool) and the overview. Use the srcwranglr MCP tools (overview, findings, input_paths, \
fuzz_targets, fuzz_harness, trace, function_source, callers, xrefs) to explore the code instead of \
grep and whole-file reads. Record each phase with journal_entry and mark findings with set_verdict \
as you triage them.";
/// The name SrcWranglr's server goes by in opencode's config.
const SERVER_NAME: &str = "srcwranglr";
const OPENCODE: &str = "opencode";
/// Config files are read at most this big, looking for the server.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// opencode and whether it lists SrcWranglr, found now.
pub fn launcher(search: &SearchPath) -> Launcher {
    let opencode = search.find(OPENCODE);
    let connect_command = opencode
        .as_deref()
        .map(|o| command_line(&connect_launch(o, &this_exe())))
        .unwrap_or_default();
    let exe = this_exe();
    Launcher {
        opencode,
        is_connected: config_dirs().iter().any(|dir| lists_this_server(dir, &exe)),
        connect_command,
    }
}

/// opencode on `root`, asked to run an assessment.
pub fn start_launch(opencode: &Path, root: &Path) -> Launch {
    Launch {
        program: opencode.display().to_string(),
        args: vec!["--prompt".into(), PROMPT.into(), root.display().to_string()],
    }
}

/// Opens opencode on `root` in a new terminal, asked to run an assessment.
pub fn start(opencode: &Path, root: &Path, search: &SearchPath) -> Result<String, String> {
    let terminal = in_new_terminal(start_launch(opencode, root), this_os()).map_err(|_| {
        "Not starting opencode: the project's path has control characters.".to_string()
    })?;
    spawn_detached(&terminal, search)?;
    Ok("opencode is starting in a terminal. Its calls show in the Calls tab, and its run here as it goes.".into())
}

/// opencode's `mcp add`, adding SrcWranglr (`exe`) for every project.
pub fn connect_launch(opencode: &Path, exe: &Path) -> Launch {
    Launch {
        program: opencode.display().to_string(),
        args: vec![
            "mcp".into(),
            "add".into(),
            "--global".into(),
            SERVER_NAME.into(),
            "--".into(),
            exe.display().to_string(),
            crate::mcp::MCP_ARG.into(),
        ],
    }
}

/// Runs `launch` to its end (opencode's `mcp add` is quick) and says how
/// it went.
pub fn connect(launch: &Launch, search: &SearchPath) -> Result<String, String> {
    let output = std::process::Command::new(&launch.program)
        .args(&launch.args)
        .env("PATH", search.joined())
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("Could not run {}: {e}", launch.program))?;
    let said = |bytes: &[u8]| String::from_utf8_lossy(bytes).trim().to_string();
    match output.status.success() {
        true => Ok(format!(
            "Connected: {}",
            said(&output.stdout)
                .lines()
                .next()
                .unwrap_or("SrcWranglr added to opencode.")
        )),
        false => Err(format!(
            "opencode couldn't add SrcWranglr ({}): {}",
            output.status,
            said(&output.stderr)
        )),
    }
}

/// `launch` as you'd type it, words with spaces quoted.
pub fn command_line(launch: &Launch) -> String {
    std::iter::once(&launch.program)
        .chain(&launch.args)
        .map(|word| match word.contains(' ') {
            true => format!("'{word}'"),
            false => word.clone(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// This program, as opencode should run it.
pub fn this_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("srcwranglr"))
}

/// Where opencode keeps its global config.
fn config_dirs() -> Vec<PathBuf> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"));
    xdg.into_iter()
        .chain(home)
        .map(|dir| dir.join(OPENCODE))
        .collect()
}

/// Whether a config file in `dir` lists an MCP server that runs `exe`
/// with `--mcp`. Falls back to naming the server when the file is JSONC
/// (comments) and won't parse as JSON.
fn lists_this_server(dir: &Path, exe: &Path) -> bool {
    ["opencode.json", "opencode.jsonc", "config.json"]
        .iter()
        .map(|name| dir.join(name))
        .filter(|path| {
            std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() <= MAX_CONFIG_BYTES)
        })
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .any(|text| config_runs_exe(&text, exe))
}

/// Whether `text` (an opencode config) runs `exe` with `--mcp` in some MCP
/// server's command.
fn config_runs_exe(text: &str, exe: &Path) -> bool {
    let exe = exe.to_string_lossy();
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(value) => command_runs_exe(&value, &exe),
        // JSONC won't parse; fall back to both strings being present.
        Err(_) => text.contains(crate::mcp::MCP_ARG) && text.contains(exe.as_ref()),
    }
}

/// Whether any array in `value` is a command running `exe` with `--mcp`.
fn command_runs_exe(value: &serde_json::Value, exe: &str) -> bool {
    match value {
        serde_json::Value::Array(items) => {
            let words: Vec<&str> = items.iter().filter_map(serde_json::Value::as_str).collect();
            (words.contains(&exe) && words.contains(&crate::mcp::MCP_ARG))
                || items.iter().any(|v| command_runs_exe(v, exe))
        }
        serde_json::Value::Object(fields) => fields.values().any(|v| command_runs_exe(v, exe)),
        _ => false,
    }
}

/// Whether starting opencode in `root` could run code the repo defines
/// (its own MCP servers, plugins, agents or AGENTS.md instructions).
pub fn would_run_repo_code(root: &Path) -> bool {
    [
        "opencode.json",
        "opencode.jsonc",
        ".opencode",
        "AGENTS.md",
        "CLAUDE.md",
    ]
    .iter()
    .any(|name| std::fs::symlink_metadata(root.join(name)).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starting_runs_opencode_on_the_project_with_the_aavr_prompt() {
        let launch = start_launch(Path::new("/bin/opencode"), Path::new("/src/linux"));
        assert_eq!(launch.program, "/bin/opencode");
        assert_eq!(launch.args[0], "--prompt");
        assert!(launch.args[1].contains("aavr-orchestrate"));
        assert!(launch.args[1].contains("srcwranglr MCP tools"));
        assert_eq!(launch.args[2], "/src/linux");
        assert!(
            !launch.args.iter().any(|a| a == "--auto"),
            "never auto-approve"
        );
    }

    #[test]
    fn connecting_adds_srcwranglr_to_opencodes_global_config() {
        let launch = connect_launch(
            Path::new("/bin/opencode"),
            Path::new("/Apps/S W/srcwranglr"),
        );
        assert_eq!(
            command_line(&launch),
            "/bin/opencode mcp add --global srcwranglr -- '/Apps/S W/srcwranglr' --mcp"
        );
    }

    #[test]
    fn a_config_running_this_exe_counts_as_connected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let exe = Path::new("/Apps/srcwranglr");
        assert!(!lists_this_server(dir.path(), exe));
        // A server that merely has the name, but runs another program, doesn't.
        std::fs::write(
            dir.path().join("opencode.json"),
            r#"{"mcp": {"servers": {"srcwranglr": {"type": "local", "command": ["/other", "x"]}}}}"#,
        )
        .expect("write");
        assert!(!lists_this_server(dir.path(), exe));
        std::fs::write(
            dir.path().join("opencode.json"),
            r#"{"mcp": {"servers": {"sw": {"type": "local", "command": ["/Apps/srcwranglr", "--mcp"]}}}}"#,
        )
        .expect("write");
        assert!(lists_this_server(dir.path(), exe));
    }
}
