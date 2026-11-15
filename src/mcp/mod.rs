//! SrcWranglr as an MCP server: `srcwranglr --mcp [folder]` indexes the
//! folder (the current one by default) and answers an agent's questions
//! about it (symbols, call graph, cross references, findings, notes) over
//! stdin and stdout, so the agent doesn't grep and read whole files to
//! learn the same things.

pub mod args;
pub mod backend;
#[cfg(unix)]
pub mod bridge;
pub mod dispatch;
pub mod folder;
pub mod format;
pub mod guard;
pub mod resolve;
pub mod server;
pub mod state;
pub mod tools;
pub mod workspace;

#[cfg(test)]
mod fixture;

use std::ffi::OsString;
use std::path::PathBuf;

use rmcp::ServiceExt;

use backend::Backend;
use server::Server;

/// The argument that runs SrcWranglr as an MCP server.
pub const MCP_ARG: &str = "--mcp";
const USAGE: &str = "usage: srcwranglr --mcp [PROJECT_DIR]";

/// Serves the folder named in `args` until the client hangs up; returns
/// the exit code. Only the protocol goes to stdout; problems go to stderr.
pub fn mcp_main(args: impl Iterator<Item = OsString>) -> i32 {
    let root = match project_folder(args) {
        Ok(root) => root,
        Err(message) => {
            eprintln!("srcwranglr --mcp: {message}");
            return 2;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("srcwranglr --mcp: couldn't start: {error}");
            return 1;
        }
    };
    let backend = std::sync::Arc::new(Backend::for_folder(root));
    let served = runtime.block_on(async {
        let service = Server::new(backend)
            .serve(rmcp::transport::stdio())
            .await
            .map_err(|e| e.to_string())?;
        service.waiting().await.map_err(|e| e.to_string())
    });
    match served {
        Ok(_) => 0,
        Err(error) => {
            eprintln!("srcwranglr --mcp: {error}");
            1
        }
    }
}

/// The one folder `args` name, if they name one, made absolute and
/// checked; with none, the client's (or the current one) is used later.
fn project_folder(mut args: impl Iterator<Item = OsString>) -> Result<Option<PathBuf>, String> {
    let Some(folder) = args.next().map(PathBuf::from) else {
        return Ok(None);
    };
    if args.next().is_some() {
        return Err(USAGE.into());
    }
    folder::checked(&folder, folder::home().as_deref()).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder_of(args: &[&std::path::Path]) -> Result<Option<PathBuf>, String> {
        project_folder(args.iter().map(|a| a.as_os_str().to_owned()))
    }

    #[test]
    fn the_folder_is_made_absolute_and_must_be_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical = std::fs::canonicalize(dir.path()).expect("canonical");
        assert_eq!(folder_of(&[dir.path()]), Ok(Some(canonical)));
        let file = dir.path().join("a.c");
        std::fs::write(&file, "int x;\n").expect("write");
        let error = folder_of(&[&file]).expect_err("a file");
        assert!(error.contains("is not a folder"), "{error}");
        assert!(folder_of(&[&dir.path().join("nope")]).is_err());
    }

    #[test]
    fn without_a_folder_one_is_found_later() {
        assert_eq!(folder_of(&[]), Ok(None));
    }

    #[test]
    fn only_one_folder_is_taken() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = folder_of(&[dir.path(), dir.path()]).expect_err("two");
        assert!(error.contains("usage"), "{error}");
    }
}
