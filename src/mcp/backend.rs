//! Where `--mcp` gets its answers: the running app, when it has the
//! project open (one index, and you see what the agent does in its Agent
//! pane), else an index of its own, made the first time it's needed. The
//! folder is settled once: from the command line, the client's roots, or
//! the folder it was started in (see `folder`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use super::dispatch::dispatch;
use super::state::{State, Status};

/// How long a tool waits for an index of its own before saying how far
/// along it is: under the 5 seconds opencode waits for an answer by
/// default.
pub const WAIT_FOR_INDEX: Duration = Duration::from_secs(4);

pub struct Backend {
    /// The folder served, once settled, or why there is none.
    root: OnceLock<Result<PathBuf, String>>,
    /// The folder of the app's sockets; `None` to never ask the app.
    sockets: Option<PathBuf>,
    /// The index of its own, once started.
    local: Mutex<Option<Arc<State>>>,
    wait: Duration,
    /// Whether the app answered the last call, to explain its going away.
    was_served: AtomicBool,
}

impl Backend {
    /// Answers about `root` (absolute), if given now, else the folder
    /// settled later: from the app if it serves it, else from an index of
    /// its own, started as soon as the folder is known.
    pub fn for_folder(root: Option<PathBuf>) -> Self {
        #[cfg(unix)]
        let sockets = super::bridge::socket_dir();
        #[cfg(not(unix))]
        let sockets = None;
        let backend = Self {
            root: OnceLock::new(),
            sockets,
            local: Mutex::new(None),
            wait: WAIT_FOR_INDEX,
            was_served: AtomicBool::new(false),
        };
        if let Some(root) = root {
            backend.settle(Ok(root));
        }
        backend
    }

    /// Whether the folder is known (or known to be missing).
    pub fn is_settled(&self) -> bool {
        self.root.get().is_some()
    }

    /// Serves `folder` from now on (unless one already is), starting an
    /// index of its own if the app doesn't serve it.
    pub fn settle(&self, folder: Result<PathBuf, String>) {
        if self.root.set(folder).is_ok() && self.root().is_ok() && !self.is_app_serving() {
            self.local();
        }
    }

    /// Waits up to `wait` for the folder to be settled, then settles it as
    /// the folder it was started in if it still isn't.
    pub fn settle_within(&self, wait: Duration) {
        let deadline = Instant::now() + wait;
        while !self.is_settled() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if !self.is_settled() {
            self.settle(super::folder::started_in());
        }
    }

    fn root(&self) -> Result<&PathBuf, String> {
        match self.root.get() {
            Some(Ok(root)) => Ok(root),
            Some(Err(why)) => Err(why.clone()),
            None => Err("SrcWranglr doesn't know the project's folder yet".into()),
        }
    }

    /// Answers from an index of its own of the folder settled later,
    /// never asking the app.
    #[cfg(test)]
    pub fn unsettled() -> Self {
        Self {
            root: OnceLock::new(),
            sockets: None,
            local: Mutex::new(None),
            wait: Duration::from_secs(30),
            was_served: AtomicBool::new(false),
        }
    }

    /// Answers from `state` only, waiting `wait` for it.
    #[cfg(test)]
    pub fn with_state(state: Arc<State>, wait: Duration) -> Self {
        Self {
            root: OnceLock::from(Ok(PathBuf::new())),
            sockets: None,
            local: Mutex::new(Some(state)),
            wait,
            was_served: AtomicBool::new(false),
        }
    }

    /// The answer of `tool` called with `args`.
    pub fn call(&self, tool: &str, args: Value) -> Result<String, String> {
        self.settle_within(Duration::ZERO);
        self.root()
            .map_err(|why| format!("SrcWranglr can't serve this project: {why}."))?;
        if let Some(answer) = self.ask_app(tool, &args) {
            self.was_served.store(true, Ordering::Relaxed);
            return answer;
        }
        let had_app = self.was_served.swap(false, Ordering::Relaxed);
        match self.local().workspace(self.wait) {
            Ok(workspace) => dispatch(&workspace, tool, args, now()),
            Err(why) if had_app => Err(format!(
                "The SrcWranglr app closed, so SrcWranglr is indexing the project itself. {why}"
            )),
            Err(why) => Err(why),
        }
    }

    #[cfg(unix)]
    fn ask_app(&self, tool: &str, args: &Value) -> Option<Result<String, String>> {
        let (sockets, root) = (self.sockets.as_deref()?, self.root().ok()?);
        super::bridge::call(sockets, root, tool, args)
    }

    #[cfg(not(unix))]
    fn ask_app(&self, _tool: &str, _args: &Value) -> Option<Result<String, String>> {
        None
    }

    fn is_app_serving(&self) -> bool {
        #[cfg(unix)]
        if let (Some(sockets), Ok(root)) = (self.sockets.as_deref(), self.root()) {
            return super::bridge::is_served(sockets, root);
        }
        false
    }

    /// The index of its own, started if it wasn't.
    fn local(&self) -> Arc<State> {
        let mut local = self.local.lock().unwrap_or_else(PoisonError::into_inner);
        let state = local.get_or_insert_with(|| match self.root() {
            Ok(root) => State::start_indexing(root.clone()),
            Err(why) => Arc::new(State::new(Status::Failed(why))),
        });
        Arc::clone(state)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(all(test, unix))]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::mcp::bridge::Host;

    #[test]
    fn the_app_answers_first_and_an_index_of_its_own_takes_over_when_it_closes() {
        let project = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            project.path().join("a.c"),
            "int helper(void) { return 1; }\n",
        )
        .expect("write");
        let root = std::fs::canonicalize(project.path()).expect("canonical");
        let short = tempfile::Builder::new()
            .prefix("swb")
            .tempdir_in("/tmp")
            .expect("tempdir");
        let sockets = short.path().join("agents");
        let host = Host::start(
            &sockets,
            &root,
            Arc::new(|tool: &str, _args: Value| Ok(format!("the app answers {tool}"))),
        )
        .expect("host");
        let backend = Backend {
            root: OnceLock::from(Ok(root)),
            sockets: Some(sockets),
            local: Mutex::new(None),
            wait: Duration::from_secs(30),
            was_served: AtomicBool::new(false),
        };
        assert!(backend.is_app_serving());
        let answer = backend.call("overview", json!({}));
        assert_eq!(answer, Ok("the app answers overview".into()));
        assert!(
            backend.local.lock().expect("lock").is_none(),
            "no index of its own yet"
        );
        drop(host);
        let answer = backend
            .call("find_symbol", json!({"query": "helper"}))
            .expect("local");
        assert!(answer.contains("helper  a.c:1"), "{answer}");
    }
}
