//! Where the index is at. The server answers at once while the project is
//! indexed in the background (the Linux kernel takes about two minutes);
//! a tool called meanwhile waits a while for it, then says how far along
//! it is rather than leaving the agent hanging.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::workspace::Workspace;
use crate::index::{index_project, IndexOptions, Progress};

pub enum Status {
    Indexing(Progress),
    /// The app arranging its index for agents.
    Preparing,
    Ready(Arc<Workspace>),
    Failed(String),
}

pub struct State {
    status: Mutex<Status>,
    /// Signalled when indexing ends, well or not.
    finished: Condvar,
}

impl State {
    pub fn new(status: Status) -> Self {
        Self {
            status: Mutex::new(status),
            finished: Condvar::new(),
        }
    }

    /// Indexes `root` on a thread of its own; the state says how it goes.
    pub fn start_indexing(root: PathBuf) -> Arc<Self> {
        let state = Arc::new(Self::new(Status::Indexing(Progress::default())));
        let shared = Arc::clone(&state);
        let spawned = std::thread::Builder::new()
            .name("mcp-index".into())
            .spawn(move || {
                let indexed = catch_unwind(AssertUnwindSafe(|| index(&root, &shared)));
                shared.finish(indexed.unwrap_or_else(|_| {
                    Status::Failed("indexing failed unexpectedly (it crashed)".into())
                }));
            });
        if let Err(error) = spawned {
            state.finish(Status::Failed(format!("indexing couldn't start: {error}")));
        }
        state
    }

    /// The app's index arranged for agents by `build`, on a thread of its
    /// own.
    pub fn preparing(build: impl FnOnce() -> Workspace + Send + 'static) -> Arc<Self> {
        let state = Arc::new(Self::new(Status::Preparing));
        let shared = Arc::clone(&state);
        let spawned = std::thread::Builder::new()
            .name("agent-workspace".into())
            .spawn(move || {
                let built = catch_unwind(AssertUnwindSafe(build));
                shared.finish(built.map_or_else(
                    |_| Status::Failed("getting ready for agents failed (it crashed)".into()),
                    |workspace| Status::Ready(Arc::new(workspace)),
                ));
            });
        if let Err(error) = spawned {
            state.finish(Status::Failed(format!(
                "getting ready couldn't start: {error}"
            )));
        }
        state
    }

    /// The workspace once indexed, waiting up to `timeout` for it; else
    /// what to tell the agent.
    pub fn workspace(&self, timeout: Duration) -> Result<Arc<Workspace>, String> {
        let deadline = Instant::now() + timeout;
        let mut status = self.lock();
        loop {
            match &*status {
                Status::Ready(workspace) => return Ok(Arc::clone(workspace)),
                Status::Failed(why) => {
                    return Err(format!("SrcWranglr couldn't index the project: {why}."))
                }
                Status::Indexing(_) | Status::Preparing => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(match &*status {
                            Status::Indexing(progress) => still_indexing(*progress),
                            _ => "SrcWranglr is getting the project ready for agents; call again in a moment.".into(),
                        });
                    }
                    status = self
                        .finished
                        .wait_timeout(status, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            }
        }
    }

    fn set_progress(&self, progress: Progress) {
        let mut status = self.lock();
        if let Status::Indexing(shown) = &mut *status {
            *shown = progress;
        }
    }

    pub fn finish(&self, status: Status) {
        *self.lock() = status;
        self.finished.notify_all();
    }

    fn lock(&self) -> MutexGuard<'_, Status> {
        self.status.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn index(root: &Path, state: &State) -> Status {
    let cancel = AtomicBool::new(false);
    let mut on_progress = |progress| state.set_progress(progress);
    match index_project(root, IndexOptions::default(), &mut on_progress, &cancel) {
        Ok(outcome) => {
            let name = root.file_name().map_or_else(
                || root.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            let workspace = Workspace::new(&name, Some(root.to_path_buf()), outcome.graph)
                .with_index_warnings(&outcome.warnings);
            Status::Ready(Arc::new(workspace))
        }
        Err(error) => Status::Failed(error.to_string()),
    }
}

fn still_indexing(progress: Progress) -> String {
    let done = match progress.total {
        0 => "finding the project's files".to_string(),
        total => format!("{} of {total} files read", progress.done),
    };
    format!(
        "SrcWranglr is still indexing the project ({done}). A tree the size of the Linux kernel takes about two minutes; call again in a little while."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::fixture::workspace;

    #[test]
    fn while_indexing_a_tool_is_told_how_far_along_it_is() {
        let state = State::new(Status::Indexing(Progress {
            done: 30,
            total: 120,
        }));
        let Err(said) = state.workspace(Duration::from_millis(10)) else {
            panic!("not indexed yet");
        };
        assert!(said.contains("30 of 120 files read"), "{said}");
    }

    #[test]
    fn a_waiting_tool_gets_the_workspace_once_indexing_ends() {
        let state = Arc::new(State::new(Status::Indexing(Progress::default())));
        let shared = Arc::clone(&state);
        let finisher = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            shared.finish(Status::Ready(Arc::new(workspace())));
        });
        assert!(state.workspace(Duration::from_secs(10)).is_ok());
        finisher.join().expect("join");
    }

    #[test]
    fn a_failed_index_says_why() {
        let state = State::new(Status::Failed("No C/C++ source files found".into()));
        let Err(said) = state.workspace(Duration::ZERO) else {
            panic!("failed");
        };
        assert!(said.contains("No C/C++ source files found"), "{said}");
    }

    #[test]
    fn a_folder_is_indexed_in_the_background() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a.c"), "int main(void) { return 0; }\n").expect("write");
        let state = State::start_indexing(dir.path().to_path_buf());
        let workspace = state.workspace(Duration::from_secs(30)).expect("indexed");
        assert_eq!(workspace.graph().file_contents.len(), 1);
    }
}
