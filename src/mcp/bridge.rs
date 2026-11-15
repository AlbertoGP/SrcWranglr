//! How `srcwranglr --mcp` reaches a running SrcWranglr that has the same
//! project open, so the agent shares the app's index and you see what it
//! does: a Unix socket per project, in a folder only you can open (no
//! network port). One call per connection: the app says which project it
//! serves, the client sends a tool and its arguments, the app answers.

use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The folder in your config folder that holds the sockets.
const SOCKET_DIR: &str = "agents";
/// macOS allows socket paths of 104 bytes, with the terminating NUL.
const MAX_SOCKET_PATH: usize = 103;
const MAX_HELLO_BYTES: usize = 64 * 1024;
/// A tool call's arguments are small; a note is at most 64 KiB.
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
/// Answers are capped by the tools; this is a backstop.
const MAX_ANSWER_BYTES: usize = 16 * 1024 * 1024;
/// A tool may walk a kernel's call graph.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a write may block.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// How much the app takes on from callers.
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Calls answered at once; a caller past this is told to try again.
    max_calls: usize,
    /// A caller must send its whole request within this, or is let go.
    request_deadline: Duration,
}

const LIMITS: Limits = Limits {
    max_calls: 32,
    request_deadline: Duration::from_secs(30),
};
const BUSY: &str = "SrcWranglr is answering too many calls at once; try again.";
const ALREADY_SERVED: &str = "another SrcWranglr window already serves this project to agents";
/// How often the app's listener checks whether to stop.
const ACCEPT_POLL: Duration = Duration::from_millis(50);

/// Answers a tool call: the tool's name and its arguments.
pub type Answerer = dyn Fn(&str, Value) -> Result<String, String> + Send + Sync;

#[derive(Serialize, Deserialize)]
struct Hello {
    srcwranglr: String,
    project: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Request {
    tool: String,
    args: Value,
}

#[derive(Serialize, Deserialize)]
struct Answer {
    ok: bool,
    text: String,
}

/// `<your config folder>/agents`.
pub fn socket_dir() -> Option<PathBuf> {
    crate::app::dangerous_lists::config_dir().map(|dir| dir.join(SOCKET_DIR))
}

/// The socket for the project at `root` (absolute) in `dir`.
pub fn socket_path(dir: &Path, root: &Path) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    dir.join(format!("{:016x}.sock", fnv1a(root.as_os_str().as_bytes())))
}

/// FNV-1a: stable across builds, unlike the standard library's hasher, so
/// the app and an `--mcp` from another build agree on the name.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Whether an app serves `root` from `dir` now.
pub fn is_served(dir: &Path, root: &Path) -> bool {
    hello_from(dir, root).is_some()
}

/// A connection to the app serving `root` from `dir`, past its hello.
fn hello_from(dir: &Path, root: &Path) -> Option<(UnixStream, BufReader<UnixStream>)> {
    // A socket in a folder others can write may be anyone's.
    if !std::fs::symlink_metadata(dir).is_ok_and(|m| is_private(&m)) {
        return None;
    }
    let stream = UnixStream::connect(socket_path(dir, root)).ok()?;
    stream.set_read_timeout(Some(ANSWER_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT)).ok()?;
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let hello: Hello = read_json(&mut reader, MAX_HELLO_BYTES).ok()??;
    (hello.project == root).then_some((stream, reader))
}

/// The answer of the app serving `root` from `dir`, if one is; `None`
/// when none does (the caller answers itself).
pub fn call(dir: &Path, root: &Path, tool: &str, args: &Value) -> Option<Result<String, String>> {
    let (stream, mut reader) = hello_from(dir, root)?;
    let request = Request {
        tool: tool.to_string(),
        args: args.clone(),
    };
    let lost = |error: String| {
        Err(format!(
            "SrcWranglr stopped answering ({error}); try again."
        ))
    };
    // An app too busy to take the call answers before reading it, then
    // closes: its answer is still there to read.
    let sent = write_json(&stream, &request);
    Some(
        match (read_json::<Answer>(&mut reader, MAX_ANSWER_BYTES), sent) {
            (Ok(Some(Answer { ok: true, text })), _) => Ok(text),
            (Ok(Some(Answer { ok: false, text })), _) => Err(text),
            (_, Err(error)) => lost(error),
            (Ok(None), Ok(())) => lost("it closed the connection".into()),
            (Err(error), Ok(())) => lost(error),
        },
    )
}

/// The app's side: serves the project at `root` until dropped.
pub struct Host {
    stop: Arc<AtomicBool>,
    path: PathBuf,
    thread: Option<JoinHandle<()>>,
    /// Held while serving, so a second window can't take the socket over.
    _lock: File,
}

impl Host {
    /// Serves `root` from `dir`, each call answered by `answer` on a
    /// thread of its own.
    pub fn start(dir: &Path, root: &Path, answer: Arc<Answerer>) -> Result<Self, String> {
        Self::start_limited(dir, root, answer, LIMITS)
    }

    fn start_limited(
        dir: &Path,
        root: &Path,
        answer: Arc<Answerer>,
        limits: Limits,
    ) -> Result<Self, String> {
        private_dir(dir)?;
        let path = socket_path(dir, root);
        if path.as_os_str().len() > MAX_SOCKET_PATH {
            return Err(format!(
                "{} is too long a path for a socket",
                path.display()
            ));
        }
        let lock = lock_for(&path)?;
        if UnixStream::connect(&path).is_ok() {
            return Err(ALREADY_SERVED.into());
        }
        // A socket left by an app that quit is replaced.
        match std::fs::symlink_metadata(&path) {
            Ok(_) => std::fs::remove_file(&path).map_err(|e| e.to_string())?,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
        let listener = UnixListener::bind(&path).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (stop, root) = (Arc::clone(&stop), root.to_path_buf());
            std::thread::Builder::new()
                .name("agent-bridge".into())
                .spawn(move || accept(&listener, &stop, (&root, limits), &answer))
                .map_err(|e| e.to_string())?
        };
        Ok(Self {
            stop,
            path,
            thread: Some(thread),
            _lock: lock,
        })
    }

    #[cfg(test)]
    pub fn socket(&self) -> &Path {
        &self.path
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The lock beside `socket`, taken: whoever holds it serves the project.
fn lock_for(socket: &Path) -> Result<File, String> {
    let path = socket.with_extension("lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    // SAFETY: the descriptor stays open as long as `file`, which owns it.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    match locked {
        0 => Ok(file),
        _ => Err(ALREADY_SERVED.into()),
    }
}

/// Counts a call while it's answered.
struct InFlight(Arc<AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn accept(
    listener: &UnixListener,
    stop: &AtomicBool,
    (root, limits): (&Path, Limits),
    answer: &Arc<Answerer>,
) {
    let in_flight = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) if in_flight.load(Ordering::Relaxed) >= limits.max_calls => {
                turn_away(&stream, root);
            }
            Ok((stream, _)) => {
                in_flight.fetch_add(1, Ordering::Relaxed);
                let counted = InFlight(Arc::clone(&in_flight));
                let (root, answer) = (root.to_path_buf(), Arc::clone(answer));
                let spawned =
                    std::thread::Builder::new()
                        .name("agent-call".into())
                        .spawn(move || {
                            let _counted = counted;
                            serve(stream, &root, limits.request_deadline, &answer);
                        });
                if let Err(error) = spawned {
                    eprintln!("SrcWranglr: couldn't answer an agent: {error}");
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(ACCEPT_POLL),
            Err(error) => {
                eprintln!("SrcWranglr: agent socket: {error}");
                std::thread::sleep(ACCEPT_POLL);
            }
        }
    }
}

/// Tells a caller past the most calls at once to try again, without
/// waiting for what it asks.
fn turn_away(stream: &UnixStream, root: &Path) {
    let told = stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(1))))
        .map_err(|e| e.to_string())
        .and_then(|()| write_json(stream, &hello(root)))
        .and_then(|()| {
            let answer = Answer {
                ok: false,
                text: BUSY.into(),
            };
            write_json(stream, &answer)
        });
    if let Err(error) = told {
        eprintln!("SrcWranglr: couldn't turn an agent's call away: {error}");
    }
}

fn hello(root: &Path) -> Hello {
    Hello {
        srcwranglr: env!("CARGO_PKG_VERSION").into(),
        project: root.to_path_buf(),
    }
}

/// Reads a stream until a deadline, however slowly the other side sends.
struct Deadline {
    stream: UnixStream,
    until: Instant,
}

impl Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "the request took too long",
            ));
        }
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read(buf)
    }
}

/// One call: hello, request, answer.
fn serve(stream: UnixStream, root: &Path, deadline: Duration, answer: &Arc<Answerer>) {
    let served = (|| -> Result<(), String> {
        stream.set_nonblocking(false).map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(WRITE_TIMEOUT))
            .map_err(|e| e.to_string())?;
        write_json(&stream, &hello(root))?;
        let mut reader = BufReader::new(Deadline {
            stream: stream.try_clone().map_err(|e| e.to_string())?,
            until: Instant::now() + deadline,
        });
        // A client checking that the app serves the project asks nothing.
        let Some(request) = read_json::<Request>(&mut reader, MAX_REQUEST_BYTES)? else {
            return Ok(());
        };
        let (ok, text) = match answer(&request.tool, request.args) {
            Ok(text) => (true, text),
            Err(text) => (false, text),
        };
        write_json(&stream, &Answer { ok, text })
    })();
    if let Err(error) = served {
        eprintln!("SrcWranglr: an agent's call failed: {error}");
    }
}

/// Makes `dir` if needed; refuses one that isn't yours alone.
fn private_dir(dir: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == ErrorKind::NotFound => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("{}: {e}", dir.display())),
        Err(e) => Err(format!("{}: {e}", dir.display())),
        Ok(metadata) if is_private(&metadata) => Ok(()),
        Ok(_) => Err(format!(
            "{} must be a folder only you can open (chmod 700)",
            dir.display()
        )),
    }
}

/// Whether `metadata` (not followed through a symlink) is of a folder
/// that's yours and only yours.
fn is_private(metadata: &std::fs::Metadata) -> bool {
    // SAFETY: geteuid has no preconditions and can't fail.
    let me = unsafe { libc::geteuid() };
    metadata.file_type().is_dir() && metadata.uid() == me && metadata.mode() & 0o077 == 0
}

fn write_json(mut stream: &UnixStream, value: &impl Serialize) -> Result<(), String> {
    let mut line = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    line.push(b'\n');
    stream.write_all(&line).map_err(|e| e.to_string())
}

/// One line of JSON, refusing longer than `max` bytes; `None` if the
/// other side closed before sending any.
fn read_json<T: serde::de::DeserializeOwned>(
    reader: &mut impl BufRead,
    max: usize,
) -> Result<Option<T>, String> {
    let mut line = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    reader
        .by_ref()
        .take(limit)
        .read_until(b'\n', &mut line)
        .map_err(|e| e.to_string())?;
    if line.is_empty() {
        return Ok(None);
    }
    if line.len() > max {
        return Err(format!("a message longer than {max} bytes"));
    }
    if line.last() != Some(&b'\n') {
        return Err("the connection closed early".into());
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
#[path = "bridge_tests.rs"]
mod tests;
