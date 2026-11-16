//! Running a command for the in-app agent, inside the project folder. This
//! executes code from the audited tree (a build runs its scripts, a fuzzer
//! runs the target), which SrcWranglr otherwise never does, so every call
//! goes through the user's approval first (see the agent runner). Output is
//! capped and the command is killed if it runs past its time limit.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Combined stdout and stderr kept, in bytes.
pub const MAX_OUTPUT: usize = 60 * 1024;
/// A command is killed after this long by default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RunCommandArgs {
    /// The shell command, run with `sh -c` in the project's folder. Add
    /// your own time and size limits (a fuzzer must run for a fixed
    /// duration, not forever).
    pub command: String,
    /// Seconds to allow before it's killed (default 600, at most 3600).
    pub timeout_seconds: Option<u32>,
}

/// Runs `command` with `sh -c` in `root`, capped at `max_output` bytes of
/// output and killed after `timeout`. It is also killed as soon as `cancel`
/// is set, so stopping the agent ends a running build or fuzzer within a
/// tick rather than at its timeout. A non-zero exit is reported in the
/// output, not as an error; only a command that can't start is an error.
pub fn run_command(
    root: &Path,
    command: &str,
    timeout: Duration,
    max_output: usize,
    cancel: &AtomicBool,
) -> Result<String, String> {
    let command = command.trim();
    if command.is_empty() {
        return Err("No command to run.".into());
    }
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("couldn't start the command: {e}"))?;
    let cap = max_output / 2;
    let stdout = capped_reader(child.stdout.take(), cap);
    let stderr = capped_reader(child.stderr.take(), cap);
    let deadline = Instant::now() + timeout;
    let mut stopped = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if cancel.load(Ordering::Relaxed) => {
                stopped = true;
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(format!("the command failed: {e}")),
        }
    };
    let out = stdout.join().unwrap_or_default();
    let err = stderr.join().unwrap_or_default();
    let line = match status {
        Some(s) if s.success() => "exit 0".to_string(),
        Some(s) => match s.code() {
            Some(code) => format!("exit {code}"),
            None => "killed by a signal".to_string(),
        },
        None if stopped => "stopped by the user".to_string(),
        None => format!("killed after {}s (timed out)", timeout.as_secs()),
    };
    let mut text = format!("$ {command}\n({line})");
    if !out.is_empty() {
        text.push_str(&format!("\n--- stdout\n{out}"));
    }
    if !err.is_empty() {
        text.push_str(&format!("\n--- stderr\n{err}"));
    }
    Ok(text)
}

/// Reads a child stream fully, keeping at most `cap` bytes, on its own
/// thread (so a full pipe never blocks the command).
fn capped_reader<R: Read + Send + 'static>(
    stream: Option<R>,
    cap: usize,
) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let Some(stream) = stream else {
            return String::new();
        };
        let mut buf = Vec::new();
        let _ = stream.take(cap as u64 + 1).read_to_end(&mut buf);
        let truncated = buf.len() > cap;
        buf.truncate(cap);
        let mut text = String::from_utf8_lossy(&buf).into_owned();
        if truncated {
            text.push_str("\n…(output truncated)");
        }
        text
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cancel flag that is never set, for the ordinary cases.
    fn never() -> AtomicBool {
        AtomicBool::new(false)
    }

    #[test]
    fn a_command_runs_in_the_folder_and_its_output_comes_back() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("marker.txt"), "x").expect("write");
        let out = run_command(
            dir.path(),
            "echo hi; ls",
            DEFAULT_TIMEOUT,
            MAX_OUTPUT,
            &never(),
        )
        .expect("ran");
        assert!(out.contains("exit 0"), "{out}");
        assert!(out.contains("hi"), "{out}");
        assert!(out.contains("marker.txt"), "ran in the folder: {out}");
    }

    #[test]
    fn a_nonzero_exit_is_output_not_an_error() {
        let dir = tempfile::tempdir().expect("dir");
        let out = run_command(
            dir.path(),
            "echo oops >&2; exit 3",
            DEFAULT_TIMEOUT,
            MAX_OUTPUT,
            &never(),
        )
        .expect("ran");
        assert!(out.contains("exit 3"), "{out}");
        assert!(out.contains("oops"), "stderr captured: {out}");
    }

    #[test]
    fn a_long_command_is_killed_at_the_timeout() {
        let dir = tempfile::tempdir().expect("dir");
        let out = run_command(
            dir.path(),
            "sleep 10",
            Duration::from_millis(300),
            MAX_OUTPUT,
            &never(),
        )
        .expect("ran");
        assert!(out.contains("timed out"), "{out}");
    }

    #[test]
    fn a_cancelled_command_is_killed_at_once() {
        let dir = tempfile::tempdir().expect("dir");
        // Already cancelled: a long command is killed on the first poll,
        // well before its generous timeout.
        let start = Instant::now();
        let out = run_command(
            dir.path(),
            "sleep 30",
            DEFAULT_TIMEOUT,
            MAX_OUTPUT,
            &AtomicBool::new(true),
        )
        .expect("ran");
        assert!(out.contains("stopped by the user"), "{out}");
        assert!(start.elapsed() < Duration::from_secs(5), "killed promptly");
    }

    #[test]
    fn output_is_capped() {
        let dir = tempfile::tempdir().expect("dir");
        let out = run_command(
            dir.path(),
            "yes abcdefgh | head -c 200000",
            DEFAULT_TIMEOUT,
            4096,
            &never(),
        )
        .expect("ran");
        assert!(out.contains("truncated"), "{}", &out[..out.len().min(200)]);
        assert!(out.len() < 8192, "capped to about 4k: {}", out.len());
    }
}
