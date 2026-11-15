use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;

use serde_json::json;

use super::*;

/// A folder short enough for socket paths (macOS allows 104 bytes),
/// and the private one in it for the sockets, which the host makes.
fn short_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("swb")
        .tempdir_in("/tmp")
        .expect("tempdir");
    let sockets = dir.path().join("agents");
    (dir, sockets)
}

fn echo() -> Arc<Answerer> {
    Arc::new(|tool: &str, args: Value| match tool {
        "refuse" => Err("not that".into()),
        _ => Ok(format!("{tool} {args}")),
    })
}

const ROOT: &str = "/projects/linux";

#[test]
fn a_call_is_answered_by_the_app_serving_the_project() {
    let (_dir, sockets) = short_dir();
    let host = Host::start(&sockets, Path::new(ROOT), echo()).expect("host");
    let answer = call(
        &sockets,
        Path::new(ROOT),
        "xrefs",
        &json!({"name": "system"}),
    );
    assert_eq!(answer, Some(Ok("xrefs {\"name\":\"system\"}".into())));
    let refused = call(&sockets, Path::new(ROOT), "refuse", &json!({}));
    assert_eq!(refused, Some(Err("not that".into())));
    let mode = |p: &Path| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode(&sockets), 0o700);
    assert_eq!(mode(host.socket()), 0o600);
    let socket = host.socket().to_path_buf();
    drop(host);
    assert!(!socket.exists());
    assert_eq!(call(&sockets, Path::new(ROOT), "xrefs", &json!({})), None);
}

#[test]
fn a_client_can_check_that_an_app_serves_the_project() {
    let (_dir, sockets) = short_dir();
    assert!(!is_served(&sockets, Path::new(ROOT)));
    let _host = Host::start(&sockets, Path::new(ROOT), echo()).expect("host");
    assert!(is_served(&sockets, Path::new(ROOT)));
    assert!(!is_served(&sockets, Path::new("/projects/other")));
}

#[test]
fn without_an_app_no_one_answers() {
    let (_dir, sockets) = short_dir();
    assert_eq!(
        call(&sockets, Path::new(ROOT), "overview", &json!({})),
        None
    );
}

#[test]
fn a_second_window_on_the_same_project_doesnt_take_over() {
    let (_dir, sockets) = short_dir();
    let _first = Host::start(&sockets, Path::new(ROOT), echo()).expect("first");
    let error = Host::start(&sockets, Path::new(ROOT), echo())
        .err()
        .expect("second refused");
    assert!(error.contains("already serves"), "{error}");
}

#[test]
fn a_socket_left_by_an_app_that_quit_is_replaced() {
    let (_dir, sockets) = short_dir();
    private_dir(&sockets).expect("folder");
    let path = socket_path(&sockets, Path::new(ROOT));
    drop(UnixListener::bind(&path).expect("bind"));
    assert!(path.exists(), "a listener leaves its file behind");
    let _host = Host::start(&sockets, Path::new(ROOT), echo()).expect("replaced");
    assert!(call(&sockets, Path::new(ROOT), "overview", &json!({})).is_some());
}

#[test]
fn a_folder_others_can_open_is_refused() {
    let (_dir, sockets) = short_dir();
    std::fs::create_dir(&sockets).expect("folder");
    std::fs::set_permissions(&sockets, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let error = Host::start(&sockets, Path::new(ROOT), echo())
        .err()
        .expect("refused");
    assert!(error.contains("only you"), "{error}");
}

#[test]
fn an_app_serving_another_project_isnt_asked() {
    let (_dir, sockets) = short_dir();
    let host = Host::start(&sockets, Path::new(ROOT), echo()).expect("host");
    let other = Path::new("/projects/other");
    std::fs::rename(host.socket(), socket_path(&sockets, other)).expect("rename");
    assert_eq!(call(&sockets, other, "overview", &json!({})), None);
}

#[test]
fn an_oversized_request_is_dropped_and_the_app_keeps_serving() {
    let (_dir, sockets) = short_dir();
    let host = Host::start(&sockets, Path::new(ROOT), echo()).expect("host");
    let mut stream = UnixStream::connect(host.socket()).expect("connect");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut hello = String::new();
    reader.read_line(&mut hello).expect("hello");
    assert!(hello.contains(ROOT), "{hello}");
    let huge = vec![b'x'; MAX_REQUEST_BYTES + 10];
    let _ = stream.write_all(&huge);
    let mut answer = String::new();
    let _ = reader.read_line(&mut answer);
    assert!(answer.is_empty(), "{answer}");
    assert!(call(&sockets, Path::new(ROOT), "overview", &json!({})).is_some());
}

#[test]
fn socket_names_are_stable_and_per_project() {
    let a = socket_path(Path::new("/s"), Path::new("/projects/linux"));
    assert_eq!(
        a,
        socket_path(Path::new("/s"), Path::new("/projects/linux"))
    );
    assert_ne!(
        a,
        socket_path(Path::new("/s"), Path::new("/projects/linux2"))
    );
    assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
}

#[test]
fn a_socket_in_a_folder_others_can_open_isnt_trusted() {
    let (_dir, sockets) = short_dir();
    std::fs::create_dir(&sockets).expect("folder");
    std::fs::set_permissions(&sockets, std::fs::Permissions::from_mode(0o777)).expect("chmod");
    // A squatter's socket, answering anything.
    let squatter = UnixListener::bind(socket_path(&sockets, Path::new(ROOT))).expect("bind");
    let _keep = squatter;
    assert!(!is_served(&sockets, Path::new(ROOT)));
    assert_eq!(
        call(&sockets, Path::new(ROOT), "overview", &json!({})),
        None
    );
}

#[test]
fn a_client_that_says_nothing_is_let_go() {
    let (_dir, sockets) = short_dir();
    let limits = Limits {
        request_deadline: Duration::from_millis(200),
        ..LIMITS
    };
    let host = Host::start_limited(&sockets, Path::new(ROOT), echo(), limits).expect("host");
    let stream = UnixStream::connect(host.socket()).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut reader = BufReader::new(stream);
    let mut hello = String::new();
    reader.read_line(&mut hello).expect("hello");
    let mut rest = String::new();
    // The app closes it once the deadline passes.
    assert_eq!(reader.read_line(&mut rest).expect("closed"), 0);
}

#[test]
fn past_the_most_calls_at_once_a_caller_is_told_to_try_again() {
    let (_dir, sockets) = short_dir();
    let limits = Limits {
        max_calls: 2,
        ..LIMITS
    };
    let host = Host::start_limited(&sockets, Path::new(ROOT), echo(), limits).expect("host");
    let idle: Vec<UnixStream> = (0..limits.max_calls)
        .map(|_| {
            let stream = UnixStream::connect(host.socket()).expect("connect");
            let mut hello = String::new();
            BufReader::new(stream.try_clone().expect("clone"))
                .read_line(&mut hello)
                .expect("hello");
            stream
        })
        .collect();
    let answer = call(&sockets, Path::new(ROOT), "overview", &json!({}));
    assert!(
        matches!(&answer, Some(Err(said)) if said.contains("too many")),
        "{answer:?}"
    );
    drop(idle);
}
