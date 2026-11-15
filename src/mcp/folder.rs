//! Which folder `--mcp` serves: the one named on its command line, else
//! the workspace the agent's client says it has open (MCP roots), else the
//! folder it was started in; but never your home folder or `/`, which
//! would be indexing everything you have.

use std::path::{Path, PathBuf};

/// The folder a `file://` root names, if it does.
pub fn from_root_uri(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    // `file:///x` and `file://localhost/x` name the same place.
    let path = match rest.strip_prefix("localhost") {
        Some(path) => path,
        None => rest,
    };
    if !path.starts_with('/') {
        return None;
    }
    Some(PathBuf::from(percent_decoded(path)?))
}

/// `text` with `%XX` escapes decoded; `None` if one is malformed or the
/// result isn't UTF-8.
fn percent_decoded(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = text.get(i + 1..i + 3)?;
                decoded.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            byte => {
                decoded.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

/// `folder` made absolute, if it's one SrcWranglr may serve: a folder, and
/// not `home` or `/`.
pub fn checked(folder: &Path, home: Option<&Path>) -> Result<PathBuf, String> {
    let absolute =
        std::fs::canonicalize(folder).map_err(|e| format!("{}: {e}", folder.display()))?;
    if !absolute.is_dir() {
        return Err(format!("{} is not a folder", folder.display()));
    }
    let home = home.and_then(|h| std::fs::canonicalize(h).ok());
    if absolute.parent().is_none()
        || Some(&absolute) == home.as_ref()
        || home.as_ref().is_some_and(|h| h.starts_with(&absolute))
        || is_system_root(&absolute)
    {
        return Err(format!(
            "{} is too big to index as one project: start the agent in the project's folder, or name it after --mcp",
            absolute.display()
        ));
    }
    Ok(absolute)
}

/// Whether `path` is a whole-system or multi-project folder no single
/// assessment should index.
fn is_system_root(path: &Path) -> bool {
    const ROOTS: [&str; 10] = [
        "/Users", "/home", "/Volumes", "/tmp", "/private", "/usr", "/opt", "/etc", "/var", "/mnt",
    ];
    // `path` is canonical, so match a root's canonical form too (macOS
    // resolves /tmp to /private/tmp).
    ROOTS.iter().any(|root| {
        path == Path::new(root) || std::fs::canonicalize(root).ok().as_deref() == Some(path)
    })
}

/// The folder `--mcp` was started in, if it may be served.
pub fn started_in() -> Result<PathBuf, String> {
    let current = std::env::current_dir().map_err(|e| format!("no current folder: {e}"))?;
    checked(&current, home().as_deref())
}

/// Your home folder, as the environment has it.
pub fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_root_names_its_folder() {
        assert_eq!(
            from_root_uri("file:///Users/me/src/linux"),
            Some(PathBuf::from("/Users/me/src/linux"))
        );
        assert_eq!(
            from_root_uri("file:///Users/me/my%20project"),
            Some(PathBuf::from("/Users/me/my project"))
        );
        assert_eq!(
            from_root_uri("file://localhost/srv/x"),
            Some(PathBuf::from("/srv/x"))
        );
        assert_eq!(from_root_uri("https://example.com/x"), None);
        assert_eq!(from_root_uri("file://host/x"), None);
        assert_eq!(from_root_uri("file:///bad%zz"), None);
        assert_eq!(from_root_uri("file:///cut%2"), None);
    }

    #[test]
    fn home_and_the_root_folder_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let project = dir.path().join("project");
        std::fs::create_dir(&project).expect("mkdir");
        let canonical = std::fs::canonicalize(&project).expect("canonical");
        assert_eq!(checked(&project, Some(dir.path())), Ok(canonical));
        let error = checked(dir.path(), Some(dir.path())).expect_err("home");
        assert!(error.contains("too big"), "{error}");
        assert!(checked(Path::new("/"), None).is_err());
        assert!(
            checked(Path::new("/tmp"), None).is_err(),
            "a shared dir is too broad"
        );
        // A folder that contains home is refused too.
        let nested = dir.path().join("a").join("b");
        std::fs::create_dir_all(&nested).expect("mkdir");
        let home = dir.path().join("a");
        assert!(checked(&nested, Some(&home)).is_ok());
        assert!(
            checked(dir.path(), Some(&home)).is_err(),
            "an ancestor of home"
        );
        let file = project.join("a.c");
        std::fs::write(&file, "int x;\n").expect("write");
        assert!(checked(&file, None)
            .expect_err("file")
            .contains("not a folder"));
    }
}
