//! fsx.rs — the host's OWN reads: opening a file beneath a directory by descriptor, never following a symlink, so a
//! link planted under the directory cannot point the host at a file outside it.
//!
//! This closes the resolve-then-open race for what the HOST reads (held output). A child process reopens its arguments
//! by name and is bounded by the OS sandbox instead (SHELL.md, "Resolve, then run").

use std::fs::File;
use std::io;
use std::path::{Component, Path};

use rustix::fs::{Mode, OFlags};

/// Opens `rel` beneath `dir` read-only. `rel` must be relative and made only of normal components (no `..`, no root,
/// no `.`); every component, the last included, must be a real directory or file, never a symlink. `dir` itself is
/// opened by name: it is the caller's own trusted directory.
pub fn open_beneath(dir: &Path, rel: &Path) -> io::Result<File> {
    let parts = normal_components(rel)?;
    #[cfg(target_os = "linux")]
    match open_beneath_openat2(dir, rel) {
        Err(e) if e.raw_os_error() == Some(rustix::io::Errno::NOSYS.raw_os_error()) => {}
        other => return other,
    }
    open_beneath_walk(dir, &parts)
}

fn normal_components(rel: &Path) -> io::Result<Vec<&std::ffi::OsStr>> {
    let mut parts = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(s) => parts.push(s),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "path must be relative, with no . or ..")),
        }
    }
    if parts.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty path"));
    }
    Ok(parts)
}

/// Linux 5.6+: one `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, which the kernel enforces atomically.
#[cfg(target_os = "linux")]
fn open_beneath_openat2(dir: &Path, rel: &Path) -> io::Result<File> {
    use rustix::fs::ResolveFlags;
    let d = rustix::fs::open(dir, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())?;
    let fd = rustix::fs::openat2(
        &d,
        rel,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;
    Ok(File::from(fd))
}

/// Everywhere else (macOS has no `openat2`): one `openat` per component with `O_NOFOLLOW`, each relative to the
/// descriptor of the directory before it, so a component swapped for a symlink mid-walk fails rather than redirects.
fn open_beneath_walk(dir: &Path, parts: &[&std::ffi::OsStr]) -> io::Result<File> {
    let mut cur = rustix::fs::open(dir, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())?;
    let (last, dirs) = parts.split_last().expect("non-empty");
    for p in dirs {
        cur = rustix::fs::openat(
            &cur,
            *p,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
    }
    let fd = rustix::fs::openat(&cur, *last, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())?;
    let f = File::from(fd);
    if !f.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // --- open beneath a directory, never through a symlink ---

    fn read(f: io::Result<File>) -> io::Result<String> {
        let mut s = String::new();
        f?.read_to_string(&mut s)?;
        Ok(s)
    }

    #[test]
    fn opens_a_nested_file() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("a/b")).unwrap();
        std::fs::write(d.path().join("a/b/f"), "hi").unwrap();
        assert_eq!(read(open_beneath(d.path(), Path::new("a/b/f"))).unwrap(), "hi");
        assert_eq!(read(open_beneath_walk(d.path(), &["a".as_ref(), "b".as_ref(), "f".as_ref()])).unwrap(), "hi");
    }

    #[test]
    fn refuses_a_symlinked_file_and_a_symlinked_directory() {
        let d = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("secret"), "no").unwrap();
        std::os::unix::fs::symlink(out.path().join("secret"), d.path().join("link")).unwrap();
        std::os::unix::fs::symlink(out.path(), d.path().join("dirlink")).unwrap();
        assert!(open_beneath(d.path(), Path::new("link")).is_err());
        assert!(open_beneath(d.path(), Path::new("dirlink/secret")).is_err());
        // the portable walk too, which is what macOS runs
        assert!(open_beneath_walk(d.path(), &["link".as_ref()]).is_err());
        assert!(open_beneath_walk(d.path(), &["dirlink".as_ref(), "secret".as_ref()]).is_err());
    }

    #[test]
    fn refuses_dot_dot_absolute_and_empty() {
        let d = tempfile::tempdir().unwrap();
        for bad in ["../x", "/etc/passwd", "a/../b", "", "./a"] {
            assert!(open_beneath(d.path(), Path::new(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn refuses_a_directory_as_the_last_component() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        assert!(open_beneath_walk(d.path(), &["sub".as_ref()]).is_err());
    }
}
