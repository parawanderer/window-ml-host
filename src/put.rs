//! put.rs — writing bytes to a file in a root: the target's checks, the staged temp file and its no-replace rename.
//! The parent directory is opened ONCE, by `put`, and held as a descriptor; every later step (the temp file's
//! creation, the target's look, the rename) goes through it, so a path component swapped for a symlink afterwards
//! cannot redirect the write (docs/PROTOCOL.md, "put / write / commit").

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use sha2::{Digest, Sha256};

use crate::facts;
use crate::sandbox;
use crate::session::Fail;
use crate::store::random_hex;

/// The most bytes one `put` may declare.
pub const MAX_PUT: u64 = 64 << 20;
/// The prefix of a staged temp file, in the target's directory.
pub const TMP_PREFIX: &str = ".wmlhost-put-";

/// The process's umask, read once. POSIX reads it only by setting it, so the set-and-restore happens a single time;
/// `main` calls this before it starts any thread, so no other thread creates a file in between.
pub fn umask() -> Mode {
    static UMASK: OnceLock<Mode> = OnceLock::new();
    *UMASK.get_or_init(|| {
        let old = rustix::process::umask(Mode::from_raw_mode(0o077));
        rustix::process::umask(old);
        old
    })
}

/// The mode a committed file gets: what the person's own tools would produce, `0666` less the umask.
pub fn committed_mode() -> Mode {
    Mode::from_raw_mode(0o666 & !umask().as_raw_mode())
}

fn fail<T>(code: &'static str, msg: impl Into<String>) -> Result<T, Fail> {
    Err(Fail(code, msg.into()))
}

/// Splits a target path into the directory part as given and the file name. The name is a normal one: not empty,
/// `.` or `..`, which also refuses a trailing `/`. A bare name has the parent `.`; `/x` has the parent `/`.
pub fn split_target(path: &str) -> Result<(&str, &str), &'static str> {
    let (parent, name) = match path.rsplit_once('/') {
        Some(("", name)) => ("/", name),
        Some((parent, name)) => (parent, name),
        None => (".", path),
    };
    if name.is_empty() || name == "." || name == ".." {
        return Err("path names a file: its last component is not empty, `.` or `..`, and it has no trailing `/`");
    }
    Ok((parent, name))
}

/// The root a (realpath) directory lies in: the deepest of the roots that contain it.
pub fn root_of<'a>(dir: &Path, roots: &'a [PathBuf]) -> Option<&'a PathBuf> {
    roots.iter().filter(|r| dir.starts_with(r)).max_by_key(|r| r.components().count())
}

/// The target's path relative to its root, `/`-separated.
pub fn rel_of(root: &Path, parent: &Path, name: &str) -> String {
    let dir = parent.strip_prefix(root).unwrap_or(Path::new(""));
    dir.join(name).to_string_lossy().into_owned()
}

/// Whether `rel` (relative to its root) is a name the sandbox never lets a child write, or lies beneath one. Compared
/// case-insensitively: the default macOS volume is, and refusing one name too many costs nothing.
pub fn is_protected(rel: &str) -> bool {
    let rel = rel.to_lowercase();
    sandbox::protected_rels().any(|p| {
        let p = p.to_lowercase();
        rel == p || rel.strip_prefix(&p).is_some_and(|rest| rest.starts_with('/'))
    })
}

/// A target no verdict can allow: a protected name of its root, or a credential's.
pub fn refused_target(full: &Path, rel: &str) -> bool {
    is_protected(rel) || facts::looks_secret(full)
}

/// What a name in the parent directory is right now.
#[derive(Debug, PartialEq, Eq)]
pub enum Kind {
    Absent,
    File(u64),
    Symlink,
    Dir,
    Other,
}

/// A put waiting for its bytes: the held parent, the temp file once created, and what has arrived.
pub struct Staged {
    pub created: Instant,
    parent: OwnedFd,
    name: String,
    tmp_name: String,
    tmp: Option<File>,
    pub size: u64,
    pub received: u64,
    hasher: Sha256,
    /// The target's realpath, and the root it lies in, and its path relative to that root.
    pub path: PathBuf,
    pub root: PathBuf,
    pub rel: String,
}

impl Drop for Staged {
    /// Discard, TTL expiry, a failed commit and the end of the session all end here: the temp file goes.
    fn drop(&mut self) {
        if self.tmp.take().is_some() {
            let _ = rustix::fs::unlinkat(&self.parent, self.tmp_name.as_str(), AtFlags::empty());
        }
    }
}

/// Opens `dir` (a realpath) as a directory descriptor, refusing when what opened is not what the path names now.
pub fn open_parent(dir: &Path) -> io::Result<OwnedFd> {
    let fd =
        rustix::fs::open(dir, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())?;
    use std::os::unix::fs::MetadataExt;
    let f = File::from(fd);
    let (a, b) = (f.metadata()?, std::fs::metadata(dir)?);
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
        return Err(io::Error::other("the directory changed while it was opened"));
    }
    Ok(f.into())
}

/// Looks at `name` in `parent` without following a symlink.
pub fn kind_at(parent: &OwnedFd, name: &str) -> io::Result<Kind> {
    match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(Kind::Absent),
        Err(e) => Err(e.into()),
        Ok(st) => Ok(match FileType::from_raw_mode(st.st_mode) {
            FileType::RegularFile => Kind::File(st.st_size as u64),
            FileType::Symlink => Kind::Symlink,
            FileType::Directory => Kind::Dir,
            _ => Kind::Other,
        }),
    }
}

/// The refusal for a target that is not a plain file or absent.
pub fn kind_refusal(kind: &Kind, rel: &str) -> Result<(), Fail> {
    match kind {
        Kind::Symlink => fail("IsSymlink", format!("{rel} is a symlink")),
        Kind::Dir => fail("IsDirectory", format!("{rel} is a directory")),
        Kind::Other => fail("BadRequest", format!("{rel} is not a regular file")),
        Kind::Absent | Kind::File(_) => Ok(()),
    }
}

fn io_fail(e: impl Into<io::Error>) -> Fail {
    Fail("Failed", e.into().to_string())
}

impl Staged {
    pub fn new(parent: OwnedFd, name: &str, id: &str, size: u64, path: PathBuf, root: PathBuf, rel: String) -> Staged {
        Staged {
            created: Instant::now(),
            parent,
            name: name.to_string(),
            tmp_name: format!("{TMP_PREFIX}{id}-{}", random_hex(4)),
            tmp: None,
            size,
            received: 0,
            hasher: Sha256::new(),
            path,
            root,
            rel,
        }
    }

    /// The target as it is now.
    pub fn target(&self) -> io::Result<Kind> {
        kind_at(&self.parent, &self.name)
    }

    /// The temp file, created on first use through the held parent: `O_CREAT|O_EXCL|O_NOFOLLOW`, `0600`, so while it
    /// is staged no other user can read or write a half-written attachment. `finish` gives it its final mode.
    fn tmp_file(&mut self) -> Result<&mut File, Fail> {
        if self.tmp.is_none() {
            let mode = Mode::RUSR | Mode::WUSR;
            let fd = rustix::fs::openat(
                &self.parent,
                self.tmp_name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                mode,
            )
            .map_err(io_fail)?;
            self.tmp = Some(File::from(fd));
        }
        Ok(self.tmp.as_mut().expect("just created"))
    }

    /// Appends the chunk that starts at `offset`; the checks of `write`.
    pub fn append(&mut self, offset: u64, data: &[u8], max_chunk: u64) -> Result<(), Fail> {
        if data.len() as u64 > max_chunk {
            return fail("BadRequest", format!("a chunk is at most {max_chunk} bytes"));
        }
        if offset != self.received {
            return fail("BadRequest", format!("offset is {offset}, the next chunk starts at {}", self.received));
        }
        if self.received + data.len() as u64 > self.size {
            return fail("BadRequest", format!("{} bytes arrived past the declared size {}", data.len(), self.size));
        }
        self.tmp_file()?.write_all(data).map_err(io_fail)?;
        self.hasher.update(data);
        self.received += data.len() as u64;
        Ok(())
    }

    /// Syncs the temp file and puts it in place; the hex sha256 of what was written. With `replace` false a file
    /// that is there now is `Exists`. On any error the temp file is left for `Drop`.
    pub fn finish(&mut self, replace: bool) -> Result<String, Fail> {
        if self.received != self.size {
            return fail("BadRequest", format!("{} of the declared {} bytes arrived", self.received, self.size));
        }
        let tmp = self.tmp_file()?;
        rustix::fs::fchmod(&*tmp, committed_mode()).map_err(io_fail)?;
        tmp.sync_all().map_err(io_fail)?;
        if replace {
            // A rename replaces a link and never writes through it, but the rule stays the one `put` applied.
            kind_refusal(&self.target().map_err(io_fail)?, &self.rel)?;
            rustix::fs::renameat(&self.parent, self.tmp_name.as_str(), &self.parent, self.name.as_str())
                .map_err(io_fail)?;
        } else {
            match rename_noreplace(&self.parent, &self.tmp_name, &self.name) {
                Ok(()) => {}
                Err(e) if e == rustix::io::Errno::EXIST => {
                    return fail("Exists", format!("{} appeared since the put", self.rel));
                }
                Err(e) => return Err(io_fail(e)),
            }
        }
        // Renamed: the temp name no longer exists, so Drop must not unlink it.
        self.tmp = None;
        Ok(hex::encode(std::mem::take(&mut self.hasher).finalize()))
    }
}

/// Renames `from` to `to` inside `dir`, failing `EXIST` when `to` is there. Atomic where the OS has a flag for it:
/// `renameat2(RENAME_NOREPLACE)` on Linux, `renameatx_np(RENAME_EXCL)` on macOS (both are `RenameFlags::NOREPLACE`
/// in rustix). Elsewhere, or on a filesystem that rejects the flag, `link` then `unlink`: link fails `EXIST` too.
pub fn rename_noreplace(dir: &OwnedFd, from: &str, to: &str) -> Result<(), rustix::io::Errno> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    match rustix::fs::renameat_with(dir, from, dir, to, rustix::fs::RenameFlags::NOREPLACE) {
        Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOSYS | rustix::io::Errno::NOTSUP) => {}
        other => return other,
    }
    link_unlink(dir, from, to)
}

/// The fallback of [`rename_noreplace`].
fn link_unlink(dir: &OwnedFd, from: &str, to: &str) -> Result<(), rustix::io::Errno> {
    rustix::fs::linkat(dir, from, dir, to, AtFlags::empty())?;
    rustix::fs::unlinkat(dir, from, AtFlags::empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- the staged file's mode ---

    #[test]
    fn a_staged_file_is_0600_and_a_committed_one_0666_less_the_umask() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().canonicalize().unwrap();
        let mut s = Staged::new(open_parent(&real).unwrap(), "f", "p1", 2, real.join("f"), real.clone(), "f".into());
        s.append(0, b"a", 2).unwrap();
        let mode = |p: &Path| Mode::from_raw_mode(rustix::fs::stat(p).unwrap().st_mode) & Mode::from_raw_mode(0o777);
        assert_eq!(mode(&real.join(&s.tmp_name)), Mode::RUSR | Mode::WUSR, "staged");
        s.append(1, b"b", 2).unwrap();
        s.finish(false).unwrap();
        assert_eq!(mode(&real.join("f")), committed_mode(), "committed");
    }

    // --- the target's name ---

    #[test]
    fn a_target_splits_into_a_directory_and_a_normal_name() {
        assert_eq!(split_target("a/b/c.txt"), Ok(("a/b", "c.txt")));
        assert_eq!(split_target("c.txt"), Ok((".", "c.txt")));
        assert_eq!(split_target("/c.txt"), Ok(("/", "c.txt")));
        assert_eq!(split_target("../c"), Ok(("..", "c")));
        for bad in ["", "a/", "/", "a/.", "a/..", "..", ".", "a//"] {
            assert!(split_target(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_deepest_root_holding_a_directory_is_its_root() {
        let roots = [PathBuf::from("/w"), PathBuf::from("/w/inner"), PathBuf::from("/other")];
        assert_eq!(root_of(Path::new("/w/inner/x"), &roots), Some(&roots[1]));
        assert_eq!(root_of(Path::new("/w/x"), &roots), Some(&roots[0]));
        assert_eq!(root_of(Path::new("/wx"), &roots), None);
        assert_eq!(rel_of(Path::new("/w"), Path::new("/w/a/b"), "f"), "a/b/f");
        assert_eq!(rel_of(Path::new("/w"), Path::new("/w"), "f"), "f");
    }

    // --- what is refused outright ---

    #[test]
    fn every_protected_name_and_what_lies_beneath_it_is_refused() {
        for p in sandbox::protected_rels() {
            assert!(is_protected(&p), "{p}");
            assert!(is_protected(&format!("{p}/x")), "{p}/x");
            assert!(is_protected(&p.to_uppercase()), "case-insensitive: {p}");
        }
        assert!(is_protected(".git/hooks/pre-commit"));
        assert!(!is_protected(".gitignore"));
        assert!(!is_protected(".bashrc2"));
        assert!(!is_protected("sub/.bashrc"), "the protected names are the root's own");
        assert!(!is_protected(".git/HEAD"));
    }

    #[test]
    fn a_credential_name_is_refused_anywhere() {
        assert!(refused_target(Path::new("/w/.ssh/x"), ".ssh/x"));
        assert!(refused_target(Path::new("/w/a/.env"), "a/.env"));
        assert!(!refused_target(Path::new("/w/a/notes.txt"), "a/notes.txt"));
    }

    // --- the rename ---

    fn dir_fd(d: &Path) -> OwnedFd {
        open_parent(&d.canonicalize().unwrap()).unwrap()
    }

    #[test]
    fn the_no_replace_rename_moves_to_a_free_name_and_refuses_a_taken_one() {
        let d = tempfile::tempdir().unwrap();
        let fd = dir_fd(d.path());
        std::fs::write(d.path().join("from"), b"new").unwrap();
        rename_noreplace(&fd, "from", "to").unwrap();
        assert_eq!(std::fs::read(d.path().join("to")).unwrap(), b"new");
        assert!(!d.path().join("from").exists());
        std::fs::write(d.path().join("from"), b"newer").unwrap();
        assert_eq!(rename_noreplace(&fd, "from", "to"), Err(rustix::io::Errno::EXIST));
        assert_eq!(std::fs::read(d.path().join("to")).unwrap(), b"new", "the taken name is untouched");
        assert!(d.path().join("from").exists(), "the source stays for the caller to clean up");
    }

    #[test]
    fn the_link_fallback_behaves_the_same() {
        let d = tempfile::tempdir().unwrap();
        let fd = dir_fd(d.path());
        std::fs::write(d.path().join("from"), b"new").unwrap();
        link_unlink(&fd, "from", "to").unwrap();
        assert_eq!(std::fs::read(d.path().join("to")).unwrap(), b"new");
        assert!(!d.path().join("from").exists());
        std::fs::write(d.path().join("from"), b"x").unwrap();
        assert_eq!(link_unlink(&fd, "from", "to"), Err(rustix::io::Errno::EXIST));
        assert_eq!(std::fs::read(d.path().join("to")).unwrap(), b"new");
        assert!(d.path().join("from").exists());
    }

    // --- the staged file ---

    fn staged(d: &Path, name: &str, size: u64) -> Staged {
        let real = d.canonicalize().unwrap();
        Staged::new(open_parent(&real).unwrap(), name, "p1", size, real.join(name), real.clone(), name.into())
    }

    fn names(d: &Path) -> Vec<String> {
        let mut v: Vec<String> =
            std::fs::read_dir(d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    #[test]
    fn chunks_must_arrive_in_order_within_size_and_the_cap() {
        let d = tempfile::tempdir().unwrap();
        let mut s = staged(d.path(), "f", 6);
        s.append(0, b"abc", 4).unwrap();
        assert_eq!(s.append(0, b"abc", 4).unwrap_err().0, "BadRequest", "a repeat");
        assert_eq!(s.append(5, b"x", 4).unwrap_err().0, "BadRequest", "a gap");
        assert_eq!(s.append(3, b"defgh", 4).unwrap_err().0, "BadRequest", "over the chunk cap");
        assert_eq!(s.append(3, b"defg", 8).unwrap_err().0, "BadRequest", "past the size");
        assert_eq!(s.finish(false).unwrap_err().0, "BadRequest", "short of the size");
        s.append(3, b"def", 4).unwrap();
        let sha = s.finish(false).unwrap();
        assert_eq!(sha, hex::encode(Sha256::digest(b"abcdef")));
        assert_eq!(std::fs::read(d.path().join("f")).unwrap(), b"abcdef");
        assert_eq!(names(d.path()), ["f"]);
    }

    #[test]
    fn dropping_a_staged_put_removes_its_temp_file_and_a_failed_commit_does_too() {
        let d = tempfile::tempdir().unwrap();
        let mut s = staged(d.path(), "f", 1);
        s.append(0, b"a", 4).unwrap();
        assert_eq!(names(d.path()).len(), 1);
        drop(s);
        assert!(names(d.path()).is_empty());
        std::fs::write(d.path().join("f"), b"old").unwrap();
        let mut s = staged(d.path(), "f", 1);
        s.append(0, b"a", 4).unwrap();
        assert_eq!(s.finish(false).unwrap_err().0, "Exists");
        drop(s);
        assert_eq!(names(d.path()), ["f"]);
        assert_eq!(std::fs::read(d.path().join("f")).unwrap(), b"old");
    }

    #[test]
    fn the_temp_file_is_made_through_the_held_parent_after_it_is_renamed_away() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        std::fs::create_dir(&a).unwrap();
        let mut s = staged(&a, "f", 1);
        std::fs::rename(&a, &b).unwrap();
        s.append(0, b"z", 4).unwrap();
        s.finish(false).unwrap();
        assert_eq!(std::fs::read(b.join("f")).unwrap(), b"z");
    }
}
