//! mounts.rs — a chat session's host directories: the scope check a cell's file request meets (window-ml's
//! FILE_ATTACHMENTS.md, H1 to H8). A mount is a directory inside a configured root that the host holds open; every path
//! in a request is relative to it and walked one component at a time from the held descriptor, never through a symlink.
//! The host refuses what no policy may lift and resolves the facts; the worker judges free or asks over them, and sends
//! back the `basis` it judged on, which a write compares before it lands (docs/PROTOCOL.md, "Mounts").

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use base64::Engine;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::facts;
use crate::gitconfig;
use crate::gitfacts::Git;
use crate::install::Browser;
use crate::put::{self, Staged};
use crate::session::Fail;

/// The cell's own paths, which a mount at, under or above would shadow or expose (FILE_ATTACHMENTS.md, H2).
pub const RESERVED: &[&str] = &["/files", "/tmp", "/lib", "/home/pyodide", "/dev", "/proc"];
/// The diff cap: a file at or under it carries a sha256 in its basis.
pub const DIFF_CAP: u64 = 1 << 20;
/// The most bytes one `fetch` returns.
pub const MAX_CHUNK: u64 = 512 * 1024;
/// The ceiling of a call's `cap` for `fetch` and `store` (provisional, FILE_ATTACHMENTS.md H1).
pub const MAX_CAP: u64 = put::MAX_PUT;
/// The most entries one `list` returns.
pub const MAX_LIST: usize = 2000;
/// The longest mount-relative path accepted.
pub const MAX_REL: usize = 4096;
/// The longest session string accepted.
pub const MAX_SESSION: usize = 256;
/// The most mounts one connection holds.
pub const MAX_MOUNTS: usize = 64;

fn fail<T>(code: &'static str, msg: impl Into<String>) -> Result<T, Fail> {
    Err(Fail(code, msg.into()))
}

fn io_fail(e: impl Into<io::Error>) -> Fail {
    Fail("Failed", e.into().to_string())
}

fn changed<T>(rel: &str) -> Result<T, Fail> {
    fail("ChangedSinceJudged", format!("{rel} changed since it was judged; stat it again"))
}

/// A refusal that carries more than a sentence: `EFBIG` names the file's size and the cap.
pub enum Refusal {
    Fail(Fail),
    TooBig { message: String, size: u64, cap: u64 },
}

impl From<Fail> for Refusal {
    fn from(f: Fail) -> Self {
        Refusal::Fail(f)
    }
}

// --- the path rule ---

/// Splits a mount-relative path into its components. Refused on every platform: a NUL, a `\`, a leading `/` (and so
/// `//`), a leading drive letter (`C:`), and a component that is empty, `.`, `..` or all dots. `""` names the mount
/// itself, where `allow_root` says it may.
pub fn rel_parts(rel: &str, allow_root: bool) -> Result<Vec<&str>, Fail> {
    if rel.is_empty() {
        return if allow_root {
            Ok(vec![])
        } else {
            fail("BadRequest", "path names a file in the mount, not the mount")
        };
    }
    if rel.len() > MAX_REL {
        return fail("BadRequest", format!("path is at most {MAX_REL} bytes"));
    }
    if rel.contains('\0') || rel.contains('\\') {
        return fail("BadRequest", "path has no NUL and no backslash");
    }
    if rel.starts_with('/') {
        return fail("BadRequest", "path is relative to the mount: no leading /");
    }
    let b = rel.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return fail("BadRequest", "path is relative to the mount: no drive letter");
    }
    let parts: Vec<&str> = rel.split('/').collect();
    if parts.iter().any(|p| p.is_empty() || p.bytes().all(|c| c == b'.')) {
        return fail("BadRequest", "path's components are not empty, and not made only of dots");
    }
    Ok(parts)
}

// --- what may be mounted ---

/// What `mount` refuses by, besides the roots: the reserved prefixes, the home directory, the host's and the browser's
/// own directories, and the session's existing mounts.
pub struct Limits<'a> {
    pub reserved: Vec<PathBuf>,
    pub home: Option<&'a Path>,
    pub forbidden: Vec<PathBuf>,
    pub roots: &'a [PathBuf],
}

impl Limits<'_> {
    /// The directories no mount may be at, under or above: every known browser's data directory (the profile lives
    /// there; the archive folder is a File System Access handle with no path, so the worker refuses it), the host's
    /// config, and the owner table's state directory. Each is taken as given and as its realpath where it exists.
    pub fn forbidden_dirs(home: Option<&Path>, owners_dir: Option<&Path>) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Some(home) = home {
            for b in [Browser::Chrome, Browser::ChromeBeta, Browser::Chromium, Browser::Brave, Browser::Edge] {
                if let Some(data) = crate::install::manifest_dir(b, home).parent() {
                    out.push(data.to_path_buf());
                }
            }
            out.push(home.join(".config/wmlhost"));
        }
        out.extend(owners_dir.map(Path::to_path_buf));
        let real: Vec<PathBuf> = out.iter().filter_map(|p| p.canonicalize().ok()).collect();
        out.extend(real);
        out
    }
}

fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Why `real` (a realpath) may not be mounted, beside `others` (this session's mounts): `None` when it may.
pub fn mount_refusal(real: &Path, limits: &Limits, others: &[&Path]) -> Option<String> {
    let shown = real.display();
    if let Some(r) = limits.reserved.iter().find(|r| overlaps(real, r)) {
        return Some(format!("{shown} is at, under or above {}, which the sandbox reserves", r.display()));
    }
    if limits.home.is_some_and(|h| h.starts_with(real)) {
        return Some(format!("{shown} is the home directory or above it: mount a project inside it"));
    }
    if let Some(f) = limits.forbidden.iter().find(|f| overlaps(real, f)) {
        return Some(format!("{shown} is at, under or above {}, the browser's or this host's own", f.display()));
    }
    if let Some(m) = others.iter().find(|m| overlaps(real, m)) {
        return Some(format!("{shown} is at, under or above {}, already mounted in this session", m.display()));
    }
    if !facts::in_roots(real, limits.roots) {
        return Some(format!("{shown} is outside every root"));
    }
    None
}

// --- a held mount ---

type DevIno = (u64, u64);

// The `stat` fields' types differ by platform (`st_dev` is an `i32` on macOS).
#[allow(clippy::unnecessary_cast)]
fn dev_ino(st: &Stat) -> DevIno {
    (st.st_dev as u64, st.st_ino as u64)
}

/// The uploads folder of a mount, and its frozen `attached/`, held by device and inode.
struct Uploads {
    rel: String,
    dir: DevIno,
    attached: DevIno,
}

/// A directory a session mounted.
pub struct Mount {
    pub id: String,
    pub session: String,
    /// The realpath, and the root it lies in.
    pub path: PathBuf,
    pub root: PathBuf,
    pub writable: bool,
    fd: OwnedFd,
    dev_ino: DevIno,
    uploads: Option<Uploads>,
}

/// Where a walk to a path's last component ended.
pub struct Walked {
    /// The last component's directory, and the last component; `None` when a directory on the way does not exist.
    pub at: Option<(OwnedFd, String)>,
    /// A directory on the way (the mount included) is the uploads folder, or `attached/`.
    pub in_uploads: bool,
    pub in_attached: bool,
}

const DIR_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

impl Mount {
    /// Holds `given` (an absolute path) as a mount, refusing what [`mount_refusal`] refuses and an `uploads` folder
    /// that is not a directory with `attached/` inside.
    pub fn open(
        id: String,
        session: String,
        given: &str,
        writable: bool,
        uploads: Option<&str>,
        limits: &Limits,
        others: &[&Path],
    ) -> Result<Mount, Fail> {
        if given.contains('\0') || !Path::new(given).is_absolute() {
            return fail("BadRequest", "path is an absolute path with no NUL");
        }
        let real = match Path::new(given).canonicalize() {
            Ok(p) if p.is_dir() => p,
            _ => return fail("MountRefused", format!("{given} is not an existing directory")),
        };
        if let Some(why) = mount_refusal(&real, limits, others) {
            return fail("MountRefused", why);
        }
        let root = put::root_of(&real, limits.roots).cloned().expect("in a root: checked above");
        let fd = put::open_parent(&real).map_err(|e| Fail("MountRefused", e.to_string()))?;
        let held = dev_ino(&rustix::fs::fstat(&fd).map_err(io_fail)?);
        let mut m = Mount { id, session, path: real, root, writable, fd, dev_ino: held, uploads: None };
        if let Some(u) = uploads {
            let refused = |why: &str| Fail("MountRefused", format!("uploads {u:?} {why}"));
            let parts = rel_parts(u, true)?;
            let dir = m.open_dir(&parts).map_err(|_| refused("is not a directory in the mount"))?;
            let attached = rustix::fs::openat(&dir, "attached", DIR_FLAGS, Mode::empty())
                .map_err(|_| refused("has no attached/ directory"))?;
            m.uploads = Some(Uploads {
                rel: u.to_string(),
                dir: dev_ino(&rustix::fs::fstat(&dir).map_err(io_fail)?),
                attached: dev_ino(&rustix::fs::fstat(&attached).map_err(io_fail)?),
            });
        }
        Ok(m)
    }

    /// The mount's facts as `mount` answers them.
    pub fn json(&self) -> Value {
        json!({ "id": self.id, "path": self.path, "root": self.root, "mode": self.mode(),
                "uploads": self.uploads.as_ref().map(|u| &u.rel) })
    }

    fn mode(&self) -> &'static str {
        if self.writable { "rw" } else { "ro" }
    }

    /// H3: the directory the mount's path names now is still the one held. A folder moved away and replaced, or
    /// deleted, refuses every request on the mount.
    pub fn check(&self) -> Result<(), Fail> {
        match rustix::fs::lstat(&self.path) {
            Ok(st) if dev_ino(&st) == self.dev_ino => Ok(()),
            _ => {
                fail("MountReplaced", format!("{} is no longer the folder mounted as {}", self.path.display(), self.id))
            }
        }
    }

    /// The uploads folder's realpath, for mapping `/files` in an argv (H9): `None` when the mount has none. The
    /// folder the name reaches now must still be the one held, as the mount itself must be (H3).
    pub fn uploads_dir(&self) -> Result<Option<PathBuf>, Fail> {
        let Some(u) = &self.uploads else { return Ok(None) };
        let dir = self.path.join(&u.rel);
        match rustix::fs::lstat(&dir) {
            Ok(st) if dev_ino(&st) == u.dir => Ok(Some(dir)),
            _ => fail("MountReplaced", format!("{} is no longer the uploads folder of {}", dir.display(), self.id)),
        }
    }

    /// Whether `path` (absolute, as the host resolved it) is this mount's `attached/` or lies beneath it: by name, and
    /// by the device and inode of each of its existing ancestors, so another name for the folder (a bind mount, a
    /// path the realpath did not fold) is caught too.
    pub fn holds_in_attached(&self, path: &Path) -> bool {
        let Some(u) = &self.uploads else { return false };
        if path.starts_with(self.path.join(&u.rel).join("attached")) {
            return true;
        }
        path.ancestors().any(|a| rustix::fs::lstat(a).is_ok_and(|st| dev_ino(&st) == u.attached))
    }

    /// A fresh descriptor of the mount's directory.
    fn top(&self) -> Result<OwnedFd, Fail> {
        rustix::fs::openat(&self.fd, ".", DIR_FLAGS, Mode::empty()).map_err(io_fail)
    }

    /// Opens a directory of the mount by walking `parts` (every one a directory).
    fn open_dir(&self, parts: &[&str]) -> Result<OwnedFd, Fail> {
        let mut cur = self.top()?;
        for (i, p) in parts.iter().enumerate() {
            cur = self
                .step(&cur, p, &parts[..=i])?
                .ok_or_else(|| Fail("NotFound", format!("{} does not exist", parts[..=i].join("/"))))?;
        }
        Ok(cur)
    }

    /// Opens directory `name` in `dir`, never through a symlink: `None` when it does not exist.
    fn step(&self, dir: &OwnedFd, name: &str, so_far: &[&str]) -> Result<Option<OwnedFd>, Fail> {
        match rustix::fs::openat(dir, name, DIR_FLAGS, Mode::empty()) {
            Ok(fd) => Ok(Some(fd)),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(e) => {
                let shown = so_far.join("/");
                match put::kind_at(dir, name) {
                    Ok(put::Kind::Symlink) => {
                        fail("IsSymlink", format!("{shown} is a symlink: a path through a symlink is refused"))
                    }
                    Ok(put::Kind::File(_) | put::Kind::Other) => {
                        fail("NotADirectory", format!("{shown} is not a directory"))
                    }
                    _ => Err(io_fail(e)),
                }
            }
        }
    }

    fn mark(&self, fd: &OwnedFd, w: &mut Walked) -> Result<(), Fail> {
        if let Some(u) = &self.uploads {
            let di = dev_ino(&rustix::fs::fstat(fd).map_err(io_fail)?);
            w.in_uploads |= di == u.dir;
            w.in_attached |= di == u.attached;
        }
        Ok(())
    }

    /// H4: walks to the last component of `parts` from the held descriptor, marking the uploads folder and
    /// `attached/` by device and inode as it passes them.
    pub fn walk(&self, parts: &[&str]) -> Result<Walked, Fail> {
        let (last, dirs) = parts.split_last().expect("a path names a file");
        let mut w = Walked { at: None, in_uploads: false, in_attached: false };
        let mut cur = self.top()?;
        self.mark(&cur, &mut w)?;
        for (i, p) in dirs.iter().enumerate() {
            match self.step(&cur, p, &parts[..=i])? {
                Some(fd) => cur = fd,
                None => return Ok(w),
            }
            self.mark(&cur, &mut w)?;
        }
        w.at = Some((cur, last.to_string()));
        Ok(w)
    }

    /// The path relative to the mount's root, as `put` reports one.
    fn root_rel(&self, rel: &str) -> String {
        let base = self.path.strip_prefix(&self.root).unwrap_or(Path::new(""));
        base.join(rel).to_string_lossy().into_owned()
    }

    /// A name no write may touch: a protected name of the root (as `put` refuses) or anything with a `.git`
    /// component, compared case-insensitively (a write under `.git/hooks` would run as code).
    pub fn protected(&self, rel: &str) -> bool {
        let r = self.root_rel(rel);
        put::is_protected(&r) || r.split('/').any(|c| c.eq_ignore_ascii_case(".git"))
    }

    fn require_writable(&self) -> Result<(), Fail> {
        if self.writable { Ok(()) } else { fail("EROFS", format!("{} is mounted read-only", self.id)) }
    }

    // --- stat ---

    /// The facts of `rel` (H7) and its basis; reads no bytes into the answer.
    pub fn stat(&self, rel: &str, git: &Git) -> Result<Value, Fail> {
        let parts = rel_parts(rel, true)?;
        let full = self.path.join(rel);
        let mut v = json!({ "mount": self.id, "path": rel, "inMount": true, "mode": self.mode(),
                            "secret": facts::looks_secret(&full), "protected": self.protected(rel),
                            "kind": null, "exists": false, "inUploads": false, "inAttached": false,
                            "ignored": null, "gitUndoable": false, "hardLinked": false, "basis": null });
        let repo = gitconfig::inspect(full.parent().unwrap_or(&self.path));
        let repo_rel = repo.as_ref().and_then(|r| full.strip_prefix(&r.root).ok()).map(|p| p.to_string_lossy());
        v["ignored"] = match (&repo, &repo_rel) {
            // Unknown, as `gitUndoable` is, when the repository's config runs code: no query of the host's reads it.
            (Some(r), _) if r.runs_code => Value::Null,
            (Some(r), Some(rr)) if !rr.is_empty() => json!(git.ignored(r, rr)),
            _ => json!(false),
        };
        if parts.is_empty() {
            let mut w = Walked { at: None, in_uploads: false, in_attached: false };
            self.mark(&self.top()?, &mut w)?;
            v["kind"] = json!("dir");
            v["exists"] = json!(true);
            v["inUploads"] = json!(w.in_uploads);
            v["inAttached"] = json!(w.in_attached);
            return Ok(v);
        }
        let w = self.walk(&parts)?;
        v["inUploads"] = json!(w.in_uploads);
        v["inAttached"] = json!(w.in_attached);
        let Some((dir, name)) = w.at else { return Ok(v) };
        let st = match rustix::fs::statat(&dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => return Ok(v),
            Err(e) => return Err(io_fail(e)),
            Ok(st) => st,
        };
        v["exists"] = json!(true);
        let kind = FileType::from_raw_mode(st.st_mode);
        v["kind"] = json!(match kind {
            FileType::RegularFile => "file",
            FileType::Directory => "dir",
            FileType::Symlink => "symlink",
            _ => "other",
        });
        if kind == FileType::Directory
            && let Some(u) = &self.uploads
        {
            v["inUploads"] = json!(w.in_uploads || dev_ino(&st) == u.dir);
            v["inAttached"] = json!(w.in_attached || dev_ino(&st) == u.attached);
        }
        if kind != FileType::RegularFile {
            return Ok(v);
        }
        let Some((file, st)) = open_file(&dir, &name)? else { return changed(rel) };
        v["hardLinked"] = json!(st.st_nlink > 1);
        let basis = Basis::of(&file, &st).map_err(io_fail)?;
        v["gitUndoable"] = match (&repo, &repo_rel) {
            (Some(r), Some(rr)) => json!(git.undoable(r, rr, basis.size, &mut ReadAt::new(&file))),
            _ => json!(false),
        };
        v["basis"] = basis.json();
        Ok(v)
    }

    // --- list ---

    /// One page of a directory's entries, sorted by name; a symlink is listed as one, never followed.
    pub fn list(&self, rel: &str, offset: usize, limit: usize) -> Result<Value, Fail> {
        let parts = rel_parts(rel, true)?;
        let dir = self.open_dir(&parts)?;
        let mut names: Vec<std::ffi::OsString> = Vec::new();
        for e in rustix::fs::Dir::read_from(&dir).map_err(io_fail)? {
            let e = e.map_err(io_fail)?;
            let n = e.file_name().to_bytes();
            if n != b"." && n != b".." {
                names.push(std::ffi::OsStr::from_bytes(n).to_os_string());
            }
        }
        names.sort();
        let total = names.len();
        let limit = limit.clamp(1, MAX_LIST);
        let entries: Vec<Value> = names
            .iter()
            .skip(offset)
            .take(limit)
            .map(|n| {
                let st = rustix::fs::statat(&dir, n.as_os_str(), AtFlags::SYMLINK_NOFOLLOW).ok();
                let kind = st.as_ref().map(|s| match FileType::from_raw_mode(s.st_mode) {
                    FileType::RegularFile => "file",
                    FileType::Directory => "dir",
                    FileType::Symlink => "symlink",
                    _ => "other",
                });
                let mut e = json!({ "name": n.to_string_lossy(), "kind": kind,
                                    "size": st.as_ref().map(|s| s.st_size as u64),
                                    "mtimeNs": st.as_ref().map(mtime_ns) });
                if n.to_str().is_none() {
                    e["lossy"] = json!(true);
                }
                e
            })
            .collect();
        Ok(json!({ "mount": self.id, "path": rel, "entries": entries, "total": total,
                   "more": offset.saturating_add(limit) < total }))
    }

    // --- fetch ---

    /// One chunk of a file, after its basis is compared with the one judged (H8) and its size with the cap (H5).
    pub fn fetch(
        &self,
        rel: &str,
        judged: Option<&Basis>,
        offset: u64,
        length: u64,
        cap: u64,
    ) -> Result<Value, Refusal> {
        let parts = rel_parts(rel, false)?;
        let Some((dir, name)) = self.walk(&parts)?.at else { return Ok(changed(rel)?) };
        let Some((file, st)) = open_file(&dir, &name)? else {
            put::kind_refusal(&put::kind_at(&dir, &name).map_err(io_fail)?, rel)?;
            return Ok(changed(rel)?);
        };
        let size = st.st_size as u64;
        if size > cap {
            return Err(Refusal::TooBig {
                message: format!("{rel} is {size} bytes, over the cap of {cap}"),
                size,
                cap,
            });
        }
        let now = Basis::of(&file, &st).map_err(io_fail)?;
        if judged != Some(&now) {
            return Ok(changed(rel)?);
        }
        let len = length.min(MAX_CHUNK).min(size.saturating_sub(offset));
        let mut buf = vec![0u8; len as usize];
        file.read_exact_at(&mut buf, offset).map_err(|_| Fail("ChangedSinceJudged", format!("{rel} shrank")))?;
        Ok(json!({ "mount": self.id, "path": rel, "offset": offset, "size": size,
                   "eof": offset + len >= size,
                   "data": { "$bytes": base64::engine::general_purpose::STANDARD.encode(&buf) } }))
    }

    // --- store, remove, rename ---

    /// H5, H6, H8: checks a whole-file write of `size` bytes to `rel` and holds its directory; writes nothing. The
    /// bytes arrive through `write` and land at `commit`, which compares the basis again.
    pub fn store(&self, rel: &str, size: u64, judged: Option<Basis>, cap: u64, id: &str) -> Result<Stored, Refusal> {
        self.require_writable()?;
        let parts = rel_parts(rel, false)?;
        let w = self.walk(&parts)?;
        if w.in_attached {
            return Err(Fail("InAttached", format!("{rel} is in attached/, the uploads as they were given")).into());
        }
        if self.protected(rel) {
            return Err(Fail("Protected", format!("{rel} is a protected name, which no write may touch")).into());
        }
        let Some((dir, name)) = w.at else {
            return Err(Fail("NoParent", format!("{rel}'s directory does not exist")).into());
        };
        // After the hard refusals, so a write no size could make allowed says why.
        if size > cap {
            return Err(Refusal::TooBig { message: format!("{size} bytes is over the cap of {cap}"), size, cap });
        }
        let kind = put::kind_at(&dir, &name).map_err(io_fail)?;
        put::kind_refusal(&kind, rel)?;
        let mode = match (kind, &judged) {
            (put::Kind::Absent, None) => put::committed_mode(),
            (put::Kind::File(_), Some(b)) => {
                let Some((file, st)) = open_file(&dir, &name)? else { return Ok(changed(rel)?) };
                if st.st_nlink > 1 {
                    return Err(
                        Fail("HardLinked", format!("{rel} has another name: a write would change it too")).into()
                    );
                }
                if Basis::of(&file, &st).map_err(io_fail)? != *b {
                    return Ok(changed(rel)?);
                }
                Mode::from_raw_mode((st.st_mode & 0o777) as _)
            }
            _ => return Ok(changed(rel)?),
        };
        let full = self.path.join(rel);
        let staged = Staged::new(dir, &name, id, size, full, self.root.clone(), self.root_rel(rel));
        Ok(Stored { staged, mount: self.id.clone(), session: self.session.clone(), judged, mode, rel: rel.into() })
    }

    /// Deletes a regular file whose basis is the one judged. In `attached/` too: the worker asks first (H6).
    pub fn remove(&self, rel: &str, judged: Option<&Basis>) -> Result<Value, Fail> {
        self.require_writable()?;
        let parts = rel_parts(rel, false)?;
        let w = self.walk(&parts)?;
        if self.protected(rel) {
            return fail("Protected", format!("{rel} is a protected name, which no write may touch"));
        }
        let Some((dir, name)) = w.at else { return changed(rel) };
        put::kind_refusal(&put::kind_at(&dir, &name).map_err(io_fail)?, rel)?;
        same_basis(&dir, &name, judged, rel)?;
        rustix::fs::unlinkat(&dir, name.as_str(), AtFlags::empty()).map_err(io_fail)?;
        Ok(json!({ "mount": self.id, "path": rel, "removed": true }))
    }

    /// Renames a regular file to a name that is free, both in this mount and neither in `attached/`. A move across
    /// filesystems fails `EXDEV` and is never made a copy and a delete.
    pub fn rename(&self, from: &str, to: &str, judged: Option<&Basis>) -> Result<Value, Fail> {
        self.require_writable()?;
        let (fp, tp) = (rel_parts(from, false)?, rel_parts(to, false)?);
        let (fw, tw) = (self.walk(&fp)?, self.walk(&tp)?);
        if fw.in_attached || tw.in_attached {
            return fail("InAttached", "a rename into or out of attached/ is refused: the uploads as they were given");
        }
        if let Some(p) = [from, to].into_iter().find(|r| self.protected(r)) {
            return fail("Protected", format!("{p} is a protected name, which no write may touch"));
        }
        let Some((fdir, fname)) = fw.at else { return changed(from) };
        let Some((tdir, tname)) = tw.at else { return fail("NoParent", format!("{to}'s directory does not exist")) };
        put::kind_refusal(&put::kind_at(&fdir, &fname).map_err(io_fail)?, from)?;
        same_basis(&fdir, &fname, judged, from)?;
        match rename_noreplace_at(&fdir, &fname, &tdir, &tname) {
            Ok(()) => Ok(json!({ "mount": self.id, "from": from, "to": to })),
            Err(rustix::io::Errno::EXIST) => fail("Exists", format!("{to} exists")),
            Err(rustix::io::Errno::XDEV) => fail("EXDEV", format!("{from} and {to} are on different filesystems")),
            Err(e) => Err(io_fail(e)),
        }
    }
}

fn same_basis(dir: &OwnedFd, name: &str, judged: Option<&Basis>, rel: &str) -> Result<(), Fail> {
    let Some((file, st)) = open_file(dir, name)? else { return changed(rel) };
    if judged != Some(&Basis::of(&file, &st).map_err(io_fail)?) {
        return changed(rel);
    }
    Ok(())
}

/// [`put::rename_noreplace`] across two directories.
fn rename_noreplace_at(fd: &OwnedFd, from: &str, td: &OwnedFd, to: &str) -> Result<(), rustix::io::Errno> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    match rustix::fs::renameat_with(fd, from, td, to, rustix::fs::RenameFlags::NOREPLACE) {
        Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOSYS | rustix::io::Errno::NOTSUP) => {}
        other => return other,
    }
    rustix::fs::linkat(fd, from, td, to, AtFlags::empty())?;
    rustix::fs::unlinkat(fd, from, AtFlags::empty())
}

/// A store waiting for its bytes or its commit.
pub struct Stored {
    pub staged: Staged,
    pub mount: String,
    pub session: String,
    judged: Option<Basis>,
    mode: Mode,
    pub rel: String,
}

impl Stored {
    /// H8's compare and swap: with a judged basis the target must still be that file, alone (one link), and is
    /// replaced keeping its permission bits; without one the name must still be free. The residual: the compare and
    /// the rename are two steps, so a writer that lands between them is lost (FILE_ATTACHMENTS.md, H8).
    pub fn commit(&mut self) -> Result<String, Fail> {
        let (judged, rel) = (self.judged.clone(), self.rel.clone());
        self.staged.finish_as(self.mode, "ChangedSinceJudged", &mut |dir, name| match &judged {
            None => Ok(false),
            Some(b) => match open_file(dir, name)? {
                Some((file, st)) if st.st_nlink == 1 && Basis::of(&file, &st).map_err(io_fail)? == *b => Ok(true),
                _ => changed(&rel),
            },
        })
    }
}

// --- the basis ---

/// What a judgment was made on: a file's identity, size and modification time, and its sha256 at or under the diff
/// cap (FILE_ATTACHMENTS.md, H7 and H8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Basis {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i64,
    pub sha256: Option<String>,
}

#[allow(clippy::unnecessary_cast)]
fn mtime_ns(st: &Stat) -> i64 {
    (st.st_mtime as i64).saturating_mul(1_000_000_000).saturating_add(st.st_mtime_nsec as i64)
}

impl Basis {
    /// The basis of an open regular file, from its `fstat`, hashing it from the start when it is at or under the cap.
    pub fn of(file: &File, st: &Stat) -> io::Result<Basis> {
        let size = st.st_size as u64;
        let sha256 = if size <= DIFF_CAP {
            let mut h = Sha256::new();
            let (mut r, mut buf) = (ReadAt::new(file).take(DIFF_CAP + 1), vec![0u8; 64 * 1024]);
            loop {
                match r.read(&mut buf)? {
                    0 => break,
                    n => h.update(&buf[..n]),
                }
            }
            Some(hex::encode(h.finalize()))
        } else {
            None
        };
        let (dev, ino) = dev_ino(st);
        Ok(Basis { dev, ino, size, mtime_ns: mtime_ns(st), sha256 })
    }

    pub fn json(&self) -> Value {
        let mut v = json!({ "dev": self.dev, "ino": self.ino, "size": self.size, "mtimeNs": self.mtime_ns });
        if let Some(h) = &self.sha256 {
            v["sha256"] = json!(h);
        }
        v
    }

    /// Reads a basis the worker sends back; absent or null is `None`.
    pub fn parse(v: Option<&Value>) -> Result<Option<Basis>, Fail> {
        let bad = || Fail("BadRequest", "basis is { dev, ino, size, mtimeNs, sha256? } as stat gave it".into());
        let o = match v {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::Object(o)) => o,
            Some(_) => return Err(bad()),
        };
        let u = |k: &str| o.get(k).and_then(Value::as_u64).ok_or_else(bad);
        let sha256 = match o.get("sha256") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err(bad()),
        };
        let mtime_ns = o.get("mtimeNs").and_then(Value::as_i64).ok_or_else(bad)?;
        Ok(Some(Basis { dev: u("dev")?, ino: u("ino")?, size: u("size")?, mtime_ns, sha256 }))
    }
}

/// Opens regular file `name` in `dir` for reading, never through a symlink and never blocking on a FIFO: `None` when
/// it is absent or not a regular file now.
fn open_file(dir: &OwnedFd, name: &str) -> Result<Option<(File, Stat)>, Fail> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match rustix::fs::openat(dir, name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::LOOP) => return Ok(None),
        Err(e) => return Err(io_fail(e)),
    };
    let st = rustix::fs::fstat(&fd).map_err(io_fail)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Ok(None);
    }
    Ok(Some((File::from(fd), st)))
}

/// Reads a file from the start by position, leaving its offset alone, so one descriptor serves the hash and git.
struct ReadAt<'a> {
    file: &'a File,
    pos: u64,
}

impl<'a> ReadAt<'a> {
    fn new(file: &'a File) -> Self {
        ReadAt { file, pos: 0 }
    }
}

impl Read for ReadAt<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read_at(buf, self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- the path rule ---

    #[test]
    fn a_mount_relative_path_refuses_what_could_leave_or_alias_the_mount() {
        for bad in ["/a", "//srv/x", "a\\b", "C:x", "c:/x", "a//b", "a/./b", "a/../b", "..", "...", "a/", "a\0b"] {
            assert!(rel_parts(bad, true).is_err(), "{bad:?}");
        }
        assert_eq!(rel_parts("a/b.txt", false).unwrap(), ["a", "b.txt"]);
        assert_eq!(rel_parts(".env", false).unwrap(), [".env"]);
        assert!(rel_parts("", false).is_err());
        assert!(rel_parts("", true).unwrap().is_empty());
        assert!(rel_parts(&"a/".repeat(2049), true).is_err());
    }

    // --- what may be mounted ---

    fn limits<'a>(roots: &'a [PathBuf], home: &'a Path) -> Limits<'a> {
        Limits {
            reserved: RESERVED.iter().map(PathBuf::from).collect(),
            home: Some(home),
            forbidden: vec![home.join("Library/Application Support/Google/Chrome")],
            roots,
        }
    }

    #[test]
    fn a_mount_is_refused_at_under_or_above_what_it_must_not_reach() {
        let home = Path::new("/Users/p");
        let roots = [PathBuf::from("/Users/p/git"), PathBuf::from("/tmp"), PathBuf::from("/")];
        let l = limits(&roots, home);
        let refused = |p: &str, others: &[&Path]| mount_refusal(Path::new(p), &l, others);
        for p in ["/tmp", "/tmp/x", "/", "/home", "/home/pyodide/x", "/Users", "/Users/p"] {
            assert!(refused(p, &[]).is_some(), "{p}");
        }
        assert!(refused("/Users/p/Library/Application Support", &[]).is_some(), "above the profile");
        assert!(refused("/Users/p/Library/Application Support/Google/Chrome/Default", &[]).is_some());
        assert!(refused("/Users/p/git/proj", &[]).is_none());
        let other = Path::new("/Users/p/git/proj");
        assert!(refused("/Users/p/git/proj/sub", &[other]).is_some(), "under a mount of this session");
        assert!(refused("/Users/p/git", &[other]).is_some(), "above a mount of this session");
        assert!(refused("/Users/p/git/proj2", &[other]).is_none(), "a sibling by component");
        let only = [PathBuf::from("/Users/p/git")];
        let l2 = limits(&only, home);
        assert!(mount_refusal(Path::new("/Users/p/docs"), &l2, &[]).is_some(), "outside every root");
    }

    // --- the basis ---

    #[test]
    fn a_basis_reads_back_as_it_was_written_and_hashes_only_at_or_under_the_cap() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("s"), "hi").unwrap();
        let f = File::open(d.path().join("s")).unwrap();
        let st = rustix::fs::fstat(&f).unwrap();
        let b = Basis::of(&f, &st).unwrap();
        assert_eq!(b.sha256.as_deref(), Some("8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"));
        assert_eq!(Basis::parse(Some(&b.json())).unwrap(), Some(b));
        std::fs::write(d.path().join("big"), vec![0u8; DIFF_CAP as usize + 1]).unwrap();
        let f = File::open(d.path().join("big")).unwrap();
        assert_eq!(Basis::of(&f, &rustix::fs::fstat(&f).unwrap()).unwrap().sha256, None);
        assert_eq!(Basis::parse(None).unwrap(), None);
        assert!(Basis::parse(Some(&json!({ "dev": 1 }))).is_err());
    }
}
