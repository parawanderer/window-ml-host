//! snapshot_bounds.rs — what a snapshot leaves out of its tree, and what it says instead (window-ml's
//! FILE_ATTACHMENTS.md, H12).
//!
//! Only a captured file enters a snapshot's tree. A regular file over [`DIFF_CAP`] is left out and listed as a [`Big`]
//! with its size and sha256, so the report compares it by those (a diff of it would be no use and would write its body
//! into the private objects). A path that cannot be captured is listed as [`NotCaptured`] with its reason: a FIFO, a
//! socket or a device (found by name and type in a directory listing, never opened), a file that cannot be read, and
//! an untracked file whose name looks like a secret (H11, amended 2026-11-19).
//!
//! The sha256 of a big file is the host's own, read from a descriptor opened without following a link, and kept in
//! [`BigHashes`] by the file's whole stat (device, inode, size, both times to the nanosecond): a file whose stat is
//! unchanged since it was hashed is not read again, which is the same trust git puts in its stat cache. A snapshot
//! reads at most [`BIG_HASH_BUDGET`] bytes of files not in the cache; a big file past it is listed with its size and
//! no hash. At the 3 GB/s this machine's sha256 measured (`openssl speed -evp sha256`, Apple M5 Pro, 2026-11-19), the
//! budget is under a second of hashing a snapshot, and the cache makes the second snapshot of a call cost nothing for a
//! big file the call did not touch.

use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use sha2::{Digest, Sha256};

/// The largest file that enters a snapshot's tree and gets a diff: 1 MiB, the spec's "1 MB" ("The diff's cap").
pub const DIFF_CAP: u64 = 1 << 20;

/// The most bytes of big files, not already in the cache, one snapshot reads to hash.
pub const BIG_HASH_BUDGET: u64 = 2 << 30;

/// The most hashes [`BigHashes`] keeps; past it the cache starts again empty.
const CACHE_MAX: usize = 4096;

/// A regular file over [`DIFF_CAP`], left out of the tree: its size, whether it is executable, and its sha256 (hex),
/// `None` when the snapshot's hash budget ran out before it or the file changed while it was read.
#[derive(Debug, Clone, PartialEq)]
pub struct Big {
    pub path: Vec<u8>,
    pub size: u64,
    pub executable: bool,
    pub sha256: Option<String>,
}

/// A path the snapshot did not capture, and why.
#[derive(Debug, Clone, PartialEq)]
pub struct NotCaptured {
    pub path: Vec<u8>,
    pub reason: &'static str,
}

/// The reason for an untracked file whose path looks like a secret (`facts::looks_secret`).
pub const WITHHELD_NAME: &str = "withheld: the name looks like a secret";
/// The reason for a FIFO, a socket or a device.
pub const NOT_A_FILE: &str = "not a regular file";
/// The reason for a file the host could not open for reading.
pub const UNREADABLE: &str = "unreadable";

/// The stat a big file's hash is kept by.
type Basis = (u64, u64, u64, i64, i64, i64, i64);

fn basis(md: &std::fs::Metadata) -> Basis {
    (md.dev(), md.ino(), md.size(), md.mtime(), md.mtime_nsec(), md.ctime(), md.ctime_nsec())
}

/// Big files' sha256 by their stat, held by whoever takes a call's snapshots, and each snapshot's hash budget.
#[derive(Default)]
pub struct BigHashes {
    known: HashMap<Basis, String>,
    /// Bytes read for hashing since [`BigHashes::start`].
    spent: u64,
}

/// What reading a big file for its hash came to.
pub enum Hashed {
    Sha(Option<String>),
    Unreadable,
}

impl BigHashes {
    /// Starts a snapshot's budget.
    pub fn start(&mut self) {
        self.spent = 0;
    }

    /// The sha256 of the file at `path`, whose `lstat` was `md`: from the cache when its stat is unchanged, otherwise
    /// read from a descriptor opened with `O_NOFOLLOW | O_NONBLOCK` while the budget lasts. A file that is no longer
    /// the one `md` describes, before or after the read, gets no hash.
    pub fn sha256(&mut self, path: &Path, md: &std::fs::Metadata) -> Hashed {
        let b = basis(md);
        if let Some(h) = self.known.get(&b) {
            return Hashed::Sha(Some(h.clone()));
        }
        if self.spent.saturating_add(md.size()) > BIG_HASH_BUDGET {
            return Hashed::Sha(None);
        }
        let mut f = match open_nofollow(path) {
            Ok(f) => f,
            Err(_) => return Hashed::Unreadable,
        };
        if !f.metadata().is_ok_and(|m| m.is_file() && basis(&m) == b) {
            return Hashed::Sha(None);
        }
        self.spent += md.size();
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut left = md.size() + 1;
        loop {
            let want = buf.len().min(left as usize);
            match std::io::Read::read(&mut f, &mut buf[..want]) {
                Ok(0) => break,
                Ok(n) => {
                    h.update(&buf[..n]);
                    left -= n as u64;
                    if left == 0 {
                        return Hashed::Sha(None);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Hashed::Unreadable,
            }
        }
        if !f.metadata().is_ok_and(|m| basis(&m) == b) {
            return Hashed::Sha(None);
        }
        let hex = hex::encode(h.finalize());
        if self.known.len() >= CACHE_MAX {
            self.known.clear();
        }
        self.known.insert(b, hex.clone());
        Hashed::Sha(Some(hex))
    }
}

/// Opens `path` for reading without following a link and without blocking on a FIFO.
pub fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32;
    std::fs::OpenOptions::new().read(true).custom_flags(flags).open(path)
}

/// The FIFOs, sockets and devices directly inside each of `dirs` (work-tree-relative directories, `b""` the root),
/// as work-tree-relative paths. Each directory is opened without following a link, and an entry is judged by the type
/// its listing gives (an `lstat` of it when the file system gives none), so nothing found is ever opened. A directory
/// that cannot be opened is skipped: its files, if git listed any, are judged one by one.
pub fn special_files(root: &Path, dirs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    use rustix::fs::{FileType, OFlags};
    let mut found = vec![];
    for d in dirs {
        let abs = root.join(std::ffi::OsStr::from_bytes(d));
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let Ok(fd) = rustix::fs::open(&abs, flags, rustix::fs::Mode::empty()) else {
            continue;
        };
        let Ok(dir) = rustix::fs::Dir::read_from(&fd) else {
            continue;
        };
        for e in dir.flatten() {
            let name = e.file_name().to_bytes();
            if name == b"." || name == b".." || (d.is_empty() && name == b".git") {
                continue;
            }
            let kind = match e.file_type() {
                FileType::Unknown => rustix::fs::statat(&fd, e.file_name(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map(|st| FileType::from_raw_mode(st.st_mode as _))
                    .unwrap_or(FileType::Unknown),
                k => k,
            };
            if matches!(kind, FileType::Fifo | FileType::Socket | FileType::CharacterDevice | FileType::BlockDevice) {
                found.push(if d.is_empty() { name.to_vec() } else { [d.as_slice(), b"/", name].concat() });
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mkfifo(p: &Path) {
        assert!(std::process::Command::new("mkfifo").arg(p).status().unwrap().success());
    }

    #[test]
    fn a_big_files_hash_is_read_once_and_kept_by_its_stat() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("big.bin");
        std::fs::write(&p, vec![7u8; 3 << 20]).unwrap();
        let md = std::fs::symlink_metadata(&p).unwrap();
        let mut h = BigHashes::default();
        h.start();
        let Hashed::Sha(Some(a)) = h.sha256(&p, &md) else { panic!("hashed") };
        assert_eq!(a, hex::encode(Sha256::digest(vec![7u8; 3 << 20])));
        assert_eq!(h.spent, 3 << 20);
        h.start();
        let Hashed::Sha(Some(b)) = h.sha256(&p, &md) else { panic!("cached") };
        assert_eq!((a, h.spent), (b, 0), "an unchanged stat is answered from the cache, reading nothing");
    }

    #[test]
    fn past_the_budget_a_big_file_gets_no_hash() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("big.bin");
        std::fs::write(&p, vec![1u8; 2 << 20]).unwrap();
        let md = std::fs::symlink_metadata(&p).unwrap();
        let mut h = BigHashes { spent: BIG_HASH_BUDGET - (1 << 20), ..Default::default() };
        assert!(matches!(h.sha256(&p, &md), Hashed::Sha(None)));
    }

    #[test]
    fn a_file_changed_since_its_lstat_gets_no_hash() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("big.bin");
        std::fs::write(&p, vec![1u8; 2 << 20]).unwrap();
        let md = std::fs::symlink_metadata(&p).unwrap();
        std::fs::write(&p, vec![2u8; 2 << 20 | 1]).unwrap();
        let mut h = BigHashes::default();
        assert!(matches!(h.sha256(&p, &md), Hashed::Sha(None)));
        assert!(h.known.is_empty(), "nor is anything cached for it");
    }

    #[test]
    fn a_fifo_and_a_socket_are_found_by_type_and_a_linked_directory_is_not_followed() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("w");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        mkfifo(&root.join("sub/pipe"));
        let _sock = std::os::unix::net::UnixListener::bind(root.join("sock")).unwrap();
        std::fs::write(root.join("plain"), "x").unwrap();
        let outside = t.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        mkfifo(&outside.join("pipe"));
        std::os::unix::fs::symlink(&outside, root.join("linked")).unwrap();
        let mut got = special_files(&root, &[b"".to_vec(), b"sub".to_vec(), b"linked".to_vec()]);
        got.sort();
        assert_eq!(got, [b"sock".to_vec(), b"sub/pipe".to_vec()]);
    }
}
