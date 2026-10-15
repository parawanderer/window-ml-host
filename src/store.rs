//! store.rs — output held at the host: each stream of each call is a file in a per-session directory, named by an
//! opaque pointer, hashed and size-capped as it is written, read back by byte range. The directory is private (0700),
//! hidden from every child by the sandbox, and deleted when the session ends.

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::fsx;

/// The most one `read` returns: 512 KiB, which is 683 KiB as base64, inside a 1 MiB native message.
pub const MAX_READ: u64 = 512 * 1024;

/// One held stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub size: u64,
    /// Hex SHA-256 of the bytes kept.
    pub sha256: String,
    /// The stream passed the cap; the first `size` bytes were kept and the rest drained.
    pub truncated: bool,
}

/// A session's held output and its calls' temp directories.
pub struct Store {
    dir: PathBuf,
    out: PathBuf,
    tmp: PathBuf,
    held: Mutex<HashMap<String, Held>>,
}

/// A fresh random hex string of `bytes` bytes.
pub fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).expect("the OS random source");
    hex::encode(b)
}

impl Store {
    /// Creates the session directory under `base` (the system temp dir in production): private, with `out/` for held
    /// output and `tmp/` for the calls' temp directories.
    pub fn create(base: &Path) -> io::Result<Store> {
        let dir = base.canonicalize()?.join(format!("wmlhost-{}-{}", std::process::id(), random_hex(8)));
        let mut b = std::fs::DirBuilder::new();
        b.mode(0o700);
        b.create(&dir)?;
        b.create(dir.join("out"))?;
        b.create(dir.join("tmp"))?;
        Ok(Store { out: dir.join("out"), tmp: dir.join("tmp"), dir, held: Mutex::new(HashMap::new()) })
    }

    /// The directory a child must never read or write (the sandbox hides it).
    pub fn out_dir(&self) -> &Path {
        &self.out
    }

    /// A private temp directory for one call, its `TMPDIR`.
    pub fn call_tmp(&self, id: &str) -> io::Result<PathBuf> {
        let p = self.tmp.join(id);
        std::fs::DirBuilder::new().mode(0o700).create(&p)?;
        Ok(p)
    }

    pub fn remove_call_tmp(&self, id: &str) {
        let _ = std::fs::remove_dir_all(self.tmp.join(id));
    }

    /// Reads `stream` to its end into a new held file: keeps at most `cap` bytes, drains the rest so the writer is
    /// never blocked, and returns the pointer.
    pub async fn capture<R: AsyncRead + Unpin>(&self, mut stream: R, cap: u64) -> io::Result<(String, Held)> {
        let name = random_hex(16);
        let mut f = tokio::fs::OpenOptions::new().write(true).create_new(true).open(self.out.join(&name)).await?;
        let mut hash = Sha256::new();
        let (mut kept, mut truncated) = (0u64, false);
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let room = cap.saturating_sub(kept) as usize;
            let take = n.min(room);
            if take < n {
                truncated = true;
            }
            if take > 0 {
                f.write_all(&buf[..take]).await?;
                hash.update(&buf[..take]);
                kept += take as u64;
            }
        }
        f.flush().await?;
        let held = Held { size: kept, sha256: hex::encode(hash.finalize()), truncated };
        let ptr = format!("out:{name}");
        self.held.lock().unwrap().insert(ptr.clone(), held.clone());
        Ok((ptr, held))
    }

    /// The bytes `[offset, offset + length)` of a held stream (`length` capped at [`MAX_READ`]), its size, and whether
    /// the range reached the end. `None` for a pointer this session does not hold. The file is opened by descriptor
    /// beneath `out/`, never through a symlink.
    pub fn read(&self, ptr: &str, offset: u64, length: u64) -> Option<io::Result<(Vec<u8>, u64, bool)>> {
        let size = self.held.lock().unwrap().get(ptr)?.size;
        let name = ptr.strip_prefix("out:")?;
        Some((|| {
            let mut f = fsx::open_beneath(&self.out, Path::new(name))?;
            let start = offset.min(size);
            let len = length.min(MAX_READ).min(size - start);
            f.seek(SeekFrom::Start(start))?;
            let mut buf = vec![0u8; len as usize];
            f.read_exact(&mut buf)?;
            Ok((buf, size, start + len >= size))
        })())
    }

    /// Forgets and deletes a held stream. False if it was not held.
    pub fn release(&self, ptr: &str) -> bool {
        let Some(_) = self.held.lock().unwrap().remove(ptr) else { return false };
        if let Some(name) = ptr.strip_prefix("out:") {
            let _ = std::fs::remove_file(self.out.join(name));
        }
        true
    }

    /// Deletes everything. Also run on drop.
    pub fn cleanup(&self) {
        self.held.lock().unwrap().clear();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- held output ---

    #[tokio::test]
    async fn capture_then_read_in_ranges() {
        let base = tempfile::tempdir().unwrap();
        let s = Store::create(base.path()).unwrap();
        let data: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
        let (ptr, held) = s.capture(&data[..], 10 << 20).await.unwrap();
        assert_eq!(held.size, data.len() as u64);
        assert!(!held.truncated);
        assert_eq!(held.sha256, hex::encode(Sha256::digest(&data)));
        let mut got = Vec::new();
        let mut off = 0;
        loop {
            let (chunk, size, eof) = s.read(&ptr, off, u64::MAX).unwrap().unwrap();
            assert!(chunk.len() as u64 <= MAX_READ);
            assert_eq!(size, data.len() as u64);
            off += chunk.len() as u64;
            got.extend(chunk);
            if eof {
                break;
            }
        }
        assert_eq!(got, data);
    }

    #[tokio::test]
    async fn the_cap_keeps_the_head_and_marks_truncation() {
        let base = tempfile::tempdir().unwrap();
        let s = Store::create(base.path()).unwrap();
        let (ptr, held) = s.capture(&b"0123456789"[..], 4).await.unwrap();
        assert_eq!(held, Held { size: 4, sha256: hex::encode(Sha256::digest(b"0123")), truncated: true });
        assert_eq!(s.read(&ptr, 0, 100).unwrap().unwrap().0, b"0123");
    }

    #[tokio::test]
    async fn unknown_and_released_pointers_read_as_none() {
        let base = tempfile::tempdir().unwrap();
        let s = Store::create(base.path()).unwrap();
        assert!(s.read("out:00", 0, 1).is_none());
        assert!(s.read("../etc/passwd", 0, 1).is_none());
        let (ptr, _) = s.capture(&b"x"[..], 10).await.unwrap();
        assert!(s.release(&ptr));
        assert!(!s.release(&ptr));
        assert!(s.read(&ptr, 0, 1).is_none());
    }

    #[test]
    fn the_session_dir_is_private_and_removed_on_drop() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let dir;
        {
            let s = Store::create(base.path()).unwrap();
            dir = s.dir.clone();
            assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        }
        assert!(!dir.exists());
    }
}
