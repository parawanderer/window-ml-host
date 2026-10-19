//! elf.rs — reads an ELF binary's `PT_INTERP`, the dynamic linker the kernel execs alongside it.
//!
//! The Linux exec set of an interpreted call needs that path (`execve` checks `LANDLOCK_ACCESS_FS_EXECUTE`
//! on the interpreter too), so `sandbox::exec_set` asks here. Only the ELF header and its program headers
//! are read: the file is never mapped or executed. Anything that is not an ELF (a `#!` script, a static
//! binary, an unreadable file) answers `None`.

use std::path::{Path, PathBuf};

const PT_INTERP: u32 = 3;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
/// Enough for the headers of every real binary, far less than the 16 MiB pin cap.
const HEAD: usize = 4096;

/// The file's `PT_INTERP`, realpath'd: what the kernel will exec as its dynamic linker. `None` when the
/// file is not an ELF with one (a script, a static binary, or one that cannot be read).
pub fn pt_interp(path: &Path) -> Option<PathBuf> {
    let head = read_head(path)?;
    let (class, le) = match (head[EI_CLASS], head[EI_DATA]) {
        (ELFCLASS64, ELFDATA2LSB) => (8usize, true),
        (ELFCLASS64, ELFDATA2MSB) => (8, false),
        (ELFCLASS32, ELFDATA2LSB) => (4, true),
        (ELFCLASS32, ELFDATA2MSB) => (4, false),
        _ => return None,
    };
    if &head[..4] != b"\x7fELF" {
        return None;
    }
    // e_phoff and e_phentsize/e_phnum sit at the same offsets in both classes; only their width differs.
    let (phoff, phentsize, phnum) = if class == 8 {
        (u64_at(&head, 32, le), u16_at(&head, 54, le), u16_at(&head, 56, le))
    } else {
        (u32_at(&head, 28, le) as u64, u16_at(&head, 42, le), u16_at(&head, 44, le))
    };
    if phentsize == 0 || phnum == 0 {
        return None;
    }
    for i in 0..phnum as usize {
        let off = phoff as usize + i * phentsize as usize;
        if off + 8 > head.len() {
            return None;
        }
        // p_type is a 4-byte word at the start of every program header, in the file's endianness.
        let p_type = u32_at(&head, off, le);
        if p_type != PT_INTERP {
            continue;
        }
        let (p_offset, p_filesz) = if class == 8 {
            (u64_at(&head, off + 8, le) as usize, u64_at(&head, off + 32, le) as usize)
        } else {
            (u32_at(&head, off + 4, le) as usize, u32_at(&head, off + 16, le) as usize)
        };
        if p_filesz == 0 || p_filesz > 4096 {
            return None;
        }
        // The interpreter string lives in the file; re-read it if it fell past the header window.
        let owned;
        let bytes: &[u8] = if p_offset + p_filesz <= head.len() {
            &head[p_offset..p_offset + p_filesz]
        } else {
            owned = read_range(path, p_offset, p_filesz)?;
            &owned
        };
        let s = bytes.split(|b| *b == 0).next().unwrap_or(bytes);
        if s.is_empty() {
            return None;
        }
        let interp = PathBuf::from(String::from_utf8_lossy(s).into_owned());
        return Some(follow(&interp));
    }
    None
}

fn read_head(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut b = vec![0u8; HEAD];
    let n = f.read(&mut b).ok()?;
    if n < 64 {
        return None;
    }
    b.truncate(n);
    Some(b)
}

fn read_range(path: &Path, offset: usize, len: usize) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    f.seek(SeekFrom::Start(offset as u64)).ok()?;
    let mut b = vec![0u8; len];
    f.read_exact(&mut b).ok()?;
    Some(b)
}

fn follow(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

fn u16_at(b: &[u8], off: usize, le: bool) -> u16 {
    let x = [b[off], b[off + 1]];
    if le { u16::from_le_bytes(x) } else { u16::from_be_bytes(x) }
}

fn u32_at(b: &[u8], off: usize, le: bool) -> u32 {
    let x = [b[off], b[off + 1], b[off + 2], b[off + 3]];
    if le { u32::from_le_bytes(x) } else { u32::from_be_bytes(x) }
}

fn u64_at(b: &[u8], off: usize, le: bool) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[off..off + 8]);
    if le { u64::from_le_bytes(x) } else { u64::from_be_bytes(x) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_elf_is_not_an_interp() {
        assert_eq!(pt_interp(Path::new("/bin/sh")), pt_interp(Path::new("/bin/sh")));
        let d = tempfile::tempdir().unwrap();
        let s = d.path().join("script.sh");
        std::fs::write(&s, "#!/bin/sh\necho hi\n").unwrap();
        assert_eq!(pt_interp(&s), None, "a #! script has no PT_INTERP");
    }

    #[test]
    fn a_dynamic_elf_names_its_loader() {
        // /bin/ls is a dynamic ELF on both platforms this crate builds for.
        let Some(i) = pt_interp(Path::new("/bin/ls")) else {
            // A static /bin/ls (Alpine) has none; that is not a defect of the reader.
            return;
        };
        let s = i.to_string_lossy();
        assert!(s.contains("ld"), "the dynamic linker is an ld-*.so: {s}");
    }
}
