//! walk.rs — what a recursive reader would reach: a bounded walk beneath a directory, never following a symlink, that
//! answers whether anything there looks like a secret. `rg pat .` reads `root/.env` without naming it; the free tier
//! needs to know (ruling of 2026-10-15, window-ml's SHELL.md).

use std::path::Path;

use crate::facts::looks_secret;

/// The most entries the walk looks at before answering "unknown".
pub const WALK_CAP: usize = 20_000;

/// `Some(true)` if `p`, or anything beneath it, looks like a secret; `Some(false)` if nothing does; `None` when the walk
/// passed `cap` entries or could not read a directory, which the worker treats as unknown. Symlinks are judged by
/// their name and never followed; `.git` directories are skipped (a recursive reader of a work tree skips them too,
/// and their size would spend the cap).
pub fn contains_secret(p: &Path, cap: usize) -> Option<bool> {
    if looks_secret(p) {
        return Some(true);
    }
    let md = std::fs::symlink_metadata(p).ok()?;
    if !md.is_dir() {
        return Some(false);
    }
    let mut stack = vec![p.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).ok()? {
            let entry = entry.ok()?;
            seen += 1;
            if seen > cap {
                return None;
            }
            let path = entry.path();
            if looks_secret(&path) {
                return Some(true);
            }
            let ft = entry.file_type().ok()?;
            if ft.is_dir() && entry.file_name() != ".git" {
                stack.push(path);
            }
        }
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- the bounded secret walk ---

    #[test]
    fn finds_a_nested_secret_and_answers_no_for_a_clean_tree() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("a/b")).unwrap();
        std::fs::write(d.path().join("a/b/main.rs"), "").unwrap();
        assert_eq!(contains_secret(d.path(), WALK_CAP), Some(false));
        std::fs::write(d.path().join("a/b/.env.local"), "K=V").unwrap();
        assert_eq!(contains_secret(d.path(), WALK_CAP), Some(true));
        assert_eq!(contains_secret(&d.path().join("a/b/main.rs"), WALK_CAP), Some(false));
        assert_eq!(contains_secret(&d.path().join("a/b/.env.local"), WALK_CAP), Some(true));
    }

    #[test]
    fn past_the_cap_it_is_unknown() {
        let d = tempfile::tempdir().unwrap();
        for i in 0..50 {
            std::fs::write(d.path().join(format!("f{i}")), "").unwrap();
        }
        assert_eq!(contains_secret(d.path(), 10), None);
        assert_eq!(contains_secret(d.path(), 100), Some(false));
    }

    #[test]
    fn a_symlinked_directory_is_not_followed_but_a_secret_name_still_counts() {
        let d = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("id_rsa"), "").unwrap();
        std::os::unix::fs::symlink(out.path(), d.path().join("elsewhere")).unwrap();
        assert_eq!(contains_secret(d.path(), WALK_CAP), Some(false), "the link's target is not walked");
        std::os::unix::fs::symlink(out.path().join("id_rsa"), d.path().join(".env")).unwrap();
        assert_eq!(contains_secret(d.path(), WALK_CAP), Some(true));
    }

    #[test]
    fn git_directories_are_skipped() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join(".git/x")).unwrap();
        std::fs::write(d.path().join(".git/x/server.key"), "").unwrap();
        assert_eq!(contains_secret(d.path(), WALK_CAP), Some(false));
    }
}
