//! glob.rs — host-side pattern expansion beneath one directory: `*`, `?`, `[abc]`, `[a-z]`, `[!abc]`, a whole-component
//! `**`, and a backslash escape. The matcher is component-wise on UTF-8 names. The walk is bounded, never follows a
//! symlink (every directory is opened by descriptor with `O_NOFOLLOW`, so a directory swapped for a link mid-walk
//! fails rather than redirects), skips `.git` directories, and has no way to leave its starting directory: the
//! pattern has no `..` and the walk only goes down.

use std::collections::BTreeSet;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};

/// The longest pattern accepted, in bytes.
pub const MAX_PATTERN: usize = 4096;
/// The deepest directory the walk enters (each level holds one descriptor open).
pub const MAX_DEPTH: usize = 64;

/// One glob character class or character, matching exactly one `char` of a name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Lit(char),
    One,
    Star,
    Class { negated: bool, ranges: Vec<(char, char)> },
}

impl Tok {
    /// Whether a non-`*` token accepts `c`.
    fn accepts(&self, c: char) -> bool {
        match self {
            Tok::Lit(l) => *l == c,
            Tok::One => true,
            Tok::Star => false,
            Tok::Class { negated, ranges } => ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&c)) != *negated,
        }
    }
}

/// One path component of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    toks: Vec<Tok>,
    /// The component starts with a literal `.`, so it may match a hidden name.
    dot: bool,
}

impl Component {
    fn parse(s: &str) -> Component {
        let cs: Vec<char> = s.chars().collect();
        let mut toks = Vec::new();
        let mut i = 0;
        while i < cs.len() {
            match cs[i] {
                '\\' => {
                    toks.push(Tok::Lit(cs.get(i + 1).copied().unwrap_or('\\')));
                    i += 2;
                }
                '*' => {
                    toks.push(Tok::Star);
                    i += 1;
                }
                '?' => {
                    toks.push(Tok::One);
                    i += 1;
                }
                '[' => match parse_class(&cs, i + 1) {
                    Some((tok, next)) => {
                        toks.push(tok);
                        i = next;
                    }
                    None => {
                        toks.push(Tok::Lit('['));
                        i += 1;
                    }
                },
                c => {
                    toks.push(Tok::Lit(c));
                    i += 1;
                }
            }
        }
        let dot = toks.first() == Some(&Tok::Lit('.'));
        Component { toks, dot }
    }

    /// Whether `name` matches. A name starting with `.` matches only a component that itself starts with a literal `.`.
    pub fn matches(&self, name: &str) -> bool {
        if name.starts_with('.') && !self.dot {
            return false;
        }
        let n: Vec<char> = name.chars().collect();
        let (mut t, mut i) = (0, 0);
        // Where the last `*` was, and how much of the name it has swallowed: every other token takes exactly one
        // character, so retrying from the latest `*` alone is complete, and the work is O(len(pattern) * len(name)).
        let mut star: Option<(usize, usize)> = None;
        while i < n.len() {
            match self.toks.get(t) {
                Some(Tok::Star) => {
                    star = Some((t, i));
                    t += 1;
                    continue;
                }
                Some(tok) if tok.accepts(n[i]) => {
                    t += 1;
                    i += 1;
                    continue;
                }
                _ => {}
            }
            let Some((st, si)) = star else { return false };
            t = st + 1;
            i = si + 1;
            star = Some((st, si + 1));
        }
        self.toks[t..].iter().all(|k| *k == Tok::Star)
    }
}

/// A class starting just after its `[`: `!` negates, a leading `]` is a member, `a-z` is a range, a backslash escapes.
/// `None` when it never closes (the `[` is then a plain character, as in a shell).
fn parse_class(cs: &[char], mut i: usize) -> Option<(Tok, usize)> {
    let negated = cs.get(i) == Some(&'!');
    if negated {
        i += 1;
    }
    let mut ranges = Vec::new();
    let mut first = true;
    loop {
        let c = *cs.get(i)?;
        if c == ']' && !first {
            return Some((Tok::Class { negated, ranges }, i + 1));
        }
        first = false;
        let (lo, after) = if c == '\\' { (*cs.get(i + 1)?, i + 2) } else { (c, i + 1) };
        // `a-z`, but a `-` right before the closing `]` is a plain member
        if cs.get(after) == Some(&'-') && cs.get(after + 1).is_some_and(|n| *n != ']') {
            let (hi, next) =
                if cs[after + 1] == '\\' { (*cs.get(after + 2)?, after + 3) } else { (cs[after + 1], after + 2) };
            ranges.push((lo, hi));
            i = next;
        } else {
            ranges.push((lo, lo));
            i = after;
        }
    }
}

/// One step of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seg {
    /// A whole-component `**`: zero or more directories.
    Globstar,
    Name(Component),
}

/// A validated pattern, split on `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    segs: Vec<Seg>,
}

impl Pattern {
    /// Validates and compiles `s`: non-empty, at most [`MAX_PATTERN`] bytes, no NUL, not absolute, and no component
    /// that is empty, `.` or `..`. The error says which rule it broke.
    pub fn parse(s: &str) -> Result<Pattern, String> {
        if s.is_empty() {
            return Err("pattern is non-empty".into());
        }
        if s.len() > MAX_PATTERN {
            return Err(format!("pattern is at most {MAX_PATTERN} bytes"));
        }
        if s.contains('\0') {
            return Err("pattern has no NUL".into());
        }
        if s.starts_with('/') {
            return Err("pattern is relative to cwd, not absolute".into());
        }
        let mut segs: Vec<Seg> = Vec::new();
        for comp in s.split('/') {
            match comp {
                "" => return Err("pattern has no empty component (no `//`, no trailing `/`)".into()),
                "." | ".." => return Err(format!("pattern has no `{comp}` component")),
                "**" => {
                    // `**/**` is `**`
                    if segs.last() != Some(&Seg::Globstar) {
                        segs.push(Seg::Globstar);
                    }
                }
                c => segs.push(Seg::Name(Component::parse(c))),
            }
        }
        Ok(Pattern { segs })
    }
}

/// What an expansion found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Expansion {
    /// Paths relative to the starting directory, `/`-separated, sorted bytewise, without duplicates.
    pub matches: Vec<String>,
    /// The walk stopped early: `limit` matches, `cap` entries, or [`MAX_DEPTH`] reached.
    pub truncated: bool,
}

/// One directory entry the walk considers.
struct Entry {
    name: String,
    /// A real directory; a symlink to one is not.
    dir: bool,
}

struct Walk {
    found: BTreeSet<String>,
    limit: usize,
    cap: usize,
    seen: usize,
    truncated: bool,
    stop: bool,
}

/// Expands `pat` beneath `cwd`: at most `limit` matches, looking at most `cap` directory entries. A directory that
/// cannot be read is skipped. Directories and files both match; a symlink may match by name as the last component and
/// is never entered; `.git` directories are skipped; hidden names follow the shell rule ([`Component::matches`]), and
/// `**` never enters or matches a hidden directory. A trailing `**` matches the directory it follows and every visible
/// directory beneath it, not files.
pub fn expand(cwd: &Path, pat: &Pattern, limit: usize, cap: usize) -> Expansion {
    let mut w = Walk { found: BTreeSet::new(), limit, cap, seen: 0, truncated: false, stop: false };
    if let Ok(fd) = rustix::fs::open(cwd, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()) {
        w.dir(&fd, "", &pat.segs, 0);
    }
    Expansion { matches: w.found.into_iter().collect(), truncated: w.truncated }
}

impl Walk {
    fn dir(&mut self, fd: &OwnedFd, rel: &str, segs: &[Seg], depth: usize) {
        if self.stop {
            return;
        }
        if depth > MAX_DEPTH {
            self.truncated = true;
            return;
        }
        let entries = self.list(fd);
        match &segs[0] {
            Seg::Name(c) => self.apply(&entries, fd, rel, c, &segs[1..], depth),
            Seg::Globstar => {
                match segs.get(1) {
                    // zero directories: the rest of the pattern against this one
                    Some(Seg::Name(c)) => self.apply(&entries, fd, rel, c, &segs[2..], depth),
                    // the directory itself, when nothing follows (consecutive ** are folded at parse)
                    None if !rel.is_empty() => self.emit(rel.to_string()),
                    _ => {}
                }
                for e in entries.iter().filter(|e| e.dir && !e.name.starts_with('.')) {
                    if self.stop {
                        return;
                    }
                    if let Some(child) = open_dir(fd, &e.name) {
                        self.dir(&child, &join(rel, &e.name), segs, depth + 1);
                    }
                }
            }
        }
    }

    /// `comp` against each entry: the last component of the pattern emits a match, an earlier one enters a directory.
    fn apply(&mut self, entries: &[Entry], fd: &OwnedFd, rel: &str, comp: &Component, after: &[Seg], depth: usize) {
        for e in entries.iter().filter(|e| comp.matches(&e.name)) {
            if self.stop {
                return;
            }
            if after.is_empty() {
                self.emit(join(rel, &e.name));
            } else if e.dir
                && let Some(child) = open_dir(fd, &e.name)
            {
                self.dir(&child, &join(rel, &e.name), after, depth + 1);
            }
        }
    }

    fn emit(&mut self, path: String) {
        if self.found.contains(&path) {
            return;
        }
        if self.found.len() >= self.limit {
            self.truncated = true;
            self.stop = true;
            return;
        }
        self.found.insert(path);
    }

    /// The entries of one directory in name order, minus `.git` directories and names that are not UTF-8. Every entry
    /// counts toward the cap, those too.
    fn list(&mut self, fd: &OwnedFd) -> Vec<Entry> {
        let Ok(dir) = Dir::read_from(fd) else { return vec![] };
        let mut out = Vec::new();
        for e in dir {
            let Ok(e) = e else { continue };
            let raw = e.file_name().to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            self.seen += 1;
            if self.seen > self.cap {
                self.truncated = true;
                self.stop = true;
                return vec![];
            }
            let Ok(name) = std::str::from_utf8(raw) else { continue };
            let ft = match e.file_type() {
                FileType::Unknown => rustix::fs::statat(fd, e.file_name(), AtFlags::SYMLINK_NOFOLLOW)
                    .map(|st| FileType::from_raw_mode(st.st_mode))
                    .unwrap_or(FileType::Unknown),
                t => t,
            };
            let dir = ft == FileType::Directory;
            if dir && name == ".git" {
                continue;
            }
            out.push(Entry { name: name.to_string(), dir });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

/// Opens the subdirectory `name` of `fd`, refusing a symlink.
fn open_dir(fd: &impl AsFd, name: &str) -> Option<OwnedFd> {
    rustix::fs::openat(fd, name, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
        .ok()
}

fn join(rel: &str, name: &str) -> String {
    if rel.is_empty() { name.to_string() } else { format!("{rel}/{name}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pat: &str, name: &str) -> bool {
        Component::parse(pat).matches(name)
    }

    // --- one component ---

    #[test]
    fn star_and_question_match_runs_and_single_characters() {
        assert!(m("*.rs", "main.rs"));
        assert!(!m("*.rs", ".rs"), "a hidden name");
        assert!(m("a*b*c", "aXXbYYc"));
        assert!(!m("a*b*c", "aXXbYY"));
        assert!(m("*", "anything"));
        assert!(m("*", ""));
        assert!(m("a?c", "abc"));
        assert!(!m("a?c", "ac"));
        assert!(!m("a?c", "abbc"));
        assert!(m("é?", "éü"), "a character is one char, not one byte");
        // the backtracking case that is exponential in a naive matcher
        assert!(!m("*a*a*a*a*a*a*a*a*b", &"a".repeat(200)));
    }

    #[test]
    fn classes_ranges_and_negation() {
        assert!(m("[abc]", "b"));
        assert!(!m("[abc]", "d"));
        assert!(m("[a-c]x", "bx"));
        assert!(!m("[a-c]x", "dx"));
        assert!(m("[!abc]", "d"));
        assert!(!m("[!abc]", "a"));
        assert!(m("[]a]", "]"), "a leading ] is a member");
        assert!(m("[a-]", "-"), "a trailing - is a member");
        assert!(m("[!]]", "x"));
        assert!(m("[a-cx-z]", "y"));
        assert!(!m("[c-a]", "b"), "an inverted range is empty");
        assert!(m("[\\]]", "]"), "a backslash escapes inside a class");
        // unterminated: the [ is a plain character
        assert!(m("[abc", "[abc"));
        assert!(!m("[abc", "a"));
    }

    #[test]
    fn a_backslash_makes_the_next_character_literal() {
        assert!(m("\\*", "*"));
        assert!(!m("\\*", "x"));
        assert!(m("a\\?b", "a?b"));
        assert!(!m("a\\?b", "axb"));
        assert!(m("\\[x]", "[x]"));
        assert!(m("a\\\\b", "a\\b"));
        assert!(m("abc\\", "abc\\"), "a trailing backslash is itself");
    }

    #[test]
    fn a_hidden_name_needs_a_pattern_that_starts_with_a_dot() {
        assert!(!m("*", ".env"));
        assert!(!m("?env", ".env"));
        assert!(!m("[.]env", ".env"));
        assert!(!m("*env", ".env"));
        assert!(m(".*", ".env"));
        assert!(m(".env", ".env"));
        assert!(m("\\.env", ".env"));
        assert!(m("*", "env"));
    }

    // --- the pattern ---

    #[test]
    fn a_pattern_is_validated() {
        for bad in ["", "/abs", "a//b", "a/", "a/../b", "..", "./a", "a/./b", "a\0b", &"a".repeat(MAX_PATTERN + 1)] {
            assert!(Pattern::parse(bad).is_err(), "{bad:?}");
        }
        for good in ["a", "**", "src/**/*.rs", "..a", "a..", "...", &"a".repeat(MAX_PATTERN)] {
            assert!(Pattern::parse(good).is_ok(), "{good:?}");
        }
        // only a whole component is a globstar
        let p = Pattern::parse("a**b/**/**").unwrap();
        assert!(matches!(p.segs[0], Seg::Name(_)));
        assert_eq!(p.segs[1..], [Seg::Globstar]);
    }

    // --- expansion ---

    fn tree(files: &[&str]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for f in files {
            let p = d.path().join(f);
            if f.ends_with('/') {
                std::fs::create_dir_all(p).unwrap();
            } else {
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(p, "").unwrap();
            }
        }
        d
    }

    fn go(d: &tempfile::TempDir, pat: &str) -> Vec<String> {
        expand(d.path(), &Pattern::parse(pat).unwrap(), 1000, 1000).matches
    }

    #[test]
    fn globstar_at_the_start_the_middle_and_the_end() {
        let d = tree(&["a.rs", "src/b.rs", "src/x/c.rs", "src/x/y/d.rs", "src/x/y/e.txt", ".hid/f.rs", "src/.h/g.rs"]);
        assert_eq!(go(&d, "**/*.rs"), ["a.rs", "src/b.rs", "src/x/c.rs", "src/x/y/d.rs"]);
        assert_eq!(go(&d, "src/**/*.rs"), ["src/b.rs", "src/x/c.rs", "src/x/y/d.rs"]);
        assert_eq!(go(&d, "src/**/y/*.rs"), ["src/x/y/d.rs"]);
        assert_eq!(go(&d, "src/**"), ["src", "src/x", "src/x/y"], "a trailing ** is the directories, itself included");
        assert_eq!(go(&d, "**/f.rs"), Vec::<String>::new(), "** does not enter hidden directories");
        assert_eq!(go(&d, "**/g.rs"), Vec::<String>::new());
        assert_eq!(go(&d, "**/.hid"), [".hid"], "but a component that names one matches it");
        assert_eq!(go(&d, ".hid/*.rs"), [".hid/f.rs"], "but a pattern can name one");
        assert_eq!(go(&d, "**/**/b.rs"), ["src/b.rs"]);
    }

    #[test]
    fn directories_and_files_both_match_and_results_are_sorted() {
        let d = tree(&["src/b", "src/a/", "src/c/inner"]);
        assert_eq!(go(&d, "src/*"), ["src/a", "src/b", "src/c"]);
        assert_eq!(go(&d, "s*/[a-b]"), ["src/a", "src/b"]);
        assert_eq!(go(&d, "nothing/*"), Vec::<String>::new());
    }

    #[test]
    fn the_limit_and_the_entry_cap_truncate() {
        let d = tree(&["f1", "f2", "f3", "f4", "f5"]);
        let p = Pattern::parse("f*").unwrap();
        let e = expand(d.path(), &p, 3, 100);
        assert_eq!((e.matches.len(), e.truncated), (3, true));
        let e = expand(d.path(), &p, 5, 100);
        assert_eq!((e.matches.len(), e.truncated), (5, false), "exactly the limit is not truncation");
        let e = expand(d.path(), &p, 100, 3);
        assert!(e.truncated);
        assert!(e.matches.len() < 5);
    }

    #[test]
    fn a_symlink_may_match_as_a_leaf_but_is_never_entered() {
        let d = tree(&["real/inside.txt"]);
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("secret.txt"), "").unwrap();
        std::os::unix::fs::symlink(out.path(), d.path().join("link")).unwrap();
        assert_eq!(go(&d, "*"), ["link", "real"]);
        assert_eq!(go(&d, "link/*"), Vec::<String>::new());
        assert_eq!(go(&d, "**/*.txt"), ["real/inside.txt"]);
    }

    #[test]
    fn git_directories_are_skipped() {
        let d = tree(&[".git/config", "a/.git/config", "a/b"]);
        assert_eq!(go(&d, ".*"), Vec::<String>::new());
        assert_eq!(go(&d, ".git/*"), Vec::<String>::new());
        assert_eq!(go(&d, "a/.*"), Vec::<String>::new());
        assert_eq!(go(&d, "**/*"), ["a", "a/b"]);
    }

    #[test]
    fn a_missing_start_directory_finds_nothing() {
        let d = tempfile::tempdir().unwrap();
        let p = Pattern::parse("*").unwrap();
        assert_eq!(expand(&d.path().join("gone"), &p, 10, 10), Expansion::default());
    }
}
