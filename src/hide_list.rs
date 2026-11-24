//! hide_list.rs — the host's copy of the extension's file-hiding rule (`src/files-hide.ts`): which paths a `hide` or a
//! `show` pattern names, and the Seatbelt regex and bounded walk the sandbox is built from. PARITY with the extension
//! is the point: a host matcher that matched fewer paths would leave a hidden file readable. So this follows the
//! extension, not [`crate::glob`]: a `*` matches a leading `.` (`*` matches `.env`), a pattern is absolute, matches
//! segment by segment with the same segment count, is case-sensitive, and has no `**`. A `hide` that matches a directory
//! holds everything under it ([`Pattern::holds`]); a `show` uses [`Pattern::matches`] only. The walk never follows a
//! symlink, skips no name (`.git` included), and is bounded.

use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};

use crate::glob::MAX_DEPTH;

/// The longest pattern an entry may have, in characters (UTF-16 code units, as the extension counts).
pub const PATTERN_MAX: usize = 512;
/// The most entries one scope (session or global) may hold.
pub const ENTRIES_MAX: usize = 256;

/// The most non-ASCII characters one class is spelled out with in [`Pattern::sbpl_regex`]; past it a `hide`'s class is
/// any one character and a `show`'s is its ASCII part, each erring its own safe way.
const CLASS_NON_ASCII_MAX: usize = 256;

const CREDENTIAL_DIRS: [&str; 8] =
    [".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".password-store", "Keychains"];
const CREDENTIAL_CONFIG_DIRS: [&str; 2] = ["gcloud", "gh"];

/// Whether an entry holds what it matches (`Hide`) or releases a hold on it (`Show`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Makes a file unreadable and unwritable.
    Hide,
    /// Releases a file the sandbox holds by default.
    Show,
}

/// One `hide` or `show` entry: its id, its effect and its compiled pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The entry's id, as the extension names it.
    pub id: String,
    /// Whether it hides or shows.
    pub effect: Effect,
    /// The compiled pattern.
    pub pattern: Pattern,
}

impl Entry {
    /// Compiles `source` for `effect` (so a `show` over a credential directory is refused) into an entry.
    pub fn new(id: &str, effect: Effect, source: &str) -> Result<Entry, String> {
        Ok(Entry { id: id.to_string(), effect, pattern: compile_as(source, effect)? })
    }
}

/// One glob token of a segment, matching exactly one `char` except `Any`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Lit(char),
    One,
    Any,
    Cls { neg: bool, ranges: Vec<(u32, u32)> },
}

/// A compiled absolute pattern: its path segments, each a list of glob tokens. The first segment is the empty one
/// before the leading `/`, so a pattern and a path are compared segment for segment, as the extension does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    segs: Vec<Vec<Tok>>,
}

/// Parses one segment into tokens, and says whether a `[` was left unclosed (that `[` is then a literal).
fn parse_seg(seg: &str) -> (Vec<Tok>, bool) {
    let chars: Vec<char> = seg.chars().collect();
    let mut toks = Vec::new();
    let mut unclosed = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '*' => {
                toks.push(Tok::Any);
                i += 1;
            }
            '?' => {
                toks.push(Tok::One);
                i += 1;
            }
            '[' => {
                let mut j = i + 1;
                let mut neg = false;
                if matches!(chars.get(j), Some('!' | '^')) {
                    neg = true;
                    j += 1;
                }
                let start = j;
                if chars.get(j) == Some(&']') {
                    j += 1; // a ] first in the class is a literal member
                }
                while j < chars.len() && chars[j] != ']' {
                    j += 1;
                }
                if j >= chars.len() {
                    unclosed = true;
                    toks.push(Tok::Lit(c));
                    i += 1;
                } else {
                    let body = &chars[start..j];
                    let mut ranges = Vec::new();
                    let mut m = 0;
                    while m < body.len() {
                        let lo = body[m] as u32;
                        if body.get(m + 1) == Some(&'-') && m + 2 < body.len() {
                            ranges.push((lo, body[m + 2] as u32));
                            m += 3;
                        } else {
                            ranges.push((lo, lo));
                            m += 1;
                        }
                    }
                    toks.push(Tok::Cls { neg, ranges });
                    i = j + 1;
                }
            }
            _ => {
                toks.push(Tok::Lit(c));
                i += 1;
            }
        }
    }
    (toks, unclosed)
}

/// Whether one single-character token accepts the character.
fn accepts(t: &Tok, ch: char) -> bool {
    match t {
        Tok::Lit(c) => *c == ch,
        Tok::One => true,
        Tok::Cls { neg, ranges } => {
            let cp = ch as u32;
            ranges.iter().any(|&(lo, hi)| cp >= lo && cp <= hi) != *neg
        }
        Tok::Any => false,
    }
}

/// Whether one segment's tokens match one segment, by a dynamic program over tokens and characters (no backtracking).
fn seg_match(toks: &[Tok], seg: &str) -> bool {
    let s: Vec<char> = seg.chars().collect();
    let mut cur = vec![false; s.len() + 1];
    cur[0] = true;
    for t in toks {
        let mut next = vec![false; s.len() + 1];
        if *t == Tok::Any {
            next[0] = cur[0];
            for j in 1..=s.len() {
                next[j] = cur[j] || next[j - 1];
            }
        } else {
            for j in 1..=s.len() {
                next[j] = cur[j - 1] && accepts(t, s[j - 1]);
            }
        }
        cur = next;
    }
    cur[s.len()]
}

/// Whether the pattern text `pattern` (one segment) matches `seg`.
fn seg_pat_match(pattern: &str, seg: &str) -> bool {
    seg_match(&parse_seg(pattern).0, seg)
}

/// The reason a pattern is refused, or `None` when it is fine: empty, too long, not absolute, `**`, a dot or empty
/// segment, an unclosed `[`, a control character, and for a `show` one that could release a credential directory.
pub fn refusal(source: &str, effect: Effect) -> Option<String> {
    if source.is_empty() {
        return Some("the pattern is empty".into());
    }
    if source.encode_utf16().count() > PATTERN_MAX {
        return Some(format!("the pattern is longer than {PATTERN_MAX} characters"));
    }
    if source.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}') {
        return Some("the pattern holds a control character".into());
    }
    if !source.starts_with('/') {
        return Some("the pattern must be an absolute path starting with /".into());
    }
    if source.contains("**") {
        return Some("** is not supported (a pattern matches within one path segment)".into());
    }
    let segs: Vec<&str> = source.split('/').skip(1).collect();
    for seg in &segs {
        if seg.is_empty() {
            return Some("the pattern has an empty segment or a trailing /".into());
        }
        if *seg == "." || *seg == ".." {
            return Some(format!("the pattern has a \"{seg}\" segment"));
        }
        if parse_seg(seg).1 {
            return Some("the pattern has an unclosed [".into());
        }
    }
    if effect == Effect::Show {
        // A directory segment that could BE a credential directory, or a last segment that names one literally: a show
        // releases what is inside it. A last-segment glob (`*.txt`, `*`) names files, so it is not read as the directory.
        for (i, seg) in segs.iter().enumerate() {
            let last = i == segs.len() - 1;
            for dir in CREDENTIAL_DIRS {
                if if last { *seg == dir } else { seg_pat_match(seg, dir) } {
                    return Some(format!("a show cannot release {dir} (a credential directory)"));
                }
            }
        }
        for i in 0..segs.len().saturating_sub(1) {
            if !seg_pat_match(segs[i], ".config") {
                continue;
            }
            for d in CREDENTIAL_CONFIG_DIRS {
                let hit = if i + 2 == segs.len() { segs[i + 1] == d } else { seg_pat_match(segs[i + 1], d) };
                if hit {
                    return Some(format!("a show cannot release .config/{d} (a credential directory)"));
                }
            }
        }
    }
    None
}

/// Compiles a `hide` pattern: refused exactly where [`refusal`] refuses it for a hide.
pub fn compile(source: &str) -> Result<Pattern, String> {
    compile_as(source, Effect::Hide)
}

/// Compiles a pattern for `effect`: refused exactly where [`refusal`] refuses it for that effect. The syntax is the same
/// for both; only a `show` has the credential-directory refusal.
pub fn compile_as(source: &str, effect: Effect) -> Result<Pattern, String> {
    if let Some(why) = refusal(source, effect) {
        return Err(why);
    }
    Ok(Pattern { segs: source.split('/').map(|s| parse_seg(s).0).collect() })
}

impl Pattern {
    /// Whether the pattern matches `path`: segment by segment, the same segment count, case-sensitive; `*`, `?` and
    /// `[...]` stay inside one `/` segment and `*` matches a leading `.`.
    pub fn matches(&self, path: &str) -> bool {
        let s: Vec<&str> = path.split('/').collect();
        s.len() == self.segs.len() && self.segs.iter().zip(&s).all(|(p, s)| seg_match(p, s))
    }

    /// Whether the pattern matches `path` or any ancestor directory of it (`/a/b/c` has `/a/b` and `/a`): a `hide`
    /// that matches a directory holds everything under it. A `show` uses [`Pattern::matches`] only.
    pub fn holds(&self, path: &str) -> bool {
        let s: Vec<&str> = path.split('/').collect();
        // The path or an ancestor matches exactly when the path's first `segs.len()` segments do.
        s.len() >= self.segs.len() && self.segs.iter().zip(&s).all(|(p, s)| seg_match(p, s))
    }

    /// The pattern with its leading literal segment `/<name>` replaced by the segments of `to`, an absolute path, each
    /// a literal (so a `[` or `*` in `to` is a character, never a glob), or `None` when the pattern does not start with
    /// that literal segment. This is how a `/files/…` pattern comes to name the mount's uploads folder.
    pub fn rebase(&self, name: &str, to: &Path) -> Option<Pattern> {
        let lit: Vec<Tok> = name.chars().map(Tok::Lit).collect();
        if self.segs.len() < 2 || self.segs[1] != lit {
            return None;
        }
        let mut segs: Vec<Vec<Tok>> = vec![vec![]];
        for c in to.to_string_lossy().split('/').filter(|c| !c.is_empty()) {
            segs.push(c.chars().map(Tok::Lit).collect());
        }
        segs.extend(self.segs[2..].iter().cloned());
        Some(Pattern { segs })
    }

    /// The Seatbelt (POSIX ERE) regex for the same paths, for an entry of `effect`: anchored `^…(/|$)` for a `hide`,
    /// which holds the subtree, and `^…$` for a `show`. Case-insensitive by construction: each ASCII letter is `[aA]`
    /// and a class is case-folded. `*` is `[^/]*`. A pattern that can match nothing (a class with no member, like
    /// `[z-a]`) gives `^$`. A non-ASCII character is written as itself, not case-folded. The text is a bare regex:
    /// quoting it into an SBPL string is the caller's.
    ///
    /// Seatbelt matches BYTES, so a token meaning one character must not be one byte where a name holds a multibyte
    /// one. Each side errs its own safe way. A `hide` holds at least what the extension does: `?` is one to four bytes
    /// (`[^/][^/]?[^/]?[^/]?`), a negated class is its ASCII members or two to four bytes, and a class with non-ASCII
    /// members is an alternation of its ASCII part and each member's bytes (past `CLASS_NON_ASCII_MAX` members, `?`'s
    /// form). A `show` releases at most what the extension does: `?` and a negated class are one byte, so a multibyte
    /// character is not released, and a class keeps its exact alternation (past the cap, its ASCII part alone).
    pub fn sbpl_regex(&self, effect: Effect) -> String {
        let hide = effect == Effect::Hide;
        let mut out = String::from("^");
        for (i, seg) in self.segs.iter().enumerate() {
            if i > 0 {
                out.push('/');
            }
            for t in seg {
                match t {
                    Tok::Lit(c) => ci_char(*c, &mut out),
                    Tok::One => out.push_str(if hide { ONE_WIDE } else { "[^/]" }),
                    Tok::Any => out.push_str("[^/]*"),
                    Tok::Cls { neg, ranges } => match class_regex(*neg, ranges, hide) {
                        Some(r) => out.push_str(&r),
                        None => return "^$".into(),
                    },
                }
            }
        }
        out.push_str(if hide { "(/|$)" } else { "$" });
        out
    }

    /// How many leading segments hold no glob token (the empty segment before the leading `/` counts).
    fn literal_len(&self) -> usize {
        self.segs.iter().take_while(|s| s.iter().all(|t| matches!(t, Tok::Lit(_)))).count()
    }

    /// The longest leading run of segments with no glob token, as a path: where a bounded walk for the pattern starts.
    /// A pattern with no glob at all is its own prefix.
    pub fn literal_prefix(&self) -> PathBuf {
        let k = self.literal_len();
        let mut s = String::new();
        for seg in &self.segs[1..k.max(1)] {
            s.push('/');
            for t in seg {
                if let Tok::Lit(c) = t {
                    s.push(*c);
                }
            }
        }
        if s.is_empty() {
            s.push('/');
        }
        PathBuf::from(s)
    }
}

/// The entry that decides `path` in `list`, which is in ASCENDING precedence: the last `hide` that holds it (the path
/// or an ancestor) or `show` that matches it exactly; `None` when no entry names it.
pub fn decide<'a>(list: &'a [Entry], path: &str) -> Option<&'a Entry> {
    list.iter().rev().find(|e| match e.effect {
        Effect::Hide => e.pattern.holds(path),
        Effect::Show => e.pattern.matches(path),
    })
}

/// One literal character as a regex fragment, case-insensitive for an ASCII letter (the convention of `sandbox::ci`).
fn ci_char(c: char, out: &mut String) {
    if c.is_ascii_alphabetic() {
        out.push('[');
        out.push(c.to_ascii_lowercase());
        out.push(c.to_ascii_uppercase());
        out.push(']');
    } else if "\\.^$|()[]{}*+?".contains(c) {
        out.push('\\');
        out.push(c);
    } else {
        out.push(c);
    }
}

/// One character of a segment in any UTF-8 length, as bytes: what a `hide` writes for `?`.
const ONE_WIDE: &str = "[^/][^/]?[^/]?[^/]?";

/// A character class as a case-folded regex that never matches `/`, or `None` when it can match nothing, for a `hide`
/// (`hide`, holding at least the class's characters) or a `show` (at most them); [`Pattern::sbpl_regex`] says how each
/// side treats a multibyte character.
fn class_regex(neg: bool, ranges: &[(u32, u32)], hide: bool) -> Option<String> {
    let mut ascii = [false; 128];
    let mut wide: Vec<char> = Vec::new();
    let mut over = false;
    for &(lo, hi) in ranges {
        for cp in lo..=hi.min(127) {
            ascii[cp as usize] = true;
        }
        let from = lo.max(128);
        if from <= hi && !over {
            if (hi - from) as usize >= CLASS_NON_ASCII_MAX {
                over = true;
            } else {
                wide.extend((from..=hi).filter_map(char::from_u32));
                over = wide.len() > CLASS_NON_ASCII_MAX;
            }
        }
    }
    for c in b'a'..=b'z' {
        let (l, u) = (c as usize, c.to_ascii_uppercase() as usize);
        let both = ascii[l] || ascii[u];
        ascii[l] = both;
        ascii[u] = both;
    }
    ascii[b'/' as usize] = neg; // a segment never holds `/`: excluded from a negation, absent from a class
    if neg {
        // Byte-wise the bracket is one byte: a `show` keeps it (a multibyte character is not released); a `hide` adds
        // any two to four bytes, so every multibyte character is held (and some it excludes, the safe side).
        let one = bracket(true, &ascii);
        return Some(if hide { format!("({one}|[^/][^/][^/]?[^/]?)") } else { one });
    }
    if over {
        if hide {
            return Some(ONE_WIDE.into());
        }
        wide.clear(); // a show releases the ASCII part alone
    }
    let any_ascii = ascii.iter().any(|&b| b);
    if !any_ascii && wide.is_empty() {
        return None;
    }
    if wide.is_empty() {
        return Some(bracket(false, &ascii));
    }
    let mut alts: Vec<String> = Vec::new();
    if any_ascii {
        alts.push(bracket(false, &ascii));
    }
    alts.extend(wide.iter().map(|c| c.to_string()));
    Some(format!("({})", alts.join("|")))
}

/// A bracket expression over ASCII members (`/` already set or cleared by the caller), negated or not, with `]` first
/// and `^` and `-` last so none reads as syntax; a positive class of `^` alone is `\^`.
fn bracket(neg: bool, ascii: &[bool; 128]) -> String {
    let mut body = String::new();
    if ascii[b']' as usize] {
        body.push(']');
    }
    let mut c = 0usize;
    while c < 128 {
        let plain = |x: usize| ascii[x] && !matches!(x as u8, b']' | b'^' | b'-');
        if !plain(c) {
            c += 1;
            continue;
        }
        let mut e = c;
        while e + 1 < 128 && plain(e + 1) {
            e += 1;
        }
        if e - c >= 2 {
            body.push(c as u8 as char);
            body.push('-');
            body.push(e as u8 as char);
        } else {
            for x in c..=e {
                body.push(x as u8 as char);
            }
        }
        c = e + 1;
    }
    if ascii[b'^' as usize] {
        body.push('^');
    }
    if ascii[b'-' as usize] {
        body.push('-');
    }
    if !neg && body == "^" {
        return "\\^".into();
    }
    format!("[{}{body}]", if neg { "^" } else { "" })
}

/// One directory entry the walk considers.
struct Item {
    name: String,
    /// A real directory; a symlink to one is not.
    dir: bool,
}

struct Walk {
    found: Vec<PathBuf>,
    limit: usize,
    cap: usize,
    seen: usize,
    truncated: bool,
    stop: bool,
}

/// Every existing path `pat` matches, files and directories both, starting at [`Pattern::literal_prefix`]: at most
/// `limit` matches, looking at most `cap` directory entries. The flag is "stopped early" (`limit`, `cap` or
/// [`MAX_DEPTH`] reached). No name is skipped (hidden names and `.git` included). Below the prefix a directory is
/// opened by descriptor with `O_NOFOLLOW`, so a symlink is never entered, though one may match by name as the last
/// segment; the prefix itself is opened by its path, as the pattern names it. A directory that cannot be opened is
/// skipped, a name that is not UTF-8 is skipped. A pattern with no glob returns its path when it exists (`lstat`, a
/// final symlink not followed).
pub fn walk(pat: &Pattern, limit: usize, cap: usize) -> (Vec<PathBuf>, bool) {
    let k = pat.literal_len();
    let prefix = pat.literal_prefix();
    if k == pat.segs.len() {
        return match std::fs::symlink_metadata(&prefix) {
            Ok(_) if limit == 0 => (vec![], true),
            Ok(_) => (vec![prefix], false),
            Err(_) => (vec![], false),
        };
    }
    let mut w = Walk { found: Vec::new(), limit, cap, seen: 0, truncated: false, stop: false };
    if let Ok(fd) = rustix::fs::open(&prefix, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()) {
        w.dir(&fd, &prefix, &pat.segs[k..], 0);
    }
    (w.found, w.truncated)
}

impl Walk {
    fn dir(&mut self, fd: &OwnedFd, path: &Path, segs: &[Vec<Tok>], depth: usize) {
        if self.stop {
            return;
        }
        if depth > MAX_DEPTH {
            self.truncated = true;
            return;
        }
        for e in self.list(fd).iter().filter(|e| seg_match(&segs[0], &e.name)) {
            if self.stop {
                return;
            }
            if segs.len() == 1 {
                self.emit(path.join(&e.name));
            } else if e.dir
                && let Some(child) = open_dir(fd, &e.name)
            {
                self.dir(&child, &path.join(&e.name), &segs[1..], depth + 1);
            }
        }
    }

    fn emit(&mut self, path: PathBuf) {
        if self.found.len() >= self.limit {
            self.truncated = true;
            self.stop = true;
            return;
        }
        self.found.push(path);
    }

    /// The entries of one directory in name order, minus names that are not UTF-8. Every entry counts toward the cap.
    fn list(&mut self, fd: &OwnedFd) -> Vec<Item> {
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
            out.push(Item { name: name.to_string(), dir: ft == FileType::Directory });
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(s: &str) -> Pattern {
        compile(s).unwrap()
    }

    // --- parity with tests/files-hide.test.mjs (window-ml's files-hide.ts) ---

    #[test]
    fn parity_the_limits_are_the_specs() {
        assert_eq!(PATTERN_MAX, 512);
        assert_eq!(ENTRIES_MAX, 256);
    }

    #[test]
    fn parity_glob_match_table() {
        let rows: [(&str, &str, bool); 23] = [
            ("/files/agent/.env", "/files/agent/.env", true),
            ("/files/agent/.env", "/files/agent/.ENV", false),
            ("/files/agent/*.env", "/files/agent/prod.env", true),
            ("/files/agent/*.env", "/files/agent/.env", true),
            ("/files/agent/*.env", "/files/agent/sub/prod.env", false),
            ("/files/agent/*", "/files/agent/a/b", false),
            ("/files/*/x", "/files/agent/x", true),
            ("/files/agent/*", "/files/agent", false),
            ("/files/agent", "/files/agent/x", false),
            ("/files/agent/a?c", "/files/agent/abc", true),
            ("/files/agent/a?c", "/files/agent/ac", false),
            ("/files/agent/a?c", "/files/agent/abbc", false),
            ("/files/agent/[abc].txt", "/files/agent/b.txt", true),
            ("/files/agent/[abc].txt", "/files/agent/d.txt", false),
            ("/files/agent/[a-c].txt", "/files/agent/b.txt", true),
            ("/files/agent/[a-c].txt", "/files/agent/z.txt", false),
            ("/files/agent/[!a-c].txt", "/files/agent/z.txt", true),
            ("/files/agent/[!a-c].txt", "/files/agent/b.txt", false),
            ("/files/agent/[^a-c].txt", "/files/agent/z.txt", true),
            ("/files/agent/[^a-c].txt", "/files/agent/a.txt", false),
            ("/files/agent/*a*b*", "/files/agent/xxaxxbxx", true),
            ("/files/agent/*a*b*", "/files/agent/xxbxxaxx", false),
            ("/files/agent/a*", "/files/agent/a", true),
        ];
        for (p, path, want) in rows {
            assert_eq!(pat(p).matches(path), want, "{p} vs {path}");
        }
    }

    #[test]
    fn parity_glob_match_is_not_exponential_on_a_pathological_pattern() {
        let p = pat(&format!("/files/agent/{}b", "*a".repeat(40)));
        let t0 = std::time::Instant::now();
        assert!(!p.matches(&format!("/files/agent/{}", "a".repeat(200))));
        assert!(t0.elapsed().as_millis() < 1000);
    }

    #[test]
    fn parity_pattern_refusal_refuses_each_malformed_shape_and_names_a_reason() {
        let long = "x".repeat(PATTERN_MAX + 1);
        let bad = [
            "",
            long.as_str(),
            "files/agent/.env",
            "/files/**/x",
            "/files/agent/./x",
            "/files/agent/../x",
            "/files//x",
            "/files/agent/",
            "/files/agent/[abc",
            "/files/a\0b",
            "/files/a\nb",
            "/files/a\x7fb",
            "/",
        ];
        for effect in [Effect::Hide, Effect::Show] {
            for s in bad {
                assert!(refusal(s, effect).is_some(), "{effect:?} {:?}", s.chars().take(40).collect::<String>());
            }
        }
    }

    #[test]
    fn parity_pattern_refusal_accepts_ordinary_patterns_and_the_exact_maximum_length() {
        let max = format!("/{}", "a".repeat(PATTERN_MAX - 1));
        let ok = [
            "/files/agent/.env",
            "/files/agent/*.env",
            "/files/attached/h1/[a-c]?.txt",
            "/files/agent/sub/x.txt",
            max.as_str(),
        ];
        for effect in [Effect::Hide, Effect::Show] {
            for s in ok {
                assert_eq!(refusal(s, effect), None, "{effect:?} {s}");
            }
        }
    }

    #[test]
    fn parity_a_show_over_each_credential_directory_is_refused_naming_it_a_hide_is_allowed() {
        for d in CREDENTIAL_DIRS {
            for s in
                [format!("/files/agent/{d}"), format!("/files/agent/{d}/id_rsa"), format!("/files/attached/h1/{d}/x")]
            {
                let r = refusal(&s, Effect::Show);
                assert!(r.as_deref().is_some_and(|r| r.contains(d)), "{s}: {r:?}");
                assert_eq!(refusal(&s, Effect::Hide), None, "hide {s}");
            }
        }
        for d in ["gcloud", "gh"] {
            let s = format!("/files/agent/.config/{d}/hosts.yml");
            let r = refusal(&s, Effect::Show);
            assert!(r.as_deref().is_some_and(|r| r.contains(&format!(".config/{d}"))), "{r:?}");
            assert_eq!(refusal(&s, Effect::Hide), None);
        }
        assert_eq!(refusal("/files/agent/.config/other/x", Effect::Show), None);
        assert_eq!(refusal("/files/agent/gcloud/x", Effect::Show), None, "gcloud without .config is fine");
    }

    #[test]
    fn parity_a_show_whose_glob_could_match_a_credential_directory_is_refused() {
        for s in [
            "/files/agent/.s*/x",
            "/files/agent/.ss?/x",
            "/files/agent/[.]ssh/x",
            "/files/agent/.config/g*/x",
            "/files/agent/.c*/gcloud/x",
        ] {
            assert!(refusal(s, Effect::Show).is_some(), "{s}");
        }
        assert_eq!(refusal("/files/agent/.s*/x", Effect::Hide), None);
    }

    #[test]
    fn parity_a_show_whose_last_segment_is_a_glob_names_files_and_is_allowed() {
        for s in ["/files/agent/*", "/files/agent/*.txt", "/files/agent/.s*", "/files/agent/.config/*"] {
            assert_eq!(refusal(s, Effect::Show), None, "{s}");
        }
        assert!(refusal("/files/agent/.ssh", Effect::Show).is_some(), "the directory itself, named literally");
        assert!(refusal("/files/agent/.config/gh", Effect::Show).is_some());
    }

    // --- compile and Entry ---

    #[test]
    fn compile_refuses_what_a_hide_refuses_and_entry_what_its_effect_refuses() {
        assert!(compile("/p/**/x").is_err());
        assert!(compile("/p/.ssh").is_ok(), "a hide over a credential directory is allowed");
        assert!(Entry::new("a", Effect::Show, "/p/.ssh").is_err());
        let e = Entry::new("a", Effect::Hide, "/p/.env").unwrap();
        assert_eq!((e.id.as_str(), e.effect), ("a", Effect::Hide));
    }

    // --- holds ---

    #[test]
    fn holds_a_directory_pattern_holds_its_subtree_not_a_name_prefix_sibling() {
        let p = pat("/p/.ssh");
        assert!(p.holds("/p/.ssh"));
        assert!(p.holds("/p/.ssh/id_rsa"));
        assert!(p.holds("/p/.ssh/a/b/c"));
        assert!(!p.holds("/p/.sshrc"));
        assert!(!p.holds("/p"));
        assert!(!p.matches("/p/.ssh/id_rsa"), "matches alone is the exact path");
    }

    #[test]
    fn holds_a_glob_over_the_directory_holds_what_is_under_each_match() {
        let p = pat("/p/build*");
        assert!(p.holds("/p/build-out/x"));
        assert!(p.holds("/p/build"));
        assert!(!p.holds("/p/rebuild/x"));
        assert!(!p.holds("/q/build/x"));
    }

    // --- sbpl_regex ---
    // No regex crate among the dev-dependencies, so the exact strings are asserted and read by hand: every ASCII letter
    // is `[xX]` (so `/p/.ENV` and `/p/.env` both match), `.` is escaped, `*` stays inside a segment, and `(/|$)` ends
    // a subtree rule at a segment boundary (`/p/.sshrc` does not match `^/p/\.[sS][sS][hH](/|$)`).

    #[test]
    fn sbpl_regex_literals_are_case_insensitive_and_escaped() {
        assert_eq!(pat("/p/.env").sbpl_regex(Effect::Show), "^/[pP]/\\.[eE][nN][vV]$");
        assert_eq!(pat("/p/.ssh").sbpl_regex(Effect::Hide), "^/[pP]/\\.[sS][sS][hH](/|$)");
        assert_eq!(pat("/a+b/c(1)").sbpl_regex(Effect::Show), "^/[aA]\\+[bB]/[cC]\\(1\\)$");
    }

    #[test]
    fn sbpl_regex_star_and_question_stay_inside_a_segment() {
        assert_eq!(pat("/p/*.env").sbpl_regex(Effect::Show), "^/[pP]/[^/]*\\.[eE][nN][vV]$");
        assert_eq!(pat("/p/a?c").sbpl_regex(Effect::Show), "^/[pP]/[aA][^/][cC]$");
        assert_eq!(pat("/*/x").sbpl_regex(Effect::Show), "^/[^/]*/[xX]$");
    }

    #[test]
    fn sbpl_regex_classes_are_case_folded_and_a_negation_excludes_both_cases() {
        assert_eq!(pat("/p/[abc].txt").sbpl_regex(Effect::Show), "^/[pP]/[A-Ca-c]\\.[tT][xX][tT]$");
        assert_eq!(pat("/p/[x]").sbpl_regex(Effect::Show), "^/[pP]/[Xx]$");
        // the negation excludes `/`, `a-c` and `A-C`
        assert_eq!(pat("/p/[!a-c]").sbpl_regex(Effect::Show), "^/[pP]/[^/A-Ca-c]$");
        assert_eq!(pat("/p/[^a-c]").sbpl_regex(Effect::Show), "^/[pP]/[^/A-Ca-c]$");
        // a class that can match nothing matches nothing
        assert_eq!(pat("/p/[z-a]").sbpl_regex(Effect::Show), "^$");
    }

    #[test]
    fn sbpl_regex_class_members_that_are_special_in_a_bracket_expression() {
        // `]` first, `^` and `-` last (a positive class cannot be a lone `^`: a leading `^` is a negation)
        assert_eq!(pat("/[]a]").sbpl_regex(Effect::Show), "^/[]Aa]$");
        assert_eq!(pat("/[a^-]").sbpl_regex(Effect::Show), "^/[Aa^-]$");
    }

    #[test]
    fn sbpl_regex_a_hide_question_spans_a_multibyte_character_a_show_one_byte() {
        // Seatbelt matches bytes: `é` is two, so a hide's `?` must take up to four and a show's stays one.
        assert_eq!(pat("/p/a?").sbpl_regex(Effect::Hide), "^/[pP]/[aA][^/][^/]?[^/]?[^/]?(/|$)");
        assert_eq!(pat("/p/a?").sbpl_regex(Effect::Show), "^/[pP]/[aA][^/]$");
    }

    #[test]
    fn sbpl_regex_a_negated_class_holds_any_multibyte_character_for_a_hide_and_releases_none_for_a_show() {
        assert_eq!(pat("/p/[!a]").sbpl_regex(Effect::Hide), "^/[pP]/([^/Aa]|[^/][^/][^/]?[^/]?)(/|$)");
        assert_eq!(pat("/p/[!a]").sbpl_regex(Effect::Show), "^/[pP]/[^/Aa]$");
    }

    #[test]
    fn sbpl_regex_a_class_with_non_ascii_members_is_an_exact_alternation_on_both_sides() {
        assert_eq!(pat("/p/[aé]").sbpl_regex(Effect::Hide), "^/[pP]/([Aa]|é)(/|$)");
        assert_eq!(pat("/p/[éü]").sbpl_regex(Effect::Show), "^/[pP]/(é|ü)$");
    }

    #[test]
    fn sbpl_regex_a_class_past_the_non_ascii_cap_widens_a_hide_and_narrows_a_show() {
        // U+0100..U+0300 is 513 members, past the cap of 256
        let p = pat("/p/[aĀ-̀]");
        assert_eq!(p.sbpl_regex(Effect::Hide), "^/[pP]/[^/][^/]?[^/]?[^/]?(/|$)");
        assert_eq!(p.sbpl_regex(Effect::Show), "^/[pP]/[Aa]$");
        assert_eq!(pat("/p/[Ā-̀]").sbpl_regex(Effect::Show), "^$", "nothing ASCII left: a show releases nothing");
    }

    // --- rebase and decide ---

    #[test]
    fn rebase_maps_a_files_pattern_onto_the_folder_its_brackets_literal() {
        let p = pat("/files/notes/*.txt").rebase("files", Path::new("/w/p[1]/up")).unwrap();
        assert!(p.matches("/w/p[1]/up/notes/a.txt"));
        assert!(!p.matches("/w/p1/up/notes/a.txt"), "the folder's `[1]` is two characters, not a class");
        assert!(pat("/files").rebase("files", Path::new("/w/up")).unwrap().holds("/w/up/x"));
        assert_eq!(pat("/filesx/a").rebase("files", Path::new("/w")), None);
        assert_eq!(pat("/f*/a").rebase("files", Path::new("/w")), None, "a glob first segment is not /files");
    }

    #[test]
    fn decide_the_last_entry_that_names_a_path_wins_a_hide_by_ancestor_a_show_exactly() {
        let e = |id: &str, eff, src: &str| Entry::new(id, eff, src).unwrap();
        let list =
            vec![e("h1", Effect::Hide, "/p/d"), e("s1", Effect::Show, "/p/d/a"), e("h2", Effect::Hide, "/p/*.key")];
        assert_eq!(decide(&list, "/p/d/a").map(|e| e.id.as_str()), Some("s1"));
        assert_eq!(
            decide(&list, "/p/d/a/x").map(|e| e.id.as_str()),
            Some("h1"),
            "a show releases only what it matches"
        );
        assert_eq!(decide(&list, "/p/d/b").map(|e| e.id.as_str()), Some("h1"));
        assert_eq!(decide(&list, "/p/x.key").map(|e| e.id.as_str()), Some("h2"));
        assert_eq!(decide(&list, "/p/x.txt"), None);
        let later_hide = vec![e("s1", Effect::Show, "/p/.env"), e("h1", Effect::Hide, "/p")];
        assert_eq!(decide(&later_hide, "/p/.env").map(|e| e.id.as_str()), Some("h1"));
    }

    // --- literal_prefix ---

    #[test]
    fn literal_prefix_stops_at_the_first_glob_segment() {
        assert_eq!(pat("/a/b/*").literal_prefix(), PathBuf::from("/a/b"));
        assert_eq!(pat("/a/b*/c").literal_prefix(), PathBuf::from("/a"));
        assert_eq!(pat("/*").literal_prefix(), PathBuf::from("/"));
        assert_eq!(pat("/a/b/c").literal_prefix(), PathBuf::from("/a/b/c"));
    }

    // --- walk ---

    fn touch(p: &Path) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, "x").unwrap();
    }

    fn names(found: &[PathBuf], root: &Path) -> Vec<String> {
        found.iter().map(|p| p.strip_prefix(root).unwrap().to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn walk_star_finds_hidden_names_and_directories() {
        let d = tempfile::tempdir().unwrap();
        for f in [".env", ".hidden", "plain", ".git/config"] {
            touch(&d.path().join(f));
        }
        let (found, stopped) = walk(&pat(&format!("{}/*", d.path().display())), 100, 1000);
        assert!(!stopped);
        assert_eq!(names(&found, d.path()), [".env", ".git", ".hidden", "plain"]);
        // a name inside .git is reachable by a pattern that names it
        let (found, _) = walk(&pat(&format!("{}/.git/*", d.path().display())), 100, 1000);
        assert_eq!(names(&found, d.path()), [".git/config"]);
    }

    #[test]
    fn walk_never_enters_a_symlinked_directory_but_may_match_it_by_name() {
        let d = tempfile::tempdir().unwrap();
        touch(&d.path().join("real/.env"));
        std::os::unix::fs::symlink(d.path().join("real"), d.path().join("link")).unwrap();
        let (found, _) = walk(&pat(&format!("{}/*/.env", d.path().display())), 100, 1000);
        assert_eq!(names(&found, d.path()), ["real/.env"]);
        let (found, _) = walk(&pat(&format!("{}/l*", d.path().display())), 100, 1000);
        assert_eq!(names(&found, d.path()), ["link"]);
    }

    #[test]
    fn walk_without_a_glob_is_an_lstat_of_the_path() {
        let d = tempfile::tempdir().unwrap();
        touch(&d.path().join("a/b"));
        std::os::unix::fs::symlink(d.path().join("nowhere"), d.path().join("dangling")).unwrap();
        let p = |n: &str| pat(&format!("{}/{n}", d.path().display()));
        assert_eq!(walk(&p("a/b"), 10, 10), (vec![d.path().join("a/b")], false));
        assert_eq!(walk(&p("a/c"), 10, 10), (vec![], false));
        assert_eq!(
            walk(&p("dangling"), 10, 10),
            (vec![d.path().join("dangling")], false),
            "a final symlink is not followed"
        );
    }

    #[test]
    fn walk_respects_limit_and_cap_and_says_it_stopped() {
        let d = tempfile::tempdir().unwrap();
        for f in ["a", "b", "c", "d"] {
            touch(&d.path().join(f));
        }
        let p = pat(&format!("{}/*", d.path().display()));
        let (found, stopped) = walk(&p, 2, 1000);
        assert_eq!((found.len(), stopped), (2, true));
        let (found, stopped) = walk(&p, 4, 1000);
        assert_eq!((found.len(), stopped), (4, false));
        let (_, stopped) = walk(&p, 100, 2);
        assert!(stopped, "the entry cap");
    }

    #[test]
    fn walk_a_missing_prefix_finds_nothing() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(walk(&pat(&format!("{}/nope/*", d.path().display())), 10, 10), (vec![], false));
    }
}
