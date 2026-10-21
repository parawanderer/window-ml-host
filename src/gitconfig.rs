//! gitconfig.rs — whether a repository's OWN config makes git run a program: the host reads the repository-level config
//! (and what its `include`/`includeIf` pull in) for the keys that do, and reports `repoConfigRunsCode` with the reasons.
//!
//! Repository config arrived with the repository and is untrusted; the person's global config is theirs and is not read
//! here. A git "read" is only a read when this is false (ruling of 2026-10-15, window-ml's SHELL.md). The host also pins
//! `core.fsmonitor` and `core.pager` for every spawn (`env.rs`), so this fact is the second line, not the only one.

use std::path::{Path, PathBuf};

/// The most bytes read from one config file, and the deepest include chain followed.
const MAX_CONFIG_BYTES: u64 = 1 << 20;
const MAX_INCLUDE_DEPTH: usize = 10;

/// What the host found about the repository a call runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoConfig {
    /// The work tree (the directory holding `.git`).
    pub root: PathBuf,
    pub runs_code: bool,
    /// Each key or include that makes it so, as `key = value` or a sentence.
    pub reasons: Vec<String>,
}

/// Finds the repository containing `dir` (walking up to the first `.git`) and inspects its config. `None` when `dir`
/// is in no repository, which the caller reports as runs-no-code: so only a `.git` that is certainly absent (NotFound)
/// is passed over, and one that cannot be read is a repository whose config runs code.
pub fn inspect(dir: &Path) -> Option<RepoConfig> {
    let (root, dotgit, md) = dir.ancestors().find_map(|a| {
        let p = a.join(".git");
        match std::fs::symlink_metadata(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            md => Some((a.to_path_buf(), p, md)),
        }
    })?;
    let mut r = RepoConfig { root: root.clone(), runs_code: false, reasons: vec![] };
    let mut flag = |why: String| {
        r.runs_code = true;
        r.reasons.push(why);
    };
    let md = match md {
        Ok(md) => md,
        Err(e) => {
            flag(format!("{} cannot be read: {e}", dotgit.display()));
            return Some(r);
        }
    };
    let gitdir = if md.file_type().is_symlink() {
        flag(".git is a symlink, so its config is wherever it points".into());
        return Some(r);
    } else if md.is_dir() {
        dotgit.clone()
    } else {
        // A gitfile (`gitdir: <path>`): a worktree or a submodule.
        match std::fs::read_to_string(&dotgit)
            .ok()
            .and_then(|s| s.strip_prefix("gitdir:").map(|p| p.trim().to_string()))
        {
            Some(p) => {
                let p = PathBuf::from(p);
                let p = if p.is_absolute() { p } else { root.join(p) };
                match p.canonicalize() {
                    Ok(c) => c,
                    Err(_) => {
                        flag(format!(".git points at {}, which does not resolve", p.display()));
                        return Some(r);
                    }
                }
            }
            None => {
                flag(".git is a file that is not a gitfile".into());
                return Some(r);
            }
        }
    };
    // A linked worktree keeps its shared config in the common dir, and may have its own config.worktree.
    // Only a `commondir` that is NotFound (a main worktree) falls back to the gitdir; one that cannot be read or does
    // not resolve would skip the shared config and report false, so it is runs-code with the reason.
    let common = match std::fs::read_to_string(gitdir.join("commondir")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => gitdir.clone(),
        Err(e) => {
            flag(format!("{} cannot be read: {e}", gitdir.join("commondir").display()));
            return Some(r);
        }
        Ok(c) => {
            let c = PathBuf::from(c.trim());
            let c = if c.is_absolute() { c } else { gitdir.join(c) };
            match c.canonicalize() {
                Ok(c) => c,
                Err(_) => {
                    flag(format!("commondir points at {}, which does not resolve", c.display()));
                    return Some(r);
                }
            }
        }
    };
    let trusted: Vec<PathBuf> = [root.canonicalize().ok(), gitdir.canonicalize().ok(), common.canonicalize().ok()]
        .into_iter()
        .flatten()
        .collect();
    let mut seen = Vec::new();
    for f in [common.join("config"), gitdir.join("config.worktree")] {
        if f.exists() {
            scan_file(&f, &trusted, 0, &mut seen, &mut flag);
        }
    }
    Some(r)
}

fn scan_file(f: &Path, trusted: &[PathBuf], depth: usize, seen: &mut Vec<PathBuf>, flag: &mut dyn FnMut(String)) {
    let Ok(real) = f.canonicalize() else {
        return flag(format!("an included config {} does not resolve", f.display()));
    };
    if seen.contains(&real) {
        return;
    }
    seen.push(real.clone());
    if depth > MAX_INCLUDE_DEPTH {
        return flag("config includes nest deeper than the host follows".into());
    }
    let text = match std::fs::metadata(&real) {
        Ok(m) if m.len() > MAX_CONFIG_BYTES => {
            return flag(format!("{} is larger than the host reads", real.display()));
        }
        Ok(_) => match std::fs::read(&real) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => return flag(format!("{} could not be read: {e}", real.display())),
        },
        Err(e) => return flag(format!("{}: {e}", real.display())),
    };
    let base = real.parent().unwrap_or(Path::new("/")).to_path_buf();
    for e in parse(&text) {
        let full = e.name();
        let v = e.value.clone().unwrap_or_default();
        if let Some(why) = runs_code(&e) {
            flag(why);
        }
        let is_include = (e.section == "include" && e.subsection.is_none() && e.key == "path")
            || (e.section == "includeif" && e.subsection.is_some() && e.key == "path");
        if is_include {
            if v.starts_with('~') || v.is_empty() {
                flag(format!("{full} = {v}: an include outside the repository"));
                continue;
            }
            let p = if Path::new(&v).is_absolute() { PathBuf::from(&v) } else { base.join(&v) };
            match p.canonicalize() {
                Ok(c) if trusted.iter().any(|t| c.starts_with(t)) => scan_file(&c, trusted, depth + 1, seen, flag),
                Ok(c) => flag(format!("{full} = {v}: an include outside the repository ({})", c.display())),
                // git ignores a missing include; so does the host, since nothing is read from it.
                Err(_) => {}
            }
        }
    }
}

/// Whether one entry makes git run a program, and why.
fn runs_code(e: &Entry) -> Option<String> {
    let v = e.value.clone().unwrap_or_default();
    let shown = || format!("{} = {v}", e.name());
    let falsy = matches!(v.to_ascii_lowercase().as_str(), "" | "false" | "no" | "off" | "0");
    let sub = e.subsection.is_some();
    let hit = match (e.section.as_str(), e.key.as_str()) {
        ("core", "fsmonitor") => !falsy || e.value.is_none(),
        ("core", "pager") => !(v.is_empty() || v == "cat"),
        ("core", "hookspath" | "sshcommand" | "askpass" | "gitproxy") => true,
        ("diff", "external") => !sub,
        ("diff", "textconv" | "command") => sub,
        ("filter", _) => sub,
        ("credential", "helper") => true,
        ("alias", _) => v.trim_start().starts_with('!'),
        ("gpg", "program") => true,
        ("remote", "uploadpack" | "receivepack") => sub,
        _ => false,
    };
    hit.then(shown)
}

/// One `key = value` of a config file. Section and key are lower-cased (git compares them case-insensitively);
/// a subsection is kept as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub section: String,
    pub subsection: Option<String>,
    pub key: String,
    /// `None` for a bare key (`[core] fsmonitor`), which git reads as true.
    pub value: Option<String>,
}

impl Entry {
    fn name(&self) -> String {
        match &self.subsection {
            Some(s) => format!("{}.{s}.{}", self.section, self.key),
            None => format!("{}.{}", self.section, self.key),
        }
    }
}

/// Parses git's config syntax: `[section]`, `[section "sub"]`, the legacy `[section.sub]`, `key = value` (also on
/// the header's line), comments after `#` or `;` outside quotes, quoted values with `\" \\ \n \t \b` escapes, and a
/// trailing backslash continuing a line. A malformed line is skipped, which only ever under-reports a key git would
/// itself refuse to load.
pub fn parse(text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    let (mut section, mut subsection) = (String::new(), None::<String>);
    let mut lines = text.lines();
    while let Some(first) = lines.next() {
        let mut line = first.to_string();
        while line.ends_with('\\') && !line.ends_with("\\\\") {
            line.pop();
            match lines.next() {
                Some(n) => line.push_str(n),
                None => break,
            }
        }
        let mut rest = line.trim_start();
        if rest.starts_with('[') {
            let Some((s, sub, after)) = header(rest) else { continue };
            section = s;
            subsection = sub;
            rest = after.trim_start();
        }
        if rest.is_empty() || rest.starts_with('#') || rest.starts_with(';') || section.is_empty() {
            continue;
        }
        let klen = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '-')).unwrap_or(rest.len());
        if klen == 0 {
            continue;
        }
        let key = rest[..klen].to_ascii_lowercase();
        let tail = rest[klen..].trim_start();
        let value = if let Some(v) = tail.strip_prefix('=') {
            Some(value(v))
        } else if tail.is_empty() || tail.starts_with('#') || tail.starts_with(';') {
            None
        } else {
            continue;
        };
        out.push(Entry { section: section.clone(), subsection: subsection.clone(), key, value });
    }
    out
}

/// A section header: its name, subsection, and whatever follows the `]`.
fn header(s: &str) -> Option<(String, Option<String>, &str)> {
    let body = &s[1..];
    let name_end = body.find([']', ' ', '\t', '"'])?;
    let name = &body[..name_end];
    let after_name = &body[name_end..];
    if let Some(stripped) = after_name.strip_prefix(']') {
        // `[section]` or the legacy `[section.sub]`.
        return Some(match name.split_once('.') {
            Some((n, sub)) => (n.to_ascii_lowercase(), Some(sub.to_ascii_lowercase()), stripped),
            None => (name.to_ascii_lowercase(), None, stripped),
        });
    }
    let q = after_name.trim_start().strip_prefix('"')?;
    let mut sub = String::new();
    let mut chars = q.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => sub.push(chars.next()?.1),
            '"' => {
                let after = q[i + 1..].trim_start().strip_prefix(']')?;
                return Some((name.to_ascii_lowercase(), Some(sub), after));
            }
            _ => sub.push(c),
        }
    }
    None
}

fn value(v: &str) -> String {
    let mut out = String::new();
    let mut quoted = false;
    let mut pending_ws = String::new();
    let mut chars = v.trim_start().chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => quoted = !quoted,
            '\\' => {
                out.push_str(&pending_ws);
                pending_ws.clear();
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('b') => {
                        out.pop();
                    }
                    Some(o) => out.push(o),
                    None => {}
                }
            }
            '#' | ';' if !quoted => break,
            c if c.is_whitespace() && !quoted => pending_ws.push(c),
            c => {
                out.push_str(&pending_ws);
                pending_ws.clear();
                out.push(c);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- the config parser ---

    #[test]
    fn parses_sections_subsections_values_and_comments() {
        let e = parse(
            "# c\n[core]\n\tpager = \"less -R\" ; comment\n\tfsmonitor\n[diff \"Sub \\\"q\\\"\"]\n textconv=a\\\n b\n[Alias] st = !sh -c x\n[remote.origin]\nuploadpack = u\n",
        );
        let pairs: Vec<(String, Option<String>)> = e.iter().map(|e| (e.name(), e.value.clone())).collect();
        assert_eq!(
            pairs,
            [
                ("core.pager".into(), Some("less -R".into())),
                ("core.fsmonitor".into(), None),
                ("diff.Sub \"q\".textconv".into(), Some("a b".into())),
                ("alias.st".into(), Some("!sh -c x".into())),
                ("remote.origin.uploadpack".into(), Some("u".into())),
            ]
        );
    }

    // --- the keys that run a program ---

    fn repo_with(config: &str) -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/config"), config).unwrap();
        (d, root)
    }

    #[test]
    fn a_plain_repository_runs_nothing() {
        let (_d, root) =
            repo_with("[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = x\n");
        let r = inspect(&root.join("sub/dir")).unwrap();
        assert_eq!(r.root, root);
        assert!(!r.runs_code, "{:?}", r.reasons);
        assert_eq!(inspect(Path::new("/")), None);
    }

    #[test]
    fn a_commondir_that_does_not_resolve_runs_code() {
        // Falling back to the worktree's own gitdir would skip the shared config and report false.
        let (_d, root) = repo_with("[core]\n\tbare = false\n");
        std::fs::write(root.join(".git/commondir"), "../missing\n").unwrap();
        let r = inspect(&root).unwrap();
        assert!(r.runs_code);
        assert!(r.reasons[0].contains("does not resolve"), "{:?}", r.reasons);
    }

    #[test]
    fn a_commondir_that_cannot_be_read_runs_code() {
        // Only NotFound means a main worktree; any other read error could hide a shared config.
        let (_d, root) = repo_with("[core]\n\tbare = false\n");
        std::fs::create_dir(root.join(".git/commondir")).unwrap();
        let r = inspect(&root).unwrap();
        assert!(r.runs_code);
        assert!(r.reasons[0].contains("cannot be read"), "{:?}", r.reasons);
    }

    #[test]
    fn a_dot_git_that_cannot_be_stat_is_not_no_repository() {
        // No repository reads as runs-no-code, so only NotFound may pass a `.git` over. Beneath a file every
        // `.git` stat fails ENOTDIR, which is not a proof of absence.
        let d = tempfile::tempdir().unwrap();
        let f = d.path().canonicalize().unwrap().join("file");
        std::fs::write(&f, "x").unwrap();
        let r = inspect(&f.join("dir")).expect("an unreadable .git is reported, not skipped");
        assert!(r.runs_code);
        assert!(r.reasons[0].contains("cannot be read"), "{:?}", r.reasons);
    }

    #[test]
    fn every_key_that_runs_a_program_is_found() {
        for (cfg, key) in [
            ("[core]\nfsmonitor = /tmp/x", "core.fsmonitor"),
            ("[core]\nfsmonitor", "core.fsmonitor"),
            ("[CORE]\nPager = less", "core.pager"),
            ("[core]\nhooksPath = h", "core.hookspath"),
            ("[core]\nsshCommand = ssh -i k", "core.sshcommand"),
            ("[diff]\nexternal = x", "diff.external"),
            ("[diff \"pdf\"]\ntextconv = pdftotext", "diff.pdf.textconv"),
            ("[diff \"x\"]\ncommand = y", "diff.x.command"),
            ("[filter \"lfs\"]\nclean = git-lfs clean", "filter.lfs.clean"),
            ("[credential]\nhelper = store", "credential.helper"),
            ("[alias]\nx = !rm -rf /", "alias.x"),
            ("[gpg]\nprogram = g", "gpg.program"),
            ("[remote \"o\"]\nuploadpack = u", "remote.o.uploadpack"),
        ] {
            let (_d, root) = repo_with(cfg);
            let r = inspect(&root).unwrap();
            assert!(r.runs_code, "{cfg}");
            assert!(r.reasons[0].starts_with(key), "{cfg}: {:?}", r.reasons);
        }
    }

    #[test]
    fn harmless_values_of_those_keys_are_not_flagged() {
        for cfg in
            ["[core]\nfsmonitor = false", "[core]\npager = cat", "[alias]\nst = status", "[diff]\nrenames = true"]
        {
            let (_d, root) = repo_with(cfg);
            assert!(!inspect(&root).unwrap().runs_code, "{cfg}");
        }
    }

    #[test]
    fn includes_inside_are_followed_and_outside_are_flagged() {
        let (_d, root) = repo_with("[include]\npath = extra.cfg\n");
        std::fs::write(root.join(".git/extra.cfg"), "[core]\nhooksPath = h\n").unwrap();
        let r = inspect(&root).unwrap();
        assert!(r.reasons.iter().any(|w| w.starts_with("core.hookspath")), "{:?}", r.reasons);

        let (_d2, root2) = repo_with("[includeIf \"gitdir:~/\"]\npath = ~/.gitconfig-work\n");
        let r2 = inspect(&root2).unwrap();
        assert!(r2.runs_code && r2.reasons[0].contains("outside the repository"), "{:?}", r2.reasons);

        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("o.cfg"), "[user]\nname = x\n").unwrap();
        let (_d3, root3) = repo_with(&format!("[include]\npath = {}\n", out.path().join("o.cfg").display()));
        assert!(inspect(&root3).unwrap().runs_code);
    }

    #[test]
    fn a_linked_worktree_reads_the_common_config() {
        let main = tempfile::tempdir().unwrap();
        let m = main.path().canonicalize().unwrap();
        std::fs::create_dir_all(m.join(".git/worktrees/wt")).unwrap();
        std::fs::write(m.join(".git/config"), "[core]\nfsmonitor = /x\n").unwrap();
        std::fs::write(m.join(".git/worktrees/wt/commondir"), "../..\n").unwrap();
        let wt = tempfile::tempdir().unwrap();
        let w = wt.path().canonicalize().unwrap();
        std::fs::write(w.join(".git"), format!("gitdir: {}\n", m.join(".git/worktrees/wt").display())).unwrap();
        let r = inspect(&w).unwrap();
        assert_eq!(r.root, w);
        assert!(r.runs_code, "{:?}", r.reasons);
    }
}
