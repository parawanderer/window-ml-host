//! redteam_sandbox_env.rs — `.env` and `.env.*` under the host's sandbox (window-ml's SECRET_HANDLES incident of
//! 2026-10-21; host#46, as built at 7c5a0e9b). The property: a call that does NOT name a dotenv file cannot read it, and
//! the facts say which files it cannot read.
//!
//! The lane's own rows (tests/stdio.rs and the unit tests in src/sandbox.rs) walk `.env`, `.env.local`, a nested one, the
//! templates and a root-top hardlink on the facts. These are the shapes those do not, and mostly as a REAL read:
//! `sandbox-exec` with the profile the call really gets. The Linux half asserts the bind list, which is the whole
//! decision there.
//!
//!   A. macOS, a real read: `.env` at any depth, `.env.local`, `.env.production`, `.env.examples` and
//!      `.env.example.local`, and the same reached through `..` and through a symlink of another name, are refused; the
//!      templates `.env.example`, `.env.sample` and `.env.template` are readable at the top and at depth; `.envrc`,
//!      `.env.d/x`, `x.env` and an ordinary file are still readable. (A case variant cannot be a real read here: on a
//!      case-insensitive volume `.ENV` IS `.env`, one inode. Its case-insensitivity is pinned on the deny line, B.)
//!   A2. a template's name reopens NOTHING else: the same name inside `~/.ssh`, under a `hidden` subpath, or as a
//!      hardlink to `.env` is still refused, while a plain template at a root's top and at depth is readable.
//!   B. the deny line is case-insensitive and stops at a `/`, the templates' allow comes after it, and the line after
//!      that re-denies the credential directories and every judged path but not the `.env.` prefix: the three
//!      properties the whole thing rests on.
//!   C. naming a dotenv file in the call makes the file readable, opens its siblings' names not at all, and opens its
//!      LINKS too (they are the inode that was approved); naming a LINK opens only that link.
//!   D. a root-top HARDLINK to `.env` is denied, masked and listed, like the file itself, on both platforms, across
//!      roots too; a link DEEPER than a root's top is readable and unlisted — the pinned known gap (docs/SANDBOX.md).
//!   D2. what BOUNDS D: the call cannot make that hardlink itself — `link` naming a denied file is refused by the same
//!      rules — so the residue is a name the person's own tooling already made, not one the call can build.
//!   E. Linux, the bind list: each root's top dotenv files (templates excluded) plus each root-top hardlink to one,
//!      every root, not `.envrc`, not a directory, not a symlink, not an ordinary hardlink, and not the one the call
//!      named — and naming `.env` drops its links with it.
//!   F. `hiddenSecrets`: only the top of each root, only regular files, never a symlink or a directory, nothing outside
//!      the roots, sorted, and a named file is not claimed — while a hardlink IS claimed, a template is not unless it is
//!      the `.env` inode, and an ordinary hardlink is never claimed.
//!   G. the window between the (dev, ino) read and the spawn: a name that is re-linked to `.env` after the scan is still
//!      denied (the rule is the PATH), and a file renamed to a fresh name after it is readable (the rule is a path, and
//!      that is the same gap as D's deep link).
//!   H. what the call's facts FLAG as secret (the public `looks_secret`, which the approval sheet shows): the templates
//!      are not, every other `.env.*` is, and a credential directory wins over a template's name.
//!
//! THE ONE THAT MATTERS MOST: D. A hardlink is the inode under another name, and no name rule sees it; the build now
//! judges each root's TOP by (dev, ino), so the shape is closed there and stays open below it, by name and by inode alike.
//! D2 is the row that says the residue is small: no one inside the sandbox can build the name.
//!
//! MUTATION PER ROW, MEASURED AT 7c5a0e9b (notes, not committed changes — one applied alone, this file run, the source
//! reverted with `git checkout -- src/`):
//!   A   src/sandbox.rs: `&& !DOTENV_TEMPLATES.contains(&name)` dropped from `is_dotenv_name` → A red:
//!      `.env.example was denied, and a template stays readable`.
//!   A   `const DOTENV_TEMPLATES: &[&str] = &[];` → A red at the same line.
//!   A2/B2  the second deny line (`p.push(format!("(deny file-read* {}", [dirs, held].concat().join(" ")));`) removed →
//!      A2 red: `a template inside .ssh was readable: PRIVATE-KEY`; B2 red at its `a deny after the templates`.
//!   D/E/F  `} else if md.nlink() > 1 {` → `} else if false {` → D red at "the facts claim the root-top hardlink"; E
//!      red on the mask list (the link is missing); F red at "a root-top hardlink is claimed".
//!   F  `.filter(|l| same(l))` → `.filter(|_| true)` → F red at "an ordinary hardlink is not claimed".
//!   D2 holds under all of the above: it asserts a refusal, so removing the deny makes it fail at its premise (the key is
//!      readable) rather than at the link.
//!
//! WHAT THIS FILE CANNOT ROW (named so the next reader does not look for it):
//!   - The case variant on a case-insensitive volume: `.ENV` and `.env` are one inode there, so a real read cannot tell
//!     the rule from the filesystem. B pins the pattern's case class instead; a case-SENSITIVE volume is not available
//!     in this session to confirm by read.
//!   - The LINUX side of D2: bwrap masks by bind mount, so `~/.ssh` is `/dev/null` inside the namespace and the source
//!     cannot even be named; whether a `link()` naming a source inside a granted-but-masked tree is refused was not
//!     measured here (no Linux host in this session). That is a reason to expect refusal, not a row.
//!   - A template's name at a depth BELOW a root's top being held when it is a link: `root_top_secrets` reads the top
//!     only, so `app/.env.example` is a link the profile's template allow reopens. Same gap as D's deep link, one name
//!     over, and pinned there.
//!   - `.env.example` being readable is a POLICY choice (a template holds no secret by convention) pinned as built, not
//!     argued: nothing parses the file, so a real secret written into one is not protected (docs/SANDBOX.md).
//!   - A `.env` below a root's top is not masked on Linux (Landlock cannot deny inside a grant). Pinned as built in E
//!     (the mask list) and F (the facts say nothing about it), and documented in docs/SANDBOX.md.
//!   - Naming a file as `secret` unmasks it for the WHOLE call, whatever the program then does with it: `pathArgs` is
//!     the consent surface, and the sheet shows what was named. Not a gap in the sandbox, a property of the approval.
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;

use window_ml_host::facts::looks_secret;
use window_ml_host::sandbox::{ExecScope, Plan, WriteScope, bwrap_args, root_top_secrets, seatbelt_profile};

// The profile's own spelling helpers, as `src/sandbox.rs` builds them (private there, mirrored here so the text
// assertions name exactly what the build writes): a case class per letter, a quoted literal, an SBPL `(regex …)`.
fn ci(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
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
    out
}
fn lit(p: &Path) -> String {
    let s = p.to_string_lossy();
    let mut out = String::from("\"");
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}
fn re(r: &str) -> String {
    format!("(regex {})", lit(Path::new(r)))
}

fn plan(roots: Vec<PathBuf>) -> Plan {
    Plan {
        roots,
        tmp: PathBuf::from("/nonexistent/tmp/c1"),
        hidden: vec![],
        allow_read: vec![],
        home: None,
        outlives_host: false,
        write: WriteScope::Today,
        exec: ExecScope::Any,
        proxy: None,
        proxy_socket: None,
    }
}

/// Every dotenv name at the top of a fresh tree, with the templates the build reopens and the near-misses a name rule
/// must leave alone. The root is the REAL path, as `configure` stores it (`resolve_root` canonicalizes) and as
/// `pathArgs[].path` comes back (`resolve_path` canonicalizes an existing file), so the plan fed here is the one a call
/// really builds.
struct Tree {
    _d: tempfile::TempDir,
    root: PathBuf,
}

/// The root-top files the build holds, before any root-top hardlink: the dotenv names, the templates left out.
const ROOT_TOP_NAMED: [&str; 5] = [".env", ".env.example.local", ".env.examples", ".env.local", ".env.production"];
/// The three templates, readable on both platforms.
const ROOT_TOP_TEMPLATES: [&str; 3] = [".env.example", ".env.sample", ".env.template"];
/// The root-top hardlink to `.env`: the same inode under a name no rule matches.
const ROOT_TOP_LINK: &str = "hardlink-to-env";
/// The hardlink to `.env` below the root's top: the pinned gap.
const DEEP_LINK: &str = "app/hardlink-to-env";

impl Tree {
    fn new() -> Tree {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap().join("w");
        std::fs::create_dir_all(root.join("app")).unwrap();
        std::fs::create_dir_all(root.join("held")).unwrap();
        for (rel, body) in [
            (".env", "DOTENV\n"),
            (".env.local", "LOCAL\n"),
            (".env.production", "PROD\n"),
            (".env.example", "EXAMPLE\n"),
            (".env.sample", "SAMPLE\n"),
            (".env.template", "TEMPLATE\n"),
            (".env.examples", "EXAMPLES\n"),
            (".env.example.local", "EXAMPLELOCAL\n"),
            (".envrc", "ENVRC\n"),
            (".env.d/x", "INDIR\n"),
            ("app/.env", "NESTED\n"),
            ("app/.env.production", "NESTEDPROD\n"),
            ("app/.env.example", "NESTEDTEMPLATE\n"),
            ("x.env", "NOTDOTENV\n"),
            ("notes.txt", "NOTHING\n"),
            ("plain-a.txt", "PLAIN\n"),
            ("plain-b.txt", "PLAIN\n"),
        ] {
            std::fs::create_dir_all(root.join(rel).parent().unwrap()).unwrap();
            std::fs::write(root.join(rel), body).unwrap();
        }
        std::fs::hard_link(root.join("plain-a.txt"), root.join("plain-b2.txt")).unwrap();
        symlink(root.join(".env"), root.join("link-to-env")).unwrap();
        std::fs::hard_link(root.join(".env"), root.join(ROOT_TOP_LINK)).unwrap();
        std::fs::hard_link(root.join(".env"), root.join(DEEP_LINK)).unwrap();
        Tree { _d: d, root }
    }
    fn at(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
    fn temp(&self) -> PathBuf {
        self._d.path().canonicalize().unwrap()
    }
    /// What `sandbox-exec` with `profile` makes of a read of `path`: whether it succeeded, and its output (either the
    /// bytes or the refusal).
    #[cfg(target_os = "macos")]
    fn read_under(&self, profile: &str, path: &Path) -> (bool, String) {
        let out = Command::new("/usr/bin/sandbox-exec").args(["-p", profile, "/bin/cat"]).arg(path).output().unwrap();
        (
            out.status.success(),
            format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)),
        )
    }
    fn masked_by(&self, p: &Plan) -> Vec<String> {
        let a: Vec<String> = bwrap_args(p, &self.root).iter().map(|s| s.to_string_lossy().into_owned()).collect();
        let mut m: Vec<String> =
            a.windows(3).filter(|w| w[0] == "--ro-bind" && w[1] == "/dev/null").map(|w| w[2].clone()).collect();
        m.sort();
        m
    }
}

// --- A: a real read through the profile the call really gets ---

/// macOS only: elsewhere there is no `sandbox-exec`, and the Linux half is E.
#[cfg(target_os = "macos")]
#[test]
fn a_dotenv_file_is_unreadable_at_any_depth_and_through_a_link_or_a_parent() {
    let t = Tree::new();
    let profile = seatbelt_profile(&plan(vec![t.root.clone()]));
    for rel in [
        ".env",
        ".env.local",
        ".env.production",
        ".env.examples",
        ".env.example.local",
        "app/.env",
        "app/.env.production",
    ] {
        let (ok, out) = t.read_under(&profile, &t.at(rel));
        assert!(!ok, "{rel} was readable: {out}");
    }
    // The templates are readable, at the top and below it: a model reads a committed template usefully.
    for rel in ROOT_TOP_TEMPLATES.iter().copied().chain(["app/.env.example"]) {
        let (ok, out) = t.read_under(&profile, &t.at(rel));
        assert!(ok, "{rel} was denied, and a template stays readable: {out}");
    }
    assert_eq!(t.read_under(&profile, &t.at(".env.sample")).1.trim(), "SAMPLE");
    // Reached another way: `..`, and a symlink named for neither.
    for (label, from) in [("through ..", t.at("app/../.env")), ("through a symlink", t.at("link-to-env"))] {
        let (ok, out) = t.read_under(&profile, &from);
        assert!(!ok, ".env was readable {label}: {out}");
    }
    let (ok, out) = t.read_under(&profile, &t.at(".env"));
    assert!(!ok && out.contains("Operation not permitted"), "the refusal is the kernel's, and says so: {out}");
    // The near-misses stay readable: `.envrc` is not `.env.`, and a directory's name is not a file's.
    for rel in [".envrc", ".env.d/x", "x.env", "notes.txt"] {
        let (ok, out) = t.read_under(&profile, &t.at(rel));
        assert!(ok, "{rel} was denied: {out}");
    }
}

// --- A2: a template's name reopens nothing else ---

/// The template allow is a NAME rule matching at any depth, so the line after it has to put back everything that was
/// denied for another reason: a credential directory, a path the call's own facts hid, and the `.env` inode by way of
/// a template's name. A template that is a symlink needs no row: `sandbox-exec` matches the RESOLVED vnode, and the
/// target is `.env`, which the deny line names.
#[cfg(target_os = "macos")]
#[test]
fn a_template_name_reopens_no_credential_dir_hidden_subpath_or_hardlink() {
    let t = Tree::new();
    let ssh = t.temp().join("home/.ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join(".env.example"), "PRIVATE-KEY\n").unwrap();
    let held = t.at("held");
    std::fs::write(held.join(".env.example"), "HELD\n").unwrap();
    std::fs::remove_file(t.at(".env.example")).unwrap();
    std::fs::hard_link(t.at(".env"), t.at(".env.example")).unwrap();
    let mut p = plan(vec![t.root.clone()]);
    p.hidden = vec![held.clone()];
    let profile = seatbelt_profile(&p);
    // The premise: a template outside all three reasons is readable.
    for rel in ROOT_TOP_TEMPLATES.iter().copied().filter(|r| *r != ".env.example").chain(["app/.env.example"]) {
        let (ok, out) = t.read_under(&profile, &t.at(rel));
        assert!(ok, "{rel} was denied: {out}");
    }
    for (label, path) in [
        ("a template inside .ssh", ssh.join(".env.example")),
        ("a template under a hidden subpath", held.join(".env.example")),
        ("a template that IS the .env inode", t.at(".env.example")),
    ] {
        let (ok, out) = t.read_under(&profile, &path);
        assert!(!ok, "{label} was readable: {out}");
    }
}

// --- B: the three properties of the deny-and-reopen lines ---

#[test]
fn the_deny_line_is_case_insensitive_and_does_not_cross_a_directory() {
    let t = Tree::new();
    let p = seatbelt_profile(&plan(vec![t.root.clone()]));
    let deny = p.lines().find(|l| l.starts_with("(deny file-read*")).expect("a deny line");
    // `.env` in any case, at any depth: the case class per letter and no `(/|$)` after it.
    assert!(deny.contains(r"/\\.[eE][nN][vV]$"), "`.env` case-insensitively, anchored at the path's end: {deny}");
    // `.env.` prefixed names, but only when the rest is the FILE's own name.
    assert!(deny.contains(r"/\\.[eE][nN][vV]\\.[^/]*$"), "`.env.*` case-insensitively, within one component: {deny}");
    // The old credential names are still there, so a refactor that dropped one did not drop the others with it.
    for n in [
        "[nN][eE][tT][rR][cC]$",
        "[gG][iI][tT]-[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL][sS]$",
        "[pP][gG][pP][aA][sS][sS]$",
    ] {
        assert!(deny.contains(n), "{n} is still denied: {deny}");
    }
    // The root-top hardlink is denied by its PATH, since no name rule sees the inode.
    assert!(
        deny.contains(&format!("(literal {})", lit(&t.at(ROOT_TOP_LINK)))),
        "the hardlink is a judged path: {deny}"
    );
}

/// The order the profile relies on: deny by name, allow the templates, then deny again everything the template's name
/// must not reopen. The second deny must NOT carry the `.env.` prefix pattern, or the templates would be shut again on
/// the line after the one that opened them.
#[test]
fn the_template_allow_sits_between_two_denies_and_only_the_second_drops_the_prefix() {
    let t = Tree::new();
    let p = seatbelt_profile(&plan(vec![t.root.clone()]));
    let at = |needle: &str| p.find(needle).unwrap_or_else(|| panic!("{needle} in {p}"));
    let template = at(&format!("(allow file-read* {}", re(&format!("/{}$", ci(".env.example")))));
    let first = at("(deny file-read*");
    let again = p[template..].find("(deny file-read*").map(|i| i + template).expect("a deny after the templates");
    assert!(first < template, "the name deny comes first");
    let line = p[again..].lines().next().unwrap();
    assert!(line.contains(&re(&format!("/{}(/|$)", ci(".ssh")))), "a credential directory is denied again: {line}");
    assert!(line.contains(&format!("(literal {})", lit(&t.at(ROOT_TOP_LINK)))), "and the hardlink: {line}");
    assert!(!line.contains(&re(&format!("/{}[^/]*$", ci(".env.")))), "the prefixes stay before the templates: {line}");
    for f in ROOT_TOP_TEMPLATES {
        assert!(p.contains(&re(&format!("/{}$", ci(f)))), "{f}'s allow is there");
    }
}

// --- C: naming the file is the way through, and it opens the inode's other names ---

#[cfg(target_os = "macos")]
#[test]
fn a_named_dotenv_file_is_readable_and_does_not_open_its_siblings_but_does_open_its_links() {
    let t = Tree::new();
    let mut p = plan(vec![t.root.clone()]);
    p.allow_read.push(t.at(".env"));
    let profile = seatbelt_profile(&p);
    let (ok, out) = t.read_under(&profile, &t.at(".env"));
    assert!(ok, "a named dotenv file was still denied: {out}");
    assert_eq!(out.trim(), "DOTENV");
    for rel in [".env.local", ".env.production", ".env.examples", "app/.env"] {
        let (ok, out) = t.read_under(&profile, &t.at(rel));
        assert!(!ok, "naming .env opened {rel}: {out}");
    }
    // The approval is of the INODE: every other name it has is the same bytes the person approved.
    let (ok, out) = t.read_under(&profile, &t.at(ROOT_TOP_LINK));
    assert!(ok, "naming .env left its hardlink denied: {out}");
    assert_eq!(out.trim(), "DOTENV");
}

/// The other direction: naming the LINK approves only that name. `.env` itself is still held, and so is its sibling.
#[cfg(target_os = "macos")]
#[test]
fn a_named_hardlink_opens_only_the_link() {
    let t = Tree::new();
    let mut p = plan(vec![t.root.clone()]);
    p.allow_read.push(t.at(ROOT_TOP_LINK));
    let profile = seatbelt_profile(&p);
    let (ok, out) = t.read_under(&profile, &t.at(ROOT_TOP_LINK));
    assert!(ok, "a named hardlink was still denied: {out}");
    for rel in [".env", ".env.local"] {
        let (ok, out) = t.read_under(&profile, &t.at(rel));
        assert!(!ok, "naming {ROOT_TOP_LINK} opened {rel}: {out}");
    }
}

// --- D: the hardlink, closed at each root's top and open below it ---

/// The shape no name rule sees. At a root's TOP the build now judges (dev, ino): the link is denied, masked and listed.
/// DEEPER the judgement stops at the top level, and the same inode is readable under a name nothing matches — the gap
/// docs/SANDBOX.md pins, and the reason the fix is a root-top check rather than a walk.
#[test]
fn a_root_top_hardlink_to_a_dotenv_file_is_held_and_a_deeper_one_is_the_pinned_gap() {
    let t = Tree::new();
    let link = t.at(ROOT_TOP_LINK);
    assert_eq!(std::fs::read(&link).unwrap(), b"DOTENV\n", "premise: the hardlink is the .env inode");
    let facts = root_top_secrets(std::slice::from_ref(&t.root), &[]);
    assert!(facts.contains(&link), "the facts claim the root-top hardlink: {facts:?}");
    // Across roots: a link in ANOTHER root's top to this root's `.env` is the same inode, and is held there too.
    let other = t.temp().join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::hard_link(t.at(".env"), other.join("cross.txt")).unwrap();
    let facts = root_top_secrets(&[t.root.clone(), other.clone()], &[]);
    assert!(facts.contains(&other.join("cross.txt")), "a cross-root hardlink is claimed: {facts:?}");
    // The mask list is the same names, so Linux hides it too.
    assert!(
        t.masked_by(&plan(vec![t.root.clone()])).contains(&link.display().to_string()),
        "the mask list holds the root-top hardlink"
    );
    #[cfg(target_os = "macos")]
    {
        let profile = seatbelt_profile(&plan(vec![t.root.clone()]));
        let (ok, out) = t.read_under(&profile, &link);
        assert!(!ok, "the root-top hardlink's bytes are readable under the sandbox: {out}");
        // The pinned gap: below the top, nothing judges it — readable, and the facts say nothing.
        let deep = t.at(DEEP_LINK);
        assert_eq!(std::fs::read(&deep).unwrap(), b"DOTENV\n", "premise: the deep link is the .env inode");
        let (ok, out) = t.read_under(&profile, &deep);
        assert!(ok, "the deep hardlink is closed now, so unpin this row and the doc: {out}");
    }
    assert!(
        !root_top_secrets(std::slice::from_ref(&t.root), &[]).contains(&t.at(DEEP_LINK)),
        "the facts do not claim a link below a root's top"
    );
}

/// What BOUNDS D: the call cannot make the hardlink itself. `link` naming a denied file is refused by the same rules,
/// so the leak needs a name the person's own tooling already made (`ln`, a backup tool, an editor's swap). Without this,
/// D would be an escape a program inside the sandbox could build for itself; measured here, and it holds.
#[cfg(target_os = "macos")]
#[test]
fn the_sandbox_does_not_let_a_program_make_the_hardlink_itself() {
    let t = Tree::new();
    let home = t.temp().join("home");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    let key = home.join(".ssh/id_rsa");
    std::fs::write(&key, "PRIVATE-KEY\n").unwrap();
    let profile = seatbelt_profile(&plan(vec![t.root.clone()]));
    let (ok, out) = t.read_under(&profile, &key);
    assert!(!ok, "premise: the key itself is read-denied: {out}");
    let leak = t.at("leak");
    let script = format!("ln {} {} 2>&1; echo ---; cat {} 2>&1", q(&key), q(&leak), q(&leak));
    let out = Command::new("/usr/bin/sandbox-exec").args(["-p", &profile, "/bin/sh", "-c", &script]).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(!leak.exists(), "the sandbox let the call hardlink a denied file into its root: {text}");
    assert!(!text.contains("PRIVATE-KEY"), "the key reached the call: {text}");
}

/// A single-quoted shell word, so a path with a space or a quote cannot change what the row runs.
#[cfg(target_os = "macos")]
fn q(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', r"'\''"))
}

// --- E: the Linux bind list ---

#[test]
fn the_linux_masks_are_each_roots_top_dotenv_files_and_hardlinks_and_nothing_else() {
    let t = Tree::new();
    let other = t.temp().join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join(".env"), "SECOND\n").unwrap();
    std::fs::write(other.join(".envrc"), "no\n").unwrap();
    std::fs::hard_link(t.at(".env"), other.join("cross.txt")).unwrap();
    let mut expected: Vec<String> = ROOT_TOP_NAMED
        .iter()
        .map(|n| t.at(n))
        .chain([t.at(ROOT_TOP_LINK), other.join(".env"), other.join("cross.txt")])
        .map(|p| p.display().to_string())
        .collect();
    expected.sort();
    assert_eq!(
        t.masked_by(&plan(vec![t.root.clone(), other.clone()])),
        expected,
        "every root's top, dotenv names (templates out) and hardlinks only"
    );
    // The templates are not masked, so the model can read them on Linux too.
    let got = t.masked_by(&plan(vec![t.root.clone()]));
    for f in ROOT_TOP_TEMPLATES {
        assert!(!got.contains(&t.at(f).display().to_string()), "{f} is not masked: {got:?}");
    }
    // A named file is not masked, and its LINKS are the inode that was named: they are not masked either. The rest
    // still are.
    let mut named = plan(vec![t.root.clone(), other.clone()]);
    named.allow_read.push(t.at(".env"));
    let got = t.masked_by(&named);
    for p in [t.at(".env"), t.at(ROOT_TOP_LINK), other.join("cross.txt")] {
        assert!(!got.contains(&p.display().to_string()), "naming .env left a link masked: {}", p.display());
    }
    assert!(got.contains(&t.at(".env.local").display().to_string()), "naming .env must not unmask .env.local: {got:?}");
    // A symlink, a directory and an ordinary hardlink are not masks. The symlink's TARGET is, so a read through it
    // comes back empty; the directory is not, so a file inside one is readable there (the documented Linux gap).
    for m in &got {
        assert_ne!(Path::new(m), t.at("link-to-env"), "a link is not a mask");
        assert_ne!(Path::new(m), t.at(".env.d"), "a directory is not a mask");
        assert_ne!(Path::new(m), t.at("plain-b2.txt"), "an ordinary hardlink is not a mask");
    }
}

// --- F: what the facts may claim ---

#[test]
fn the_facts_list_each_roots_top_dotenv_files_and_hardlinks_and_nothing_else() {
    let t = Tree::new();
    let other = t.temp().join("other");
    std::fs::create_dir_all(other.join("deep")).unwrap();
    std::fs::write(other.join("deep/.env"), "DEEP\n").unwrap();
    std::fs::write(other.join(".env"), "SECOND\n").unwrap();
    std::fs::hard_link(other.join(".env"), other.join(".env.example")).unwrap();
    let got = root_top_secrets(&[t.root.clone(), other.clone()], &[]);
    for n in ROOT_TOP_NAMED {
        assert!(got.contains(&t.at(n)), "{n} at the root's top is claimed");
    }
    assert!(got.contains(&t.at(ROOT_TOP_LINK)), "a root-top hardlink is claimed");
    assert!(got.contains(&other.join(".env")), "a second root's .env is claimed too");
    // A template is not claimed — unless it IS the hidden inode, under a template's name.
    assert!(got.contains(&other.join(".env.example")), "a template that is the .env inode is claimed");
    for f in ROOT_TOP_TEMPLATES {
        assert!(!got.contains(&t.at(f)), "{f} is a template, not a secret");
    }
    assert!(!got.contains(&other.join("deep/.env")), "a deeper file is not claimed (Linux would not hide it)");
    assert!(!got.contains(&t.at("app/.env")), "a nested file is not claimed");
    assert!(!got.contains(&t.at(DEEP_LINK)), "a link below the top is not claimed");
    assert!(!got.contains(&t.at("link-to-env")), "a symlink is not claimed, and not masked");
    assert!(!got.contains(&t.at("plain-b2.txt")), "an ordinary hardlink is not claimed");
    assert!(!got.contains(&t.at(".env.d")), "a directory is not claimed");
    assert!(!got.contains(&t.at("x.env")), "`x.env` is not a dotenv name");
    let mut sorted = got.clone();
    sorted.sort();
    assert_eq!(got, sorted, "the list is sorted");
    // Naming the file drops it AND every link that is its inode; naming a link drops only the link.
    let named = root_top_secrets(std::slice::from_ref(&t.root), &[t.at(".env")]);
    assert!(!named.contains(&t.at(".env")) && !named.contains(&t.at(ROOT_TOP_LINK)), "naming .env opens its links");
    let linked = root_top_secrets(std::slice::from_ref(&t.root), &[t.at(ROOT_TOP_LINK)]);
    assert!(!linked.contains(&t.at(ROOT_TOP_LINK)), "a named link is not claimed");
    assert!(linked.contains(&t.at(".env")), "naming a link does not open the file");
    for p in &got {
        assert!(p.starts_with(&t.root) || p.starts_with(&other), "claimed a path outside the roots: {}", p.display());
    }
}

// --- G: between the (dev, ino) read and the spawn ---

/// The scan and the profile are one moment; the tree can change before the program starts. The rule is a PATH, which
/// gives both halves of this row: a judged path stays denied whatever inode it names now (cheap over-denial), and a name
/// made or renamed into after the scan is judged by nothing (the window). The second is D's deep-link gap reached from
/// the other side, and is pinned for the same reason: closing it needs a check at open time, and D2 says nothing inside
/// the sandbox can build the link.
#[cfg(target_os = "macos")]
#[test]
fn a_link_made_after_the_scan_is_judged_by_no_rule_and_a_judged_path_stays_denied() {
    let t = Tree::new();
    let profile = seatbelt_profile(&plan(vec![t.root.clone()]));
    let (ok, out) = t.read_under(&profile, &t.at(ROOT_TOP_LINK));
    assert!(!ok, "premise: the root-top hardlink is denied at the scan: {out}");
    // A judged path keeps its deny even when the inode it held is gone and an ordinary file takes the name.
    std::fs::remove_file(t.at(ROOT_TOP_LINK)).unwrap();
    std::fs::write(t.at(ROOT_TOP_LINK), "ORDINARY NOW\n").unwrap();
    let (ok, out) = t.read_under(&profile, &t.at(ROOT_TOP_LINK));
    assert!(!ok, "a judged path stopped being denied when its inode changed: {out}");
    // A name made AFTER the scan that links `.env` is unjudged: the window, and it reads the value.
    std::fs::hard_link(t.at(".env"), t.at("late-link.txt")).unwrap();
    let (ok, out) = t.read_under(&profile, &t.at("late-link.txt"));
    assert!(ok, "a link made after the scan is judged now, so unpin this row and the doc: {out}");
    assert_eq!(out.trim(), "DOTENV");
    // And a rename of the file itself to a fresh name, which is the same shape.
    std::fs::rename(t.at(".env"), t.at("env-renamed.txt")).unwrap();
    let (ok, out) = t.read_under(&profile, &t.at("env-renamed.txt"));
    assert!(ok, "a renamed .env is denied now, so unpin this row and the doc: {out}");
    assert_eq!(out.trim(), "DOTENV");
}

// --- H: what the call's facts may FLAG as secret, the public judgement the sheet shows ---

/// The sandbox and the facts must agree on which names are templates, or a template is refused for being secret while
/// the sandbox would let it through (or the reverse: a `.env.production` shown as ordinary). `looks_secret` is the
/// public form (`src/facts.rs`), and a credential directory still wins over a template's name.
#[test]
fn a_template_is_not_flagged_secret_but_everything_a_secret_directory_holds_is() {
    for p in ["/r/.env.example", "/r/.ENV.Sample", "/r/app/.env.template", "/r/app/.env.example"] {
        assert!(!looks_secret(Path::new(p)), "{p} is a template, not a secret");
    }
    for p in ["/r/.env", "/r/.env.local", "/r/.env.examples", "/r/.env.example.local", "/home/u/.ssh/.env.example"] {
        assert!(looks_secret(Path::new(p)), "{p} is not a template");
    }
}
