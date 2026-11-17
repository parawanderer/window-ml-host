//! redteam_sandbox_env.rs — `.env` and `.env.*` under the host's sandbox (window-ml's SECRET_HANDLES incident of
//! 2026-10-21; host#46, as built at 7c5a0e9b, plus the write deny of 621d2a9). The property: a call that does NOT name a
//! dotenv file cannot read it, and the facts say which files it cannot read — and a name the sandbox holds cannot be
//! MOVED out from under that rule either, because the next call's read is judged by the new name.
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
//!   J. the MOVE across calls (the write deny, 621d2a9): a held name cannot become a name nothing holds — by rename, by
//!      copy, by link, or by a write onto the held name from an allowed one — while an ordinary file and a template
//!      still rename under the same write scope, which is the control that makes a refusal mean the dotenv rule. On
//!      macOS this is a real `mv`/`cp`/`ln`/`git add` under the profile; the attempt is then followed by the NEXT call's
//!      own scan, which must read nothing at the names the attempts would have made. Naming `.env` reopens its read and
//!      still not its rename or its removal. The write deny covers every name the read side holds (`.env`, `.env.*` and
//!      the credential files, whose rename launders them the same way), not the templates, and not `.envrc` or `x.env`.
//!      Renaming the PARENT of a deep `.env` is allowed and moves nothing: the next call still refuses `app2/.env`.
//!   K. a root-top SYMLINK with a HELD name (the repair at 549faf3): the value is unreadable through the link name,
//!      through the target's own path, through a second hardlink and a second link to the target, and through a chain
//!      (the END of the chain is what is held); a link made or retargeted AFTER the scan is refused at its own name and
//!      the target's fresh name is the window, with the next call's scan holding the link and the target; a dotenv-named
//!      link to a DIRECTORY or a device holds nothing, and what the directory holds is judged by its own name; and every
//!      path the facts list is one the sandbox really holds, on both platforms.
//!
//! THE ONE THAT MATTERS MOST: D. A hardlink is the inode under another name, and no name rule sees it; the build now
//! judges each root's TOP by (dev, ino), so the shape is closed there and stays open below it, by name and by inode alike.
//! D2 is the row that says the residue is small: no one inside the sandbox can build the name. J is the second one: with
//! no write rule, a rename in one call hands the value to the next call under a name nothing holds, and the read deny is
//! never consulted.
//!
//! MUTATION PER ROW, MEASURED AT 7c5a0e9b (section J at 7b59af9; notes, not committed changes — one applied alone, this
//! file run, the source reverted with `git checkout -- src/`):
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
//!   J-a the `p.push(format!("(deny file-write* {}", held_write.join(" ")))` line removed (the whole write deny) → J red
//!      at `mv .env.local moved-local.txt succeeded`: the laundering rename works and nothing else looks at the new name.
//!      J2 red at `naming .env let the call mv .env moved.txt`; the text row red at "the dotenv write deny". Measured at
//!      7b59af9: `mv .env` is refused even without the line (its inode also bears two read-denied hardlink literals), so
//!      the row leads with a plain dotenv name; the DEST direction (`mv notes-new.txt .env`) also reds there, and is a
//!      later shape on purpose.
//!   J-b `held_write`'s `(require-all (require-any names) (require-not (require-any templates)))` reduced to
//!      `(require-any names)` → J red at "the control failed: … mv: rename .env.template to tmpl-renamed.txt: Operation
//!      not permitted", the text row at its template assertion: the exclusion is what keeps a template writable.
//!
//! MUTATION PER ROW, MEASURED AT 549faf3 (section K, the same way: one applied alone, this file run, reverted):
//!   K1/K2/K3/K5  the link branch's `links.push(e.path()); named.push((t, tm.dev(), tm.ino()));` removed (a symlink is
//!      not listed — the rule before the repair) → K1 red at ".env is not held", K2 at "the chain's link is listed", K3
//!      at ".env is not held by the next call's scan", K5 at the same list.
//!   K4  `if tm.is_file() && !own && …` → `if !own && …` → K4 red at "a link to a directory holds .env.conf", and K5 at
//!      the Linux half: a directory target is listed, and `--ro-bind /dev/null` is not what a directory gets.
//!   (No single-line mutation lists a path WITHOUT holding it: `bwrap_args` and `seatbelt_profile` both read the one
//!    `root_top_secrets`, so an extra entry reaches the masks and the deny line together. Adding `notes.txt` to the
//!    output reds section E, A and J on the unexpected mask, and K5 stays green because both halves moved together —
//!    which is the property K5 exists to state, not a gap in it.)
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
//!   - The LINUX half of J as a real command: there is no Linux host in this session, so a rename or unlink inside the
//!     namespace cannot be run here. E asserts the mask list the rename would hit (each root's top names and each
//!     root-top hardlink, by bind mount), and the lane's tests/stdio.rs row asserts the refusal on Linux CI.
//!   - A rename made OUTSIDE the sandbox between the scan and the spawn: no rule can see it, which is the same window G
//!     pins from the read side and docs/SANDBOX.md documents. J closes the move the CALL can make, not the person's own.
//!   - K3's window is not closable at the path level, for G's reason: the profile is built from ONE scan. What the row
//!     asserts is both halves of where it lands: a held-name link made or retargeted after the scan still cannot be read
//!     (resolving it is a metadata read of a `.env*` name, which the name rule denies), while its target's fresh name can
//!     (that is G's window), and the next call's scan holds the link and the target it resolves to.
//!   - A held-name link whose target is a dotenv FILE inside a directory: the directory is not held (K4), so the file is
//!     reached through a name nothing holds; on macOS the name rule still refuses `dir/.env` at any depth, on Linux it is
//!     the documented deep-file gap. K4 states both, as a row for the directory and a mask-list assertion for the file.
//!   - On Linux a listed LINK is not masked itself: `bwrap_args` masks what `symlink_metadata` calls a file or a
//!     directory, and a link is neither. The read through the name lands on the masked TARGET, so the value is closed;
//!     K1, K2 and K5 assert it that way rather than asserting a mask that is not built.
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;

use window_ml_host::facts::looks_secret;
use window_ml_host::sandbox::{
    DOTENV_TEMPLATES, ExecScope, Plan, WriteScope, bwrap_args, root_top_secrets, seatbelt_profile,
};

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

// --- J: the move across calls (host#46's write deny, 621d2a9) ---

/// `sandbox-exec` with `profile`, running `script` in `cwd`: whether it exited 0, and what it said. macOS only; the
/// Linux side of the same property is the bind mask (E), which makes a rename of a masked name EBUSY rather than a
/// denial, and is asserted there as a list because this session has no Linux host.
#[cfg(target_os = "macos")]
fn run_under(profile: &str, cwd: &Path, script: &str) -> (bool, String) {
    let out = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", profile, "/bin/sh", "-c", script])
        .current_dir(cwd)
        .output()
        .unwrap();
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// The profile the NEXT call would build, from the tree the first call left: the scan is per call, so a name the first
/// call created is judged by the next call's rules and not by the profile it ran under.
#[cfg(target_os = "macos")]
fn next_call(t: &Tree) -> String {
    seatbelt_profile(&plan(vec![t.root.clone()]))
}

#[cfg(target_os = "macos")]
fn have_git() -> bool {
    Command::new("git").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

/// A rename needs no read: `mv .env.local moved-local.txt` in one call would leave the value under a name nothing holds,
/// and the next call — a fresh scan of the tree this one left — would read it. The write deny (621d2a9) is the fix; this
/// row asserts the CONTROL that makes it load-bearing (an ordinary file and a template both rename fine under the same
/// write scope, so a refusal below is the dotenv rule and not "the profile cannot rename"), the shapes, and then what
/// the next call can actually read at the names the attempts would have made. The source-direction shapes use a plain
/// dotenv name on purpose: measured at 7b59af9 with the deny line removed, `mv .env` is STILL refused while
/// `mv .env.local` succeeds, because `.env` in this fixture is the inode of two read-denied hardlink literals and the
/// refusal comes from those, not from the write rule — so a row that led with `mv .env` would red for the wrong reason.
#[cfg(target_os = "macos")]
#[test]
fn a_held_dotenv_cannot_be_moved_or_copied_and_the_next_call_reads_nothing_at_the_new_name() {
    let t = Tree::new();
    let profile = next_call(&t);
    for (label, cmd, from, to) in [
        ("an ordinary file", "mv notes.txt notes-new.txt", "notes.txt", "notes-new.txt"),
        ("a template", "mv .env.template tmpl-renamed.txt", ".env.template", "tmpl-renamed.txt"),
    ] {
        let (ok, out) = run_under(&profile, &t.root, cmd);
        assert!(ok, "the control failed: {label} must still rename under this write scope: {out}");
        assert!(t.at(to).exists() && !t.at(from).exists(), "the control's premise: {cmd}");
    }
    for cmd in [
        // The threat first: a held name moved to a name nothing holds, at the top and at depth.
        "mv .env.local moved-local.txt",
        "mv .env.example.local ex-local.txt",
        "mv app/.env app/env-renamed.txt",
        "mv .env moved.txt",
        // Then the same value reached another way: a copy, a link, and a name that resolves to `.env`.
        "cp .env copied.txt",
        "ln .env linked.txt",
        "ln -s .env sym.txt",
        // Then the WRITE onto a held name from a name that is allowed, and the laundering into a readable template.
        "mv notes-new.txt .env",
        "mv .env .env.local",
        "cp .env .env.example",
    ] {
        let (ok, out) = run_under(&profile, &t.root, cmd);
        // A symlink names `.env` without opening it, so `ln -s` may succeed; what must not is the read of the name it
        // made, asserted with the next call's profile below.
        assert!(!ok || cmd.starts_with("ln -s"), "{cmd} succeeded: {out}");
        assert_eq!(std::fs::read(t.at(".env")).unwrap(), b"DOTENV\n", "{cmd}: the held file is untouched");
        assert_eq!(std::fs::read(t.at(".env.local")).unwrap(), b"LOCAL\n", "{cmd}: the sibling is untouched");
        assert_eq!(std::fs::read(t.at(".env.example")).unwrap(), b"EXAMPLE\n", "{cmd}: the template is untouched");
        assert!(!t.at("moved.txt").exists(), "{cmd}");
        assert!(!t.at("copied.txt").exists(), "{cmd}");
        assert!(!t.at("linked.txt").exists(), "{cmd}");
        assert!(!t.at("env-renamed.txt").exists(), "{cmd}");
        assert!(!t.at("moved-local.txt").exists(), "{cmd}");
        assert!(!t.at("ex-local.txt").exists(), "{cmd}");
    }
    // The next call: a fresh scan of the tree this one left. No name an attempt could have made holds a readable value,
    // `.env` is still refused, and a symlink the call managed to make resolves to `.env` and is refused by the rule's
    // PATH, not by the link's name.
    let after = next_call(&t);
    for rel in ["moved.txt", "copied.txt", "linked.txt", "moved-local.txt", "ex-local.txt", "app/env-renamed.txt"] {
        let (ok, out) = t.read_under(&after, &t.at(rel));
        assert!(!ok, "{rel} exists and the next call reads it: {out}");
    }
    if t.at("sym.txt").exists() {
        let (ok, out) = t.read_under(&after, &t.at("sym.txt"));
        assert!(!ok, "a symlink to .env made by the call is readable by the next one: {out}");
    }
    let (ok, out) = t.read_under(&after, &t.at(".env"));
    assert!(!ok, ".env was readable by the next call: {out}");
    // Renaming the PARENT of a deep `.env` moves the whole name, not a file: the deny is a resolved PATH, so the next
    // call refuses `app2/.env` too. The DEEP hardlink stays readable, which is D's gap and not this row's business, and
    // is asserted so that the parent's rename is not credited with closing it.
    let (ok, out) = run_under(&profile, &t.root, "mv app app2");
    assert!(ok, "the premise: a directory's own name is not a dotenv name: {out}");
    let moved = next_call(&t);
    for rel in ["app2/.env", "app2/.env.production", "app2/.env.example.local"] {
        let (ok, out) = t.read_under(&moved, &t.at(rel));
        assert!(!ok, "renaming the parent of {rel} made it readable: {out}");
    }
    let (ok, out) = t.read_under(&moved, &t.at("app2/.env.example"));
    assert!(ok, "a template stays readable after its directory is renamed: {out}");
    let (ok, out) = t.read_under(&moved, &t.at(DEEP_LINK.replace("app/", "app2/").as_str()));
    assert!(
        ok,
        "the deep hardlink is D's pinned gap, and moving its parent must not be credited with closing it: {out}"
    );
}

/// Naming a file reopens its READ and nothing else: the approval is of the bytes, not of the name's freedom. So a call
/// that named `.env` can `cat` it and still cannot RENAME, REMOVE or overwrite it — the move that would leave the value
/// under a name nothing holds. A COPY or a hardlink the call makes of it is NOT asserted as a refusal: an approved read
/// is the bytes already in the call's hands, and a model can put those bytes into a file by other means, so refusing the
/// copy would buy nothing the approval had not given away. What must hold is that the held NAME cannot be moved.
#[cfg(target_os = "macos")]
#[test]
fn naming_a_dotenv_file_reopens_its_read_and_not_its_rename() {
    let t = Tree::new();
    let mut p = plan(vec![t.root.clone()]);
    p.allow_read.push(t.at(".env"));
    let profile = seatbelt_profile(&p);
    let (ok, out) = t.read_under(&profile, &t.at(".env"));
    assert!(ok, "premise: a named dotenv file is readable: {out}");
    for cmd in ["mv .env moved.txt", "rm .env", "mv .env .env.local", "mv notes.txt .env"] {
        let (ok, out) = run_under(&profile, &t.root, cmd);
        assert!(!ok, "naming .env let the call {cmd}: {out}");
        assert_eq!(std::fs::read(t.at(".env")).unwrap(), b"DOTENV\n", "{cmd}");
        assert!(!t.at("moved.txt").exists(), "{cmd}");
    }
    // The next call carries no approval: the name is held again, and no name the attempts would have made is readable.
    let after = next_call(&t);
    for rel in [".env", "moved.txt"] {
        let (ok, out) = t.read_under(&after, &t.at(rel));
        assert!(!ok, "{rel} is readable by the next call: {out}");
    }
}

/// `git add` reads the file, so a held dotenv file cannot enter the index, and nothing in `.git/objects` holds its
/// bytes afterwards: the next call cannot `git show` what was never added. A template does add, so the refusal is the
/// file and not a broken repository.
#[cfg(target_os = "macos")]
#[test]
fn a_held_dotenv_cannot_be_git_added_and_no_blob_holds_it() {
    let t = Tree::new();
    if !have_git() {
        return;
    }
    let git = |args: &[&str]| {
        Command::new("git")
            .current_dir(&t.root)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "e3")
            .env("GIT_AUTHOR_EMAIL", "e3@example.invalid")
            .env("GIT_COMMITTER_NAME", "e3")
            .env("GIT_COMMITTER_EMAIL", "e3@example.invalid")
            .output()
            .unwrap()
    };
    assert!(git(&["init", "-q", "-b", "main"]).status.success(), "premise: a repository");
    assert!(git(&["add", ".env.template", "notes.txt"]).status.success(), "premise: an ordinary add");
    let committed = git(&["commit", "-qm", "base"]).status.success();
    assert!(committed, "premise: a commit");
    let profile = next_call(&t);
    for cmd in ["git add .env", "git add .env.local", "git hash-object .env", "git add app/.env"] {
        let (ok, out) = run_under(&profile, &t.root, cmd);
        assert!(!ok, "{cmd} succeeded on a held file: {out}");
    }
    // `add -A` may fail or may walk past the file; what matters is that no blob holds the value either way.
    let _ = run_under(&profile, &t.root, "git add -A");
    let mut leaked = vec![];
    let mut stack = vec![t.at(".git/objects")];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if std::fs::read(&p).map(|b| b.windows(6).any(|w| w == b"DOTENV")).unwrap_or(false) {
                leaked.push(p);
            }
        }
    }
    assert!(leaked.is_empty(), "the object store holds the value: {leaked:?}");
    assert_eq!(std::fs::read(t.at(".env")).unwrap(), b"DOTENV\n");
    // The next call cannot show what was never added, and the repository still works for a template.
    let after = next_call(&t);
    let (ok, out) = run_under(&after, &t.root, "git show :.env");
    assert!(!ok && !out.contains("DOTENV"), "the next call showed a held file from the index: {out}");
    let (ok, out) = run_under(&after, &t.root, "git show :.env.template");
    assert!(ok, "a template's blob is not there or the repository is broken: {out}");
}

// --- J2: the write deny, as the text the profile really carries ---

/// macOS's half of the move is one line, and its properties are what make it safe rather than merely present: it comes
/// AFTER the write allow (an earlier deny would be overridden), it holds every non-template name the sandbox refuses to
/// READ anywhere — `.env`, every `.env.*`, and the credential files `.netrc`, `.git-credentials` and `.pgpass`, which
/// launder through a rename exactly as `.env` does — it excludes the templates by `require-not` (or a template would stop
/// being writable), it holds each root-top hardlink by literal (no name rule sees the inode), and it adds no name the
/// read side leaves alone (`.envrc`, `x.env`). Linux's half is the bind mask asserted in E; its rename refusal and a
/// template's writability are the lane's rows in tests/stdio.rs.
#[test]
fn the_write_deny_holds_every_name_the_read_side_holds_and_not_the_templates() {
    let t = Tree::new();
    let p = seatbelt_profile(&plan(vec![t.root.clone()]));
    let line = p
        .lines()
        .find(|l| l.starts_with("(deny file-write*") && l.contains("require-all"))
        .expect("the dotenv write deny");
    let allow = p.find("(allow file-write* ").expect("the write allow");
    assert!(allow < p.find(line).unwrap(), "a write deny before the allow would be overridden by it: {line}");
    for n in [".env", ".netrc", ".git-credentials", ".pgpass"] {
        assert!(
            line.contains(&re(&format!("/{}$", ci(n)))),
            "{n} is a name the read side holds, so a rename must not launder it: {line}"
        );
    }
    assert!(line.contains(&re(&format!("/{}[^/]*$", ci(".env.")))), "the prefixed names, within one component: {line}");
    assert!(line.contains("(require-not (require-any "), "the templates are excluded, not the whole line: {line}");
    for f in DOTENV_TEMPLATES {
        assert!(line.contains(&re(&format!("/{}$", ci(f)))), "the template {f} is writable: {line}");
    }
    assert!(
        line.contains(&format!("(literal {})", lit(&t.at(ROOT_TOP_LINK)))),
        "the root-top hardlink is held by path: {line}"
    );
    for n in [".envrc", "x.env", "notes.txt"] {
        assert!(
            !line.contains(&re(&format!("/{}$", ci(n)))),
            "{n} is not held for reading, so it is not held for writing: {line}"
        );
    }
}

// --- K: a root-top SYMLINK with a HELD name: the link, its target, and every way to reach it ---

/// The shape the repair at 549faf3 is about, in one root: `config.txt` is an ordinary file, `.env` is a SYMLINK with a
/// held name to it, `copy.txt` is a hardlink to it, `alias.txt` is a symlink to it under a name nothing holds, a two-hop
/// chain ends at `end.txt`, `.env.conf` is a link to a directory, and `.env.null` points at the sandbox's own /dev/null.
struct KTree {
    _d: tempfile::TempDir,
    root: PathBuf,
}

impl KTree {
    fn new() -> KTree {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap().join("w");
        std::fs::create_dir_all(root.join("conf")).unwrap();
        std::fs::write(root.join("config.txt"), "TARGET\n").unwrap();
        std::fs::write(root.join("end.txt"), "CHAINEND\n").unwrap();
        std::fs::write(root.join("notes.txt"), "NOTHING\n").unwrap();
        std::fs::write(root.join("conf/.env"), "INNERDOTENV\n").unwrap();
        std::fs::write(root.join("conf/plain.txt"), "INNERPLAIN\n").unwrap();
        symlink(Path::new("config.txt"), root.join(".env")).unwrap();
        std::fs::hard_link(root.join("config.txt"), root.join("copy.txt")).unwrap();
        symlink(Path::new("config.txt"), root.join("alias.txt")).unwrap();
        symlink(Path::new("end.txt"), root.join("hop")).unwrap();
        symlink(Path::new("hop"), root.join(".env.chain")).unwrap();
        symlink(Path::new("conf"), root.join(".env.conf")).unwrap();
        symlink(Path::new("/dev/null"), root.join(".env.null")).unwrap();
        KTree { _d: d, root }
    }
    fn at(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
    /// What the facts list for this root, as the sheet would show it.
    fn held(&self) -> Vec<PathBuf> {
        root_top_secrets(std::slice::from_ref(&self.root), &[])
    }
    fn masked_by(&self, p: &Plan) -> Vec<String> {
        let a: Vec<String> = bwrap_args(p, &self.root).iter().map(|s| s.to_string_lossy().into_owned()).collect();
        let mut m: Vec<String> =
            a.windows(3).filter(|w| w[0] == "--ro-bind" && w[1] == "/dev/null").map(|w| w[2].clone()).collect();
        m.sort();
        m
    }
    #[cfg(target_os = "macos")]
    fn read_under(&self, profile: &str, path: &Path) -> (bool, String) {
        let out = Command::new("/usr/bin/sandbox-exec").args(["-p", profile, "/bin/cat"]).arg(path).output().unwrap();
        (
            out.status.success(),
            format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)),
        )
    }
}

/// A link with a held name is not the file: holding only the NAME would leave `config.txt` open under its own name and
/// `copy.txt` open by inode. The repair holds the target too, which closes all four ways at one judged path — the link
/// name, the target's path, a second hardlink (same inode, matched at a root's top) and a second link (its own name is
/// nothing, and it resolves to a judged path).
#[test]
fn a_held_name_link_holds_its_target_and_every_root_top_name_to_it() {
    let t = KTree::new();
    assert_eq!(std::fs::read(t.at(".env")).unwrap(), b"TARGET\n", "premise: the link reads the file");
    let held = t.held();
    for n in [".env", "config.txt", "copy.txt"] {
        assert!(held.contains(&t.at(n)), "{n} is not held: {held:?}");
    }
    assert!(!held.contains(&t.at("alias.txt")), "a link whose own name nothing holds is not listed; its target is");
    // Linux: the masks are the TARGET and the hardlink. A link's own path is not one — `bwrap_args` masks what
    // `symlink_metadata` calls a file or a directory, and a link is neither — but a read through the name lands on the
    // masked target, so the value comes back as /dev/null's all the same.
    let masked = t.masked_by(&plan(vec![t.root.clone()]));
    for n in ["config.txt", "copy.txt"] {
        assert!(masked.contains(&t.at(n).display().to_string()), "{n} is held but not masked: {masked:?}");
    }
    for n in [".env", "alias.txt"] {
        assert!(!masked.contains(&t.at(n).display().to_string()), "a link's own path is not a mask: {n} in {masked:?}");
    }
    #[cfg(target_os = "macos")]
    {
        let profile = seatbelt_profile(&plan(vec![t.root.clone()]));
        for n in [".env", "config.txt", "copy.txt", "alias.txt"] {
            let (ok, out) = t.read_under(&profile, &t.at(n));
            assert!(!ok, "the value is readable through {n}: {out}");
            assert!(!out.contains("TARGET"), "the value reached the call through {n}: {out}");
        }
    }
    // Naming the target is the way through, and it opens the link that resolves to it — nothing else.
    let named = root_top_secrets(std::slice::from_ref(&t.root), &[t.at("config.txt")]);
    assert!(
        !named.contains(&t.at("config.txt")) && !named.contains(&t.at(".env")),
        "naming the target opens it and the link to it: {named:?}"
    );
    assert!(named.contains(&t.at("end.txt")), "naming one target must not open another: {named:?}");
}

/// A chain has one thing worth holding: its end. `canonicalize` follows it, so the middle hop needs no name of its own,
/// and a read through any name in the chain lands on the end, whose path is judged.
#[test]
fn a_link_chain_is_resolved_to_its_end_and_the_end_is_what_is_held() {
    let t = KTree::new();
    assert_eq!(std::fs::read(t.at(".env.chain")).unwrap(), b"CHAINEND\n", "premise: the chain reads the end");
    let held = t.held();
    assert!(held.contains(&t.at(".env.chain")), "the chain's link is listed: {held:?}");
    assert!(held.contains(&t.at("end.txt")), "the END of the chain is held, not the hop: {held:?}");
    assert!(!held.contains(&t.at("hop")), "a link in the middle of a chain needs no name of its own: {held:?}");
    let masked = t.masked_by(&plan(vec![t.root.clone()]));
    assert!(
        masked.contains(&t.at("end.txt").display().to_string()),
        "the chain's end is held but not masked: {masked:?}"
    );
    assert!(
        !masked.contains(&t.at(".env.chain").display().to_string()),
        "a link's own path is not a mask; the end it resolves to is: {masked:?}"
    );
    #[cfg(target_os = "macos")]
    {
        let profile = seatbelt_profile(&plan(vec![t.root.clone()]));
        for n in [".env.chain", "hop", "end.txt"] {
            let (ok, out) = t.read_under(&profile, &t.at(n));
            assert!(!ok, "the chain's end is readable through {n}: {out}");
            assert!(!out.contains("CHAINEND"), "the value reached the call through {n}: {out}");
        }
    }
}

/// The scan and the profile are one moment, and the rule is a PATH — but a held-NAME link is judged TWICE over: resolving
/// it is a metadata read of a `.env*` name, which the name rule denies, so neither a link made after the scan nor a
/// retargeted one opens the file it lands on. What the window does give is the TARGET's own name: `fresh.txt` was never
/// judged, so it reads directly (G's window, reached through a link). The next call's scan resolves both links and holds
/// the target.
#[cfg(target_os = "macos")]
#[test]
fn a_held_name_link_made_or_retargeted_after_the_scan_is_refused_at_its_name_and_the_next_call_holds_the_target() {
    let t = KTree::new();
    let profile = seatbelt_profile(&plan(vec![t.root.clone()]));
    let (ok, out) = t.read_under(&profile, &t.at("config.txt"));
    assert!(!ok, "premise: the scan holds the link's target: {out}");
    // A held-name link made AFTER the scan, to a file the scan never saw: no rule names `fresh.txt`, and the link is
    // refused anyway — reading it means reading the name `.env.late`.
    std::fs::write(t.at("fresh.txt"), "FRESH\n").unwrap();
    symlink(Path::new("fresh.txt"), t.at(".env.late")).unwrap();
    let (ok, out) = t.read_under(&profile, &t.at(".env.late"));
    assert!(!ok, "a held-name link made after the scan was readable, so the window is open here: {out}");
    assert!(!out.contains("FRESH"), "the value reached the call through the new link: {out}");
    // The target's own name is the window, and it is G's: nothing judged `fresh.txt`, and a link points at it now.
    let (ok, out) = t.read_under(&profile, &t.at("fresh.txt"));
    assert!(ok, "the unjudged target is refused, so something judges a fresh name now: {out}");
    assert_eq!(out.trim(), "FRESH");
    // Retargeted after the scan: still refused at the name, and the path the scan judged stays denied whatever it names.
    std::fs::remove_file(t.at(".env")).unwrap();
    symlink(Path::new("fresh.txt"), t.at(".env")).unwrap();
    let (ok, out) = t.read_under(&profile, &t.at(".env"));
    assert!(!ok, "a retargeted link was followed, so the profile judges the target now: {out}");
    let (ok, _) = t.read_under(&profile, &t.at("config.txt"));
    assert!(!ok, "a judged path stopped being denied when the link moved off it");
    // What the NEXT call sees: its scan resolves both links, and holds each target it lands on.
    let next = root_top_secrets(std::slice::from_ref(&t.root), &[]);
    for n in [".env", ".env.late", "fresh.txt"] {
        assert!(next.contains(&t.at(n)), "{n} is not held by the next call's scan: {next:?}");
    }
}

/// Only a REGULAR file target is held: a directory is not a secret, and /dev/null (like /proc) is the call's OWN device
/// tree in the sandbox, so masking the host's path would buy nothing and could fail the spawn. On macOS the link is still
/// refused at its own name (`.env.conf` is a dotenv name), so nothing inside the directory is reachable THROUGH it, and
/// what it holds is judged by its own name: `conf/.env` is refused at any depth, `conf/plain.txt` is nobody's secret. On
/// Linux neither a link nor a directory is masked, so an ordinary file inside is reachable by name once the link is
/// followed — the deep-file gap's shape, and the reason the plan lists nothing for either.
#[test]
fn a_held_name_link_to_a_directory_or_a_device_holds_nothing() {
    let t = KTree::new();
    let held = t.held();
    for n in [".env.conf", "conf"] {
        assert!(!held.contains(&t.at(n)), "a link to a directory holds {n}: {held:?}");
    }
    assert!(!held.contains(&t.at(".env.null")), "a link to /dev/null is the call's own file: {held:?}");
    let masked = t.masked_by(&plan(vec![t.root.clone()]));
    for n in [".env.conf", "conf", "conf/.env", ".env.null"] {
        assert!(!masked.contains(&t.at(n).display().to_string()), "{n} is masked: {masked:?}");
    }
    #[cfg(target_os = "macos")]
    {
        let profile = seatbelt_profile(&plan(vec![t.root.clone()]));
        // The link is refused at its own name, so nothing is read THROUGH it, whatever it targets.
        for n in [".env.conf/plain.txt", ".env.conf/.env", ".env.null"] {
            let (ok, out) = t.read_under(&profile, &t.at(n));
            assert!(!ok, "a held-name link to a non-file was readable through {n}: {out}");
        }
        // Reached directly, what the directory holds is judged by ITS OWN name, which is the rule that covers it.
        let (ok, out) = t.read_under(&profile, &t.at("conf/.env"));
        assert!(!ok, "a dotenv file at depth is readable: {out}");
        assert!(!out.contains("INNERDOTENV"), "the value reached the call: {out}");
        let (ok, out) = t.read_under(&profile, &t.at("conf/plain.txt"));
        assert!(ok, "an ordinary file at depth is readable, and nothing claims it: {out}");
        assert_eq!(out.trim(), "INNERPLAIN");
    }
}

/// The property the whole section rests on, enumerated rather than sampled: every path the facts list is one the sandbox
/// does not let the call read — masked on Linux, refused by the real profile on macOS. A repair that listed a name it
/// did not deny (or denied one it did not list) would red here, whichever direction the mistake ran.
#[test]
fn every_path_the_facts_list_is_one_the_sandbox_holds_on_both_platforms() {
    let t = KTree::new();
    let listed = t.held();
    for n in [".env", "config.txt", "copy.txt", ".env.chain", "end.txt"] {
        assert!(
            listed.contains(&t.at(n)),
            "{n} is missing from the list, so the loop below is not over the shapes: {listed:?}"
        );
    }
    let masked = t.masked_by(&plan(vec![t.root.clone()]));
    for p in &listed {
        // A held LINK is not masked itself: what a read through it lands on is, and that is the whole of the Linux rule.
        let md = std::fs::symlink_metadata(p).expect("a listed path exists");
        let need = if md.file_type().is_symlink() { std::fs::canonicalize(p).unwrap() } else { p.clone() };
        assert!(
            masked.iter().any(|m| Path::new(m) == &need),
            "listed but nothing holds what a read of it lands on: {} (target {})",
            p.display(),
            need.display()
        );
    }
    #[cfg(target_os = "macos")]
    {
        let profile = seatbelt_profile(&plan(vec![t.root.clone()]));
        for p in &listed {
            let (ok, out) = t.read_under(&profile, p);
            assert!(!ok, "listed as held but readable: {} ({out})", p.display());
        }
    }
}
