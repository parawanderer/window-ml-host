//! redteam_sandbox_env.rs — `.env` and `.env.*` under the host's sandbox (window-ml's SECRET_HANDLES incident of
//! 2026-10-21; host#46, as built at 444b039a). The property: a call that does NOT name a dotenv file cannot read it,
//! and the facts say which files it cannot read.
//!
//! The lane's own rows (tests/stdio.rs and the unit tests in src/sandbox.rs) walk `.env`, `.env.local` and a nested one
//! on macOS, and check the regexes' TEXT. These are the shapes those do not, and mostly as a REAL read: `sandbox-exec`
//! with the profile the call really gets. The Linux half asserts the bind list, which is the whole decision there.
//!
//!   A. macOS, a real read: `.env` at any depth, `.env.local`, `.env.production`, `.env.example`, and the same reached
//!      through `..` and through a symlink of another name, are refused; `.envrc`, `.env.d/x`, `x.env` and an ordinary
//!      file are still readable. (The case variant cannot be a real read here: on a case-insensitive volume `.ENV` IS
//!      `.env`, one inode. Its case-insensitivity is pinned on the deny line instead, B.)
//!   B. the deny line is case-insensitive and stops at a `/`: the two properties the whole thing rests on, since a
//!      name check that crossed a directory would hide a root called `.env.d` and one that ignored case would miss
//!      `.ENV` on the Linux and case-sensitive-macOS volumes.
//!   C. a named dotenv file is readable, and naming it does not open its siblings.
//!   D. RED — a HARDLINK to `.env` is readable on both platforms: `ln .env notes.txt` is the same inode under a name
//!      nothing denies, the facts do not list it, and the docs say "unreadable unless named" without the caveat.
//!   D2. what BOUNDS D: the call cannot make that hardlink itself — `link` naming a denied file is refused by the same
//!      rules — so the residue is a name the person's own tooling already made, not one the call can build.
//!   E. Linux, the bind list: each root's top dotenv files, every root, not `.envrc`, not a directory, not a symlink,
//!      and not the one the call named.
//!   F. `hiddenSecrets`: only the top of each root, only regular files, never a symlink or a directory, nothing outside
//!      the roots, sorted, and a named file is not claimed.
//!
//! THE ONE THAT MATTERS MOST: D. Everything else here restates the deny lists from the outside; D is the shape that is
//! not in them at any depth, and it needs a decision (an inode check, or docs that say a hardlink is a name like any
//! other and a person's `ln` is out of scope), not another regex. D2 is the row that says the decision can stay small:
//! no one inside the sandbox can build the name.
//!
//! MUTATION PER ROW, MEASURED AT 444b039a (notes, not committed changes — one applied alone, this file run, the source
//! reverted with `git checkout -- src/`; it was 6/7 before and after, D the red one):
//!   A/B/D/E/F  src/sandbox.rs: `.env` out of `DENY_READ_FILES` and `.env.` out of `DENY_READ_PREFIXES` → A red at
//!      `.env.local was readable`, E and F red on their lists, D red at "the facts claim the hardlink" (a name added to
//!      that list is claimed by the facts AND denied by the profile, which is the whole mechanism: a NAME list).
//!   C  `seatbelt_profile`: the `(allow file-read* …)` re-allow block removed → C red: the named file is denied.
//!   E  `Scratch`-side: `masks.extend(root_top_secrets(&plan.roots, &plan.allow_read))` removed → E red.
//!   E/F  `root_top_secrets`: ` && !allow_read.contains(&e.path())` removed → F red at "a named file is not claimed";
//!      E stays green because bwrap has a SECOND guard (`allow_read.starts_with(&m) { continue }`) — with BOTH removed
//!      E reds at "a named file is not masked", so the row is measured against the pair.
//!   F  `root_top_secrets`: the regular-file check removed → F red at "a directory is not claimed"; `out.sort()`
//!      removed → F red at "the list is sorted".
//!   D2 holds under all of the above: it asserts a refusal, so removing the deny makes it fail at its premise (the key
//!      is readable) rather than at the link.
//!
//! WHAT THIS FILE CANNOT ROW (named so the next reader does not look for it):
//!   - The case variant on a case-insensitive volume: `.ENV` and `.env` are one inode there, so a real read cannot tell
//!     the rule from the filesystem. B pins the pattern's case class instead; a case-SENSITIVE volume is not available
//!     in this session to confirm by read.
//!   - The LINUX side of D2: bwrap masks by bind mount, so `~/.ssh` is `/dev/null` inside the namespace and the source
//!     cannot even be named; whether a `link()` naming a source inside a granted-but-masked tree is refused was not
//!     measured here (no Linux host in this session). That is a reason to expect refusal, not a row.
//!   - `.env.example` being hidden is a POLICY choice (a template holds no secret) pinned as built, not argued: the
//!     prefix list cannot tell a template from a real one without parsing the file.
//!   - Naming a file as `secret` unmasks it for the WHOLE call, whatever the program then does with it: `pathArgs` is
//!     the consent surface, and the sheet shows what was named. Not a gap in the sandbox, a property of the approval.
//!   - A `.env` below a root's top is not masked on Linux (Landlock cannot deny inside a grant). Pinned as built in E
//!     (the mask list) and F (the facts say nothing about it), and documented in docs/SANDBOX.md.
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use window_ml_host::sandbox::{ExecScope, Plan, WriteScope, bwrap_args, root_top_secrets, seatbelt_profile};

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

/// Every dotenv name at the top of a fresh tree, with the near-misses a name rule must leave alone. The root is the
/// REAL path, as `configure` stores it (`resolve_root` canonicalizes) and as `pathArgs[].path` comes back
/// (`resolve_path` canonicalizes an existing file), so the plan fed here is the one a call really builds.
struct Tree {
    _d: tempfile::TempDir,
    root: PathBuf,
}

impl Tree {
    fn new() -> Tree {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap().join("w");
        std::fs::create_dir_all(root.join("app")).unwrap();
        for (rel, body) in [
            (".env", "DOTENV\n"),
            (".env.local", "LOCAL\n"),
            (".env.production", "PROD\n"),
            (".env.example", "EXAMPLE\n"),
            (".envrc", "ENVRC\n"),
            (".env.d/x", "INDIR\n"),
            ("app/.env", "NESTED\n"),
            ("app/.env.production", "NESTEDPROD\n"),
            ("x.env", "NOTDOTENV\n"),
            ("notes.txt", "NOTHING\n"),
        ] {
            std::fs::create_dir_all(root.join(rel).parent().unwrap()).unwrap();
            std::fs::write(root.join(rel), body).unwrap();
        }
        symlink(root.join(".env"), root.join("link-to-env")).unwrap();
        std::fs::hard_link(root.join(".env"), root.join("hardlink-to-env")).unwrap();
        Tree { _d: d, root }
    }
    fn at(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
    /// What `sandbox-exec` with `profile` makes of a read of `path`: whether it succeeded, and its output (either the
    /// bytes or the refusal).
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
    for rel in [".env", ".env.local", ".env.production", "app/.env", "app/.env.production"] {
        let (ok, out) = t.read_under(&profile, &t.at(rel));
        assert!(!ok, "{rel} was readable: {out}");
    }
    // `.env.example` is a template with no secrets in it, and it is hidden too: pinned as built, not as ideal.
    let (ok, out) = t.read_under(&profile, &t.at(".env.example"));
    assert!(!ok, ".env.example is hidden at 444b039a (the prefix list catches it): {out}");
    // Reached another way: `..`, and a symlink named for neither.
    for (label, from) in [("through ..", t.at("app/../.env")), ("through a symlink", t.at("link-to-env"))] {
        let (ok, out) = t.read_under(&profile, &from);
        assert!(!ok, ".env was readable {label}: {out}");
    }
    let (ok, out) = t.read_under(&profile, &t.at(".env"));
    assert!(ok == false && out.contains("Operation not permitted"), "the refusal is the kernel's, and says so: {out}");
    // The near-misses stay readable: `.envrc` is not `.env.`, and a directory's name is not a file's.
    for rel in [".envrc", ".env.d/x", "x.env", "notes.txt"] {
        let (ok, out) = t.read_under(&profile, &t.at(rel));
        assert!(ok, "{rel} was denied: {out}");
    }
}

// --- B: the two properties of the deny line ---

#[test]
fn the_deny_line_is_case_insensitive_and_does_not_cross_a_directory() {
    let p = seatbelt_profile(&plan(vec![PathBuf::from("/w/proj")]));
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
}

// --- C: naming the file is the way through ---

#[cfg(target_os = "macos")]
#[test]
fn a_named_dotenv_file_is_readable_and_does_not_open_its_siblings() {
    let t = Tree::new();
    let mut p = plan(vec![t.root.clone()]);
    p.allow_read.push(t.at(".env"));
    let profile = seatbelt_profile(&p);
    let (ok, out) = t.read_under(&profile, &t.at(".env"));
    assert!(ok, "a named dotenv file was still denied: {out}");
    assert_eq!(out.trim(), "DOTENV");
    for rel in [".env.local", ".env.production", "app/.env"] {
        let (ok, out) = t.read_under(&profile, &t.at(rel));
        assert!(!ok, "naming .env opened {rel}: {out}");
    }
}

// --- D: the hardlink, which no path in either design can see ---

/// RED at 444b039a. A hardlink is the same inode under a name of its own: `ln .env notes.txt` puts the secret at a path
/// no deny rule matches, no mask covers, and no fact names, since all three judge a file by its NAME. macOS then reads
/// it; on Linux it is not in the mask list at all. The docs' "unreadable unless named" wants the caveat, or the facts
/// want to see it (a link count over one is the only cheap tell).
#[test]
fn a_hardlink_to_a_dotenv_file_is_not_hidden_by_any_path_the_sandbox_judges() {
    let t = Tree::new();
    let link = t.at("hardlink-to-env");
    assert_eq!(std::fs::read(&link).unwrap(), b"DOTENV\n", "premise: the hardlink is the .env inode");
    // Nothing tells the model: the facts list dotenv NAMES, and this one has an ordinary one.
    let facts = root_top_secrets(&[t.root.clone()], &[]);
    assert!(!facts.contains(&link), "the facts claim the hardlink: {facts:?}");
    assert_eq!(
        facts,
        vec![t.at(".env"), t.at(".env.example"), t.at(".env.local"), t.at(".env.production")],
        "the facts are the dotenv names, so the hardlink is invisible to them",
    );
    // Nor is it masked on Linux: the mask list is the same names.
    assert!(
        !t.masked_by(&plan(vec![t.root.clone()])).contains(&link.display().to_string()),
        "the mask list names only dotenv names"
    );
    #[cfg(target_os = "macos")]
    {
        let profile = seatbelt_profile(&plan(vec![t.root.clone()]));
        let (ok, out) = t.read_under(&profile, &link);
        assert!(!ok, "the hardlink's bytes are readable under the sandbox: {out}");
    }
}

/// What BOUNDS D: the call cannot make the hardlink itself. `link` naming a denied file is refused by the same rules,
/// so the leak needs a name the person's own tooling already made (`ln`, a backup tool, an editor's swap). Without this,
/// D would be an escape a program inside the sandbox could build for itself; measured here, and it holds.
#[cfg(target_os = "macos")]
#[test]
fn the_sandbox_does_not_let_a_program_make_the_hardlink_itself() {
    let t = Tree::new();
    let home = t._d.path().canonicalize().unwrap().join("home");
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
fn q(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', r"'\''"))
}

// --- E: the Linux bind list ---

#[test]
fn the_linux_masks_are_each_roots_top_dotenv_files_and_nothing_else() {
    let t = Tree::new();
    let other = t._d.path().canonicalize().unwrap().join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join(".env"), "SECOND\n").unwrap();
    std::fs::write(other.join(".envrc"), "no\n").unwrap();
    let mut expected: Vec<String> =
        [t.at(".env"), t.at(".env.example"), t.at(".env.local"), t.at(".env.production"), other.join(".env")]
            .iter()
            .map(|p| p.display().to_string())
            .collect();
    expected.sort();
    assert_eq!(
        t.masked_by(&plan(vec![t.root.clone(), other.clone()])),
        expected,
        "every root's top, dotenv names only"
    );
    // A named file is not masked; the rest still are.
    let mut named = plan(vec![t.root.clone(), other.clone()]);
    named.allow_read.push(t.at(".env"));
    let got = t.masked_by(&named);
    assert!(!got.contains(&t.at(".env").display().to_string()), "a named file is not masked: {got:?}");
    assert!(got.contains(&t.at(".env.local").display().to_string()), "naming .env must not unmask .env.local: {got:?}");
    // A symlink and a directory are not masked. The symlink's TARGET is, so a read through it comes back empty; the
    // directory is not, so a file inside one is readable there (the documented Linux gap, `sub/.env`).
    for m in &got {
        assert_ne!(Path::new(m), t.at("link-to-env"), "a link is not a mask");
        assert_ne!(Path::new(m), t.at(".env.d"), "a directory is not a mask");
    }
}

// --- F: what the facts may claim ---

#[test]
fn the_facts_list_each_roots_top_dotenv_files_only() {
    let t = Tree::new();
    let other = t._d.path().canonicalize().unwrap().join("other");
    std::fs::create_dir_all(other.join("deep")).unwrap();
    std::fs::write(other.join("deep/.env"), "DEEP\n").unwrap();
    std::fs::write(other.join(".env"), "SECOND\n").unwrap();
    let got = root_top_secrets(&[t.root.clone(), other.clone()], &[]);
    assert!(got.contains(&t.at(".env")), "the root's own .env is claimed");
    assert!(got.contains(&other.join(".env")), "a second root's .env is claimed too");
    assert!(!got.contains(&other.join("deep/.env")), "a deeper file is not claimed (Linux would not hide it)");
    assert!(!got.contains(&t.at("app/.env")), "a nested file is not claimed");
    assert!(!got.contains(&t.at("link-to-env")), "a symlink is not claimed, and not masked");
    assert!(!got.contains(&t.at(".env.d")), "a directory is not claimed");
    let mut sorted = got.clone();
    sorted.sort();
    assert_eq!(got, sorted, "the list is sorted");
    assert!(
        !root_top_secrets(&[t.root.clone()], &[t.at(".env")]).contains(&t.at(".env")),
        "a named file is not claimed"
    );
    for p in &got {
        assert!(p.starts_with(&t.root) || p.starts_with(&other), "claimed a path outside the roots: {}", p.display());
    }
}
