// replies.rs — the describer's FULL reply, the native build and the built wasm over one committed corpus.
// (compiled for tests only: `cargo test -p describe-wasm --lib`)
//
// What the worker judges by is `describe` in the wasm module; what still runs is the native build of the same crate. A
// call the two describe differently is a call judged one way and run another, so both are held to the same bytes here:
//
// - every recorded vector row (calls, flavoured, resolved, shapes), as the request `tools/describe-replay.mjs` builds,
//   with the WHOLE reply pinned — the replay compares nine fields, a `pre`, and described/why; this pins the rest;
// - shapes a hostile page can steer a model into: argv[0] spellings, operands after the terminator, shell syntax in a
//   path, sed/find/git escapes, an unknown manifest key, a duplicate JSON key, a NUL in a name;
// - malformed and oversized requests, each of which must end in `{"error": ...}` — never a panic here, never a trap in
//   the wasm (the driver asserts the same pinned reply there).
//
// The pin is `tests/replies.json`. A deliberate change to the describer regenerates it with
// `WML_DESCRIBE_BLESS=1 cargo test -p describe-wasm --lib`; `tools/describe-replies.mjs <describe.wasm>` replays the
// same file through the module the extension loads and also asserts the module imports nothing.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/replies.json");
const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/program-manifests");
const BLESS: &str = "WML_DESCRIBE_BLESS";

/// The kinds of recorded row and how many each contributes; `tools/describe-replay.mjs` asserts the same four counts, so
/// a vector change fails here and there together.
const COUNTS: [(&str, usize); 4] = [("calls", 507), ("flavoured", 25), ("resolved", 324), ("shapes", 8)];

/// One request: its name and the exact bytes both sides feed to the describer.
type Entry = (String, Vec<u8>);

fn read(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A request as JSON text (text, so a duplicate key survives to the parser).
fn ask(
    argv: &Value,
    manifest: &Value,
    version: Option<&Value>,
    flavour: Option<&str>,
    env_set: Option<&Value>,
) -> Vec<u8> {
    let mut req = serde_json::Map::new();
    req.insert("argv".into(), argv.clone());
    req.insert("manifest".into(), manifest.clone());
    if let Some(v) = version {
        req.insert("version".into(), v.clone());
    }
    if let Some(f) = flavour {
        req.insert("flavour".into(), json!(f));
    }
    if let Some(e) = env_set {
        req.insert("envSet".into(), e.clone());
    }
    Value::Object(req).to_string().into_bytes()
}

/// The programs, sorted: a manifest added to the vectors is described here without editing this file.
fn programs() -> Vec<String> {
    let dir = Path::new(VECTORS).join("manifests");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("dirent").file_name().to_string_lossy().into_owned())
        .filter_map(|f| f.strip_suffix(".json").map(String::from))
        .collect();
    names.sort();
    names
}

fn manifest(program: &str) -> Value {
    read(&Path::new(VECTORS).join("manifests").join(format!("{program}.json")))
}

/// Every recorded row, as the replay builds its request: the program's manifest, the file's version, and the row's own
/// flavour or manifest where the file carries one.
fn recorded(out: &mut Vec<Entry>, counts: &mut BTreeMap<String, usize>) {
    let rows = |kind: &str, program: &str| read(&Path::new(VECTORS).join(kind).join(format!("{program}.json")));
    for program in programs() {
        let m = manifest(&program);
        for kind in ["calls", "resolved"] {
            let file = rows(kind, &program);
            let version = file.get("version");
            for (i, row) in file["calls"].as_array().expect("calls").iter().enumerate() {
                *counts.entry(kind.to_string()).or_default() += 1;
                out.push((format!("{kind}/{program}/{i}"), ask(&row["argv"], &m, version, None, None)));
            }
        }
    }
    for program in ["awk", "sed"] {
        let m = manifest(program);
        let file = read(&Path::new(VECTORS).join("flavoured").join(format!("{program}.json")));
        for (i, row) in file["calls"].as_array().expect("calls").iter().enumerate() {
            *counts.entry("flavoured".into()).or_default() += 1;
            let flavour = row["flavour"].as_str().expect("flavour");
            out.push((
                format!("flavoured/{program}/{i}"),
                ask(&row["argv"], &m, file.get("version"), Some(flavour), None),
            ));
        }
    }
    let shapes = read(&Path::new(VECTORS).join("resolved").join("shapes.json"));
    for (i, row) in shapes["calls"].as_array().expect("calls").iter().enumerate() {
        *counts.entry("shapes".into()).or_default() += 1;
        out.push((format!("shapes/{i}"), ask(&row["argv"], &row["manifest"], row.get("version"), None, None)));
    }
}

/// Shapes a hostile page can steer the model into. Each carries a real manifest, since a call with none is an error
/// (every entry would then test the same error rather than the description).
fn hostile(out: &mut Vec<Entry>) {
    {
        let mut add = |name: &str, program: &str, argv: Value| {
            out.push((name.to_string(), ask(&argv, &manifest(program), None, None, None)))
        };
        for (name, argv0) in [
            ("hostile/argv0-absolute", "/usr/bin/rm"),
            ("hostile/argv0-dotted", "./rm"),
            ("hostile/argv0-trailing-slash", "rm/"),
            ("hostile/argv0-case", "RM"),
            ("hostile/argv0-unicode", "ｒｍ"),
            ("hostile/argv0-empty", ""),
            ("hostile/argv0-flag", "-rm"),
            ("hostile/argv0-newline", "rm\n"),
        ] {
            add(name, "rm", json!([argv0, "a"]));
        }
        add("hostile/argv-empty", "rm", json!([]));
        add("hostile/terminator-then-flag", "rm", json!(["rm", "--", "-rf", "/"]));
        add("hostile/flag-then-terminator", "rm", json!(["rm", "-rf", "--", "x"]));
        add("hostile/terminator-twice", "rm", json!(["rm", "--", "--", "x"]));
        add("hostile/terminator-dash", "rm", json!(["rm", "--", "-"]));
        add("hostile/path-dotdot", "rm", json!(["rm", "../../etc/passwd"]));
        add("hostile/path-home", "cat", json!(["cat", "~/.ssh/id_ed25519"]));
        add("hostile/path-secret-name", "rm", json!(["rm", ".env"]));
        add("hostile/path-substitution", "rm", json!(["rm", "$(rm -rf /)"]));
        add("hostile/path-backticks", "rm", json!(["rm", "`whoami`"]));
        add("hostile/path-semicolon", "cat", json!(["cat", "a;b"]));
        add("hostile/path-pipe", "cat", json!(["cat", "a|b"]));
        add("hostile/path-newline", "rm", json!(["rm", "a\nb"]));
        add("hostile/path-nul", "rm", json!(["rm", "a\u{0}b"]));
        add("hostile/path-glob", "rm", json!(["rm", "*.txt"]));
        add("hostile/path-long", "rm", json!(["rm", "a".repeat(4096)]));
        add("hostile/dup-operand", "rm", json!(["rm", "a", "a"]));
        add("hostile/sed-write-script", "sed", json!(["sed", "-e", "s/a/b/w /tmp/x", "a"]));
        add("hostile/sed-inplace-suffix", "sed", json!(["sed", "-i.bak", "s/a/b/", "a"]));
        add("hostile/sed-equals", "sed", json!(["sed", "--expression=s/a/b/", "a"]));
        add("hostile/sed-semicolon-flag", "sed", json!(["sed", "-n;p", "a"]));
        add("hostile/find-exec", "find", json!(["find", ".", "-exec", "rm", "{}", ";"]));
        add("hostile/find-delete", "find", json!(["find", ".", "-delete"]));
        add("hostile/find-fprint", "find", json!(["find", ".", "-fprint", "/tmp/x"]));
        add("hostile/find-bang-exec", "find", json!(["find", ".", "!", "-name", "a", "-execdir", "sh", "{}", "+"]));
        add("hostile/git-config-injection", "git", json!(["git", "-c", "core.pager=sh", "log"]));
        add("hostile/git-output", "git", json!(["git", "log", "--output=/tmp/x"]));
        add("hostile/git-dir", "git", json!(["git", "--git-dir=/tmp/x", "status"]));
        add("hostile/git-alias", "git", json!(["git", "alias.x=!sh", "x"]));
        add("hostile/ls-dash-file", "ls", json!(["ls", "--", "-l"]));
        add("hostile/gh-token", "gh", json!(["gh", "auth", "token"]));
    }
    // A declared name, an undeclared one, an assignment dressed as a name, and a non-string entry.
    for (name, set) in [
        ("hostile/env-declared", json!(["GIT_PAGER=sh"])),
        ("hostile/env-undeclared", json!(["PATH=/evil"])),
        ("hostile/env-empty-name", json!([""])),
        ("hostile/env-not-string", json!([7])),
    ] {
        out.push((name.to_string(), ask(&json!(["git", "log"]), &manifest("git"), None, None, Some(&set))));
    }
    // Version and flavour, outside what the vectors record.
    for (name, version) in
        [("hostile/version-empty", ""), ("hostile/version-garbage", "garbage"), ("hostile/version-newline", "1.2.3\n")]
    {
        out.push((name.to_string(), ask(&json!(["git", "log"]), &manifest("git"), Some(&json!(version)), None, None)));
    }
    for (name, flavour) in [("hostile/flavour-other", "other"), ("hostile/flavour-gnu-on-unflavoured", "gnu")] {
        out.push((
            name.to_string(),
            ask(&json!(["sed", "-i", "s/a/b/", "a"]), &manifest("sed"), None, Some(flavour), None),
        ));
    }
    // Manifests that do not parse: each must be the same error on both sides, never a description with no effects.
    let rm = manifest("rm");
    let mut mangle =
        |name: &str, m: Value| out.push((name.to_string(), ask(&json!(["rm", "a"]), &m, None, None, None)));
    let with = |f: &dyn Fn(&mut Value)| {
        let mut m = rm.clone();
        f(&mut m);
        m
    };
    mangle("hostile/manifest-unknown-key", with(&|m| m["nonsense"] = json!(1)));
    mangle("hostile/manifest-unknown-effect", with(&|m| m["command"]["effects"] = json!(["read", "write-everything"])));
    mangle("hostile/manifest-okcode-256", with(&|m| m["okCodes"] = json!([256])));
    mangle("hostile/manifest-empty-program", with(&|m| m["program"] = json!("")));
    mangle("hostile/manifest-null-command", with(&|m| m["command"] = Value::Null));
    mangle("hostile/manifest-flags-array", with(&|m| m["command"]["flags"] = json!(["-f"])));
    mangle(
        "hostile/manifest-no-version",
        with(&|m| {
            m.as_object_mut().expect("object").remove("version");
        }),
    );
}

/// Malformed requests, as exact text.
fn malformed(out: &mut Vec<Entry>) {
    let rm = manifest("rm").to_string();
    let mut add = |name: &str, text: String| out.push((name.to_string(), text.into_bytes()));
    add("malformed/empty", String::new());
    add("malformed/not-json", "hello".into());
    add("malformed/array-top", "[]".into());
    add("malformed/no-argv", "{}".into());
    add("malformed/null-argv", "{\"argv\":null}".into());
    add("malformed/argv-string", "{\"argv\":\"ls\"}".into());
    add("malformed/argv-numbers", "{\"argv\":[1,null,{}]}".into());
    add("malformed/argv-nested", "{\"argv\":[[\"ls\"]]}".into());
    add("malformed/manifest-string", "{\"argv\":[\"ls\"],\"manifest\":\"x\"}".into());
    add("malformed/no-manifest", "{\"argv\":[\"ls\"]}".into());
    add("malformed/version-number", format!("{{\"argv\":[\"rm\"],\"manifest\":{rm},\"version\":1}}"));
    add("malformed/flavour-number", format!("{{\"argv\":[\"rm\"],\"manifest\":{rm},\"flavour\":1}}"));
    add("malformed/flavour-unknown", format!("{{\"argv\":[\"rm\"],\"manifest\":{rm},\"flavour\":\"plan9\"}}"));
    add("malformed/envset-not-array", format!("{{\"argv\":[\"rm\"],\"manifest\":{rm},\"envSet\":7}}"));
    add("malformed/string-top", "\"ls\"".into());
    add("malformed/true-top", "true".into());
    add("malformed/null-top", "null".into());
    add("malformed/trailing-garbage", "{\"argv\":[\"rm\"]} x".into());
    add("malformed/bom", "\u{feff}{\"argv\":[\"rm\"]}".into());
    // A duplicate key: serde_json keeps the last on both sides, so the second argv's description is the answer.
    add("malformed/duplicate-argv", format!("{{\"argv\":[\"ls\",\"-l\"],\"argv\":[\"rm\",\"a\"],\"manifest\":{rm}}}"));
    add(
        "malformed/duplicate-flavour",
        format!("{{\"argv\":[\"sed\",\"a\"],\"manifest\":{rm},\"flavour\":\"gnu\",\"flavour\":\"plan9\"}}"),
    );
}

/// The oversized requests, built identically by `tools/describe-replies.mjs`: `(name, bytes)`.
fn big() -> Vec<(&'static str, Vec<u8>)> {
    let rm = manifest("rm").to_string();
    let argv = Value::Array(std::iter::once(json!("x")).chain(std::iter::repeat_n(json!("a"), 100_000)).collect());
    vec![
        (
            "big/nested-100000",
            format!("{{\"argv\":[\"rm\"],\"manifest\":{rm},\"x\":{}{}}}", "[".repeat(100_000), "]".repeat(100_000))
                .into_bytes(),
        ),
        ("big/argv-100000", format!("{{\"argv\":{argv},\"manifest\":{rm}}}").into_bytes()),
        (
            "big/string-2000000",
            format!("{{\"argv\":[\"x\",\"{}\"],\"manifest\":{rm}}}", "a".repeat(2_000_000)).into_bytes(),
        ),
        ("big/junk-4000000", format!("{{\"argv\":[\"x\"],\"manifest\":{rm}}}{}", " ".repeat(4_000_000)).into_bytes()),
        ("big/whitespace-4000000", " ".repeat(4_000_000).into_bytes()),
        // The one request that is not UTF-8 at all: the parser must say so, not read it as something else.
        ("big/invalid-utf8", b"{\"argv\":[\"\xff\xfe\"]}".to_vec()),
    ]
}

/// The reply `describe` returns for these bytes: `run`'s value, or its error as the `{"error": ...}` object.
fn reply(bytes: &[u8]) -> Value {
    match super::run(bytes) {
        Ok(v) => v,
        Err(e) => json!({ "error": e }),
    }
}

/// The reply as one canonical string: object keys sorted, so native and the driver's `JSON.stringify` of the same
/// value agree. serde_json's maps are BTreeMaps, so this only has to prove it, not impose it.
fn canonical(v: &Value) -> String {
    serde_json::to_string(v).expect("a value serialises")
}

/// sha256 of [`canonical`]: what a large reply is pinned by, since pinning 100k hardened arguments as JSON is megabytes.
fn digest(v: &Value) -> String {
    let mut h = Sha256::new();
    h.update(canonical(v).as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The corpus, ready to compare.
fn corpus() -> (Vec<Entry>, BTreeMap<String, usize>) {
    let mut entries = Vec::new();
    let mut counts = BTreeMap::new();
    recorded(&mut entries, &mut counts);
    hostile(&mut entries);
    malformed(&mut entries);
    entries.extend(big().into_iter().map(|(name, bytes)| (name.to_string(), bytes)));
    let mut names = BTreeSet::new();
    for (name, _) in &entries {
        assert!(!name.is_empty(), "an entry with no name");
        assert!(names.insert(name.clone()), "{name}: two entries with one name");
    }
    for (kind, want) in COUNTS {
        let got = counts.get(kind).copied().unwrap_or(0);
        assert_eq!(
            got, want,
            "{kind}: {got} recorded rows where the replay and this file assert {want}: regenerate the pin"
        );
    }
    (entries, counts)
}

/// Whether a reply is pinned whole (the hostile and malformed shapes, which a reader should be able to read) or by its
/// digest (the recorded rows, read in `vectors/`, and the oversized inputs, whose replies are megabytes).
fn pinned_whole(name: &str) -> bool {
    name.starts_with("hostile/") || name.starts_with("malformed/")
}

#[test]
fn a_call_describes_identically_natively_and_in_the_pin_the_wasm_is_replayed_against() {
    let (entries, _) = corpus();
    let path = PathBuf::from(FIXTURE);
    if std::env::var_os(BLESS).is_some() {
        let mut whole = Vec::new();
        let mut hashed = Vec::new();
        for (name, bytes) in &entries {
            let got = reply(bytes);
            if pinned_whole(name) {
                match std::str::from_utf8(bytes) {
                    Ok(text) => whole.push(json!({ "name": name, "request": text, "reply": got })),
                    // Bytes no string can carry: the driver reads the request from its hex.
                    Err(_) => {
                        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                        whole.push(json!({ "name": name, "requestHex": hex, "reply": got }));
                    }
                }
            } else {
                hashed.push(json!({ "name": name, "sha256": digest(&got) }));
            }
        }
        std::fs::create_dir_all(path.parent().expect("tests/")).expect("tests/");
        let pin = json!({ "note": NOTE, "whole": whole, "digest": hashed });
        // Pretty, one value per line: a blessed change shows in the diff as the replies it changed.
        let text = serde_json::to_string_pretty(&pin).expect("the pin serialises");
        std::fs::write(&path, format!("{text}\n")).expect("write the pin");
        panic!("the pin was rewritten ({BLESS}): read the diff, then run again without it");
    }
    let pin = read(&path);
    let whole: BTreeMap<&str, &Value> = pin["whole"]
        .as_array()
        .expect("whole")
        .iter()
        .map(|e| (e["name"].as_str().expect("name"), &e["reply"]))
        .collect();
    let hashed: BTreeMap<&str, &str> = pin["digest"]
        .as_array()
        .expect("digest")
        .iter()
        .map(|e| (e["name"].as_str().expect("name"), e["sha256"].as_str().expect("sha256")))
        .collect();
    let mut differences = Vec::new();
    for (name, bytes) in &entries {
        let got = reply(bytes);
        if pinned_whole(name) {
            match whole.get(name.as_str()) {
                Some(want) if **want == got => {}
                Some(want) => differences.push(format!("{name}\n  native: {got}\n  pinned: {want}")),
                None => differences.push(format!("{name}: pinned nothing: regenerate the pin with {BLESS}=1")),
            }
        } else {
            match hashed.get(name.as_str()) {
                Some(want) if *want == digest(&got) => {}
                Some(want) => differences.push(format!("{name}\n  native: {got}\n  pinned sha256: {want}")),
                None => differences.push(format!("{name}: pinned nothing: regenerate the pin with {BLESS}=1")),
            }
        }
    }
    assert!(
        differences.is_empty(),
        "{} difference(s) from the pin; the first 10:\n{}",
        differences.len(),
        differences.iter().take(10).cloned().collect::<Vec<_>>().join("\n")
    );
    let names: BTreeSet<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    for name in whole.keys().chain(hashed.keys()) {
        assert!(names.contains(name), "{name}: pinned, but not in the corpus: a removed row leaves its pin behind");
    }
    assert_eq!(
        whole.len() + hashed.len(),
        entries.len(),
        "the pin and the corpus disagree on how many requests there are"
    );
}

/// What the pin is and how it is regenerated; written into the file so a reader of the diff knows.
const NOTE: &str = "Every request the describer is held to, with the native reply: the recorded vector rows, hostile shapes, and malformed or oversized input. describe-wasm/src/replies.rs asserts the native build answers this; tools/describe-replies.mjs asserts the built wasm answers identically and imports nothing. Regenerate with WML_DESCRIBE_BLESS=1 cargo test -p describe-wasm --lib";
