//! manifest_vectors.rs — the program manifest reader held to window-ml's shared vectors (vectors/program-manifests/).

use std::fs;
use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use window_ml_host::manifest::{
    Direction, Flavour, Manifest, Network, ProgramEffect, describe_call, describe_call_as, harden_argv, in_range,
};

// --- program manifest vectors ---

const PROGRAMS: [&str; 15] =
    ["cat", "cp", "find", "gh", "git", "head", "jq", "ls", "mv", "rg", "rm", "rmdir", "tail", "unlink", "wc"];

fn dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/program-manifests")
}

fn load(kind: &str, program: &str) -> Value {
    let p = dir().join(kind).join(format!("{program}.json"));
    serde_json::from_str(&fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap()
}

#[test]
fn every_vector_call_describes_as_recorded() {
    let mut total = 0;
    for program in PROGRAMS {
        let manifest: Manifest =
            serde_json::from_value(load("manifests", program)).unwrap_or_else(|e| panic!("{program}: {e}"));
        let fx = load("calls", program);
        assert_eq!(fx["program"], program);
        let version = fx["version"].as_str().unwrap();
        for c in fx["calls"].as_array().unwrap() {
            total += 1;
            let argv: Vec<String> =
                c["argv"].as_array().unwrap().iter().map(|a| a.as_str().unwrap().to_string()).collect();
            let who = format!("{program}: {argv:?} ({})", c["note"].as_str().unwrap());
            let d = describe_call(&argv, &manifest, Some(version), &[]);
            assert_eq!(json!(d.described), c["described"], "described: {who}");
            assert_eq!(d.effects.to_json(), c["effects"], "effects: {who}");
            assert_eq!(serde_json::to_value(&d.path_args).unwrap(), c["pathArgs"], "pathArgs: {who}");
            assert_eq!(json!(d.acts_on_dir), c["actsOnDir"], "actsOnDir: {who}");
            assert_eq!(json!(d.runner), c["runner"], "runner: {who}");
            assert_eq!(json!(d.ok_codes), c["okCodes"], "okCodes: {who}");
            assert_eq!(json!(d.echoes), c["echoes"], "echoes: {who}");
            assert_eq!(json!(d.recursive), c["recursive"], "recursive: {who}");
            assert_eq!(json!(harden_argv(&argv, &d)), c["hardened"], "hardened: {who}");
        }
    }
    assert_eq!(total, 471);
}

#[test]
fn all_fifteen_programs_have_a_manifest_and_a_calls_file() {
    let mut names: Vec<String> = fs::read_dir(dir().join("manifests"))
        .unwrap()
        .map(|e| e.unwrap().path().file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, PROGRAMS);
    let mut calls: Vec<String> = fs::read_dir(dir().join("calls"))
        .unwrap()
        .map(|e| e.unwrap().path().file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    calls.sort();
    assert_eq!(calls, PROGRAMS);
}

/// The copy's hash, held by window-ml's `tests/program-manifest.test.mjs` too: a change to a manifest or call fixture
/// on either side fails both suites until the copy and both pins move together.
const VECTOR_PIN: &str = "a09ef075ba3ef647db8dff2924b71de18ca0d59f1c8028b7fd1f3c1c5627ec3d";

/// The agreed input (lanes 10 and 11, 2026-10-21): every `calls/*.json` and `manifests/*.json` by that name, sorted
/// bytewise, one `<sha256 of the raw bytes>  <name>\n` line each (shasum's format), and the sha256 of those lines.
fn vector_hash() -> String {
    let mut names: Vec<String> = ["calls", "manifests"]
        .iter()
        .flat_map(|kind| {
            fs::read_dir(dir().join(kind))
                .unwrap()
                .map(move |e| format!("{kind}/{}", e.unwrap().file_name().to_string_lossy()))
        })
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    let lines: String = names
        .iter()
        .map(|n| format!("{}  {n}\n", hex::encode(Sha256::digest(fs::read(dir().join(n)).unwrap()))))
        .collect();
    hex::encode(Sha256::digest(lines.as_bytes()))
}

#[test]
fn the_vector_copy_matches_the_pin_window_ml_holds() {
    assert_eq!(
        vector_hash(),
        VECTOR_PIN,
        "vectors/program-manifests/ changed: copy the same files from window-ml, then update VECTOR_PIN here, the PIN \
         file, and window-ml's pin to the new hash in step"
    );
}

#[test]
fn an_unknown_key_in_a_manifest_fails_to_parse() {
    let base = load("manifests", "cat");
    let mut top = base.clone();
    top["runer"] = json!(true);
    assert!(serde_json::from_value::<Manifest>(top).is_err(), "top level");
    let mut cmd = base.clone();
    cmd["command"]["clustres"] = json!(true);
    assert!(serde_json::from_value::<Manifest>(cmd).is_err(), "command");
    let mut flag = base.clone();
    let first = flag["command"]["flags"].as_object().unwrap().keys().next().unwrap().clone();
    flag["command"]["flags"][&first]["runer"] = json!(true);
    assert!(serde_json::from_value::<Manifest>(flag).is_err(), "flag");
    assert!(serde_json::from_value::<Manifest>(base).is_ok());

    // Every level under `flavours`, at the top and in a command: an unknown key there is a dropped hardening or flag.
    let base = flavoured_json();
    let levels: [(&str, &[&str]); 7] = [
        ("flavours", &["flavours"]),
        ("flavours.gnu", &["flavours", "gnu"]),
        ("flavours.gnu.probe", &["flavours", "gnu", "probe"]),
        ("flavours.bsd", &["flavours", "bsd"]),
        ("command.flavour", &["command", "flavour"]),
        ("command.flavour.gnu", &["command", "flavour", "gnu"]),
        ("command.flavour.bsd", &["command", "flavour", "bsd"]),
    ];
    for (name, path) in levels {
        let mut m = base.clone();
        let mut at = &mut m;
        for key in path {
            at = &mut at[*key];
        }
        at["runer"] = json!(true);
        assert!(serde_json::from_value::<Manifest>(m).is_err(), "{name}");
    }
    assert!(serde_json::from_value::<Manifest>(base).is_ok());
}

#[test]
fn in_range_matches_the_reference_cases() {
    assert!(in_range("2.55.0", ">=2.30.0 <3"));
    assert!(in_range("2.30", ">=2.30.0 <3"));
    assert!(!in_range("3.0.0", ">=2.30.0 <3"));
    assert!(!in_range("2.29.9", ">=2.30.0"));
    assert!(in_range("14.1.1", ">=13"));
    assert!(in_range("1.7.1", "=1.7.1"));
    assert!(!in_range("garbage", ">=1"));
    assert!(!in_range("1.0", ""));
}

// --- the effect vocabulary, enumerated ---

/// Every recorded call's effects across the fifteen programs: `None` for the top element (`"unknown"`).
fn recorded_effects() -> Vec<Option<Vec<String>>> {
    let mut out = Vec::new();
    for program in PROGRAMS {
        for c in load("calls", program)["calls"].as_array().unwrap() {
            out.push(c["effects"].as_array().map(|ks| ks.iter().map(|k| k.as_str().unwrap().to_string()).collect()));
        }
    }
    out
}

/// Whether a recorded call's effects show `term` was read: `None` is the top element. Exhaustive, so a new
/// `ProgramEffect` variant does not build until it has a key here, as it does not build until it has a slot in
/// `ProgramEffect::ALL` (`ProgramEffect::slot`).
fn shows(term: &ProgramEffect, effects: &Option<Vec<String>>) -> bool {
    let Some(keys) = effects else { return *term == ProgramEffect::Unknown };
    let has = |prefix: &str| keys.iter().any(|k| k.starts_with(prefix));
    match term {
        ProgramEffect::Read => has("read:fs:"),
        ProgramEffect::Write => has("write:fs:"),
        ProgramEffect::WriteNames => has("write-names:fs:"),
        ProgramEffect::RunsCode => has("exec:process"),
        ProgramEffect::Unknown => false,
        ProgramEffect::Network(n) => match n.direction.unwrap_or(Direction::Both) {
            Direction::Both => has("read:net:") && has("write:net:"),
            Direction::Read => has("read:net:") && !has("write:net:"),
            Direction::Write => has("write:net:") && !has("read:net:"),
        },
    }
}

#[test]
fn every_term_sits_in_its_own_slot_of_the_inventory() {
    for (i, term) in ProgramEffect::ALL.iter().enumerate() {
        assert_eq!(term.slot(), i, "{term:?}");
    }
}

#[test]
fn every_effect_term_the_host_reads_is_exercised_by_a_vector() {
    let recorded = recorded_effects();
    // No vector manifest says `{"network": {"direction": "write"}}`: none of the fifteen programs only sends. It is held
    // by `a_change_only_network_term_describes_as_a_write` below until window-ml's vectors gain one.
    let without_vector = [ProgramEffect::Network(Network { direction: Some(Direction::Write) })];
    for term in ProgramEffect::ALL {
        let seen = recorded.iter().any(|e| shows(&term, e));
        if without_vector.contains(&term) {
            assert!(!seen, "{term:?} now has a vector: drop it from without_vector");
        } else {
            assert!(seen, "no vector call exercises {term:?}");
        }
    }
}

#[test]
fn a_change_only_network_term_describes_as_a_write() {
    let mut m = load("manifests", "cat");
    m["command"]["effects"] = json!([{ "network": { "direction": "write" } }]);
    let manifest: Manifest = serde_json::from_value(m).unwrap();
    let d = describe_call(&["cat".to_string()], &manifest, None, &[]);
    assert_eq!(d.effects.to_json(), json!(["write:net:*"]));
}

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

// No shipped flag or primary both takes a path and claims write-names (find's -delete takes no value), so these two
// hold the rule on a synthetic manifest: a term that names the path it acts on applies to that path (ruled 2026-10-21).
#[test]
fn a_path_valued_flags_write_names_applies_to_its_value_not_the_operands() {
    let mut m = load("manifests", "cat");
    m["command"]["flags"]["-o"] = json!({ "value": true, "valueIsPath": "write", "effects": ["write-names"] });
    let manifest: Manifest = serde_json::from_value(m).unwrap();
    let d = describe_call(&argv(&["cat", "-o", "out", "in"]), &manifest, None, &[]);
    assert_eq!(d.effects.to_json(), json!(["read:fs:in:?:?", "write-names:fs:out:?:?", "write:fs:out:?:?"]));
}

#[test]
fn a_path_taking_find_primarys_write_names_applies_to_its_argument_not_the_start_points() {
    let mut m = load("manifests", "find");
    m["command"]["primaries"]["-newer"] = json!({ "args": 1, "argIsPath": "write", "effects": ["write-names"] });
    let manifest: Manifest = serde_json::from_value(m).unwrap();
    let d = describe_call(&argv(&["find", "dir", "-newer", "ref"]), &manifest, None, &[]);
    assert_eq!(d.effects.to_json(), json!(["read:fs:dir:?:?", "write-names:fs:ref:?:?", "write:fs:ref:?:?"]));
}

#[test]
fn an_unknown_effect_word_fails_to_parse() {
    let base = load("manifests", "cat");
    for word in [
        json!("reed"),
        json!("write_names"),
        json!({ "network": { "direction": "sideways" } }),
        json!({ "netwerk": {} }),
    ] {
        let mut cmd = base.clone();
        cmd["command"]["effects"] = json!([word.clone()]);
        assert!(serde_json::from_value::<Manifest>(cmd).is_err(), "command: {word}");
        let mut flag = base.clone();
        let first = flag["command"]["flags"].as_object().unwrap().keys().next().unwrap().clone();
        flag["command"]["flags"][&first]["effects"] = json!([word.clone()]);
        assert!(serde_json::from_value::<Manifest>(flag).is_err(), "flag: {word}");
    }
    // The control: the same two places parse with a known word, so the refusals above are about the word.
    let mut ok = base.clone();
    let first = ok["command"]["flags"].as_object().unwrap().keys().next().unwrap().clone();
    ok["command"]["effects"] = json!(["write-names"]);
    ok["command"]["flags"][&first]["effects"] = json!([{ "network": { "direction": "write" } }]);
    assert!(serde_json::from_value::<Manifest>(ok).is_ok());
}

// --- flavours: what each implementation adds (window-ml PROGRAM_MANIFEST.md "Flavours", ruled 2026-11-17) ---

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// window-ml's flavoured fixture (tests/program-manifest.test.mjs `FLAVOURED`): GNU permutes and hardens with
/// --sandbox; BSD stops at the first operand and has its own -l.
fn flavoured_json() -> serde_json::Value {
    json!({
        "program": "tool", "version": { "range": "*", "args": [], "pattern": "" },
        "flavours": { "gnu": { "probe": { "args": ["--version"], "pattern": "^tool \\(GNU tool\\) (\\d+\\.\\d+)", "range": ">=4.3 <5" } }, "bsd": { "system": "macos" } },
        "command": {
            "effects": ["read"], "paths": "operands", "terminator": "--", "clusters": true, "flags": { "-n": {} },
            "flavour": { "gnu": { "flags": { "--quiet": {}, "--sandbox": {} }, "argOrder": "permute", "harden": ["--sandbox"] }, "bsd": { "flags": { "-l": {} }, "argOrder": "stop" } }
        }
    })
}

fn flavoured() -> Manifest {
    serde_json::from_value(flavoured_json()).unwrap()
}

#[test]
fn a_manifest_without_flavours_describes_every_vector_identically_whatever_the_flavour() {
    for program in PROGRAMS {
        let manifest: Manifest = serde_json::from_value(load("manifests", program)).unwrap();
        let fx = load("calls", program);
        let version = fx["version"].as_str().unwrap();
        for c in fx["calls"].as_array().unwrap() {
            let argv: Vec<String> =
                c["argv"].as_array().unwrap().iter().map(|a| a.as_str().unwrap().to_string()).collect();
            let today = describe_call(&argv, &manifest, Some(version), &[]);
            for f in [Some(Flavour::Gnu), Some(Flavour::Bsd), Some(Flavour::Other), None] {
                assert_eq!(
                    describe_call_as(&argv, &manifest, Some(version), &[], f),
                    today,
                    "{program} {argv:?} as {f:?}"
                );
            }
        }
    }
}

/// One flavour row: argv, the flavour, whether it is described, and the path operands when it is.
type Row = (&'static [&'static str], Option<Flavour>, bool, Option<Vec<usize>>);

#[test]
fn a_detected_flavour_reads_the_core_and_its_overlay_undetected_the_core_with_options_first_other_nothing() {
    let m = flavoured();
    let gnu = Some(Flavour::Gnu);
    let bsd = Some(Flavour::Bsd);
    let rows: Vec<Row> = vec![
        (&["tool", "-n", "f"], gnu, true, Some(vec![2])),
        (&["tool", "f", "--quiet"], gnu, true, Some(vec![1])),
        (&["tool", "f", "-n"], gnu, true, Some(vec![1])),
        (&["tool", "-l", "f"], gnu, false, None),
        (&["tool", "-n", "f"], bsd, true, Some(vec![2])),
        (&["tool", "-l", "f"], bsd, true, Some(vec![2])),
        (&["tool", "--quiet", "f"], bsd, false, None),
        (&["tool", "f", "-n"], bsd, true, Some(vec![1, 2])),
        (&["tool", "f", "--", "-x"], bsd, true, Some(vec![1, 2, 3])),
        (&["tool", "-n", "f"], None, true, Some(vec![2])),
        (&["tool", "f", "-n"], None, false, None),
        (&["tool", "--quiet", "f"], None, false, None),
        (&["tool", "-l", "f"], None, false, None),
        (&["tool", "-n", "f"], Some(Flavour::Other), false, None),
        (&["tool", "f"], Some(Flavour::Other), false, None),
    ];
    for (argv, f, described, path_args) in rows {
        let d = describe_call_as(&args(argv), &m, None, &[], f);
        assert_eq!(d.described, described, "{argv:?} as {f:?}: {:?}", d.why);
        if let Some(p) = path_args {
            assert_eq!(d.path_args.iter().map(|p| p.arg).collect::<Vec<_>>(), p, "{argv:?} as {f:?}");
        }
    }
}

#[test]
fn a_flavours_hardening_follows_the_cores_for_that_flavour_only() {
    let m = flavoured();
    let hardened = |f| harden_argv(&args(&["tool", "f"]), &describe_call_as(&args(&["tool", "f"]), &m, None, &[], f));
    assert_eq!(hardened(Some(Flavour::Gnu)), args(&["tool", "--sandbox", "f"]));
    for f in [Some(Flavour::Bsd), Some(Flavour::Other), None] {
        assert_eq!(hardened(f), args(&["tool", "f"]), "{f:?}");
    }
}

#[test]
fn under_stop_an_argument_after_an_operand_that_spells_a_flag_doing_more_than_a_read_is_unknown_in_every_spelling() {
    // window-ml's row of the same name: the two describers agree on `tool f.txt --write-all` (red-team, window-ml#1963).
    let m: Manifest = serde_json::from_value(json!({
        "program": "tool", "version": { "range": "*", "args": [], "pattern": "" }, "flavours": { "bsd": { "system": "macos" } },
        "command": { "effects": ["read"], "paths": "operands", "clusters": true, "terminator": "--", "flags": {
            "-n": {}, "--write-all": { "effects": ["write"] }, "-w": { "effects": ["write"] },
            "--out": { "value": true, "valueIsPath": "write" }, "-R": { "recursive": true },
            "--exec": { "runner": true, "effects": ["runs-code"] }, "--grep": { "value": true, "effects": ["read"] } },
            "flavour": { "bsd": { "argOrder": "stop", "flags": { "--rm": { "effects": ["write-names"] } } } } }
    }))
    .unwrap();
    let bsd = Some(Flavour::Bsd);
    let tails: [&[&str]; 12] = [
        &["--write-all"],
        &["--write-all=x"],
        &["-w"],
        &["-nw"],
        &["--out", "o"],
        &["--out=o"],
        &["-R"],
        &["--exec"],
        &["--rm"],
        &["--", "--write-all"],
        &["g", "-w"],
        &["-xw"],
    ];
    for tail in tails {
        let a: Vec<&str> = ["tool", "f.txt"].iter().chain(tail).copied().collect();
        let d = describe_call_as(&args(&a), &m, None, &[], bsd);
        assert!(!d.described, "{a:?} was described under stop: {:?}", d.path_args);
        assert!(d.why.iter().any(|w| w.contains("does more than read")), "{a:?}: {:?}", d.why);
    }
    for tail in [["-n"], ["--grep"], ["--nope"], ["-x"]] {
        let a: Vec<&str> = ["tool", "f.txt"].iter().chain(&tail).copied().collect();
        let d = describe_call_as(&args(&a), &m, None, &[], bsd);
        assert!(d.described, "{a:?}: {:?}", d.why);
        assert_eq!(d.path_args.iter().map(|p| p.arg).collect::<Vec<_>>(), vec![1, 2], "{a:?}");
    }
    assert!(describe_call_as(&args(&["tool", "-w", "f.txt"]), &m, None, &[], bsd).described);
    // A `--` the command honours, before any operand, ends the options for every implementation: what follows stays an operand.
    let t = describe_call_as(&args(&["tool", "--", "f.txt", "--write-all"]), &m, None, &[], bsd);
    assert!(t.described, "{:?}", t.why);
    assert_eq!(t.path_args.iter().map(|p| p.arg).collect::<Vec<_>>(), vec![2, 3]);
}
