//! manifest_vectors.rs — the program manifest reader held to window-ml's shared vectors (vectors/program-manifests/).

use std::fs;
use std::path::Path;

use serde_json::{Value, json};
use window_ml_host::manifest::{Direction, Manifest, Network, ProgramEffect, describe_call, harden_argv, in_range};

// --- program manifest vectors ---

const PROGRAMS: [&str; 9] = ["cat", "find", "git", "head", "jq", "ls", "rg", "tail", "wc"];

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
    assert_eq!(total, 227);
}

#[test]
fn all_nine_programs_have_a_manifest_and_a_calls_file() {
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

/// Every recorded call's effects across the nine programs: `None` for the top element (`"unknown"`).
fn recorded_effects() -> Vec<Option<Vec<String>>> {
    let mut out = Vec::new();
    for program in PROGRAMS {
        for c in load("calls", program)["calls"].as_array().unwrap() {
            out.push(c["effects"].as_array().map(|ks| ks.iter().map(|k| k.as_str().unwrap().to_string()).collect()));
        }
    }
    out
}

/// One value of each effect term and network direction. The match below is exhaustive, so a new variant does not
/// compile until it is listed here and given a key.
fn every_term() -> Vec<ProgramEffect> {
    let net = |direction| ProgramEffect::Network(Network { direction });
    vec![
        ProgramEffect::Read,
        ProgramEffect::Write,
        ProgramEffect::WriteNames,
        ProgramEffect::RunsCode,
        ProgramEffect::Unknown,
        net(None),
        net(Some(Direction::Both)),
        net(Some(Direction::Read)),
        net(Some(Direction::Write)),
    ]
}

/// Whether a recorded call's effects show `term` was read: `None` is the top element.
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
fn every_effect_term_the_host_reads_is_exercised_by_a_vector() {
    let recorded = recorded_effects();
    // No vector manifest says `{"network": {"direction": "write"}}`: none of the nine programs only sends. It is held
    // by `a_send_only_network_term_describes_as_a_write` below until window-ml's vectors gain one.
    let without_vector = [ProgramEffect::Network(Network { direction: Some(Direction::Write) })];
    for term in every_term() {
        let seen = recorded.iter().any(|e| shows(&term, e));
        if without_vector.contains(&term) {
            assert!(!seen, "{term:?} now has a vector: drop it from without_vector");
        } else {
            assert!(seen, "no vector call exercises {term:?}");
        }
    }
}

#[test]
fn a_send_only_network_term_describes_as_a_write() {
    let mut m = load("manifests", "cat");
    m["command"]["effects"] = json!([{ "network": { "direction": "write" } }]);
    let manifest: Manifest = serde_json::from_value(m).unwrap();
    let d = describe_call(&["cat".to_string()], &manifest, None, &[]);
    assert_eq!(d.effects.to_json(), json!(["write:net:*"]));
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
