//! manifest_vectors.rs — the program manifest reader held to window-ml's shared vectors (vectors/program-manifests/).

use std::fs;
use std::path::Path;

use serde_json::{Value, json};
use window_ml_host::manifest::{Manifest, describe_call, harden_argv, in_range};

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
