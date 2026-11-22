//! lib.rs — the describer (`wmlhost-describe`) behind a raw wasm ABI, for window.ml's service worker.
//!
//! Exports: `memory`, `alloc(len) -> ptr`, `dealloc(ptr, cap)` and `describe(ptr, len) -> ptr`. The caller `alloc`s the
//! request and writes it, calls `describe`, reads `[u32 LE length][JSON]` at the returned pointer, and frees the
//! request with `dealloc(ptr, len)` and the reply with `dealloc(ptr, 4 + length)`.
//!
//! Request (UTF-8 JSON): `{"argv": [string], "manifest": <program manifest>, "version"?: string, "envSet"?: [string],
//! "flavour"?: "gnu" | "bsd" | "other"}`. A missing `version` is "not reported", a missing `flavour` "undetected".
//!
//! Reply: `{"error": string}` when the request does not parse (a wrong type anywhere, an unreadable manifest, an
//! unknown flavour); nothing here panics on input. Otherwise the description BEFORE path resolution, which the caller
//! resolves itself (docs/plan ONE_DESCRIBER_BUILD.md section 1), with the names the shared vectors record:
//!
//! - `described`, `why`, `program`, `subcommand`, `pathArgs`, `actsOnDir`, `dirArg`, `recursive`, `harden`
//!   (`[{at, args}]`), `operandStart`, `terminator`, `runner`, `echoes`, `okCodes`, `hardened` (the argv with the
//!   hardening inserted): as `CallDescription` and `harden_argv` give them.
//! - `effects`: the unresolved effects (`"unknown"` or keys ending `:?:?`), as `describe_call_as` gives them.
//! - `pre`: the effect terms with their targets as placeholders, as `describe_pre` gives them and the `resolved/` rows
//!   record them (`[{term, targets: [{arg, given}]}]`); empty when the call is not described.

use serde_json::{Value, json};
use wmlhost_describe::manifest::{Flavour, Manifest, describe_pre, harden_argv};

/// Reserves `len` bytes in the module's memory for the caller to write into.
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// Frees what `alloc` (or `describe`) returned, given the size it was made with.
///
/// # Safety
/// `ptr` must come from `alloc(cap)` or from `describe` (then `cap` is `4 + length`), and not be freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, cap: usize) {
    // SAFETY: the caller's contract above: the pointer and capacity are what the allocation was made with.
    unsafe { drop(Vec::from_raw_parts(ptr, 0, cap.max(1))) }
}

/// A request field that must be an array of strings when present.
fn strings(v: &Value, key: &str) -> Result<Vec<String>, String> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|s| s.as_str().map(String::from).ok_or_else(|| format!("{key}: every entry must be a string")))
            .collect(),
        Some(_) => Err(format!("{key}: must be an array of strings")),
    }
}

/// The reply for one request, or why it could not be read.
fn run(req: &[u8]) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(req).map_err(|e| format!("request: {e}"))?;
    if v.get("argv").is_none() {
        return Err("argv: missing".into());
    }
    let argv = strings(&v, "argv")?;
    let env = strings(&v, "envSet")?;
    let m: Manifest = serde_json::from_value(v.get("manifest").cloned().unwrap_or(Value::Null))
        .map_err(|e| format!("manifest: {e}"))?;
    let version = match v.get("version") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return Err("version: must be a string".into()),
    };
    let flavour = match v.get("flavour") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(match s.as_str() {
            "gnu" => Flavour::Gnu,
            "bsd" => Flavour::Bsd,
            "other" => Flavour::Other,
            f => return Err(format!("flavour: unknown {f:?}")),
        }),
        Some(_) => return Err("flavour: must be a string".into()),
    };
    let (d, pre) = describe_pre(&argv, &m, version, &env, flavour);
    let hardened = harden_argv(&argv, &d);
    Ok(json!({
        "described": d.described, "why": d.why, "program": d.program, "subcommand": d.subcommand,
        "effects": d.effects.to_json(), "pre": pre, "pathArgs": d.path_args,
        "actsOnDir": d.acts_on_dir, "dirArg": d.dir_arg, "recursive": d.recursive,
        "harden": d.harden.iter().map(|h| json!({"at": h.at, "args": h.args})).collect::<Vec<_>>(),
        "operandStart": d.operand_start, "terminator": d.terminator,
        "runner": d.runner, "echoes": d.echoes, "okCodes": d.ok_codes, "hardened": hardened,
    }))
}

/// Describes the request at `ptr`/`len`; returns a pointer to `[u32 LE length][JSON]`, freed with `dealloc(ptr, 4 +
/// length)`.
///
/// # Safety
/// `ptr` must be `alloc`'d with at least `len` bytes written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn describe(ptr: *const u8, len: usize) -> *mut u8 {
    // SAFETY: the caller's contract above.
    let req = unsafe { std::slice::from_raw_parts(ptr, len) };
    let reply = run(req).unwrap_or_else(|e| json!({ "error": e }));
    let out = serde_json::to_vec(&reply).unwrap_or_else(|_| br#"{"error":"reply: not serialisable"}"#.to_vec());
    let mut buf = Vec::with_capacity(4 + out.len());
    buf.extend_from_slice(&(out.len() as u32).to_le_bytes());
    buf.extend_from_slice(&out);
    let mut b = buf.into_boxed_slice();
    let p = b.as_mut_ptr();
    std::mem::forget(b);
    p
}
