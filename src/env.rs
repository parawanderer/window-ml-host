//! env.rs — the environment a child gets: a scrubbed base built from a whitelist of the host's own variables, plus
//! the call's additions, minus the names that turn a read into running code (`PAGER`, `GIT_EXTERNAL_DIFF`,
//! `LD_PRELOAD`, …). The host's environment is the person's login session (or Chrome's); none of the rest crosses.

use std::collections::BTreeMap;

use serde_json::Value;

/// Variables copied from the host's own environment into the base, when set.
const BASE_PASS: &[&str] = &["HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ"];

/// Variables the base always sets: no terminal; git never prompts (stdin is closed anyway) and never takes its
/// OPTIONAL locks, so `git status` does not refresh `.git/index` and a call its manifest calls a read stays one; and
/// git's command-line config pins `core.fsmonitor` off and `core.pager` to `cat` over whatever the repository's own
/// config says (a repository arrives with its config). `diff.external` is NOT pinned: an empty value makes every
/// `git diff` fail (measured with git 2.55); the manifest's `--no-ext-diff` and the `repoConfigRunsCode` fact cover it.
const BASE_SET: &[(&str, &str)] = &[
    ("TERM", "dumb"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_CONFIG_COUNT", "2"),
    ("GIT_CONFIG_KEY_0", "core.fsmonitor"),
    ("GIT_CONFIG_VALUE_0", "false"),
    ("GIT_CONFIG_KEY_1", "core.pager"),
    ("GIT_CONFIG_VALUE_1", "cat"),
];

/// Names a call may set and still be in the free tier (SHELL.md's whitelist): locale, time zone, colour and width.
/// `TERM` only as `dumb`. Anything else a call sets makes it ask; the denylist above refuses outright.
const FREE_NAMES: &[&str] = &["LANG", "TZ", "NO_COLOR", "COLUMNS", "TERM"];

/// Whether every variable the call sets is on the FREE list (`env.free` in the facts).
pub fn is_free(call: &CallEnv) -> bool {
    call.secrets.is_empty()
        && call.plain.iter().all(|(k, v)| {
            (k == "TERM" && v == "dumb") || (k != "TERM" && (FREE_NAMES.contains(&k.as_str()) || k.starts_with("LC_")))
        })
}

/// Names a call may never set, compared in upper case. Each makes some program run code, read a different config, or
/// write a file it was not asked to (PROGRAM_MANIFEST.md, `env`). `PATH`, `HOME` and `TMPDIR` belong to the host.
const DENY_NAMES: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "SHELL",
    "PAGER",
    "MANPAGER",
    "GIT_PAGER",
    "EDITOR",
    "VISUAL",
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "GIT_EXTERNAL_DIFF",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_PROXY_COMMAND",
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_EXTERNAL_TOOL",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "PROMPT_COMMAND",
    "IFS",
    "SHELLOPTS",
    "BASHOPTS",
    "PS4",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "CLASSPATH",
    "LESSOPEN",
    "LESSCLOSE",
    "GCONV_PATH",
    "HOSTALIASES",
    "RES_OPTIONS",
    "LOCALDOMAIN",
    "NLSPATH",
    "TERMINFO",
    "TERMCAP",
    "XDG_CONFIG_HOME",
    "XDG_CONFIG_DIRS",
    "XDG_DATA_HOME",
    "XDG_DATA_DIRS",
    "CURL_HOME",
    "WGETRC",
    "RIPGREP_CONFIG_PATH",
    "JQ_LIBRARY_PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
];

/// Prefixes a call may never set: the dynamic loaders, git's config injection and tracing (which writes to a path it
/// names), npm's config, and exported shell functions.
const DENY_PREFIXES: &[&str] =
    &["LD_", "DYLD_", "GIT_CONFIG", "GIT_TRACE", "NPM_CONFIG_", "BASH_FUNC_", "MALLOC", "SSH_", "GPG_"];

/// Why an `env` entry was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum EnvError {
    /// Not a valid name, or a value that is neither a string nor a handle, or a NUL in it.
    Bad(String),
    /// A name on the denylist.
    Refused(String),
    /// A secret handle the store does not hold.
    SecretUnavailable(String),
}

/// Where secret values come from at spawn. The value never crosses the protocol; only the handle's NAME does.
pub trait SecretStore: Send + Sync {
    fn resolve(&self, name: &str) -> Option<String>;
}

/// The store this version ships: empty, so every handle is `SecretUnavailable` (SECRET_HANDLES.md, "Processes as a
/// sink": the injection point exists, nothing is held yet).
pub struct NoSecrets;

impl SecretStore for NoSecrets {
    fn resolve(&self, _: &str) -> Option<String> {
        None
    }
}

/// A call's `env` after checking: what it sets, and which of those are secret handles (by name).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CallEnv {
    /// Plain values, by name.
    pub plain: BTreeMap<String, String>,
    /// Handles: variable name to secret name.
    pub secrets: BTreeMap<String, String>,
}

/// Checks a call's `env` object: every name valid and not denied, every value a string or `{ "$secret": name }`
/// held by `store`.
pub fn check_call_env(env: &serde_json::Map<String, Value>, store: &dyn SecretStore) -> Result<CallEnv, EnvError> {
    let mut out = CallEnv::default();
    for (name, value) in env {
        if !valid_name(name) {
            return Err(EnvError::Bad(format!("not an environment variable name: {name:?}")));
        }
        if denied(name) {
            return Err(EnvError::Refused(name.clone()));
        }
        match value {
            Value::String(s) if !s.contains('\0') => {
                out.plain.insert(name.clone(), s.clone());
            }
            Value::Object(o) if o.len() == 1 && o.get("$secret").is_some_and(Value::is_string) => {
                let secret = o["$secret"].as_str().unwrap_or_default().to_string();
                if store.resolve(&secret).is_none() {
                    return Err(EnvError::SecretUnavailable(secret));
                }
                out.secrets.insert(name.clone(), secret);
            }
            _ => return Err(EnvError::Bad(format!("{name}: a value is a string or {{\"$secret\": name}}"))),
        }
    }
    Ok(out)
}

/// Whether a call may never set `name`.
pub fn denied(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    DENY_NAMES.contains(&up.as_str()) || DENY_PREFIXES.iter().any(|p| up.starts_with(p))
}

fn valid_name(n: &str) -> bool {
    let mut cs = n.chars();
    matches!(cs.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && cs.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// The full environment for one spawn: the base (whitelisted host variables, `PATH`, `TMPDIR`, the fixed settings),
/// then the call's plain values, then its secrets resolved from `store`. `host` is the host's own environment.
pub fn build(
    host: &dyn Fn(&str) -> Option<String>,
    path: &str,
    tmpdir: &str,
    call: &CallEnv,
    store: &dyn SecretStore,
) -> Result<BTreeMap<String, String>, EnvError> {
    let mut env = BTreeMap::new();
    for k in BASE_PASS {
        if let Some(v) = host(k) {
            env.insert((*k).to_string(), v);
        }
    }
    for (k, v) in BASE_SET {
        env.insert((*k).to_string(), (*v).to_string());
    }
    env.insert("PATH".into(), path.into());
    env.insert("TMPDIR".into(), tmpdir.into());
    env.extend(call.plain.iter().map(|(k, v)| (k.clone(), v.clone())));
    for (k, s) in &call.secrets {
        let v = store.resolve(s).ok_or_else(|| EnvError::SecretUnavailable(s.clone()))?;
        env.insert(k.clone(), v);
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- the call's env additions ---

    fn check(v: Value) -> Result<CallEnv, EnvError> {
        check_call_env(v.as_object().unwrap(), &NoSecrets)
    }

    #[test]
    fn plain_values_pass() {
        let e = check(json!({ "LC_ALL": "C", "RUST_LOG": "debug" })).unwrap();
        assert_eq!(e.plain.len(), 2);
    }

    #[test]
    fn every_name_that_runs_code_is_refused_in_any_case() {
        for n in [
            "PAGER",
            "pager",
            "GIT_EXTERNAL_DIFF",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "GIT_SSH_COMMAND",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_PARAMETERS",
            "GIT_TRACE",
            "GIT_TRACE_PACKET",
            "npm_config_script_shell",
            "BASH_FUNC_x%%",
            "PATH",
            "HOME",
            "TMPDIR",
            "NODE_OPTIONS",
            "RIPGREP_CONFIG_PATH",
            "GIT_DIR",
            "SSH_AUTH_SOCK",
        ] {
            let r = check(json!({ n: "x" }));
            assert!(matches!(r, Err(EnvError::Refused(_)) | Err(EnvError::Bad(_))), "{n}: {r:?}");
        }
    }

    #[test]
    fn bad_names_and_values_are_refused() {
        assert!(matches!(check(json!({ "1ABC": "x" })), Err(EnvError::Bad(_))));
        assert!(matches!(check(json!({ "A=B": "x" })), Err(EnvError::Bad(_))));
        assert!(matches!(check(json!({ "": "x" })), Err(EnvError::Bad(_))));
        assert!(matches!(check(json!({ "A": 1 })), Err(EnvError::Bad(_))));
        assert!(matches!(check(json!({ "A": "a\u{0}b" })), Err(EnvError::Bad(_))));
        assert!(matches!(check(json!({ "A": { "$secret": "x", "more": 1 } })), Err(EnvError::Bad(_))));
    }

    #[test]
    fn a_secret_handle_is_unavailable_while_the_store_is_empty() {
        assert_eq!(
            check(json!({ "GITHUB_TOKEN": { "$secret": "github" } })),
            Err(EnvError::SecretUnavailable("github".into()))
        );
    }

    #[test]
    fn a_held_secret_is_injected_at_build_and_reported_by_name_only() {
        struct One;
        impl SecretStore for One {
            fn resolve(&self, n: &str) -> Option<String> {
                (n == "github").then(|| "s3cret".into())
            }
        }
        let e = check_call_env(json!({ "GITHUB_TOKEN": { "$secret": "github" } }).as_object().unwrap(), &One).unwrap();
        assert_eq!(e.secrets.get("GITHUB_TOKEN").map(String::as_str), Some("github"));
        let env = build(&|_| None, "/usr/bin", "/tmp/x", &e, &One).unwrap();
        assert_eq!(env.get("GITHUB_TOKEN").map(String::as_str), Some("s3cret"));
    }

    // --- the scrubbed base ---

    #[test]
    fn the_base_carries_only_the_whitelist() {
        let host = |k: &str| match k {
            "HOME" => Some("/home/u".to_string()),
            "AWS_SECRET_ACCESS_KEY" | "SSH_AUTH_SOCK" | "OPENAI_API_KEY" | "PAGER" => Some("leak".into()),
            _ => None,
        };
        let env = build(&host, "/usr/bin:/bin", "/tmp/c1", &CallEnv::default(), &NoSecrets).unwrap();
        let keys: Vec<&str> = env.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "GIT_CONFIG_COUNT",
                "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_KEY_1",
                "GIT_CONFIG_VALUE_0",
                "GIT_CONFIG_VALUE_1",
                "GIT_OPTIONAL_LOCKS",
                "GIT_TERMINAL_PROMPT",
                "HOME",
                "PATH",
                "TERM",
                "TMPDIR"
            ]
        );
        assert!(!env.values().any(|v| v == "leak"));
    }
}

#[cfg(test)]
mod free_tests {
    use super::*;
    use serde_json::json;

    // --- the FREE list ---

    #[test]
    fn only_locale_time_colour_width_and_a_dumb_terminal_are_free() {
        let free = |v: serde_json::Value| is_free(&check_call_env(v.as_object().unwrap(), &NoSecrets).unwrap());
        assert!(free(json!({})));
        assert!(free(
            json!({ "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "NO_COLOR": "1", "COLUMNS": "200", "TERM": "dumb" })
        ));
        assert!(!free(json!({ "TERM": "xterm" })));
        assert!(!free(json!({ "RUST_LOG": "debug" })));
    }
}
