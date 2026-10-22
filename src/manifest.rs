//! manifest.rs — the program manifest reader: what a command line does (which arguments are paths, what it reads,
//! writes or runs), computed from the same JSON as window-ml's `describeCall`, held to the shared vectors.
//!
//! This is a port of window-ml's `src/shell/program-manifest.ts` (`describeCall`, `hardenArgv`, `inRange`) and of the
//! parts of `src/effects.ts` they use (`fromProgramEffect`, `union`, `effectKey`). Paths are described as given: the
//! reader does not resolve them (no `resolve` callback), so every filesystem effect key ends in `:?:?`. A manifest
//! DESCRIBES a program and never decides; the policy that reads the description lives in the extension.

use std::fmt;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

// --- the format ---

/// A JSON object whose entries keep the order the file wrote them in. A repeated key keeps the last value, as
/// `JSON.parse` does.
#[derive(Debug, Clone, PartialEq)]
pub struct OrderedMap<T>(Vec<(String, T)>);

impl<T> OrderedMap<T> {
    /// The value under `key`, if the table lists it.
    pub fn get(&self, key: &str) -> Option<&T> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The entries in the order the JSON gave them.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &T)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// How many entries the table has.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OrderedMap<T> {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct V<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = OrderedMap<T>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out: Vec<(String, T)> = Vec::new();
                while let Some((k, v)) = map.next_entry::<String, T>()? {
                    match out.iter_mut().find(|(ek, _)| *ek == k) {
                        Some(slot) => slot.1 = v,
                        None => out.push((k, v)),
                    }
                }
                Ok(OrderedMap(out))
            }
        }
        de.deserialize_map(V(std::marker::PhantomData))
    }
}

/// Which way a `network` effect moves data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Reads the remote resource (`git fetch`, whatever its transport sends).
    Read,
    /// Changes the remote resource (`git push`); one that only fetches is a read, whatever it sends (EFFECTS.md).
    Write,
    /// Both; what a `network` term without a direction means.
    Both,
}

/// An effect term in the program-manifest vocabulary.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub enum ProgramEffect {
    /// Reads the command's path targets.
    #[serde(rename = "read")]
    Read,
    /// Writes the command's path targets.
    #[serde(rename = "write")]
    Write,
    /// Creates, removes or renames the command's path targets as entries (`find -delete`, `rm`, `mv`): a `write` whose
    /// key is kept apart from an in-place one (`write-names:fs:…`), so the two never de-duplicate (window-ml's
    /// `EFFECTS.md`, "The top-level names of a root are outside `B`").
    #[serde(rename = "write-names")]
    WriteNames,
    /// Starts another program.
    #[serde(rename = "runs-code")]
    RunsCode,
    /// Can do what no manifest describes: the call is not described.
    #[serde(rename = "unknown")]
    Unknown,
    /// Reaches the network, in a direction (both when absent).
    #[serde(rename = "network")]
    Network(Network),
}

impl ProgramEffect {
    /// One value of each term and of each network direction, absent included: the inventory the vector test
    /// (`tests/manifest_vectors.rs`) holds to the recorded calls. Held to the enum by [`ProgramEffect::slot`]: a new
    /// variant does not build until it has a slot here.
    pub const ALL: [ProgramEffect; 9] = [
        ProgramEffect::Read,
        ProgramEffect::Write,
        ProgramEffect::WriteNames,
        ProgramEffect::RunsCode,
        ProgramEffect::Unknown,
        ProgramEffect::Network(Network { direction: None }),
        ProgramEffect::Network(Network { direction: Some(Direction::Both) }),
        ProgramEffect::Network(Network { direction: Some(Direction::Read) }),
        ProgramEffect::Network(Network { direction: Some(Direction::Write) }),
    ];

    /// Where this term sits in [`ProgramEffect::ALL`]. The `match` is exhaustive, so a new variant (or direction) does
    /// not build until it has an arm; each arm indexes `ALL` at its own slot, and a slot `ALL` does not have is an
    /// out-of-bounds index into a constant, which does not build either (`unconditional_panic`, deny by default).
    pub const fn slot(&self) -> usize {
        match self {
            ProgramEffect::Read => {
                let _ = &Self::ALL[0];
                0
            }
            ProgramEffect::Write => {
                let _ = &Self::ALL[1];
                1
            }
            ProgramEffect::WriteNames => {
                let _ = &Self::ALL[2];
                2
            }
            ProgramEffect::RunsCode => {
                let _ = &Self::ALL[3];
                3
            }
            ProgramEffect::Unknown => {
                let _ = &Self::ALL[4];
                4
            }
            ProgramEffect::Network(Network { direction: None }) => {
                let _ = &Self::ALL[5];
                5
            }
            ProgramEffect::Network(Network { direction: Some(Direction::Both) }) => {
                let _ = &Self::ALL[6];
                6
            }
            ProgramEffect::Network(Network { direction: Some(Direction::Read) }) => {
                let _ = &Self::ALL[7];
                7
            }
            ProgramEffect::Network(Network { direction: Some(Direction::Write) }) => {
                let _ = &Self::ALL[8];
                8
            }
        }
    }
}

/// The body of a `{ "network": ... }` term.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// The direction, both when absent.
    pub direction: Option<Direction>,
}

/// Whether a flag's or primary's path is read or written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The program reads it.
    Read,
    /// The program writes it.
    Write,
}

/// The end-of-options marker a command honours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Terminator {
    /// `--`.
    #[serde(rename = "--")]
    DashDash,
    /// `--end-of-options`.
    #[serde(rename = "--end-of-options")]
    EndOfOptions,
}

impl Terminator {
    /// The marker as written on a command line.
    pub fn as_str(self) -> &'static str {
        match self {
            Terminator::DashDash => "--",
            Terminator::EndOfOptions => "--end-of-options",
        }
    }
}

/// What a command touches when it is given no path operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoPaths {
    /// The current directory (`ls`, `rg`).
    Cwd,
    /// Nothing (stdin: `cat`).
    Nothing,
}

/// The words of a `paths` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathsWord {
    /// No operand is a path.
    None,
    /// Every operand is a path.
    Operands,
    /// The repository: the cwd, or a `valueIsDir` flag's value.
    Repo,
}

/// `{ "operandsFrom": n }`: the operands from an index on are paths.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperandsFrom {
    /// The first operand index that is a path.
    pub operands_from: usize,
}

/// Which operands of a command are paths.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Paths {
    /// A word: none, operands or repo.
    Word(PathsWord),
    /// All operands from an index on.
    From(OperandsFrom),
}

/// A command's grammar when it is not options-then-operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Syntax {
    /// `find`: options, path operands, then an expression of primaries.
    #[serde(rename = "find")]
    Find,
}

/// One flag of a command. A flag the table does not list makes the call unknown.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlagSpec {
    /// Takes one value: `--f=v`, `--f v`, `-fv` or `-f v`.
    #[serde(default)]
    pub value: bool,
    /// Takes a value only in the attached form (`--color=always`).
    #[serde(default)]
    pub optional_value: bool,
    /// Effects the flag adds.
    #[serde(default)]
    pub effects: Vec<ProgramEffect>,
    /// The flag's value is a path the program reads or writes.
    pub value_is_path: Option<Role>,
    /// The flag's value is the directory the command acts in.
    #[serde(default)]
    pub value_is_dir: bool,
    /// With this flag, path operands start at this index.
    pub paths_from: Option<usize>,
    /// It starts another program.
    #[serde(default)]
    pub runner: bool,
    /// It prints the environment or its inputs back.
    #[serde(default)]
    pub echoes: bool,
    /// Exit codes that become answers with this flag.
    pub ok_codes: Option<Vec<u8>>,
    /// With this flag the command walks its directory arguments.
    #[serde(default)]
    pub recursive: bool,
}

/// A `find`-style expression primary.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrimarySpec {
    /// Arguments consumed after the primary.
    pub args: Option<usize>,
    /// Consumes arguments up to and including one of these.
    pub until: Option<Vec<String>>,
    /// Effects the primary adds.
    #[serde(default)]
    pub effects: Vec<ProgramEffect>,
    /// Its first argument is a path the program reads or writes.
    pub arg_is_path: Option<Role>,
    /// It starts another program.
    #[serde(default)]
    pub runner: bool,
}

/// A program or one of its subcommands.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandSpec {
    /// What the command does with no flags, applied to its path targets.
    pub effects: Vec<ProgramEffect>,
    /// Which operands are paths.
    pub paths: Paths,
    /// What the command touches when it is given no path operand.
    pub no_paths: Option<NoPaths>,
    /// The end-of-options marker the command honours.
    pub terminator: Option<Terminator>,
    /// Accepts `-<n>` as a number.
    #[serde(default)]
    pub numeric_flag: bool,
    /// Short flags combine.
    #[serde(default)]
    pub clusters: bool,
    /// At most this many operands; more makes the call unknown.
    pub max_operands: Option<usize>,
    /// The command's flags, in the file's order.
    pub flags: OrderedMap<FlagSpec>,
    /// The first operand selects one of these.
    pub subcommands: Option<OrderedMap<CommandSpec>>,
    /// A grammar other than options-then-operands.
    pub syntax: Option<Syntax>,
    /// For `find` syntax: every primary and operator.
    pub primaries: Option<OrderedMap<PrimarySpec>>,
    /// Exit codes that are answers.
    pub ok_codes: Option<Vec<u8>>,
    /// Prints its inputs back.
    #[serde(default)]
    pub echoes: bool,
    /// Walks its directory arguments.
    #[serde(default)]
    pub recursive: bool,
    /// Arguments inserted right after this command's name.
    pub harden: Option<Vec<String>>,
    /// An argument starting with `-` after an operand, `--` included, makes the call unknown (GNU permutes, BSD stops).
    #[serde(default)]
    pub options_first: bool,
    /// A lone `-` is a file name: it stays a path operand.
    #[serde(default)]
    pub dash_is_path: bool,
    /// Effects also fall on the directory the command acts in and on the repository's root.
    #[serde(default)]
    pub repo_wide: bool,
    /// Operands are git pathspecs: one starting with `:`, or holding `*`, `?`, `[` or `\\`, makes the call unknown.
    #[serde(default)]
    pub pathspecs: bool,
}

/// The versions a manifest was written against and how the host reads the version.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionSpec {
    /// A range of space-separated comparators, or `"*"` for a program that reports no version.
    pub range: String,
    /// The arguments that make the program print its version.
    pub args: Vec<String>,
    /// A regex whose group 1 is the version.
    pub pattern: String,
}

/// A program manifest: the program, its versions and its command tree.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// The program's name, which `argv[0]`'s basename must equal.
    pub program: String,
    /// The versions the manifest was written against.
    pub version: VersionSpec,
    /// Exit codes that are answers (`[0]` when absent).
    #[serde(rename = "okCodes")]
    pub ok_codes: Option<Vec<u8>>,
    /// Prints its inputs back.
    #[serde(default)]
    pub echoes: bool,
    /// Environment variables that change what the program does.
    #[serde(default)]
    pub env: Vec<String>,
    /// The command tree.
    pub command: CommandSpec,
}

// --- the description ---

/// A path the host is asked to resolve: its argv index, the separator to split on when it is a flag's attached value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathArg {
    /// The argv index.
    pub arg: usize,
    /// The separator, when the path follows it inside the argument (`--output=f`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split: Option<String>,
    /// Whether the program reads or writes it.
    pub role: Role,
    /// The call walks this directory.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub walk: bool,
}

/// Where `harden_argv` inserts a command's hardening arguments: after argv index `at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Harden {
    /// The argv index the arguments go after.
    pub at: usize,
    /// The arguments.
    pub args: Vec<String>,
}

/// A call's effects: the sorted, de-duplicated effect keys, or the top element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effects {
    /// Anything in the call is outside the manifest.
    Unknown,
    /// Keys in window-ml's `effectKey` format (`read:fs:.:?:?`, `read:net:*`, `exec:process`), sorted.
    Keys(Vec<String>),
}

impl Effects {
    /// The JSON the vectors record: the string `"unknown"`, or the array of keys.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Effects::Unknown => serde_json::Value::String("unknown".into()),
            Effects::Keys(k) => serde_json::json!(k),
        }
    }
}

/// What `describe_call` finds in one argv: the facts a policy is given, before the host resolves the paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallDescription {
    /// False when anything in the call is outside the manifest; `why` says what.
    pub described: bool,
    /// Why the call is not described.
    pub why: Vec<String>,
    /// The program's name.
    pub program: String,
    /// The subcommand path, empty for a program without subcommands.
    pub subcommand: Vec<String>,
    /// What the call affects.
    pub effects: Effects,
    /// The arguments the host resolves.
    pub path_args: Vec<PathArg>,
    /// The command acts on its directory (the cwd, or `dir_arg`'s value).
    pub acts_on_dir: bool,
    /// The argv index of a `valueIsDir` flag's value.
    pub dir_arg: Option<usize>,
    /// The call walks directories.
    pub recursive: bool,
    /// Where `harden_argv` inserts arguments.
    pub harden: Vec<Harden>,
    /// Where operands start, if any.
    pub operand_start: Option<usize>,
    /// The terminator the command honours.
    pub terminator: Option<Terminator>,
    /// The call starts another program.
    pub runner: bool,
    /// The call prints its inputs back.
    pub echoes: bool,
    /// The exit codes that are answers.
    pub ok_codes: Vec<u8>,
}

/// Where a term applies: the command's targets, or one argument (after a separator, if any).
enum Targets {
    Command,
    Arg(usize, Option<String>),
}

type Terms = Vec<(ProgramEffect, Targets)>;

/// What a flag's value looks like on the command line.
struct ValueAt {
    arg: usize,
    split: Option<&'static str>,
    attached: bool,
}

/// What an options or find parse hands back.
struct Parsed {
    operands: Vec<usize>,
    paths_from: Option<usize>,
    sub: Option<usize>,
}

/// Appends `add` to `list`, skipping what it already holds (a JS `Set` over numbers, in insertion order).
fn push_unique(list: &mut Vec<u8>, add: impl IntoIterator<Item = u8>) {
    for c in add {
        if !list.contains(&c) {
            list.push(c);
        }
    }
}

/// Describes one argv by its program's manifest. `argv[0]` is the program as the caller wrote it; its basename must
/// name the manifest's program. `version` is the version the host recorded (`None`: not reported); `env_set` names the
/// environment variables the call sets. Paths are left as given.
pub fn describe_call(argv: &[String], m: &Manifest, version: Option<&str>, env_set: &[String]) -> CallDescription {
    let mut d = CallDescription {
        described: true,
        why: Vec::new(),
        program: m.program.clone(),
        subcommand: Vec::new(),
        effects: Effects::Keys(Vec::new()),
        path_args: Vec::new(),
        acts_on_dir: false,
        dir_arg: None,
        recursive: false,
        harden: Vec::new(),
        operand_start: None,
        terminator: None,
        runner: false,
        echoes: m.echoes,
        ok_codes: m.ok_codes.clone().unwrap_or_else(|| vec![0]),
    };
    let first = argv.first().map(String::as_str).unwrap_or("");
    let base = first.rsplit('/').next().unwrap_or("");
    if base != m.program {
        unknown(&mut d, format!("argv[0] {first:?} is not {}", m.program));
    }
    if m.version.range != "*" {
        match version {
            None => unknown(&mut d, "the program's version was not reported".into()),
            Some(v) if !in_range(v, &m.version.range) => {
                unknown(&mut d, format!("version {v} is outside {}", m.version.range))
            }
            Some(_) => {}
        }
    }
    for n in env_set {
        if m.env.contains(n) {
            unknown(&mut d, format!("the call sets {n}, which changes what {} does", m.program));
        }
    }

    let mut terms: Terms = Vec::new();
    let mut cmd = &m.command;
    let mut i = 1;
    let mut operand_paths: Vec<usize> = Vec::new();
    if let Some(h) = cmd.harden.as_ref().filter(|h| !h.is_empty()) {
        d.harden.push(Harden { at: 0, args: h.clone() });
    }
    // Descend through subcommands: options before a subcommand belong to the level above it.
    loop {
        let r = if cmd.syntax == Some(Syntax::Find) {
            parse_find(argv, i, cmd, &mut d, &mut terms)
        } else {
            parse_options(argv, i, cmd, &mut d, &mut terms)
        };
        let Some(sub) = r.sub else {
            operand_paths = finish_command(argv, cmd, &r.operands, r.paths_from, &mut d, &mut terms);
            break;
        };
        let Some(next) = cmd.subcommands.as_ref().and_then(|s| s.get(&argv[sub])) else {
            let path = std::iter::once(m.program.as_str()).chain(d.subcommand.iter().map(String::as_str));
            let msg =
                format!("{} has no subcommand {:?} in its manifest", path.collect::<Vec<_>>().join(" "), argv[sub]);
            unknown(&mut d, msg);
            break;
        };
        d.subcommand.push(argv[sub].clone());
        if let Some(h) = next.harden.as_ref().filter(|h| !h.is_empty()) {
            d.harden.push(Harden { at: sub, args: h.clone() });
        }
        cmd = next;
        i = sub + 1;
    }
    if cmd.recursive {
        d.recursive = true;
    }
    if d.recursive {
        for p in &mut d.path_args {
            if operand_paths.contains(&p.arg) {
                p.walk = true;
            }
        }
    }
    if let Some(codes) = &cmd.ok_codes {
        let mut merged: Vec<u8> = Vec::new();
        push_unique(&mut merged, codes.iter().copied());
        push_unique(&mut merged, d.ok_codes.iter().copied().filter(|c| *c != 0));
        d.ok_codes = merged;
    }
    if cmd.echoes {
        d.echoes = true;
    }

    if !d.described {
        d.effects = Effects::Unknown;
        return d;
    }
    let given = |i: usize, split: Option<&str>| -> String {
        match split.filter(|s| !s.is_empty()) {
            Some(s) => argv[i].find(s).map_or(argv[i].clone(), |at| argv[i][at + s.len()..].to_string()),
            None => argv[i].clone(),
        }
    };
    let repo_wide = cmd.repo_wide;
    let mut command_targets: Vec<String> = operand_paths.iter().map(|i| argv[*i].clone()).collect();
    if d.acts_on_dir {
        command_targets.push(d.dir_arg.map_or(".".to_string(), |a| argv[a].clone()));
    }
    if repo_wide {
        command_targets.push(d.dir_arg.map_or(".".to_string(), |a| argv[a].clone()));
        command_targets.push(".".to_string());
    }
    let mut keys: Vec<String> = Vec::new();
    for (term, targets) in &terms {
        let paths: Vec<String> = match targets {
            Targets::Command => command_targets.clone(),
            Targets::Arg(i, split) => vec![given(*i, split.as_deref())],
        };
        match term {
            ProgramEffect::Unknown => {
                d.effects = Effects::Unknown;
                return d;
            }
            ProgramEffect::RunsCode => keys.push("exec:process".into()),
            ProgramEffect::Read | ProgramEffect::Write => {
                let op = if *term == ProgramEffect::Read { "read" } else { "write" };
                keys.extend(paths.iter().map(|p| format!("{op}:fs:{p}:?:?")));
            }
            ProgramEffect::WriteNames => keys.extend(paths.iter().map(|p| format!("write-names:fs:{p}:?:?"))),
            ProgramEffect::Network(n) => match n.direction.unwrap_or(Direction::Both) {
                Direction::Both => keys.extend(["read:net:*".to_string(), "write:net:*".to_string()]),
                Direction::Read => keys.push("read:net:*".into()),
                Direction::Write => keys.push("write:net:*".into()),
            },
        }
    }
    // JS `Array.sort` compares UTF-16 code units, which is not Rust's byte order for characters above U+FFFF.
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    keys.dedup();
    d.effects = Effects::Keys(keys);
    d
}

/// Marks the call as not described, with the reason.
fn unknown(d: &mut CallDescription, why: String) {
    d.described = false;
    d.why.push(why);
}

/// The argv with the manifest's hardening arguments inserted (`git --no-pager diff --no-ext-diff ...`), skipping any
/// already present in the original argv. It describes exactly as the original does.
pub fn harden_argv(argv: &[String], d: &CallDescription) -> Vec<String> {
    let mut out = argv.to_vec();
    let mut hs: Vec<&Harden> = d.harden.iter().collect();
    hs.sort_by_key(|h| std::cmp::Reverse(h.at));
    for h in hs {
        let add = h.args.iter().filter(|a| !argv.contains(a)).cloned();
        let at = (h.at + 1).min(out.len());
        out.splice(at..at, add);
    }
    out
}

/// Whether a flag's or primary's term acts on the path it takes, when it takes one, rather than on the command's
/// targets: read, write and write-names (ruled 2026-10-21).
fn names_its_path(t: &ProgramEffect) -> bool {
    matches!(t, ProgramEffect::Read | ProgramEffect::Write | ProgramEffect::WriteNames)
}

/// Applies a flag to the call: its effects, its path or directory value, and its flags on the call as a whole.
fn apply(
    d: &mut CallDescription,
    terms: &mut Terms,
    paths_from: &mut Option<usize>,
    name: &str,
    f: &FlagSpec,
    value_at: Option<ValueAt>,
) {
    if f.effects.contains(&ProgramEffect::Unknown) {
        let msg = format!("{name} can make {} do what no manifest describes", d.program);
        unknown(d, msg);
    }
    // A flag's read/write/write-names applies to its own path value when it has one (`--output=f`), else to the
    // command's targets (`git push -u` writes the repository's config).
    for t in &f.effects {
        if f.value_is_path.is_some() && names_its_path(t) {
            continue;
        }
        terms.push((t.clone(), Targets::Command));
    }
    if let (Some(role), Some(v)) = (f.value_is_path, &value_at) {
        if v.attached {
            unknown(d, format!("{name}'s path is attached to a short flag; pass it as its own argument"));
        } else {
            let split = v.split.map(str::to_string);
            d.path_args.push(PathArg { arg: v.arg, split: split.clone(), role, walk: false });
            if f.effects.contains(&ProgramEffect::WriteNames) {
                terms.push((ProgramEffect::WriteNames, Targets::Arg(v.arg, split.clone())));
            }
            let term = if role == Role::Read { ProgramEffect::Read } else { ProgramEffect::Write };
            terms.push((term, Targets::Arg(v.arg, split)));
        }
    }
    if let (true, Some(v)) = (f.value_is_dir, &value_at) {
        if v.attached || v.split.is_some() {
            unknown(d, format!("{name}'s directory must be its own argument"));
        } else {
            d.dir_arg = Some(v.arg);
            d.path_args.push(PathArg { arg: v.arg, split: None, role: Role::Read, walk: false });
        }
    }
    if let Some(p) = f.paths_from {
        *paths_from = Some(p);
    }
    if f.runner {
        d.runner = true;
    }
    if f.echoes {
        d.echoes = true;
    }
    if f.recursive {
        d.recursive = true;
    }
    if let Some(c) = &f.ok_codes {
        push_unique(&mut d.ok_codes, c.iter().copied());
    }
}

/// Whether git may read a pathspec as something other than the one path it spells: `:` magic, or a glob or escape git expands.
fn not_literal_pathspec(a: &str) -> bool {
    a.starts_with(':') || a.contains(['*', '?', '[', '\\'])
}

/// Options-then-operands. Returns the operand indices, the path start a flag set, and the index of a subcommand name
/// when the command has subcommands and one was reached before any operand.
fn parse_options(
    argv: &[String],
    start: usize,
    cmd: &CommandSpec,
    d: &mut CallDescription,
    terms: &mut Terms,
) -> Parsed {
    let mut operands: Vec<usize> = Vec::new();
    let mut paths_from: Option<usize> = None;
    let mut after_terminator = false;
    let mut i = start;
    while i < argv.len() {
        let a = argv[i].as_str();
        if after_terminator {
            if cmd.pathspecs && not_literal_pathspec(a) {
                unknown(d, format!("pathspec {a:?} is magic or a glob, not a path"));
            }
            operands.push(i);
            i += 1;
            continue;
        }
        if cmd.options_first && !operands.is_empty() && a != "-" && a.starts_with('-') {
            unknown(d, format!("{a} follows an operand: GNU reads it as an option, BSD as a file name"));
            i += 1;
            continue;
        }
        if a == "--" || a == "--end-of-options" {
            let honoured = cmd.terminator.map(Terminator::as_str);
            if honoured == Some(a) || (a == "--" && honoured == Some("--end-of-options")) {
                after_terminator = true;
            } else {
                unknown(d, format!("{a} is not a terminator this command honours"));
            }
            i += 1;
            continue;
        }
        if a == "-" || !a.starts_with('-') {
            if cmd.subcommands.is_some() && operands.is_empty() {
                return Parsed { operands, paths_from, sub: Some(i) };
            }
            if cmd.pathspecs && not_literal_pathspec(a) {
                unknown(d, format!("pathspec {a:?} is magic or a glob, not a path"));
            }
            operands.push(i);
            i += 1;
            continue;
        }
        if cmd.numeric_flag && a.len() > 1 && a[1..].bytes().all(|b| b.is_ascii_digit()) {
            i += 1;
            continue;
        }
        if a.starts_with("--") {
            let eq = a.find('=');
            let name = eq.map_or(a, |e| &a[..e]);
            let Some(f) = cmd.flags.get(name) else {
                unknown(d, format!("flag {name} is not in the manifest"));
                i += 1;
                continue;
            };
            if f.value {
                if eq.is_some() {
                    apply(
                        d,
                        terms,
                        &mut paths_from,
                        name,
                        f,
                        Some(ValueAt { arg: i, split: Some("="), attached: false }),
                    );
                } else if i + 1 < argv.len() {
                    apply(
                        d,
                        terms,
                        &mut paths_from,
                        name,
                        f,
                        Some(ValueAt { arg: i + 1, split: None, attached: false }),
                    );
                    i += 1;
                } else {
                    unknown(d, format!("{name} needs a value"));
                }
            } else if eq.is_some() {
                if f.optional_value {
                    apply(d, terms, &mut paths_from, name, f, None);
                } else {
                    unknown(d, format!("{name} takes no value"));
                }
            } else {
                apply(d, terms, &mut paths_from, name, f, None);
            }
            i += 1;
            continue;
        }
        // A single-dash flag: a whole name first (`-C`, `-name`), then a cluster of one-letter flags.
        if let Some(whole) = cmd.flags.get(a) {
            if whole.value {
                if i + 1 < argv.len() {
                    apply(
                        d,
                        terms,
                        &mut paths_from,
                        a,
                        whole,
                        Some(ValueAt { arg: i + 1, split: None, attached: false }),
                    );
                    i += 1;
                } else {
                    unknown(d, format!("{a} needs a value"));
                }
            } else {
                apply(d, terms, &mut paths_from, a, whole, None);
            }
            i += 1;
            continue;
        }
        let letters: Vec<char> = a[1..].chars().collect();
        for (j, letter) in letters.iter().enumerate() {
            let name = format!("-{letter}");
            let Some(f) = cmd.flags.get(&name) else {
                let inside = if letters.len() > 1 { format!(" (in {a})") } else { String::new() };
                unknown(d, format!("flag {name}{inside} is not in the manifest"));
                break;
            };
            if j > 0 && !cmd.clusters {
                unknown(d, format!("{a}: this command's short flags do not combine"));
                break;
            }
            if f.value {
                if j + 1 < letters.len() {
                    apply(d, terms, &mut paths_from, &name, f, Some(ValueAt { arg: i, split: None, attached: true }));
                } else if i + 1 < argv.len() {
                    apply(
                        d,
                        terms,
                        &mut paths_from,
                        &name,
                        f,
                        Some(ValueAt { arg: i + 1, split: None, attached: false }),
                    );
                    i += 1;
                } else {
                    unknown(d, format!("{name} needs a value"));
                }
                break;
            }
            apply(d, terms, &mut paths_from, &name, f, None);
        }
        i += 1;
    }
    Parsed { operands, paths_from, sub: None }
}

/// find's grammar: options, then path operands up to the first expression token, then primaries and operators.
fn parse_find(argv: &[String], start: usize, cmd: &CommandSpec, d: &mut CallDescription, terms: &mut Terms) -> Parsed {
    let mut operands: Vec<usize> = Vec::new();
    let mut i = start;
    let is_pre_option = |a: &str| a.len() > 1 && a.starts_with('-') && a[1..].chars().all(|c| "HLPEXdsx".contains(c));
    while i < argv.len() && is_pre_option(&argv[i]) {
        let Some(f) = cmd.flags.get(&argv[i]) else { break };
        if f.effects.contains(&ProgramEffect::Unknown) {
            unknown(d, format!("{} can make find do what no manifest describes", argv[i]));
        }
        for t in &f.effects {
            terms.push((t.clone(), Targets::Command));
        }
        i += 1;
    }
    while i < argv.len() && !argv[i].starts_with('-') && !["(", ")", "!", ","].contains(&argv[i].as_str()) {
        operands.push(i);
        i += 1;
    }
    while i < argv.len() {
        let a = argv[i].as_str();
        let Some(p) = cmd.primaries.as_ref().and_then(|ps| ps.get(a)) else {
            unknown(d, format!("find expression {a:?} is not in the manifest"));
            break;
        };
        if p.effects.contains(&ProgramEffect::Unknown) {
            unknown(d, format!("{a} can make find do what no manifest describes"));
        }
        for t in &p.effects {
            if p.arg_is_path.is_some() && names_its_path(t) {
                continue;
            }
            terms.push((t.clone(), Targets::Command));
        }
        if p.runner {
            d.runner = true;
        }
        if let Some(until) = &p.until {
            let mut k = i + 1;
            while k < argv.len() && !until.contains(&argv[k]) {
                k += 1;
            }
            if k >= argv.len() {
                unknown(d, format!("{a} is not terminated by {}", until.join(" or ")));
                break;
            }
            i = k + 1;
            continue;
        }
        let n = p.args.unwrap_or(0);
        if i + n >= argv.len() {
            unknown(d, format!("{a} needs {n} argument{}", if n == 1 { "" } else { "s" }));
            break;
        }
        if let (Some(role), true) = (p.arg_is_path, n > 0) {
            d.path_args.push(PathArg { arg: i + 1, split: None, role, walk: false });
            if p.effects.contains(&ProgramEffect::WriteNames) {
                terms.push((ProgramEffect::WriteNames, Targets::Arg(i + 1, None)));
            }
            let term = if role == Role::Read { ProgramEffect::Read } else { ProgramEffect::Write };
            terms.push((term, Targets::Arg(i + 1, None)));
        }
        i += n + 1;
    }
    Parsed { operands, paths_from: None, sub: None }
}

/// After parsing a command: its path operands (returned; `-` is stdin, not a path), what it acts on without them, and
/// its own effects over those targets.
fn finish_command(
    argv: &[String],
    cmd: &CommandSpec,
    operands: &[usize],
    paths_from: Option<usize>,
    d: &mut CallDescription,
    terms: &mut Terms,
) -> Vec<usize> {
    if let Some(max) = cmd.max_operands {
        if operands.len() > max {
            unknown(d, format!("more than {max} operand(s)"));
        }
    }
    d.operand_start = operands.first().copied();
    d.terminator = cmd.terminator;
    let mut paths: Vec<usize> = match &cmd.paths {
        Paths::Word(PathsWord::Operands) => operands.to_vec(),
        Paths::From(f) => operands.get(paths_from.unwrap_or(f.operands_from)..).unwrap_or(&[]).to_vec(),
        Paths::Word(_) => Vec::new(),
    };
    if !cmd.dash_is_path {
        paths.retain(|i| argv[*i] != "-");
    }
    for i in &paths {
        d.path_args.push(PathArg { arg: *i, split: None, role: Role::Read, walk: false });
    }
    let none = cmd.paths == Paths::Word(PathsWord::None);
    d.acts_on_dir =
        cmd.paths == Paths::Word(PathsWord::Repo) || (paths.is_empty() && cmd.no_paths == Some(NoPaths::Cwd) && !none);
    if d.dir_arg.is_some() && cmd.paths != Paths::Word(PathsWord::Repo) && !cmd.repo_wide {
        unknown(d, "a directory flag on a command that does not act on a repository".into());
    }
    // The host resolves operands against the cwd; git resolves them against the -C directory (and composes repeated -C).
    if d.dir_arg.is_some() && cmd.repo_wide && !paths.is_empty() {
        unknown(d, "a directory flag moves where the operands resolve".into());
    }
    if cmd.effects.contains(&ProgramEffect::Unknown) {
        let path = std::iter::once(d.program.as_str()).chain(d.subcommand.iter().map(String::as_str));
        let msg = format!("{} is described as unknown", path.collect::<Vec<_>>().join(" "));
        unknown(d, msg);
    }
    for t in &cmd.effects {
        terms.push((t.clone(), Targets::Command));
    }
    paths
}

// --- versions ---

/// Whether a dotted version satisfies a range of space-separated comparators (`>=2.30.0 <3`), all of which must hold.
/// A version or comparator that is not dotted digits fails, so `"*"` is not a range here: `describe_call` skips the
/// check for it.
pub fn in_range(version: &str, range: &str) -> bool {
    let Some(v) = parse_version(version) else { return false };
    let mut any = false;
    for c in range.split_whitespace() {
        any = true;
        let (op, rest) =
            ["<=", ">=", ">", "<", "="].iter().find_map(|op| c.strip_prefix(op).map(|r| (*op, r))).unwrap_or(("=", c));
        let Some(want) = parse_version(rest) else { return false };
        let cmp = compare_versions(&v, &want);
        let ok = match op {
            ">=" => cmp >= 0,
            "<=" => cmp <= 0,
            ">" => cmp > 0,
            "<" => cmp < 0,
            _ => cmp == 0,
        };
        if !ok {
            return false;
        }
    }
    // An empty range splits to one empty comparator in the reference, which matches nothing.
    any
}

/// `1.2.3` as numbers, or `None` when it is not digits separated by dots.
fn parse_version(s: &str) -> Option<Vec<f64>> {
    s.split('.')
        .map(|p| if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) { p.parse::<f64>().ok() } else { None })
        .collect()
}

/// Compares two versions component by component, a missing component being 0.
fn compare_versions(a: &[f64], b: &[f64]) -> i32 {
    for i in 0..a.len().max(b.len()) {
        let d = a.get(i).copied().unwrap_or(0.0) - b.get(i).copied().unwrap_or(0.0);
        if d > 0.0 {
            return 1;
        }
        if d < 0.0 {
            return -1;
        }
    }
    0
}
