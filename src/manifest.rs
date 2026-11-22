//! manifest.rs — the program manifest reader: what a command line does (which arguments are paths, what it reads,
//! writes or runs), computed from the same JSON as window-ml's `describeCall`, held to the shared vectors.
//!
//! This is a port of window-ml's `src/shell/program-manifest.ts` (`describeCall`, `hardenArgv`, `inRange`) and of the
//! parts of `src/effects.ts` they use (`fromProgramEffect`, `union`, `effectKey`). Paths are described as given: the
//! reader does not resolve them (no `resolve` callback), so every filesystem effect key ends in `:?:?`. A manifest
//! DESCRIBES a program and never decides; the policy that reads the description lives in the extension.
//!
//! A manifest that declares `flavours` (BSD and GNU, window-ml PROGRAM_MANIFEST.md "Flavours") is read here too:
//! [`describe_call_as`] takes the flavour as an input. Detecting it is the extension's (`flavourOf`, from the facts
//! this host reports); [`describe_call`] reads it undetected, and a manifest without `flavours` the same either way.

use std::borrow::Cow;
use std::fmt;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::script_grammar::{awk_program_refusal, is_awk_assignment, sed_script_refusal};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// The direction, both when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
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

/// Which path operands a writing command writes: the value of a `writtenOperands` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WrittenOperands {
    /// The last one, the destination (`cp a b dir`); the others are read.
    Last,
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
    /// The only values the flag is described with (BSD `sed -i ''`: `[""]`); any other value makes the call unknown.
    pub values: Option<Vec<String>>,
    /// A short flag whose value is the rest of its argument, empty when bare, and never the next argument (GNU
    /// `sed -i`, `-i.bak`).
    #[serde(default)]
    pub attached_value: bool,
    /// The value is a script in the command's `script` language (`sed -e`), checked by its grammar (`script_grammar`).
    #[serde(default)]
    pub script: bool,
}

/// A program language whose text a narrow grammar checks (`script_grammar`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptLang {
    /// A sed script.
    Sed,
    /// An awk program.
    Awk,
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
    /// Which path operands a writing command writes. Absent, a command whose effects write writes every path operand.
    pub written_operands: Option<WrittenOperands>,
    /// What one detected flavour adds to this command: only in a manifest that declares `flavours`.
    pub flavour: Option<CommandFlavours>,
    /// The first operand is a program in this language unless a `script` flag gave one (`sed 's/a/b/' f`, `awk '{print
    /// $1}' f`): a text outside its narrow grammar makes the call unknown. For `awk`, an operand that is an assignment
    /// (`n=1`) is not a path.
    pub script: Option<ScriptLang>,
    /// Internal (never in the JSON): a flavour that stops at the first operand reads every later argument as an operand.
    #[serde(skip)]
    pub stop: bool,
}

/// The overlays of one command, one per declared flavour.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandFlavours {
    /// What GNU adds.
    pub gnu: Option<FlavourOverlay>,
    /// What BSD adds.
    pub bsd: Option<FlavourOverlay>,
}

/// What one flavour adds to a command. Overlays only add: a flag in both the core and an overlay is refused by the
/// extension's validator.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlavourOverlay {
    /// Flags only this flavour accepts with this meaning.
    pub flags: Option<OrderedMap<FlagSpec>>,
    /// How this flavour reads an argument starting with `-` after an operand.
    pub arg_order: Option<ArgOrder>,
    /// Hardening arguments for this flavour, after the command's own.
    pub harden: Option<Vec<String>>,
}

/// How a flavour reads an argument starting with `-` after an operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ArgOrder {
    /// As a flag (GNU getopt).
    Permute,
    /// As an operand, with everything after the first operand (BSD getopt).
    Stop,
}

/// How each declared flavour is recognised. The extension detects the flavour (window-ml `flavourOf`); the host only
/// reads the manifest that declares it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flavours {
    /// GNU, by a version probe.
    pub gnu: Option<GnuFlavour>,
    /// BSD, as the system's own program.
    pub bsd: Option<BsdFlavour>,
}

/// GNU's probe: the arguments, a regex anchored with `^` whose group 1 is the version, and the range it must be in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnuFlavour {
    /// The version probe.
    pub probe: VersionSpec,
}

/// BSD: the system whose own program it is.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BsdFlavour {
    /// `"macos"`.
    pub system: String,
}

/// Which implementation runs, as the extension detected it; `None` where a flavour is asked for is undetected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// GNU, by its probe.
    Gnu,
    /// BSD, the system's own program.
    Bsd,
    /// An implementation the manifest does not describe.
    Other,
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

/// An interpreted script tool's pin: the script's path (relative to a workspace root) and its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entrypoint {
    /// The script, `argv[1]` of every call this manifest describes.
    pub path: String,
    /// The script's SHA-256, 64 lowercase hex digits.
    pub sha256: String,
}

/// What a program shows about other processes: the only value of a manifest's `reveals`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Reveals {
    /// It lists other processes (`ps`, `top`), so the extension gates it.
    #[serde(rename = "processes")]
    Processes,
}

/// A program manifest as the JSON has it, before the exactly-one rule of `version` and `entrypoint` is checked.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    #[serde(rename = "$schema")]
    #[allow(dead_code)]
    schema: Option<String>,
    program: String,
    version: Option<VersionSpec>,
    entrypoint: Option<Entrypoint>,
    #[serde(rename = "okCodes")]
    ok_codes: Option<Vec<u8>>,
    #[serde(default)]
    echoes: bool,
    #[serde(default)]
    env: Vec<String>,
    reveals: Option<Reveals>,
    credential: Option<ManifestCredential>,
    network: Option<ManifestNetwork>,
    flavours: Option<Flavours>,
    command: CommandSpec,
}

impl TryFrom<RawManifest> for Manifest {
    type Error = String;

    fn try_from(r: RawManifest) -> Result<Self, String> {
        match (&r.version, &r.entrypoint) {
            (Some(_), Some(_)) => {
                return Err(
                    "a manifest has exactly one of `version` and `entrypoint`, and this one has both: a script \
                            is pinned by its entrypoint's sha256, so it has no version"
                        .into(),
                );
            }
            (None, None) => {
                return Err("a manifest has exactly one of `version` and `entrypoint`, and this one has neither".into());
            }
            _ => {}
        }
        Ok(Manifest {
            program: r.program,
            version: r.version,
            entrypoint: r.entrypoint,
            ok_codes: r.ok_codes,
            echoes: r.echoes,
            env: r.env,
            reveals: r.reveals,
            credential: r.credential,
            network: r.network,
            flavours: r.flavours,
            command: r.command,
        })
    }
}

/// A program manifest: the program, its versions (or, for an interpreted script, its entrypoint) and its command tree.
/// Every deserialisation checks that exactly one of `version` and `entrypoint` is present.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(try_from = "RawManifest")]
pub struct Manifest {
    /// The program's name, which `argv[0]`'s basename must equal.
    pub program: String,
    /// The versions the manifest was written against; `None` exactly when `entrypoint` is set.
    pub version: Option<VersionSpec>,
    /// An interpreted script tool's pin (`argv[1]` is the script); `None` exactly when `version` is set.
    pub entrypoint: Option<Entrypoint>,
    /// Exit codes that are answers (`[0]` when absent).
    pub ok_codes: Option<Vec<u8>>,
    /// Prints its inputs back.
    pub echoes: bool,
    /// Environment variables that change what the program does.
    pub env: Vec<String>,
    /// The program shows other processes, so the extension gates it.
    pub reveals: Option<Reveals>,
    /// A credential the host holds and injects, named by provider ([`crate::credential`]).
    pub credential: Option<ManifestCredential>,
    /// What the credentialed profile may connect to.
    pub network: Option<ManifestNetwork>,
    /// The implementations the manifest tells apart; absent, one description for every implementation.
    pub flavours: Option<Flavours>,
    /// The command tree.
    pub command: CommandSpec,
}

/// Which host-held credential a program's calls carry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestCredential {
    /// A provider of [`crate::credential::PROVIDERS`].
    pub provider: String,
}

/// Where a credentialed call may connect: ports and, through its proxy, host names.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestNetwork {
    /// TCP ports, each one of the provider's.
    pub ports: Vec<u16>,
    /// Host names, each one of the provider's; absent (a manifest from before hosts) means all of them.
    #[serde(default)]
    pub hosts: Option<Vec<String>>,
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

/// Which argument a [`Placeholder`] stands for: an argv index, the directory the call acts in when no flag named one
/// (`cwd`), or the repository's root (`repo`). JSON: a number, `"cwd"` or `"repo"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceArg {
    /// The argv index.
    Index(usize),
    /// The current directory.
    Cwd,
    /// The repository root.
    Repo,
}

impl Serialize for PlaceArg {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            PlaceArg::Index(i) => s.serialize_u64(*i as u64),
            PlaceArg::Cwd => s.serialize_str("cwd"),
            PlaceArg::Repo => s.serialize_str("repo"),
        }
    }
}

/// A path the describer names but does not resolve: which argument it is and the text as given (`{"arg": 3, "given":
/// "a"}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Placeholder {
    /// Which argument.
    pub arg: PlaceArg,
    /// The path as the call wrote it (after the separator of an attached value), `"."` for `cwd` and `repo`.
    pub given: String,
}

/// One effect term of a call and what it falls on, before any path is resolved (`{"term": "read", "targets": [...]}`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PreTerm {
    /// The term as a manifest writes it.
    pub term: ProgramEffect,
    /// What it falls on, in the order the keys are built; unused by `runs-code`, `unknown` and `network`.
    pub targets: Vec<Placeholder>,
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
    /// The values of `script` flags, in order.
    scripts: Vec<String>,
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
    describe_call_as(argv, m, version, env_set, None)
}

/// A command as one flavour reads it (window-ml `flavoured`): a manifest without `flavours` as written; undetected
/// (`None`) and `Other` the core with `optionsFirst`; a detected flavour the core's flags and its overlay's, its
/// argument order, and both hardenings.
fn flavoured<'a>(cmd: &'a CommandSpec, m: &Manifest, f: Option<Flavour>) -> Cow<'a, CommandSpec> {
    if m.flavours.is_none() {
        return Cow::Borrowed(cmd);
    }
    let overlay = match f {
        Some(Flavour::Gnu) => cmd.flavour.as_ref().and_then(|o| o.gnu.as_ref()),
        Some(Flavour::Bsd) => cmd.flavour.as_ref().and_then(|o| o.bsd.as_ref()),
        _ => {
            let mut c = cmd.clone();
            c.options_first = true;
            return Cow::Owned(c);
        }
    };
    let Some(o) = overlay else { return Cow::Borrowed(cmd) };
    let mut c = cmd.clone();
    if let Some(flags) = &o.flags {
        for (k, v) in flags.iter() {
            c.flags.0.push((k.to_string(), v.clone()));
        }
    }
    if let Some(order) = o.arg_order {
        c.options_first = false;
        c.stop = order == ArgOrder::Stop;
    }
    if let Some(h) = o.harden.as_ref().filter(|h| !h.is_empty()) {
        c.harden = Some([c.harden.clone().unwrap_or_default(), h.clone()].concat());
    }
    Cow::Owned(c)
}

/// [`describe_call`] as one flavour reads the manifest (`flavour` from the extension's facts; `None`: undetected). A
/// manifest without `flavours` describes the same whatever `flavour` says.
pub fn describe_call_as(
    argv: &[String],
    m: &Manifest,
    version: Option<&str>,
    env_set: &[String],
    flavour: Option<Flavour>,
) -> CallDescription {
    describe_pre(argv, m, version, env_set, flavour).0
}

/// [`describe_call_as`] with the effect terms before any path is resolved: the description (its `effects` are the
/// unresolved ones, every path as given with `:?:?`) and, for each term of the call, what it falls on as
/// [`Placeholder`]s. A caller that resolves paths itself builds its keys from the terms. Empty when the call is not
/// described.
pub fn describe_pre(
    argv: &[String],
    m: &Manifest,
    version: Option<&str>,
    env_set: &[String],
    flavour: Option<Flavour>,
) -> (CallDescription, Vec<PreTerm>) {
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
    // An entrypoint is pinned by its hash, and a "*" range is written for every implementation: neither reads a version.
    if let Some(range) = m.version.as_ref().map(|v| v.range.as_str()).filter(|r| *r != "*") {
        match version {
            None => unknown(&mut d, "the program's version was not reported".into()),
            Some(v) if !in_range(v, range) => unknown(&mut d, format!("version {v} is outside {range}")),
            Some(_) => {}
        }
    }
    for n in env_set {
        if m.env.contains(n) {
            unknown(&mut d, format!("the call sets {n}, which changes what {} does", m.program));
        }
    }

    // An interpreted script: argv[1] is the script itself. Any interpreter flag before it (`-u`, `-X dev`, `--import`,
    // even `--`) changes what runs, so the call is not this manifest's.
    let ep = m.entrypoint.as_ref();
    if let Some(ep) = ep {
        if argv.len() < 2 || argv[1].starts_with('-') {
            let p = &m.program;
            unknown(&mut d, format!("{p} is described only as {p} {}, with no interpreter flag before it", ep.path));
        }
    }
    if m.flavours.is_some() && flavour == Some(Flavour::Other) {
        unknown(&mut d, format!("this {} is an implementation its manifest does not describe", m.program));
    }

    let mut terms: Terms = Vec::new();
    let mut cmd = flavoured(&m.command, m, flavour);
    let mut i = if ep.is_some() { 2 } else { 1 };
    let mut operand_paths: Vec<usize> = Vec::new();
    if let Some(h) = cmd.harden.as_ref().filter(|h| !h.is_empty()) {
        d.harden.push(Harden { at: i - 1, args: h.clone() });
    }
    // Descend through subcommands: options before a subcommand belong to the level above it.
    loop {
        let r = if cmd.syntax == Some(Syntax::Find) {
            parse_find(argv, i, &cmd, &mut d, &mut terms)
        } else {
            parse_options(argv, i, &cmd, &mut d, &mut terms)
        };
        let Some(sub) = r.sub else {
            operand_paths = finish_command(argv, &cmd, &r.operands, r.paths_from, &mut d, &mut terms);
            if let Some(lang) = cmd.script {
                check_script(argv, lang, &r.operands, &r.scripts, flavour == Some(Flavour::Gnu), &mut d);
            }
            break;
        };
        let Some(next) = cmd.subcommands.as_ref().and_then(|s| s.get(&argv[sub])).cloned() else {
            let path = std::iter::once(m.program.as_str()).chain(d.subcommand.iter().map(String::as_str));
            let msg =
                format!("{} has no subcommand {:?} in its manifest", path.collect::<Vec<_>>().join(" "), argv[sub]);
            unknown(&mut d, msg);
            break;
        };
        d.subcommand.push(argv[sub].clone());
        let next = flavoured(&next, m, flavour).into_owned();
        if let Some(h) = next.harden.as_ref().filter(|h| !h.is_empty()) {
            d.harden.push(Harden { at: sub, args: h.clone() });
        }
        cmd = Cow::Owned(next);
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
    // Which operands are written: those the command's own write terms fall on (its effects, or a flag's with no path of
    // its own, `sed -i`); `writtenOperands: "last"` narrows them to the destination.
    let last_only = cmd.written_operands == Some(WrittenOperands::Last);
    let dest = operand_paths.last().copied();
    let writes_operands = terms.iter().any(|(t, g)| matches!(g, Targets::Command) && writes_path(t));
    if writes_operands {
        for p in &mut d.path_args {
            if operand_paths.contains(&p.arg) && (!last_only || Some(p.arg) == dest) {
                p.role = Role::Write;
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
        return (d, Vec::new());
    }
    let given = |i: usize, split: Option<&str>| -> String {
        match split.filter(|s| !s.is_empty()) {
            Some(s) => argv[i].find(s).map_or(argv[i].clone(), |at| argv[i][at + s.len()..].to_string()),
            None => argv[i].clone(),
        }
    };
    let repo_wide = cmd.repo_wide;
    let dir_place = || match d.dir_arg {
        Some(a) => Placeholder { arg: PlaceArg::Index(a), given: argv[a].clone() },
        None => Placeholder { arg: PlaceArg::Cwd, given: ".".into() },
    };
    let mut around: Vec<Placeholder> = Vec::new();
    if d.acts_on_dir {
        around.push(dir_place());
    }
    if repo_wide {
        around.push(dir_place());
        around.push(Placeholder { arg: PlaceArg::Repo, given: ".".into() });
    }
    let operand_res = |keep: &dyn Fn(usize) -> bool| -> Vec<Placeholder> {
        operand_paths
            .iter()
            .filter(|i| keep(**i))
            .map(|i| Placeholder { arg: PlaceArg::Index(*i), given: argv[*i].clone() })
            .collect()
    };
    let with_around = |mut v: Vec<Placeholder>| -> Vec<Placeholder> {
        v.extend(around.iter().cloned());
        v
    };
    let command_targets = with_around(operand_res(&|_| true));
    // With `writtenOperands: "last"` a write falls on the destination and a read on the sources; any other term on all.
    let targets_of = |term: &ProgramEffect| -> Vec<Placeholder> {
        if !last_only {
            command_targets.clone()
        } else if writes_path(term) {
            with_around(operand_res(&|i| Some(i) == dest))
        } else if *term == ProgramEffect::Read {
            with_around(operand_res(&|i| Some(i) != dest))
        } else {
            command_targets.clone()
        }
    };
    let pre: Vec<PreTerm> = terms
        .iter()
        .map(|(term, targets)| PreTerm {
            term: term.clone(),
            targets: match targets {
                Targets::Command => targets_of(term),
                Targets::Arg(i, split) => {
                    vec![Placeholder { arg: PlaceArg::Index(*i), given: given(*i, split.as_deref()) }]
                }
            },
        })
        .collect();
    d.effects = unresolved_effects(&pre);
    (d, pre)
}

/// The effect keys of a call whose paths stay as given (`:?:?`): window-ml's `unresolved` resolver. Any `unknown` term
/// makes the whole `Unknown`.
fn unresolved_effects(pre: &[PreTerm]) -> Effects {
    let mut keys: Vec<String> = Vec::new();
    for PreTerm { term, targets } in pre {
        match term {
            ProgramEffect::Unknown => return Effects::Unknown,
            ProgramEffect::RunsCode => keys.push("exec:process".into()),
            ProgramEffect::Read | ProgramEffect::Write => {
                let op = if *term == ProgramEffect::Read { "read" } else { "write" };
                keys.extend(targets.iter().map(|p| format!("{op}:fs:{}:?:?", p.given)));
            }
            ProgramEffect::WriteNames => keys.extend(targets.iter().map(|p| format!("write-names:fs:{}:?:?", p.given))),
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
    Effects::Keys(keys)
}

/// Whether a term writes a path: bytes in place, or its entry.
fn writes_path(t: &ProgramEffect) -> bool {
    matches!(t, ProgramEffect::Write | ProgramEffect::WriteNames)
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

/// A `script` command's program (`script` flags' values joined by newlines, else its first operand) checked by its
/// language's narrow grammar; one outside it makes the call unknown.
fn check_script(
    argv: &[String],
    lang: ScriptLang,
    operands: &[usize],
    scripts: &[String],
    gnu: bool,
    d: &mut CallDescription,
) {
    let name = if lang == ScriptLang::Sed { "sed" } else { "awk" };
    let text = if !scripts.is_empty() { Some(scripts.join("\n")) } else { operands.first().map(|i| argv[*i].clone()) };
    let Some(text) = text else {
        unknown(d, format!("{name} was given no program"));
        return;
    };
    let why = if lang == ScriptLang::Sed { sed_script_refusal(&text, gnu) } else { awk_program_refusal(&text) };
    if let Some(why) = why {
        unknown(d, why);
    }
}

/// The flags parsed so far: the path start a flag set and the values of `script` flags.
struct Seen {
    paths_from: Option<usize>,
    scripts: Vec<String>,
}

/// Applies a flag to the call: its effects, its path or directory value, and its flags on the call as a whole. `text`
/// is the flag's value as given, when it has one.
fn apply(
    d: &mut CallDescription,
    terms: &mut Terms,
    seen: &mut Seen,
    name: &str,
    f: &FlagSpec,
    value_at: Option<ValueAt>,
    text: Option<&str>,
) {
    if let Some(values) = &f.values {
        if !text.is_some_and(|t| values.iter().any(|v| v == t)) {
            unknown(d, format!("{name} {:?} is not a value its manifest describes", text.unwrap_or("")));
        }
    }
    if let (true, Some(t)) = (f.script, text) {
        seen.scripts.push(t.to_string());
    }
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
        seen.paths_from = Some(p);
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

/// Whether a flag only reads (window-ml `readOnlyFlag`): its effects are `read` or none, its value is no written path or
/// directory, and it starts, echoes and walks nothing.
fn read_only_flag(f: &FlagSpec) -> bool {
    f.effects.iter().all(|e| *e == ProgramEffect::Read)
        && f.value_is_path != Some(Role::Write)
        && !f.value_is_dir
        && !f.runner
        && !f.echoes
        && !f.recursive
        && f.paths_from.is_none()
}

/// Under `argOrder: "stop"`, the declared flag a post-operand argument spells whose meaning is more than a read (window-ml
/// `stopShadow`): `--name`, `--name=v`, the whole `-name`, or any letter of a `-abc` cluster. Read as a file name it
/// would drop the write the manifest declares, so the call is unknown; both describers agree on `tool f.txt --write-all`.
fn stop_shadow(a: &str, flags: &OrderedMap<FlagSpec>) -> Option<String> {
    if a == "-" || !a.starts_with('-') {
        return None;
    }
    let names: Vec<String> = if a.starts_with("--") {
        vec![a.split('=').next().unwrap_or(a).to_string()]
    } else {
        std::iter::once(a.to_string()).chain(a[1..].chars().map(|c| format!("-{c}"))).collect()
    };
    names.into_iter().find(|n| flags.get(n).is_some_and(|f| !read_only_flag(f)))
}

/// Options-then-operands. Returns the operand indices, the path start a flag set, the values of `script` flags, and the
/// index of a subcommand name when the command has subcommands and one was reached before any operand.
fn parse_options(
    argv: &[String],
    start: usize,
    cmd: &CommandSpec,
    d: &mut CallDescription,
    terms: &mut Terms,
) -> Parsed {
    let mut operands: Vec<usize> = Vec::new();
    let mut seen = Seen { paths_from: None, scripts: Vec::new() };
    let mut after_terminator = false;
    let mut i = start;
    while i < argv.len() {
        let a = argv[i].as_str();
        // A flavour that stops at the first operand (BSD getopt) reads everything after it as an operand, `--` included.
        if after_terminator || (cmd.stop && !operands.is_empty()) {
            if !after_terminator {
                if let Some(shadow) = stop_shadow(a, &cmd.flags) {
                    unknown(
                        d,
                        format!(
                            "{a} follows an operand: this flavour reads it as a file name, but {shadow} is a flag that does more than read"
                        ),
                    );
                }
            }
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
                return Parsed { operands, paths_from: seen.paths_from, sub: Some(i), scripts: seen.scripts };
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
            let after_eq = eq.map(|e| &a[e + 1..]);
            if f.value {
                if eq.is_some() {
                    let at = ValueAt { arg: i, split: Some("="), attached: false };
                    apply(d, terms, &mut seen, name, f, Some(at), after_eq);
                } else if i + 1 < argv.len() {
                    let at = ValueAt { arg: i + 1, split: None, attached: false };
                    apply(d, terms, &mut seen, name, f, Some(at), Some(&argv[i + 1]));
                    i += 1;
                } else {
                    unknown(d, format!("{name} needs a value"));
                }
            } else if eq.is_some() {
                if f.optional_value {
                    apply(d, terms, &mut seen, name, f, None, after_eq);
                } else {
                    unknown(d, format!("{name} takes no value"));
                }
            } else {
                apply(d, terms, &mut seen, name, f, None, None);
            }
            i += 1;
            continue;
        }
        // A single-dash flag: a whole name first (`-C`, `-name`), then a cluster of one-letter flags.
        if let Some(whole) = cmd.flags.get(a) {
            if whole.attached_value {
                apply(d, terms, &mut seen, a, whole, None, Some(""));
            } else if whole.value {
                if i + 1 < argv.len() {
                    let at = ValueAt { arg: i + 1, split: None, attached: false };
                    apply(d, terms, &mut seen, a, whole, Some(at), Some(&argv[i + 1]));
                    i += 1;
                } else {
                    unknown(d, format!("{a} needs a value"));
                }
            } else {
                apply(d, terms, &mut seen, a, whole, None, None);
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
            let rest: String = letters[j + 1..].iter().collect();
            if f.attached_value {
                apply(d, terms, &mut seen, &name, f, None, Some(&rest));
                break;
            }
            if f.value {
                if j + 1 < letters.len() {
                    let at = ValueAt { arg: i, split: None, attached: true };
                    apply(d, terms, &mut seen, &name, f, Some(at), Some(&rest));
                } else if i + 1 < argv.len() {
                    let at = ValueAt { arg: i + 1, split: None, attached: false };
                    apply(d, terms, &mut seen, &name, f, Some(at), Some(&argv[i + 1]));
                    i += 1;
                } else {
                    unknown(d, format!("{name} needs a value"));
                }
                break;
            }
            apply(d, terms, &mut seen, &name, f, None, None);
        }
        i += 1;
    }
    Parsed { operands, paths_from: seen.paths_from, sub: None, scripts: seen.scripts }
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
    Parsed { operands, paths_from: None, sub: None, scripts: Vec::new() }
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
    // awk reads an operand `name=value` as an assignment, never a file.
    if cmd.script == Some(ScriptLang::Awk) {
        paths.retain(|i| !is_awk_assignment(&argv[*i]));
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

// --- which operands a writing command writes ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A one-command manifest over operand paths, with the given effects and extra command fields.
    fn manifest(effects: serde_json::Value, extra: serde_json::Value) -> Result<Manifest, serde_json::Error> {
        let mut command = json!({ "effects": effects, "paths": "operands", "flags": {} });
        for (k, v) in extra.as_object().unwrap() {
            command[k] = v.clone();
        }
        serde_json::from_value(json!({
            "program": "cp", "version": { "range": "*", "args": [], "pattern": "" }, "command": command
        }))
    }

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn roles(d: &CallDescription) -> Vec<(usize, Role)> {
        d.path_args.iter().map(|p| (p.arg, p.role)).collect()
    }

    #[test]
    fn written_operands_last_writes_the_destination_and_reads_the_sources() {
        let m = manifest(json!(["read", "write"]), json!({ "writtenOperands": "last" })).unwrap();
        let d = describe_call(&argv(&["cp", "a", "b", "dir"]), &m, None, &[]);
        assert_eq!(roles(&d), [(1, Role::Read), (2, Role::Read), (3, Role::Write)]);
        assert_eq!(d.effects.to_json(), json!(["read:fs:a:?:?", "read:fs:b:?:?", "write:fs:dir:?:?"]));
    }

    #[test]
    fn a_writing_command_without_the_field_writes_every_operand() {
        let m = manifest(json!(["read", "write"]), json!({})).unwrap();
        let d = describe_call(&argv(&["cp", "a", "b"]), &m, None, &[]);
        assert_eq!(roles(&d), [(1, Role::Write), (2, Role::Write)]);
        let ro = manifest(json!(["read"]), json!({})).unwrap();
        let d = describe_call(&argv(&["cp", "a", "b"]), &ro, None, &[]);
        assert_eq!(roles(&d), [(1, Role::Read), (2, Role::Read)]);
    }

    #[test]
    fn a_written_operands_value_other_than_last_fails_to_parse() {
        for v in [json!("first"), json!("Last"), json!(true), json!(["last"])] {
            assert!(manifest(json!(["write"]), json!({ "writtenOperands": v.clone() })).is_err(), "{v}");
        }
    }

    // --- entrypoint, reveals, $schema ---

    fn raw(extra: serde_json::Value) -> Result<Manifest, serde_json::Error> {
        let mut m = json!({
            "program": "python3",
            "command": { "effects": ["read"], "paths": "operands", "flags": { "-v": {} } }
        });
        for (k, v) in extra.as_object().unwrap() {
            m[k] = v.clone();
        }
        serde_json::from_value(m)
    }

    fn entry() -> serde_json::Value {
        json!({ "entrypoint": { "path": "tools/t.py", "sha256": "0".repeat(64) } })
    }

    #[test]
    fn an_entrypoint_manifest_is_described_and_refused_when_a_flag_precedes_the_script() {
        let m = raw(entry()).unwrap();
        assert!(m.version.is_none());
        let d = describe_call(&argv(&["python3", "tools/t.py", "a", "b"]), &m, None, &[]);
        assert!(d.described, "{:?}", d.why);
        assert_eq!(d.effects.to_json(), json!(["read:fs:a:?:?", "read:fs:b:?:?"]));
        let why = "python3 is described only as python3 tools/t.py, with no interpreter flag before it";
        for a in [&["python3"][..], &["python3", "-u", "t.py"], &["python3", "--", "t.py"]] {
            let d = describe_call(&argv(a), &m, None, &[]);
            assert!(!d.described);
            assert_eq!(d.why, [why], "{a:?}");
        }
        // the script's own flags are the command's flags, parsed from index 2
        let d = describe_call(&argv(&["python3", "t.py", "-v", "a"]), &m, None, &[]);
        assert!(d.described, "{:?}", d.why);
        assert_eq!(d.effects.to_json(), json!(["read:fs:a:?:?"]));
    }

    #[test]
    fn an_entrypoint_manifests_harden_goes_after_the_script() {
        let mut m = raw(entry()).unwrap();
        m.command.harden = Some(vec!["--safe".into()]);
        let a = argv(&["python3", "t.py", "a"]);
        let d = describe_call(&a, &m, None, &[]);
        assert_eq!(d.harden, [Harden { at: 1, args: vec!["--safe".into()] }]);
        assert_eq!(harden_argv(&a, &d), argv(&["python3", "t.py", "--safe", "a"]));
    }

    #[test]
    fn exactly_one_of_version_and_entrypoint() {
        let v = json!({ "version": { "range": "*", "args": [], "pattern": "" } });
        assert!(raw(v.clone()).is_ok());
        let mut both = entry();
        both["version"] = v["version"].clone();
        let e = raw(both).unwrap_err().to_string();
        assert!(e.contains("exactly one of `version` and `entrypoint`") && e.contains("has both"), "{e}");
        let e = raw(json!({})).unwrap_err().to_string();
        assert!(e.contains("exactly one of `version` and `entrypoint`") && e.contains("has neither"), "{e}");
        let e =
            serde_json::from_str::<Manifest>(r#"{"program":"x","command":{"effects":[],"paths":"none","flags":{}}}"#);
        assert!(e.is_err());
        let mut extra = entry();
        extra["entrypoint"]["extra"] = json!(1);
        assert!(raw(extra).is_err());
    }

    #[test]
    fn reveals_and_schema_parse() {
        let mut j = entry();
        j["$schema"] = json!("https://example.test/x.json");
        j["reveals"] = json!("processes");
        assert_eq!(raw(j).unwrap().reveals, Some(Reveals::Processes));
        let mut bad = entry();
        bad["reveals"] = json!("files");
        assert!(raw(bad).is_err());
        let mut bad = entry();
        bad["$schema"] = json!(3);
        assert!(raw(bad).is_err());
    }

    // --- describe_pre ---

    fn pre_json(m: &Manifest, a: &[&str]) -> serde_json::Value {
        serde_json::to_value(describe_pre(&argv(a), m, None, &[], None).1).unwrap()
    }

    #[test]
    fn pre_of_a_written_operands_last_command_splits_sources_and_destination() {
        let m = manifest(json!(["read", "write"]), json!({ "writtenOperands": "last" })).unwrap();
        assert_eq!(
            pre_json(&m, &["cp", "a", "b", "dir"]),
            json!([
                { "term": "read", "targets": [{ "arg": 1, "given": "a" }, { "arg": 2, "given": "b" }] },
                { "term": "write", "targets": [{ "arg": 3, "given": "dir" }] },
            ])
        );
    }

    fn with_flags(command: serde_json::Value) -> Manifest {
        serde_json::from_value(json!({
            "program": "tool", "version": { "range": "*", "args": [], "pattern": "" }, "command": command
        }))
        .unwrap()
    }

    #[test]
    fn pre_of_an_attached_path_value_is_the_text_after_the_separator() {
        let m = with_flags(json!({ "effects": ["read"], "paths": "operands", "flags": {
            "--out": { "value": true, "valueIsPath": "write" } } }));
        assert_eq!(
            pre_json(&m, &["tool", "--out=o.txt", "in"]),
            json!([
                { "term": "write", "targets": [{ "arg": 1, "given": "o.txt" }] },
                { "term": "read", "targets": [{ "arg": 2, "given": "in" }] },
            ])
        );
        // a separate value has no separator to split on
        assert_eq!(pre_json(&m, &["tool", "--out", "o.txt"])[0]["targets"], json!([{ "arg": 2, "given": "o.txt" }]));
    }

    #[test]
    fn pre_of_a_dir_flag_and_a_repo_wide_command_names_the_directory_and_the_repo() {
        let flags = json!({ "-C": { "value": true, "valueIsDir": true } });
        // acts on the repository: the directory (twice, once as acts-on-dir and once as repo-wide), then the repo
        let m = with_flags(json!({ "effects": ["write"], "paths": "repo", "repoWide": true, "flags": flags }));
        assert_eq!(
            pre_json(&m, &["tool"]),
            json!([{ "term": "write", "targets": [
                { "arg": "cwd", "given": "." }, { "arg": "cwd", "given": "." }, { "arg": "repo", "given": "." },
            ] }])
        );
        assert_eq!(
            pre_json(&m, &["tool", "-C", "sub"])[0]["targets"],
            json!([
                { "arg": 2, "given": "sub" }, { "arg": 2, "given": "sub" }, { "arg": "repo", "given": "." },
            ])
        );
        // operands come first, then what is around them
        let m = with_flags(json!({ "effects": ["write"], "paths": "operands", "repoWide": true, "flags": {} }));
        assert_eq!(
            pre_json(&m, &["tool", "f"])[0]["targets"],
            json!([{ "arg": 1, "given": "f" }, { "arg": "cwd", "given": "." }, { "arg": "repo", "given": "." }])
        );
    }

    #[test]
    fn pre_keeps_network_terms_and_is_empty_when_not_described() {
        let m =
            with_flags(json!({ "effects": [{ "network": {} }, { "network": { "direction": "read" } }, "runs-code"],
            "paths": "none", "flags": {} }));
        assert_eq!(
            pre_json(&m, &["tool"]),
            json!([
                { "term": { "network": {} }, "targets": [] },
                { "term": { "network": { "direction": "read" } }, "targets": [] },
                { "term": "runs-code", "targets": [] },
            ])
        );
        // an `unknown` term (a command's or a flag's) makes the call undescribed, so no term list reaches a caller
        let u = with_flags(json!({ "effects": ["read", "unknown"], "paths": "operands", "flags": {} }));
        let (d, pre) = describe_pre(&argv(&["tool", "a"]), &u, None, &[], None);
        assert!(!d.described && pre.is_empty());
        assert_eq!(d.effects, Effects::Unknown);
        let (d, pre) = describe_pre(&argv(&["other"]), &m, None, &[], None);
        assert!(!d.described && pre.is_empty());
    }

    #[test]
    fn program_effects_serialise_as_a_manifest_writes_them() {
        for t in ProgramEffect::ALL {
            let j = serde_json::to_value(&t).unwrap();
            assert_eq!(serde_json::from_value::<ProgramEffect>(j).unwrap(), t);
        }
        assert_eq!(serde_json::to_value(ProgramEffect::WriteNames).unwrap(), json!("write-names"));
        assert_eq!(serde_json::to_value(ProgramEffect::RunsCode).unwrap(), json!("runs-code"));
        assert_eq!(
            serde_json::to_value(ProgramEffect::Network(Network { direction: None })).unwrap(),
            json!({ "network": {} })
        );
        assert_eq!(
            serde_json::to_value(Placeholder { arg: PlaceArg::Repo, given: ".".into() }).unwrap(),
            json!({ "arg": "repo", "given": "." })
        );
    }
}
