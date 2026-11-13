# The host's protocol with the extension (v1)

What the extension's service worker and `wmlhost` say to each other over native messaging. The design behind it, and why
the host resolves facts but never decides, is window-ml's
[`SHELL.md`](https://github.com/parawanderer/window-ml/blob/main/docs/spec/SHELL.md); this file is the wire as built.

## Framing

Chrome's native messaging: every message, in either direction, is a 4-byte length in NATIVE byte order followed by that
many bytes of UTF-8 JSON, one object per message.

| Limit | Value | Why |
| --- | --- | --- |
| host → extension | 1 MiB per message (`MAX_OUT`) | Chrome's limit. Nothing the host sends can grow past it: output crosses only through `read`, whose `length` is capped |
| extension → host | 64 MiB per message (`MAX_IN`) | Chrome's limit. A longer length prefix is a protocol error and the host exits |

End of input (Chrome closed the port, or the browser exited) ends the session: every running process group is killed
and the held output is deleted.

## Calls and answers

The shapes follow window-ml's [`ML_WIRE.md`](https://github.com/parawanderer/window-ml/blob/main/docs/spec/ML_WIRE.md):
the extension sends a call with a sequence number, and the host answers that number once, with a value or an error.

```jsonc
{ "seq": 7, "call": "spawn", "args": { … } }                        // extension → host
{ "seq": 7, "value": { … } }                                        // host → extension
{ "seq": 7, "error": { "code": "CwdOutsideRoots", "message": "…" } }
{ "event": "done", "id": "c3", … }                                  // unsolicited, no seq
```

`seq` is any integer the extension chooses (a double-safe one: below 2^53); the host only echoes it. Calls may overlap:
the host answers each as it finishes, not in order. A message that is not an object with a numeric `seq` and a string
`call` is answered with `BadRequest` and `seq: null`.

### `hello`

`args: {}` → the host's identity and what it can do. Safe to call any time.

```jsonc
{ "host": "window-ml-host", "version": "0.9.0", "protocol": 1, "platform": "macos",
  "sandbox": { "kind": "seatbelt", "available": true, "landlockAbi": null },  // kind: "seatbelt" | "bwrap" | null; "reason" when unavailable; landlockAbi: number | null (Linux only)
  "modes": ["host"],                                                // "container" appears once a runner exists
  "peek": true,                                                     // this host answers `peek`; an older host has no such field
  "tilde": true,                                                    // this host expands a leading `~` in argv and cwd (see `spawn`); an older host has no such field
  "credentials": ["github"],                                        // the credential providers a `spawn` may name (see "A credentialed call"); [] where the sandbox cannot hold the profile (Linux without Landlock) and over the hub; an older host has no such field
  "put": { "max": 67108864 },                                       // this host answers `put`, `write` and `commit`; `max` is the most bytes one put may declare; `null` over the hub, where the three are refused; an older host has no such field
  "mounts": true,                                                   // this host answers the mount calls (see "Mounts"); false over the hub, where they are refused; an older host has no such field, and the worker never probes by calling
  "owners": { "ledger": true, "register": true },                   // ledger false: the table is in memory only; register false over the hub (see "Owners")
  "memory": { "metric": "phys_footprint", "enforcer": "watchdog", "everyMs": 100 },
  "cpu": { "metric": "user+system, with reaped children" } }        // what `cpuMs` counts: measured, never bounded
```

Over the hub (`docs/HUB.md`) `hello` adds `"transport": "hub"` and `"hub": { "roots": [...], "callers": 2, "revocationsAgeMs": 3600000, "events": true }`:
the roots the person at the machine granted (`hub-roots`), within which a `configure` may narrow, how many principals
may call, how old the account's revocation list is (`null` while there is none to go stale), and whether this caller
is given its session events (`done`), which over the hub are published on a stream of its own rather than written.

`memory.metric` names what a memory bound is measured on: `phys_footprint` on macOS (what Activity Monitor and Jetsam
use), `rss_anon+rss_shmem+swap` on Linux. Never the address space.

`sandbox.landlockAbi` is the Landlock ABI the host can fully enforce a ruleset at (Linux). `null` means the restriction
is unavailable (no Landlock, or only a best-effort one): a `start`/`pipe` asking for an envelope narrower than the
bwrap floor fails `SandboxFailed` rather than running unrestricted. On macOS it is always `null` (Seatbelt holds every
envelope in-profile).

### `configure`

The session's settings, from the person's DevTools Settings. A spawn before the first `configure` fails `NotConfigured`.

```jsonc
args: { "roots": ["/Users/me/src/proj"],     // workspace roots: absolute, existing directories, never "/"
        "sandbox": true,                     // default true; false = plain host mode, by the person's choice
        "path": ["/opt/homebrew/bin", "/usr/bin", "/bin"],   // optional: PATH for lookup and for the child
        "timeoutMs": 120000,                 // optional default per call, at most 3600000
        "outputCap": 67108864,               // optional bytes kept per stream, at most 1 GiB
        "memoryBound": 4294967296,           // optional default bound per call, bytes of physical footprint (default 4 GiB)
        "memoryMax": 17179869184,            // optional ceiling a call's memoryBound is clamped to (default 16 GiB)
        "onOwnerLoss": "kill",               // optional default: "kill" | "orphan" (see "Owners")
        "orphanTimeoutMs": 600000 }          // optional: how long an orphan lives, at most 86400000 (default 10 min)
value: { "roots": [{ "given": "…", "path": "<realpath>" }], "sandboxed": true,
         "memoryBound": 4294967296, "memoryMax": 17179869184, "onOwnerLoss": { "policy": "kill" } }
```

Every bound is clamped to at least 16 MiB.

Over the hub, a `configure` may only narrow what the person at the machine granted: a root not within one of `hub-roots`
is `BadRequest` naming it, no `hub-roots` (or an empty one) is `NotConfigured`, `sandbox: false` is `BadRequest`, and a
machine with no working sandbox answers `SandboxFailed`. A refused `configure` changes nothing.

`sandboxed` in the answer is whether calls will run under the OS sandbox: `sandbox` asked for it AND it is available.
Reconfiguring drops every pending spawn, put and store (their facts were judged against the old roots); running processes continue. It also drops every mount whose path is not inside the new roots; the others stay ("Mounts").

### `spawn`: resolve the facts, start nothing

```jsonc
args: { "argv": ["git", "diff", "--stat", "HEAD~1"],
        "cwd": "/Users/me/src/proj",          // absolute; must resolve inside a root
        "env": { "LC_ALL": "C" },             // ADDED to the scrubbed base; a value may be { "$secret": "<name>" }
        "mode": "host",                       // "host" | "container"
        "pathArgs": [{ "arg": 3 }],           // which argv slots are paths (from the program manifest); see below
        "walkCwd": false,                     // the call walks its cwd (a recursive reader given no path): report containsSecret
        "repoArg": 2,                         // optional: the argv slot naming the repository (`git -C dir`); else the cwd's
        "timeoutMs": 30000,                   // optional, at most 3600000
        "owner": { "session": "…", "run": "…", "step": 3 },   // optional: who the call is for, opaque, at most 1 KiB of JSON
        "memoryBound": 536870912,             // optional: this call's bound, clamped to [16 MiB, memoryMax]
        "onOwnerLoss": "orphan", "orphanTimeoutMs": 60000,    // optional: this call's owner-loss policy
        "credential": { "provider": "github", "manifest": "<sha256 hex>" } }   // optional: see "A credentialed call"
```

The answer is the RESOLVED FACTS, everything a policy is given about the call (`SHELL.md`, "What it is given"):

```jsonc
{ "id": "c3",                                   // names this pending call for start / discard
  "argv": ["git", "diff", "--stat", "HEAD~1"],  // after tilde expansion
  "tilde": [],                                  // always present; one entry per `~` argument, see below
  "program": { "path": "/usr/bin/git", "inRoot": false,     // argv[0] after PATH lookup, realpath'd
               "fingerprint": "16777234:1152921500312187:134512:1760000000123456789" },
  "cwd": { "path": "/Users/me/src/proj", "inRoot": true },  // + "containsSecret" with walkCwd
  "env": { "set": ["LC_ALL"], "secrets": [], "free": true }, // names only; free: every name is on the FREE list
  "repo": { "root": "/Users/me/src/proj", "reasons": [] },  // null outside a git repository
  "repoConfigRunsCode": false,                  // the repository's own config makes git run a program; false with no repository
  "paths": [{ "arg": 3, "given": "HEAD~1", "path": "/Users/me/src/proj/HEAD~1",
              "inRoot": true, "secret": false, "exists": false }],
  "credential": null,                           // { provider, ports, profile } when the spawn asked for one and it is honoured
  "effects": "unknown",                         // from the program manifest once one exists (root F); "unknown" until then
  "mode": "host",
  "sandboxed": true,
  "placement": "host-sandbox",                  // "host-sandbox" | "host-plain": the enforcer whose bound applies (EFFECTS.md)
  "memoryBound": 536870912,                     // the bound the call will run under, after clamping
  "onOwnerLoss": { "policy": "orphan", "timeoutMs": 60000 },
  "owner": { "session": "…", "run": "…", "step": 3 },        // as given; null when none was
  "expiresInMs": 1800000 }                      // after this the id is gone and start fails UnknownId
```

- **`tilde`** lists each argument that began with `~`, in argv order and then `cwd`: `{ "index": 1, "from": "~/notes.txt",
  "to": "/Users/me/notes.txt" }`. `index` is `number | "cwd" | "path"`: the argv position, the string `"cwd"` for the `cwd` argument, or, in `put`'s facts, `"path"` for its `path`.
  The host rewrites argv and `cwd` before it resolves anything, so `argv`, `paths[].given`, the facts' paths and the
  program that runs all carry the expanded string, and `from` is where the original lives. An argument expands only when
  it is exactly `~` or starts with `~/`, in `argv[0]`, every later argument and `cwd` alike: `~user`, `a~/b`, `x=~/a` and
  `--flag=~/x` stay literal and leave no entry, and nothing else expands (no glob, no `$VAR`). `~` is the host process's
  own `HOME`, read once at start. When `HOME` is unset, empty or not absolute, the argument stays literal and its entry has
  `"to": null` and `"reason"`: `"no-home"` (unset or empty) or `"home-not-absolute"`. `cwd` is expanded before the checks
  on it, so `~/proj` outside every root is `CwdOutsideRoots`, and a `~` cwd with no usable `HOME` is `BadRequest`.
- **`program.fingerprint`** is `<dev>:<ino>:<size>:<mtime_ns>` of the program file (`null` if its metadata cannot be
  read). Any rewrite of the binary changes it, so the extension can cache what it learned about a program (its version)
  per fingerprint.
- **`pathArgs`** entries are `{ "arg": i }` (the whole argument is a path) or `{ "arg": i, "split": "=" }` (the part
  after the first `=`, for `--output=f`). The host resolves only the arguments it is told are paths: an argument nobody
  marked is not a path the host can vouch for, and the worker treats the call accordingly. Root F moves this list into
  the program manifests, which the host will also read.
- **A path is resolved with `realpath` against `cwd`.** One that does not exist yet is its deepest existing ancestor's
  realpath plus the rest, and is never `inRoot` if the rest contains `..`. A symlink is followed, so one pointing out of
  a root is `inRoot: false`. When the last component is itself a symlink (a trailing `/` included), the fact adds `link`, the
  link's own path (its parent's realpath plus its name), and `inRoot` and `secret` hold for the link too: `rm top`
  removes the link `top`, wherever its target is (window-ml #990's review, 2026-10-22).
- **`walk: true`** on a `pathArgs` entry (a recursive reader: `rg`, `find`, `ls -R`) adds `containsSecret`: `true` if
  anything beneath the path looks like a secret, `false` if nothing does, `null` past 20 000 entries or an unreadable
  directory. The walk never follows a symlink (a link is judged by its name) and skips `.git` directories.
- **`hash: true`** on a `pathArgs` entry (an interpreted script's entrypoint: `node scripts/index.mjs`, PROGRAM_MANIFEST.md
  "Interpreted script tools") adds `sha256`: the hex sha256 of the resolved file, after symlinks, so `given` and `path`
  name both. `null` for anything but a regular file, or one over 16 MiB. The host compares it with nothing: whether it
  matches a manifest's pin is the worker's decision. `start` hashes the file again (below).
- **`repoConfigRunsCode`** comes from the host's own read of the repository-level config (`.git/config`, a worktree's
  common config and `config.worktree`, and the `include`/`includeIf` files they pull in from inside the repository):
  true for `core.fsmonitor`, `core.pager` other than `cat`, `core.hooksPath`, `core.sshCommand`, `core.askPass`,
  `core.gitProxy`, `diff.external`, `diff.*.textconv`, `diff.*.command`, any `filter.*`, `credential.helper`, an
  `alias.*` starting with `!`, `gpg.program`, `remote.*.uploadpack`/`receivepack`, and any include from outside the
  repository; `reasons` lists each. A `.git` the host cannot stat, a worktree's `commondir` it cannot read or resolve,
  or a config or include it cannot read, is `true` with the reason. With no repository around `cwd` (or `repoArg`) it is `false` and `repo` is `null`: there is no
  repository config to run. The person's global config is not read.
- **`env.free`**: every variable the call sets is one of `LANG`, `LC_*`, `TZ`, `NO_COLOR`, `COLUMNS`, or `TERM=dumb`.
- **`secret`** is the host's name check (`.env`, `*.pem`, `id_*`, `.ssh/`, …; the list is `SECRET_PATTERNS` in
  `src/facts.rs`) on the resolved path and on the path as given.
- **Refused at spawn, whatever a policy would say** (these are enforcement, not decisions): `cwd` outside every root
  (`CwdOutsideRoots`); an `env` name on the denylist (`EnvRefused`); a secret handle the host's store does not hold
  (`SecretUnavailable`, always this round: the store is empty); `argv[0]` not found (`ProgramNotFound`); `mode:
  "container"` (`Unsupported`, until a runner exists); a `credential` the host does not honour (`CredentialRefused`)
  or cannot hold (`SandboxFailed`), below.

#### A credentialed call

`credential: { "provider": "github", "manifest": "<sha256>" }` asks the host to inject a credential it holds
(`src/credential.rs`): the call then runs under the credentialed profile of the sandbox. The host honours it only when
ALL hold, and otherwise refuses the spawn; it never runs the call under the ordinary profile instead, which for gh is the
one that answers anonymously without saying so:

- `provider` is in the host's table (`hello.credentials`; v1 has `github`), else `CredentialRefused`.
- `manifest` is the lowercase hex sha256 of the program manifest's BYTES the worker described the call with, and those
  bytes are one this host pinned (`vectors/program-manifests/`, window-ml's shipped manifest), which names this
  provider in `credential.provider`, a subset of the provider's ports in `network.ports` and, when present, a non-empty
  subset of the provider's host names in `network.hosts`, else `CredentialRefused`. A pinned manifest with no
  `network.hosts` (one from before hosts) gets every provider host. A release pins the current shipped manifest and the
  one before it (`pinned/`), so an extension one release behind is still honoured.
  A manifest the worker holds that the host does not (a stored one, or a newer shipped one than this host's copy) names
  no credential here.
- The provider is its program's alone, and the program is the person's: `argv[0]` is exactly the provider's program
  (`gh`, found on `PATH`, never a path), the manifest's `program` and the resolved binary's name are too, and the
  resolved binary is outside every root, else `CredentialRefused`. The token fetch runs that binary unconfined, so a
  `gh` a repository could have planted is never it.
- The session is sandboxed with a sandbox that can hold the profile: macOS's Seatbelt, or bubblewrap with Landlock. A session with
  `sandbox: false`, Linux without Landlock and a machine with no sandbox answer `SandboxFailed`.
- Not over the hub (`CredentialRefused`): only a connection on this machine may send the person's token.

The facts then carry `"credential": { "provider": "github", "ports": [443], "hosts": [<names>], "profile":
"credentialed:github" }`.
At `start`, after the verdict and before the program runs, the host obtains the token by running the call's own
resolved binary unconfined with the provider's arguments (`gh auth token --hostname github.com`), in an environment of
the host's `HOME`, `USER`, `LOGNAME`, the call's `PATH` and the person's own `GH_CONFIG_DIR`, `XDG_CONFIG_HOME`,
`GH_TOKEN` and `GITHUB_TOKEN` when set, nothing the call set; stdout is the token, stderr is discarded, neither is
logged, and 30 s is the limit. No token (not logged in, a non-zero exit, empty or malformed output) fails the `start`
with `SecretUnavailable` and the program never runs. The child gets `GH_TOKEN`, `GH_CONFIG_DIR` set to an empty
directory under its `$TMPDIR` (none of the person's gh config is read), `GH_PROMPT_DISABLED=1`,
`GH_NO_UPDATE_NOTIFIER=1` and `GH_TELEMETRY=0`, and the call's proxy in `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`,
`http_proxy`, `ALL_PROXY` and `all_proxy` (`http://127.0.0.1:<port>`), with `NO_PROXY` and `no_proxy` empty. The token
never crosses the protocol.

The host starts a CONNECT proxy for the call on `127.0.0.1:<ephemeral>` (`src/proxy.rs`) and closes it before `done`.
On Linux the call has no network of its own (`--unshare-net`): the proxy listens on a unix socket bound into the
sandbox, and `wmlhost exec-under` starts `wmlhost forward`, which carries the call's `127.0.0.1:18443` to it; the
proxy env names that port. A Linux host without Landlock offers no credential.
It admits only a request line `CONNECT <name>:<port> HTTP/1.1` (or `1.0`) whose name, ASCII-lowercased with one
trailing dot dropped, is exactly one of the granted hosts and whose port is one of the granted ports; anything else (an
IP literal, userinfo, an escape, another method) gets `403` and no outbound connection. It resolves the name with the
host's resolver and splices bytes; it never terminates TLS. The profile is the ordinary one plus outbound TCP to that
proxy's port on localhost alone (no other address, no DNS resolver socket) and the certificate trust daemon, with exec always program-only
whatever the envelope said: the program's own chain, plus `git` resolved on the call's `PATH` and, from `git
--exec-path`, `git` and `git-remote-http(s)`, each with its chain. The envelope's `write` applies as sent. `done`
reports `"envelope": { "write": …, "exec": "program-only", "profile": "credentialed:github", "hosts": [<names>] }`.

### `start`: run it

`args: { "id": "c3" }` → `{ "id": "c3", "pid": 4242 }`, then a `done` event when it ends. Sent by the worker only after
its verdict. **The host spawns nothing without it.** A second `start` of the same id fails `UnknownId`.

What the host enforces whatever the verdict was: argv executed directly with no shell, git's `core.fsmonitor` off and
`core.pager` set to `cat` (through `GIT_CONFIG_COUNT`, over the repository's own config) and its optional locks off, `program.path` executed (so a
`PATH` change in between cannot swap it), stdin closed, no terminal, a new process group, the scrubbed environment, the
time limit, the output cap, and the OS sandbox when `sandboxed` was true. If the sandbox then fails to start, the
call's `done` carries `error: { code: "SandboxFailed" }` and the program never ran; the host never falls back to running
it unsandboxed.

**The optional `envelope` narrows the sandbox further.** The worker sends the narrowest envelope the approved
description allows; it can only ever NARROW what the host does today, never widen it.

```jsonc
args: { "id": "c3", "envelope": { "write": "roots" | "none", "exec": "any" | "program-only" } }
```

- `write: "roots"` is narrower than today's floor: the roots and `$TMPDIR`, with a NAME-IMMUTABLE top level (no
  create, remove or rename of any name directly under a root; `docs/SANDBOX.md`). `write: "none"` is `$TMPDIR` alone.
- `exec: "any"` is today's floor; `exec: "program-only"` allows only the resolved program, its `#!` interpreters (and
  `env`'s target), each hashed path argument's own chain, and on Linux each ELF's `PT_INTERP` (plus macOS's `sh`→`bash`
  variant).
- **Absent** means today's behaviour (an older worker). **Malformed** (`write: "all"`, `write: "today"`, `exec: 7`, an
  unknown key, a missing key) is `BadRequest` and the call is gone — never a silent fallback to today. `"today"` is
  the host's name for the floor on `done`; a worker may never SEND it.
- The envelope carries two enums and nothing else. `write: "roots"` means the roots the HOST configured under the
  name-immutable universal, never a path list the worker sends; `exec: "program-only"` means the set the HOST
  resolved, never a list from the worker.
- On Linux, anything narrower than the bwrap floor (including every `write: "roots"`) needs Landlock
  (`hello.sandbox.landlockAbi`). Without it the call fails `SandboxFailed` rather than running unrestricted. On
  macOS, Seatbelt holds every envelope in-profile.

**A hashed path argument that changed since `spawn`** (its `sha256` is not the one the facts reported) refuses the call
with `PinChanged`, and the call is gone: it is a different program than the one judged, and nothing of it ran. The same
holds for any stage of a `pipe`. The worker treats it as a call with no manifest, never as a hash to re-approve.

**The answer to `start` always comes before that call's `done`**: the host queues it before the call can end.

### `pipe`: run pending calls joined by OS pipes

Each stage is first `spawn`ed on its own, so each has its own facts and the extension can approve all of them on one
card. Then, instead of `start`:

```jsonc
args:  { "ids": ["c3", "c4", "c5"] }                  // 2 to 16 distinct ids, in pipeline order
args:  { "ids": ["c3", "c4", "c5"],                   // optional per-stage envelopes, same length as ids
         "envelopes": [null, { "write": "roots", "exec": "program-only" }, { "write": "none", "exec": "any" }] }
value: { "ids": ["c3", "c4", "c5"], "pids": [4242, 4243, 4244] }
```

`envelopes[i]` is `null` (that stage keeps today's floor) or an envelope object as under `start`. Present means the
array is exactly as long as `ids`; anything else is `BadRequest` and nothing starts.

Stage 0 has stdin closed, as under `start`; stage *i* > 0 reads stage *i* − 1's stdout through an OS pipe. Only the last
stage's stdout is held. Every stage's stderr is held. Each stage keeps what `start` gives a call: its own sandbox
wrapping, scrubbed environment, `cwd`, time limit, output cap and process group. Each ends with its own `done` event, whose
`stdout` is `{ "piped": true }` for every stage but the last. `cancel` works per id. A stage that exits early closes its
pipe: the stage writing into it gets SIGPIPE (or fails its write), so `yes | head -n1` ends. Stages are independent
otherwise: one failing does not kill the others, and each has its own `code` and `ok`.

- **All or nothing, before anything starts.** `ids` that is not an array of 2 to 16 distinct strings is `BadRequest`. A
  pending call that is missing, expired or already started is `UnknownId`, naming the first such id; none of the ids is
  consumed. Fewer than `ids.length` free running slots (32 in all) is `Busy`. Only after every check passes are the ids
  removed from the pending set.
- **If starting a stage fails** (`SandboxFailed` or `SpawnFailed`, as for `start`), the stages already started are
  killed with their process groups and reaped, their temp directories are removed, and the call answers the error. No
  `done` events follow.
- **The answer to `pipe` comes before any of its stages' `done`**, as for `start`.

### `glob`: expand a pattern within the roots

```jsonc
args:  { "cwd": "/Users/me/src/proj", "pattern": "src/**/*.rs", "limit": 10000 }   // limit optional
value: { "matches": ["src/a.rs", "src/x/b.rs"], "truncated": false }
```

`cwd` is judged as `spawn` judges it: absolute, resolved with `realpath`, a directory inside a root, else
`CwdOutsideRoots`. Before `configure`: `NotConfigured`. The host expands the pattern itself, so the extension can show
the person the names a command will receive instead of a pattern a shell would expand.

- **`pattern`**: a non-empty string of at most 4096 bytes, no NUL, not absolute, split on `/` into components, none of
  which is empty, `.` or `..` (so no `//`, no trailing `/`): else `BadRequest`.
- **Syntax, per component**: `*` any run of characters (not `/`), `?` one character, `[abc]` and `[a-z]` classes,
  `[!abc]` a negated class, `\x` the character `x` literally. A `[` that never closes is literal. A component that is
  exactly `**` matches zero or more directories; it is not special inside a longer component (`a**b` is `a*b`). Names
  are matched as UTF-8 characters; a name that is not UTF-8 never matches.
- **Hidden names**: a name starting with `.` matches only a component that itself starts with a literal `.`, as in a
  shell (`*` does not match `.env`; `.*` does). `**` never enters or matches a hidden directory.
- **Directories and files both match**: `src/*` lists the files and directories in `src`. A trailing `**` matches the
  directory before it and every visible directory beneath it, not files; use `**/*` for everything.
- **The walk**: never follows a symlink (a symlink may match by name as the last component, and is never entered, even
  one pointing at a directory; every directory is opened without following links, so one swapped for a link mid-walk is
  skipped). Skips `.git` directories. Cannot leave `cwd`: there is no `..`, and the walk only goes down. A directory that
  cannot be read is skipped without failing the call. At most 20 000 directory entries are looked at in total and 64
  levels entered; past either, the walk stops with `truncated: true`.
- **`limit`**: default 10 000, clamped to 1..=100 000. The call stops at `limit` matches with `truncated: true`; exactly
  `limit` matches is not truncation. Which matches a truncated answer holds is by directory name order, not the sorted
  whole.
- **`matches`** are paths relative to `cwd`, `/`-separated, sorted bytewise, without duplicates.

### `discard`

`args: { "id": "c3" }` → `{}`. The worker denied the call; forget it. (Unstarted ids also expire on their own.) It also drops a put or a `store` ("Mounts") by its id, deleting the temp file.

### `cancel`

`args: { "id": "c3" }` → `{ "signalled": true }`. SIGTERM to the process group, SIGKILL two seconds later if it is still
there. The `done` event follows with `cancelled: true`.

### `peek`: the latest output of a running call

```jsonc
args:  { "id": "c3", "bytes": 4096 }        // bytes optional, default 4096, clamped to 512 KiB (the limit of `read`); 0, negative or non-integer: BadRequest
value: { "id": "c3",
         "stdout": { "size": 18342, "truncated": false, "data": { "$bytes": "<base64>" } },   // null when this call's stdout went to the next stage of a pipeline
         "stderr": { "size": 0, "truncated": false, "data": { "$bytes": "" } } }
```

Output is held only once a call ends (`done` carries the pointers), so `peek` is how to read a call that is still
running. `data` is the LAST `min(bytes, size)` bytes kept so far of each stream; `size` is the bytes kept so far. A
stream that has passed the output cap has `truncated: true`: kept bytes stop at the cap, so `peek` then shows the last
bytes BEFORE the cap, and `size` stays at the cap.

The bytes are bytes, as for `read`: the cut may split a UTF-8 sequence or a line, so the reader decodes and trims. A
clamped `bytes` is not marked in the answer.

512 KiB is the budget of the whole answer, both streams together, since two full streams as base64 would pass the 1 MiB
message limit. Each stream gets the last `bytes` it holds when the two fit; past that each gets at least half, and what
one stream does not use goes to the other. `size` is always the stream's own.

Only a call in this session's running table answers. Anything else (an unknown id, a call not yet started, a call that
has ended, a call of another connection) is `UnknownId` "no running call", as for `cancel`; once a call has ended, its
`done` event's pointers and `read` are the way. A group declared with `register` has no output of the host's, and
answers `stdout` and `stderr` as `null`. Offered over every transport, like `read` and `cancel`: it reads only a call
of this connection.

### put / write / commit: write bytes to a file in a root

Three calls write one file: `put` resolves the target and writes nothing, `write` sends the bytes in chunks, `commit` puts them in place. They follow `spawn`'s shape: the host resolves the facts, the worker judges, the host acts. A put shares `spawn`'s pending table: the same 30-minute TTL (`expiresInMs`), the same `Busy` limit of 256 and the same id counter, with ids of the form `p3` where a spawn's are `c3`. `discard` drops a put. Offered over a native connection only: over the hub all three are `Refused` with `reason: "scope"`, before their arguments are read, with the eight mount calls ("Mounts").

```jsonc
put    args:  { "path": "inbox/report.pdf", "cwd": "/Users/sb/work", "size": 48213 }   // cwd required for a relative path; a leading ~ expands as for spawn
       value: { "id": "p3", "path": "/Users/sb/work/inbox/report.pdf", "root": "/Users/sb/work", "rel": "inbox/report.pdf",
                "exists": false, "existingSize": null, "size": 48213, "tilde": [], "expiresInMs": 1800000 }
write  args:  { "id": "p3", "offset": 0, "bytes": { "$bytes": "<base64>" } }
       value: { "id": "p3", "received": 32768 }
commit args:  { "id": "p3", "replace": false }                                          // replace optional, default false
       value: { "id": "p3", "path": "/Users/sb/work/inbox/report.pdf", "rel": "inbox/report.pdf", "size": 48213, "sha256": "<hex>" }
```

`put` checks, in order: `size` is at most `hello.put.max` (`TooLarge`); the last component of `path` is a normal name, not empty, `.` or `..`, with no trailing `/` (`BadRequest`); the parent directory exists (`NoParent`; the host never creates a directory) and its realpath lies in a root (`OutsideRoots`, which a `..` or a symlinked directory leading out also gives); the target is not a protected name of its root (`sandbox::protected_rels()`, relative to the root the parent lies in, compared case-insensitively) and does not look like a credential (`Protected`, with no verdict that can allow it, the same names the sandbox keeps a child from writing); the target is not a symlink (`IsSymlink`, whatever it points at) or a directory (`IsDirectory`). `exists` and `existingSize` are the worker's input for "an existing file always asks". The host opens the parent once and holds it as a directory descriptor with the put; every later step goes through it, so a path component swapped for a symlink afterwards cannot redirect the write: the bytes land in the original directory, wherever it has been renamed to.

`write` appends one chunk of at most 512 KiB (the limit of `read`). `offset` must equal the bytes received so far, so a gap, a repeat, a chunk over the cap, bytes past the declared `size` and a malformed `bytes` are `BadRequest`, and the message of an offset error names the expected one. The first chunk creates a temp file `.wmlhost-put-<id>-<random>` in the parent through the held descriptor (`O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0600`, so no other user reads or writes it while it is staged). A put of `size: 0` needs no chunk.

`commit` needs `received == size` (`BadRequest` otherwise, and the put stays open to continue). It sets the temp file's mode to `0666` less the umask (what the person's own tools would produce; the umask is read once at start), syncs it, and renames it into place through the held descriptor. With `replace: false` the rename refuses to replace: `renameat2(RENAME_NOREPLACE)` on Linux, `renameatx_np(RENAME_EXCL)` on macOS, and `link` then `unlink` where the OS or filesystem has no such flag. A file that appeared since `put` is `Exists`. With `replace: true` (the worker sends it only once the person approved overwriting) the host looks at the target again, refuses a symlink or directory as `put` did, and renames over it. A commit consumes the put, whatever its outcome. `sha256` is of the bytes written.

The temp file is deleted by `discard`, by TTL expiry, by a failed `commit`, by a `configure` (which drops pending calls) and when the connection ends. `write`, `commit` and `discard` also take the id of a `store` ("Mounts"), which shares this table.

### Mounts: a chat session's folders

A mount is a directory inside a configured root that the host holds open for one chat session, so a cell's file request
is resolved against a descriptor the host already has instead of a path it must re-trust. The design is window-ml's
[`FILE_ATTACHMENTS.md`](https://github.com/parawanderer/window-ml/blob/main/docs/spec/FILE_ATTACHMENTS.md), "What
window-ml-host must do for mounts, `/files` and `ml.sh` diffs" (H1 to H8). The split is the one `spawn` has: the host
resolves facts and refuses what no policy may lift; whether a read or write is free or asks the person is the worker's
judgment, made over the facts and sent back as a `basis`. Offered over a native connection only: over the hub the eight
calls below are `Refused` with `reason: "scope"`, before their arguments are read, and `hello.mounts` is `false`.

```jsonc
mount   args:  { "session": "chat-7f", "path": "/Users/sb/work/proj", "mode": "rw",         // "rw" | "ro"
                 "uploads": "uploads" }                       // optional: the uploads folder, relative to the mount
        value: { "id": "m4", "path": "/Users/sb/work/proj", "root": "/Users/sb/work", "mode": "rw", "uploads": "uploads" }
unmount args:  { "session": "chat-7f", "mount": "m4" }        value: {}
stat    args:  { "session": "chat-7f", "mount": "m4", "path": "src/a.rs" }                  // "" is the mount itself
        value: { "mount": "m4", "path": "src/a.rs", "inMount": true, "mode": "rw", "secret": false, "protected": false,
                 "kind": "file", "exists": true, "inUploads": false, "inAttached": false,
                 "ignored": false, "gitUndoable": true, "hardLinked": false,
                 "basis": { "dev": 16777234, "ino": 8812345, "size": 912, "mtimeNs": 1760000000123456789, "sha256": "<hex>" } }
list    args:  { "session": "…", "mount": "m4", "path": "src", "offset": 0, "limit": 2000 }       // offset, limit optional
        value: { "mount": "m4", "path": "src", "total": 2, "more": false,
                 "entries": [{ "name": "a.rs", "kind": "file", "size": 912, "mtimeNs": 1760000000123456789 }] }
fetch   args:  { "session": "…", "mount": "m4", "path": "src/a.rs", "basis": { … },
                 "offset": 0, "length": 524288, "cap": 67108864 }                  // offset, length, cap optional
        value: { "mount": "m4", "path": "src/a.rs", "offset": 0, "size": 912, "eof": true, "data": { "$bytes": "<base64>" } }
store   args:  { "session": "…", "mount": "m4", "path": "src/a.rs", "size": 948, "basis": { … }, "cap": 67108864 }
        value: { "id": "s5", "mount": "m4", "path": "src/a.rs", "size": 948, "expiresInMs": 1800000 }
write   args:  { "id": "s5", "offset": 0, "bytes": { "$bytes": "<base64>" } }              // as for a put
commit  args:  { "id": "s5" }
        value: { "id": "s5", "mount": "m4", "path": "src/a.rs", "size": 948, "sha256": "<hex>" }
remove  args:  { "session": "…", "mount": "m4", "path": "src/old.rs", "basis": { … } }   value: { "mount": "m4", "path": "src/old.rs", "removed": true }
rename  args:  { "session": "…", "mount": "m4", "from": "src/a.rs", "to": "src/b.rs", "basis": { … } }
        value: { "mount": "m4", "from": "src/a.rs", "to": "src/b.rs" }
```

**The session is the worker's stamp.** Every call but `write`, `commit` and `discard` carries `session`, a string of 1 to
256 bytes (else `BadRequest`), and speaks only for the mounts that session made: a mount id of another session is
`UnknownMount`, the same answer as one that never existed. The host cannot tell sessions apart, because one port carries
them all and the worker sets the stamp; the cell never does. This is a stated trust, not a check. `write`, `commit` and
`discard` name a store by its id, as they name a put.

**A mount's life.** `mount` allocates an id `m<n>` from the id counter `spawn` and `put` share, and holds the directory
until one of: `unmount` (which also drops that mount's stores, deleting their temp files); a `configure` after which the
mount's root is no longer the deepest root holding its path (its protected names were read against that root; a mount
whose root is still that root stays); or the connection closing. At most 64 mounts per connection (`Busy`). A mount is the realpath of `path`,
which must be absolute, so a symlink in the given path is followed once, at `mount`, and never again. `mode` is the
mount's ceiling: on `"ro"` `store`, `remove` and `rename` are `EROFS`. `uploads` names a directory of the mount holding
a directory `attached/`; both are held by device and inode, and every `stat` reports `inUploads` and `inAttached` for a
path in them (the folder itself included). An `uploads` that is not a directory
with an `attached/` inside is `MountRefused`.

**What `mount` refuses**, whatever a policy would say (`MountRefused`, the message naming the path it ran into). Every
check is on the realpath, and "overlaps" means at, under or above:

- a path that is not an existing directory;
- one that overlaps a cell path the sandbox reserves: `/files`, `/tmp`, `/lib`, `/home/pyodide`, `/dev`, `/proc` (H2);
- the home directory or any directory above it (a project inside it is fine);
- one that overlaps the browser's or the host's own state: the data directory of Chrome, Chrome Beta, Chromium, Brave
  and Edge (the profile lives there), `~/.config/wmlhost`, and the owner table's state directory, each as given and as
  its realpath. The archive folder cannot be refused here: it is a File System Access handle in the browser with no
  path the host could compare, so the worker refuses it;
- one that overlaps another mount of the SAME session (two sessions may mount overlapping folders);
- one outside every configured root.

`mount` before `configure` is `NotConfigured`.

**The path rule.** Every `path`, `from` and `to` is relative to the mount and is split on `/` into components
(`rel_parts`). Refused as `BadRequest`, on every platform: more than 4096 bytes, a NUL, a `\`, a leading `/` (so `//`),
a leading drive letter (`C:`), and a component that is empty, `.`, `..` or only dots. `""` names the mount itself and is
accepted by `stat` and `list` only. The host never lexically cleans a path; it refuses the ones that need it.

**The walk.** A path is walked one component at a time from the held descriptor (`openat` with `O_NOFOLLOW |
O_DIRECTORY`), so no component is resolved by the OS from `/`, and no symlink is ever followed: a symlink on the way is
`IsSymlink`, a file where a directory should be `NotADirectory`, a missing directory on the way `NotFound` for `list`
and, for the others, the same as a missing last component (`exists: false`, or `NoParent` for a write). The last
component is opened `O_NOFOLLOW | O_NONBLOCK`, so a symlink is never read through and a FIFO never blocks the host. A
symlink as the last component is reported by `stat` as `kind: "symlink"` and listed as one; `fetch`, `store`, `remove`
and `rename` of it are `IsSymlink`, of a directory `IsDirectory`, of anything that is neither (a socket, a device)
`BadRequest`.

**H3: a replaced folder.** Before every call but `mount`, `unmount`, `write` and `discard`, the host checks that the
mount's path still names the directory it holds (device and inode, by `lstat`). A folder moved away and replaced, or
deleted, answers `MountReplaced` to every request on the mount until it is unmounted. The commit of a `store` checks
this too, and consumes the store whatever the outcome.

**`stat`** resolves the facts and reads no bytes into the answer. `kind` is `"file"`, `"dir"`, `"symlink"` or `"other"`
(`null` when it does not exist). `secret` is the host's name check on the full path (`facts::looks_secret`, as for
`spawn`). `protected` is true for a protected name of the mount's root (as `put` refuses, relative to the ROOT, so the
mount's own place in it counts) and for anything with a `.git` component, compared case-insensitively: a write there
would run as code. `hardLinked` is `st_nlink > 1` of a regular file. `ignored` is whether git ignores the path,
`gitUndoable` whether a git checkout would give back the bytes the file holds now, both below. `basis` is the identity
the worker judges on, and is `null` for anything but a regular file:

```jsonc
{ "dev": 16777234, "ino": 8812345, "size": 912, "mtimeNs": 1760000000123456789, "sha256": "<hex>" }
```

`sha256` is present only for a file of at most 1 MiB (`DIFF_CAP`), hashed from the same descriptor the other fields
came from; past it the basis is identity, size and time alone. The worker sends the basis back as it got it.

**`list`** is one page of the directory's entries, sorted bytewise by name, `.` and `..` left out. `limit` is clamped to
1..=2000 and defaults to 2000, `offset` defaults to 0 and `more` says entries remain past the page. An entry is
`{ name, kind, size, mtimeNs }` from an `lstat`, so a symlink is a symlink and its target is never touched; `kind`,
`size` and `mtimeNs` are `null` for an entry that vanished between the read and the `lstat`, and a name that is not
UTF-8 is lossily converted and carries `"lossy": true`.

**`fetch`** reads one chunk of a regular file. `length` is clamped to 512 KiB, `offset` past the end gives zero bytes
with `eof: true`, and `cap` (default and ceiling 64 MiB, `put`'s) is the most bytes the file may have. The order of the
checks is: the cap, then the basis. A file over the cap is `EFBIG` (H5) and nothing is read. A `basis` that is absent
or is not the file's now is `ChangedSinceJudged` (H8): a fetch without a basis never succeeds, since the worker judges
on a `stat` first. The basis is compared on the descriptor the bytes are then read from.

**`store`** writes a whole file in the three steps a put does, and shares the put's machinery: `store` checks and holds
the target's directory (writing nothing) and answers a store id `s<n>`; the bytes go through `write` (the same chunk
rules, 512 KiB, `offset` equal to the bytes so far); `commit` puts them in place. A store shares the put's pending table:
the same 30-minute TTL (`expiresInMs`), the same limit of 256 waiting calls and the same id counter, and `discard`, a
`configure`, an `unmount` of its mount and the connection closing delete its temp file (`.wmlhost-put-<id>-<random>`)
as they delete a put's. `write` and `discard` take either id. `store` checks, in order: the mount is `rw` (`EROFS`);
the path (`BadRequest`); the walk, and that no directory on it is `attached/` (`InAttached`: the uploads as they were
given); that the target is not protected (the same rule as `stat`'s `protected`; `Protected`); that its directory
exists (`NoParent`); `size` against `cap` (default and ceiling 64 MiB; over it `EFBIG`, H5), after the hard refusals so
a write no size could make allowed says why; and the target's kind (as under the walk). Then it decides by the pair of the target and the `basis`:

| Target now | `basis` | Result |
| --- | --- | --- |
| absent | absent | a new file, mode `0666` less the umask |
| a regular file | present and equal | replaces it, keeping its permission bits (`st_mode & 0777`) |
| a regular file with another name (`st_nlink` > 1) | present | `HardLinked`: replacing it would leave the other name with the old bytes |
| a regular file | absent or different | `ChangedSinceJudged` |
| absent | present | `ChangedSinceJudged` |

`commit` needs every declared byte (`BadRequest` otherwise, the store staying open to continue), syncs the temp file
and then does the compare-and-swap (H8) through the held directory. With a basis: the target is opened again and must
still be a regular file with one link and the same basis, else `ChangedSinceJudged`; it is then replaced by `rename`.
Without one: the rename refuses to replace (as a put's `replace: false` does), and a file that appeared is
`ChangedSinceJudged` where a put says `Exists`. **The stated residual:** the compare and the rename are two steps and
no OS call does both, so a writer that lands between them is lost. The window is the two syscalls; nothing closes it.

**`remove`** unlinks a regular file whose basis is the one judged (`ChangedSinceJudged` otherwise, a missing file
included). It is `EROFS` on a read-only mount and `Protected` for a protected name. It is allowed in `attached/`: the
worker asks the person first (H6), and the host keeps no rule the worker cannot lift, as it does for `store` and
`rename`, which are `InAttached` there. A directory is `IsDirectory`; a hard-linked file is removed (only the name goes).

**`rename`** moves a regular file within the mount to a name that is free, with `renameat2(RENAME_NOREPLACE)` or
`renameatx_np(RENAME_EXCL)`, and `link` then `unlink` where the OS has none. It is `EROFS`, `InAttached` (the source or
the destination in `attached/`, in either direction), `Protected` (either name), `NoParent` (the destination's
directory), `ChangedSinceJudged` (the source's basis), and `Exists` when the destination is there. A move across
filesystems is `EXDEV`: the host never falls back to copy and delete, since the rename would no longer be one step.

#### Git facts

`stat` asks git two questions about the path, with the host's own `git` (found on the session's `PATH`, the one
`configure` gave), not through a call. These are the host's queries and run under a stricter belt than a call does
(`src/gitfacts.rs`): the person's global and system config are not read (`GIT_CONFIG_GLOBAL=/dev/null`,
`GIT_CONFIG_NOSYSTEM=1`; a `filter.lfs.clean` there would run in a content compare), `GIT_DIR` and `GIT_WORK_TREE` are
named explicitly from the host's own read of the repository (`gitconfig`), so a `core.worktree` cannot point the query
elsewhere, `core.fsmonitor` is off and `core.pager` is `cat`, the environment is cleared, there is no prompt and no
optional lock, each query has a 10 s limit, and no command that compares the work tree's content (`diff`, `status`,
`add`) is ever run.

- **`ignored`**: `git check-ignore -q`. `false` when the path is in no repository, or is the work tree's root; `null`
  when git cannot be asked (no `git` on the path, the query failed or timed out) and, as for `gitUndoable`, when the
  repository's config runs code: no query of the host's reads such a config.
- **`gitUndoable`**: true when `git checkout` of the path would give back the bytes the file holds now. It is decided by
  hashing the file's bytes with `git hash-object --no-filters` (no clean filter runs) and comparing the blob with the
  index's entry and with HEAD's: the path must be a tracked regular file at stage 0 whose index entry carries neither
  the assume-unchanged nor the skip-worktree bit (either hides a change from git, so both read false), and its index
  blob, HEAD blob and the file's own hash must be the same. `false` for an untracked, modified, ignored or conflicted
  file, a symlink entry, a repository with no commit, and a file over 64 MiB. `null` when the repository's own config
  makes git run a program (`repoConfigRunsCode`, `spawn`'s fact: the undo itself would run it) or git cannot be asked.
  `false` outside a repository, and for anything that is not a regular file.

`null` is unknown, never "no": the worker asks the person on `null`, as on `false`, but may say why.

### `register`: own a process group this connection started

```jsonc
args:  { "pgid": 51234,                                   // a process group this connection started itself
         "owner": { "session": "…", "harness": "claude-code", "run": "…", "step": 3 },  // required, at most 1 KiB of JSON
         "memoryBound": 4294967296,                       // optional, as for spawn
         "onOwnerLoss": "orphan", "orphanTimeoutMs": 60000 }   // optional, as for spawn
value: { "id": "r4", "pid": 51234, "memoryBound": 4294967296, "onOwnerLoss": { "policy": "kill" } }
```

A group the host did NOT spawn becomes a row of its owner table (window-ml's `SHELL.md`, the ruling of 2026-10-23), so
"whose process is this" is answered for it as for a spawn. Ownership is DECLARED, never observed: the host verifies
nothing about who started the group. The row answers with the `owner` this connection declared and is bound to this
connection: the port closing is its owner going, under the same `onOwnerLoss` as a spawn (killed by default, an orphan
with a deadline otherwise), with the same `ended` records. A harness with no native port holds a `wmlhost serve`
session open over stdio; that process exiting is its owner going. `configure` is not needed; without it the bound and
the policy take their defaults.

The host is not the group's parent. It samples the group, its recorded members and their descendants every 100 ms, as
it does a spawn's; holds it to its memory bound (`killed: "oom"`); answers `cancel` (SIGTERM, then SIGKILL after 2 s);
and signals it only while the group id still names the recorded group (its leader's start time, as a ledger entry is
judged). When nothing of it is left, a `done` follows with `"registered": true`, `code`, `signal` and `ok` all `null`
(the host never sees an exit status), and `killed`, `cancelled`, `durationMs`, `peakFootprint`, `memoryBound`, `cpuMs`.
A registered row counts toward the 32 running calls.

Refused with `BadRequest`, and nothing else checked: a `pgid` of 1 or less; a group this host cannot signal (gone, or
another user's); a group that holds this host or any of its ancestors (the port closing would kill the browser); a
group that is already a row of this host's table or of any ledger in the state directory; an `owner` that is not an
object of at most 1 KiB. Over the hub the call is `Refused` with `reason: "scope"` before its arguments are read: a
remote principal registering a group here would hold a kill over any process of this user.

### `owner`: whose process is this

```jsonc
args:  { "pid": 51240 }
value: { "owner": { "session": "…" }, "id": "r4", "kind": "registered", "pgid": 51234, "host": "this", "orphan": false }
value: { "owner": null }                                  // no row reaches it: nobody's, and that is the answer
```

The pid is looked for in each row's members as the watchdog follows them (the group, recorded members still the same
process, and every descendant): this connection's rows first (`host: "this"`), then, over native messaging only, every
other host's rows in the state directory, live hosts' running calls and gone hosts' orphans (`host: "other"`; `orphan`
says which). Over the hub only the caller's own rows are read. Nothing is scanned beyond the rows: a process no row
reaches is nobody's.

### `status`: the owner table

`args: {}` → every running call of this session (spawned and registered), the orphans other host processes left, and the calls that ended with
nobody to read their `done`:

```jsonc
{ "running": [{ "id": "c3", "pid": 4242, "owner": { "run": "…" }, "startedMs": 1760000000000,
                "memoryBound": 4294967296, "footprint": 52428800, "peakFootprint": 61865984,
                "cpuMs": 1520, "kind": "spawned", "onOwnerLoss": { "policy": "kill" } }],
  "orphans": [{ "id": "c1", "pid": 4100, "owner": { "run": "…" }, "startedMs": 1760000000000,
                "deadlineMs": 1760000600000, "footprint": 10485760, "cpuMs": 40,
                "protectedChanged": [{ "root": "/Users/me/proj", "name": ".envrc", "change": "created" }] }],
  "ended": [{ "id": "c1", "owner": { "run": "…" }, "startedMs": 1760000000000, "deadlineMs": 1760000600000,
              "endedMs": 1760000600140, "cause": "deadline", "killed": true,
              "protectedChanged": [{ "root": "/Users/me/proj", "name": ".vscode", "change": "created" }] }] }
```

`footprint` is the last measurement of the call's process group and its descendants; `pid` is the group's id. `cpuMs`
is the CPU time (user and system) of the members alive at that measurement, each with the children it has reaped: a
member that exited takes its time with it unless a member reaped it, so it can fall. It is measured and never bounded.
`kind` is `"spawned"` or `"registered"` (`register`); an orphan's and an ended record's `kind` is present only for a
registered one. Reading
`status` also sweeps: an orphan past its deadline is killed rather than listed. An orphan's `protectedChanged` is
computed at the read, against the snapshot its `start` took (as on `done`, below): what changed so far. It is absent for
an orphan an older host started.

`ended` lists each call that left the owner table with no `done` anyone could read, ONCE: the first `status` of any
later session returns a record and deletes it, so no later one returns it again. `cause` is how it ended:

| `cause` | What happened | `killed` |
| --- | --- | --- |
| `deadline` | an orphan's `orphanTimeoutMs` passed | whether anything of it was left to kill |
| `owner-lost` | the port closed under `onOwnerLoss: "kill"` | the same |
| `host-lost` | its host was killed outright under `"kill"`, and a warden or a later host swept it | the same |
| `exited` | a sweep found nothing of it left: it ended on its own | `false` |
| `not-ours` | its group id now names another process's group, which is never signalled | `false` |

`protectedChanged` is the compare against the call's `start` snapshot, taken after the kill, with `done`'s bounds and
`protectedChangedTruncated` sibling; absent for an entry an older host wrote (unknown, never "nothing"). `deadlineMs`
is `null` for a call that was not an orphan. Records leave in `endedMs` order while the reply fits the 1 MiB frame;
`endedMore: true` says some stayed for the next `status`. An unread record is kept 7 days, and at most 64 are kept,
the oldest dropped first. Both bounds are guesses. A record the host cannot read as its own is dropped too.
`endedDropped` counts every drop since the last `status`, and both keys are absent when there is nothing to say. A
host older than 0.6.0 has no `ended` key. Its absence is unknown, never "nothing ended".

Any later session with the same state directory consumes a record, so two browser profiles sharing one
`wmlhost-owners-<uid>` can read each other's. `orphans` has the same property; the `owner` is how a reader tells its
own.

### `read`: a range of held output

```jsonc
args:  { "ptr": "out:9f2e…", "offset": 0, "length": 524288 }       // length at most 524288 (512 KiB)
value: { "ptr": "out:9f2e…", "offset": 0, "length": 524288, "size": 2097152, "eof": false, "data": { "$bytes": "…" } }
```

An `offset` past the end returns zero bytes with `eof: true`. Bytes, not text: output is whatever the program wrote. `data` is `{ "$bytes": <base64> }`, the form the `ml` wire uses for bytes. 512 KiB is 683 KiB as base64, inside the 1 MiB message limit.

### `release`

`args: { "ptr": "out:9f2e…" }` → `{}`. Deletes held output early; everything is deleted when the session ends anyway.

### The `done` event

```jsonc
{ "event": "done", "id": "c3",
  "code": 0, "signal": null,                  // code null when killed by a signal ("SIGKILL")
  "ok": true,                                 // code is in okCodes; okCodes is [0] until manifests (root F)
  "timedOut": false, "cancelled": false, "durationMs": 31,
  "killed": null,                             // "oom": past its memory bound, the whole call was killed (SIGKILL, no grace)
  "peakFootprint": 61865984, "memoryBound": 4294967296,      // bytes; the peak the watchdog measured
  "cpuMs": 31,                                               // CPU time at the watchdog's last sample (`status`)
  "envelope": { "write": "today", "exec": "any" },           // the scope the host APPLIED ("today" when the worker sent none)
  "protectedChanged": [],                                    // protected names that changed during the call (below)
  "stdout": { "ptr": "out:…", "size": 812, "sha256": "…", "truncated": false },   // { "piped": true } for a non-last `pipe` stage
  "stderr": { "ptr": "out:…", "size": 0, "sha256": "…", "truncated": false } }
```

A non-last stage of a `pipe` has `"stdout": { "piped": true }`: its output went to the next stage and nothing of it is
held. A stream the host could not keep (the disk filled, say) is `{ "error": "…" }` instead of a pointer. A sandboxed call
whose sandbox refused to start the program adds `"error": { "code": "SandboxFailed", "message": "…" }` and `ok: false`.

`envelope` is the scope the host APPLIED, with `profile` and `hosts` only for a credentialed call (`"credentialed:github"`, the names its proxy admitted); an
envelope without it ran under the ordinary profile. `write: "today"` is the host's name for today's floor: what an ABSENT
envelope means, and what `done` reports for one — never `"roots"`. A worker may not SEND `"today"`; that is
malformed. An ABSENT `envelope` on `done` means an older host; the extension treats that as unknown, never as narrow.

`protectedChanged` lists what changed among the roots' protected names while the call ran, `[]` when nothing: each
`{ "root", "name", "change" }`, `change` one of `"created"`, `"modified"`, `"removed"`, sorted by root and name. The
host records, at `start` (once for a whole `pipe`, before its first stage), every protected top-level name of every root
(`.envrc`, `.mcp.json`, `.vscode`, … as in docs/SANDBOX.md), `.git/config`, `.git/hooks` and each entry of `.git/hooks`,
by type, inode, size, mode, `mtime` and `ctime`, and compares at `done`. A new hook is `.git/hooks/<name>` `created`
(and `.git/hooks` `modified`). It is reported for every call, sandboxed or not, and never reverted. It says what changed
DURING the call, not BY it: two calls in one root both see either's change. A nested repository's hooks are not read.
ABSENT means an older host: unknown, never "nothing". It is bounded: at most 256 hooks per root are read (by name;
past that a new hook is not named, but `.git/hooks` itself is reported `modified`), and the list holds at most 256
changes and at most 512 KiB of JSON, with `"protectedChangedTruncated": true` when it was cut (absent: complete). The
bound, not the fallback below, is what keeps a `done` under the native limit (docs/SANDBOX.md).

A message past the 1 MiB native limit is never dropped. An answer becomes `{ "seq", "error": { "code": "TooLarge" } }`.
A `done` keeps its `event` and `id`: it first loses `protectedChanged` (absent: unknown), and if it is still too large it
is `{ "event": "done", "id", "ok": false, "error": { "code": "TooLarge" } }`.

`{ code, ok, stdout, stderr }` is the result shape `ml.sh.run` returns, with `stdout`/`stderr` as pointers. `truncated`
means the stream passed the output cap: the host kept the first `outputCap` bytes and drained the rest so the program was
not blocked.

## Owners

Every running call is a row of the host's ONE owner table: its process group, its leader's start time, and the `owner`
the spawn named. `status` reads it. Each call runs in its own process group; a sandbox wrapper that moves the program
into a session of its own is followed through its descendants, never through `ps`.

- **The port closing is the owner going.** With `onOwnerLoss: "kill"` (the default) the call's group and descendants are
  killed at once. With `"orphan"` the call keeps running until `orphanTimeoutMs` after the port closed, listed in the
  `orphans` of any later host's `status`, then is killed.
- **A host killed outright** (SIGKILL, Jetsam, the OOM killer) gets no EOF. Each host mirrors its table to a ledger file
  (`$WMLHOST_STATE_DIR`, else `wmlhost-owners-<uid>` in the temp directory, private) and starts a warden (`wmlhost warden
  <ledger>`, its own process group, no stdio) with its first call. The warden kills the dead host's calls, keeping orphans
  until their deadlines, then exits. A new host sweeps dead hosts' ledgers too. Nothing is swept, killed or read as a record from a state
  directory that is not the user's own and private (0700): someone who could write a ledger there would name the
  groups the user's host kills.
- **Nothing leaves the table unreported.** A call that leaves it with no `done` anyone could read (killed with its port,
  at its deadline, by a sweep, or found gone) leaves an `ended` record, `<host pid>-<host start>.<call id>.ended`, next to
  its ledger. Sweeps hold an exclusive `flock` on `sweep.lock` in that directory, and a record is linked into place
  no-replace, so each call has one record and one `status` returns it (`status`, above).
- **A pid is never trusted alone.** A recorded group is killed only while its leader has the recorded start time, or the
  leader is gone and the group still has members (a group id is not reused while a member lives).
- **Over the hub the owner is the caller.** Its presence gone for 30 s closes its session, as the port closing does
  here, and only its calls meet their `onOwnerLoss`: each caller has its own table (`docs/HUB.md`).
- The host owns what it spawned and what a connection on this machine declared to it with `register`, and nothing
  else. A process neither reaches is nobody's (`owner`).

**The memory bound** is on physical footprint, summed over the call's group and descendants, sampled every 100 ms. Past
it the call is killed and `done` says `killed: "oom"`. A call allocating faster than the bound per interval overshoots by
at most one interval's growth.

## Error codes

These are the host's own; the worker maps them onto the `ml` wire's codes (`Refused`, `Denied`, `BadRequest`, `Failed`, …) when it answers a script.

| Code | When |
| --- | --- |
| `BadRequest` | malformed message, unknown call, a field of the wrong type |
| `NotConfigured` | `spawn`, `glob` or `mount` before `configure` |
| `BadRoot` | a root that is not an absolute existing directory, or is `/` |
| `ProgramNotFound` | `argv[0]` not found on `PATH`, or not an executable file |
| `CwdOutsideRoots` | `cwd` (of `spawn`, `glob` or `put`) missing, not a directory, or resolving outside every root |
| `EnvRefused` | an `env` name on the denylist (`src/env.rs`), which includes every `GH_*`, `GITHUB_*`, `SSL_CERT_*` and `*_PROXY` (any case) |
| `CredentialRefused` | `spawn`: a `credential` the host does not honour: an unknown provider, a manifest hash it did not pin or whose manifest names no such credential, another program, or the hub transport |
| `SecretUnavailable` | an `env` handle the host's store does not hold; `start`/`pipe` of a credentialed call whose provider gave no token |
| `Unsupported` | `mode: "container"` this version |
| `UnknownId` | `start`/`discard`/`cancel`/`pipe`/`peek`/`write`/`commit` (a put's or a store's) of an id that never existed, expired, or already started (`start`, `pipe`) |
| `UnknownPtr` | `read`/`release` of a pointer that does not exist |
| `SandboxFailed` | the sandbox program itself could not be started (a refusal by the sandbox shows in `done`); a `start`/`pipe` with an `envelope` on a call that is not sandboxed (an envelope is a request for a bound; an unsandboxed call holds none); a `write: "roots"` or `exec: "program-only"` on Linux without Landlock; a `credential` on a session or platform that cannot hold the credentialed profile (unsandboxed, Linux without Landlock) |
| `SpawnFailed` | the OS refused to start the program |
| `PinChanged` | `start`/`pipe` of a call whose hashed path argument changed since its facts were read |
| `Busy` | 256 calls already wait for a verdict, or 32 are running (a `pipe` counts its stages); 64 mounts are held |
| `Failed` | reading held output failed on disk |
| `Refused` | over the hub only: the host's own checks refused the caller before the call was looked at; `reason` is `scope`, `revoked`, `stale` or `notACaller` (`docs/HUB.md`) |
| `TooLarge` | the answer would exceed 1 MiB (an `argv` that large, echoed back in the facts); a `put` whose `size` is over `hello.put.max` |
| `NoParent` | `put`/`store`/`rename`: the parent directory of the target does not exist, or is not a directory |
| `OutsideRoots` | `put`: the parent directory's realpath is in no root |
| `IsSymlink` | `put`/`commit`: the target is a symbolic link; a mount call: a symlink on the path or as the file operated on |
| `IsDirectory` | `put`/`commit`: the target is a directory; `fetch`/`store`/`remove`/`rename`: the path names a directory |
| `Protected` | `put`: the target is a protected name of its root (`.git/hooks`, `.bashrc`, …) or looks like a credential; `store`/`remove`/`rename`: a protected name of the root, or any path with a `.git` component |
| `Exists` | `commit` without `replace`: a file is at the target now; `rename`: the destination exists |
| `NotADirectory` | a mount call: a file where a directory is needed on the path |
| `NotFound` | `list`: a directory on the path does not exist |
| `MountRefused` | `mount`: not an existing directory, or at, under or above something no mount may reach (reserved cell paths, home or above, the browser's and the host's state, another mount of the session), or outside every root; a bad `uploads` |
| `UnknownMount` | a mount call naming a mount this session does not hold (another session's included), or a `commit` whose mount is gone |
| `MountReplaced` | a mount call whose mount path no longer names the folder held (H3) |
| `ChangedSinceJudged` | `fetch`/`store`/`commit`/`remove`/`rename`: the file is not what the `basis` judged (absent, different, or no basis where one is needed); a `store`'s target appeared or changed before its commit |
| `EROFS` | `store`/`remove`/`rename` on a read-only mount |
| `EFBIG` | `fetch` of a file, or `store` of a `size`, over `cap`; the error also carries `size` and `cap` (bytes) beside `code` and `message` |
| `InAttached` | `store`/`rename` into or out of a directory the mount's `uploads` names `attached/` (`remove` is allowed there) |
| `HardLinked` | `store` replacing a file that has another name |
| `EXDEV` | `rename` across filesystems; never made a copy and a delete |

## Not in v1, and where it will go

- On Linux, a transient cgroup per call (`memory.max`, `memory.swap.max=0`) so the kernel enforces the bound instead of
  the watchdog; needs a delegated cgroup subtree, which an unprivileged native host does not always have.

- A text pipe over held output (`ml.pipe` at the host): a call taking a `ptr` and a pipe string, answering a new `ptr`.
- Program manifests read by the host (root F): `effects`, `okCodes`, the operand terminator and the program's version
  fill in from the manifest; `pathArgs` becomes the manifest's.
- The container runner: `mode: "container"`, with `placement: "container"`.
- The hub transport: the same calls carried as sealed commands (the `hub` Cargo feature).
