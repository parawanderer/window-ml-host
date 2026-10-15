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
{ "host": "window-ml-host", "version": "0.2.0", "protocol": 1, "platform": "macos",
  "sandbox": { "kind": "seatbelt", "available": true },             // kind: "seatbelt" | "bwrap" | null; "reason" when unavailable
  "modes": ["host"] }                                               // "container" appears once a runner exists
```

### `configure`

The session's settings, from the person's DevTools Settings. A spawn before the first `configure` fails `NotConfigured`.

```jsonc
args: { "roots": ["/Users/me/src/proj"],     // workspace roots: absolute, existing directories, never "/"
        "sandbox": true,                     // default true; false = plain host mode, by the person's choice
        "path": ["/opt/homebrew/bin", "/usr/bin", "/bin"],   // optional: PATH for lookup and for the child
        "timeoutMs": 120000,                 // optional default per call, at most 3600000
        "outputCap": 67108864 }              // optional bytes kept per stream, at most 1 GiB
value: { "roots": [{ "given": "…", "path": "<realpath>" }], "sandboxed": true }
```

`sandboxed` in the answer is whether calls will run under the OS sandbox: `sandbox` asked for it AND it is available.
Reconfiguring drops every pending spawn (their facts were judged against the old roots); running processes continue.

### `spawn`: resolve the facts, start nothing

```jsonc
args: { "argv": ["git", "diff", "--stat", "HEAD~1"],
        "cwd": "/Users/me/src/proj",          // absolute; must resolve inside a root
        "env": { "LC_ALL": "C" },             // ADDED to the scrubbed base; a value may be { "$secret": "<name>" }
        "mode": "host",                       // "host" | "container"
        "pathArgs": [{ "arg": 3 }],           // which argv slots are paths (from the program manifest); see below
        "walkCwd": false,                     // the call walks its cwd (a recursive reader given no path): report containsSecret
        "repoArg": 2,                         // optional: the argv slot naming the repository (`git -C dir`); else the cwd's
        "timeoutMs": 30000 }                  // optional, at most 3600000
```

The answer is the RESOLVED FACTS, everything a policy is given about the call (`SHELL.md`, "What it is given"):

```jsonc
{ "id": "c3",                                   // names this pending call for start / discard
  "argv": ["git", "diff", "--stat", "HEAD~1"],
  "program": { "path": "/usr/bin/git", "inRoot": false,     // argv[0] after PATH lookup, realpath'd
               "fingerprint": "16777234:1152921500312187:134512:1760000000123456789" },
  "cwd": { "path": "/Users/me/src/proj", "inRoot": true },  // + "containsSecret" with walkCwd
  "env": { "set": ["LC_ALL"], "secrets": [], "free": true }, // names only; free: every name is on the FREE list
  "repo": { "root": "/Users/me/src/proj", "reasons": [] },  // null outside a git repository
  "repoConfigRunsCode": false,                  // the repository's own config makes git run a program; null: no repository
  "paths": [{ "arg": 3, "given": "HEAD~1", "path": "/Users/me/src/proj/HEAD~1",
              "inRoot": true, "secret": false, "exists": false }],
  "effects": "unknown",                         // from the program manifest once one exists (root F); "unknown" until then
  "mode": "host",
  "sandboxed": true,
  "placement": "host-sandbox",                  // "host-sandbox" | "host-plain": the enforcer whose bound applies (EFFECTS.md)
  "expiresInMs": 1800000 }                      // after this the id is gone and start fails UnknownId
```

- **`program.fingerprint`** is `<dev>:<ino>:<size>:<mtime_ns>` of the program file (`null` if its metadata cannot be
  read). Any rewrite of the binary changes it, so the extension can cache what it learned about a program (its version)
  per fingerprint.
- **`pathArgs`** entries are `{ "arg": i }` (the whole argument is a path) or `{ "arg": i, "split": "=" }` (the part
  after the first `=`, for `--output=f`). The host resolves only the arguments it is told are paths: an argument nobody
  marked is not a path the host can vouch for, and the worker treats the call accordingly. Root F moves this list into
  the program manifests, which the host will also read.
- **A path is resolved with `realpath` against `cwd`.** One that does not exist yet is its deepest existing ancestor's
  realpath plus the rest, and is never `inRoot` if the rest contains `..`. A symlink is followed, so one pointing out of
  a root is `inRoot: false`.
- **`walk: true`** on a `pathArgs` entry (a recursive reader: `rg`, `find`, `ls -R`) adds `containsSecret`: `true` if
  anything beneath the path looks like a secret, `false` if nothing does, `null` past 20 000 entries or an unreadable
  directory. The walk never follows a symlink (a link is judged by its name) and skips `.git` directories.
- **`repoConfigRunsCode`** comes from the host's own read of the repository-level config (`.git/config`, a worktree's
  common config and `config.worktree`, and the `include`/`includeIf` files they pull in from inside the repository):
  true for `core.fsmonitor`, `core.pager` other than `cat`, `core.hooksPath`, `core.sshCommand`, `core.askPass`,
  `core.gitProxy`, `diff.external`, `diff.*.textconv`, `diff.*.command`, any `filter.*`, `credential.helper`, an
  `alias.*` starting with `!`, `gpg.program`, `remote.*.uploadpack`/`receivepack`, and any include from outside the
  repository; `reasons` lists each. The person's global config is not read.
- **`env.free`**: every variable the call sets is one of `LANG`, `LC_*`, `TZ`, `NO_COLOR`, `COLUMNS`, or `TERM=dumb`.
- **`secret`** is the host's name check (`.env`, `*.pem`, `id_*`, `.ssh/`, …; the list is `SECRET_PATTERNS` in
  `src/facts.rs`) on the resolved path and on the path as given.
- **Refused at spawn, whatever a policy would say** (these are enforcement, not decisions): `cwd` outside every root
  (`CwdOutsideRoots`); an `env` name on the denylist (`EnvRefused`); a secret handle the host's store does not hold
  (`SecretUnavailable`, always this round: the store is empty); `argv[0]` not found (`ProgramNotFound`); `mode:
  "container"` (`Unsupported`, until a runner exists).

### `start`: run it

`args: { "id": "c3" }` → `{ "id": "c3", "pid": 4242 }`, then a `done` event when it ends. Sent by the worker only after
its verdict. **The host spawns nothing without it.** A second `start` of the same id fails `UnknownId`.

What the host enforces whatever the verdict was: argv executed directly with no shell, git's `core.fsmonitor` off and
`core.pager` set to `cat` (through `GIT_CONFIG_COUNT`, over the repository's own config) and its optional locks off, `program.path` executed (so a
`PATH` change in between cannot swap it), stdin closed, no terminal, a new process group, the scrubbed environment, the
time limit, the output cap, and the OS sandbox when `sandboxed` was true. If the sandbox then fails to start, the
call's `done` carries `error: { code: "SandboxFailed" }` and the program never ran; the host never falls back to running
it unsandboxed.

**The answer to `start` always comes before that call's `done`**: the host queues it before the call can end.

### `pipe`: run pending calls joined by OS pipes

Each stage is first `spawn`ed on its own, so each has its own facts and the extension can approve all of them on one
card. Then, instead of `start`:

```jsonc
args:  { "ids": ["c3", "c4", "c5"] }                  // 2 to 16 distinct ids, in pipeline order
value: { "ids": ["c3", "c4", "c5"], "pids": [4242, 4243, 4244] }
```

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

`args: { "id": "c3" }` → `{}`. The worker denied the call; forget it. (Unstarted ids also expire on their own.)

### `cancel`

`args: { "id": "c3" }` → `{ "signalled": true }`. SIGTERM to the process group, SIGKILL two seconds later if it is still
there. The `done` event follows with `cancelled: true`.

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
  "stdout": { "ptr": "out:…", "size": 812, "sha256": "…", "truncated": false },   // { "piped": true } for a non-last `pipe` stage
  "stderr": { "ptr": "out:…", "size": 0, "sha256": "…", "truncated": false } }
```

A non-last stage of a `pipe` has `"stdout": { "piped": true }`: its output went to the next stage and nothing of it is
held. A stream the host could not keep (the disk filled, say) is `{ "error": "…" }` instead of a pointer. A sandboxed call
whose sandbox refused to start the program adds `"error": { "code": "SandboxFailed", "message": "…" }` and `ok: false`.

`{ code, ok, stdout, stderr }` is the result shape `ml.sh.run` returns, with `stdout`/`stderr` as pointers. `truncated`
means the stream passed the output cap: the host kept the first `outputCap` bytes and drained the rest so the program was
not blocked.

## Error codes

These are the host's own; the worker maps them onto the `ml` wire's codes (`Refused`, `Denied`, `BadRequest`, `Failed`, …) when it answers a script.

| Code | When |
| --- | --- |
| `BadRequest` | malformed message, unknown call, a field of the wrong type |
| `NotConfigured` | `spawn` or `glob` before `configure` |
| `BadRoot` | a root that is not an absolute existing directory, or is `/` |
| `ProgramNotFound` | `argv[0]` not found on `PATH`, or not an executable file |
| `CwdOutsideRoots` | `cwd` (of `spawn` or `glob`) missing, not a directory, or resolving outside every root |
| `EnvRefused` | an `env` name on the denylist (`src/env.rs`) |
| `SecretUnavailable` | an `env` handle the host's store does not hold |
| `Unsupported` | `mode: "container"` this version |
| `UnknownId` | `start`/`discard`/`cancel`/`pipe` of an id that never existed, expired, or already started (`start`, `pipe`) |
| `UnknownPtr` | `read`/`release` of a pointer that does not exist |
| `SandboxFailed` | the sandbox program itself could not be started (a refusal by the sandbox shows in `done`) |
| `SpawnFailed` | the OS refused to start the program |
| `Busy` | 256 calls already wait for a verdict, or 32 are running (a `pipe` counts its stages) |
| `Failed` | reading held output failed on disk |
| `TooLarge` | the answer would exceed 1 MiB (an `argv` that large, echoed back in the facts) |

## Not in v1, and where it will go

- A text pipe over held output (`ml.pipe` at the host): a call taking a `ptr` and a pipe string, answering a new `ptr`.
- Program manifests read by the host (root F): `effects`, `okCodes`, the operand terminator and the program's version
  fill in from the manifest; `pathArgs` becomes the manifest's.
- The container runner: `mode: "container"`, with `placement: "container"`.
- The hub transport: the same calls carried as sealed commands (the `hub` Cargo feature).
