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
{ "host": "window-ml-host", "version": "0.3.0", "protocol": 1, "platform": "macos",
  "sandbox": { "kind": "seatbelt", "available": true, "landlockAbi": null },  // kind: "seatbelt" | "bwrap" | null; "reason" when unavailable; landlockAbi: number | null (Linux only)
  "modes": ["host"],                                                // "container" appears once a runner exists
  "owners": { "ledger": true },                                     // false: the owner table is in memory only (see "Owners")
  "memory": { "metric": "phys_footprint", "enforcer": "watchdog", "everyMs": 100 } }
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
        "timeoutMs": 30000,                   // optional, at most 3600000
        "owner": { "session": "…", "run": "…", "step": 3 },   // optional: who the call is for, opaque, at most 1 KiB of JSON
        "memoryBound": 536870912,             // optional: this call's bound, clamped to [16 MiB, memoryMax]
        "onOwnerLoss": "orphan", "orphanTimeoutMs": 60000 }   // optional: this call's owner-loss policy
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
  "repoConfigRunsCode": false,                  // the repository's own config makes git run a program; false with no repository
  "paths": [{ "arg": 3, "given": "HEAD~1", "path": "/Users/me/src/proj/HEAD~1",
              "inRoot": true, "secret": false, "exists": false }],
  "effects": "unknown",                         // from the program manifest once one exists (root F); "unknown" until then
  "mode": "host",
  "sandboxed": true,
  "placement": "host-sandbox",                  // "host-sandbox" | "host-plain": the enforcer whose bound applies (EFFECTS.md)
  "memoryBound": 536870912,                     // the bound the call will run under, after clamping
  "onOwnerLoss": { "policy": "orphan", "timeoutMs": 60000 },
  "owner": { "session": "…", "run": "…", "step": 3 },        // as given; null when none was
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

`args: { "id": "c3" }` → `{}`. The worker denied the call; forget it. (Unstarted ids also expire on their own.)

### `cancel`

`args: { "id": "c3" }` → `{ "signalled": true }`. SIGTERM to the process group, SIGKILL two seconds later if it is still
there. The `done` event follows with `cancelled: true`.

### `status`: the owner table

`args: {}` → every running call of this session, the orphans other host processes left, and the calls that ended with
nobody to read their `done`:

```jsonc
{ "running": [{ "id": "c3", "pid": 4242, "owner": { "run": "…" }, "startedMs": 1760000000000,
                "memoryBound": 4294967296, "footprint": 52428800, "peakFootprint": 61865984,
                "onOwnerLoss": { "policy": "kill" } }],
  "orphans": [{ "id": "c1", "pid": 4100, "owner": { "run": "…" }, "startedMs": 1760000000000,
                "deadlineMs": 1760000600000, "footprint": 10485760,
                "protectedChanged": [{ "root": "/Users/me/proj", "name": ".envrc", "change": "created" }] }],
  "ended": [{ "id": "c1", "owner": { "run": "…" }, "startedMs": 1760000000000, "deadlineMs": 1760000600000,
              "endedMs": 1760000600140, "cause": "deadline", "killed": true,
              "protectedChanged": [{ "root": "/Users/me/proj", "name": ".vscode", "change": "created" }] }] }
```

`footprint` is the last measurement of the call's process group and its descendants; `pid` is the group's id. Reading
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
  "envelope": { "write": "today", "exec": "any" },           // the scope the host APPLIED ("today" when the worker sent none)
  "protectedChanged": [],                                    // protected names that changed during the call (below)
  "stdout": { "ptr": "out:…", "size": 812, "sha256": "…", "truncated": false },   // { "piped": true } for a non-last `pipe` stage
  "stderr": { "ptr": "out:…", "size": 0, "sha256": "…", "truncated": false } }
```

A non-last stage of a `pipe` has `"stdout": { "piped": true }`: its output went to the next stage and nothing of it is
held. A stream the host could not keep (the disk filled, say) is `{ "error": "…" }` instead of a pointer. A sandboxed call
whose sandbox refused to start the program adds `"error": { "code": "SandboxFailed", "message": "…" }` and `ok: false`.

`envelope` is the scope the host APPLIED. `write: "today"` is the host's name for today's floor: what an ABSENT
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
- The host owns what it spawned and nothing else.

**The memory bound** is on physical footprint, summed over the call's group and descendants, sampled every 100 ms. Past
it the call is killed and `done` says `killed: "oom"`. A call allocating faster than the bound per interval overshoots by
at most one interval's growth.

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
| `SandboxFailed` | the sandbox program itself could not be started (a refusal by the sandbox shows in `done`); a `start`/`pipe` with an `envelope` on a call that is not sandboxed (an envelope is a request for a bound; an unsandboxed call holds none); a `write: "roots"` or `exec: "program-only"` on Linux without Landlock |
| `SpawnFailed` | the OS refused to start the program |
| `PinChanged` | `start`/`pipe` of a call whose hashed path argument changed since its facts were read |
| `Busy` | 256 calls already wait for a verdict, or 32 are running (a `pipe` counts its stages) |
| `Failed` | reading held output failed on disk |
| `Refused` | over the hub only: the host's own checks refused the caller before the call was looked at; `reason` is `scope`, `revoked`, `stale` or `notACaller` (`docs/HUB.md`) |
| `TooLarge` | the answer would exceed 1 MiB (an `argv` that large, echoed back in the facts) |

## Not in v1, and where it will go

- On Linux, a transient cgroup per call (`memory.max`, `memory.swap.max=0`) so the kernel enforces the bound instead of
  the watchdog; needs a delegated cgroup subtree, which an unprivileged native host does not always have.

- A text pipe over held output (`ml.pipe` at the host): a call taking a `ptr` and a pipe string, answering a new `ptr`.
- Program manifests read by the host (root F): `effects`, `okCodes`, the operand terminator and the program's version
  fill in from the manifest; `pathArgs` becomes the manifest's.
- The container runner: `mode: "container"`, with `placement: "container"`.
- The hub transport: the same calls carried as sealed commands (the `hub` Cargo feature).
