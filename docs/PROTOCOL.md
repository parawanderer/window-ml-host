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
{ "host": "window-ml-host", "version": "0.1.0", "protocol": 1, "platform": "macos",
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
        "timeoutMs": 30000 }                  // optional, at most 3600000
```

The answer is the RESOLVED FACTS, everything a policy is given about the call (`SHELL.md`, "What it is given"):

```jsonc
{ "id": "c3",                                   // names this pending call for start / discard
  "argv": ["git", "diff", "--stat", "HEAD~1"],
  "program": { "path": "/usr/bin/git", "inRoot": false },   // argv[0] after PATH lookup, realpath'd
  "cwd": { "path": "/Users/me/src/proj", "inRoot": true },
  "env": { "set": ["LC_ALL"], "secrets": [] },  // names only: what the call changes from the base, and which are handles
  "paths": [{ "arg": 3, "given": "HEAD~1", "path": "/Users/me/src/proj/HEAD~1",
              "inRoot": true, "secret": false, "exists": false }],
  "effects": "unknown",                         // from the program manifest once one exists (root F); "unknown" until then
  "mode": "host",
  "sandboxed": true,
  "placement": "host-sandbox",                  // "host-sandbox" | "host-plain": the enforcer whose bound applies (EFFECTS.md)
  "expiresInMs": 1800000 }                      // after this the id is gone and start fails UnknownId
```

- **`pathArgs`** entries are `{ "arg": i }` (the whole argument is a path) or `{ "arg": i, "split": "=" }` (the part
  after the first `=`, for `--output=f`). The host resolves only the arguments it is told are paths: an argument nobody
  marked is not a path the host can vouch for, and the worker treats the call accordingly. Root F moves this list into
  the program manifests, which the host will also read.
- **A path is resolved with `realpath` against `cwd`.** One that does not exist yet is its deepest existing ancestor's
  realpath plus the rest, and is never `inRoot` if the rest contains `..`. A symlink is followed, so one pointing out of
  a root is `inRoot: false`.
- **`secret`** is the host's name check (`.env`, `*.pem`, `id_*`, `.ssh/`, …; the list is `SECRET_PATTERNS` in
  `src/facts.rs`) on the resolved path and on the path as given.
- **Refused at spawn, whatever a policy would say** (these are enforcement, not decisions): `cwd` outside every root
  (`CwdOutsideRoots`); an `env` name on the denylist (`EnvRefused`); a secret handle the host's store does not hold
  (`SecretUnavailable`, always this round: the store is empty); `argv[0]` not found (`ProgramNotFound`); `mode:
  "container"` (`Unsupported`, until a runner exists).

### `start`: run it

`args: { "id": "c3" }` → `{ "id": "c3", "pid": 4242 }`, then a `done` event when it ends. Sent by the worker only after
its verdict. **The host spawns nothing without it.** A second `start` of the same id fails `UnknownId`.

What the host enforces whatever the verdict was: argv executed directly with no shell, `program.path` executed (so a
`PATH` change in between cannot swap it), stdin closed, no terminal, a new process group, the scrubbed environment, the
time limit, the output cap, and the OS sandbox when `sandboxed` was true. If the sandbox then fails to start, the call
fails (`SandboxFailed`); it never falls back to running unsandboxed.

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

Bytes, not text: output is whatever the program wrote. `data` is `{ "$bytes": <base64> }`, the form the `ml` wire uses for bytes. 512 KiB is 683 KiB as base64, inside the 1 MiB message limit.

### `release`

`args: { "ptr": "out:9f2e…" }` → `{}`. Deletes held output early; everything is deleted when the session ends anyway.

### The `done` event

```jsonc
{ "event": "done", "id": "c3",
  "code": 0, "signal": null,                  // code null when killed by a signal ("SIGKILL")
  "ok": true,                                 // code is in okCodes; okCodes is [0] until manifests (root F)
  "timedOut": false, "cancelled": false, "durationMs": 31,
  "stdout": { "ptr": "out:…", "size": 812, "sha256": "…", "truncated": false },
  "stderr": { "ptr": "out:…", "size": 0, "sha256": "…", "truncated": false } }
```

`{ code, ok, stdout, stderr }` is the result shape `ml.sh.run` returns, with `stdout`/`stderr` as pointers. `truncated`
means the stream passed the output cap: the host kept the first `outputCap` bytes and drained the rest so the program was
not blocked.

## Error codes

These are the host's own; the worker maps them onto the `ml` wire's codes (`Refused`, `Denied`, `BadRequest`, `Failed`, …) when it answers a script.

| Code | When |
| --- | --- |
| `BadRequest` | malformed message, unknown call, a field of the wrong type |
| `NotConfigured` | `spawn` before `configure` |
| `BadRoot` | a root that is not an absolute existing directory, or is `/` |
| `ProgramNotFound` | `argv[0]` not found on `PATH`, or not an executable file |
| `CwdOutsideRoots` | `cwd` missing, not a directory, or resolving outside every root |
| `EnvRefused` | an `env` name on the denylist (`src/env.rs`) |
| `SecretUnavailable` | an `env` handle the host's store does not hold |
| `Unsupported` | `mode: "container"` this version |
| `UnknownId` | `start`/`discard`/`cancel` of an id that never existed, expired, or already started (`start`) |
| `UnknownPtr` | `read`/`release` of a pointer that does not exist |
| `SandboxFailed` | `start` of a sandboxed call whose sandbox did not start |
| `SpawnFailed` | the OS refused to start the program |

## Not in v1, and where it will go

- `pipe` (stages joined by real OS pipes, one approval) and `glob` (host-side expansion within the roots): both are calls
  of this protocol, answering the same facts per stage.
- A text pipe over held output (`ml.pipe` at the host): a call taking a `ptr` and a pipe string, answering a new `ptr`.
- Program manifests read by the host (root F): `effects`, `okCodes`, the operand terminator and the program's version
  fill in from the manifest; `pathArgs` becomes the manifest's.
- The container runner: `mode: "container"`, with `placement: "container"`.
- The hub transport: the same calls carried as sealed commands (the `hub` Cargo feature).
