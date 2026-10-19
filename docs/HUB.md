# The host on a hub

With the `hub` feature, `wmlhost` is also a desktop runtime on a window.ml hub: the same calls as over native
messaging, carried as sealed commands from a principal holding the `desktop` scope, so that a browser on another
machine (or an orchestrator) can run programs here. The design is window-ml's
[`SHELL.md`](https://github.com/parawanderer/window-ml/blob/main/docs/spec/SHELL.md) ("Where processes run") and
[`RUNTIME_HUB.md`](https://github.com/parawanderer/window-ml/blob/main/docs/spec/RUNTIME_HUB.md); the rulings this
follows are window-ml's coordinator's of 2026-10-19.

A hub is not an execution environment: the default build has no hub code (`tools/check-no-hub.sh`), and the hub
learns nothing about shells or processes beyond relaying sealed bytes.

## What is built

| Slice | What | State |
| --- | --- | --- |
| H1 | identity: keys, pairing as a runtime, the local roots and callers files, `wmlhost hub …` | done |
| H2 | serving: one session per caller over the same engine as native messaging; scope, revocation, callers | done |
| H3 | `done` published on a stream of the caller's own; a caller's session ending when its presence does | this |

## Pairing

```
wmlhost hub pair --hub wss://hub.example --label "the desktop"
```

prints a code and a fingerprint. The person types the code on the account's phone (the root, or a device it lets
pair), checks that the phone shows the same fingerprint, and confirms. The host asks to be a `Runtime` and refuses
an answer that names another principal, another agreement key, another role, or a chain that does not verify to the
root it names; nothing is stored then. Pairing again (`--again`) keeps the keys, so the host stays the same principal.

The flow is wmlbox's (window-ml-hub `crates/connector/src/pair.rs`), with the role changed.

## What only the person at this machine decides

Two files in the state directory (`$WMLHOST_HUB_DIR`, else `~/.config/wmlhost/hub`), written by `wmlhost hub`, `0600`
in a `0700` directory, and refused if anyone else can read them (as the keys are):

- **`hub-roots`**: the directories a caller over the hub may work in, one resolved absolute path a line
  (`wmlhost hub roots add <dir>`). No file is no roots, and every call is then `NotConfigured`. A caller's
  `configure` may only NARROW within these (H2): a root it names that is not under one of them is `BadRequest`.
- **`hub-callers`**: the principals that may call at all, one hex principal id a line (`wmlhost hub allow
  <principal>`, `disallow`). Empty refuses everyone, a valid `desktop` holder included. Holding `desktop` is not
  enough because a `may_pair` delegate anywhere in the account can mint a `desktop` holder; this file is the one
  statement about who drives this machine that the account's keys cannot produce.

A line in either file that is not what the host wrote (a relative path, a missing directory, a file, bad hex) is an
error naming the file and line, never skipped. `wmlhost hub status` prints the principal, the account, the
certificate's lifetime, the roots and the callers.

## Serving

```
wmlhost hub serve --hub wss://hub.example --hub-name hub.example
```

logs in as the paired `Runtime` and answers until the connection ends (a service manager restarts it). Each command's
body is one call of `docs/PROTOCOL.md` (`{ "seq", "call", "args" }`), and its answer, with the caller's own `seq`, is
sealed back as the command's result. Each caller gets a session of its own, over the same engine as native messaging,
so one caller's pending calls, held output and `configure` are invisible to another. Each also has its own owner
table (`owners/<principal>` in the state directory): the native one's `status` would show a remote caller the orphans,
and their owners, of the person's own sessions. What a session says unprompted (`done`) is published to its caller
alone ("Session events").

### The order of checks on a call

The seal opens first, in its own order (window-ml-hub `crates/seal`: size, HPKE, chain to the root with leaf ==
sender, signature, scope held, from/to/clock, nonce). A command that does not open is answered with nothing: nothing
about its sender is verified. Then the host, each refusal sealed back as `Refused` with a `reason` and spawning nothing:

1. the command is asked under `desktop` (`scope`);
2. the account's revocation list does not name the sender (`revoked`), and the list is fresh (`stale`). This is
   wmlbox's logic, used as a crate rather than copied (`wmlhub_connector::revoked`): the host follows every principal
   it sees holding `may_revoke`, applies their lists, and writes them to `revocations` and `revokers` in the state
   directory, so a restart still refuses. Once a revoker has been seen, a list more than seven days old refuses
   everyone, as a box connector stops granting its key: a hub that withholds the list causes an outage, not a bypass;
3. the sender is in `hub-callers` (`notACaller`), read again on every call, so `wmlhost hub disallow` holds at once.

Only then is the body routed. A body that is not a call is `BadRequest` with `seq: null`, and reaches no session.

### What `hello` tells a caller before it asks

Over the hub `hello` adds `transport: "hub"` and `hub: { roots, callers, revocationsAgeMs, events }`: the roots granted
here, how many principals may call, how old the held revocation list is (`null` while no revoker has been seen, so
nothing can go stale; past seven days every call is `stale`), and whether this caller will be given its session
events (it holds `view`). `sandbox` is the host's own fact as over native
messaging, so a caller learns that a machine without one cannot serve it before its first `configure`.

### What a caller cannot change

`configure` over the hub may only narrow: every root within `hub-roots` (else `BadRequest` naming it; no file is
`NotConfigured`), the sandbox on (`sandbox: false` is `BadRequest`), and a machine with no working sandbox refuses
every `configure` with `SandboxFailed`. Plain host mode is the person's choice at their own machine, never a remote
caller's.

### Session events

What a session says unprompted, `done` today, is published, never sent: the hub's one path for a runtime's unsolicited
output (window-ml's coordinator, 2026-10-19, Q2). Each caller has a stream of its own on the host's channels, named
from the account's channel key with the caller's principal as subject:

| Channel | Carries |
| --- | --- |
| `ChannelKey::channel("host.events", <caller>)` | each event, the JSON a native session would write, sealed as a stream frame |
| `ChannelKey::channel("host.keys", <caller>)` | the stream's key, wrapped to the caller's agreement key (retained) |

The key is granted only to the caller whose session it is, and only if its leaf holds `view`: another device of the
account can name the channels (it holds the channel key) and cannot open the grant. A caller without `view` is told
by `hello` (`events: false`) and its events go to nobody. Reading held output stays a call (`read`), answered to its
nonce.

One key per caller per `wmlhost hub serve` process, kept across that caller's sessions. The counter starts at the
clock in microseconds, so a restarted host's new key never repeats a counter a reader passed.

### A caller going away

A caller's presence going offline starts a grace of 30 s (chosen, not derived); back online, or a call from it, ends
the grace. Past it, the caller's session closes as a closed native port does: its calls meet their `onOwnerLoss`
policy. Only its own: each caller's owner table is its own (`owners/<principal>`), so what dies with one caller is
what that caller started, and another caller's calls run on.

Each caller's session also has a store of its own (held output and the calls' temp directories), as
`Host::from_system` gives it; a store shared by two callers' sessions collides on their calls' temp directories and
would let one `read` the other's output.
