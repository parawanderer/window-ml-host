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
| H1 | identity: keys, pairing as a runtime, the local roots and callers files, `wmlhost hub …` | this |
| H2 | serving: one session per caller over the same engine as native messaging; scope, revocation, callers | next |
| H3 | `done` and the other session events published on the host's channel; a caller's session ending | after |

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

## The order of checks on a call (H2)

The seal opens first, in its own order (window-ml-hub `crates/seal`: size, HPKE, chain to the root with leaf ==
sender, signature, scope held, from/to/clock, nonce). Then the host: the declared scope is `desktop`, the sender is
not revoked, the sender is in `hub-callers`, and only then is the body routed. A refusal at any step is sealed back
and spawns nothing.
