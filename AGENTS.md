# AGENTS.md: window-ml-host

window.ml's process host. What it is: [README.md](README.md). It is one part of
[window-ml](https://github.com/parawanderer/window-ml), and **window-ml's AGENTS.md holds the rules that apply to both**
(branch + PR + CI, one clone per session, every GitHub post naming its session). This file holds only what is specific
here. The design stays in window-ml's `docs/spec/` (`SHELL.md`, `PROGRAM_MANIFEST.md`, `EFFECTS.md`); do not copy it
here, link to it.

## Invariants (do not regress these)

- **The host never decides.** `spawn` resolves facts and starts nothing; only `start` for that id runs it. A policy, a
  free tier or a cache of verdicts does not belong in this repository.
- **It enforces whatever the verdict was**: argv without a shell, the resolved program path, stdin closed, the scrubbed
  environment, `cwd` inside a root, the time limit, the output cap, the process group killed with the call.
- **The sandbox fails closed.** Unavailable: say `sandboxed: false`. Failed to start: the call fails. Never retry a
  call unsandboxed.
- **stdout carries only protocol frames.** Log to stderr.
- **Every message to the extension stays under 1 MiB**; output crosses only through `read`.
- **The default build compiles no hub crate** (`tools/check-no-hub.sh`). Anything that knows what a hub is sits behind
  the `hub` feature.
- **A secret's value never crosses the protocol**: handles by name only, resolved at spawn by the host's store.
- **No `unsafe`** (forbidden in `Cargo.toml`; `rustix` provides the syscalls safely).

## Working here

- A change to the sandbox profile comes with a test in `tests/stdio.rs` that FAILS against the old profile, and a line
  in `docs/SANDBOX.md`'s table. A sandbox test that cannot fail proves nothing; check it against a weakened profile.
- A change to the wire is a change to `docs/PROTOCOL.md` in the same commit, and to `clients/node/`.
- `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test` before a commit; CI runs them on Linux and macOS.
