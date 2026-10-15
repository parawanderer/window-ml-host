# window-ml-host

The process host for [window.ml](https://github.com/parawanderer/window-ml): a native program that the extension
reaches over Chrome's native messaging to run programs on this machine. The extension sends an argv; the host answers
with the RESOLVED FACTS (the program after `PATH` lookup, `cwd` and path arguments against the workspace roots, the
secret flags, whether the OS sandbox applies); the extension's worker decides; the host runs the call only on an
explicit `start`, under the OS sandbox, and keeps its output as pointers read by range.

The design is window-ml's [`SHELL.md`](https://github.com/parawanderer/window-ml/blob/main/docs/spec/SHELL.md). This
repository holds:

- [`docs/PROTOCOL.md`](docs/PROTOCOL.md): the wire, call by call.
- [`docs/SANDBOX.md`](docs/SANDBOX.md): what a sandboxed call may and may not do on macOS and Linux, what the tests
  show, the limits, and what container mode will need.
- `clients/node/`: a dependency-free Node client and a smoke check.

## Build, test, install

```bash
cargo build --release              # target/release/wmlhost; no hub code (the `hub` feature is off by default)
cargo test                         # unit tests, and tests/stdio.rs driving the binary over stdio
node --test clients/node/*.test.mjs && node clients/node/smoke.mjs target/release/wmlhost
target/release/wmlhost install --extension-id <the extension's 32-letter id> [--browser chrome|brave|…|all]
```

`install` writes the native messaging host manifest (`com.parawanderer.window_ml_host`) naming this binary and allowing
only that extension. `wmlhost uninstall` removes it.

The extension does not use the host yet: its side waits on the `ml` wire protocol (window-ml's `ML_WIRE.md`).

## Hub

A hub is not an execution environment, and an execution environment is not a hub. `cargo build` with default
features compiles no crate from [window-ml-hub](https://github.com/parawanderer/window-ml-hub)
(`tools/check-no-hub.sh`, in CI); the hub transport will be the optional `hub` feature.
