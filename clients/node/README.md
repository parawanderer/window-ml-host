# Node client for wmlhost

`wmlhost-client.mjs` speaks the host's native messaging protocol (`docs/PROTOCOL.md`) from Node >= 20, with no dependencies. The framing (`encodeFrame`, `FrameDecoder`, `spawnHost`) is separate from the call layer (`HostClient`, which takes any `{ send, onMessage }`), so the call layer can run over `chrome.runtime.connectNative` too.

Smoke check, against a debug build:

    cargo build
    node clients/node/smoke.mjs target/debug/wmlhost

Framing unit tests: `node --test 'clients/node/*.test.mjs'` (newer Node takes globs, not a bare directory).
