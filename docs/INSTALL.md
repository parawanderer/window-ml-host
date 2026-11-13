# Installing the host

Each release carries `install.sh`, written by the release workflow with the sha256 of that release's three archives
inside it (`tools/render-install.sh`, from `tools/install.sh.in`). window.ml's Settings, Programs (ml.sh), shows the line
with the version and the extension's own id filled in:

```sh
curl -fsSL https://github.com/parawanderer/window-ml-host/releases/download/v0.10.0/install.sh | sh -s -- --extension-id <32 letters a-p>
```

The version is in the URL, so the line names the bytes it runs; a release never changes after publication (RELEASE.md).
The script takes the id as an argument and never guesses it; add `--browser chrome|chrome-beta|chromium|brave|edge|all`
(repeatable) to register another browser than Chrome.

What it does, in order, and prints:

1. Picks the archive for this machine: x86_64 or aarch64 Linux, Apple-silicon macOS. Any other platform stops with
   "no window-ml-host build for ...".
2. Downloads that archive from the same release and checks its sha256 against the hash written into the script. A
   mismatch stops it before anything is unpacked.
3. Unpacks it to `${XDG_DATA_HOME:-~/.local/share}/window-ml-host/wmlhost-<tag>-<target>/`.
4. Runs `wmlhost install --extension-id <id>`, which writes the native messaging manifest naming that binary and allowing
   only that extension.

It needs no root and touches nothing else. To undo it, run the two lines it prints at the end: `<binary> uninstall`
(add the same `--browser` flags) and `rm -rf` of the folder above.

Trust: the sha256 is checked against the script, and the script comes from the same immutable release as the archive, so
this guards against a corrupted or swapped download, not against a compromised release. Compare with the pin window-ml's
CI holds in `tools/host-dist.json`, which is reviewed separately.

The template in the repository (`tools/install.sh.in`) refuses to run. `tools/test-install.sh` runs the rendered script
against a fake release (happy path, a tampered archive, a malformed id, an unknown browser); CI runs it on Linux and macOS.
