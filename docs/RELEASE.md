# Releases

How a `wmlhost` release is cut, what it publishes, and the pin window-ml holds against it. The workflow is
[`.github/workflows/release.yml`](../.github/workflows/release.yml).

## Cutting one

1. Set `version` in `Cargo.toml` to the new version, in a PR, and merge it.
2. Tag main's merge commit `v<version>` and push the tag (`git tag v0.7.0 <sha> && git push origin v0.7.0`).
3. The workflow builds each target from the TAG, checks that the binary reports the tag's version, runs
   `clients/node/smoke.mjs` against the unpacked binary, attests it, builds the describer's wasm and replays every
   shared vector through it, and publishes. A version that was not bumped fails
   the build before anything is published.

`workflow_dispatch` with a `tag` input builds an existing tag. It cannot replace assets the tag already has. A PR that
changes the workflow runs the build, version check and smoke test for every target (as `v` + Cargo.toml's version),
without attesting or publishing.

## What a release holds

| Asset | What it is |
| --- | --- |
| `wmlhost-<tag>-<target>.tar.gz` | a directory `wmlhost-<tag>-<target>/` holding `wmlhost`, `LICENSE`, `README.md` |
| `wmlhost-<tag>-<target>.tar.gz.sha256` | that archive's sha256, in `shasum -a 256` format |
| `SHA256SUMS` | every archive's sha256, one `<sha256>  <file>` line each, sorted by file name |
| `install.sh` | the installer with those hashes written in ([INSTALL.md](INSTALL.md)) |
| `describe.wasm` | the describer (`describe/`) compiled to `wasm32-unknown-unknown` for window.ml's service worker, opt-level `z` (the `wasm` profile); its ABI is in `describe-wasm/src/lib.rs` |
| `describe.wasm.sha256` | that file's sha256, in `shasum -a 256` format |
| `describe.json` | `{"commit": <the tag's commit>, "vectorPin": <VECTOR_PIN of tests/manifest_vectors.rs>, "sha256": <describe.wasm's>}` |

Targets: `x86_64-unknown-linux-gnu` (built on Ubuntu 24.04, so glibc 2.39 or newer), `aarch64-unknown-linux-gnu`
(Ubuntu 24.04 arm), `aarch64-apple-darwin` (macOS 15), `x86_64-apple-darwin` (Intel Mac, macOS 15 on the Intel runner). Each is the default feature set: `native`, no `hub`. Linux needs
bubblewrap installed at run time; it is not shipped.

The wasm is built on Ubuntu 24.04 with the pinned toolchain by `tools/build-describer.sh`, which `ci.yml` runs on every PR
too. The script replays every vector row through the built module (`tools/describe-replay.mjs`) before it writes the
assets, so a describer that diverges from the recorded vectors is never published. `describe.wasm` has a
build-provenance attestation like the archives; window-ml pins its sha256 beside the binary's, at the same tag, and
`vectorPin` tells it which vectors the build was held to.

The binaries are not code-signed. Each archive has a build-provenance attestation: `gh attestation verify
<archive> --repo parawanderer/window-ml-host` checks that this workflow built it at that tag. That is provenance. What
a consumer gates on is a sha256 it pinned itself (below).

## A tag's bytes never change

The repository has GitHub's immutable releases on, so a PUBLISHED release's assets and tag cannot be changed, added
to or deleted, by this workflow or by anyone. The workflow therefore makes the release as a draft with every asset in
it and then publishes it; it fails rather than touch a release that is already published. A draft left by a failed
run is filled by the re-run, since a draft is not public and nothing has pinned it. window-ml pins each archive's
sha256, so new bytes under an old tag would break every pin that names it, or, worse, satisfy a pin taken after the
change. A broken release is fixed with a new tag.

## The pin window-ml holds

window-ml does not trust the checksum files above at fetch time. It commits its own pin, reviewed in a window-ml PR,
and verifies every download against that:

```json
{
  "repo": "parawanderer/window-ml-host",
  "tag": "v0.7.0",
  "commit": "<the commit the tag points at>",
  "assets": {
    "x86_64-unknown-linux-gnu":  { "file": "wmlhost-v0.7.0-x86_64-unknown-linux-gnu.tar.gz",  "sha256": "<64 hex>" },
    "aarch64-unknown-linux-gnu": { "file": "wmlhost-v0.7.0-aarch64-unknown-linux-gnu.tar.gz", "sha256": "<64 hex>" },
    "aarch64-apple-darwin":      { "file": "wmlhost-v0.7.0-aarch64-apple-darwin.tar.gz",      "sha256": "<64 hex>" }
  }
}
```

`commit` lets a reviewer check the tag did not move: `git rev-parse v0.7.0^{commit}` here. `SHA256SUMS` is read only
when the pin is BUMPED. window-ml's `fetch-host --bump <tag>` hashes each archive itself and refuses unless the result
agrees with `SHA256SUMS`. The script, the pin file's name and the bump command belong to window-ml.
