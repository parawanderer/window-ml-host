# Releases

How a `wmlhost` release is cut, what it publishes, and the pin window-ml holds against it. The workflow is
[`.github/workflows/release.yml`](../.github/workflows/release.yml).

## Cutting one

1. Set `version` in `Cargo.toml` to the new version, in a PR, and merge it.
2. Tag main's merge commit `v<version>` and push the tag (`git tag v0.7.0 <sha> && git push origin v0.7.0`).
3. The workflow builds each target from the TAG, checks that the binary reports the tag's version, runs
   `clients/node/smoke.mjs` against the unpacked binary, attests it, and publishes. A version that was not bumped fails
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

Targets: `x86_64-unknown-linux-gnu` (built on Ubuntu 24.04, so glibc 2.39 or newer), `aarch64-unknown-linux-gnu`
(Ubuntu 24.04 arm), `aarch64-apple-darwin` (macOS 14). Each is the default feature set: `native`, no `hub`. Linux needs
bubblewrap installed at run time; it is not shipped.

The binaries are not code-signed. Each archive has a build-provenance attestation: `gh attestation verify
<archive> --repo parawanderer/window-ml-host` checks that this workflow built it at that tag. That is provenance. What
a consumer gates on is a sha256 it pinned itself (below).

## A tag's bytes never change

The upload does not overwrite: if an asset already exists under the tag, the job fails. window-ml pins each archive's
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
