#!/usr/bin/env bash
# build-describer.sh — builds the describer's wasm with the `wasm` profile, replays every shared vector through it, and
# writes describe.wasm, describe.wasm.sha256 and describe.json into <out-dir> (default dist-describer/). CI and the
# release run this one script, so what CI proves is what a tag ships. Needs the wasm32-unknown-unknown target of the
# pinned toolchain (`rustup target add wasm32-unknown-unknown`).
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:-dist-describer}"

cargo build -p describe-wasm --profile wasm --target wasm32-unknown-unknown --locked
built=target/wasm32-unknown-unknown/wasm/describe_wasm.wasm

# A divergence from the recorded vectors stops here, before anything is written.
node tools/describe-replay.mjs "$built"
# And from the reply pin the native describer is held to: every hostile and malformed shape, through the same ABI, plus
# the two properties only the artifact shows (nothing imported, no request a trap).
node tools/describe-replies.mjs "$built"

mkdir -p "$out"
cp "$built" "$out/describe.wasm"
( cd "$out" && shasum -a 256 describe.wasm > describe.wasm.sha256 )
sha=$(cut -d' ' -f1 "$out/describe.wasm.sha256")
pin=$(sed -n 's/^const VECTOR_PIN: &str = "\([0-9a-f]\{64\}\)";$/\1/p' tests/manifest_vectors.rs)
[ -n "$pin" ] || { echo "VECTOR_PIN not found in tests/manifest_vectors.rs" >&2; exit 1; }
printf '{"commit":"%s","vectorPin":"%s","sha256":"%s"}\n' "$(git rev-parse HEAD)" "$pin" "$sha" > "$out/describe.json"
echo "describe.wasm: $(wc -c < "$out/describe.wasm" | tr -d ' ') bytes, sha256 $sha"
