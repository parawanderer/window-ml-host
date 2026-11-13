#!/bin/sh
# test-install.sh — the installer against a fake release served from a folder: the happy path, a tampered archive, a bad
# extension id, and an unknown browser. Needs a built target/release/wmlhost (cargo build --release).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"; root="$(dirname "$here")"
bin="$root/target/release/wmlhost"; [ -x "$bin" ] || { echo "build first: cargo build --release" >&2; exit 1; }
w="$(mktemp -d)"; trap 'rm -rf "$w"' EXIT
tag="v0.0.0"
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) target=x86_64-unknown-linux-gnu ;; Linux-aarch64) target=aarch64-unknown-linux-gnu ;;
    Darwin-arm64) target=aarch64-apple-darwin ;; Darwin-x86_64) target=x86_64-apple-darwin ;; *) echo "skip: no build target"; exit 0 ;;
esac
name="wmlhost-$tag-$target"
mkdir -p "$w/rel/$name" && cp "$bin" "$w/rel/$name/wmlhost"
tar -czf "$w/rel/$name.tar.gz" -C "$w/rel" "$name"
h="$( (sha256sum "$w/rel/$name.tar.gz" 2>/dev/null || shasum -a 256 "$w/rel/$name.tar.gz") | cut -d' ' -f1)"
for t in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu aarch64-apple-darwin x86_64-apple-darwin; do
    [ "$t" = "$target" ] && x="$h" || x="$(printf '%064d' 0)"
    echo "$x  wmlhost-$tag-$t.tar.gz"
done > "$w/SHA256SUMS"
"$here/render-install.sh" "$tag" "$w/SHA256SUMS" > "$w/install.sh"
id=abcdefghijklmnopabcdefghijklmnop
export HOME="$w/home" WMLHOST_BASE_URL="file://$w/rel"
mkdir -p "$HOME"
fail() { echo "FAIL: $*" >&2; exit 1; }

out="$(sh "$w/install.sh" --extension-id $id --browser chromium)" || fail "happy path: $out"
echo "$out" | grep -q 'sha256 verified' || fail "no verified line"
echo "$out" | grep -q 'uninstall --browser chromium' || fail "no undo line"
f="$(find "$HOME" -name com.parawanderer.window_ml_host.json)"; [ -n "$f" ] || fail "no manifest written"
grep -q "chrome-extension://$id/" "$f" || fail "manifest does not name the extension"
grep -q "\"path\": \"$HOME/.local/bin/wmlhost\"" "$f" || fail "manifest does not name the one installed path"
[ -x "$HOME/.local/bin/wmlhost" ] || fail "no binary at the one path"
echo "$out" | grep -q 'export PATH=' || fail "no PATH line though the folder is not on PATH"
"$HOME/.local/bin/wmlhost" --version >/dev/null || fail "the installed binary does not run"

# A folder with a space in it reaches wmlhost whole: the manifest names the whole path.
rm -f "$f"
out="$(WMLHOST_BIN_DIR="$w/with space/bin" sh "$w/install.sh" --extension-id $id --browser chromium)" || fail "a bin folder with a space: $out"
f="$(find "$HOME" -name com.parawanderer.window_ml_host.json)"
grep -q "\"path\": \"$w/with space/bin/wmlhost\"" "$f" || fail "the manifest does not name the whole path with a space"

echo tampered >> "$w/rel/$name.tar.gz"
rm -f "$f"
if out="$(sh "$w/install.sh" --extension-id $id 2>&1)"; then fail "a tampered archive installed"; fi
echo "$out" | grep -q 'sha256 mismatch' || fail "no mismatch message: $out"
[ -z "$(find "$HOME" -name com.parawanderer.window_ml_host.json)" ] || fail "manifest written after a mismatch"

for bad in "" "short" "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP" "abcdefghijklmnopabcdefghijklmnopq" "../../x"; do
    if sh "$w/install.sh" --extension-id "$bad" >/dev/null 2>&1; then fail "accepted id '$bad'"; fi
done
if sh "$w/install.sh" --extension-id $id --browser firefox >/dev/null 2>&1; then fail "accepted browser firefox"; fi
if sh "$w/install.sh" >/dev/null 2>&1; then fail "ran without an extension id"; fi
if sh "$w/install.sh" --extension-id $id --evil >/dev/null 2>&1; then fail "accepted unknown flag"; fi
echo "install.sh: ok"
