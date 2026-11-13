#!/bin/sh
# render-install.sh — writes install.sh for one release: tools/install.sh.in with the tag and the three archives' sha256
# taken from that release's SHA256SUMS. Refuses to render if any is missing.
# Usage: tools/render-install.sh <tag> <SHA256SUMS> > install.sh
set -eu
[ $# -eq 2 ] || { echo "usage: render-install.sh <tag> <SHA256SUMS>" >&2; exit 2; }
tag="$1"; sums="$2"
here="$(cd "$(dirname "$0")" && pwd)"
hash_of() {
    h="$(awk -v f="wmlhost-$tag-$1.tar.gz" '$2 == f { print $1 }' "$sums")"
    case "$h" in *[!0-9a-f]*|"") echo "render-install: no sha256 for wmlhost-$tag-$1.tar.gz in $sums" >&2; exit 1 ;; esac
    [ "${#h}" -eq 64 ] || { echo "render-install: bad sha256 for $1" >&2; exit 1; }
    printf '%s' "$h"
}
a="$(hash_of x86_64-unknown-linux-gnu)"; b="$(hash_of aarch64-unknown-linux-gnu)"; c="$(hash_of aarch64-apple-darwin)"
sed -e "s/@TAG@/$tag/g" -e "s/@SHA_X86_64_LINUX@/$a/" -e "s/@SHA_AARCH64_LINUX@/$b/" -e "s/@SHA_AARCH64_MACOS@/$c/" "$here/install.sh.in"
