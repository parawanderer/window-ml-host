#!/usr/bin/env bash
# check-no-hub.sh — the default build compiles no crate from the hub; the `hub` feature build still pulls them in.
set -euo pipefail

cd "$(dirname "$0")/.."

tree() {
  cargo tree --locked -e normal,build --prefix none --format '{p}' "$@"
}

default_out=$(tree)
offenders=$(grep '^wmlhub' <<<"$default_out" | awk '{print $1}' | sort -u || true)
if [ -n "$offenders" ]; then
  echo "FAIL: the default build compiles hub crates:" >&2
  echo "$offenders" | sed 's/^/  /' >&2
  exit 1
fi

hub_out=$(tree --features hub)
if ! grep -q '^wmlhub-client' <<<"$hub_out"; then
  echo "FAIL: --features hub does not pull in wmlhub-client; the check would pass vacuously" >&2
  exit 1
fi

echo "ok: the default build has no wmlhub-* crate; --features hub pulls in wmlhub-client"
