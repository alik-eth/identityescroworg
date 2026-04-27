#!/usr/bin/env bash
# Cross-compile the qkb CLI to single-file native binaries via `bun build --compile`.
# Produces five targets under `packages/qkb-cli/dist-binaries/`. Locally only the
# host architecture's binary will run; the others are emitted for CI release.
#
# Usage:
#   pnpm -F @qkb/cli build:binaries           # all five
#   ./scripts/build-binaries.sh               # all five (direct)
#   QKB_BUILD_TARGETS=linux-x64 ./scripts/build-binaries.sh   # one
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
DIST="$HERE/dist-binaries"
ENTRY="$HERE/src/cli.ts"

if ! command -v bun >/dev/null 2>&1; then
  echo "error: bun is required (https://bun.sh — brew install oven-sh/bun/bun)" >&2
  exit 1
fi

mkdir -p "$DIST"

# label : bun --target value
ALL_TARGETS=(
  "linux-x64:bun-linux-x64"
  "linux-arm64:bun-linux-arm64"
  "darwin-x64:bun-darwin-x64"
  "darwin-arm64:bun-darwin-arm64"
  "windows-x64:bun-windows-x64"
)

# Allow callers to filter to a single label via QKB_BUILD_TARGETS=linux-x64.
if [[ -n "${QKB_BUILD_TARGETS:-}" ]]; then
  TARGETS=()
  for spec in "${ALL_TARGETS[@]}"; do
    label="${spec%%:*}"
    case ",$QKB_BUILD_TARGETS," in
      *",$label,"*) TARGETS+=("$spec") ;;
    esac
  done
  if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "error: QKB_BUILD_TARGETS=$QKB_BUILD_TARGETS matched no known target" >&2
    echo "known: linux-x64 linux-arm64 darwin-x64 darwin-arm64 windows-x64" >&2
    exit 1
  fi
else
  TARGETS=("${ALL_TARGETS[@]}")
fi

for spec in "${TARGETS[@]}"; do
  label="${spec%%:*}"
  bunTarget="${spec##*:}"
  ext=""
  if [[ "$label" == "windows-x64" ]]; then
    ext=".exe"
  fi
  out="$DIST/qkb-$label$ext"
  echo "→ building qkb-$label ($bunTarget)"
  bun build "$ENTRY" \
    --compile \
    --target="$bunTarget" \
    --outfile "$out"
done

echo
echo "Built binaries:"
ls -la "$DIST"
