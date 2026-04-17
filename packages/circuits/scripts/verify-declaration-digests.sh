#!/usr/bin/env bash
# Verify that the SHA-256 of the canonical declaration texts still match
# the constants pinned in DeclarationWhitelist.circom. Run from CI before
# every circuit build to catch drift between the source-of-truth fixture
# files and the in-circuit whitelist.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCOM="${HERE}/../circuits/binding/DeclarationWhitelist.circom"
DIGESTS="${HERE}/../../../fixtures/declarations/digests.json"
EN_FILE="${HERE}/../../../fixtures/declarations/en.txt"
UK_FILE="${HERE}/../../../fixtures/declarations/uk.txt"

for f in "${CIRCOM}" "${DIGESTS}" "${EN_FILE}" "${UK_FILE}"; do
  [[ -f "${f}" ]] || { echo "missing: ${f}" >&2; exit 1; }
done

en_actual=$(sha256sum "${EN_FILE}" | awk '{print $1}')
uk_actual=$(sha256sum "${UK_FILE}" | awk '{print $1}')

# Pull the digests pinned in the circom file (header comment).
en_pinned=$(grep -oE '0x[0-9a-f]{64}' "${CIRCOM}" | head -1 | sed 's/^0x//')
uk_pinned=$(grep -oE '0x[0-9a-f]{64}' "${CIRCOM}" | sed -n '2p' | sed 's/^0x//')

# Pull from digests.json for cross-check.
en_json=$(grep -oE '0x[0-9a-f]{64}' "${DIGESTS}" | head -1 | sed 's/^0x//')
uk_json=$(grep -oE '0x[0-9a-f]{64}' "${DIGESTS}" | sed -n '2p' | sed 's/^0x//')

fail=0
check() {
  local label=$1 actual=$2 pinned=$3 json=$4
  if [[ "${actual}" != "${pinned}" ]]; then
    echo "DRIFT: ${label} actual ${actual} != pinned ${pinned}" >&2
    fail=1
  fi
  if [[ "${actual}" != "${json}" ]]; then
    echo "DRIFT: ${label} actual ${actual} != digests.json ${json}" >&2
    fail=1
  fi
  echo "${label} OK: ${actual}"
}

check EN "${en_actual}" "${en_pinned}" "${en_json}"
check UK "${uk_actual}" "${uk_pinned}" "${uk_json}"

if (( fail )); then
  echo "Declaration digest drift detected. Re-run regen-declaration-whitelist.ts and bump circuit version." >&2
  exit 2
fi
echo "All declaration digests match."
