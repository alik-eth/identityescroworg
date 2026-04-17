#!/usr/bin/env bash
# Pinned circom version for reproducibility.
# Install via: cargo install --git https://github.com/iden3/circom.git --tag v2.1.9
set -euo pipefail

REQUIRED="2.1.9"

if ! command -v circom >/dev/null 2>&1; then
  echo "circom not found. Install with:"
  echo "  cargo install --git https://github.com/iden3/circom.git --tag v${REQUIRED}"
  exit 1
fi

INSTALLED=$(circom --version | awk '{print $NF}')
if [ "${INSTALLED}" != "${REQUIRED}" ]; then
  echo "circom ${INSTALLED} found, but ${REQUIRED} required."
  echo "Reinstall with:"
  echo "  cargo install --git https://github.com/iden3/circom.git --tag v${REQUIRED} --force"
  exit 1
fi

echo "circom ${INSTALLED} OK"
