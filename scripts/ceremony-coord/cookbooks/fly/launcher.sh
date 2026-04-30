#!/bin/bash
# zk-QES V5 Phase 2 ceremony — one-command interactive Fly.io launcher.
#
# Hosted at: https://prove.identityescrow.org/ceremony/fly-launch.sh
#
# Usage (inspect-before-run recommended):
#   curl -sSL https://prove.identityescrow.org/ceremony/fly-launch.sh -o fly-launch.sh
#   cat fly-launch.sh        # read what you are about to run
#   bash fly-launch.sh
#
# Pipe-safe shortcut (if you trust the host):
#   curl -sSL https://prove.identityescrow.org/ceremony/fly-launch.sh | bash
#
# What you need: flyctl (offered below if missing). Nothing else.
# Docker, Node.js, and this repository are NOT required.
# The ceremony image is pulled by Fly's infrastructure from GHCR.
#
# SECURITY: set +x is unconditional. CONTRIBUTOR_ENTROPY is read with
# echo suppressed and is never written to disk or logged by this script.

set +x
set -euo pipefail

GHCR_IMAGE="ghcr.io/identityescroworg/qkb-ceremony:v1"
DEFAULT_REGION="fra"

# ── helpers ──────────────────────────────────────────────────────────────────
# All terminal I/O goes through /dev/tty so the script works when stdin is
# the pipe itself (curl ... | bash).

tty_print()  { printf '%s\n' "$*" >/dev/tty; }
tty_printf() { printf '%s'   "$*" >/dev/tty; }

ask() {
  # ask <prompt> <varname> [default]
  local prompt="$1" varname="$2" default="${3:-}"
  if [ -n "$default" ]; then
    tty_printf "${prompt} [${default}]: "
  else
    tty_printf "${prompt}: "
  fi
  IFS= read -r "${varname?}" </dev/tty
  if [ -z "${!varname}" ] && [ -n "$default" ]; then
    printf -v "$varname" '%s' "$default"
  fi
}

ask_secret() {
  # ask_secret <prompt> <varname>  — input is not echoed
  local prompt="$1" varname="$2"
  tty_printf "${prompt} (not echoed): "
  IFS= read -rs "${varname?}" </dev/tty
  tty_print ""   # newline after silent read
}

die() {
  tty_print ""
  tty_print "ERROR: $*"
  exit 1
}

confirm_proceed() {
  tty_printf "$* [y/N]: "
  local ans
  IFS= read -r ans </dev/tty
  [ "$ans" = "y" ] || [ "$ans" = "Y" ]
}

# ── flyctl prerequisite ───────────────────────────────────────────────────────

if ! command -v flyctl >/dev/null 2>&1; then
  tty_print "flyctl is not installed."
  if confirm_proceed "Install it now via fly.io/install.sh?"; then
    curl -fsSL https://fly.io/install.sh | sh
    # fly installs to ~/.fly/bin by default
    export PATH="${HOME}/.fly/bin:${PATH}"
    command -v flyctl >/dev/null 2>&1 \
      || die "Installation did not add flyctl to PATH. Restart your shell and re-run, or install manually: https://fly.io/docs/hands-on/install-flyctl/"
    tty_print "flyctl installed."
  else
    die "flyctl required. Install from: https://fly.io/docs/hands-on/install-flyctl/"
  fi
fi

# ── banner ────────────────────────────────────────────────────────────────────

cat >/dev/tty <<'BANNER'

================================================================
 zk-QES V5 Phase 2 trusted-setup ceremony
 Fly.io launcher

 This script will:
   1. Collect your round details (provided by the coordinator).
   2. Generate your entropy — the one value that comes from you.
   3. Spin up a Fly machine with 4 vCPUs and 32 GB RAM.
   4. Run the full contribute → verify → upload pipeline.
   5. Print your attestation hash and offer to destroy the app.

 No Docker or repository clone required.
 The ceremony image is pulled directly from GitHub Container Registry
 by Fly's infrastructure.

 Time: ~45-60 min total (mostly network + compute).
 Cost: under $0.30, covered by Fly's free-tier credit.
================================================================

BANNER

# ── collect inputs ────────────────────────────────────────────────────────────

tty_print "--- Your identity ---"
ask "Fly handle (e.g. alice, bob-eth)" CONTRIBUTOR_HANDLE
[[ -n "$CONTRIBUTOR_HANDLE" ]] || die "Handle is required."
[[ "$CONTRIBUTOR_HANDLE" =~ ^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$ ]] \
  || die "Handle must be lowercase letters, numbers, and hyphens (no leading/trailing hyphen)."

ask "Region" FLY_REGION "${DEFAULT_REGION}"

tty_print ""
tty_print "--- Round details (from the coordinator's DM) ---"
ask "Round number" ROUND
[[ "$ROUND" =~ ^[1-9][0-9]*$ ]] || die "Round must be a positive integer (≥ 1)."

ask "PREV_ROUND_URL (previous contributor's zkey download URL)" PREV_ROUND_URL
[[ -n "$PREV_ROUND_URL" ]] || die "PREV_ROUND_URL is required."

ask "R1CS_URL" R1CS_URL
[[ -n "$R1CS_URL" ]] || die "R1CS_URL is required."

ask "PTAU_URL" PTAU_URL
[[ -n "$PTAU_URL" ]] || die "PTAU_URL is required."

ask "SIGNED_PUT_URL (your single-use upload URL)" SIGNED_PUT_URL
[[ -n "$SIGNED_PUT_URL" ]] || die "SIGNED_PUT_URL is required."

tty_print ""
tty_print "--- Your public attestation name ---"
tty_print "(appears in the public contribution log at prove.identityescrow.org)"
ask "Contributor name" CONTRIBUTOR_NAME
[[ -n "$CONTRIBUTOR_NAME" ]] || die "Contributor name is required."

tty_print ""
tty_print "--- Your entropy ---"
tty_print "This is the ONLY value that must come from YOUR machine."
tty_print "Fly runs the math; the randomness comes from you."
tty_print ""
tty_print "Generate on your machine with:"
tty_print "  openssl rand -hex 32"
tty_print ""
tty_print "Paste it below. Input is not echoed or logged."
ask_secret "Entropy (32-byte hex)" CONTRIBUTOR_ENTROPY
[[ -n "$CONTRIBUTOR_ENTROPY" ]] || die "Entropy is required."
[[ ${#CONTRIBUTOR_ENTROPY} -ge 32 ]] \
  || die "Entropy looks too short (got ${#CONTRIBUTOR_ENTROPY} chars; openssl rand -hex 32 produces 64)."

APP="qkb-ceremony-${CONTRIBUTOR_HANDLE}"

# ── confirmation ──────────────────────────────────────────────────────────────

cat >/dev/tty <<CONFIRM

================================================================
 Summary (verify before proceeding)
   Fly app:     ${APP}
   Region:      ${FLY_REGION}
   Round:       ${ROUND}
   Contributor: ${CONTRIBUTOR_NAME}
   Entropy:     (set — ${#CONTRIBUTOR_ENTROPY} chars, not displayed)
   Image:       ${GHCR_IMAGE}
================================================================
CONFIRM

confirm_proceed "Proceed with launch?" || { tty_print "Aborted."; exit 0; }

# ── 1. Auth ───────────────────────────────────────────────────────────────────

tty_print ""
tty_print "[1/4] Checking Fly authentication..."
if ! flyctl auth whoami >/dev/null 2>&1; then
  tty_print "Not logged in. Opening browser for Fly login..."
  flyctl auth login
fi
tty_print "      Auth OK."

# ── 2. Create app ─────────────────────────────────────────────────────────────

tty_print ""
tty_print "[2/4] Creating Fly app ${APP}..."
if flyctl apps create "${APP}" --region "${FLY_REGION}" 2>/dev/null; then
  tty_print "      App created."
else
  tty_print "      App already exists (continuing)."
fi

# ── 3. Set secrets ────────────────────────────────────────────────────────────

tty_print ""
tty_print "[3/4] Setting Fly secrets (entropy encrypted at rest)..."
flyctl secrets set \
  "ROUND=${ROUND}" \
  "PREV_ROUND_URL=${PREV_ROUND_URL}" \
  "R1CS_URL=${R1CS_URL}" \
  "PTAU_URL=${PTAU_URL}" \
  "SIGNED_PUT_URL=${SIGNED_PUT_URL}" \
  "CONTRIBUTOR_NAME=${CONTRIBUTOR_NAME}" \
  "CONTRIBUTOR_ENTROPY=${CONTRIBUTOR_ENTROPY}" \
  --app "${APP}" \
  --stage
tty_print "      Secrets staged."

# ── 4. Deploy ─────────────────────────────────────────────────────────────────

tty_print ""
tty_print "[4/4] Deploying ceremony machine..."
tty_print "      Image: ${GHCR_IMAGE}"
tty_print "      Size:  performance-cpu-4x / 32 GB RAM / 60 GB scratch"
tty_print "      (No local Docker build — image pulled by Fly from GHCR.)"
tty_print ""

# Write a minimal fly.toml to a temp dir so flyctl deploy has the full
# machine config. The --image flag skips any local Dockerfile build.
WORK_DIR=$(mktemp -d)
# Clean up temp dir on exit (not on Ctrl-C so the partial deploy is inspectable)
trap 'rm -rf "${WORK_DIR}"' EXIT

cat > "${WORK_DIR}/fly.toml" <<TOML
# Auto-generated by fly-launch.sh — not committed.
app            = "${APP}"
primary_region = "${FLY_REGION}"

[processes]
  contribute = "/entrypoint.sh"

[[vm]]
  size      = "performance-cpu-4x"
  memory    = "32gb"
  processes = ["contribute"]

[[mounts]]
  source       = "ceremony_scratch"
  destination  = "/data"
  initial_size = "60gb"
  processes    = ["contribute"]
TOML

flyctl deploy \
  --config   "${WORK_DIR}/fly.toml" \
  --image    "${GHCR_IMAGE}" \
  --vm-size  performance-cpu-4x \
  --vm-memory 32768 \
  --strategy immediate \
  --app      "${APP}"

# ── tail logs ─────────────────────────────────────────────────────────────────

cat >/dev/tty <<'LOGBANNER'

================================================================
 Ceremony machine running.

 Watching logs (30-45 min). When you see:

   === SAVE THIS — attestation hash for round N ===
   <64-character sha256>
   ================================================

 Copy that hash and send it to the coordinator.
 Then press Ctrl-C to stop watching logs.
================================================================

LOGBANNER

flyctl logs --app "${APP}" || true

# ── post-run ──────────────────────────────────────────────────────────────────

cat >/dev/tty <<'POSTHASH'

================================================================
 Before destroying the app, confirm you have:
   - Copied the attestation hash
   - Sent it to the coordinator (Alik.eth)
================================================================
POSTHASH

if confirm_proceed "Destroy the app now (recommended)?"; then
  flyctl apps destroy "${APP}" --yes
  tty_print ""
  tty_print "App destroyed. No artefacts remain on Fly infrastructure."
else
  tty_print ""
  tty_print "Remember to destroy the app when you are done:"
  tty_print "  flyctl apps destroy ${APP} --yes"
fi

tty_print ""
tty_print "Thank you for contributing to the zk-QES V5 trusted-setup ceremony."
tty_print "Your round will be verified and published to the public status feed"
tty_print "at https://prove.identityescrow.org/ceremony/status.json"
tty_print ""
