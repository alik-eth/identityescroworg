#!/bin/bash
# zk-QES V5 Phase 2 ceremony — interactive Fly.io launcher.
#
# Hosted at: https://prove.identityescrow.org/ceremony/fly-launch.sh
#
# Recommended usage (inspect before running):
#   curl -fsSL https://prove.identityescrow.org/ceremony/fly-launch.sh -o fly-launch.sh
#   cat fly-launch.sh
#   bash fly-launch.sh
#
# Pipe shortcut (if you trust the host):
#   curl -fsSL https://prove.identityescrow.org/ceremony/fly-launch.sh | bash
#
# Requires:
#   flyctl   — https://fly.io/docs/hands-on/install-flyctl/
#   openssl  — pre-installed on macOS/Linux; used for entropy generation
#
# Does NOT require: Docker, Node.js, or this repository.
# The ceremony image is pulled by Fly's infrastructure from GHCR.
#
# SECURITY: set +x is unconditional and permanent. CONTRIBUTOR_ENTROPY is
# never written to disk, never echoed, and never appears in this script's
# stdout or stderr. It is stored in Fly's HSM-backed encrypted secrets store.

set +x
set -euo pipefail

GHCR_IMAGE="ghcr.io/identityescroworg/qkb-ceremony:v1"
DEFAULT_REGION="fra"

# ── state (used by cleanup trap) ─────────────────────────────────────────────
APP=""
WORK_DIR=""
CLEANUP_DONE=0

# ── helpers ───────────────────────────────────────────────────────────────────
# All terminal I/O via /dev/tty so the script works when stdin is the pipe
# (curl ... | bash). Entropy is never passed through any of these helpers.

tty_out()    { printf '%s\n' "$*" >/dev/tty; }
tty_outf()   { printf '%s'   "$*" >/dev/tty; }
tty_banner() { printf '\n%s\n\n' "$*" >/dev/tty; }

ask() {
  # ask <prompt> <varname> [default]
  local prompt="$1" varname="$2" default="${3:-}"
  if [ -n "$default" ]; then
    tty_outf "${prompt} [${default}]: "
  else
    tty_outf "${prompt}: "
  fi
  IFS= read -r "${varname?}" </dev/tty
  if [ -z "${!varname}" ] && [ -n "$default" ]; then
    printf -v "$varname" '%s' "$default"
  fi
}

ask_secret() {
  # ask_secret <prompt> <varname>  — input is not echoed
  local prompt="$1" varname="$2"
  tty_outf "${prompt}: "
  IFS= read -rs "${varname?}" </dev/tty
  tty_out ""    # newline after silent read
}

die() {
  tty_out ""
  tty_out "ERROR: $*"
  exit 1
}

# Default Y — empty answer = yes
confirm_y() {
  tty_outf "$* [Y/n]: "
  local ans
  IFS= read -r ans </dev/tty || true
  [ -z "$ans" ] || [ "$ans" = "y" ] || [ "$ans" = "Y" ]
}

# Default N — explicit y required
confirm_n() {
  tty_outf "$* [y/N]: "
  local ans
  IFS= read -r ans </dev/tty || true
  [ "$ans" = "y" ] || [ "$ans" = "Y" ]
}

# ── cleanup ───────────────────────────────────────────────────────────────────

_cleanup() {
  [ "$CLEANUP_DONE" -eq 1 ] && return
  CLEANUP_DONE=1
  set +e
  [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR"
}

_interrupt() {
  set +e
  tty_out ""
  tty_out "Interrupted."
  if [ -n "$APP" ]; then
    if confirm_y "Destroy Fly app ${APP} to avoid orphan charges?"; then
      tty_out "Destroying ${APP}..."
      flyctl apps destroy "${APP}" --yes 2>/dev/null || tty_out "(destroy failed — run manually: flyctl apps destroy ${APP} --yes)"
      tty_out "App destroyed."
    else
      tty_out ""
      tty_out "Reminder: flyctl apps destroy ${APP} --yes"
    fi
  fi
  _cleanup
  exit 130
}

trap '_cleanup' EXIT
trap '_interrupt' INT TERM

# ── prerequisite checks ───────────────────────────────────────────────────────

if ! command -v flyctl >/dev/null 2>&1; then
  cat >/dev/tty <<'MISSING'

flyctl is not installed.

Install it with:
  curl -L https://fly.io/install.sh | sh

Then re-run this script. Full instructions:
  https://fly.io/docs/hands-on/install-flyctl/
MISSING
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  die "openssl is required for entropy generation. Install it via your package manager."
fi

# ── banner ────────────────────────────────────────────────────────────────────

cat >/dev/tty <<'BANNER'

================================================================
 zk-QES V5 Phase 2 trusted-setup ceremony
 Fly.io one-command launcher

 Prompts you for your round details, then handles everything:
   apps create → secrets set → deploy → logs → cleanup

 Time:  ~45-60 min total
 Cost:  under $0.30 (free-tier credit covers it)
 Needs: flyctl only — no Docker, no Node.js, no repo clone
================================================================

BANNER

# ── collect inputs ────────────────────────────────────────────────────────────

# Default app name: random 8-char hex suffix, unguessable, disposable.
DEFAULT_APP="qkb-ceremony-$(openssl rand -hex 4)"

tty_out "--- Fly app name ---"
tty_out "(leave blank for auto-generated; the name only appears in Fly logs)"
ask "App name" APP "${DEFAULT_APP}"
[[ "$APP" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,}[a-zA-Z0-9]$ ]] \
  || die "App name must be at least 3 chars, letters/numbers/hyphens only."

ask "Region" FLY_REGION "${DEFAULT_REGION}"

tty_out ""
tty_out "--- Round details (paste from the coordinator's DM) ---"
ask "Round number" ROUND
[[ "$ROUND" =~ ^[1-9][0-9]*$ ]] || die "Round must be a positive integer (≥ 1)."

ask "PREV_ROUND_URL  (previous contributor's zkey)" PREV_ROUND_URL
[ -n "$PREV_ROUND_URL" ] || die "PREV_ROUND_URL is required."

ask "R1CS_URL" R1CS_URL
[ -n "$R1CS_URL" ] || die "R1CS_URL is required."

ask "PTAU_URL" PTAU_URL
[ -n "$PTAU_URL" ] || die "PTAU_URL is required."

ask "SIGNED_PUT_URL  (your single-use upload URL)" SIGNED_PUT_URL
[ -n "$SIGNED_PUT_URL" ] || die "SIGNED_PUT_URL is required."

tty_out ""
tty_out "--- Attestation name ---"
tty_out "(appears in the public contribution log at prove.identityescrow.org)"
ask "Contributor name" CONTRIBUTOR_NAME
[ -n "$CONTRIBUTOR_NAME" ] || die "Contributor name is required."

# ── entropy ───────────────────────────────────────────────────────────────────
# Default: generate on this machine with openssl rand.
# Optional override: contributor pastes their own high-entropy string.
# The entropy variable is NEVER echoed or logged anywhere.

tty_out ""
tty_out "--- Entropy ---"
tty_out "Your entropy is the only value that comes from you, not Fly."
tty_out "Default: auto-generated with 'openssl rand -hex 32' on this machine."
tty_out "Override: paste your own (hardware RNG, dice, keystrokes, etc.)."
tty_out "(Input is not echoed.)"
tty_out ""

CUSTOM_ENTROPY=""
ask_secret "Custom entropy (press Enter to auto-generate)" CUSTOM_ENTROPY

CONTRIBUTOR_ENTROPY=""
if [ -n "$CUSTOM_ENTROPY" ]; then
  [ ${#CUSTOM_ENTROPY} -ge 32 ] \
    || die "Entropy too short (${#CUSTOM_ENTROPY} chars). openssl rand -hex 32 produces 64."
  CONTRIBUTOR_ENTROPY="$CUSTOM_ENTROPY"
  ENTROPY_SOURCE="user-supplied (${#CONTRIBUTOR_ENTROPY} chars)"
else
  CONTRIBUTOR_ENTROPY="$(openssl rand -hex 32)"
  ENTROPY_SOURCE="openssl rand -hex 32 (auto-generated on this machine)"
fi
unset CUSTOM_ENTROPY

# ── confirmation ──────────────────────────────────────────────────────────────

cat >/dev/tty <<CONFIRM

================================================================
 Ready to launch — verify before proceeding:

   Fly app:     ${APP}
   Region:      ${FLY_REGION}
   Round:       ${ROUND}
   Contributor: ${CONTRIBUTOR_NAME}
   Entropy:     ${ENTROPY_SOURCE}
   Image:       ${GHCR_IMAGE}
================================================================
CONFIRM

confirm_n "Proceed?" || { tty_out "Aborted."; exit 0; }

# From this point, the signal trap will offer to destroy the app on Ctrl-C.

# ── 1. Auth ───────────────────────────────────────────────────────────────────

tty_out ""
tty_out "[1/4] Checking Fly authentication..."
if ! flyctl auth whoami >/dev/null 2>&1; then
  tty_out "      Not logged in. Opening browser for Fly auth..."
  flyctl auth login
fi
tty_out "      Authenticated."

# ── 2. Create app ─────────────────────────────────────────────────────────────

tty_out ""
tty_out "[2/4] Creating Fly app ${APP}..."
if flyctl apps create "${APP}" --region "${FLY_REGION}" 2>/dev/null; then
  tty_out "      Created."
else
  tty_out "      App already exists — continuing."
fi

# ── 3. Secrets ────────────────────────────────────────────────────────────────

tty_out ""
tty_out "[3/4] Setting encrypted secrets..."
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
unset CONTRIBUTOR_ENTROPY   # clear from shell env immediately after handing off
tty_out "      Secrets staged (entropy cleared from shell)."

# ── 4. Deploy ─────────────────────────────────────────────────────────────────

tty_out ""
tty_out "[4/4] Deploying ceremony machine..."
tty_out "      Image:  ${GHCR_IMAGE}"
tty_out "      Size:   performance-cpu-4x / 32 GB RAM / 60 GB scratch volume"
tty_out "      No local Docker build — image pulled by Fly's builder from GHCR."
tty_out ""

WORK_DIR="$(mktemp -d)"

cat > "${WORK_DIR}/fly.toml" <<TOML
# Auto-generated by launcher.sh — not committed.
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
  --config    "${WORK_DIR}/fly.toml" \
  --image     "${GHCR_IMAGE}" \
  --vm-size   performance-cpu-4x \
  --vm-memory 32768 \
  --strategy  immediate \
  --app       "${APP}"

# ── Tail logs + capture SHA-256 ───────────────────────────────────────────────
# flyctl logs --follow exits when the machine stops.
# We tee everything to a temp file so we can extract the attestation hash.

cat >/dev/tty <<'LOGINFO'

================================================================
 Ceremony machine running (30-45 min).

 Logs will stream below. The machine exits when done and the log
 stream ends automatically. If it does not stop after ~60 min,
 press Ctrl-C — the interrupt handler will offer to clean up.
================================================================

LOGINFO

SHA_LOG="$(mktemp)"
# Pipe flyctl logs through tee: contributor sees everything on stdout,
# and the full log is saved to SHA_LOG for hash extraction.
flyctl logs --app "${APP}" --follow 2>&1 | tee "${SHA_LOG}" || true

# Extract the SHA-256 from the log: look for the first 64-char hex that
# appears after the "SAVE THIS" marker line printed by entrypoint.sh.
CONTRIBUTION_HASH=""
CONTRIBUTION_HASH="$(
  awk '
    /SAVE THIS/ { found=1; next }
    found && match($0, /[0-9a-f]{64}/) {
      print substr($0, RSTART, RLENGTH)
      exit
    }
  ' "${SHA_LOG}" || true
)"
rm -f "${SHA_LOG}"

# ── final summary + destroy ───────────────────────────────────────────────────

tty_out ""

if [ -n "$CONTRIBUTION_HASH" ]; then
  cat >/dev/tty <<SUMMARY

================================================================
 Contribution complete.

   Round:           ${ROUND}
   Contributor:     ${CONTRIBUTOR_NAME}
   Attestation SHA: ${CONTRIBUTION_HASH}

 Save this hash and your DM thread with the coordinator.
 That is your complete contribution record.

 The coordinator will verify independently and publish your
 entry to the public log at:
 https://prove.identityescrow.org/ceremony/status.json
================================================================
SUMMARY
else
  cat >/dev/tty <<NOSUMMARY

================================================================
 Log stream ended — attestation hash not found in output.

 This may mean the machine exited before the contribution
 finished, or you pressed Ctrl-C before the hash was printed.

 Check the machine status:
   flyctl machine list -a ${APP}
 Retrieve full logs:
   flyctl logs -a ${APP} --no-tail
================================================================
NOSUMMARY
fi

tty_out ""
if confirm_y "Destroy app ${APP} now? (Recommended — removes all artefacts from Fly infra.)"; then
  flyctl apps destroy "${APP}" --yes
  APP=""   # prevent double-destroy in EXIT trap
  tty_out "App destroyed. No artefacts remain on Fly infrastructure."
else
  tty_out ""
  tty_out "Reminder: flyctl apps destroy ${APP} --yes"
fi

tty_out ""
tty_out "Thank you for contributing to the zk-QES V5 trusted-setup ceremony."
tty_out ""
