#!/bin/bash
# zk-QES V5 Phase 2 ceremony — interactive Fly.io launcher.
#
# Hosted at: https://prove.zkqes.org/ceremony/fly-launch.sh
#
# Recommended usage (inspect before running):
#   curl -fsSL https://prove.zkqes.org/ceremony/fly-launch.sh -o fly-launch.sh
#   cat fly-launch.sh
#   bash fly-launch.sh
#
# Pipe shortcut (if you trust the host):
#   curl -fsSL https://prove.zkqes.org/ceremony/fly-launch.sh | bash
#
# Requires:
#   flyctl   — https://fly.io/docs/hands-on/install-flyctl/
#   openssl  — pre-installed on macOS/Linux; used for entropy generation
#
# Does NOT require: Docker, Node.js, fly.toml, or this repository.
# The ceremony image is pulled by Fly's infrastructure from GHCR.
# Uses fly machine run — the correct primitive for one-shot batch jobs.
#
# SECURITY: set +x is unconditional. CONTRIBUTOR_ENTROPY is never echoed
# and is unset from the shell immediately after flyctl machine run launches.
# See README §6 (trust model) for the --env vs encrypted-secrets trade-off.

set +x
set -euo pipefail

# ── image reference ──────────────────────────────────────────────────────────
# CONTRIBUTORS: this is the SHA-256 digest of the GHCR ceremony image. Pinning
# by digest (not tag) means the team-lead cannot swap the image under your
# feet — Docker/Fly will pull exactly this digest or fail. To independently
# verify, compare against the digest published in the coordinator's DM and
# at:  https://prove.zkqes.org/ceremony/image-digest.txt
#
# TEAM-LEAD: after `docker push` (README §9), copy the resulting digest into
# GHCR_IMAGE_DIGEST below, re-publish launcher.sh to R2, and update the
# image-digest.txt object. Contributors NEVER see a moving target.
# NOTE: GHCR_IMAGE_DIGEST is intentionally empty until the founder builds and
# pushes the image under the new name (alik-eth/zkqes-ceremony). Founder
# action required out-of-band before the next ceremony run.
GHCR_IMAGE_REPO="ghcr.io/alik-eth/zkqes-ceremony"
GHCR_IMAGE_TAG="v1"          # human-readable, used only as fallback in DEV
GHCR_IMAGE_DIGEST=""         # set to "sha256:abc123..." after first push

# Build the canonical image reference. Prefer digest; fall back to tag with a
# loud warning (DEV mode only — never publish a launcher with empty digest).
if [ -n "$GHCR_IMAGE_DIGEST" ]; then
  GHCR_IMAGE="${GHCR_IMAGE_REPO}@${GHCR_IMAGE_DIGEST}"
  IMAGE_REF_KIND="digest-pinned"
else
  GHCR_IMAGE="${GHCR_IMAGE_REPO}:${GHCR_IMAGE_TAG}"
  IMAGE_REF_KIND="TAG-ONLY (dev)"
fi

DEFAULT_REGION="fra"

# Fly region codes — sourced from https://fly.io/docs/reference/regions/.
# Update if Fly adds new regions. Used for input validation; a typo here
# would silently pass to flyctl and only fail mid-deploy with an unclear
# error.
FLY_REGIONS="ams arn atl bog bom bos cdg den dfw ewr eze fra gdl gig gru \
hkg iad jnb lax lhr mad mia nrt ord otp phx qro scl sea sin sjc syd waw \
yul yyz"

# ── state (used by interrupt trap) ───────────────────────────────────────────
APP=""

# ── helpers ───────────────────────────────────────────────────────────────────
# All terminal I/O via /dev/tty so the script works when stdin is the pipe
# (curl ... | bash).

tty_out()  { printf '%s\n' "$*" >/dev/tty; }
tty_outf() { printf '%s'   "$*" >/dev/tty; }

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

ask_required() {
  # ask_required <prompt> <varname>  — prompt and abort if empty.
  ask "$1" "$2"
  [ -n "${!2}" ] || die "$2 is required."
}

ask_secret() {
  # ask_secret <prompt> <varname>  — input is not echoed
  local prompt="$1" varname="$2"
  tty_outf "${prompt}: "
  IFS= read -rs "${varname?}" </dev/tty
  tty_out ""
}

die() {
  tty_out ""
  tty_out "ERROR: $*"
  exit 1
}

confirm_y() {
  # Default Y — empty answer = yes
  tty_outf "$* [Y/n]: "
  local ans
  IFS= read -r ans </dev/tty || true
  [ -z "$ans" ] || [ "$ans" = "y" ] || [ "$ans" = "Y" ]
}

confirm_n() {
  # Default N — explicit y required
  tty_outf "$* [y/N]: "
  local ans
  IFS= read -r ans </dev/tty || true
  [ "$ans" = "y" ] || [ "$ans" = "Y" ]
}

preflight_url() {
  # preflight_url <label> <url> <allow_403>
  # HEAD a URL with a 10s cap. Allow 2xx/3xx always. Allow 403/405 only when
  # <allow_403> is "yes" — that's the case for signed URLs whose method-specific
  # signature legitimately rejects HEAD (R2/S3 PUT URLs in particular).
  # Connection failures (000) are always fatal.
  local label="$1" url="$2" allow_403="${3:-no}"
  local code
  code="$(curl -sIL --max-time 10 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)" || code="000"
  case "$code" in
    2*|3*)
      tty_out "      ${label}: HTTP ${code} OK"
      ;;
    403|405)
      if [ "$allow_403" = "yes" ]; then
        tty_out "      ${label}: HTTP ${code} (signed URL — host reachable, signature not validated)"
      else
        die "${label} returned HTTP ${code} on HEAD — URL may be misconfigured or wrong host."
      fi
      ;;
    000)
      die "${label}: connection failed (DNS error, timeout, or unreachable). Check the URL."
      ;;
    *)
      die "${label} returned HTTP ${code} — URL may be wrong, expired, or already consumed."
      ;;
  esac
}

extract_sha() {
  # extract_sha <log-file>  — scan for the attestation SHA (line after "SAVE THIS").
  # Prints the hash on hit, empty on miss.
  awk '
    /SAVE THIS/ { found=1; next }
    found && match($0, /[0-9a-f]{64}/) {
      print substr($0, RSTART, RLENGTH)
      exit
    }
  ' "$1" 2>/dev/null || true
}

# ── signal trap ──────────────────────────────────────────────────────────────

_interrupt() {
  set +e
  tty_out ""
  tty_out "Interrupted."
  if [ -n "$APP" ]; then
    if confirm_y "Destroy Fly app ${APP} to avoid orphan charges?"; then
      tty_out "Destroying ${APP}..."
      flyctl apps destroy "${APP}" --yes 2>/dev/null \
        || tty_out "(destroy failed — run manually: flyctl apps destroy ${APP} --yes)"
      tty_out "App destroyed."
    else
      tty_out "Reminder: flyctl apps destroy ${APP} --yes"
    fi
  fi
  exit 130
}

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
  die "openssl is required for entropy generation. Install via your package manager."
fi

if ! command -v curl >/dev/null 2>&1; then
  die "curl is required for URL pre-flight checks. Install via your package manager."
fi

# ── banner ────────────────────────────────────────────────────────────────────

cat >/dev/tty <<'BANNER'

================================================================
 zk-QES V5 Phase 2 trusted-setup ceremony
 Fly.io one-command launcher

 Five steps:
   1. Authenticate with Fly
   2. Create app + scratch volume
   3. Start ceremony machine
   4. Stream logs and capture attestation hash
   5. Destroy app

 Time:  ~45-60 min total
        (downloads ~5 min · contribute 30-45 min · verify+upload ~5 min)
 Cost:  under $0.30 (free-tier credit covers it)
 Needs: flyctl only — no Docker, no Node.js, no repo clone
================================================================

BANNER

# ── collect inputs ────────────────────────────────────────────────────────────

DEFAULT_APP="zkqes-ceremony-$(openssl rand -hex 4)"

tty_out "--- Fly app name ---"
tty_out "(leave blank for auto-generated; the name only appears in Fly logs)"
ask "App name" APP "${DEFAULT_APP}"
[[ "$APP" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,}[a-zA-Z0-9]$ ]] \
  || die "App name must be ≥3 chars, letters/numbers/hyphens only."

ask "Region (3-letter Fly region code, e.g. fra, iad, ord)" FLY_REGION "${DEFAULT_REGION}"
# Check membership in the whitelist. Wrap both the haystack and needle in
# spaces so substring match works (avoids "fra" matching "fram" if such a
# region ever exists).
# shellcheck disable=SC2153  # FLY_REGION is set indirectly by `ask` via `read`.
case " ${FLY_REGIONS} " in
  *" ${FLY_REGION} "*) : ;;
  *) die "Unknown Fly region '${FLY_REGION}'. See https://fly.io/docs/reference/regions/ for the full list." ;;
esac

tty_out ""
tty_out "--- Round details (paste from the coordinator's DM) ---"
ask_required "Round number" ROUND
[[ "$ROUND" =~ ^[1-9][0-9]*$ ]] || die "Round must be a positive integer (≥ 1)."

ask_required "PREV_ROUND_URL  (previous contributor's zkey)" PREV_ROUND_URL
ask_required "R1CS_URL" R1CS_URL
ask_required "PTAU_URL" PTAU_URL
ask_required "SIGNED_PUT_URL  (your single-use upload URL)" SIGNED_PUT_URL

tty_out ""
tty_out "--- Attestation name ---"
tty_out "(appears in the public contribution log at prove.zkqes.org)"
ask_required "Contributor name" CONTRIBUTOR_NAME

# ── entropy ───────────────────────────────────────────────────────────────────

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
  ENTROPY_SOURCE="openssl rand -hex 32 on this machine"
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
   Image ref:   ${IMAGE_REF_KIND}

 URLs (verify each matches the coordinator's DM):
   PREV_ROUND_URL: ${PREV_ROUND_URL}
   R1CS_URL:       ${R1CS_URL}
   PTAU_URL:       ${PTAU_URL}
   SIGNED_PUT_URL: ${SIGNED_PUT_URL}
================================================================
CONFIRM

if [ "$IMAGE_REF_KIND" = "TAG-ONLY (dev)" ]; then
  cat >/dev/tty <<'TAGWARN'

  ⚠  WARNING: image is referenced by tag, not digest.
     The team-lead has not yet pinned a digest in this launcher.
     A tag-pinned image can be silently replaced; a digest-pinned
     image cannot. If you obtained this launcher from the official
     coordinator URL and the published digest is empty, that's
     expected pre-first-push. Otherwise STOP and re-fetch the launcher.

TAGWARN
fi

confirm_n "Proceed?" || { tty_out "Aborted."; exit 0; }

# ── pre-flight URL checks ────────────────────────────────────────────────────
# Validate URLs are reachable BEFORE spinning up Fly auth + machine. Catches
# typos, wrong hosts, expired signed URLs, R2 outages — saves ~5 min and a
# Fly machine boot if any URL is broken.

tty_out ""
tty_out "Pre-flight: checking URLs are reachable..."

# PREV_ROUND_URL is usually public, but coordinators sometimes mint signed
# read URLs for it; allow 403 in that case.
preflight_url "PREV_ROUND_URL" "${PREV_ROUND_URL}" "yes"
preflight_url "R1CS_URL"       "${R1CS_URL}"       "no"
preflight_url "PTAU_URL"       "${PTAU_URL}"       "no"

# SIGNED_PUT_URL is single-use and PUT-only; HEAD will return 403 because the
# signature does not authorise HEAD. We only check that the host is reachable.
preflight_url "SIGNED_PUT_URL" "${SIGNED_PUT_URL}" "yes"

tty_out "      All URLs reachable."

# ── 1. Auth ───────────────────────────────────────────────────────────────────

tty_out ""
tty_out "[1/5] Checking Fly authentication..."
if ! flyctl auth whoami >/dev/null 2>&1; then
  tty_out "      Not logged in — opening browser..."
  flyctl auth login
fi
tty_out "      Authenticated."

# ── 2. Create app + volume ────────────────────────────────────────────────────

tty_out ""
tty_out "[2/5] Creating app and scratch volume..."

if flyctl apps create "${APP}" --region "${FLY_REGION}" 2>/dev/null; then
  tty_out "      App created."
else
  tty_out "      App already exists — continuing."
fi

# Volumes are independent of machines; must be created before machine run.
# --yes suppresses the interactive region-confirmation prompt.
if flyctl volumes create ceremony_scratch \
     --app     "${APP}" \
     --region  "${FLY_REGION}" \
     --size    60 \
     --yes 2>/dev/null; then
  tty_out "      Volume created (60 GB)."
else
  tty_out "      Volume already exists — continuing."
fi

# ── 3. Machine run ────────────────────────────────────────────────────────────
# fly machine run is the correct primitive for one-shot batch jobs on Fly:
# no fly.toml needed, no persistent app config, exits when the entrypoint exits.
#
# ENTROPY NOTE: --env passes values as plain-text machine config (visible in
# Fly's Machines API to account holders). This is intentional: the alternative
# (flyctl secrets set + --file-secret) requires a separate step and a change to
# entrypoint.sh, with no meaningful ceremony-security benefit — if Fly is
# adversarial they control the compute directly. See README §6.

tty_out ""
tty_out "[3/5] Starting ceremony machine..."
tty_out "      Image:  ${GHCR_IMAGE}"
tty_out "      Size:   performance-cpu-4x / 32 GB RAM / 60 GB scratch"
tty_out ""

flyctl machine run "${GHCR_IMAGE}" \
  --app         "${APP}" \
  --region      "${FLY_REGION}" \
  --vm-size     performance-cpu-4x \
  --vm-memory   32768 \
  --volume      "ceremony_scratch:/data" \
  --restart     no \
  --env         "ROUND=${ROUND}" \
  --env         "PREV_ROUND_URL=${PREV_ROUND_URL}" \
  --env         "R1CS_URL=${R1CS_URL}" \
  --env         "PTAU_URL=${PTAU_URL}" \
  --env         "SIGNED_PUT_URL=${SIGNED_PUT_URL}" \
  --env         "CONTRIBUTOR_NAME=${CONTRIBUTOR_NAME}" \
  --env         "CONTRIBUTOR_ENTROPY=${CONTRIBUTOR_ENTROPY}"

# Clear entropy from shell env immediately after machine run accepts it.
# The value now lives only inside the Fly machine's process for ~45 min.
unset CONTRIBUTOR_ENTROPY

# ── 4. Tail logs + capture SHA-256 ───────────────────────────────────────────
#
# Two-pass capture:
#   pass 1: `flyctl logs --follow` streams in real time so the contributor
#           sees progress. tee'd to disk for awk.
#   pass 2: after the stream ends (cleanly OR from a network blip), we
#           re-fetch the full archived log via `--no-tail` and combine it
#           with the streamed log, then awk both. This makes the attestation
#           hash robust to any --follow disconnect.

tty_out ""
tty_out "[4/5] Streaming machine logs (downloads ~5 min · contribute 30-45 min)..."

cat >/dev/tty <<'LOGINFO'

================================================================
 Machine running.

 Logs stream below. The machine exits when done and the stream
 ends automatically. Ctrl-C at any time — the interrupt handler
 will offer to destroy the app cleanly.
================================================================

LOGINFO

# Temp files in $HOME so they survive /tmp cleanup races.
SHA_LOG="$(mktemp -p "${HOME}" zkqes-ceremony-stream.XXXXXX)"
ARCHIVE_LOG="$(mktemp -p "${HOME}" zkqes-ceremony-archive.XXXXXX)"

# Stream pass — real-time progress for the contributor; tee'd for awk.
flyctl logs --app "${APP}" --follow 2>&1 | tee "${SHA_LOG}" || true

# Archive pass — full machine-side history; safer than trusting --follow
# held the connection for 45 min.
tty_out ""
tty_out "      Fetching full archived log (post-stream double-check)..."
flyctl logs --app "${APP}" --no-tail >"${ARCHIVE_LOG}" 2>/dev/null || true

# Prefer archive; fall back to stream.
CONTRIBUTION_HASH="$(extract_sha "${ARCHIVE_LOG}")"
[ -n "${CONTRIBUTION_HASH}" ] || CONTRIBUTION_HASH="$(extract_sha "${SHA_LOG}")"
rm -f "${SHA_LOG}" "${ARCHIVE_LOG}"

# ── final summary + destroy ───────────────────────────────────────────────────

tty_out ""

if [ -n "$CONTRIBUTION_HASH" ]; then
  # Persist a copy to the contributor's CWD so it survives terminal close,
  # scrollback overflow, etc. The hash is public-by-design (it's the public
  # commitment of the contribution); no secret material is written.
  SUMMARY_FILE="./zkqes-ceremony-round-${ROUND}.txt"
  {
    printf '# zk-QES V5 Phase 2 ceremony — round %s contribution record\n' "${ROUND}"
    printf '# Generated: %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'Round:           %s\n' "${ROUND}"
    printf 'Contributor:     %s\n' "${CONTRIBUTOR_NAME}"
    printf 'Attestation SHA: %s\n' "${CONTRIBUTION_HASH}"
    printf 'Image ran:       %s\n' "${GHCR_IMAGE}"
    printf 'Image ref kind:  %s\n' "${IMAGE_REF_KIND}"
    printf 'Fly app:         %s\n' "${APP}"
    printf 'Fly region:      %s\n' "${FLY_REGION}"
  } >"${SUMMARY_FILE}" 2>/dev/null || SUMMARY_FILE=""

  cat >/dev/tty <<SUMMARY

================================================================
 Contribution complete.

   Round:           ${ROUND}
   Contributor:     ${CONTRIBUTOR_NAME}
   Attestation SHA: ${CONTRIBUTION_HASH}
   Image ran:       ${GHCR_IMAGE}
   Image ref:       ${IMAGE_REF_KIND}

 Save this hash and your DM thread with the coordinator.
 That is your complete contribution record.

 The coordinator will verify independently and publish your
 entry to the public log at:
 https://prove.zkqes.org/ceremony/status.json
================================================================
SUMMARY

  if [ -n "${SUMMARY_FILE}" ] && [ -f "${SUMMARY_FILE}" ]; then
    tty_out ""
    tty_out "A copy was saved to: ${SUMMARY_FILE}"
  fi
else
  cat >/dev/tty <<NOSUMMARY

================================================================
 Log stream ended — attestation hash not captured.

 The machine may still be running, or exited before the
 contribution completed. Check status:
   flyctl machine list -a ${APP}
 Retrieve full logs:
   flyctl logs -a ${APP} --no-tail
================================================================
NOSUMMARY
fi

tty_out ""
tty_out "[5/5] Cleanup..."
if confirm_y "Destroy app ${APP} now? (Removes all artefacts from Fly infra.)"; then
  flyctl apps destroy "${APP}" --yes
  APP=""
  tty_out "App destroyed. No artefacts remain on Fly infrastructure."
else
  tty_out "Reminder: flyctl apps destroy ${APP} --yes"
fi

tty_out ""
tty_out "Thank you for contributing to the zk-QES V5 trusted-setup ceremony."
tty_out ""
