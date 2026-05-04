// Pure helpers behind the /ceremony/contribute Fly launcher form
// (task A2.7b). Extracted from the React component so they can be
// unit-tested in isolation — slug correctness, hex validation, and
// the exact rendered shell sequence are load-bearing for whether a
// contributor's round actually runs, so they get their own tests.
//
// Canonical command shape mirrors A2.5's
// scripts/ceremony-coord/cookbooks/fly/launch.sh — see the lead's
// A2.7b dispatch for the verbatim line-by-line text.

/**
 * Hard-coded URL placeholders documented as fixed paths in the Fly
 * cookbook. They are intentionally NOT fetched from
 * /ceremony/status.json — those URLs may change between rounds, but
 * the cookbook anchors them as static, and a live fetch would couple
 * this widget to status-feed availability.
 */
export const FLY_FIXED_URLS = {
  R1CS: 'https://prove.zkqes.org/ceremony/main.r1cs',
  PTAU: 'https://prove.zkqes.org/ceremony/pot/pot22.ptau',
  /** Returns the previous-round URL given the current round N. */
  prevRound: (round: number): string =>
    `https://prove.zkqes.org/ceremony/rounds/round-${round - 1}.zkey`,
  /** GHCR image tag the cookbook deploys. */
  IMAGE: 'ghcr.io/zkqes/zkqes-ceremony:v1',
} as const;

export const NAME_MAX_LEN = 40;
export const ENTROPY_BYTES = 32;
export const ENTROPY_HEX_LEN = ENTROPY_BYTES * 2;

/**
 * Reduce an arbitrary contributor name to a Fly-safe app-name slug.
 * Fly app names are roughly `[a-z0-9-]{1,30}` — anything outside that
 * collapses to `-`, leading/trailing hyphens are stripped, and the
 * result is truncated to 30 chars.
 */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 30);
}

/**
 * Strict 32-byte hex check. Anything else (extra spaces, leading
 * `0x`, uppercase, wrong length) is rejected — `flyctl secrets set`
 * accepts arbitrary strings, and we don't want to silently corrupt
 * a contributor's entropy by normalising it for them.
 */
export function isValidEntropyHex(s: string): boolean {
  return /^[0-9a-f]{64}$/.test(s);
}

/**
 * 32 bytes from `crypto.getRandomValues`, hex-encoded. Same source
 * the entrypoint script's `openssl rand -hex 32` uses; the four
 * commands docs and the launcher both accept either.
 */
export function generateEntropyHex(): string {
  const buf = new Uint8Array(ENTROPY_BYTES);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Parse the round number out of a signed PUT URL of the shape
 * `…/round-N.zkey…`. Returns `null` when the URL doesn't contain a
 * recognisable round-N segment, so the form can fall back to a
 * blank round input rather than guessing.
 */
export function parseRoundFromUrl(url: string): number | null {
  const m = /round-(\d+)\.zkey/i.exec(url);
  if (!m || m[1] === undefined) return null;
  const n = Number.parseInt(m[1], 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

export interface FlyLaunchInputs {
  readonly name: string;
  readonly round: number;
  readonly signedPutUrl: string;
  readonly entropyHex: string;
}

/**
 * Render the full multi-line `flyctl` invocation from the form
 * inputs. The shape is verbatim from the A2.7b dispatch:
 *
 *   APP="zkqes-ceremony-{slug}"
 *   flyctl apps create "$APP" --org personal
 *   flyctl secrets set \
 *     ROUND="{round}" \
 *     PREV_ROUND_URL="…round-{round-1}.zkey" \
 *     R1CS_URL="…main.r1cs" \
 *     PTAU_URL="…pot22.ptau" \
 *     SIGNED_PUT_URL='{signed}' \
 *     CONTRIBUTOR_NAME='{name}' \
 *     CONTRIBUTOR_ENTROPY={hex} \
 *     -a "$APP"
 *   flyctl deploy --image …:v1 --vm-size performance-cpu-4x \
 *     --vm-memory 32768 --strategy immediate -a "$APP"
 *   flyctl logs -a "$APP" --follow
 *   # After the run completes (you'll see SHA-256 in the logs), save it, then:
 *   flyctl apps destroy "$APP" --yes
 *
 * Single-quoting on SIGNED_PUT_URL + CONTRIBUTOR_NAME is intentional:
 * it escapes the shell metachars ('?', '&', '=', spaces, '$') that
 * commonly appear in signed query strings and human names. Entropy
 * stays unquoted because it's pure hex.
 */
export function buildFlyLaunchCommand(inputs: FlyLaunchInputs): string {
  const slug = slugify(inputs.name);
  const round = inputs.round;
  const lines = [
    `APP="zkqes-ceremony-${slug}"`,
    `flyctl apps create "$APP" --org personal`,
    `flyctl secrets set \\`,
    `  ROUND="${round}" \\`,
    `  PREV_ROUND_URL="${FLY_FIXED_URLS.prevRound(round)}" \\`,
    `  R1CS_URL="${FLY_FIXED_URLS.R1CS}" \\`,
    `  PTAU_URL="${FLY_FIXED_URLS.PTAU}" \\`,
    `  SIGNED_PUT_URL='${inputs.signedPutUrl}' \\`,
    `  CONTRIBUTOR_NAME='${inputs.name}' \\`,
    `  CONTRIBUTOR_ENTROPY=${inputs.entropyHex} \\`,
    `  -a "$APP"`,
    `flyctl deploy \\`,
    `  --image ${FLY_FIXED_URLS.IMAGE} \\`,
    `  --vm-size performance-cpu-4x \\`,
    `  --vm-memory 32768 \\`,
    `  --strategy immediate \\`,
    `  -a "$APP"`,
    `flyctl logs -a "$APP" --follow`,
    `# After the run completes (you'll see SHA-256 in the logs), save it, then:`,
    `flyctl apps destroy "$APP" --yes`,
  ];
  return lines.join('\n');
}
