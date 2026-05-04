// V5 Phase 2 ceremony — status feed types + polling.
//
// The ceremony progress is a small JSON document the lead admin
// publishes to a known URL after each contributor's round closes.
// Frontend polls every 30 s and renders progress + contributor chain.
//
// Production URL (post-§9.4):
//   https://prove.zkqes.org/ceremony/status.json
//
// Dev fixture (this repo):
//   public/ceremony/status.json
//
// The shape is locked across (admin script that writes it) and (this
// frontend that reads it). Don't change types here without coordinating
// with the admin tooling.

export interface CeremonyContributor {
  /** Display handle / email — what we show in the public chain. */
  readonly name: string;
  /** 1-indexed round position. */
  readonly round: number;
  /** Optional Twitter / GitHub / web profile for credibility surfacing. */
  readonly profileUrl?: string;
  /**
   * Optional attestation hash — the contributor's BLAKE2b of their
   * `zkey contribute` output, signed via PGP / X (whatever the admin
   * chose). Lets the public verify each link in the chain independently.
   */
  readonly attestation?: string;
  /** ISO-8601 of when the round was accepted by the admin. */
  readonly completedAt: string;
}

export interface CeremonyStatusPayload {
  /** Current round in flight (1-indexed). When `round > totalRounds`,
   *  ceremony is complete and `finalZkeySha256` is non-null. */
  readonly round: number;
  /** Planned total contributors. */
  readonly totalRounds: number;
  /** Chain of completed rounds in order. */
  readonly contributors: readonly CeremonyContributor[];
  /** ISO-8601 of when the current round opened (for "awaiting next contributor" UX). */
  readonly currentRoundOpenedAt?: string;
  /** Final zkey hash; non-null once ceremony is complete + attested. */
  readonly finalZkeySha256: string | null;
  /** Public-randomness beacon — block height + hash from the agreed
   *  Bitcoin / Ethereum mainnet block consumed as a randomness commit
   *  AFTER the last contributor. Per §11 spec. */
  readonly beaconBlockHeight: number | null;
  readonly beaconHash: string | null;
}

export type CeremonyState = 'planned' | 'in-progress' | 'complete';

export function deriveCeremonyState(p: CeremonyStatusPayload): CeremonyState {
  if (p.finalZkeySha256 !== null) return 'complete';
  if (p.round >= 1 && p.contributors.length > 0) return 'in-progress';
  return 'planned';
}

/**
 * Fetch the published status JSON. Network failures surface as `null`
 * so the caller can render a "feed unavailable" state without crashing.
 *
 * `cacheBust` adds a query param so polling doesn't get cached by the
 * CDN — R2 / Cloudflare honour `?t=<ms>` cache busting.
 */
export async function fetchCeremonyStatus(
  url: string,
  signal?: AbortSignal,
): Promise<CeremonyStatusPayload | null> {
  try {
    const sep = url.includes('?') ? '&' : '?';
    const r = await fetch(`${url}${sep}t=${Date.now()}`, signal ? { signal } : {});
    if (!r.ok) return null;
    return (await r.json()) as CeremonyStatusPayload;
  } catch {
    return null;
  }
}

/** Polling interval — 30 s per founder dispatch. */
export const CEREMONY_POLL_MS = 30_000;

/** Production status feed URL. Override via `VITE_CEREMONY_STATUS_URL` for
 *  local dev (defaults to the bundled fixture). */
export const CEREMONY_STATUS_URL =
  (typeof import.meta !== 'undefined' &&
    import.meta.env?.VITE_CEREMONY_STATUS_URL) ||
  '/ceremony/status.json';
