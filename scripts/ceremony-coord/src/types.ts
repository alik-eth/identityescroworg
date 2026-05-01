// Mirror of `packages/web/src/lib/ceremonyStatus.ts` — the JSON shape of
// `status.json` published to R2. The web frontend polls + parses this.
//
// Don't change types here without updating the web file in lockstep; both
// sides MUST byte-deserialize identical objects.

export interface CeremonyContributor {
  readonly name: string;
  readonly round: number;
  readonly profileUrl?: string;
  readonly attestation?: string;
  readonly completedAt: string;
}

export interface CeremonyStatusPayload {
  readonly round: number;
  readonly totalRounds: number;
  readonly contributors: readonly CeremonyContributor[];
  readonly currentRoundOpenedAt?: string;
  readonly finalZkeySha256: string | null;
  readonly beaconBlockHeight: number | null;
  readonly beaconHash: string | null;
}

export type CeremonyState = 'planned' | 'in-progress' | 'complete';

export function deriveCeremonyState(p: CeremonyStatusPayload): CeremonyState {
  if (p.finalZkeySha256 !== null) return 'complete';
  if (p.round >= 1 && p.contributors.length > 0) return 'in-progress';
  return 'planned';
}

export function validateStatusPayload(p: unknown): asserts p is CeremonyStatusPayload {
  if (typeof p !== 'object' || p === null) throw new Error('not an object');
  const o = p as Record<string, unknown>;
  if (typeof o.round !== 'number') throw new Error('round not a number');
  if (typeof o.totalRounds !== 'number') throw new Error('totalRounds not a number');
  if (!Array.isArray(o.contributors)) throw new Error('contributors not an array');
  if (o.finalZkeySha256 !== null && typeof o.finalZkeySha256 !== 'string')
    throw new Error('finalZkeySha256 not string|null');
  if (o.beaconBlockHeight !== null && typeof o.beaconBlockHeight !== 'number')
    throw new Error('beaconBlockHeight not number|null');
  if (o.beaconHash !== null && typeof o.beaconHash !== 'string')
    throw new Error('beaconHash not string|null');
  for (const [i, c] of (o.contributors as unknown[]).entries()) {
    if (typeof c !== 'object' || c === null) throw new Error(`contributors[${i}] not object`);
    const cc = c as Record<string, unknown>;
    if (typeof cc.name !== 'string') throw new Error(`contributors[${i}].name not string`);
    if (typeof cc.round !== 'number') throw new Error(`contributors[${i}].round not number`);
    if (typeof cc.completedAt !== 'string') throw new Error(`contributors[${i}].completedAt not string`);
  }
}
