// Atomically update the public ceremony status.json.
//
// Usage (after verify-contribution succeeds):
//   pnpm tsx scripts/publish-status.ts --round 3 --commit
//
// Beacon mode (after final round, beacon block confirmed):
//   pnpm tsx scripts/publish-status.ts --beacon 21000000 0xdeadbeef… --commit
//
// Final mode (after qkb-v5-final.zkey is uploaded):
//   pnpm tsx scripts/publish-status.ts --finalize --commit
//
// Without --commit: dry-run prints the diff and exits.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { loadEnvFromAncestors } from '../src/env.ts';
import {
  loadR2Config,
  makeR2Client,
  readStatusWithEtag,
  writeStatusConditional,
} from '../src/r2.ts';

loadEnvFromAncestors(import.meta.dirname ?? process.cwd());
import {
  validateStatusPayload,
  type CeremonyStatusPayload,
  type CeremonyContributor,
} from '../src/types.ts';

interface Args {
  round?: number;
  beacon?: { height: number; hash: string };
  finalize?: boolean;
  finalSha?: string;
  commit: boolean;
}

function parseCliArgs(): Args {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      round: { type: 'string' },
      beacon: { type: 'boolean' },
      finalize: { type: 'boolean' },
      'final-sha': { type: 'string' },
      commit: { type: 'boolean', default: false },
    },
  });
  const args: Args = { commit: values.commit ?? false };
  if (values.round) {
    args.round = Number(values.round);
    if (!Number.isInteger(args.round) || args.round < 1)
      throw new Error('--round must be ≥ 1');
  }
  if (values.beacon) {
    if (positionals.length !== 2)
      throw new Error('--beacon requires <height> <hash>');
    args.beacon = { height: Number(positionals[0]), hash: positionals[1] };
    if (!Number.isInteger(args.beacon.height))
      throw new Error('beacon height must be integer');
  }
  if (values.finalize) {
    args.finalize = true;
    if (!values['final-sha']) throw new Error('--finalize requires --final-sha');
    args.finalSha = values['final-sha'];
  }
  const modes = [args.round, args.beacon, args.finalize].filter(Boolean).length;
  if (modes !== 1) throw new Error('exactly one of --round / --beacon / --finalize required');
  return args;
}

function applyRoundUpdate(
  current: CeremonyStatusPayload,
  round: number,
): CeremonyStatusPayload {
  const pendingFile = join(import.meta.dirname ?? '.', '..', 'pending', `round-${round}.json`);
  const attestationFile = join(import.meta.dirname ?? '.', '..', 'pending', `round-${round}.attestation`);
  const pending = JSON.parse(readFileSync(pendingFile, 'utf-8')) as {
    name: string;
    profileUrl?: string;
  };
  const attestation = JSON.parse(readFileSync(attestationFile, 'utf-8')) as {
    sha256: string;
    verifiedAt: string;
  };
  const entry: CeremonyContributor = {
    name: pending.name,
    round,
    completedAt: attestation.verifiedAt,
    ...(pending.profileUrl ? { profileUrl: pending.profileUrl } : {}),
    attestation: attestation.sha256,
  };
  if (current.contributors.some((c) => c.round === round))
    throw new Error(`round ${round} already in chain`);
  if (round !== current.round)
    throw new Error(`expected round ${current.round}, got ${round}`);
  return {
    ...current,
    round: round + 1,
    contributors: [...current.contributors, entry],
    currentRoundOpenedAt: new Date().toISOString(),
  };
}

function applyBeacon(
  current: CeremonyStatusPayload,
  height: number,
  hash: string,
): CeremonyStatusPayload {
  if (current.contributors.length < current.totalRounds)
    throw new Error('cannot beacon — chain incomplete');
  return { ...current, beaconBlockHeight: height, beaconHash: hash };
}

function applyFinalize(
  current: CeremonyStatusPayload,
  finalSha: string,
): CeremonyStatusPayload {
  if (current.beaconBlockHeight === null)
    throw new Error('cannot finalize — beacon not applied');
  return { ...current, finalZkeySha256: finalSha };
}

async function main(): Promise<void> {
  const args = parseCliArgs();
  const cfg = loadR2Config();
  const client = makeR2Client(cfg);

  const { body, etag } = await readStatusWithEtag(client, cfg);
  const current = JSON.parse(body) as unknown;
  validateStatusPayload(current);

  let next: CeremonyStatusPayload;
  if (args.round !== undefined) next = applyRoundUpdate(current, args.round);
  else if (args.beacon)
    next = applyBeacon(current, args.beacon.height, args.beacon.hash);
  else if (args.finalize) next = applyFinalize(current, args.finalSha!);
  else throw new Error('unreachable');

  console.log('--- DIFF ---');
  console.log(
    JSON.stringify(
      {
        round: { from: current.round, to: next.round },
        contributors: { from: current.contributors.length, to: next.contributors.length },
        beaconBlockHeight: { from: current.beaconBlockHeight, to: next.beaconBlockHeight },
        finalZkeySha256: { from: current.finalZkeySha256, to: next.finalZkeySha256 },
      },
      null,
      2,
    ),
  );

  if (!args.commit) {
    console.log('\nDry-run. Re-run with --commit to publish.');
    return;
  }

  await writeStatusConditional(client, cfg, JSON.stringify(next, null, 2), etag);
  console.log('Published status.json.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
