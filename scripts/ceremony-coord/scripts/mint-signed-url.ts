// Mint a 24h signed PUT URL for the next contributor's zkey upload.
//
// Usage:
//   pnpm tsx scripts/mint-signed-url.ts --round 3 --name "Vitalik B."
//
// Records the round + name + open time to `pending/round-N.json` so
// publish-status.ts knows what to publish after verification.

import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { loadEnvFromAncestors } from '../src/env.ts';
import {
  loadR2Config,
  makeR2Client,
  mintSignedPutUrl,
  assertObjectAbsent,
  ROUND_KEY,
} from '../src/r2.ts';

loadEnvFromAncestors(import.meta.dirname ?? process.cwd());

interface Args {
  round: number;
  name: string;
  profile?: string;
}

function parseCliArgs(): Args {
  const { values } = parseArgs({
    options: {
      round: { type: 'string' },
      name: { type: 'string' },
      profile: { type: 'string' },
    },
  });
  if (!values.round) throw new Error('--round required');
  if (!values.name) throw new Error('--name required');
  const round = Number(values.round);
  if (!Number.isInteger(round) || round < 1) throw new Error('--round must be ≥ 1');
  return { round, name: values.name, profile: values.profile };
}

async function main(): Promise<void> {
  const args = parseCliArgs();
  const cfg = loadR2Config();
  const client = makeR2Client(cfg);

  await assertObjectAbsent(client, cfg, ROUND_KEY(args.round));

  const url = await mintSignedPutUrl(client, cfg, args.round);

  const pendingDir = join(import.meta.dirname ?? '.', '..', 'pending');
  mkdirSync(pendingDir, { recursive: true });
  const pendingFile = join(pendingDir, `round-${args.round}.json`);
  if (existsSync(pendingFile)) {
    console.warn(`overwriting existing ${pendingFile}`);
  }
  writeFileSync(
    pendingFile,
    JSON.stringify(
      {
        round: args.round,
        name: args.name,
        profileUrl: args.profile,
        openedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      },
      null,
      2,
    ),
  );

  console.log(`Round ${args.round} signed URL for "${args.name}":\n`);
  console.log(url);
  console.log(`\nPending tracker written to: ${pendingFile}`);
  // The signed URL is bound to a PutObjectCommand with `IfNoneMatch: '*'`
  // and `ContentType: 'application/octet-stream'`. Both headers are part
  // of the SigV4 canonical request — the contributor MUST include them
  // verbatim or R2 will reject with SignatureDoesNotMatch. Print the
  // exact curl invocation so DM templates don't drop them.
  console.log(
    [
      '',
      'Recipient runs (headers are signature-bound — include them verbatim):',
      `  curl -X PUT --upload-file round-${args.round}.zkey \\`,
      '    -H "If-None-Match: *" \\',
      '    -H "Content-Type: application/octet-stream" \\',
      `    "${url}"`,
      '',
    ].join('\n'),
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
