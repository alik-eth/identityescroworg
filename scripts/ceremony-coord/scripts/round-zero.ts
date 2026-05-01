// Generate the round-0 zkey from the production R1CS + pot23 + bootstrap
// the ceremony status feed.
//
// Usage:
//   pnpm tsx scripts/round-zero.ts \
//     --r1cs ../../../packages/circuits/build/v5_1/main.r1cs \
//     --ptau ../../../packages/circuits/ceremony/v5_1/pot23.ptau \
//     --out  pending/round-0.zkey \
//     --total-rounds 10 \
//     [--commit]   # uploads to R2 + initializes status.json;
//                  # without it, just produces the file locally
//
// Process:
//   1. snarkjs groth16 setup r1cs ptau round-0.zkey   (produces an
//      "uninitialized" zkey — no contributions yet, equivalent to ptau)
//   2. snarkjs zkey contribute round-0.zkey round-0-final.zkey \
//        --name="admin-seed" -e="<random entropy>"   (admin's contribution
//      becomes the chain seed; the next contributor builds on this)
//   3. Optional --commit:
//      a. upload zkey to R2 ceremony/rounds/round-0.zkey (write-once)
//      b. initialize ceremony/status.json with round=1, totalRounds=N,
//         contributors=[]. Without this step, publish-status --round 1
//         would fail because applyRoundUpdate requires current.round == 1.
//
// Round 1 contributors download round-0.zkey, contribute, upload to round-1.

import { spawn } from 'node:child_process';
import { createReadStream, statSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { randomBytes } from 'node:crypto';
import { PutObjectCommand } from '@aws-sdk/client-s3';
import { loadEnvFromAncestors } from '../src/env.ts';
import { loadR2Config, makeR2Client, ROUND_KEY, STATUS_KEY } from '../src/r2.ts';
import type { CeremonyStatusPayload } from '../src/types.ts';

loadEnvFromAncestors(import.meta.dirname ?? process.cwd());

interface Args {
  r1cs: string;
  ptau: string;
  out: string;
  totalRounds: number;
  commit: boolean;
}

function parseCliArgs(): Args {
  const { values } = parseArgs({
    options: {
      r1cs: { type: 'string' },
      ptau: { type: 'string' },
      out: { type: 'string' },
      'total-rounds': { type: 'string' },
      commit: { type: 'boolean', default: false },
    },
  });
  if (!values.r1cs) throw new Error('--r1cs required');
  if (!values.ptau) throw new Error('--ptau required');
  if (!values.out) throw new Error('--out required');
  if (!values['total-rounds']) throw new Error('--total-rounds required');
  const totalRounds = Number(values['total-rounds']);
  if (!Number.isInteger(totalRounds) || totalRounds < 1)
    throw new Error('--total-rounds must be ≥ 1');
  return {
    r1cs: values.r1cs,
    ptau: values.ptau,
    out: values.out,
    totalRounds,
    commit: values.commit ?? false,
  };
}

function exec(cmd: string, args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: 'inherit' });
    p.on('exit', (code) =>
      code === 0 ? resolve() : reject(new Error(`${cmd} exit ${code}`)),
    );
    p.on('error', reject);
  });
}

async function main(): Promise<void> {
  const args = parseCliArgs();
  const intermediate = `${args.out}.uninit`;

  console.log('Step 1/3: snarkjs groth16 setup …');
  await exec('npx', ['snarkjs', 'groth16', 'setup', args.r1cs, args.ptau, intermediate]);

  console.log('Step 2/3: snarkjs zkey contribute (admin seed) …');
  const entropy = randomBytes(32).toString('hex');
  await exec('npx', [
    'snarkjs',
    'zkey',
    'contribute',
    intermediate,
    args.out,
    '--name=admin-seed',
    `-e=${entropy}`,
  ]);

  const size = statSync(args.out).size;
  console.log(`round-0 zkey written: ${args.out} (${(size / 1024 / 1024 / 1024).toFixed(2)} GB)`);

  if (!args.commit) {
    console.log('\nLocal-only. Re-run with --commit to upload + bootstrap status.');
    return;
  }

  const cfg = loadR2Config();
  const client = makeR2Client(cfg);

  // Step 3a: upload zkey via streaming Body — multi-GB zkeys must NOT
  // be buffered into RAM.
  console.log('Step 3a/3: streaming round-0.zkey to R2 …');
  // Write-once via `IfNoneMatch: '*'` — round-0 is the chain seed; an
  // accidental re-run of `round-zero --commit` could otherwise overwrite
  // the verified seed and silently re-root the entire ceremony chain.
  // First upload succeeds; subsequent attempts return 412 PreconditionFailed.
  // To re-seed deliberately, delete `ceremony/rounds/round-0.zkey` from
  // R2 first (admin action, audit-trailed in R2 access logs).
  try {
    await client.send(
      new PutObjectCommand({
        Bucket: cfg.bucket,
        Key: ROUND_KEY(0),
        Body: createReadStream(args.out),
        ContentLength: size,
        ContentType: 'application/octet-stream',
        IfNoneMatch: '*',
      }),
    );
  } catch (e: unknown) {
    const code = (e as { name?: string; $metadata?: { httpStatusCode?: number } }).name;
    const status = (e as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
    if (code === 'PreconditionFailed' || status === 412) {
      throw new Error(
        `round-0 already exists at ${cfg.publicBase}/${ROUND_KEY(0)}. ` +
          'Re-seeding the chain is destructive — delete the existing object ' +
          'from R2 first if you really want to overwrite.',
      );
    }
    throw e;
  }
  console.log(`Uploaded to ${cfg.publicBase}/${ROUND_KEY(0)}`);

  // Step 3b: bootstrap status.json. Without this, publish-status --round 1
  // would fail because applyRoundUpdate enforces `round === current.round`
  // and the initial state must therefore have round=1 (= the round we're
  // awaiting). We use IfNoneMatch: '*' on this PUT too — re-running
  // round-zero must not silently overwrite a partially-progressed
  // ceremony's status.
  console.log('Step 3b/3: bootstrapping status.json (round=1, awaiting first contributor) …');
  const initialStatus: CeremonyStatusPayload = {
    round: 1,
    totalRounds: args.totalRounds,
    contributors: [],
    currentRoundOpenedAt: new Date().toISOString(),
    finalZkeySha256: null,
    beaconBlockHeight: null,
    beaconHash: null,
  };
  try {
    await client.send(
      new PutObjectCommand({
        Bucket: cfg.bucket,
        Key: STATUS_KEY,
        Body: JSON.stringify(initialStatus, null, 2),
        ContentType: 'application/json',
        CacheControl: 'public, max-age=15',
        IfNoneMatch: '*',
      }),
    );
  } catch (e: unknown) {
    const code = (e as { name?: string; $metadata?: { httpStatusCode?: number } }).name;
    const status = (e as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
    if (code === 'PreconditionFailed' || status === 412) {
      throw new Error(
        `status.json already exists. Ceremony state is in flight; round-zero ` +
          'is the bootstrap step and should only run once. Delete ' +
          `${cfg.publicBase}/${STATUS_KEY} only if you intend to fully reset.`,
      );
    }
    throw e;
  }
  console.log(`Bootstrap complete. status.json initialized at ${cfg.publicBase}/${STATUS_KEY}`);
  console.log(`\nNext: founder DMs round-1 contributor with signed URL from`);
  console.log(`  pnpm tsx scripts/mint-signed-url.ts --round 1 --name "..."`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
