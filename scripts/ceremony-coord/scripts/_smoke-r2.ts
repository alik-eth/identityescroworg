// R2 smoke test — round-trips a 1 KB object via signed PUT URL.
//
// Usage: pnpm tsx scripts/_smoke-r2.ts
//
// Verifies:
//   - .env credentials work
//   - bucket exists + writable
//   - signed-URL flow succeeds end-to-end (mint → PUT → GET → match)
//
// Cleans up the test object on success.

import { randomBytes, createHash } from 'node:crypto';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { loadEnvFromAncestors } from '../src/env.ts';
import { loadR2Config, makeR2Client } from '../src/r2.ts';

loadEnvFromAncestors(import.meta.dirname ?? process.cwd());

const SMOKE_KEY = `_smoke/${Date.now()}-${randomBytes(4).toString('hex')}.bin`;

async function main(): Promise<void> {
  const cfg = loadR2Config();
  const client = makeR2Client(cfg);
  const payload = randomBytes(1024);
  const expectedSha = createHash('sha256').update(payload).digest('hex');

  console.log(`[1/4] Minting signed PUT URL for ${SMOKE_KEY}…`);
  const putUrl = await getSignedUrl(
    client,
    new PutObjectCommand({ Bucket: cfg.bucket, Key: SMOKE_KEY }),
    { expiresIn: 60 },
  );

  console.log('[2/4] Uploading via signed URL…');
  const putRes = await fetch(putUrl, { method: 'PUT', body: payload });
  if (!putRes.ok) throw new Error(`PUT failed: ${putRes.status} ${await putRes.text()}`);

  console.log('[3/4] Downloading via authenticated GET…');
  const getRes = await client.send(
    new GetObjectCommand({ Bucket: cfg.bucket, Key: SMOKE_KEY }),
  );
  const got = Buffer.from(await getRes.Body!.transformToByteArray());
  const gotSha = createHash('sha256').update(got).digest('hex');
  if (gotSha !== expectedSha)
    throw new Error(`hash mismatch: expected ${expectedSha}, got ${gotSha}`);

  console.log('[4/4] Cleaning up smoke object…');
  await client.send(new DeleteObjectCommand({ Bucket: cfg.bucket, Key: SMOKE_KEY }));
  console.log('R2 smoke test PASSED.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
