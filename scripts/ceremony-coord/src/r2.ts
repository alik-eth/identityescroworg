// R2 (S3-compatible) client + helpers. R2 honours the AWS SigV4 signed-URL
// flow for both GET and PUT. We use single-PUT signed URLs for contributor
// uploads (single-shot, write-once enforced via `If-None-Match: *` baked
// into the signature — see mintSignedPutUrl).

import {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
  HeadObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

export interface R2Config {
  readonly accountId: string;
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
  readonly bucket: string;
  readonly publicBase: string;
}

export function loadR2Config(): R2Config {
  const required = [
    'R2_ACCOUNT_ID',
    'R2_ACCESS_KEY_ID',
    'R2_SECRET_ACCESS_KEY',
  ] as const;
  for (const k of required) {
    if (!process.env[k]) throw new Error(`missing env: ${k}`);
  }
  // R2_PUBLIC_BASE_URL is the canonical name (matches root .env convention);
  // R2_PUBLIC_BASE is accepted for backward-compat with earlier scaffolds.
  const publicBase =
    process.env.R2_PUBLIC_BASE_URL ??
    process.env.R2_PUBLIC_BASE ??
    'https://prove.zkqes.org';
  // Allow either `prove.zkqes.org` or `https://...` form.
  const normalizedPublicBase = publicBase.startsWith('http')
    ? publicBase
    : `https://${publicBase}`;
  return {
    accountId: process.env.R2_ACCOUNT_ID!,
    accessKeyId: process.env.R2_ACCESS_KEY_ID!,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY!,
    bucket: process.env.R2_BUCKET ?? 'proving-1',
    publicBase: normalizedPublicBase,
  };
}

export function makeR2Client(cfg: R2Config): S3Client {
  return new S3Client({
    region: 'auto',
    endpoint: `https://${cfg.accountId}.r2.cloudflarestorage.com`,
    credentials: {
      accessKeyId: cfg.accessKeyId,
      secretAccessKey: cfg.secretAccessKey,
    },
  });
}

export const ROUND_KEY = (round: number) => `ceremony/rounds/round-${round}.zkey`;
export const STATUS_KEY = 'ceremony/status.json';
export const FINAL_ZKEY_KEY = 'zkqes-v5-final.zkey';
export const VKEY_KEY = 'verification_key.json';
export const PTAU_KEY = 'ceremony/pot/pot23.ptau';

export const SIGNED_URL_TTL_SECONDS = 24 * 60 * 60;

/**
 * Mint a write-once signed PUT URL for a round zkey upload.
 *
 * Write-once is enforced via `If-None-Match: *` baked into the SigV4
 * signature (same mechanism as S3 conditional writes). The first PUT to
 * this key succeeds; any subsequent PUT — including replay by the
 * contributor of a different (potentially malicious) zkey — returns
 * HTTP 412 Precondition Failed. This closes the replay-after-verify
 * attack: once a round's zkey is in R2 and the admin has verified it,
 * the contributor cannot overwrite it with a different file even though
 * their signed URL hasn't expired.
 *
 * Caveat: the 24h TTL still gates the FIRST upload (so a contributor can
 * complete their compute within the window). After the first successful
 * upload, the conditional header takes over and subsequent uploads fail
 * regardless of TTL.
 */
export async function mintSignedPutUrl(
  client: S3Client,
  cfg: R2Config,
  round: number,
): Promise<string> {
  const cmd = new PutObjectCommand({
    Bucket: cfg.bucket,
    Key: ROUND_KEY(round),
    ContentType: 'application/octet-stream',
    IfNoneMatch: '*',
  });
  return getSignedUrl(client, cmd, { expiresIn: SIGNED_URL_TTL_SECONDS });
}

/** Throws if the object already exists (write-once enforcement). */
export async function assertObjectAbsent(
  client: S3Client,
  cfg: R2Config,
  key: string,
): Promise<void> {
  try {
    await client.send(new HeadObjectCommand({ Bucket: cfg.bucket, Key: key }));
    throw new Error(`object already exists: ${key}`);
  } catch (e: unknown) {
    if (e instanceof Error && e.message.startsWith('object already exists')) throw e;
    // 404 from R2 surfaces as NotFound — that's the success path
    const code = (e as { name?: string }).name;
    if (code === 'NotFound' || code === 'NoSuchKey') return;
    throw e;
  }
}

/**
 * Read status.json with the current ETag captured for conditional writes.
 *
 * Concurrency model: status.json updates are admin-only. With a single
 * admin running this tool, races are rare in practice. The ETag
 * round-trip below is defense-in-depth, not the primary safeguard
 * (admin discipline of "one publish-status invocation at a time" is).
 */
export async function readStatusWithEtag(
  client: S3Client,
  cfg: R2Config,
): Promise<{ body: string; etag: string }> {
  const r = await client.send(
    new GetObjectCommand({ Bucket: cfg.bucket, Key: STATUS_KEY }),
  );
  if (!r.Body) throw new Error('status.json missing');
  const body = await r.Body.transformToString('utf-8');
  const etag = r.ETag;
  if (!etag) throw new Error('status.json missing ETag');
  return { body, etag };
}

/**
 * Write status.json conditional on the ETag matching what we read.
 *
 * If R2 returns 412 Precondition Failed, another publish landed in the
 * gap: caller should re-read + retry. Currently surfaces the SDK error
 * directly; callers are single-admin and rare-race, so a manual retry
 * is acceptable. If we ever need automated retries, wrap this in a
 * `withRetryOnPreconditionFailed` helper.
 *
 * Note: the AWS SDK v3 PutObjectCommand does support `IfMatch`
 * officially (as of @aws-sdk/client-s3 ≥ 3.681). Earlier scaffold's
 * `@ts-expect-error` was based on stale typings; removed.
 */
export async function writeStatusConditional(
  client: S3Client,
  cfg: R2Config,
  body: string,
  ifMatch: string,
): Promise<void> {
  await client.send(
    new PutObjectCommand({
      Bucket: cfg.bucket,
      Key: STATUS_KEY,
      Body: body,
      ContentType: 'application/json',
      CacheControl: 'public, max-age=15',
      IfMatch: ifMatch,
    }),
  );
}
