// Manifest fetch + Ed25519 verify — orchestration §1.3.
//
// Fetches `<manifest-url>` and `<manifest-url>.sig`, verifies the
// detached Ed25519 signature against the embedded production
// pubkey (`signing-key.ts`), and returns the parsed `ManifestV1`.
//
// Schemes supported:
//   https://, http://  — Node's global `fetch`.
//   file://             — `fs/promises.readFile` (Node 20's fetch
//                         rejects file:// schemes — explicit dispatch
//                         here keeps the dev workflow local-file-only
//                         while production lives behind HTTPS).
//
// Bypass: callers can pass `verifySignature: false` to skip the
// crypto check (used by `--no-verify` flag).  Stderr warning on every
// `zkqes serve` boot when this is true is emitted by the caller, not
// here — this module stays free of console writes for testability.

import { createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { ManifestParseError, parseManifest, type ManifestV1 } from './types.js';
import { EMBEDDED_MANIFEST_SIGNING_PUBKEY_PEM } from './signing-key.js';

export class ManifestSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ManifestSignatureError';
  }
}

export interface FetchManifestInput {
  /** Manifest URL.  Sig is fetched from `${manifestUrl}.sig`. */
  readonly manifestUrl: string;
  /** Skip Ed25519 verification.  ONLY for `--no-verify` dev flag. */
  readonly verifySignature: boolean;
  /** Override embedded signing pubkey (used by tests; production uses embedded). */
  readonly signingKeyPemOverride?: string;
}

export async function fetchAndVerifyManifest(
  input: FetchManifestInput,
): Promise<ManifestV1> {
  const manifestBytes = await fetchBytes(input.manifestUrl);

  if (input.verifySignature) {
    const sigBytes = await fetchBytes(`${input.manifestUrl}.sig`);
    const pubkeyPem =
      input.signingKeyPemOverride ?? EMBEDDED_MANIFEST_SIGNING_PUBKEY_PEM;
    const pubkey = createPublicKey({ key: pubkeyPem, format: 'pem' });

    // Ed25519 verify: pass `null` algorithm (Ed25519 has its own
    // hash); pass the raw manifest bytes (not a digest); pass the
    // raw 64-byte signature.
    const ok = verify(null, manifestBytes, pubkey, sigBytes);
    if (!ok) {
      throw new ManifestSignatureError(
        `Ed25519 signature verification failed for ${input.manifestUrl}`,
      );
    }
  }

  const rawJson = manifestBytes.toString('utf8');
  return parseManifest(rawJson);
}

/** Re-export for convenience to callers that want to surface error type. */
export { ManifestParseError };

async function fetchBytes(url: string): Promise<Buffer> {
  if (url.startsWith('file://')) {
    const path = fileURLToPath(url);
    return readFile(path);
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    throw new Error(`unsupported manifest URL scheme: ${url}`);
  }
  const res = await fetch(url, {
    // No credentials — manifest is public.
    credentials: 'omit',
    redirect: 'follow',
  });
  if (!res.ok) {
    throw new Error(`fetch ${url} failed: HTTP ${res.status}`);
  }
  const ab = await res.arrayBuffer();
  return Buffer.from(ab);
}
