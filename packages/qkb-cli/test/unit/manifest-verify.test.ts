// Manifest fetch + Ed25519 verify unit tests.
//
// All tests use ephemeral Ed25519 keypairs generated per-test via
// `crypto.generateKeyPairSync` — keeps the suite self-contained and
// independent of the lead-issued dev key at /tmp/qkb-cli-dev-keys/.
// The dev key path gets exercised in T6 integration testing (real
// dev manifest at /tmp/dev-manifest.json).
//
// Manifest URLs are file:// in these tests — fetchAndVerifyManifest
// dispatches on URL scheme so file:// uses fs.readFile (Node 20's
// global fetch rejects file://).

import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  fetchAndVerifyManifest,
  ManifestSignatureError,
  ManifestParseError,
} from '../../src/manifest/fetch.js';
import type { ManifestV1 } from '../../src/manifest/types.js';

const VALID_MANIFEST: ManifestV1 = {
  version: '1.0.0-test',
  released: '2026-05-03T15:30:00Z',
  changelog: 'unit test manifest',
  minSupportedVersion: '1.0.0-test',
  circuits: {
    'v5.2': {
      zkeyUrl: 'file:///tmp/test-zkey',
      zkeySha256:
        'b66bad1d27f2e0b00f2db7437a0fab365433165dccb2f11d09ee3eb475debce2',
      wasmUrl: 'file:///tmp/test-wasm',
      wasmSha256:
        '0000000000000000000000000000000000000000000000000000000000000001',
      vkeyUrl: 'file:///tmp/test-vkey',
      vkeySha256:
        'cd80192769ffa3a8b469eefb1374775593c02869854ac17403be768dff82806d',
    },
  },
};

describe('fetchAndVerifyManifest', () => {
  let tmp: string;
  let pubkeyPem: string;
  let privkeyPem: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), 'qkb-cli-manifest-test-'));
    const kp = generateKeyPairSync('ed25519');
    pubkeyPem = kp.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    privkeyPem = kp.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true });
  });

  async function writeSignedManifest(
    manifest: object,
    signWithKey?: string,
  ): Promise<{ manifestUrl: string }> {
    const manifestPath = join(tmp, 'manifest.json');
    const sigPath = join(tmp, 'manifest.json.sig');
    const bytes = Buffer.from(JSON.stringify(manifest));
    await writeFile(manifestPath, bytes);
    const signature = sign(null, bytes, signWithKey ?? privkeyPem);
    await writeFile(sigPath, signature);
    return { manifestUrl: `file://${manifestPath}` };
  }

  it('accepts a well-signed manifest and returns the parsed shape', async () => {
    const { manifestUrl } = await writeSignedManifest(VALID_MANIFEST);
    const result = await fetchAndVerifyManifest({
      manifestUrl,
      verifySignature: true,
      signingKeyPemOverride: pubkeyPem,
    });
    expect(result.version).toBe('1.0.0-test');
    expect(result.circuits['v5.2']?.zkeySha256).toBe(
      VALID_MANIFEST.circuits['v5.2']!.zkeySha256,
    );
  });

  it('rejects a manifest signed with a different key', async () => {
    const otherKey = generateKeyPairSync('ed25519').privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
    const { manifestUrl } = await writeSignedManifest(VALID_MANIFEST, otherKey);

    await expect(
      fetchAndVerifyManifest({
        manifestUrl,
        verifySignature: true,
        signingKeyPemOverride: pubkeyPem, // expects the original pubkey
      }),
    ).rejects.toBeInstanceOf(ManifestSignatureError);
  });

  it('rejects a manifest whose body was tampered after signing', async () => {
    const { manifestUrl } = await writeSignedManifest(VALID_MANIFEST);
    // Overwrite the manifest with different bytes — signature now over
    // stale bytes, will fail to verify.
    const manifestPath = manifestUrl.replace('file://', '');
    await writeFile(
      manifestPath,
      JSON.stringify({ ...VALID_MANIFEST, version: 'tampered' }),
    );

    await expect(
      fetchAndVerifyManifest({
        manifestUrl,
        verifySignature: true,
        signingKeyPemOverride: pubkeyPem,
      }),
    ).rejects.toBeInstanceOf(ManifestSignatureError);
  });

  it('rejects malformed JSON with a clear ManifestParseError', async () => {
    const manifestPath = join(tmp, 'manifest.json');
    const sigPath = join(tmp, 'manifest.json.sig');
    const garbage = Buffer.from('not json {{{');
    await writeFile(manifestPath, garbage);
    await writeFile(sigPath, sign(null, garbage, privkeyPem));

    await expect(
      fetchAndVerifyManifest({
        manifestUrl: `file://${manifestPath}`,
        verifySignature: true,
        signingKeyPemOverride: pubkeyPem,
      }),
    ).rejects.toBeInstanceOf(ManifestParseError);
  });

  it('rejects a manifest missing required schema fields', async () => {
    const incomplete = { version: '1.0.0-test', circuits: {} };
    const { manifestUrl } = await writeSignedManifest(incomplete);

    await expect(
      fetchAndVerifyManifest({
        manifestUrl,
        verifySignature: true,
        signingKeyPemOverride: pubkeyPem,
      }),
    ).rejects.toBeInstanceOf(ManifestParseError);
  });

  it('rejects a manifest with a non-hex sha256 (e.g., placeholder string)', async () => {
    // Catches the dev manifest bug where wasmSha256 was left as
    // "TBD-circuits-eng-T6" — schema rejects with a clear error.
    const withPlaceholder = {
      ...VALID_MANIFEST,
      circuits: {
        'v5.2': {
          ...VALID_MANIFEST.circuits['v5.2']!,
          wasmSha256: 'TBD-circuits-eng-T6',
        },
      },
    };
    const { manifestUrl } = await writeSignedManifest(withPlaceholder);

    await expect(
      fetchAndVerifyManifest({
        manifestUrl,
        verifySignature: true,
        signingKeyPemOverride: pubkeyPem,
      }),
    ).rejects.toBeInstanceOf(ManifestParseError);
  });

  it('skips signature check when verifySignature: false (--no-verify)', async () => {
    const { manifestUrl } = await writeSignedManifest(VALID_MANIFEST);
    // Overwrite signature with garbage — should still verify because
    // we're bypassing.
    const sigPath = `${manifestUrl.replace('file://', '')}.sig`;
    await writeFile(sigPath, Buffer.from('not a valid signature'));

    const result = await fetchAndVerifyManifest({
      manifestUrl,
      verifySignature: false,
    });
    expect(result.version).toBe('1.0.0-test');
  });

  it('rejects unsupported URL schemes', async () => {
    await expect(
      fetchAndVerifyManifest({
        manifestUrl: 'ftp://malicious.example.com/manifest.json',
        verifySignature: false,
      }),
    ).rejects.toThrow(/unsupported manifest URL scheme/);
  });
});
