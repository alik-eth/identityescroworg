/**
 * Sprint 0 S0.3 — prover variant routing.
 *
 * Validates that pickVariantUrls dispatches to the right ceremony artifacts
 * based on the detected algorithmTag, handling both the Phase-1 single-
 * variant urls.json shape (still in the bundle today) and the Phase-2
 * dual-variant shape {rsa, ecdsa} that the lead will pump after circuits-
 * eng's two-ceremony run.
 */
import { describe, expect, it } from 'vitest';
import {
  pickVariantUrls,
  variantForAlgorithmTag,
  type DualUrlsJson,
  type UrlsJson,
} from '../../src/lib/circuitArtifacts';
import { ALGORITHM_TAG_ECDSA, ALGORITHM_TAG_RSA } from '../../src/lib/cades';

const zero64 = '0'.repeat(64);
const one64 = 'a'.repeat(64);
const two64 = 'b'.repeat(64);

function rsaEntry(): Omit<UrlsJson, 'variant'> {
  return {
    wasmUrl: 'https://prove.identityescrow.org/rsa.wasm',
    zkeyUrl: 'https://prove.identityescrow.org/rsa.zkey',
    wasmSha256: zero64,
    zkeySha256: one64,
  };
}

function ecdsaEntry(): Omit<UrlsJson, 'variant'> {
  return {
    wasmUrl: 'https://prove.identityescrow.org/ecdsa.wasm',
    zkeyUrl: 'https://prove.identityescrow.org/ecdsa.zkey',
    wasmSha256: two64,
    zkeySha256: zero64,
  };
}

describe('variantForAlgorithmTag', () => {
  it('maps algorithmTag 0 → rsa and 1 → ecdsa', () => {
    expect(variantForAlgorithmTag(ALGORITHM_TAG_RSA)).toBe('rsa');
    expect(variantForAlgorithmTag(ALGORITHM_TAG_ECDSA)).toBe('ecdsa');
  });
});

describe('pickVariantUrls — dual-variant Phase-2 schema', () => {
  it('picks rsa entry when requested', () => {
    const dual: DualUrlsJson = {
      rsa: { variant: 'rsa', ...rsaEntry() },
      ecdsa: { variant: 'ecdsa', ...ecdsaEntry() },
    };
    const picked = pickVariantUrls(dual, 'rsa');
    expect(picked.variant).toBe('rsa');
    expect(picked.wasmUrl).toBe('https://prove.identityescrow.org/rsa.wasm');
    expect(picked.wasmSha256).toBe(zero64);
  });

  it('picks ecdsa entry when requested', () => {
    const dual: DualUrlsJson = {
      rsa: { variant: 'rsa', ...rsaEntry() },
      ecdsa: { variant: 'ecdsa', ...ecdsaEntry() },
    };
    const picked = pickVariantUrls(dual, 'ecdsa');
    expect(picked.variant).toBe('ecdsa');
    expect(picked.zkeyUrl).toBe('https://prove.identityescrow.org/ecdsa.zkey');
    expect(picked.wasmSha256).toBe(two64);
  });

  it('overrides inner variant key with the requested variant (avoids mis-labeled entries)', () => {
    // Even if somehow the inner entry carries a wrong `variant`, the picker
    // pins the requested variant on the returned UrlsJson so downstream
    // loaders cannot pull a mismatched artifact.
    const bad = { rsa: { variant: 'ecdsa', ...rsaEntry() }, ecdsa: { variant: 'rsa', ...ecdsaEntry() } };
    const picked = pickVariantUrls(bad, 'rsa');
    expect(picked.variant).toBe('rsa');
  });

  it('throws prover.artifactMismatch when the requested variant is absent', () => {
    const partial = { rsa: { variant: 'rsa', ...rsaEntry() }, ecdsa: null };
    expect(() => pickVariantUrls(partial, 'ecdsa')).toThrowError(
      expect.objectContaining({ code: 'prover.artifactMismatch' }) as unknown as Error,
    );
  });
});

describe('pickVariantUrls — Phase-1 single-variant fallback', () => {
  it('passes through a single-variant ecdsa urls.json unchanged', () => {
    const single: UrlsJson = { variant: 'ecdsa', ...ecdsaEntry() };
    const picked = pickVariantUrls(single, 'ecdsa');
    expect(picked.variant).toBe('ecdsa');
    expect(picked.wasmUrl).toBe('https://prove.identityescrow.org/ecdsa.wasm');
  });

  it('rejects a single-variant file when the wrong variant is requested', () => {
    const single: UrlsJson = { variant: 'ecdsa', ...ecdsaEntry() };
    expect(() => pickVariantUrls(single, 'rsa')).toThrowError(
      expect.objectContaining({ code: 'prover.artifactMismatch' }) as unknown as Error,
    );
  });
});

describe('pickVariantUrls — malformed input', () => {
  it('throws on non-object input', () => {
    expect(() => pickVariantUrls(null, 'rsa')).toThrowError(
      expect.objectContaining({ code: 'prover.artifactMismatch' }) as unknown as Error,
    );
    expect(() => pickVariantUrls('not-an-object', 'rsa')).toThrowError(
      expect.objectContaining({ code: 'prover.artifactMismatch' }) as unknown as Error,
    );
  });

  it('throws on entry with bad sha (dual shape)', () => {
    const dual = {
      rsa: { variant: 'rsa', ...rsaEntry(), wasmSha256: 'not-hex' },
      ecdsa: { variant: 'ecdsa', ...ecdsaEntry() },
    };
    expect(() => pickVariantUrls(dual, 'rsa')).toThrowError(
      expect.objectContaining({ code: 'prover.artifactMismatch' }) as unknown as Error,
    );
  });
});
