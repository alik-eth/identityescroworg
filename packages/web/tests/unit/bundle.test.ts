import { describe, expect, it } from 'vitest';
import {
  BUNDLE_VERSION,
  buildBundle,
  parseBundle,
  serializeBundle,
  validateBundle,
} from '../../src/lib/bundle';
import type { Groth16Proof } from '../../src/lib/prover';

const SAMPLE_PROOF: Groth16Proof = {
  pi_a: ['0x1', '0x2', '0x1'],
  pi_b: [
    ['0x3', '0x4'],
    ['0x5', '0x6'],
    ['0x1', '0x0'],
  ],
  pi_c: ['0x7', '0x8', '0x1'],
  protocol: 'groth16',
  curve: 'bn128',
};

const PUBLIC_SIGNALS = Array.from({ length: 13 }, (_, i) => `0x${(i + 1).toString(16)}`);

const baseInput = () => ({
  bcanon: new TextEncoder().encode('{"v":"QKB/1.0"}'),
  bcanonHash: new Uint8Array(32).fill(0xab),
  cades: new Uint8Array([1, 2, 3]),
  leafCertDer: new Uint8Array([4, 5, 6]),
  intCertDer: new Uint8Array([7, 8, 9]),
  proof: SAMPLE_PROOF,
  publicSignals: PUBLIC_SIGNALS,
  algorithmTag: 0 as const,
  circuitVersion: 'qkb-presentation-v1',
  trustedListRoot:
    '0x2aabe358cd38fe2859cdc57d62d611d76bce881ec49ecefa2d26f9338ff0228f',
  builtAt: '2026-04-17T03:00:00.000Z',
});

describe('bundle', () => {
  it('buildBundle produces the orchestration §2.4 shape', () => {
    const b = buildBundle(baseInput());
    expect(b.version).toBe(BUNDLE_VERSION);
    expect(b.binding.bcanonB64).toBe(btoa('{"v":"QKB/1.0"}'));
    expect(b.binding.bcanonHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(b.qes.cadesB64).toBe(btoa('\x01\x02\x03'));
    expect(b.qes.leafCertDerB64).toBe(btoa('\x04\x05\x06'));
    expect(b.qes.intCertDerB64).toBe(btoa('\x07\x08\x09'));
    expect(b.algorithmTag).toBe(0);
    expect(b.publicSignals).toEqual(PUBLIC_SIGNALS);
    expect(b.circuitVersion).toBe('qkb-presentation-v1');
    expect(b.builtAt).toBe('2026-04-17T03:00:00.000Z');
  });

  it('round-trips: build → serialize → parse equals build output', () => {
    const built = buildBundle(baseInput());
    const json = serializeBundle(built);
    const parsed = parseBundle(json);
    expect(parsed).toEqual(built);
  });

  it('builtAt defaults to a fresh ISO timestamp', () => {
    const inp = baseInput();
    delete (inp as { builtAt?: string }).builtAt;
    const b = buildBundle(inp);
    expect(() => new Date(b.builtAt).toISOString()).not.toThrow();
  });

  it('accepts algorithmTag=1 for ECDSA', () => {
    const b = buildBundle({ ...baseInput(), algorithmTag: 1 });
    const round = parseBundle(serializeBundle(b));
    expect(round.algorithmTag).toBe(1);
  });

  it('parseBundle rejects malformed JSON with bundle.malformed', () => {
    expect(() => parseBundle('not json')).toThrowError(
      expect.objectContaining({ code: 'bundle.malformed' }) as unknown as Error,
    );
  });

  it('validateBundle rejects wrong version', () => {
    const b = { ...buildBundle(baseInput()), version: 'QKB/2.0' };
    expect(() => validateBundle(b)).toThrowError(
      expect.objectContaining({ code: 'bundle.malformed' }) as unknown as Error,
    );
  });

  it('validateBundle rejects missing binding fields', () => {
    const b = { ...buildBundle(baseInput()), binding: { bcanonB64: '' } };
    expect(() => validateBundle(b)).toThrowError(
      expect.objectContaining({ code: 'bundle.malformed' }) as unknown as Error,
    );
  });

  it('validateBundle rejects missing qes fields', () => {
    const b = {
      ...buildBundle(baseInput()),
      qes: { cadesB64: 'a', leafCertDerB64: 'b' },
    };
    expect(() => validateBundle(b)).toThrowError(
      expect.objectContaining({ code: 'bundle.malformed' }) as unknown as Error,
    );
  });

  it('validateBundle rejects unknown algorithmTag', () => {
    const b = { ...buildBundle(baseInput()), algorithmTag: 7 };
    expect(() => validateBundle(b)).toThrowError(
      expect.objectContaining({ code: 'bundle.malformed' }) as unknown as Error,
    );
  });

  it('validateBundle rejects bad proof shape', () => {
    const b = { ...buildBundle(baseInput()), proof: { pi_a: 'no' } };
    expect(() => validateBundle(b)).toThrowError(
      expect.objectContaining({ code: 'bundle.malformed' }) as unknown as Error,
    );
  });

  it('validateBundle rejects non-string-array publicSignals', () => {
    const b = { ...buildBundle(baseInput()), publicSignals: [1, 2, 3] };
    expect(() => validateBundle(b)).toThrowError(
      expect.objectContaining({ code: 'bundle.malformed' }) as unknown as Error,
    );
  });

  it('validateBundle rejects non-object input', () => {
    expect(() => validateBundle(null)).toThrowError(
      expect.objectContaining({ code: 'bundle.malformed' }) as unknown as Error,
    );
  });
});
