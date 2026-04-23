import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import {
  buildAgeProofBundle,
  loadAgeWitness,
} from '../src/age-witness-io.js';

describe('age witness + proof bundle schemas', () => {
  it('round-trips qkb-age-witness/v1', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'qkb-age-'));
    const path = join(dir, 'witness.json');
    try {
      await writeFile(
        path,
        JSON.stringify({
          schema: 'qkb-age-witness/v1',
          artifacts: {
            age: {
              wasmUrl: 'https://x/age.wasm',
              wasmSha256: 'a'.repeat(64),
              zkeyUrl: 'https://x/age.zkey',
              zkeySha256: 'b'.repeat(64),
            },
          },
          age: {
            dobYmd: '19900815',
            sourceTag: '1',
            ageCutoffDate: '20080424',
            dobCommit: '42',
            ageQualified: '1',
          },
        }),
      );
      const w = await loadAgeWitness(path);
      expect(w.schema).toBe('qkb-age-witness/v1');
      expect(w.age.ageCutoffDate).toBe('20080424');
      expect(w.age.dobCommit).toBe('42');
      expect(w.artifacts.age.wasmUrl).toBe('https://x/age.wasm');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('rejects a file with the wrong schema', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'qkb-age-'));
    const path = join(dir, 'witness.json');
    try {
      await writeFile(path, JSON.stringify({ schema: 'bogus/v0' }));
      await expect(loadAgeWitness(path)).rejects.toThrow(/qkb-age-witness/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('builds qkb-age-proof-bundle/v1 with 3 public signals', () => {
    const bundle = buildAgeProofBundle({
      proofAge: {
        pi_a: ['0', '0'],
        pi_b: [
          ['0', '0'],
          ['0', '0'],
        ],
        pi_c: ['0', '0'],
      },
      publicAge: ['123', '20080424', '1'],
    });
    expect(bundle.schema).toBe('qkb-age-proof-bundle/v1');
    expect(bundle.publicAge).toEqual(['123', '20080424', '1']);
  });

  it('rejects publicAge with wrong length', () => {
    expect(() =>
      buildAgeProofBundle({
        proofAge: {},
        publicAge: ['1', '2'],
      }),
    ).toThrow(/3 public signals/);
  });
});
