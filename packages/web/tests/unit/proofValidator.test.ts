import { describe, it, expect } from 'vitest';
import { validateProof, type ProofPayload } from '../../src/lib/proofValidator';

const valid: ProofPayload = {
  version: 'qkb/2.0',
  chainProof: { proof: { a: ['1','2'], b: [['3','4'],['5','6']], c: ['7','8'] }, rTL: '9', algorithmTag: 1, leafSpkiCommit: '10' },
  leafProof: {
    proof: { a: ['1','2'], b: [['3','4'],['5','6']], c: ['7','8'] },
    pkX: ['1','2','3','4'], pkY: ['5','6','7','8'],
    ctxHash: '9', policyLeafHash: '10', policyRoot: '11', timestamp: '12',
    nullifier: '13', leafSpkiCommit: '10', dobCommit: '14', dobSupported: '1',
  },
};

describe('proof validator', () => {
  it('accepts a complete valid payload', () => {
    expect(validateProof(valid).ok).toBe(true);
  });

  it('rejects missing version', () => {
    const bad = { ...valid, version: undefined } as unknown as ProofPayload;
    expect(validateProof(bad).ok).toBe(false);
  });

  it('rejects pkX with wrong limb count', () => {
    const bad = { ...valid, leafProof: { ...valid.leafProof, pkX: ['1', '2', '3'] } } as unknown as ProofPayload;
    expect(validateProof(bad).ok).toBe(false);
  });

  it('rejects non-string field values', () => {
    const bad = { ...valid, leafProof: { ...valid.leafProof, nullifier: 13 as unknown as string } };
    expect(validateProof(bad).ok).toBe(false);
  });

  it('rejects malformed JSON-string input', () => {
    expect(validateProof('not-json' as unknown as ProofPayload).ok).toBe(false);
  });
});
