import { describe, expect, it } from 'vitest';
import {
  MockProver,
  proveSplit,
  type AlgorithmArtifactUrls,
} from '../src/prover/index.js';
import type { Phase2Witness } from '../src/core/index.js';

const ARTIFACTS: AlgorithmArtifactUrls = {
  leaf: {
    wasmUrl: 'https://example.test/leaf.wasm',
    zkeyUrl: 'https://example.test/leaf.zkey',
    zkeySha256: 'a'.repeat(64),
  },
  chain: {
    wasmUrl: 'https://example.test/chain.wasm',
    zkeyUrl: 'https://example.test/chain.zkey',
    zkeySha256: 'b'.repeat(64),
  },
};

function makeWitness(): Phase2Witness {
  return {
    leaf: {
      pkX: ['1', '2', '3', '4'],
      pkY: ['5', '6', '7', '8'],
      ctxHash: '100',
      declHash: '200',
      timestamp: '1730000000',
      nullifier: '42',
      leafSpkiCommit: '99',
      subjectSerialValueOffset: 0,
      subjectSerialValueLength: 0,
      Bcanon: [],
      BcanonLen: 0,
      BcanonPaddedIn: [],
      BcanonPaddedLen: 0,
      pkValueOffset: 0,
      schemeValueOffset: 0,
      ctxValueOffset: 0,
      ctxHexLen: 0,
      declValueOffset: 0,
      declValueLen: 0,
      tsValueOffset: 0,
      tsDigitCount: 0,
      declPaddedIn: [],
      declPaddedLen: 0,
      signedAttrs: [],
      signedAttrsLen: 0,
      signedAttrsPaddedIn: [],
      signedAttrsPaddedLen: 0,
      mdOffsetInSA: 0,
      leafDER: [],
      leafSpkiXOffset: 0,
      leafSpkiYOffset: 0,
      leafSigR: [],
      leafSigS: [],
    },
    chain: {
      rTL: '0xdeadbeef',
      algorithmTag: '1',
      leafSpkiCommit: '99',
      leafDER: [],
      leafSpkiXOffset: 0,
      leafSpkiYOffset: 0,
      leafTbsPaddedIn: [],
      leafTbsPaddedLen: 0,
      intDER: [],
      intDerLen: 0,
      intSpkiXOffset: 0,
      intSpkiYOffset: 0,
      intSigR: [],
      intSigS: [],
      merklePath: [],
      merkleIndices: [],
    },
    shared: {
      pkX: ['1', '2', '3', '4'],
      pkY: ['5', '6', '7', '8'],
      ctxHash: '100',
      declHash: '200',
      timestamp: '1730000000',
      nullifier: '42',
      leafSpkiCommit: '99',
      rTL: '0xdeadbeef',
      algorithmTag: '1',
    },
  };
}

describe('MockProver', () => {
  it('emits witness/prove/finalize progress events in order', async () => {
    const seen: string[] = [];
    const prover = new MockProver({ delayMs: 6 });
    await prover.prove(
      { side: 'leaf' } as Record<string, unknown>,
      {
        wasmUrl: 'x',
        zkeyUrl: 'y',
        side: 'leaf',
        onProgress: (p) => seen.push(p.stage),
      },
    );
    expect(seen).toEqual(['witness', 'prove', 'finalize']);
  });

  it('returns the canned default when no witness shape match', async () => {
    const prover = new MockProver({ delayMs: 0 });
    const r = await prover.prove(
      { totally: 'unrelated' },
      { wasmUrl: 'x', zkeyUrl: 'y', side: 'leaf' },
    );
    expect(r.publicSignals).toHaveLength(16);
  });

  it('shapes V3 leaf publicSignals to length 13 when declHash is present', async () => {
    const prover = new MockProver({ delayMs: 0 });
    const r = await prover.prove(
      {
        pkX: ['1', '2', '3', '4'],
        pkY: ['5', '6', '7', '8'],
        ctxHash: '9',
        declHash: '10',
        timestamp: '11',
        nullifier: '12',
        leafSpkiCommit: '13',
      } as Record<string, unknown>,
      { wasmUrl: 'x', zkeyUrl: 'y', side: 'leaf' },
    );
    expect(r.publicSignals).toHaveLength(13);
    expect(r.publicSignals[12]).toBe('13');
  });

  it('shapes V4 leaf publicSignals to length 16 when policyLeafHash + policyRoot are present', async () => {
    const prover = new MockProver({ delayMs: 0 });
    const r = await prover.prove(
      {
        pkX: ['1', '2', '3', '4'],
        pkY: ['5', '6', '7', '8'],
        ctxHash: '9',
        policyLeafHash: '10',
        policyRoot: '11',
        timestamp: '12',
        nullifier: '13',
        leafSpkiCommit: '14',
        dobCommit: '15',
        dobSupported: '1',
      } as Record<string, unknown>,
      { wasmUrl: 'x', zkeyUrl: 'y', side: 'leaf' },
    );
    expect(r.publicSignals).toHaveLength(16);
    expect(r.publicSignals[15]).toBe('1');
  });

  it('shapes chain publicSignals to length 3', async () => {
    const prover = new MockProver({ delayMs: 0 });
    const r = await prover.prove(
      {
        rTL: '0xfeed',
        algorithmTag: '1',
        leafSpkiCommit: '99',
      } as Record<string, unknown>,
      { wasmUrl: 'x', zkeyUrl: 'y', side: 'chain' },
    );
    expect(r.publicSignals).toEqual(['0xfeed', '1', '99']);
  });

  it('rejects with prover.cancelled when AbortSignal fires before prove starts', async () => {
    const prover = new MockProver({ delayMs: 100 });
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(
      prover.prove({} as Record<string, unknown>, {
        wasmUrl: 'x',
        zkeyUrl: 'y',
        signal: ctrl.signal,
      }),
    ).rejects.toMatchObject({ code: 'prover.cancelled' });
  });
});

describe('proveSplit', () => {
  it('runs leaf then chain serially and tags progress with side', async () => {
    const prover = new MockProver({ delayMs: 6 });
    const seen: Array<{ side: string; stage: string }> = [];
    const result = await proveSplit(makeWitness(), {
      prover,
      artifacts: ARTIFACTS,
      onProgress: (p) => seen.push({ side: p.side, stage: p.stage }),
    });
    expect(result.proofLeaf).toBeDefined();
    expect(result.proofChain).toBeDefined();
    expect(result.publicLeaf).toHaveLength(13);
    expect(result.publicChain).toHaveLength(3);
    const sides = seen.map((s) => s.side);
    const firstChain = sides.indexOf('chain');
    const lastLeaf = sides.lastIndexOf('leaf');
    expect(firstChain).toBeGreaterThan(lastLeaf);
  });
});
