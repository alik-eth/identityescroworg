import { describe, expect, it } from 'vitest';
import {
  buildInclusionPath,
  canonicalizeCertHash,
  lookupCa,
  recomputeRoot,
  type LayersFile,
  type TrustedCasFile,
} from '../../src/lib/merkleLookup';
import trustedCas from '../fixtures/flattener/trusted-cas.json';
import root from '../fixtures/flattener/root.json';
import layers from '../fixtures/flattener/layers.json';

const TRUSTED: TrustedCasFile = trustedCas as TrustedCasFile;
const LAYERS: LayersFile = layers as LayersFile;
const ROOT_HEX = (root as { rTL: string }).rTL.toLowerCase();

const KNOWN_DER = b64ToBytes(TRUSTED.cas[0]!.certDerB64);
const KNOWN_POSEIDON = TRUSTED.cas[0]!.poseidonHash!.toLowerCase();

describe('canonicalizeCertHash', () => {
  it('matches the pinned poseidonHash from the flattener for the test CA', async () => {
    const v = await canonicalizeCertHash(KNOWN_DER);
    expect(`0x${v.toString(16).padStart(64, '0')}`).toBe(KNOWN_POSEIDON);
  });

  it('is deterministic across calls', async () => {
    const a = await canonicalizeCertHash(KNOWN_DER);
    const b = await canonicalizeCertHash(KNOWN_DER);
    expect(a).toBe(b);
  });

  it('changes when a single byte is flipped', async () => {
    const orig = await canonicalizeCertHash(KNOWN_DER);
    const flipped = new Uint8Array(KNOWN_DER);
    flipped[100]! ^= 0x01;
    const mut = await canonicalizeCertHash(flipped);
    expect(mut).not.toBe(orig);
  });
});

describe('lookupCa', () => {
  it('returns merkleIndex + poseidonHash for a known CA DER', async () => {
    const r = await lookupCa(KNOWN_DER, TRUSTED);
    expect(r.merkleIndex).toBe(0);
    expect(r.poseidonHashHex).toBe(KNOWN_POSEIDON);
  });

  it('returns the first match when multiple entries share the same DER', async () => {
    const der = b64ToBytes(TRUSTED.cas[1]!.certDerB64);
    const r = await lookupCa(der, TRUSTED);
    expect([0, 1]).toContain(r.merkleIndex);
    expect(r.poseidonHashHex).toBe(KNOWN_POSEIDON);
  });

  it('throws qes.unknownCA for a DER not in the trust list', async () => {
    const fake = new Uint8Array([0x30, 0x82, 0, 0]);
    await expect(lookupCa(fake, TRUSTED)).rejects.toMatchObject({ code: 'qes.unknownCA' });
  });
});

describe('buildInclusionPath', () => {
  it('reconstructs the on-disk root for merkleIndex=0', async () => {
    const proof = await buildInclusionPath(0, LAYERS);
    expect(proof.rootHex).toBe(ROOT_HEX);
    expect(proof.path).toHaveLength(LAYERS.depth);
    expect(proof.indices).toHaveLength(LAYERS.depth);
  });

  it('recomputeRoot from the leaf + path matches the on-disk rTL', async () => {
    const leaf = await canonicalizeCertHash(KNOWN_DER);
    const proof = await buildInclusionPath(0, LAYERS);
    const reroot = await recomputeRoot(leaf, 0, proof);
    expect(`0x${reroot.toString(16).padStart(64, '0')}`).toBe(ROOT_HEX);
  });

  it('reconstructs the root for merkleIndex=1 too', async () => {
    const der = b64ToBytes(TRUSTED.cas[1]!.certDerB64);
    const leaf = await canonicalizeCertHash(der);
    const proof = await buildInclusionPath(1, LAYERS);
    const reroot = await recomputeRoot(leaf, 1, proof);
    expect(`0x${reroot.toString(16).padStart(64, '0')}`).toBe(ROOT_HEX);
  });

  it('rejects a negative index with qes.unknownCA', async () => {
    await expect(buildInclusionPath(-1, LAYERS)).rejects.toMatchObject({
      code: 'qes.unknownCA',
    });
  });

  it('rejects a layers file with wrong depth shape', async () => {
    const bad: LayersFile = { depth: 16, layers: [['0x0']] };
    await expect(buildInclusionPath(0, bad)).rejects.toMatchObject({
      code: 'qes.unknownCA',
    });
  });
});

function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
