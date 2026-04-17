// Writes the three flattener output artifacts. Schemas are frozen in
// docs/superpowers/plans/2026-04-17-qkb-orchestration.md §2.1.
//
// Bigint serialization: lower-case `0x`-prefixed hex, minimum width one byte
// (single hex digit values are zero-padded to two so consumers can rely on an
// even-length payload).

import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { FlattenedCA } from '../types.js';

export interface WriterInput {
  rTL: bigint;
  treeDepth: number;
  layers: bigint[][];
  cas: FlattenedCA[];
  lotlVersion: string;
  builtAt: string;
}

const toHex = (v: bigint): string => {
  if (v < 0n) throw new Error('bigint must be non-negative for hex serialization');
  let h = v.toString(16);
  if (h.length % 2 === 1) h = `0${h}`;
  return `0x${h}`;
};

const toB64 = (b: Uint8Array): string => Buffer.from(b).toString('base64');

export async function writeOutput(input: WriterInput, dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });

  // merkleIndex == position in the input cas[] array, which the caller
  // ensures matches the leaf index in `layers[0]`. The writer preserves
  // input order; downstream readers can re-sort by merkleIndex if needed.
  const trustedCas = {
    version: 1,
    lotlSnapshot: input.builtAt,
    treeDepth: input.treeDepth,
    cas: input.cas.map((c, idx) => ({
      merkleIndex: idx,
      certDerB64: toB64(c.certDer),
      issuerDN: c.issuerDN,
      validFrom: c.validFrom,
      validTo: c.validTo,
      poseidonHash: toHex(c.poseidonHash),
    })),
  };

  const root = {
    rTL: toHex(input.rTL),
    treeDepth: input.treeDepth,
    builtAt: input.builtAt,
    lotlVersion: input.lotlVersion,
  };

  const layers = {
    depth: input.treeDepth,
    layers: input.layers.map((layer) => layer.map(toHex)),
  };

  await Promise.all([
    writeFile(join(dir, 'trusted-cas.json'), `${JSON.stringify(trustedCas, null, 2)}\n`),
    writeFile(join(dir, 'root.json'), `${JSON.stringify(root, null, 2)}\n`),
    writeFile(join(dir, 'layers.json'), `${JSON.stringify(layers, null, 2)}\n`),
  ]);
}
