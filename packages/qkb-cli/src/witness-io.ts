/**
 * Witness-bundle JSON schema + loader.
 *
 * The browser SPA writes this file from `/upload` after verify + witness build
 * (src/routes/upload.tsx). The CLI reads it and hands the two witnesses to the
 * chosen prover backend. Keeping the schema versioned (`schema: "qkb-witness/v1"`)
 * so future circuit revisions can evolve the payload without silent breakage.
 */

import { readFile } from 'node:fs/promises';

export interface WitnessArtifactUrls {
  readonly wasmUrl: string;
  readonly zkeyUrl: string;
  readonly wasmSha256: string;
  readonly zkeySha256: string;
}

export interface WitnessArtifactsBlock {
  readonly leaf: WitnessArtifactUrls;
  readonly chain: WitnessArtifactUrls;
  // Additional urls.json fields we pass through without touching.
  readonly [k: string]: unknown;
}

export interface WitnessBundle {
  readonly schema: 'qkb-witness/v1';
  readonly circuitVersion: string;
  readonly algorithmTag: 0 | 1;
  readonly artifacts: WitnessArtifactsBlock;
  readonly leaf: Record<string, unknown>;
  readonly chain: Record<string, unknown>;
}

export async function loadWitnessBundle(path: string): Promise<WitnessBundle> {
  const raw = await readFile(path, 'utf-8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`witness bundle is not valid JSON: ${(err as Error).message}`);
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('witness bundle must be a JSON object');
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.schema !== 'qkb-witness/v1') {
    throw new Error(
      `witness bundle schema must be "qkb-witness/v1" (got ${JSON.stringify(obj.schema)})`,
    );
  }
  if (typeof obj.circuitVersion !== 'string') {
    throw new Error('witness bundle missing circuitVersion');
  }
  if (obj.algorithmTag !== 0 && obj.algorithmTag !== 1) {
    throw new Error(
      `witness bundle algorithmTag must be 0 or 1 (got ${JSON.stringify(obj.algorithmTag)})`,
    );
  }
  const artifacts = obj.artifacts as Record<string, unknown> | undefined;
  if (!artifacts || typeof artifacts !== 'object') {
    throw new Error('witness bundle missing artifacts block');
  }
  assertArtifactSide(artifacts.leaf, 'leaf');
  assertArtifactSide(artifacts.chain, 'chain');
  if (!obj.leaf || typeof obj.leaf !== 'object') {
    throw new Error('witness bundle missing leaf witness');
  }
  if (!obj.chain || typeof obj.chain !== 'object') {
    throw new Error('witness bundle missing chain witness');
  }
  return obj as unknown as WitnessBundle;
}

function assertArtifactSide(v: unknown, side: 'leaf' | 'chain'): void {
  if (!v || typeof v !== 'object') {
    throw new Error(`witness bundle artifacts.${side} missing`);
  }
  const side_ = v as Record<string, unknown>;
  const required = ['wasmUrl', 'zkeyUrl', 'wasmSha256', 'zkeySha256'];
  for (const k of required) {
    if (typeof side_[k] !== 'string' || (side_[k] as string).length === 0) {
      throw new Error(`witness bundle artifacts.${side}.${k} must be a non-empty string`);
    }
  }
}

export interface ProofBundle {
  readonly schema: 'qkb-proof-bundle/v1';
  readonly circuitVersion: string;
  readonly algorithmTag: 0 | 1;
  readonly proofLeaf: Record<string, unknown>;
  readonly publicLeaf: string[];
  readonly proofChain: Record<string, unknown>;
  readonly publicChain: string[];
}

export function buildProofBundle(args: {
  circuitVersion: string;
  algorithmTag: 0 | 1;
  proofLeaf: Record<string, unknown>;
  publicLeaf: string[];
  proofChain: Record<string, unknown>;
  publicChain: string[];
}): ProofBundle {
  if (args.publicLeaf.length !== 13) {
    throw new Error(
      `leaf public signals must have 13 entries (got ${args.publicLeaf.length})`,
    );
  }
  if (args.publicChain.length !== 3) {
    throw new Error(
      `chain public signals must have 3 entries (got ${args.publicChain.length})`,
    );
  }
  return {
    schema: 'qkb-proof-bundle/v1',
    circuitVersion: args.circuitVersion,
    algorithmTag: args.algorithmTag,
    proofLeaf: args.proofLeaf,
    publicLeaf: args.publicLeaf,
    proofChain: args.proofChain,
    publicChain: args.publicChain,
  };
}
