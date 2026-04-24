/**
 * Age-witness + age-proof-bundle JSON schemas.
 *
 * Browser SPA writes `qkb-age-witness/v1` after the holder re-opens the DOB
 * commitment from the leaf proof. CLI's `qkb prove-age` reads it, runs the
 * Groth16 prover against the age circuit, and emits `qkb-age-proof-bundle/v1`.
 * Three public signals in the on-chain order: dobCommit, ageCutoffDate,
 * ageQualified (see IGroth16AgeVerifierV4).
 */

import { readFile } from 'node:fs/promises';
import type { WitnessArtifactUrls } from './witness-io.js';

export interface AgeWitnessArtifactsBlock {
  readonly age: WitnessArtifactUrls;
  readonly [k: string]: unknown;
}

export interface AgeWitnessInputs {
  readonly dobYmd: string;
  readonly sourceTag: string;
  readonly ageCutoffDate: string;
  readonly dobCommit: string;
  readonly ageQualified: string;
}

export interface AgeWitnessBundle {
  readonly schema: 'qkb-age-witness/v1';
  readonly artifacts: AgeWitnessArtifactsBlock;
  readonly age: AgeWitnessInputs;
}

export interface AgeProofBundle {
  readonly schema: 'qkb-age-proof-bundle/v1';
  readonly proofAge: Record<string, unknown>;
  readonly publicAge: readonly [string, string, string];
}

export async function loadAgeWitness(path: string): Promise<AgeWitnessBundle> {
  const raw = await readFile(path, 'utf-8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `failed to parse age witness JSON at ${path}: ${(err as Error).message}`,
    );
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error(`age witness at ${path} is not a JSON object`);
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.schema !== 'qkb-age-witness/v1') {
    throw new Error(
      `expected qkb-age-witness/v1 schema at ${path}; got ${String(obj.schema)}`,
    );
  }
  return obj as unknown as AgeWitnessBundle;
}

export function buildAgeProofBundle(args: {
  readonly proofAge: Record<string, unknown>;
  readonly publicAge: readonly string[];
}): AgeProofBundle {
  if (args.publicAge.length !== 3) {
    throw new Error(
      `age proof must have 3 public signals; got ${args.publicAge.length}`,
    );
  }
  return {
    schema: 'qkb-age-proof-bundle/v1',
    proofAge: args.proofAge,
    publicAge: [
      args.publicAge[0]!,
      args.publicAge[1]!,
      args.publicAge[2]!,
    ],
  };
}
