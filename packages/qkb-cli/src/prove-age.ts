/**
 * `qkb prove-age` implementation — Groth16-prove the age circuit offline.
 *
 * Reads a `qkb-age-witness/v1` file, downloads (or reuses the cached) age
 * artifacts, runs the selected backend, and writes `qkb-age-proof-bundle/v1`.
 * Three public signals in the on-chain order: dobCommit, ageCutoffDate,
 * ageQualified.
 */

import { chmod, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { ensureArtifact } from './artifacts.js';
import {
  buildAgeProofBundle,
  loadAgeWitness,
} from './age-witness-io.js';
import type { IProverBackend } from './backend.js';
import { RapidsnarkBackend } from './backend-rapidsnark.js';
import { SnarkjsBackend } from './backend-snarkjs.js';

export interface ProveAgeOptions {
  readonly out: string;
  readonly backend: 'snarkjs' | 'rapidsnark';
  readonly rapidsnarkBin?: string;
  readonly cacheDir: string;
}

export async function runProveAge(
  witnessPath: string,
  opts: ProveAgeOptions,
): Promise<void> {
  console.error(`[qkb] loading age witness from ${witnessPath}`);
  const bundle = await loadAgeWitness(witnessPath);

  const backend = buildBackend(opts);
  console.error(`[qkb] backend: ${backend.name}`);
  console.error(`[qkb] cache dir: ${opts.cacheDir}`);

  const wasm = await ensureArtifact({
    url: bundle.artifacts.age.wasmUrl,
    expectedSha256: bundle.artifacts.age.wasmSha256,
    cacheDir: opts.cacheDir,
    label: 'age wasm',
  });
  const zkey = await ensureArtifact({
    url: bundle.artifacts.age.zkeyUrl,
    expectedSha256: bundle.artifacts.age.zkeySha256,
    cacheDir: opts.cacheDir,
    label: 'age zkey',
  });

  const { proof, publicSignals } = await backend.prove({
    side: 'age',
    witness: bundle.age as unknown as Record<string, unknown>,
    wasmPath: wasm,
    zkeyPath: zkey,
    onLog: (m) => console.error(`[qkb] ${m}`),
  });

  const out = buildAgeProofBundle({
    proofAge: proof as unknown as Record<string, unknown>,
    publicAge: publicSignals,
  });

  const outDir = resolve(opts.out);
  const outPath = resolve(outDir, 'age-proof-bundle.json');
  await mkdir(outDir, { recursive: true, mode: 0o700 });
  await writeFile(outPath, JSON.stringify(out, null, 2));
  await chmod(outPath, 0o600);
  console.error(`[qkb] wrote ${outPath}`);
  console.error(
    `[qkb] reminder: delete ${outDir} after /register succeeds — witness + proof files are PII-adjacent`,
  );
}

function buildBackend(opts: ProveAgeOptions): IProverBackend {
  if (opts.backend === 'rapidsnark') {
    if (!opts.rapidsnarkBin) {
      throw new Error(
        '--rapidsnark-bin is required when --backend rapidsnark is set',
      );
    }
    return new RapidsnarkBackend({ binPath: opts.rapidsnarkBin });
  }
  if (opts.backend === 'snarkjs') return new SnarkjsBackend();
  throw new Error(`unknown backend: ${opts.backend}`);
}
