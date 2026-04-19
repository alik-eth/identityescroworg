/**
 * Backend using rapidsnark (C++ Groth16 prover) via shell-out.
 *
 * Flow:
 *   1. snarkjs.wtns.calculate(witness, wasmPath, wtnsPath) → .wtns file
 *   2. `<rapidsnark-bin> <zkey> <wtns> <proof.json> <public.json>`
 *   3. Parse the two JSON files into the canonical ProveResult shape
 *
 * Rapidsnark is ~10x faster than snarkjs and uses substantially less RAM,
 * but requires the user to supply the binary (iden3/rapidsnark builds are
 * Linux-x86_64-centric; macOS + arm64 users typically build from source).
 */

import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import type { IProverBackend, ProveInput, ProveResult } from './backend.js';

export interface RapidsnarkBackendOptions {
  readonly binPath: string;
}

export class RapidsnarkBackend implements IProverBackend {
  readonly name = 'rapidsnark';

  constructor(private readonly opts: RapidsnarkBackendOptions) {}

  async prove(input: ProveInput): Promise<ProveResult> {
    const dir = await mkdtemp(join(tmpdir(), 'qkb-rs-'));
    const wtnsPath = join(dir, `${input.side}.wtns`);
    const proofPath = join(dir, `${input.side}.proof.json`);
    const publicPath = join(dir, `${input.side}.public.json`);
    try {
      input.onLog?.(`[${input.side}] wtns.calculate start`);
      const snarkjs = (await import('snarkjs')) as unknown as {
        wtns: {
          calculate: (
            witness: Record<string, unknown>,
            wasmPath: string,
            outPath: string,
          ) => Promise<void>;
        };
      };
      await snarkjs.wtns.calculate(input.witness, input.wasmPath, wtnsPath);
      input.onLog?.(`[${input.side}] wtns.calculate done`);

      input.onLog?.(`[${input.side}] rapidsnark prove start`);
      await runRapidsnark(this.opts.binPath, [
        input.zkeyPath,
        wtnsPath,
        proofPath,
        publicPath,
      ]);
      input.onLog?.(`[${input.side}] rapidsnark prove done`);

      const [proofJson, publicJson] = await Promise.all([
        readFile(proofPath, 'utf-8'),
        readFile(publicPath, 'utf-8'),
      ]);
      const proof = JSON.parse(proofJson) as ProveResult['proof'];
      const publicSignals = JSON.parse(publicJson) as string[];
      return { proof, publicSignals };
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
}

function runRapidsnark(bin: string, args: string[]): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(bin, args, { stdio: 'inherit' });
    child.on('error', (err: Error) => reject(err));
    child.on('close', (code: number | null) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`rapidsnark exited with code ${code ?? 'unknown'}`));
    });
  });
}
