/**
 * `qkb verify` — Groth16-verify a proof + public-signals tuple against a
 * verification key.
 *
 * Reads a JSON file containing `proof` and `publicSignals` (either the bare
 * snarkjs output OR a `qkb-proof-bundle/v1` whose leaf side we extract), plus
 * a path to a verification_key.json. Prints `VERIFY: OK` and exits 0 on
 * success, prints `VERIFY: FAIL` and exits 2 on failure.
 *
 * Verification is fast (sub-second), no artifact download required — caller
 * supplies the vkey locally. For QKB ceremony vkeys see
 * `https://prove.identityescrow.org/<circuit>/verification_key.json`.
 */

import { readFile } from 'node:fs/promises';

export interface VerifyOptions {
  readonly proofPath: string;
  readonly vkeyPath: string;
  /** Which side to verify when given a `qkb-proof-bundle/v1`. Default 'leaf'. */
  readonly side?: 'leaf' | 'chain';
}

export async function runVerify(opts: VerifyOptions): Promise<void> {
  const proofRaw = JSON.parse(await readFile(opts.proofPath, 'utf-8')) as Record<string, unknown>;
  const vkey = JSON.parse(await readFile(opts.vkeyPath, 'utf-8'));

  const { proof, publicSignals } = pickProofAndSignals(proofRaw, opts.side ?? 'leaf');

  const snarkjs = (await import('snarkjs')) as unknown as {
    groth16: {
      verify: (
        vkey: unknown,
        publicSignals: string[],
        proof: unknown,
      ) => Promise<boolean>;
    };
  };
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  if (!ok) {
    console.error('VERIFY: FAIL');
    process.exit(2);
  }
  console.log('VERIFY: OK');
}

function pickProofAndSignals(
  raw: Record<string, unknown>,
  side: 'leaf' | 'chain',
): { proof: unknown; publicSignals: string[] } {
  // qkb-proof-bundle/v1 carries leaf + chain side-by-side; bare snarkjs output
  // has top-level proof + publicSignals.
  if (raw.schema === 'qkb-proof-bundle/v1') {
    const proofKey = side === 'leaf' ? 'proofLeaf' : 'proofChain';
    const sigKey = side === 'leaf' ? 'publicLeaf' : 'publicChain';
    const proof = raw[proofKey];
    const publicSignals = raw[sigKey];
    if (!proof || !Array.isArray(publicSignals)) {
      throw new Error(
        `qkb-proof-bundle missing ${proofKey} / ${sigKey}; got keys: ${Object.keys(raw).join(', ')}`,
      );
    }
    return { proof, publicSignals: publicSignals as string[] };
  }
  if ('proof' in raw && 'publicSignals' in raw) {
    return {
      proof: raw.proof,
      publicSignals: raw.publicSignals as string[],
    };
  }
  throw new Error(
    `unrecognized proof file shape — expected qkb-proof-bundle/v1 or { proof, publicSignals }`,
  );
}
