// Regression check on the §8 stub ceremony artifacts pumped from
// arch-circuits' `ceremony/v5-stub/`. The pumped files live at
// `packages/sdk/fixtures/v5/ceremony-stub/`:
//
//   verification_key.json   — canonical Groth16 vkey for the V5 main circuit
//   proof-sample.json       — real groth16.prove() output sample
//   public-sample.json      — matching 14 public signals
//
// The cross-package contract: the (vkey, public-sample, proof-sample)
// triple MUST verify cleanly. If circuits-eng amends the circuit and
// re-runs the stub ceremony, the pump lands fresh artifacts and this
// test catches any drift between the vkey and the sample proof at
// pump time rather than at the §9.4 Sepolia-deploy gate.
//
// We use snarkjs.groth16.verify directly (same call SnarkjsWorkerProver's
// post-prove sanity hook would use, just without the prove). Verify is
// fast (~ms) and runs main-thread without OOM concerns; only fullProve
// over the 2.2 GB zkey needs Worker isolation.
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { verifyGroth16 } from './verify.js';
import type { Groth16Proof } from '../core/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const STUB_DIR = resolve(HERE, '../../fixtures/v5/ceremony-stub');

function readJson<T>(name: string): T {
  return JSON.parse(readFileSync(resolve(STUB_DIR, name), 'utf8')) as T;
}

describe('§8 stub ceremony artifacts — verifies cleanly', () => {
  it('pumped (vkey, public-sample, proof-sample) verifies', async () => {
    const verificationKey = readJson<Record<string, unknown>>('verification_key.json');
    const publicSignals = readJson<string[]>('public-sample.json');
    const proof = readJson<Groth16Proof>('proof-sample.json');

    expect(publicSignals.length).toBe(14);
    expect(verificationKey.protocol).toBe('groth16');
    expect(verificationKey.curve).toBe('bn128');
    expect(verificationKey.nPublic).toBe(14);

    const ok = await verifyGroth16({ verificationKey, publicSignals, proof });
    expect(ok).toBe(true);
  });

  it('verify rejects a tampered public signal (sanity)', async () => {
    const verificationKey = readJson<Record<string, unknown>>('verification_key.json');
    const publicSignals = readJson<string[]>('public-sample.json');
    const proof = readJson<Groth16Proof>('proof-sample.json');

    // Flip one bit in the first signal — verify must reject. This guards
    // against `verifyGroth16` accidentally returning `true` for any input
    // (e.g. if a future snarkjs version's API drifted).
    const tampered = [...publicSignals];
    tampered[0] = (BigInt(tampered[0]!) ^ 1n).toString();

    const ok = await verifyGroth16({
      verificationKey,
      publicSignals: tampered,
      proof,
    });
    expect(ok).toBe(false);
  });
});
