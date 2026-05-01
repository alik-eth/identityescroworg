// Regression check on the §8 stub ceremony artifacts pumped from
// arch-circuits' V5.1 stub ceremony (`65818a0`, 4,022,171 constraints,
// fullProve verified at 74.7s + tampered-msgSender reject works).
// Pumped files live at `packages/sdk/fixtures/v5_1/`:
//
//   verification_key.json    — canonical Groth16 vkey for the V5.1 main circuit
//   proof-sample.json        — real groth16.fullProve() output sample
//   public-sample.json       — matching 19 public signals
//   witness-input-sample.json — full witness inputs (host-side reference)
//
// The cross-package contract mirrors the V5 stub: the (vkey, public-sample,
// proof-sample) triple MUST verify cleanly. If circuits-eng amends the V5.1
// circuit and re-runs the stub ceremony, lead pumps fresh artifacts and this
// test catches any drift at pump time rather than at the §9.4 Sepolia-deploy
// gate.
//
// V5.1 deltas vs the V5 stub:
//   - nPublic 14 → 19 (orchestration §1.1 FROZEN layout: identityFingerprint,
//     identityCommitment, rotationMode, rotationOldCommitment, rotationNewWallet
//     added at slots 14-18).
//   - vkey curve + protocol unchanged (groth16 / bn128).
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { verifyGroth16 } from './verify.js';
import type { Groth16Proof } from '../core/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const STUB_DIR = resolve(HERE, '../../fixtures/v5_1');

function readJson<T>(name: string): T {
  return JSON.parse(readFileSync(resolve(STUB_DIR, name), 'utf8')) as T;
}

describe('V5.1 stub ceremony artifacts — verifies cleanly', () => {
  it('pumped (vkey, public-sample, proof-sample) verifies', async () => {
    const verificationKey = readJson<Record<string, unknown>>('verification_key.json');
    const publicSignals = readJson<string[]>('public-sample.json');
    const proof = readJson<Groth16Proof>('proof-sample.json');

    expect(publicSignals.length).toBe(19);
    expect(verificationKey.protocol).toBe('groth16');
    expect(verificationKey.curve).toBe('bn128');
    expect(verificationKey.nPublic).toBe(19);

    const ok = await verifyGroth16({ verificationKey, publicSignals, proof });
    expect(ok).toBe(true);
  });

  it('verify rejects a tampered public signal (sanity)', async () => {
    const verificationKey = readJson<Record<string, unknown>>('verification_key.json');
    const publicSignals = readJson<string[]>('public-sample.json');
    const proof = readJson<Groth16Proof>('proof-sample.json');

    // Flip one bit in the first signal (msgSender) — verify must reject.
    // Mirrors the circuits-eng tampered-msgSender E2E reject check.
    const tampered = [...publicSignals];
    tampered[0] = (BigInt(tampered[0]!) ^ 1n).toString();

    const ok = await verifyGroth16({
      verificationKey,
      publicSignals: tampered,
      proof,
    });
    expect(ok).toBe(false);
  });

  it('rejects tampering on a V5.1 amendment slot (identityFingerprint)', async () => {
    const verificationKey = readJson<Record<string, unknown>>('verification_key.json');
    const publicSignals = readJson<string[]>('public-sample.json');
    const proof = readJson<Groth16Proof>('proof-sample.json');

    // Flip identityFingerprint (slot 14) — V5.1-specific guard. Catches any
    // future drift where the verifier ignored the new public signals.
    const tampered = [...publicSignals];
    tampered[14] = (BigInt(tampered[14]!) ^ 1n).toString();

    const ok = await verifyGroth16({
      verificationKey,
      publicSignals: tampered,
      proof,
    });
    expect(ok).toBe(false);
  });
});
