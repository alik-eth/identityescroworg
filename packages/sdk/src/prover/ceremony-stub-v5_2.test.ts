// Regression check on the V5.2 stub ceremony artifacts pumped from
// arch-circuits' V5.2 stub run (`5cbd888`). V5.2 deltas vs V5.1:
//
//   - keccak gate moved from circuit to contract → `msgSender` slot is
//     dropped, freeing 1 slot.
//   - 4 `bindingPk*` 16-byte BE limbs added at slots 18-21 to let the
//     contract recompute the keccak walletDerivationGate against the
//     proof's claimed pkBytes.
//   - Net public-signal count: 19 (V5.1) → 22 (V5.2).
//   - Constraint count drops to ~3.88M (vs 4.02M for V5.1) per
//     circuits-eng's T3 surface, which fits pot22 (2^22 domain) — pot23
//     is no longer needed.
//
// Pumped files live at `packages/sdk/fixtures/v5_2/`:
//
//   verification_key.json    — canonical Groth16 vkey for the V5.2 main circuit
//   proof-sample.json        — real groth16.fullProve() output sample
//   public-sample.json       — matching 22 public signals
//   witness-input-sample.json — full witness inputs (host-side reference)
//
// The cross-package contract mirrors V5.1: the (vkey, public-sample,
// proof-sample) triple MUST verify cleanly. Three tampering tests pin
// soundness against accidental slot-reorder drift (one V5.2-specific:
// the bindingPkXHi limb at slot 18 — if the verifier ever silently
// accepts a tampered limb, the on-chain walletDerivationGate would be
// usable as an attack surface, so we catch it here at pump time).
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { verifyGroth16 } from './verify.js';
import type { Groth16Proof } from '../core/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const STUB_DIR = resolve(HERE, '../../fixtures/v5_2');

function readJson<T>(name: string): T {
  return JSON.parse(readFileSync(resolve(STUB_DIR, name), 'utf8')) as T;
}

describe('V5.2 stub ceremony artifacts — verifies cleanly', () => {
  it('pumped (vkey, public-sample, proof-sample) verifies', async () => {
    const verificationKey = readJson<Record<string, unknown>>('verification_key.json');
    const publicSignals = readJson<string[]>('public-sample.json');
    const proof = readJson<Groth16Proof>('proof-sample.json');

    expect(publicSignals.length).toBe(22);
    expect(verificationKey.protocol).toBe('groth16');
    expect(verificationKey.curve).toBe('bn128');
    expect(verificationKey.nPublic).toBe(22);

    const ok = await verifyGroth16({ verificationKey, publicSignals, proof });
    expect(ok).toBe(true);
  });

  it('verify rejects a tampered public signal (sanity)', async () => {
    const verificationKey = readJson<Record<string, unknown>>('verification_key.json');
    const publicSignals = readJson<string[]>('public-sample.json');
    const proof = readJson<Groth16Proof>('proof-sample.json');

    // Flip one bit in the first signal (timestamp — V5.2 slot 0 since
    // msgSender was removed). Verify must reject. Mirrors the V5.1
    // tampered-msgSender check, just one slot down because the layout
    // shifted up.
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

    // Flip identityFingerprint — V5.1 amendment guard. Slot 13 in V5.2
    // (was slot 14 in V5.1; msgSender removal shifted slots 1-18 down
    // by one). Catches any drift where the V5.2 verifier silently
    // ignored the V5.1-era public signals after the layout reshuffle.
    const tampered = [...publicSignals];
    tampered[13] = (BigInt(tampered[13]!) ^ 1n).toString();

    const ok = await verifyGroth16({
      verificationKey,
      publicSignals: tampered,
      proof,
    });
    expect(ok).toBe(false);
  });

  it('rejects tampering on a V5.2 bindingPkXHi limb (slot 18)', async () => {
    const verificationKey = readJson<Record<string, unknown>>('verification_key.json');
    const publicSignals = readJson<string[]>('public-sample.json');
    const proof = readJson<Groth16Proof>('proof-sample.json');

    // Flip bindingPkXHi (slot 18) — V5.2-specific guard. The contract's
    // walletDerivationGate keccaks pkBytes reconstructed from these four
    // limbs; if the verifier ever silently accepted a tampered limb the
    // contract would derive a different (attacker-chosen) wallet from a
    // valid-looking proof, so this is a soundness boundary we want
    // pinned at pump time rather than at the §9.4 Sepolia gate.
    const tampered = [...publicSignals];
    tampered[18] = (BigInt(tampered[18]!) ^ 1n).toString();

    const ok = await verifyGroth16({
      verificationKey,
      publicSignals: tampered,
      proof,
    });
    expect(ok).toBe(false);
  });
});
