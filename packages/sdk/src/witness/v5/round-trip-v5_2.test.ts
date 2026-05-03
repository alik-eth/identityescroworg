// V5.2 witness builder — synthetic-CAdES round-trip integration test.
//
// Mirrors `round-trip.test.ts` for V5.1 but asserts the V5.2 witness
// shape:
//   - `msgSender` field MUST be absent (no longer a circuit-emitted
//     public signal; the contract derives msg.sender on-chain via
//     keccak256 of the four `bindingPk*` limbs).
//   - 22 public-signal-named fields present in the witness JSON, in the
//     spec §"Public-signal layout V5.1 → V5.2" order.
//   - `bindingPkXHi/Lo + bindingPkYHi/Lo` correctly equal the 4 × 16-byte
//     big-endian splits of the binding's claimed wallet pk (pkBytes[1..65]).
//
// The V5.1 round-trip test stays in place; both run in CI to guard
// against drift in either direction. Pinned witness assertions
// for V5.2 fields use the same admin-ecdsa fixture binding as V5.1 (pk
// = 0x04 || 0x11×32 || 0x22×32), so the expected limb values are
// computable in-test.

import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2';
import { describe, expect, it } from 'vitest';
import { buildWitnessV5_2 } from './build-witness-v5_2';
import { parseP7s } from './parse-p7s';
import { buildSynthCades } from './_test-helpers/build-synth-cades';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = resolve(HERE, '../../../fixtures/v5/admin-ecdsa');

function readFixture(name: string): Buffer {
  return Buffer.from(readFileSync(resolve(FIXTURE_DIR, name)));
}

describe('V5.2 witness builder — synthetic-CAdES round-trip', () => {
  it('produces a 22-signal V5.2 witness with bindingPk limbs and no msgSender', async () => {
    const bindingBytes = readFixture('binding.qkb2.json');
    const leafCertDer = readFixture('leaf.der');
    const leafSpki = readFixture('leaf-spki.bin');
    const intSpki = readFixture('intermediate-spki.bin');

    const bindingDigest = Buffer.from(sha256(bindingBytes));
    const synth = buildSynthCades({
      contentDigest: bindingDigest,
      leafCertDer,
    });
    const parsed = parseP7s(synth.p7sBuffer);

    const witness = await buildWitnessV5_2({
      bindingBytes,
      leafCertDer: parsed.leafCertDer,
      leafSpki,
      intSpki,
      signedAttrsDer: parsed.signedAttrsDer,
      signedAttrsMdOffset: parsed.signedAttrsMdOffset,
      walletSecret: Buffer.alloc(32),
    });

    // ---- V5.2 negative assertion: msgSender removed ----
    expect((witness as Record<string, unknown>).msgSender).toBeUndefined();

    // ---- V5.2 positive assertion: bindingPk limbs computed correctly ----
    // The admin-ecdsa fixture uses synthetic pk = 0x04 || 0x11×32 || 0x22×32.
    // bindingPkXHi = bytes[1..17]   = 0x11 × 16 → BE bigint = 0x1111…11 (16 bytes)
    // bindingPkXLo = bytes[17..33]  = 0x11 × 16 → BE bigint = 0x1111…11 (16 bytes)
    // bindingPkYHi = bytes[33..49]  = 0x22 × 16 → BE bigint = 0x2222…22 (16 bytes)
    // bindingPkYLo = bytes[49..65]  = 0x22 × 16 → BE bigint = 0x2222…22 (16 bytes)
    const expected128_11 = BigInt('0x' + '11'.repeat(16));
    const expected128_22 = BigInt('0x' + '22'.repeat(16));
    expect(BigInt(witness.bindingPkXHi as string)).toBe(expected128_11);
    expect(BigInt(witness.bindingPkXLo as string)).toBe(expected128_11);
    expect(BigInt(witness.bindingPkYHi as string)).toBe(expected128_22);
    expect(BigInt(witness.bindingPkYLo as string)).toBe(expected128_22);

    // ---- V5.2 limb range: each must fit in 128 bits ----
    const U128_MAX = 1n << 128n;
    for (const k of ['bindingPkXHi', 'bindingPkXLo', 'bindingPkYHi', 'bindingPkYLo'] as const) {
      const v = BigInt(witness[k] as string);
      expect(v).toBeGreaterThanOrEqual(0n);
      expect(v).toBeLessThan(U128_MAX);
    }

    // ---- 22 public signals all present ----
    // Order matches spec §"Public-signal layout V5.1 → V5.2" (FROZEN).
    const PUBLIC_KEYS_V5_2 = [
      'timestamp', 'nullifier',
      'ctxHashHi', 'ctxHashLo',
      'bindingHashHi', 'bindingHashLo',
      'signedAttrsHashHi', 'signedAttrsHashLo',
      'leafTbsHashHi', 'leafTbsHashLo',
      'policyLeafHash', 'leafSpkiCommit', 'intSpkiCommit',
      'identityFingerprint', 'identityCommitment',
      'rotationMode', 'rotationOldCommitment', 'rotationNewWallet',
      'bindingPkXHi', 'bindingPkXLo', 'bindingPkYHi', 'bindingPkYLo',
    ];
    expect(PUBLIC_KEYS_V5_2.length).toBe(22);
    for (const k of PUBLIC_KEYS_V5_2) {
      expect(witness[k as keyof typeof witness]).toBeDefined();
    }

    // ---- Carry-forward V5.1 assertions ----
    // timestamp from the admin-ecdsa fixture binding (pinned).
    expect(witness.timestamp).toBe(1777478400);
    // nullifier + identity-fingerprint are non-zero field elements.
    expect(witness.nullifier).toMatch(/^\d+$/);
    expect(BigInt(witness.nullifier as string)).not.toBe(0n);
    expect(BigInt(witness.identityFingerprint as string)).not.toBe(0n);
    expect(BigInt(witness.identityCommitment as string)).not.toBe(0n);
    // rotationMode defaults to 0 (register mode).
    expect(witness.rotationMode).toBe(0);
  });

  it('rejects oversize bindingBytes via the V5.1 size guard (delegates internally)', async () => {
    // V5.2 reuses V5.1's binding parser, so the same MAX_BCANON guard
    // applies. Confirm the error surfaces through the V5.2 wrapper.
    const oversize = Buffer.alloc(2048);
    await expect(
      buildWitnessV5_2({
        bindingBytes: oversize,
        leafCertDer: Buffer.alloc(0),
        leafSpki: Buffer.alloc(91),
        intSpki: Buffer.alloc(91),
        signedAttrsDer: Buffer.alloc(0),
        signedAttrsMdOffset: 0,
        walletSecret: Buffer.alloc(32),
        bindingOffsets: {
          pkValueOffset: 0, schemeValueOffset: 0, assertionsValueOffset: 0,
          statementSchemaValueOffset: 0, nonceValueOffset: 0, ctxValueOffset: 0,
          ctxHexLen: 0, policyIdValueOffset: 0, policyIdLen: 0,
          policyLeafHashValueOffset: 0, policyBindingSchemaValueOffset: 0,
          policyVersionValueOffset: 0, policyVersionDigitCount: 0,
          tsValueOffset: 0, tsDigitCount: 0, versionValueOffset: 0,
        },
      }),
    ).rejects.toThrow(/MAX_BCANON/);
  });
});
