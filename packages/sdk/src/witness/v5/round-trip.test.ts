// V5 witness builder — synthetic-CAdES round-trip integration test.
//
// Covers the full browser-side path that the V5 register flow drives:
//
//   admin-ecdsa fixture binding (JCS bytes)
//     → buildSynthCades(content_digest, leaf, intermediate)
//     → parseP7s(p7sBuffer) → CmsExtraction
//     → buildWitnessV5(BuildWitnessV5Input)
//     → assert public-signal values match circuits-eng's reference.
//
// Catches drift between the vendored copy under
// `packages/sdk/src/witness/v5/` and arch-circuits' source-of-truth
// (`build-witness-v5.test.ts:46`'s production-builder round-trip). The
// pinned witness assertions mirror those in circuits-eng's test:
//
//   - witness.timestamp === 1777478400 (admin-ecdsa fixture's binding ts).
//   - witness.msgSender derives from binding.pk via keccak256[12:32].
//   - witness.nullifier is a non-zero decimal-string field element.
//   - witness.policyLeafHash is a non-zero decimal-string field element.
//
// The fixtures (binding.qkb2.json, leaf.der, leaf-spki.bin,
// intermediate-spki.bin, fixture-qkb2.json) are vendored under
// `fixtures/v5/admin-ecdsa/` from arch-circuits f0d5a73 and tracked by
// the `drift-check` script's lockfile alongside the source.

import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { describe, expect, it } from 'vitest';
import { buildWitnessV5 } from './build-witness-v5';
import { parseP7s } from './parse-p7s';
import { decodeEcdsaSigSequence } from './ecdsa-sig';
import { buildSynthCades } from './_test-helpers/build-synth-cades';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = resolve(HERE, '../../../fixtures/v5/admin-ecdsa');

function readFixture(name: string): Buffer {
  return Buffer.from(readFileSync(resolve(FIXTURE_DIR, name)));
}

describe('V5 witness builder — synthetic-CAdES round-trip', () => {
  it('parseP7s + buildWitnessV5 produces a witness matching circuits-eng reference', async () => {
    const bindingBytes = readFixture('binding.qkb2.json');
    const leafCertDer = readFixture('leaf.der');
    const leafSpki = readFixture('leaf-spki.bin');
    const intSpki = readFixture('intermediate-spki.bin');

    // Synthesize a structurally-valid CAdES-BES around the admin-ecdsa
    // leaf cert. Real Diia .p7s would land here in production; for CI
    // we assemble a faithful container around the same fixtures
    // arch-circuits' integration tests use.
    const bindingDigest = Buffer.from(sha256(bindingBytes));
    const synth = buildSynthCades({
      contentDigest: bindingDigest,
      leafCertDer,
      // No intermediate cert in the synthetic CMS — we feed the
      // intermediate SPKI directly into buildWitnessV5 below. Keeps
      // parseP7s' "single cert is treated as leaf" path exercised.
    });

    // parseP7s round-trip: pulls signedAttrsDer + signedAttrsMdOffset
    // back out of the synth p7s. Equality with the synth output
    // confirms parseP7s handles our own emission correctly.
    const parsed = parseP7s(synth.p7sBuffer);
    expect(parsed.signedAttrsDer.toString('hex')).toBe(synth.signedAttrsDer.toString('hex'));
    expect(parsed.signedAttrsMdOffset).toBe(synth.signedAttrsMdOffset);
    expect(parsed.leafCertDer.toString('hex')).toBe(leafCertDer.toString('hex'));

    // ECDSA-Sig-Value (r, s) decode — buildSynthCades plants a known
    // placeholder SEQUENCE { INTEGER 1, INTEGER 1 } as the SignerInfo
    // signature (the V5 circuit doesn't verify the signature; EIP-7212
    // does that on chain). Round-trip the leafSig through
    // decodeEcdsaSigSequence and confirm we get (1, 1) padded to 32 B.
    expect(parsed.leafSigR).toBeDefined();
    const { r, s } = decodeEcdsaSigSequence(parsed.leafSigR!);
    expect(r.length).toBe(32);
    expect(s.length).toBe(32);
    expect(BigInt('0x' + r.toString('hex'))).toBe(1n);
    expect(BigInt('0x' + s.toString('hex'))).toBe(1n);

    const witness = await buildWitnessV5({
      bindingBytes,
      leafCertDer: parsed.leafCertDer,
      leafSpki,
      // Intermediate cert isn't in the synth p7s → feed SPKI directly.
      intSpki,
      signedAttrsDer: parsed.signedAttrsDer,
      signedAttrsMdOffset: parsed.signedAttrsMdOffset,
    });

    // ---- Assertions mirror arch-circuits' build-witness-v5.test.ts ----
    // 1. timestamp from the admin-ecdsa fixture binding.
    expect(witness.timestamp).toBe(1777478400);

    // 2. msgSender keccak-derives from binding.pk. The admin-ecdsa
    //    fixture uses the synthetic SEC1 form 0x04 || 0x11×32 || 0x22×32,
    //    so the expected address is the low 20 bytes of keccak(pk[1:65]).
    const pk = Buffer.concat([Buffer.alloc(32, 0x11), Buffer.alloc(32, 0x22)]);
    const expectedAddrHex = Buffer.from(keccak_256(pk)).toString('hex').slice(24);
    const witnessAddrHex = BigInt(witness.msgSender as string)
      .toString(16)
      .padStart(40, '0');
    expect(witnessAddrHex).toBe(expectedAddrHex);

    // 3. nullifier + policyLeafHash are non-zero decimal-string field
    //    elements. Pinning exact values would require an arch-circuits
    //    fixture pump (TODO: add a `witness-snapshot.json` to the
    //    fixtures dir once circuits-eng emits one).
    expect(witness.nullifier).toMatch(/^\d+$/);
    expect(BigInt(witness.nullifier as string)).not.toBe(0n);
    expect(witness.policyLeafHash).toMatch(/^\d+$/);
    expect(BigInt(witness.policyLeafHash as string)).not.toBe(0n);

    // 4. the 14 public signals are all present.
    const PUBLIC_KEYS = [
      'msgSender', 'timestamp', 'nullifier',
      'ctxHashHi', 'ctxHashLo',
      'bindingHashHi', 'bindingHashLo',
      'signedAttrsHashHi', 'signedAttrsHashLo',
      'leafTbsHashHi', 'leafTbsHashLo',
      'policyLeafHash', 'leafSpkiCommit', 'intSpkiCommit',
    ];
    for (const k of PUBLIC_KEYS) {
      expect(witness[k]).toBeDefined();
    }
  });
});
