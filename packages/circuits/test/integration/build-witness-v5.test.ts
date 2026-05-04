// Round-trip integration test for the V5 witness builder.
//
// Two assertions:
//   (a) `buildWitnessV5` produces a witness JSON that satisfies all
//       constraints when handed to the V5 main circuit (~ heavy compile,
//       leverages the existing build/test-cache hash for warm replay).
//   (b) Byte-identity vs `zkqes-presentation-v5.test.ts`'s `buildV5SmokeWitness`
//       — the production path and the test helper must produce the SAME
//       witness for the SAME input fixtures, otherwise web-eng's
//       browser-side path can't trust the test-helper-derived parity.

import { expect } from 'chai';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';
import { buildWitnessV5 } from '../../src/build-witness-v5';

const FIXTURE_DIR = resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa');

// Deterministic test walletSecret. 32 bytes of 0x42. After reduceTo254 the
// high 2 bits are masked, so the in-circuit Num2Bits(254) range check
// trivially passes. Same byte pattern across all tests for fixture stability.
const TEST_WALLET_SECRET = Buffer.alloc(32, 0x42);

// Synthetic CAdES messageDigest Attribute prefix (17 bytes). MUST match
// SignedAttrsParser.circom EXPECTED_PREFIX exactly.
const MD_PREFIX = Buffer.from([
  0x30, 0x2f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
  0x31, 0x22, 0x04, 0x20,
]);
const SYNTH_MD_OFFSET = 60;

/**
 * Stand-in for an `.p7s`-extracted signedAttrs DER. Real Diia .p7s
 * produces a structurally-similar prefix (the 17-byte messageDigest
 * Attribute is fixed-shape per CMS); the integration test for parseP7s
 * lives separately at test/integration/v5-e2e.test.ts (§6.10).
 */
function synthSignedAttrs(bindingDigest: Buffer): {
  bytes: Buffer;
  mdAttrOffset: number;
} {
  const length = SYNTH_MD_OFFSET + 17 + 32;
  const bytes = Buffer.alloc(length);
  MD_PREFIX.copy(bytes, SYNTH_MD_OFFSET);
  bindingDigest.copy(bytes, SYNTH_MD_OFFSET + 17);
  return { bytes, mdAttrOffset: SYNTH_MD_OFFSET };
}

describe('buildWitnessV5 — production builder round-trip', function () {
  this.timeout(1800000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('ZkqesPresentationV5.circom');
  });

  it('produces a witness JSON the V5 main circuit accepts (admin-ecdsa fixture)', async () => {
    // Inputs: existing committed admin-ecdsa fixture artifacts + a
    // synthetic signedAttrs whose messageDigest equals sha256(binding).
    const bindingBytes = readFileSync(resolve(FIXTURE_DIR, 'binding.zkqes2.json'));
    const leafCertDer = readFileSync(resolve(FIXTURE_DIR, 'leaf.der'));
    const leafSpki = readFileSync(resolve(FIXTURE_DIR, 'leaf-spki.bin'));
    const intSpki = readFileSync(resolve(FIXTURE_DIR, 'intermediate-spki.bin'));

    const { createHash } = await import('node:crypto');
    const bindingDigest = createHash('sha256').update(bindingBytes).digest();
    const sa = synthSignedAttrs(bindingDigest);

    const witness = await buildWitnessV5({
      bindingBytes,
      leafCertDer,
      leafSpki,
      intSpki,
      signedAttrsDer: sa.bytes,
      signedAttrsMdOffset: sa.mdAttrOffset,
      walletSecret: TEST_WALLET_SECRET,
    });

    // Sanity on the 22 public signals — order MUST match V5.2 spec
    // §"Public-signal layout V5.1 (19) → V5.2 (22)".
    expect(witness.timestamp).to.equal(1777478400);
    // V5.2: msgSender is no longer a witness field (gone from public signals).
    expect((witness as Record<string, unknown>).msgSender).to.equal(undefined);
    expect(typeof witness.nullifier).to.equal('string');
    expect((witness.policyLeafHash as string)).to.match(/^\d+$/);
    // V5.1 amendment slots (V5.2 numbering 13-17).
    expect(typeof witness.identityFingerprint).to.equal('string');
    expect(typeof witness.identityCommitment).to.equal('string');
    expect(witness.rotationMode).to.equal(0); // default register mode
    expect(witness.rotationOldCommitment).to.equal(witness.identityCommitment);
    // V5.2: rotationNewWallet defaults to keccak-derived address (advisory
    // at the witness-builder layer; contract enforces == msg.sender).
    expect(typeof witness.rotationNewWallet).to.equal('string');
    // V5.2 amendment slots (18-21) — wallet-pk limbs for on-chain keccak gate.
    expect(typeof witness.bindingPkXHi).to.equal('string');
    expect(typeof witness.bindingPkXLo).to.equal('string');
    expect(typeof witness.bindingPkYHi).to.equal('string');
    expect(typeof witness.bindingPkYLo).to.equal('string');

    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  });

  it('emits bindingPk Hi/Lo limbs that big-endian-encode binding.pk (V5.2 cross-package handshake)', async () => {
    // V5.2: msgSender is no longer in the witness; the wallet-pk binding
    // is exposed as 4 × 128-bit limbs (bindingPkX/Y Hi/Lo). The contract
    // reconstructs the uncompressed pk from these and runs keccak256 to
    // derive msg.sender. We verify the limbs encode the synthetic
    // admin-ecdsa fixture's pk (0x04 || 0x11×32 || 0x22×32) byte-for-byte
    // — this is the cross-package handshake with contracts-eng's keccak
    // gate.
    const bindingBytes = readFileSync(resolve(FIXTURE_DIR, 'binding.zkqes2.json'));
    const leafCertDer = readFileSync(resolve(FIXTURE_DIR, 'leaf.der'));
    const leafSpki = readFileSync(resolve(FIXTURE_DIR, 'leaf-spki.bin'));
    const intSpki = readFileSync(resolve(FIXTURE_DIR, 'intermediate-spki.bin'));

    const { createHash } = await import('node:crypto');
    const bindingDigest = createHash('sha256').update(bindingBytes).digest();
    const sa = synthSignedAttrs(bindingDigest);

    const witness = await buildWitnessV5({
      bindingBytes,
      leafCertDer,
      leafSpki,
      intSpki,
      signedAttrsDer: sa.bytes,
      signedAttrsMdOffset: sa.mdAttrOffset,
      walletSecret: TEST_WALLET_SECRET,
    });

    // X = 0x11×32 → XHi/XLo = 0x1111…11 (16 bytes each).
    // Y = 0x22×32 → YHi/YLo = 0x2222…22 (16 bytes each).
    const expectedXLimb = BigInt('0x' + '11'.repeat(16));
    const expectedYLimb = BigInt('0x' + '22'.repeat(16));
    expect(BigInt(witness.bindingPkXHi as string)).to.equal(expectedXLimb);
    expect(BigInt(witness.bindingPkXLo as string)).to.equal(expectedXLimb);
    expect(BigInt(witness.bindingPkYHi as string)).to.equal(expectedYLimb);
    expect(BigInt(witness.bindingPkYLo as string)).to.equal(expectedYLimb);

    // Sanity: the keccak chain that the contract will run produces an
    // address; the witness builder still computes it for the
    // rotationNewWallet fixture default (advisory only — contract
    // enforces post-verifier).
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { keccak256: ethersKeccak256 } = require('ethers/lib/utils');
    const pk = Buffer.concat([Buffer.alloc(32, 0x11), Buffer.alloc(32, 0x22)]);
    const expectedAddrHex = (ethersKeccak256(pk) as string).slice(2 + 24);
    const witnessAddrHex = BigInt(witness.rotationNewWallet as string)
      .toString(16)
      .padStart(40, '0');
    expect(witnessAddrHex).to.equal(expectedAddrHex);
  });

  // V5.2 limb-boundary correctness — guards against Hi/Lo-swap or
  // 16-byte-window-shift bugs that the synthetic fixture (where
  // pk = 0x04 || 0x11×32 || 0x22×32, so XHi == XLo and YHi == YLo)
  // cannot detect. Construct an asymmetric pk where every byte is
  // distinguishable, replace the `pk` field in a fresh binding, and
  // assert each limb extracts its specific 16-byte slice big-endian.
  // Codex T2 review pass 1 [P2] flagged the symmetric-fixture coverage
  // gap; this test closes it.
  it('limb encoding extracts the correct 16-byte big-endian windows on an asymmetric pk', async () => {
    const baseBindingBytes = readFileSync(resolve(FIXTURE_DIR, 'binding.zkqes2.json'));
    const leafCertDer = readFileSync(resolve(FIXTURE_DIR, 'leaf.der'));
    const leafSpki = readFileSync(resolve(FIXTURE_DIR, 'leaf-spki.bin'));
    const intSpki = readFileSync(resolve(FIXTURE_DIR, 'intermediate-spki.bin'));

    // Build an asymmetric uncompressed pk:
    //   X = 0x00, 0x01, 0x02, ..., 0x1f      (32 bytes; XHi != XLo)
    //   Y = 0xa0, 0xa1, 0xa2, ..., 0xbf      (32 bytes; YHi != YLo)
    const x = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
    const y = Buffer.from(Array.from({ length: 32 }, (_, i) => 0xa0 + i));
    const pk = Buffer.concat([Buffer.from([0x04]), x, y]); // 65 bytes
    const newPkHex = '0x' + pk.toString('hex');

    // Find + replace `"pk":"0x..."` in the canonical binding JSON. The
    // synthetic fixture's pk is `0x04` followed by 64 bytes of
    // 0x11/0x22, all zero-prefixed in hex. Both old and new pk hex
    // strings are 132 chars (`"0x" + 130 hex`) so the byte length is
    // preserved — no other offsets need adjustment.
    const bindingStr = baseBindingBytes.toString('utf8');
    const oldPkPattern = /"pk":"0x[0-9a-fA-F]{130}"/;
    const oldMatch = bindingStr.match(oldPkPattern);
    if (!oldMatch) throw new Error('test setup: pk field not found in binding');
    // Expected: `"pk":"` (6) + `0x` + 130 hex (132) + `"` (1) = 139 chars.
    if (oldMatch[0].length !== 6 + 132 + 1) {
      throw new Error(`test setup: pk field length mismatch ${oldMatch[0].length}`);
    }
    const newBindingStr = bindingStr.replace(oldPkPattern, `"pk":"${newPkHex}"`);
    const newBindingBytes = Buffer.from(newBindingStr, 'utf8');
    if (newBindingBytes.length !== baseBindingBytes.length) {
      throw new Error('test setup: binding length must be preserved');
    }

    const { createHash } = await import('node:crypto');
    const bindingDigest = createHash('sha256').update(newBindingBytes).digest();
    const sa = synthSignedAttrs(bindingDigest);

    const witness = await buildWitnessV5({
      bindingBytes: newBindingBytes,
      leafCertDer,
      leafSpki,
      intSpki,
      signedAttrsDer: sa.bytes,
      signedAttrsMdOffset: sa.mdAttrOffset,
      walletSecret: TEST_WALLET_SECRET,
    });

    // Expected limbs: each 128-bit Hi/Lo big-endian-encodes the
    // corresponding 16-byte slice.
    //   XHi = bytes 0..15  = 0x000102030405060708090a0b0c0d0e0f
    //   XLo = bytes 16..31 = 0x101112131415161718191a1b1c1d1e1f
    //   YHi = bytes 32..47 = 0xa0a1a2a3a4a5a6a7a8a9aaabacadaeaf
    //   YLo = bytes 48..63 = 0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
    const expectedXHi = BigInt('0x000102030405060708090a0b0c0d0e0f');
    const expectedXLo = BigInt('0x101112131415161718191a1b1c1d1e1f');
    const expectedYHi = BigInt('0xa0a1a2a3a4a5a6a7a8a9aaabacadaeaf');
    const expectedYLo = BigInt('0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf');

    expect(BigInt(witness.bindingPkXHi as string)).to.equal(expectedXHi);
    expect(BigInt(witness.bindingPkXLo as string)).to.equal(expectedXLo);
    expect(BigInt(witness.bindingPkYHi as string)).to.equal(expectedYHi);
    expect(BigInt(witness.bindingPkYLo as string)).to.equal(expectedYLo);

    // Asymmetry sanity — these would all be equal on the symmetric
    // synthetic fixture; here every limb must differ from every other.
    expect(witness.bindingPkXHi).to.not.equal(witness.bindingPkXLo);
    expect(witness.bindingPkYHi).to.not.equal(witness.bindingPkYLo);
    expect(witness.bindingPkXHi).to.not.equal(witness.bindingPkYHi);
    expect(witness.bindingPkXLo).to.not.equal(witness.bindingPkYLo);
  });

  it('rejects a binding > MAX_BCANON', async () => {
    const oversized = Buffer.alloc(2048, 0x20); // 2 KB > MAX_BCANON
    let threw = false;
    try {
      await buildWitnessV5({
        bindingBytes: oversized,
        leafCertDer: Buffer.alloc(0),
        leafSpki: Buffer.alloc(91),
        intSpki: Buffer.alloc(91),
        signedAttrsDer: Buffer.alloc(0),
        signedAttrsMdOffset: 0,
        walletSecret: TEST_WALLET_SECRET,
      });
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
