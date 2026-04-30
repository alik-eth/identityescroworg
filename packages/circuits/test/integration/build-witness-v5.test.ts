// Round-trip integration test for the V5 witness builder.
//
// Two assertions:
//   (a) `buildWitnessV5` produces a witness JSON that satisfies all
//       constraints when handed to the V5 main circuit (~ heavy compile,
//       leverages the existing build/test-cache hash for warm replay).
//   (b) Byte-identity vs `qkb-presentation-v5.test.ts`'s `buildV5SmokeWitness`
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
    circuit = await compile('QKBPresentationV5.circom');
  });

  it('produces a witness JSON the V5 main circuit accepts (admin-ecdsa fixture)', async () => {
    // Inputs: existing committed admin-ecdsa fixture artifacts + a
    // synthetic signedAttrs whose messageDigest equals sha256(binding).
    const bindingBytes = readFileSync(resolve(FIXTURE_DIR, 'binding.qkb2.json'));
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

    // Sanity on the 19 public signals — order MUST match orchestration §1.1.
    expect(witness.timestamp).to.equal(1777478400);
    expect(typeof witness.msgSender).to.equal('string');
    expect(typeof witness.nullifier).to.equal('string');
    expect((witness.policyLeafHash as string)).to.match(/^\d+$/);
    // V5.1 additions (slots 14-18).
    expect(typeof witness.identityFingerprint).to.equal('string');
    expect(typeof witness.identityCommitment).to.equal('string');
    expect(witness.rotationMode).to.equal(0); // default register mode
    expect(witness.rotationOldCommitment).to.equal(witness.identityCommitment);
    expect(witness.rotationNewWallet).to.equal(witness.msgSender);

    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  });

  it('msgSender derives from binding.pk via keccak256 (production parity)', async () => {
    // The synthetic admin-ecdsa fixture's binding pk is
    //   0x04 || 0x11×32 || 0x22×32
    // → keccak256(pk[1:65])[12:32] should match the witness's msgSender.
    const bindingBytes = readFileSync(resolve(FIXTURE_DIR, 'binding.qkb2.json'));
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

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { keccak256: ethersKeccak256 } = require('ethers/lib/utils');
    const pk = Buffer.concat([Buffer.alloc(32, 0x11), Buffer.alloc(32, 0x22)]);
    const expectedAddrHex = (ethersKeccak256(pk) as string).slice(2 + 24);
    const witnessAddrHex = BigInt(witness.msgSender as string)
      .toString(16)
      .padStart(40, '0');
    expect(witnessAddrHex).to.equal(expectedAddrHex);
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
