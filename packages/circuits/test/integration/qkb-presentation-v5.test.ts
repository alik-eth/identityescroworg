import { expect } from 'chai';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';
import { rightPadZero, shaPad } from '../helpers/shaPad';
import {
  buildV2CoreWitnessFromFixture,
  loadFixture,
  V2CORE_MAX_BCANON,
  V2CORE_MAX_POLICY_ID,
} from '../binding/v2core-witness';
import {
  decomposeTo643Limbs,
  parseP256Spki,
  spkiCommit,
} from '../../scripts/spki-commit-ref';

const FIXTURE_DIR = resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa');
const MAX_SA = 1536;
const MAX_LEAF_TBS = 1024;
const MAX_CERT = 2048;

// Synthetic CAdES messageDigest Attribute prefix (17 bytes). Same constant
// SignedAttrsParser.circom EXPECTED_PREFIX uses.
const MD_PREFIX = Buffer.from([
  0x30, 0x2f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
  0x31, 0x22, 0x04, 0x20,
]);
const SYNTH_MD_OFFSET = 60; // matches Diia's actual offset; keeps mdAttrOffset < 256

function zeros(n: number): number[] {
  return new Array<number>(n).fill(0);
}

/**
 * Build a synthetic signedAttrs blob whose messageDigest at SYNTH_MD_OFFSET
 * is sha256(bindingBytes). The bytes before the messageDigest Attribute are
 * zero-padding; the parser only checks the 17-byte prefix at the witnessed
 * offset and reads 32 bytes of digest immediately after.
 *
 * Real Diia signedAttrs has additional Attributes (contentType,
 * signing-time, …) before/after; the parser doesn't care, only the
 * messageDigest extraction matters for §6.4.
 */
function buildSyntheticSignedAttrs(bindingDigest: Buffer): {
  bytes: Buffer;
  length: number;
  mdAttrOffset: number;
} {
  const length = SYNTH_MD_OFFSET + 17 + 32; // 109
  const bytes = Buffer.alloc(length);
  MD_PREFIX.copy(bytes, SYNTH_MD_OFFSET);
  bindingDigest.copy(bytes, SYNTH_MD_OFFSET + 17);
  return { bytes, length, mdAttrOffset: SYNTH_MD_OFFSET };
}

/**
 * Build a minimal V5-main witness exercising §6.2-§6.5:
 *   §6.2 parser binds (timestamp + policyLeafHash)
 *   §6.3 three SHA-256 chains (binding, signedAttrs, leafTBS) + Bytes32ToHiLo
 *   §6.4 SignedAttrsParser + messageDigest === sha256(bindingBytes)
 *   §6.5 leafSpkiCommit + intSpkiCommit from real SPKI fixtures
 *
 * leafTBS is a synthetic 64-byte stand-in (any well-padded byte sequence
 * works for §6.3; §6.9 will bind it to leaf-cert DER consistency later).
 *
 * Public signals not yet wired (msgSender, nullifier, ctxHashHi/Lo) stay
 * anchored by _unusedHash; the witness passes any self-consistent value.
 */
async function buildV5SmokeWitness(): Promise<Record<string, unknown>> {
  const v2core = buildV2CoreWitnessFromFixture(FIXTURE_DIR);
  const fix = loadFixture(FIXTURE_DIR);
  const bindingBuf = readFileSync(resolve(FIXTURE_DIR, 'binding.qkb2.json'));

  // SHA-256 of the binding (the "bindingHash" public signal pair).
  const bindingDigest = createHash('sha256').update(bindingBuf).digest();
  const bindingHashHi = BigInt('0x' + bindingDigest.subarray(0, 16).toString('hex'));
  const bindingHashLo = BigInt('0x' + bindingDigest.subarray(16, 32).toString('hex'));
  const bindingPadded = shaPad(bindingBuf);

  // Synthetic signedAttrs containing messageDigest = sha256(binding).
  const sa = buildSyntheticSignedAttrs(bindingDigest);
  const saDigest = createHash('sha256').update(sa.bytes).digest();
  const signedAttrsHashHi = BigInt('0x' + saDigest.subarray(0, 16).toString('hex'));
  const signedAttrsHashLo = BigInt('0x' + saDigest.subarray(16, 32).toString('hex'));
  const saPadded = shaPad(sa.bytes);

  // Synthetic leafTBS — 64 bytes of arbitrary content. The leafTbsHash
  // public signals are bound to its sha256 here; §6.9 adds a separate
  // consistency check against leafCertBytes.
  const leafTbsBuf = Buffer.alloc(64);
  for (let i = 0; i < 64; i++) leafTbsBuf[i] = i;
  const leafTbsDigest = createHash('sha256').update(leafTbsBuf).digest();
  const leafTbsHashHi = BigInt('0x' + leafTbsDigest.subarray(0, 16).toString('hex'));
  const leafTbsHashLo = BigInt('0x' + leafTbsDigest.subarray(16, 32).toString('hex'));
  const leafTbsPadded = shaPad(leafTbsBuf);

  const policyLeafHash = BigInt('0x' + fix.expected.policyLeafHashHex);

  // §6.5 — real SPKI fixtures (leaf + intermediate from admin-ecdsa).
  // SpkiCommit() inside the circuit consumes the 6×43-bit LE limb
  // decomposition; the public-signal binding asserts equality with the
  // off-circuit `spkiCommit(spki)` reference value.
  const leafSpki = readFileSync(resolve(FIXTURE_DIR, 'leaf-spki.bin'));
  const intSpki = readFileSync(resolve(FIXTURE_DIR, 'intermediate-spki.bin'));
  const { x: leafX, y: leafY } = parseP256Spki(leafSpki);
  const { x: intX, y: intY } = parseP256Spki(intSpki);
  const leafXLimbs = decomposeTo643Limbs(leafX);
  const leafYLimbs = decomposeTo643Limbs(leafY);
  const intXLimbs = decomposeTo643Limbs(intX);
  const intYLimbs = decomposeTo643Limbs(intY);
  const leafSpkiCommit = await spkiCommit(leafSpki);
  const intSpkiCommit = await spkiCommit(intSpki);

  return {
    // 14 public inputs (canonical V5 spec §0.1 order).
    msgSender: 0,
    timestamp: fix.expected.timestamp,             // §6.2
    nullifier: 0,
    ctxHashHi: 0,
    ctxHashLo: 0,
    bindingHashHi,                                  // §6.3
    bindingHashLo,                                  // §6.3
    signedAttrsHashHi,                              // §6.3
    signedAttrsHashLo,                              // §6.3
    leafTbsHashHi,                                  // §6.3
    leafTbsHashLo,                                  // §6.3
    policyLeafHash,                                 // §6.2
    leafSpkiCommit,                                 // §6.5
    intSpkiCommit,                                  // §6.5

    // Parser inputs (§6.2).
    bindingBytes: v2core.bytes,
    bindingLength: v2core.bcanonLen,
    bindingPaddedIn: rightPadZero(bindingPadded, V2CORE_MAX_BCANON),
    bindingPaddedLen: bindingPadded.length,
    pkValueOffset: v2core.pkValueOffset,
    schemeValueOffset: v2core.schemeValueOffset,
    assertionsValueOffset: v2core.assertionsValueOffset,
    statementSchemaValueOffset: v2core.statementSchemaValueOffset,
    nonceValueOffset: v2core.nonceValueOffset,
    ctxValueOffset: v2core.ctxValueOffset,
    ctxHexLen: v2core.ctxHexLen,
    policyIdValueOffset: v2core.policyIdValueOffset,
    policyIdLen: v2core.policyIdLen,
    policyLeafHashValueOffset: v2core.policyLeafHashValueOffset,
    policyBindingSchemaValueOffset: v2core.policyBindingSchemaValueOffset,
    policyVersionValueOffset: v2core.policyVersionValueOffset,
    policyVersionDigitCount: v2core.policyVersionDigitCount,
    tsValueOffset: v2core.tsValueOffset,
    tsDigitCount: v2core.tsDigitCount,
    versionValueOffset: v2core.versionValueOffset,
    nonceBytesIn: v2core.nonceBytesIn,
    policyIdBytesIn: v2core.policyIdBytesIn,
    policyVersionIn: v2core.policyVersionIn,

    // §6.3 / §6.4 inputs.
    signedAttrsBytes: rightPadZero(sa.bytes, MAX_SA),
    signedAttrsLength: sa.length,
    signedAttrsPaddedIn: rightPadZero(saPadded, MAX_SA),
    signedAttrsPaddedLen: saPadded.length,
    mdAttrOffset: sa.mdAttrOffset,

    leafTbsBytes: rightPadZero(leafTbsBuf, MAX_LEAF_TBS),
    leafTbsLength: leafTbsBuf.length,
    leafTbsPaddedIn: rightPadZero(leafTbsPadded, MAX_LEAF_TBS),
    leafTbsPaddedLen: leafTbsPadded.length,

    // §6.5 limb inputs — real fixtures (consumed by SpkiCommit instances).
    leafXLimbs,
    leafYLimbs,
    intXLimbs,
    intYLimbs,

    // Still-unwired inputs (§6.6-§6.10) — zero-padded.
    leafCertBytes: zeros(MAX_CERT),
    subjectSerialValueOffset: 0,
    subjectSerialValueLength: 0,
    pkX: zeros(4),
    pkY: zeros(4),
  };
}

describe('QKBPresentationV5 — §6.2-§6.5 (parser + 3× SHA + signedAttrs binding + 2× SpkiCommit)', function () {
  this.timeout(1800000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('QKBPresentationV5.circom');
  });

  it('compiles + accepts the QKB/2.0 fixture witness with all wired binds satisfied', async () => {
    const input = await buildV5SmokeWitness();
    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);

    // Sanity on what we passed in (the real soundness comes from the constraints).
    expect(input.timestamp).to.equal(1777478400);
    expect((input.policyLeafHash as bigint).toString(16)).to.equal(
      '2d00e73da8dd4dc99f04371d3ce01ecbcf4ad8e476c9017a304c57873494f812',
    );
  });

  // §6.2 tamper rejections
  it('rejects a tampered timestamp public signal (§6.2)', async () => {
    const input = await buildV5SmokeWitness();
    const tampered = { ...input, timestamp: 1777478401 };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a tampered policyLeafHash public signal (§6.2)', async () => {
    const input = await buildV5SmokeWitness();
    const tampered = {
      ...input,
      policyLeafHash: (input.policyLeafHash as bigint) + 1n,
    };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // §6.3 tamper rejections — the SHA-chain binding is enforced via
  // bindingHashHi/Lo public-signal equality with Bytes32ToHiLo(sha256(bindingBytes)).
  it('rejects a tampered bindingHashHi public signal (§6.3)', async () => {
    const input = await buildV5SmokeWitness();
    const tampered = { ...input, bindingHashHi: (input.bindingHashHi as bigint) ^ 1n };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a tampered signedAttrsHashLo public signal (§6.3)', async () => {
    const input = await buildV5SmokeWitness();
    const tampered = {
      ...input,
      signedAttrsHashLo: (input.signedAttrsHashLo as bigint) ^ 1n,
    };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a non-canonical bindingPaddedIn (§6.3 Sha256CanonPad)', async () => {
    const input = await buildV5SmokeWitness();
    // Flip the FIPS-required 0x80 marker byte at index dataLen (the byte
    // immediately after the message). Sha256CanonPad asserts paddedIn[dataLen] === 0x80;
    // changing it to anything else fails canonical-padding verification. Bytes
    // beyond paddedLen aren't checked, so we have to land within the active range.
    const dataLen = input.bindingLength as number;
    const tamperedPadded = [...(input.bindingPaddedIn as number[])];
    tamperedPadded[dataLen] = 0x81; // was 0x80 per FIPS canonical padding
    const tampered = { ...input, bindingPaddedIn: tamperedPadded };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // §6.4 tamper rejection — the soundness chain. If signedAttrs.messageDigest
  // ≠ sha256(bindingBytes), the equality bindingDigestBytes[i] === saParser.messageDigestBytes[i]
  // must fail. This is THE load-bearing invariant for the §4 fixed-shape walker.
  it('rejects a signedAttrs whose messageDigest does not equal sha256(bindingBytes) (§6.4 — soundness chain)', async () => {
    const input = await buildV5SmokeWitness();
    // Flip one byte of the messageDigest content inside signedAttrsBytes.
    // The 32-byte content sits at SYNTH_MD_OFFSET + 17. Re-pad the SHA input
    // so the *bindingHash* public signal still matches (else we'd be testing
    // §6.3 instead of §6.4).
    const saBytes = [...(input.signedAttrsBytes as number[])];
    const mdContentStart = SYNTH_MD_OFFSET + 17;
    saBytes[mdContentStart] = ((saBytes[mdContentStart] as number) ^ 0xff) & 0xff;
    // Recompute SA padded form + hash so §6.3 stays satisfied; only the
    // §6.4 messageDigest === bindingHash equality is the failing constraint.
    const tamperedSaBuf = Buffer.from(saBytes.slice(0, input.signedAttrsLength as number));
    const tamperedSaDigest = createHash('sha256').update(tamperedSaBuf).digest();
    const tamperedSaPadded = shaPad(tamperedSaBuf);
    const tampered = {
      ...input,
      signedAttrsBytes: rightPadZero(tamperedSaBuf, MAX_SA),
      signedAttrsPaddedIn: rightPadZero(tamperedSaPadded, MAX_SA),
      signedAttrsPaddedLen: tamperedSaPadded.length,
      // Re-supply the matching new SA hash so §6.3 doesn't fire instead.
      signedAttrsHashHi: BigInt('0x' + tamperedSaDigest.subarray(0, 16).toString('hex')),
      signedAttrsHashLo: BigInt('0x' + tamperedSaDigest.subarray(16, 32).toString('hex')),
    };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // §6.5 tamper rejection — flipping any single limb of leafXLimbs while
  // keeping leafSpkiCommit at the original Poseidon₂(Poseidon₆(X), Poseidon₆(Y))
  // breaks the public-signal binding. This catches silent SPKI substitution
  // (the contract-side spkiCommit-from-DER and the circuit-side
  // spkiCommit-from-limbs MUST agree on identical inputs).
  it('rejects a tampered leafXLimbs[0] while keeping leafSpkiCommit (§6.5)', async () => {
    const input = await buildV5SmokeWitness();
    const tamperedLimbs = [...(input.leafXLimbs as bigint[])];
    tamperedLimbs[0] = (tamperedLimbs[0] as bigint) + 1n;
    const tampered = { ...input, leafXLimbs: tamperedLimbs };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // Suppress unused-import lint; reserved for §6.6+ wiring.
  void V2CORE_MAX_POLICY_ID;
});
