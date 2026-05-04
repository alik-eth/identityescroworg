import { expect } from 'chai';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';
import {
  buildV2CoreWitnessFromFixture,
  loadFixture,
  V2CORE_MAX_BCANON,
  V2CORE_MAX_POLICY_ID,
  V2CORE_NONCE_LEN,
} from './v2core-witness';

const FIXTURE_DIR = resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa');
const MAX_CTX = 256;

// BN254 scalar field modulus. Bits256ToField reduces the 256-bit leafHash to
// the field; for a 256-bit value < p (which is the case for our fixture's
// leafHash) the packed value equals the integer itself.
const BN254_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function fieldFromHex(hex: string): bigint {
  const v = BigInt('0x' + hex);
  if (v >= 1n << 256n) throw new Error('leafHash > 256 bits');
  // The circuit asserts top two bits zero AND alias-checks the low 254 bits.
  // For our fixture value the top two bits are zero already.
  return v % BN254_P;
}

// Output ordering inside the witness vector (post `1`):
//   pkBytes[65]
//   nonceBytes[32]
//   ctxBytes[MAX_CTX]
//   ctxLen
//   policyIdBytes[MAX_POLICY_ID]
//   policyLeafHash
//   policyVersion
//   tsValue
function sliceOutputs(witness: bigint[]): {
  pkBytes: bigint[];
  nonceBytes: bigint[];
  ctxBytes: bigint[];
  ctxLen: bigint;
  policyIdBytes: bigint[];
  policyLeafHash: bigint;
  policyVersion: bigint;
  tsValue: bigint;
} {
  let i = 1;
  const pkBytes = witness.slice(i, i + 65);
  i += 65;
  const nonceBytes = witness.slice(i, i + V2CORE_NONCE_LEN);
  i += V2CORE_NONCE_LEN;
  const ctxBytes = witness.slice(i, i + MAX_CTX);
  i += MAX_CTX;
  const ctxLen = witness[i] as bigint;
  i += 1;
  const policyIdBytes = witness.slice(i, i + V2CORE_MAX_POLICY_ID);
  i += V2CORE_MAX_POLICY_ID;
  const policyLeafHash = witness[i] as bigint;
  i += 1;
  const policyVersion = witness[i] as bigint;
  i += 1;
  const tsValue = witness[i] as bigint;
  return {
    pkBytes,
    nonceBytes,
    ctxBytes,
    ctxLen,
    policyIdBytes,
    policyLeafHash,
    policyVersion,
    tsValue,
  };
}

describe(`BindingParseV2Core legacy (MAX_BCANON=${V2CORE_MAX_BCANON}, MAX_CTX=${MAX_CTX})`, function () {
  this.timeout(900000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('binding/BindingParseV2CoreLegacyTest.circom');
  });

  it('parses the deterministic zkqes binding fixture (version "QKB/2.0" frozen) and produces well-formed outputs', async () => {
    const input = buildV2CoreWitnessFromFixture(FIXTURE_DIR);
    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);
    const o = sliceOutputs(w);

    // Structural sanity: pkBytes[0] is the SEC1 uncompressed prefix 0x04.
    expect(Number(o.pkBytes[0])).to.equal(0x04);
    // ctxLen for empty context "0x" must be 0.
    expect(Number(o.ctxLen)).to.equal(0);
    // ctxBytes must be all zeros (no context bytes).
    for (let k = 0; k < MAX_CTX; k++) {
      expect(o.ctxBytes[k]).to.equal(0n);
    }
    // policyIdBytes beyond policyIdLen must be zero (BPFSliceVar masks them).
    for (let k = 14; k < V2CORE_MAX_POLICY_ID; k++) {
      expect(o.policyIdBytes[k]).to.equal(0n);
    }
  });

  it('matches deterministic spot-checks — tsValue, policyVersion, policyLeafHash, nonceBytes', async () => {
    const input = buildV2CoreWitnessFromFixture(FIXTURE_DIR);
    const fix = loadFixture(FIXTURE_DIR);
    const w = await circuit.calculateWitness(input, true);
    const o = sliceOutputs(w);

    // 1. tsValue == 1777478400
    expect(Number(o.tsValue)).to.equal(fix.expected.timestamp);
    expect(Number(o.tsValue)).to.equal(1777478400);

    // 2. policyVersion == 1
    expect(Number(o.policyVersion)).to.equal(fix.expected.policyVersion);
    expect(Number(o.policyVersion)).to.equal(1);

    // 3. policyLeafHash field-equivalent to 0x2d00…f812 (mod p — but the
    //    fixture value is < p, so equality holds modulo nothing).
    const expectedLeaf = fieldFromHex(fix.expected.policyLeafHashHex);
    expect(o.policyLeafHash).to.equal(expectedLeaf);

    // 4. nonceBytes[i] == 0xAB for all 32 positions.
    for (let k = 0; k < V2CORE_NONCE_LEN; k++) {
      expect(Number(o.nonceBytes[k])).to.equal(0xab);
    }

    // 5. policyIdBytes[0..14) decodes to "qkb-default-ua".
    //    frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
    const policyId = Buffer.from(
      o.policyIdBytes.slice(0, 14).map((b) => Number(b)),
    ).toString('utf8');
    expect(policyId).to.equal('qkb-default-ua'); // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
  });

  it('rejects a tampered policyVersion ASCII digit (2→9) at the witnessed offset', async () => {
    const fix = loadFixture(FIXTURE_DIR);
    const input = buildV2CoreWitnessFromFixture(FIXTURE_DIR);
    // Flip the single policyVersion digit from "1" to "9". The decimal parser
    // emits 9, but the witness assert `policyVersion === policyVersionIn`
    // (where policyVersionIn==1 from the fixture) must reject.
    const tampered = [...(input.bytes as number[])];
    tampered[fix.offsets.policyVersionValue] = 0x39; // ASCII '9'
    const tamperedInput = { ...input, bytes: tampered };
    let threw = false;
    try {
      await circuit.calculateWitness(tamperedInput, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a shifted pkValueOffset (BindingKeyAt mismatch)', async () => {
    const input = buildV2CoreWitnessFromFixture(FIXTURE_DIR);
    const shifted = { ...input, pkValueOffset: (input.pkValueOffset as number) + 1 };
    let threw = false;
    try {
      await circuit.calculateWitness(shifted, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
