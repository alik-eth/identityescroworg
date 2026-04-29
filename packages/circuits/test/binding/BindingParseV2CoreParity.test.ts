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

// Output ordering — same for both Legacy and Fast (signal output declarations
// in BindingParseV2CoreFast match BindingParseV2Core verbatim).
//
//   pkBytes[65] | nonceBytes[32] | ctxBytes[MAX_CTX] | ctxLen
//   | policyIdBytes[MAX_POLICY_ID] | policyLeafHash | policyVersion | tsValue
const OUTPUTS_LEN = 65 + V2CORE_NONCE_LEN + MAX_CTX + 1 + V2CORE_MAX_POLICY_ID + 1 + 1 + 1;

function extractOutputs(witness: bigint[]): bigint[] {
  // calculateWitness returns [1, ...outputs, ...intermediate signals].
  return witness.slice(1, 1 + OUTPUTS_LEN);
}

describe('BindingParseV2Core legacy ↔ fast parity', function () {
  this.timeout(1800000);

  let legacy: CompiledCircuit;
  let fast: CompiledCircuit;

  before(async () => {
    legacy = await compile('binding/BindingParseV2CoreLegacyTest.circom');
    fast = await compile('binding/BindingParseV2CoreFastTest.circom');
  });

  it('produces byte-identical outputs on the QKB/2.0 fixture', async () => {
    const input = buildV2CoreWitnessFromFixture(FIXTURE_DIR);

    const legacyWitness = await legacy.calculateWitness(input, true);
    await legacy.checkConstraints(legacyWitness);

    const fastWitness = await fast.calculateWitness(input, true);
    await fast.checkConstraints(fastWitness);

    const legacyOut = extractOutputs(legacyWitness);
    const fastOut = extractOutputs(fastWitness);

    expect(fastOut.length).to.equal(legacyOut.length);
    for (let i = 0; i < legacyOut.length; i++) {
      // Use eql (deep) on bigint primitives; chai supports bigint equality
      // via strict equal too.
      if (legacyOut[i] !== fastOut[i]) {
        // Surface position context on first divergence for fast triage.
        let region = '?';
        let regionIdx = i;
        if (i < 65) {
          region = 'pkBytes';
        } else if (i < 65 + V2CORE_NONCE_LEN) {
          region = 'nonceBytes';
          regionIdx = i - 65;
        } else if (i < 65 + V2CORE_NONCE_LEN + MAX_CTX) {
          region = 'ctxBytes';
          regionIdx = i - 65 - V2CORE_NONCE_LEN;
        } else if (i === 65 + V2CORE_NONCE_LEN + MAX_CTX) {
          region = 'ctxLen';
        } else if (i < 65 + V2CORE_NONCE_LEN + MAX_CTX + 1 + V2CORE_MAX_POLICY_ID) {
          region = 'policyIdBytes';
          regionIdx = i - (65 + V2CORE_NONCE_LEN + MAX_CTX + 1);
        } else if (i === 65 + V2CORE_NONCE_LEN + MAX_CTX + 1 + V2CORE_MAX_POLICY_ID) {
          region = 'policyLeafHash';
        } else if (
          i === 65 + V2CORE_NONCE_LEN + MAX_CTX + 1 + V2CORE_MAX_POLICY_ID + 1
        ) {
          region = 'policyVersion';
        } else {
          region = 'tsValue';
        }
        throw new Error(
          `parity divergence at output index ${i} (${region}[${regionIdx}]): ` +
            `legacy=${legacyOut[i]} fast=${fastOut[i]}`,
        );
      }
    }
  });

  it('matches the same deterministic spot-checks as the standalone legacy test', async () => {
    const input = buildV2CoreWitnessFromFixture(FIXTURE_DIR);
    const fix = loadFixture(FIXTURE_DIR);
    const witness = await fast.calculateWitness(input, true);
    const out = extractOutputs(witness);

    // tsValue is the LAST output. policyVersion is the second-to-last.
    // policyLeafHash is third-to-last.
    const tsValue = out[out.length - 1];
    const policyVersion = out[out.length - 2];
    const policyLeafHash = out[out.length - 3];

    expect(Number(tsValue)).to.equal(fix.expected.timestamp);
    expect(Number(policyVersion)).to.equal(fix.expected.policyVersion);
    expect(policyLeafHash).to.equal(BigInt('0x' + fix.expected.policyLeafHashHex));

    // pk SEC1 prefix
    expect(Number(out[0])).to.equal(0x04);
    // nonceBytes all 0xAB
    for (let i = 0; i < V2CORE_NONCE_LEN; i++) {
      expect(Number(out[65 + i])).to.equal(0xab);
    }
  });

  it('rejects a tampered policyVersion digit (Fast tamper-rejection mirrors Legacy)', async () => {
    const fix = loadFixture(FIXTURE_DIR);
    const input = buildV2CoreWitnessFromFixture(FIXTURE_DIR);
    const tampered = [...(input.bytes as number[])];
    tampered[fix.offsets.policyVersionValue] = 0x39; // ASCII '9'
    const tamperedInput = { ...input, bytes: tampered };
    let threw = false;
    try {
      await fast.calculateWitness(tamperedInput, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects an offset out of Decoder bounds in the Fast template', async () => {
    // Fast's BPFSliceFast(MAX_B, K) builds Decoder(MAX_B - K + 1) and asserts
    // success === 1. Setting an offset that pushes any slice past
    // (MAX_BCANON - K) MUST fail. pkValueOffset reading 133 bytes; setting it
    // to MAX_BCANON - 132 = 892 would still be valid, but
    // (MAX_BCANON - 133 + 1) = 892. Any offset >= 892 forces dec.success → 0.
    const input = buildV2CoreWitnessFromFixture(FIXTURE_DIR);
    const malformed = { ...input, pkValueOffset: V2CORE_MAX_BCANON - 100 };
    let threw = false;
    try {
      await fast.calculateWitness(malformed, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
