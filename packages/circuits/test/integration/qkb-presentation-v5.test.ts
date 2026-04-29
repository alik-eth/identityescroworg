import { expect } from 'chai';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';
import {
  buildV2CoreWitnessFromFixture,
  loadFixture,
  V2CORE_MAX_BCANON,
  V2CORE_MAX_POLICY_ID,
} from '../binding/v2core-witness';

const FIXTURE_DIR = resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa');
const MAX_SA = 1536;
const MAX_LEAF_TBS = 1024;
const MAX_CERT = 2048;

function zeros(n: number): number[] {
  return new Array<number>(n).fill(0);
}

/**
 * Build a minimal V5-main witness that exercises only §6.2 (parser binds).
 * Unwired-as-of-§6.2 private inputs are zero-padded and unwired-as-of-§6.2
 * public inputs are bound only by the placeholder _unusedHash sum, so any
 * self-consistent value is fine.
 *
 * As §6.3-§6.10 wire actual constraints, this builder will get extended in
 * lockstep with the circuit; for now it pins the parser-driven invariants
 * (tsValue ↔ timestamp, parser.policyLeafHash ↔ policyLeafHash).
 */
function buildV5SmokeWitness(): Record<string, unknown> {
  const v2core = buildV2CoreWitnessFromFixture(FIXTURE_DIR);
  const fix = loadFixture(FIXTURE_DIR);

  // Public-signal placeholders. Pick zero for the unwired ones and the
  // expected fixture-derived values for the wired ones (timestamp,
  // policyLeafHash). msgSender, nullifier, ctxHash*, bindingHash*, sa hash,
  // leafTbs hash, leafSpkiCommit, intSpkiCommit all fall under _unusedHash
  // and are arbitrary.
  const policyLeafHash = BigInt('0x' + fix.expected.policyLeafHashHex);

  return {
    // 14 public inputs (canonical order — see V5 spec §0.1).
    msgSender: 0,
    timestamp: fix.expected.timestamp,        // §6.2 binds this to parser.tsValue
    nullifier: 0,
    ctxHashHi: 0,
    ctxHashLo: 0,
    bindingHashHi: 0,
    bindingHashLo: 0,
    signedAttrsHashHi: 0,
    signedAttrsHashLo: 0,
    leafTbsHashHi: 0,
    leafTbsHashLo: 0,
    policyLeafHash,                            // §6.2 binds this to parser.policyLeafHash
    leafSpkiCommit: 0,
    intSpkiCommit: 0,

    // Parser inputs (§6.2 — wired).
    bindingBytes: v2core.bytes,
    bindingLength: v2core.bcanonLen,
    bindingPaddedIn: zeros(V2CORE_MAX_BCANON),
    bindingPaddedLen: 0,
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

    // SHA / cert / SPKI / pk inputs (§6.3-§6.10 — currently zero-padded).
    signedAttrsBytes: zeros(MAX_SA),
    signedAttrsLength: 0,
    signedAttrsPaddedIn: zeros(MAX_SA),
    signedAttrsPaddedLen: 0,
    mdAttrOffset: 0,

    leafTbsBytes: zeros(MAX_LEAF_TBS),
    leafTbsLength: 0,
    leafTbsPaddedIn: zeros(MAX_LEAF_TBS),
    leafTbsPaddedLen: 0,

    leafCertBytes: zeros(MAX_CERT),
    subjectSerialValueOffset: 0,
    subjectSerialValueLength: 0,

    leafXLimbs: zeros(6),
    leafYLimbs: zeros(6),
    intXLimbs: zeros(6),
    intYLimbs: zeros(6),

    pkX: zeros(4),
    pkY: zeros(4),
  };
}

describe('QKBPresentationV5 — §6.2 BindingParseV2CoreFast wiring', function () {
  this.timeout(1800000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('QKBPresentationV5.circom');
  });

  it('compiles + accepts the QKB/2.0 fixture witness with parser binds satisfied', async () => {
    const input = buildV5SmokeWitness();
    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);

    // The circuit binds parser.tsValue === timestamp (public) and
    // parser.policyLeafHash === policyLeafHash (public). If the witness was
    // built from the same fixture and matches the public signals we passed,
    // calculateWitness wouldn't have thrown. The asserts here are defensive
    // sanity — the real soundness lives in the byte-equality binds inside
    // BindingParseV2CoreFast (already covered by the parity test).
    expect(input.timestamp).to.equal(1777478400);
    expect((input.policyLeafHash as bigint).toString(16)).to.equal(
      '2d00e73da8dd4dc99f04371d3ce01ecbcf4ad8e476c9017a304c57873494f812',
    );
  });

  it('rejects a tampered timestamp public signal (parser.tsValue === timestamp)', async () => {
    const input = buildV5SmokeWitness();
    const tampered = { ...input, timestamp: 1777478401 };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a tampered policyLeafHash public signal (parser.policyLeafHash === policyLeafHash)', async () => {
    const input = buildV5SmokeWitness();
    // Flip a single bit in policyLeafHash.
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

  // Suppress unused-import lint for V2CORE_MAX_POLICY_ID; reserved for §6.3+.
  void V2CORE_MAX_POLICY_ID;
});
