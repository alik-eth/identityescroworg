import { expect } from 'chai';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';

const CERT_PATH = resolve(__dirname, '..', '..', 'fixtures', 'test-ca.der');
// Pinned cross-check vector supplied by team-lead, computed off-circuit by
// `canonicalizeCertHash` in @zkqes/lotl-flattener (commit b1ffbd9).
const EXPECTED =
  3343320682401079542006381927947751400566902976482490538395564021405243591237n;

describe('PoseidonChunkHash (fixed-length 839 bytes)', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('primitives/PoseidonChunkHash839.circom');
  });

  it('matches the flattener canonicalizeCertHash on the pinned 839-byte test cert', async () => {
    const der = readFileSync(CERT_PATH);
    expect(der.length).to.equal(839);

    const witness = await circuit.calculateWitness(
      { bytes: Array.from(der) },
      true,
    );
    await circuit.checkConstraints(witness);
    // Output `out` is signal index 1 (output-first).
    expect(witness[1]).to.equal(EXPECTED);
  });

  it('changes when a single byte is flipped', async () => {
    const der = Buffer.from(readFileSync(CERT_PATH));
    der[100] ^= 0x01;
    const witness = await circuit.calculateWitness(
      { bytes: Array.from(der) },
      true,
    );
    expect(witness[1]).to.not.equal(EXPECTED);
  });
});
