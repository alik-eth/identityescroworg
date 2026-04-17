import { expect } from 'chai';
import { compile, type CompiledCircuit } from './helpers/compile';

describe('smoke: harness', () => {
  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('_smoke.circom');
  });

  it('computes b = a + 1 and the witness satisfies constraints', async () => {
    const witness = await circuit.calculateWitness({ a: 41 }, true);
    await circuit.checkConstraints(witness);
    // witness[0] is the constant 1; witness[1] is the first output (b).
    expect(witness[1]).to.equal(42n);
  });
});
