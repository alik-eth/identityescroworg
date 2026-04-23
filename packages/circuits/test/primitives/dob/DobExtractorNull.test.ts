import { expect } from 'chai';
import { compile, type CompiledCircuit } from '../../helpers/compile';

describe('DobExtractorNull', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('dob/DobExtractorNull.circom');
  });

  it('always emits dobSupported=0, sourceTag=0, dobYmd=0', async () => {
    const witness = await circuit.calculateWitness(
      {
        leafDER: Array(2048).fill(0),
        leafDerLen: 0,
      },
      true,
    );
    await circuit.checkConstraints(witness);
    // Output order: dobYmd, sourceTag, dobSupported (witness[1..3]).
    expect(witness[1]).to.equal(0n);
    expect(witness[2]).to.equal(0n);
    expect(witness[3]).to.equal(0n);
  });

  it('ignores leafDerLen for a non-zero prefix — still dobSupported=0', async () => {
    const witness = await circuit.calculateWitness(
      {
        leafDER: Array(2048).fill(0x42),
        leafDerLen: 100,
      },
      true,
    );
    await circuit.checkConstraints(witness);
    expect(witness[1]).to.equal(0n);
    expect(witness[2]).to.equal(0n);
    expect(witness[3]).to.equal(0n);
  });
});
