import { expect } from 'chai';
import { buildPoseidon } from 'circomlibjs';
import { compile, type CompiledCircuit } from '../helpers/compile';

describe('ZkqesPresentationAgeV4', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;
  let poseidonDobCommit: (dobYmd: bigint, sourceTag: bigint) => bigint;

  before(async () => {
    circuit = await compile('ZkqesPresentationAgeV4.circom');
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    poseidonDobCommit = (dobYmd, sourceTag) =>
      F.toObject(poseidon([dobYmd, sourceTag])) as bigint;
  });

  it('proves dobYmd <= ageCutoffDate → ageQualified=1', async () => {
    const dobYmd = 19900815n;
    const sourceTag = 1n;
    const ageCutoffDate = 20080424n;
    const dobCommit = poseidonDobCommit(dobYmd, sourceTag);
    const witness = await circuit.calculateWitness(
      { dobYmd, sourceTag, ageCutoffDate, dobCommit, ageQualified: 1n },
      true,
    );
    await circuit.checkConstraints(witness);
    // Public signal order: dobCommit, ageCutoffDate, ageQualified (inputs in
    // the order declared on `component main` public list).
    expect(witness[1]).to.equal(dobCommit);
    expect(witness[2]).to.equal(ageCutoffDate);
    expect(witness[3]).to.equal(1n);
  });

  it('emits ageQualified=0 when dobYmd > cutoff', async () => {
    const dobYmd = 20100101n;
    const sourceTag = 1n;
    const ageCutoffDate = 20080424n;
    const dobCommit = poseidonDobCommit(dobYmd, sourceTag);
    const witness = await circuit.calculateWitness(
      { dobYmd, sourceTag, ageCutoffDate, dobCommit, ageQualified: 0n },
      true,
    );
    await circuit.checkConstraints(witness);
    expect(witness[3]).to.equal(0n);
  });

  it('rejects a mismatched dobCommit', async () => {
    const dobYmd = 19900815n;
    const sourceTag = 1n;
    const ageCutoffDate = 20080424n;
    // Caller supplies the wrong commitment.
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          dobYmd,
          sourceTag,
          ageCutoffDate,
          dobCommit: 12345n,
          ageQualified: 1n,
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw, 'witness calc must fail when dobCommit is wrong').to.equal(true);
  });

  it('rejects a mismatched ageQualified', async () => {
    const dobYmd = 19900815n;
    const sourceTag = 1n;
    const ageCutoffDate = 20080424n;
    const dobCommit = poseidonDobCommit(dobYmd, sourceTag);
    let threw = false;
    try {
      await circuit.calculateWitness(
        { dobYmd, sourceTag, ageCutoffDate, dobCommit, ageQualified: 0n },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw, 'witness calc must fail when ageQualified disagrees').to.equal(true);
  });
});
