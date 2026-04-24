import { expect } from 'chai';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';
import { buildLeafWitness } from './witness-builder';

const FIXTURE_DIR = resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa');

describe('QKBPresentationEcdsaLeaf — end-to-end (real Diia admin QES binding)', function () {
  // Leaf-side proof: constraints 1, 2, 5, 6 + scoped credential nullifier (§14.4).
  // One EcdsaP256Verify plus three Sha256Var instantiations; fits the 22 GB
  // systemd cap with NODE_OPTIONS=--max-old-space-size=20480. The chain-side
  // proof is covered in qkb-ecdsa-chain.test.ts.
  this.timeout(60 * 60 * 1000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('QKBPresentationEcdsaLeaf.circom');
  });

  it('calculateWitness passes on the real Diia admin binding', async () => {
    const input = await buildLeafWitness(FIXTURE_DIR);
    const witness = await circuit.calculateWitness(
      input as unknown as Record<string, unknown>,
      true,
    );
    await circuit.checkConstraints(witness);
    expect(witness.length).to.be.greaterThan(0);
  });
});
