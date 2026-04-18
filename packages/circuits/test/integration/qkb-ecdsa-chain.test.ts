import { expect } from 'chai';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';
import { buildChainWitness, buildLeafWitness } from './witness-builder';

const FIXTURE_DIR = resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa');

describe('QKBPresentationEcdsaChain — end-to-end (real Diia leaf + synth intermediate)', function () {
  // Chain-side proof: constraints 3 (intermediate signs leaf TBS) + 4
  // (intermediate ∈ Merkle rTL). Smaller than the leaf (~3.2 M constraints
  // target per spec §14.3) — no Bcanon/BindingParseFull, only one EcdsaP256
  // verify + one Sha256Var + Merkle depth-16. Complements
  // qkb-ecdsa.test.ts and asserts the on-chain equality glue holds (leaf's
  // leafSpkiCommit == chain's leafSpkiCommit).
  this.timeout(60 * 60 * 1000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('QKBPresentationEcdsaChain.circom');
  });

  it('calculateWitness passes on the real Diia admin binding', async () => {
    const input = await buildChainWitness(FIXTURE_DIR);
    const witness = await circuit.calculateWitness(
      input as unknown as Record<string, unknown>,
      true,
    );
    await circuit.checkConstraints(witness);
    expect(witness.length).to.be.greaterThan(0);
  });

  it('leafSpkiCommit matches between leaf + chain witness derivations (on-chain equality gate precondition)', async () => {
    // Both builders call buildSharedInputs → computeLeafSpkiCommit on the
    // same leafDer bytes, so the leafSpkiCommit values they feed into their
    // respective witnesses MUST be identical. If this ever drifts, the
    // on-chain `require(leafInputs.leafSpkiCommit == chainInputs.leafSpkiCommit)`
    // in QKBVerifier.verify will reject every split-proof submission.
    const { buildSharedInputs } = await import('./witness-builder');
    const sharedA = await buildSharedInputs(FIXTURE_DIR);
    const sharedB = await buildSharedInputs(FIXTURE_DIR);
    expect(sharedA.leafSpkiCommit).to.equal(sharedB.leafSpkiCommit);

    // And confirm it's not just pair-equal but consumed by both builders:
    // the ChainWitnessInput doesn't expose leafSpkiCommit directly (it's an
    // output, not an input), but the leafSpkiXOffset/leafSpkiYOffset it
    // supplies MUST match the leaf builder's.
    const leafIn = await buildLeafWitness(FIXTURE_DIR);
    const chainIn = await buildChainWitness(FIXTURE_DIR);
    expect(chainIn.leafSpkiXOffset).to.equal(leafIn.leafSpkiXOffset);
    expect(chainIn.leafSpkiYOffset).to.equal(leafIn.leafSpkiYOffset);
  });
});
