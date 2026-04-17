import { expect } from 'chai';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';
import { buildEcdsaWitness } from './witness-builder';

const FIXTURE_DIR = resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa');

// Pick only the signals QKBPresentationEcdsaLeaf declares as inputs. The
// chain-side witness inputs (intDER, merkle path, intSigR/S, algorithmTag,
// rTL) go to QKBPresentationEcdsaChain — compiled separately so each proof
// stays within the 22 GB compile-memory budget (spec §5.4 split-proof
// fallback).
function leafInputs(full: ReturnType<typeof buildEcdsaWitness>): Record<string, unknown> {
  const {
    pkX, pkY, ctxHash, declHash, timestamp,
    Bcanon, BcanonLen, BcanonPaddedIn, BcanonPaddedLen,
    pkValueOffset, schemeValueOffset, ctxValueOffset, ctxHexLen,
    declValueOffset, declValueLen, tsValueOffset, tsDigitCount,
    declPaddedIn, declPaddedLen,
    signedAttrs, signedAttrsLen, signedAttrsPaddedIn, signedAttrsPaddedLen, mdOffsetInSA,
    leafDER, leafSpkiXOffset, leafSpkiYOffset,
    leafSigR, leafSigS,
  } = full;
  return {
    pkX, pkY, ctxHash, declHash, timestamp,
    Bcanon, BcanonLen, BcanonPaddedIn, BcanonPaddedLen,
    pkValueOffset, schemeValueOffset, ctxValueOffset, ctxHexLen,
    declValueOffset, declValueLen, tsValueOffset, tsDigitCount,
    declPaddedIn, declPaddedLen,
    signedAttrs, signedAttrsLen, signedAttrsPaddedIn, signedAttrsPaddedLen, mdOffsetInSA,
    leafDER, leafSpkiXOffset, leafSpkiYOffset,
    leafSigR, leafSigS,
  };
}

describe('QKBPresentationEcdsaLeaf — end-to-end (real Diia admin QES binding)', function () {
  // Compile + witness for the leaf-side proof. One EcdsaP256Verify plus
  // three Sha256Var instantiations; fits under 22 GB systemd cap with
  // NODE_OPTIONS=--max-old-space-size=20480.
  this.timeout(60 * 60 * 1000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('QKBPresentationEcdsaLeaf.circom');
  });

  it('calculateWitness passes on the real Diia admin binding', async () => {
    const full = buildEcdsaWitness(FIXTURE_DIR);
    const witness = await circuit.calculateWitness(leafInputs(full), true);
    await circuit.checkConstraints(witness);
    expect(witness.length).to.be.greaterThan(0);
  });
});
