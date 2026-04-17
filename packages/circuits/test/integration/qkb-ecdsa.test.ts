import { expect } from 'chai';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';
import { buildEcdsaWitness } from './witness-builder';

const FIXTURE_DIR = resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa');

describe('QKBPresentationEcdsa — end-to-end (real Diia admin QES + synth intermediate)', function () {
  // The main circuit involves 2× EcdsaP256Verify plus three Sha256Var
  // instantiations at MAX_BYTES=2048, which compiles slowly (tens of
  // minutes) and needs generous heap. Run under `systemd-run -p
  // MemoryMax=22G -p MemorySwapMax=0 --setenv=NODE_OPTIONS='--max-old-space-size=20480'`.
  this.timeout(60 * 60 * 1000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('QKBPresentationEcdsa.circom');
  });

  it('calculateWitness passes on the real Diia admin binding + synth chain', async () => {
    const input = buildEcdsaWitness(FIXTURE_DIR) as unknown as Record<string, unknown>;
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);
    expect(witness.length).to.be.greaterThan(0);
  });
});
