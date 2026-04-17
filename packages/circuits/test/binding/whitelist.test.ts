import { expect } from 'chai';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';

function hashToBitsMsbFirst(hash: Uint8Array): number[] {
  const bits: number[] = [];
  for (const b of hash) {
    for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  }
  return bits;
}

// __dirname is .../packages/circuits/test/binding → repo root is 4 levels up.
const repoRoot = resolve(__dirname, '..', '..', '..', '..');
const enText = readFileSync(resolve(repoRoot, 'fixtures', 'declarations', 'en.txt'));
const ukText = readFileSync(resolve(repoRoot, 'fixtures', 'declarations', 'uk.txt'));

describe('DeclarationWhitelist', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('binding/DeclarationWhitelistTest.circom');
  });

  it('accepts the EN canonical declaration digest', async () => {
    const h = createHash('sha256').update(enText).digest();
    const witness = await circuit.calculateWitness(
      { digestBits: hashToBitsMsbFirst(h).map(String) },
      true,
    );
    await circuit.checkConstraints(witness);
  });

  it('accepts the UK canonical declaration digest', async () => {
    const h = createHash('sha256').update(ukText).digest();
    await circuit.calculateWitness(
      { digestBits: hashToBitsMsbFirst(h).map(String) },
      true,
    );
  });

  it('rejects an unknown digest (1-bit perturbation of EN)', async () => {
    const h = createHash('sha256').update(enText).digest();
    const bits = hashToBitsMsbFirst(h);
    bits[42] = 1 - bits[42]!;
    let threw = false;
    try {
      await circuit.calculateWitness({ digestBits: bits.map(String) }, true);
    } catch {
      threw = true;
    }
    expect(threw, 'unknown digest must fail').to.equal(true);
  });

  it('rejects all zeros', async () => {
    let threw = false;
    try {
      await circuit.calculateWitness(
        { digestBits: new Array(256).fill(0).map(String) },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
