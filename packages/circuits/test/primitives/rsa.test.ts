import { expect } from 'chai';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';

interface VectorCase {
  label: string;
  message: string[];
  signature: string[];
  modulus: string[];
  shouldVerify: boolean;
}

interface FixtureFile {
  cases: Record<string, VectorCase>;
}

const fixturePath = resolve(__dirname, '..', '..', 'fixtures', 'rsa-vectors.json');
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as FixtureFile;

describe('RsaPkcs1V15Verify (2048-bit, e=65537)', function () {
  // RSA-2048 verify is heavy: ~1M constraints. Allow up to 10 minutes total.
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('primitives/RsaPkcs1V15VerifyTest.circom');
  });

  it('accepts a valid signature', async () => {
    const c = fixture.cases.valid;
    const witness = await circuit.calculateWitness(
      { message: c.message, signature: c.signature, modulus: c.modulus },
      true,
    );
    await circuit.checkConstraints(witness);
  });

  it('rejects a signature with a flipped bit', async () => {
    const c = fixture.cases.tamperedSignature;
    let threw = false;
    try {
      await circuit.calculateWitness(
        { message: c.message, signature: c.signature, modulus: c.modulus },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw, 'witness calculation must fail for tampered signature').to.equal(true);
  });

  it('rejects a valid signature against a wrong modulus', async () => {
    const c = fixture.cases.wrongModulus;
    let threw = false;
    try {
      await circuit.calculateWitness(
        { message: c.message, signature: c.signature, modulus: c.modulus },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw, 'witness calculation must fail for wrong modulus').to.equal(true);
  });
});
