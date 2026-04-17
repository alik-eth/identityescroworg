import { expect } from 'chai';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';

interface VectorCase {
  label: string;
  msghash: string[];
  r: string[];
  s: string[];
  pubkey: [string[], string[]];
  shouldVerify: boolean;
}

interface FixtureFile {
  cases: Record<string, VectorCase>;
}

const fixturePath = resolve(
  __dirname,
  '..',
  '..',
  'fixtures',
  'ecdsa-p256-vectors.json',
);
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as FixtureFile;

describe('EcdsaP256Verify (P-256, n=43 k=6)', function () {
  // P-256 verify is the heaviest sub-circuit: ~3M constraints, expect 60-180s.
  this.timeout(1800000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('primitives/EcdsaP256Verify.circom');
  });

  it('accepts a valid signature', async () => {
    const c = fixture.cases.valid;
    const witness = await circuit.calculateWitness(
      { msghash: c.msghash, r: c.r, s: c.s, pubkey: c.pubkey },
      true,
    );
    await circuit.checkConstraints(witness);
  });

  it('rejects a signature with r tampered (+1 mod n)', async () => {
    const c = fixture.cases.tamperedR;
    let threw = false;
    try {
      await circuit.calculateWitness(
        { msghash: c.msghash, r: c.r, s: c.s, pubkey: c.pubkey },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw, 'tampered r must fail (result === 1 violated)').to.equal(true);
  });

  it('rejects a signature with s tampered (+1 mod n)', async () => {
    const c = fixture.cases.tamperedS;
    let threw = false;
    try {
      await circuit.calculateWitness(
        { msghash: c.msghash, r: c.r, s: c.s, pubkey: c.pubkey },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw, 'tampered s must fail').to.equal(true);
  });

  it('rejects a valid signature against a wrong pubkey', async () => {
    const c = fixture.cases.wrongPubkey;
    let threw = false;
    try {
      await circuit.calculateWitness(
        { msghash: c.msghash, r: c.r, s: c.s, pubkey: c.pubkey },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw, 'wrong pubkey must fail').to.equal(true);
  });
});
