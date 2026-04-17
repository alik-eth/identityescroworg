import { expect } from 'chai';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';

const fixturesDir = resolve(__dirname, '..', '..', 'fixtures', 'x509-samples');
const der = readFileSync(resolve(fixturesDir, 'leaf.der'));
const fixture = JSON.parse(
  readFileSync(resolve(fixturesDir, 'leaf.fixture.json'), 'utf8'),
) as {
  notBefore: { contentOffset: number; ascii: string };
  notAfter: { contentOffset: number; ascii: string };
  derLength: number;
};

const MAX = 1024;

function paddedDer(): number[] {
  const out = new Array<number>(MAX).fill(0);
  for (let i = 0; i < der.length; i++) out[i] = der[i]!;
  return out;
}

describe('X509Parse: Asn1GeneralizedTime15', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('x509/Asn1GeneralizedTime15Test.circom');
  });

  it('extracts 15-byte content at the notBefore offset', async () => {
    const witness = await circuit.calculateWitness(
      { bytes: paddedDer(), offset: fixture.notBefore.contentOffset },
      true,
    );
    await circuit.checkConstraints(witness);
    // Output content[0..14] is signals 1..15 (output-first ordering).
    let s = '';
    for (let i = 1; i <= 15; i++) s += String.fromCharCode(Number(witness[i]!));
    expect(s).to.equal(fixture.notBefore.ascii);
  });

  it('extracts 15-byte content at the notAfter offset', async () => {
    const witness = await circuit.calculateWitness(
      { bytes: paddedDer(), offset: fixture.notAfter.contentOffset },
      true,
    );
    await circuit.checkConstraints(witness);
    let s = '';
    for (let i = 1; i <= 15; i++) s += String.fromCharCode(Number(witness[i]!));
    expect(s).to.equal(fixture.notAfter.ascii);
  });

  it('rejects an offset that does not land on a GeneralizedTime tag', async () => {
    let threw = false;
    try {
      // Intentional: offset+1 lands one byte past the real header so the
      // tag check (bytes[offset-2] === 0x18) will fail.
      await circuit.calculateWitness(
        { bytes: paddedDer(), offset: fixture.notBefore.contentOffset + 1 },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw, 'wrong-offset must fail tag check').to.equal(true);
  });

  it('rejects an offset outside the buffer', async () => {
    let threw = false;
    try {
      await circuit.calculateWitness({ bytes: paddedDer(), offset: MAX - 5 }, true);
    } catch {
      threw = true;
    }
    expect(threw, 'offset+expectedLen > MAX must fail bound check').to.equal(true);
  });
});
