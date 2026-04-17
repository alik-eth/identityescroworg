import { expect } from 'chai';
import { compile, type CompiledCircuit } from '../helpers/compile';

function digits(s: string): number[] {
  if (s.length !== 14) throw new Error('expected 14-char YYYYMMDDHHMMSS');
  return Array.from(s).map((c) => c.charCodeAt(0));
}

describe('X509Validity', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('x509/X509ValidityTest.circom');
  });

  it('accepts ts strictly within the validity window', async () => {
    const witness = await circuit.calculateWitness(
      {
        notBefore: digits('20260101000000'),
        notAfter: digits('20300101000000'),
        ts: digits('20280601120000'),
      },
      true,
    );
    await circuit.checkConstraints(witness);
  });

  it('accepts ts equal to notBefore (boundary)', async () => {
    await circuit.calculateWitness(
      {
        notBefore: digits('20260101000000'),
        notAfter: digits('20300101000000'),
        ts: digits('20260101000000'),
      },
      true,
    );
  });

  it('accepts ts equal to notAfter (boundary)', async () => {
    await circuit.calculateWitness(
      {
        notBefore: digits('20260101000000'),
        notAfter: digits('20300101000000'),
        ts: digits('20300101000000'),
      },
      true,
    );
  });

  it('rejects ts before notBefore', async () => {
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          notBefore: digits('20260101000000'),
          notAfter: digits('20300101000000'),
          ts: digits('20251231235959'),
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects ts after notAfter', async () => {
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          notBefore: digits('20260101000000'),
          notAfter: digits('20300101000000'),
          ts: digits('20300101000001'),
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects empty validity window where notAfter < notBefore and ts in the middle', async () => {
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          notBefore: digits('20300101000000'),
          notAfter: digits('20260101000000'),
          ts: digits('20280601120000'),
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
