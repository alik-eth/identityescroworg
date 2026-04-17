import { expect } from 'chai';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';

interface RsaSpkiFixture {
  derPath: string;
  derLength: number;
  modulusOffset: number;
  modulusLength: number;
  modulusHex: string;
  exponentOffset: number;
  exponentBytes: number[];
}

const MAX_LEN = 512;
const fixturesDir = resolve(__dirname, '..', '..', 'fixtures', 'x509-samples');

function loadFixture(): { fix: RsaSpkiFixture; der: Buffer } {
  const fix = JSON.parse(
    readFileSync(resolve(fixturesDir, 'rsa-spki.fixture.json'), 'utf8'),
  ) as RsaSpkiFixture;
  const der = readFileSync(resolve(fixturesDir, fix.derPath));
  return { fix, der };
}

function paddedBytes(der: Buffer, max: number): number[] {
  if (der.length > max) throw new Error(`${der.length} > MAX ${max}`);
  const out = new Array<number>(max).fill(0);
  for (let i = 0; i < der.length; i++) out[i] = der[i]!;
  return out;
}

describe(`RsaSpkiExtract2048 (MAX_LEN=${MAX_LEN})`, function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('x509/RsaSpkiExtractTest.circom');
  });

  it('extracts the 256-byte modulus and validates the 65537 exponent', async () => {
    const { fix, der } = loadFixture();
    const w = await circuit.calculateWitness(
      {
        bytes: paddedBytes(der, MAX_LEN),
        modulusOffset: fix.modulusOffset,
        exponentOffset: fix.exponentOffset,
      },
      true,
    );
    await circuit.checkConstraints(w);
    // modulusBytes[0] lands at witness index 1.
    const expectedFirst = parseInt(fix.modulusHex.slice(0, 2), 16);
    expect(Number(w[1])).to.equal(expectedFirst);
  });

  it('rejects a shifted modulusOffset (sign-byte check fails)', async () => {
    const { fix, der } = loadFixture();
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          bytes: paddedBytes(der, MAX_LEN),
          modulusOffset: fix.modulusOffset - 1, // now sign byte is no longer 0x00
          exponentOffset: fix.exponentOffset,
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a wrong exponentOffset (not landing on INTEGER 3 01 00 01)', async () => {
    const { fix, der } = loadFixture();
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          bytes: paddedBytes(der, MAX_LEN),
          modulusOffset: fix.modulusOffset,
          exponentOffset: fix.exponentOffset + 1,
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a tampered modulus TLV length byte', async () => {
    const { fix, der } = loadFixture();
    const buf = Buffer.from(der);
    // bytes[modulusOffset - 2] is the length-hi byte (0x01). Flip to 0x02.
    buf[fix.modulusOffset - 2] = 0x02;
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          bytes: paddedBytes(buf, MAX_LEN),
          modulusOffset: fix.modulusOffset,
          exponentOffset: fix.exponentOffset,
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a tampered sign byte', async () => {
    const { fix, der } = loadFixture();
    const buf = Buffer.from(der);
    buf[fix.modulusOffset - 1] = 0x01;
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          bytes: paddedBytes(buf, MAX_LEN),
          modulusOffset: fix.modulusOffset,
          exponentOffset: fix.exponentOffset,
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
