import { expect } from 'chai';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';

interface JcsFixture {
  bcanonHex: string;
  bcanonLength: number;
  offsets: Record<string, number>;
}

const fixturesDir = resolve(__dirname, '..', '..', 'fixtures', 'jcs-bindings');
const MAX_B = 1024;

function loadFixture(name: string): JcsFixture {
  return JSON.parse(readFileSync(resolve(fixturesDir, `${name}.json`), 'utf8')) as JcsFixture;
}

function paddedBytes(hex: string, max: number): number[] {
  const buf = Buffer.from(hex, 'hex');
  if (buf.length > max) throw new Error(`${buf.length} > MAX ${max}`);
  const out = new Array<number>(max).fill(0);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i]!;
  return out;
}

describe('BindingParse (MAX_B = 1024)', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('binding/BindingParseTest.circom');
  });

  it('parses a Bcanon with EN declaration and a non-empty context', async () => {
    const f = loadFixture('en-with-context');
    expect(f.bcanonLength).to.be.lessThanOrEqual(MAX_B);
    const witness = await circuit.calculateWitness(
      {
        bytes: paddedBytes(f.bcanonHex, MAX_B),
        bcanonLen: f.bcanonLength,
        pkValueOffset: f.offsets.pk!,
        schemeValueOffset: f.offsets.scheme!,
      },
      true,
    );
    await circuit.checkConstraints(witness);
    // Outputs: pkBytes[65] starts at signal index 1.
    // Verify pk[0] == 0x04 (uncompressed prefix).
    expect(Number(witness[1])).to.equal(0x04);
  });

  it('parses a Bcanon with EN declaration and an empty context', async () => {
    const f = loadFixture('en-no-context');
    await circuit.calculateWitness(
      {
        bytes: paddedBytes(f.bcanonHex, MAX_B),
        bcanonLen: f.bcanonLength,
        pkValueOffset: f.offsets.pk!,
        schemeValueOffset: f.offsets.scheme!,
      },
      true,
    );
  });

  it('rejects a Bcanon where the supplied pk offset does not land after the "pk":" key', async () => {
    const f = loadFixture('en-with-context');
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          bytes: paddedBytes(f.bcanonHex, MAX_B),
          bcanonLen: f.bcanonLength,
          pkValueOffset: f.offsets.pk! + 5,
          schemeValueOffset: f.offsets.scheme!,
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a tampered scheme value (e.g. "secp256k0")', async () => {
    const f = loadFixture('en-with-context');
    const buf = Buffer.from(f.bcanonHex, 'hex');
    // The scheme value starts at offsets.scheme; replace the closing '1'
    // (9th character of "secp256k1") with '0'.
    buf[f.offsets.scheme! + 8] = 0x30;
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          bytes: paddedBytes(buf.toString('hex'), MAX_B),
          bcanonLen: f.bcanonLength,
          pkValueOffset: f.offsets.pk!,
          schemeValueOffset: f.offsets.scheme!,
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a tampered pk value (one nibble perturbed)', async () => {
    const f = loadFixture('en-with-context');
    const buf = Buffer.from(f.bcanonHex, 'hex');
    // Flip one nibble in the pk hex. pkValueOffset points at '0' of "0x04…";
    // index +5 is one of the '04' / payload chars. We accept either: the
    // witness will still calc but the pkBytes output bytes change. Stronger
    // failure mode: replace a hex digit with an invalid char like 'g'.
    buf[f.offsets.pk! + 5] = 0x67; // 'g' — not a hex char.
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          bytes: paddedBytes(buf.toString('hex'), MAX_B),
          bcanonLen: f.bcanonLength,
          pkValueOffset: f.offsets.pk!,
          schemeValueOffset: f.offsets.scheme!,
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw, 'invalid hex char in pk must fail').to.equal(true);
  });

  it('rejects a Bcanon length above MAX_B', async () => {
    const f = loadFixture('en-with-context');
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          bytes: paddedBytes(f.bcanonHex, MAX_B),
          bcanonLen: MAX_B + 1,
          pkValueOffset: f.offsets.pk!,
          schemeValueOffset: f.offsets.scheme!,
        },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
