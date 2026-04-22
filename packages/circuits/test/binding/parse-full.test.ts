import { expect } from 'chai';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';

interface JcsFixture {
  bcanonHex: string;
  bcanonLength: number;
  offsets: Record<string, number>;
  declarationBytesHex: string;
  declarationBytesLength: number;
}

const fixturesDir = resolve(__dirname, '..', '..', 'fixtures', 'jcs-bindings');
const MAX_B = 2048;
const MAX_CTX = 256;
const MAX_DECL = 1024;
const MAX_TS = 20;

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

// Scan the number of hex chars after the "0x" prefix at `ctxOffset`
// (terminated by the closing JSON quote 0x22).
function computeCtxHexLen(bcanonHex: string, ctxOffset: number): number {
  const h = Buffer.from(bcanonHex, 'hex');
  let i = ctxOffset + 2;
  let n = 0;
  while (h[i] !== 0x22) {
    n++;
    i++;
  }
  return n;
}

// Scan consecutive decimal digits at `tsOffset`.
function computeTsDigitCount(bcanonHex: string, tsOffset: number): number {
  const h = Buffer.from(bcanonHex, 'hex');
  let n = 0;
  while (h[tsOffset + n]! >= 0x30 && h[tsOffset + n]! <= 0x39) n++;
  return n;
}

function buildInput(f: JcsFixture): Record<string, unknown> {
  return {
    bytes: paddedBytes(f.bcanonHex, MAX_B),
    bcanonLen: f.bcanonLength,
    pkValueOffset: f.offsets.pk!,
    schemeValueOffset: f.offsets.scheme!,
    ctxValueOffset: f.offsets.context!,
    ctxHexLen: computeCtxHexLen(f.bcanonHex, f.offsets.context!),
    declValueOffset: f.offsets.declaration!,
    declValueLen: f.declarationBytesLength,
    tsValueOffset: f.offsets.timestamp!,
    tsDigitCount: computeTsDigitCount(f.bcanonHex, f.offsets.timestamp!),
  };
}

describe(`BindingParseFull (MAX_B=${MAX_B}, CTX=${MAX_CTX}, DECL=${MAX_DECL}, TS=${MAX_TS})`, function () {
  this.timeout(900000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('binding/BindingParseFullTest.circom');
  });

  it('parses en-with-context (8-byte context, 510-byte decl, 10-digit ts)', async () => {
    const f = loadFixture('en-with-context');
    const w = await circuit.calculateWitness(buildInput(f), true);
    await circuit.checkConstraints(w);
    // Outputs begin at witness index 1. pkBytes[0] is the first output.
    expect(Number(w[1])).to.equal(0x04);
  });

  it('parses en-no-context (empty context → "0x" literal)', async () => {
    const f = loadFixture('en-no-context');
    const w = await circuit.calculateWitness(buildInput(f), true);
    await circuit.checkConstraints(w);
  });

  it('parses uk-with-context (583-byte declaration)', async () => {
    const f = loadFixture('uk-with-context');
    const w = await circuit.calculateWitness(buildInput(f), true);
    await circuit.checkConstraints(w);
  });

  it('rejects a shifted declValueOffset (fails the "declaration":" key match)', async () => {
    const f = loadFixture('en-with-context');
    const input = buildInput(f);
    input.declValueOffset = (input.declValueOffset as number) + 1;
    let threw = false;
    try {
      await circuit.calculateWitness(input, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a tampered scheme value (9th char flipped)', async () => {
    const f = loadFixture('en-with-context');
    const buf = Buffer.from(f.bcanonHex, 'hex');
    buf[f.offsets.scheme! + 8] = 0x30; // "secp256k1" → "secp256k0"
    const input = buildInput(f);
    input.bytes = paddedBytes(buf.toString('hex'), MAX_B);
    let threw = false;
    try {
      await circuit.calculateWitness(input, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects odd ctxHexLen (even-bit constraint)', async () => {
    const f = loadFixture('en-with-context');
    const input = buildInput(f);
    input.ctxHexLen = 7;
    let threw = false;
    try {
      await circuit.calculateWitness(input, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects tsDigitCount=0 (DecimalAsciiToUint64 requires ≥1 digit)', async () => {
    const f = loadFixture('en-with-context');
    const input = buildInput(f);
    input.tsDigitCount = 0;
    let threw = false;
    try {
      await circuit.calculateWitness(input, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects declValueLen > MAX_DECL', async () => {
    const f = loadFixture('en-with-context');
    const input = buildInput(f);
    input.declValueLen = MAX_DECL + 1;
    let threw = false;
    try {
      await circuit.calculateWitness(input, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
