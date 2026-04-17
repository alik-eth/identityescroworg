import { expect } from 'chai';
import { compile, type CompiledCircuit } from '../helpers/compile';

const MAX_DIGITS = 20;

function asciiPadded(s: string): { ascii: number[]; numDigits: number } {
  const ascii = new Array<number>(MAX_DIGITS).fill(0);
  for (let i = 0; i < s.length; i++) ascii[i] = s.charCodeAt(i);
  return { ascii, numDigits: s.length };
}

describe('DecimalAsciiToUint64 (MAX_DIGITS = 20)', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('binding/DecimalAsciiToUint64Test.circom');
  });

  const positiveCases: Array<{ label: string; s: string; expected: bigint }> = [
    { label: '"0"', s: '0', expected: 0n },
    { label: '"7"', s: '7', expected: 7n },
    { label: '"42"', s: '42', expected: 42n },
    { label: '"1776390649" (admin binding ts)', s: '1776390649', expected: 1776390649n },
    { label: '"9999999999"', s: '9999999999', expected: 9999999999n },
    { label: '"18446744073709551615" (uint64 max)', s: '18446744073709551615', expected: 18446744073709551615n },
  ];

  for (const tc of positiveCases) {
    it(`parses ${tc.label}`, async () => {
      const { ascii, numDigits } = asciiPadded(tc.s);
      const witness = await circuit.calculateWitness(
        { ascii: ascii.map(String), numDigits: String(numDigits) },
        true,
      );
      await circuit.checkConstraints(witness);
      expect(witness[1]).to.equal(tc.expected);
    });
  }

  it('rejects empty input (numDigits = 0)', async () => {
    const ascii = new Array<number>(MAX_DIGITS).fill(0);
    let threw = false;
    try {
      await circuit.calculateWitness({ ascii: ascii.map(String), numDigits: '0' }, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects leading zero ("042")', async () => {
    const { ascii, numDigits } = asciiPadded('042');
    let threw = false;
    try {
      await circuit.calculateWitness(
        { ascii: ascii.map(String), numDigits: String(numDigits) },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects non-digit byte ("1A")', async () => {
    const { ascii, numDigits } = asciiPadded('1A');
    let threw = false;
    try {
      await circuit.calculateWitness(
        { ascii: ascii.map(String), numDigits: String(numDigits) },
        true,
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects numDigits > MAX_DIGITS', async () => {
    const ascii = new Array<number>(MAX_DIGITS).fill(0x31); // all '1'
    let threw = false;
    try {
      await circuit.calculateWitness({ ascii: ascii.map(String), numDigits: String(MAX_DIGITS + 1) }, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
