import { expect } from 'chai';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../../helpers/compile';

const FIXTURE_PATH = resolve(
  __dirname,
  '..',
  '..',
  '..',
  'fixtures',
  'dob',
  'ua',
  'diia-admin.der.txt',
);

describe('DobExtractorDiiaUA', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('dob/DobExtractorDiiaUATest.circom');
  });

  it('extracts DOB from a real Diia leaf cert (OID 2.5.29.9 present)', async () => {
    const derB64 = readFileSync(FIXTURE_PATH, 'utf8').trim();
    const der = Buffer.from(derB64, 'base64');
    const leafDER = [
      ...Array.from(der),
      ...Array(1536 - der.length).fill(0),
    ];

    const witness = await circuit.calculateWitness(
      { leafDER, leafDerLen: der.length },
      true,
    );
    await circuit.checkConstraints(witness);
    // Output order: dobYmd, sourceTag, dobSupported (witness[1..3]).
    expect(witness[3]).to.equal(1n); // dobSupported
    expect(witness[2]).to.equal(1n); // sourceTag = 1 (Diia UA)
    // Admin fixture (sha256 42e7dda…): PrintableString content "19990426-02970"
    // → first 8 ASCII digits = 19990426.
    expect(witness[1]).to.equal(19990426n); // dobYmd
  });

  it('extracts dobYmd from a synthetic Diia-shaped DER', async () => {
    // Craft a DER with the exact Diia SubjectDirectoryAttributes layout at
    // p0=0. Pins the offset arithmetic independently of the real fixture.
    const OUTER  = [0x06, 0x03, 0x55, 0x1d, 0x09];
    const WRAP   = [0x04, 0x24, 0x30, 0x22, 0x30, 0x20];
    const INNER  = [
      0x06, 0x0c, 0x2a, 0x86, 0x24, 0x02, 0x01, 0x01,
      0x01, 0x0b, 0x01, 0x04, 0x0b, 0x01,
    ];
    const SET    = [0x31, 0x10, 0x13, 0x0e];
    const DIGITS = [0x32, 0x30, 0x32, 0x35, 0x31, 0x32, 0x33, 0x31]; // "20251231"
    const TAIL   = [0x2d, 0x31, 0x32, 0x33, 0x34, 0x35];
    const der = [...OUTER, ...WRAP, ...INNER, ...SET, ...DIGITS, ...TAIL];
    const leafDER = [...der, ...Array(1536 - der.length).fill(0)];

    const witness = await circuit.calculateWitness(
      { leafDER, leafDerLen: der.length },
      true,
    );
    await circuit.checkConstraints(witness);
    expect(witness[3]).to.equal(1n);
    expect(witness[1]).to.equal(20251231n);
  });

  it('emits dobSupported=0 when OID 2.5.29.9 is absent', async () => {
    // Synthetic DER: 100 bytes of 0x42, no OID header sequence.
    const der = Array.from({ length: 100 }, () => 0x42);
    const leafDER = [...der, ...Array(1536 - der.length).fill(0)];
    const witness = await circuit.calculateWitness(
      { leafDER, leafDerLen: der.length },
      true,
    );
    await circuit.checkConstraints(witness);
    expect(witness[3]).to.equal(0n); // dobSupported
    expect(witness[1]).to.equal(0n); // dobYmd
  });

  it('emits dobSupported=0 when outer OID is present but inner attr OID is wrong', async () => {
    // Same layout as the synthetic test above, but inner OID bytes mangled so
    // the innerOidAllMatch gate must fire. Confirms dobSupported drops to 0
    // even when the 5-byte outer header is found.
    const OUTER  = [0x06, 0x03, 0x55, 0x1d, 0x09];
    const WRAP   = [0x04, 0x24, 0x30, 0x22, 0x30, 0x20];
    const INNER  = [
      0x06, 0x0c, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // wrong attr OID body
      0x01, 0x0b, 0x01, 0x04, 0x0b, 0x01,
    ];
    const SET    = [0x31, 0x10, 0x13, 0x0e];
    const DIGITS = [0x31, 0x39, 0x39, 0x39, 0x30, 0x34, 0x32, 0x36];
    const TAIL   = [0x2d, 0x30, 0x32, 0x39, 0x37, 0x30];
    const der = [...OUTER, ...WRAP, ...INNER, ...SET, ...DIGITS, ...TAIL];
    const leafDER = [...der, ...Array(1536 - der.length).fill(0)];

    const witness = await circuit.calculateWitness(
      { leafDER, leafDerLen: der.length },
      true,
    );
    await circuit.checkConstraints(witness);
    expect(witness[3]).to.equal(0n);
    expect(witness[1]).to.equal(0n);
  });

  it('emits dobSupported=0 when leafDerLen=0', async () => {
    const witness = await circuit.calculateWitness(
      { leafDER: Array(1536).fill(0), leafDerLen: 0 },
      true,
    );
    await circuit.checkConstraints(witness);
    expect(witness[3]).to.equal(0n);
    expect(witness[1]).to.equal(0n);
  });
});
