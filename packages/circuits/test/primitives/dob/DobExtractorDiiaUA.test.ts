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
      ...Array(2048 - der.length).fill(0),
    ];

    const witness = await circuit.calculateWitness(
      { leafDER, leafDerLen: der.length },
      true,
    );
    await circuit.checkConstraints(witness);
    // Output order: dobYmd, sourceTag, dobSupported (witness[1..3]).
    // NOTE: dobYmd extraction deferred to task M2.3b (see plan §M2.3b);
    // the current stub only asserts the OID header is present.
    expect(witness[3]).to.equal(1n); // dobSupported
    expect(witness[2]).to.equal(1n); // sourceTag = 1 (Diia UA)
    expect(witness[1]).to.equal(0n); // dobYmd = 0 until M2.3b
  });

  it('emits dobSupported=0 when OID 2.5.29.9 is absent', async () => {
    // Synthetic DER: 100 bytes of 0x42, no OID header sequence.
    const der = Array.from({ length: 100 }, () => 0x42);
    const leafDER = [...der, ...Array(2048 - der.length).fill(0)];
    const witness = await circuit.calculateWitness(
      { leafDER, leafDerLen: der.length },
      true,
    );
    await circuit.checkConstraints(witness);
    expect(witness[3]).to.equal(0n); // dobSupported
    expect(witness[1]).to.equal(0n); // dobYmd
  });

  it('emits dobSupported=0 when leafDerLen=0', async () => {
    const witness = await circuit.calculateWitness(
      { leafDER: Array(2048).fill(0), leafDerLen: 0 },
      true,
    );
    await circuit.checkConstraints(witness);
    expect(witness[3]).to.equal(0n);
    expect(witness[1]).to.equal(0n);
  });
});
