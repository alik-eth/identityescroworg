import { expect } from 'chai';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';
import { rightPadZero } from '../helpers/shaPad';

interface DiiaFixture {
  derPath: string;
  derLength: number;
  serialNumberValue: {
    contentOffset: number;
    contentLength: number;
    asciiValue: string;
    hexValue: string;
    limbsLE64: string[];
  };
}

const fixtureDir = resolve(__dirname, '..', '..', 'fixtures', 'x509-samples');
const fixture = JSON.parse(
  readFileSync(resolve(fixtureDir, 'subject-serial-diia.fixture.json'), 'utf8'),
) as DiiaFixture;
const derPath = resolve(fixtureDir, fixture.derPath);
const MAX_CERT = 2048;

function derBytes(): number[] {
  const raw = readFileSync(derPath);
  expect(raw.length).to.equal(fixture.derLength);
  return rightPadZero(new Uint8Array(raw), MAX_CERT);
}

describe('X509SubjectSerial (MAX_CERT = 2048)', function () {
  this.timeout(600000);

  let circuit: CompiledCircuit;
  before(async () => {
    circuit = await compile('primitives/X509SubjectSerialTest.circom');
  });

  it('extracts Diia РНОКПП "TINUA-3627506575" at the pinned offset', async () => {
    const leafDER = derBytes();
    const witness = await circuit.calculateWitness(
      {
        leafDER,
        subjectSerialValueOffset: fixture.serialNumberValue.contentOffset,
        subjectSerialValueLength: fixture.serialNumberValue.contentLength,
      },
      true,
    );
    await circuit.checkConstraints(witness);

    // Outputs precede inputs in circom-tester witness layout: witness[0]=1,
    // witness[1..4] = subjectSerialLimbs[0..3].
    for (let l = 0; l < 4; l++) {
      expect(witness[1 + l]).to.equal(BigInt(fixture.serialNumberValue.limbsLE64[l]!));
    }
  });

  it('rejects a wrong offset (byte-range or mismatch detected elsewhere)', async () => {
    const leafDER = derBytes();
    // Offset shifted by 1 → still extracts 16 bytes but they no longer match
    // the fixture limbs. We don't assert constraint failure (length still ≤32,
    // bytes still 0..255), only that the output limbs differ — which is what
    // the outer circuit's nullifier-binding proof relies on.
    const witness = await circuit.calculateWitness(
      {
        leafDER,
        subjectSerialValueOffset: fixture.serialNumberValue.contentOffset + 1,
        subjectSerialValueLength: fixture.serialNumberValue.contentLength,
      },
      true,
    );
    await circuit.checkConstraints(witness);
    let any = false;
    for (let l = 0; l < 4; l++) {
      if (witness[1 + l] !== BigInt(fixture.serialNumberValue.limbsLE64[l]!)) {
        any = true;
        break;
      }
    }
    expect(any).to.equal(true);
  });

  it('zero-pads when length < 32 (limbs [2],[3] = 0 for 16-byte serial)', async () => {
    const leafDER = derBytes();
    const witness = await circuit.calculateWitness(
      {
        leafDER,
        subjectSerialValueOffset: fixture.serialNumberValue.contentOffset,
        subjectSerialValueLength: fixture.serialNumberValue.contentLength,
      },
      true,
    );
    // 16-byte serial → limb[2] and limb[3] are zero irrespective of what the
    // DER bytes at contentOffset+16..+32 happen to be.
    expect(witness[3]).to.equal(0n);
    expect(witness[4]).to.equal(0n);
  });

  it('rejects length = 0 (empty-serial collision universe)', async () => {
    const leafDER = derBytes();
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          leafDER,
          subjectSerialValueOffset: fixture.serialNumberValue.contentOffset,
          subjectSerialValueLength: 0,
        },
        true,
      );
    } catch (err) {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects length > 32 (would truncate into colliding limbs)', async () => {
    const leafDER = derBytes();
    let threw = false;
    try {
      await circuit.calculateWitness(
        {
          leafDER,
          subjectSerialValueOffset: fixture.serialNumberValue.contentOffset,
          subjectSerialValueLength: 33,
        },
        true,
      );
    } catch (err) {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
