import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { expect } from 'chai';

import {
    decomposeTo643Limbs,
    parseP256Spki,
} from '../../scripts/spki-commit-ref';
import { compile, type CompiledCircuit } from '../helpers/compile';

// V5 spec §0.2 cross-impl parity gate. The TS reference impl
// (scripts/spki-commit-ref.ts), the Solidity impl
// (arch-contracts/src/lib/P256Verify.sol), and this circom template all
// must produce the same Poseidon₂(Poseidon₆(xLimbs), Poseidon₆(yLimbs))
// for the same SPKI bytes. The lead-pumped fixture pins the canonical
// expected values per case.
const PARITY_FIXTURE_PATH = resolve(
    __dirname,
    '..',
    '..',
    '..',
    '..',
    'fixtures',
    'spki-commit',
    'v5-parity.json',
);

interface ParityCase {
    label: string;
    description: string;
    spki: string; // hex
    expectedCommitDecimal: string;
}

interface ParityFixture {
    schema: string;
    cases: ParityCase[];
}

const COMMIT_OUT = 1; // witness[1] = first output (commit)

function loadParityCases(): ParityCase[] {
    const fixture = JSON.parse(
        readFileSync(PARITY_FIXTURE_PATH, 'utf8'),
    ) as ParityFixture;
    expect(fixture.schema).to.equal('v5-spki-commit-parity-1');
    expect(fixture.cases.length).to.be.greaterThanOrEqual(2);
    return fixture.cases;
}

describe('SpkiCommit (circom template)', function () {
    this.timeout(600000);

    let circuit: CompiledCircuit;
    let cases: ParityCase[];

    before(async () => {
        circuit = await compile('primitives/SpkiCommitTest.circom');
        cases = loadParityCases();
    });

    it('matches the TS / Solidity parity fixture for every SPKI case', async () => {
        for (const c of cases) {
            const spki = Buffer.from(c.spki, 'hex');
            const { x, y } = parseP256Spki(spki);
            const xLimbs = decomposeTo643Limbs(x);
            const yLimbs = decomposeTo643Limbs(y);
            const witness = await circuit.calculateWitness(
                {
                    xLimbs: xLimbs.map((l) => l.toString()),
                    yLimbs: yLimbs.map((l) => l.toString()),
                },
                true,
            );
            await circuit.checkConstraints(witness);
            const got = witness[COMMIT_OUT];
            expect(
                got?.toString(10),
                `SpkiCommit case "${c.label}" diverged from parity fixture`,
            ).to.equal(c.expectedCommitDecimal);
        }
    });

    it('all-zero limbs produce a deterministic non-zero commit', async () => {
        const witness = await circuit.calculateWitness(
            {
                xLimbs: ['0', '0', '0', '0', '0', '0'],
                yLimbs: ['0', '0', '0', '0', '0', '0'],
            },
            true,
        );
        await circuit.checkConstraints(witness);
        // Poseidon of all-zero inputs is a fixed non-zero value (Poseidon
        // is not the identity on the zero vector). Just assert the commit
        // is well-defined and not 0n — pinning the exact value is not the
        // point of this case; the parity case above pins real values.
        const got = witness[COMMIT_OUT];
        expect(got).to.not.equal(undefined);
        expect(got).to.not.equal(0n);
    });
});
