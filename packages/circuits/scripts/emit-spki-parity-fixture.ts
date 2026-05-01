// Emits packages/circuits/../../fixtures/spki-commit/v5-parity.json — the
// cross-package parity reference for the V5 SpkiCommit construction
// (spec §0.2 / orchestration §2.2). Both contracts-eng's
// `P256Verify.spkiCommit` (Solidity) and flattener-eng's `spkiCommit.ts`
// (TypeScript) gate against the values in this file. If any of the three
// implementations diverges from this fixture, the trust-list Merkle gate
// breaks and the proof's `intSpkiCommit` won't match the on-chain leaf.
//
// Lead pumps the file to consumer worktrees per orchestration plan §6 after
// each regen.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { spkiCommit } from './spki-commit-ref';

const WORKTREE_ROOT = resolve(__dirname, '../../..');
const FIXTURE_PATH = resolve(WORKTREE_ROOT, 'fixtures/spki-commit/v5-parity.json');

interface SourceCase {
    label: string;
    description: string;
    path: string;
}

interface ParityCase {
    label: string;
    description: string;
    spki: string; // hex (no 0x prefix)
    expectedCommitDecimal: string; // bigint encoded as base-10 string
}

const SOURCES: SourceCase[] = [
    {
        label: 'admin-leaf-ecdsa',
        description: 'Real Diia admin leaf SPKI extracted from leaf.der.',
        path: resolve(
            WORKTREE_ROOT,
            'packages/circuits/fixtures/integration/admin-ecdsa/leaf-spki.bin',
        ),
    },
    {
        label: 'admin-intermediate-ecdsa',
        description: 'Synthetic Diia QTSP intermediate SPKI extracted from synth-intermediate.der.',
        path: resolve(
            WORKTREE_ROOT,
            'packages/circuits/fixtures/integration/admin-ecdsa/intermediate-spki.bin',
        ),
    },
];

async function main(): Promise<void> {
    const cases: ParityCase[] = [];
    for (const src of SOURCES) {
        const spki = readFileSync(src.path);
        if (spki.length !== 91) {
            throw new Error(`${src.label}: expected 91-byte SPKI, got ${spki.length} bytes`);
        }
        const commit = await spkiCommit(spki);
        cases.push({
            label: src.label,
            description: src.description,
            spki: spki.toString('hex'),
            expectedCommitDecimal: commit.toString(10),
        });
    }
    const out = {
        schema: 'v5-spki-commit-parity-1',
        description: 'Reference values for SpkiCommit() byte-equivalence parity tests.',
        generator: 'packages/circuits/scripts/spki-commit-ref.ts',
        poseidonReference: 'circomlibjs ^0.1.7 (BN254, iden3 params)',
        cases,
    };
    mkdirSync(dirname(FIXTURE_PATH), { recursive: true });
    writeFileSync(FIXTURE_PATH, `${JSON.stringify(out, null, 2)}\n`);
    console.log(`Wrote ${cases.length} cases to ${FIXTURE_PATH}`);
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
