import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

// Worktree-local path. Lead pumps to contracts-eng + flattener-eng worktrees
// post-merge per orchestration plan §6 (the fixture's "produced by circuits-
// eng" status was scaffolded in 78e5dff).
const FIXTURE_PATH = resolve(__dirname, '../../../fixtures/spki-commit/v5-parity.json');

interface ParityCase {
    label: string;
    description: string;
    spki: string;
    expectedCommitDecimal: string;
}

interface ParityFixture {
    schema: string;
    description: string;
    generator: string;
    poseidonReference: string;
    cases: ParityCase[];
}

describe('SpkiCommit parity fixture', () => {
    it('exists and parses', () => {
        expect(existsSync(FIXTURE_PATH)).toBe(true);
        const json = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as ParityFixture;
        expect(json).toHaveProperty('cases');
        expect(json.cases.length).toBeGreaterThanOrEqual(2); // leaf + intermediate
    });

    it('every case has spki-hex and expected-commit-decimal', () => {
        const json = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as ParityFixture;
        for (const c of json.cases) {
            expect(c).toHaveProperty('label');
            expect(c).toHaveProperty('spki');
            expect(c).toHaveProperty('expectedCommitDecimal');
            expect(typeof c.spki).toBe('string');
            expect(c.spki).toMatch(/^[0-9a-f]+$/);
            expect(typeof c.expectedCommitDecimal).toBe('string');
        }
    });

    it('top-level schema metadata is present', () => {
        const json = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as ParityFixture;
        expect(json.schema).toBe('v5-spki-commit-parity-1');
        expect(json.generator).toMatch(/spki-commit-ref/);
        expect(json.poseidonReference).toMatch(/circomlibjs/);
    });
});
