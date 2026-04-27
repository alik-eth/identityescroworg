import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { renderSigil } from '../../src/lib/sigil';

describe('browser sigil renderer', () => {
  it('matches contract output for nullifier=0xDEADBEEF (parity test)', () => {
    const expected = readFileSync(
      'tests/fixtures/sigil-deadbeef.svg.txt',
      'utf8',
    ).trim();
    const got = renderSigil('0x' + '00'.repeat(28) + 'DEADBEEF');
    expect(got).toBe(expected);
  });

  it('is deterministic', () => {
    const n = '0x' + '00'.repeat(31) + 'AB';
    expect(renderSigil(n)).toBe(renderSigil(n));
  });

  it('differs by nullifier', () => {
    expect(renderSigil('0x' + '00'.repeat(31) + 'AB'))
      .not.toBe(renderSigil('0x' + '00'.repeat(31) + 'CD'));
  });
});
