import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import { parseLotl, type LotlPointer } from '../../src/fetch/lotl.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(here, '../../fixtures/lotl-mini.xml');

describe('parseLotl', () => {
  test('extracts MS pointers from LOTL xml', async () => {
    const xml = await readFile(fixturePath, 'utf8');
    const pointers: LotlPointer[] = parseLotl(xml);
    expect(pointers).toHaveLength(2);
    expect(pointers.map((p) => p.territory).sort()).toEqual(['EE', 'PL']);
    expect(pointers[0]!.location).toBe('ms-tl-ee.xml');
  });

  test('throws on malformed xml', () => {
    expect(() => parseLotl('<not-lotl/>')).toThrow(/not a LOTL/);
  });
});
