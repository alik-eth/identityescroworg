import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import { parseMsTl, type RawService } from '../../src/fetch/msTl.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(here, '../../fixtures/ms-tl-ee.xml');

describe('parseMsTl', () => {
  test('returns one RawService per TSPService with decoded certs', async () => {
    const xml = await readFile(fixturePath, 'utf8');
    const services: RawService[] = parseMsTl(xml);
    expect(services).toHaveLength(2);
    const caQc = services.find((s) => s.serviceTypeIdentifier.endsWith('CA/QC'));
    const other = services.find((s) => s.serviceTypeIdentifier.endsWith('unspecified'));
    expect(caQc).toBeDefined();
    expect(other).toBeDefined();
    expect(caQc!.status).toMatch(/granted$/);
    expect(caQc!.x509CertificateList).toHaveLength(1);
    expect(caQc!.x509CertificateList[0]).toBeInstanceOf(Uint8Array);
    expect(caQc!.x509CertificateList[0]!.length).toBeGreaterThan(0);
    expect(typeof caQc!.statusStartingTime).toBe('number');
    expect(caQc!.statusStartingTime).toBeGreaterThan(1_500_000_000);
  });

  test('throws on xml that is not an MS TL', () => {
    expect(() => parseMsTl('<not-tsl/>')).toThrow(/not a Member State/);
  });
});
