import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import { extractIntSpki } from '../../src/ca/extractIntSpki.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = resolve(here, '../../fixtures');

describe('extractIntSpki', () => {
  test('extracts 91 bytes from an ECDSA-P256 cert DER', async () => {
    const certDer = await readFile(resolve(fixtures, 'certs/admin-leaf-ecdsa.der'));
    const spki = extractIntSpki(new Uint8Array(certDer));
    expect(spki.length).toBe(91);
    expect(spki[0]).toBe(0x30);
    expect(spki[1]).toBe(0x59);
  });

  test('rejects RSA SPKI', async () => {
    const rsaDer = await readFile(resolve(fixtures, 'certs/test-ca.der'));
    expect(() => extractIntSpki(new Uint8Array(rsaDer))).toThrow(/not ECDSA-P256/);
  });
});
