// Static guard: built dist/index.html must reference assets with relative
// URLs so it boots from the file:// scheme. This is the cheapest test that
// catches an accidental `base: '/'` regression in vite.config.ts.
//
// Skipped when dist/ is absent (the e2e workflow rebuilds before running).

import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const distHtml = resolve(here, '../../dist/index.html');

describe.skipIf(!existsSync(distHtml))('dist/ smoke (file:// safety)', () => {
  it('references assets with relative URLs (no leading "/")', () => {
    const html = readFileSync(distHtml, 'utf8');
    const srcRefs = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map((m) => m[1] ?? '');
    const local = srcRefs.filter(
      (u) => !u.startsWith('http') && !u.startsWith('//') && !u.startsWith('data:'),
    );
    expect(local.length).toBeGreaterThan(0);
    for (const u of local) {
      expect(u, `asset ${u} must NOT be absolute (would 404 under file://)`).not.toMatch(
        /^\//,
      );
    }
  });
});
