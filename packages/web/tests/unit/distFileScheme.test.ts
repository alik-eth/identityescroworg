// Static guard: built dist/index.html must reference local assets with
// absolute paths (`/assets/...`). The SPA is served over HTTPS at a domain
// root with deep client-side routes (`/ua/cli`, etc.); under SPA fallback
// the browser would otherwise resolve `./assets/...` against the current
// path and the Caddy try_files would return index.html (text/html) for
// `/ua/assets/index-*.css` — fatal for styles + JS load.
//
// Skipped when dist/ is absent (the e2e workflow rebuilds before running).

import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const distHtml = resolve(here, '../../dist/index.html');

describe.skipIf(!existsSync(distHtml))('dist/ smoke (deep-route safety)', () => {
  it('references local assets with absolute paths starting with "/"', () => {
    const html = readFileSync(distHtml, 'utf8');
    const srcRefs = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map((m) => m[1] ?? '');
    const local = srcRefs.filter(
      (u) => !u.startsWith('http') && !u.startsWith('//') && !u.startsWith('data:'),
    );
    expect(local.length).toBeGreaterThan(0);
    for (const u of local) {
      expect(u, `asset ${u} must be absolute (relative breaks on deep routes)`).toMatch(
        /^\//,
      );
    }
  });
});
