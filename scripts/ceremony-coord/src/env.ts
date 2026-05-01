// .env loader that walks up from the calling script to find the nearest
// .env file. Prefers `scripts/ceremony-coord/.env` (per-tool config) but
// falls back to the repo-root `.env` so admin creds shared with the rest
// of the project (R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY,
// R2_BUCKET, R2_PUBLIC_BASE_URL) work without duplication.
//
// Why a walker, not just `import 'dotenv/config'`:
// dotenv's default behaviour reads `process.cwd()/.env`, which is the
// ceremony-coord directory when scripts are invoked from there — so the
// repo-root .env is invisible. Walking up handles either layout.

import { config as dotenvConfig } from 'dotenv';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

export function loadEnvFromAncestors(startDir: string): string | null {
  let dir = resolve(startDir);
  while (true) {
    const candidate = join(dir, '.env');
    if (existsSync(candidate)) {
      dotenvConfig({ path: candidate });
      return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) return null; // hit filesystem root, stop
    dir = parent;
  }
}
