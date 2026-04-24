import { defineConfig } from '@playwright/test';

const REAL_PROVER = process.env.E2E_REAL_PROVER === '1';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: REAL_PROVER ? 20 * 60_000 : 30_000,
  fullyParallel: true,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:4173',
  },
  webServer: {
    command: 'pnpm run build && pnpm run preview',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
  projects: [
    {
      name: 'smoke',
      testMatch: /smoke\.spec\.ts/,
    },
    {
      name: 'flow',
      testMatch: /flow\.spec\.ts/,
    },
    {
      name: 'real-prover',
      testMatch: /happy-path\.spec\.ts/,
    },
    {
      name: 'real-qes',
      testMatch: /real-qes\.spec\.ts/,
    },
  ],
});
