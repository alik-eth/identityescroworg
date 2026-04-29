import { defineConfig } from '@playwright/test';

const REAL_PROVER = process.env.E2E_REAL_PROVER === '1';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: REAL_PROVER ? 20 * 60_000 : 30_000,
  fullyParallel: true,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'on-first-retry',
  },
  webServer: {
    command: 'pnpm run build && pnpm run preview',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
    env: {
      VITE_CHAIN: 'sepolia',
      VITE_WALLETCONNECT_PROJECT_ID: 'e2e-mock-walletconnect-project-id',
    },
  },
  projects: [
    {
      name: 'smoke',
      testMatch: /smoke\.spec\.ts/,
    },
    {
      name: 'ua',
      testMatch: /ua-register\.spec\.ts/,
    },
    {
      name: 'ua-upload-real-diia',
      testMatch: /ua-upload-real-diia\.spec\.ts/,
    },
    {
      name: 'wasm-prover-benchmark',
      testMatch: /wasm-prover-benchmark\.spec\.ts/,
    },
    {
      name: 'v5',
      use: { browserName: 'chromium' },
      testMatch: /v5-(register-route|flow)\.spec\.ts/,
    },
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
      testMatch: /(landing|flow-happy|flow-already-minted|flow-deadline-expired|i18n|mobile)\.spec\.ts/,
    },
  ],
});
