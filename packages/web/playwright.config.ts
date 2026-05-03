import { defineConfig } from '@playwright/test';

const REAL_PROVER = process.env.E2E_REAL_PROVER === '1';

// V5.4 T7 carve-out: when running ONLY the cli-flow project against a
// live `qkb serve` instance, the test does not navigate to the web app
// (its assertions are fetch-only against :9080). Skip the webServer
// startup in that mode so a transient web-build hiccup (e.g. the
// argon2-browser ESM-wasm issue tracked separately) doesn't block the
// real-CLI prove-pipeline check.
//
// Engaged explicitly via `PLAYWRIGHT_SKIP_WEB_SERVER=1`. T7's typical
// invocation:
//   T7_DEV_MANIFEST=/tmp/dev-manifest.json PLAYWRIGHT_SKIP_WEB_SERVER=1 \
//     pnpm -F @qkb/web exec playwright test --project=cli-flow
//
// The variable is intentionally separate from T7_DEV_MANIFEST so an
// operator running the full suite + cli-flow together (with the dev
// manifest set) doesn't accidentally drop the webServer for the
// non-cli-flow projects that DO need it.
const SKIP_WEB_SERVER = process.env.PLAYWRIGHT_SKIP_WEB_SERVER === '1';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: REAL_PROVER ? 20 * 60_000 : 30_000,
  fullyParallel: true,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'on-first-retry',
  },
  ...(SKIP_WEB_SERVER
    ? {}
    : {
        webServer: {
          command: 'pnpm run build && pnpm run preview',
          url: 'http://127.0.0.1:4173',
          reuseExistingServer: !process.env.CI,
          timeout: 180_000,
          env: {
            VITE_CHAIN: 'sepolia',
            VITE_WALLETCONNECT_PROJECT_ID: 'e2e-mock-walletconnect-project-id',
            // V5 prover artifacts ship post-§9.6 ceremony; until then the e2e
            // drives Step 4 through the mock-prover path. Real-prover E2E
            // becomes the §9.7 acceptance gate post-deploy.
            VITE_USE_MOCK_PROVER: '1',
          },
        },
      }),
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
      testMatch: /v5-(register-route|mint|flow|device-gating)\.spec\.ts/,
    },
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
      testMatch: /(landing|flow-happy|flow-already-minted|flow-deadline-expired|i18n|mobile|route-coverage)\.spec\.ts/,
    },
    {
      name: 'ceremony',
      use: { browserName: 'chromium' },
      testMatch: /ceremony\.spec\.ts/,
    },
    {
      // V5.4 T7 — opt-in via T7_DEV_MANIFEST env var. Spec
      // self-skips when unset, so this project is a no-op on
      // machines without the V5.2 stub artefacts.
      name: 'cli-flow',
      use: { browserName: 'chromium' },
      testMatch: /cli-flow\.spec\.ts/,
    },
  ],
});
