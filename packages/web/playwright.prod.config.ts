import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  testMatch: /prod-smoke\.spec\.ts/,
  timeout: 60_000,
  fullyParallel: false,
  reporter: 'list',
  retries: 1,
  use: {
    trace: 'retain-on-failure',
    // Per-test viewports come from describe blocks in the spec
    // (desktop 1440x900, tablet 768x1024, mobile 390x844).
    // No global viewport here — let the spec drive it.
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
});
