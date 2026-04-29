import { defineConfig } from 'vitest/config';

// V5 split-runner convention:
// - vitest owns TS-only fast tests under `test/**/*.vitest.ts`.
// - mocha + circom_tester continues to own circuit tests under `test/**/*.test.ts`
//   (driven by the `test` npm script).
// The two extensions never overlap so each runner stays scoped to its files.
export default defineConfig({
    test: {
        environment: 'node',
        include: ['test/**/*.vitest.ts'],
    },
});
