# @qkb/web

Static SPA for Qualified Key Binding (QKB). Pure client-side: keygen, JCS
canonicalization, CAdES parse, off-circuit QES verify, Groth16 prove (Web
Worker), bundle, and on-chain `register()` via the user's wallet.

## Build & run

```sh
pnpm --filter @qkb/web dev          # vite dev server, http://localhost:5173
pnpm --filter @qkb/web build        # type-check + production bundle into dist/
pnpm --filter @qkb/web preview      # vite preview, http://127.0.0.1:4173
pnpm --filter @qkb/web test         # vitest unit tests
pnpm --filter @qkb/web exec playwright test --project=smoke
```

## file:// distribution

`vite.config.ts` sets `base: './'` so the production build references all
assets relatively. After `pnpm build` you can double-click
`dist/index.html` (or `xdg-open dist/index.html`) and the SPA boots without
a server. The `dist/ smoke (file:// safety)` vitest guard fails the build
if anyone accidentally reverts that.

To package a release tarball:

```sh
pnpm --filter @qkb/web package
# → packages/web/release/qkb-web-<short-sha>.tar.gz
```

The tarball contains the full `dist/` tree; extract anywhere and open
`dist/index.html` from disk.

## Real-prover nightly E2E

`tests/e2e/happy-path.spec.ts` includes a `real-prover` suite that runs the
full circuit end-to-end. It is gated on `E2E_REAL_PROVER=1` so it stays
out of normal PR runs (snarkjs proofs take 3–10 minutes on commodity
hardware). Run locally with:

```sh
E2E_REAL_PROVER=1 pnpm --filter @qkb/web exec playwright test
```

CI runs it nightly via `.github/workflows/nightly-web-e2e.yml`.
