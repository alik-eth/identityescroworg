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

## Fly.io deployment

The static SPA is deployed to Fly.io app **`identityescrow`** (production
domain: `identityescrow.org`). Container is `caddy:2-alpine` serving the
built `dist/` on port 8080 with SPA fallback (`try_files {path} /index.html`)
so TanStack Router deep-link reloads work.

First-time setup (once per Fly account):

```sh
flyctl auth login
flyctl launch --no-deploy --name identityescrow --copy-config --config packages/web/fly.toml
```

Day-to-day deploy from a clean monorepo checkout:

```sh
pnpm deploy:fly                                 # from repo root
# or
pnpm --filter @qkb/web run deploy:fly           # from packages/web
```

Both invoke `flyctl deploy --config packages/web/fly.toml --dockerfile
packages/web/Dockerfile` against the monorepo root as the docker build
context (so the multi-stage Dockerfile can `COPY package.json
pnpm-workspace.yaml packages/web ...`). The root `.dockerignore` keeps the
context lean — only `packages/web`, `fixtures`, and the workspace
manifests are sent.

CI: `.github/workflows/deploy-web.yml` runs `flyctl deploy --remote-only`
on `workflow_dispatch`. The workflow needs a repo secret `FLY_API_TOKEN`
(`flyctl auth token` then add via `gh secret set FLY_API_TOKEN`).

Custom domain (one-time, after the app is deployed):

```sh
flyctl certs add identityescrow.org
flyctl certs add www.identityescrow.org
```

Then point your DNS at the values printed by `flyctl certs show
identityescrow.org`.

Local container smoke test (no Fly account needed):

```sh
docker build -f packages/web/Dockerfile -t qkb-web:dev .
docker run --rm -p 8080:8080 qkb-web:dev
# open http://localhost:8080
```
