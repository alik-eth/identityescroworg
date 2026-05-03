// Three-subdomain split per BRAND.md §Domains (locked 2026-05-03):
//
//   zkqes.org       (root)  — pre-ceremony hero + recruitment CTA. NO register flow.
//   app.zkqes.org           — register flow at /v5/registerV5 + /account/rotate. SPA.
//   docs.zkqes.org          — VitePress static (separate, see #61).
//
// `VITE_TARGET` controls which route subset is included in the SPA bundle:
//
//   VITE_TARGET=landing  → root + ceremony only (zkqes.org root)
//   VITE_TARGET=app      → full SPA including register + rotate (app.zkqes.org)
//   (unset)              → defaults to 'app' for backwards-compat with the
//                          existing pages.yml workflow that builds without
//                          the env var
//
// The two builds share the same source tree; the route tree in router.tsx
// is filtered by this constant. Routes that are excluded from a given
// target are also excluded from the bundle (TanStack Router doesn't
// pull components for unregistered routes; tree-shaking does the rest).
//
// Why a single shared source tree (instead of two repos / two SPAs):
// the civic-monumental theme primitives (PaperGrain, doc-grid, hr.rule,
// EB Garamond + Inter Tight) and the ceremony pages (status, contribute,
// verify) are reused unchanged on both surfaces. A separate landing repo
// would either duplicate the theme + ceremony components or ship a thin
// shell that re-imports from `packages/web` — neither pays for itself
// at this scale. One source tree, two filtered builds, one component
// library.

export type BuildTarget = 'landing' | 'app';

/**
 * **Direct property access on `import.meta.env.VITE_TARGET`** — load-
 * bearing for Vite's `define`-plugin substitution. Vite replaces the
 * exact source-text `import.meta.env.VITE_TARGET` with a string
 * literal at build time (e.g. `"landing"`); when terser/esbuild
 * minify, the comparison `"landing" === "landing"` folds to `true`,
 * and `IS_APP_TARGET`/`IS_LANDING_TARGET` become compile-time
 * constants. That's what lets the `IS_APP_TARGET ? [...] : []` dead
 * branch in `router.tsx` get eliminated, dropping the dynamic-
 * import expressions for the app-only routes from the landing
 * bundle.
 *
 * Earlier versions of this file used `(import.meta as any)?.env?.
 * VITE_TARGET` to satisfy strict TS without a separate `vite-env.d.ts`,
 * but the optional-chaining + `as any` cast prevented Vite's regex-
 * based substitution from matching the source text — the runtime
 * behaviour was correct, but the bundler kept both branches alive
 * and the landing entry chunk shipped the app-only screens. Now
 * resolved with `vite-env.d.ts` typing the env var (see
 * `src/vite-env.d.ts`) so direct access type-checks cleanly.
 */
const RAW_TARGET: string = import.meta.env.VITE_TARGET ?? 'app';

/** Validate at module-load time so a typo in the env var fails fast at
 *  build/startup rather than producing a silently-wrong route tree. */
function asBuildTarget(s: string): BuildTarget {
  if (s === 'landing' || s === 'app') return s;
  throw new Error(
    `VITE_TARGET must be 'landing' or 'app'; got ${JSON.stringify(s)}. ` +
      'See packages/web/src/lib/buildTarget.ts for context.',
  );
}

export const BUILD_TARGET: BuildTarget = asBuildTarget(RAW_TARGET);

/** Convenience: route registration guards. Slightly more readable at
 *  call sites than `BUILD_TARGET === 'app'`. */
export const IS_APP_TARGET: boolean = BUILD_TARGET === 'app';
export const IS_LANDING_TARGET: boolean = BUILD_TARGET === 'landing';
