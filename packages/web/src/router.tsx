import {
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
  type AnyRoute,
  Outlet,
} from '@tanstack/react-router';
// `IS_APP_TARGET` constant from `./lib/buildTarget` is fine for runtime
// checks but is NOT used here as the dead-branch guard: Rollup processes
// the module graph (registering dynamic imports as chunks) BEFORE
// terser/esbuild do constant folding. So even if `IS_APP_TARGET === false`
// folds to `false` post-Rollup, the dynamic imports inside the dead
// `[...]` branch have already been added to the chunk graph by then.
//
// Inlining `import.meta.env.VITE_TARGET === 'app'` at the comparison
// site lets Vite's `define` plugin substitute the literal string at
// source-text time, so Rollup itself sees `"landing" === "app"` (or
// `"app" === "app"`) when parsing the AST — and DOES constant-fold
// before module-graph processing. With the branch literally
// `false ? [...] : []`, the `[...]` is never parsed, the dynamic
// imports never enter the chunk graph, and the landing entry chunk
// drops by ~4 MB.
//
// The comparison string is duplicated between buildTarget.ts and
// here; if a third call site emerges, factor through a build-time
// macro (`vite-plugin-replace` or a custom transform), not a runtime
// const.
import { IndexScreen } from './routes/index';
import { IntegrationsScreen } from './routes/integrations';
import { CeremonyIndex } from './routes/ceremony/index';
import { CeremonyContribute } from './routes/ceremony/contribute';
import { CeremonyStatus } from './routes/ceremony/status';
import { CeremonyVerify } from './routes/ceremony/verify';

function RootLayout() {
  return <Outlet />;
}

const rootRoute = createRootRoute({ component: RootLayout });

// ---------------------------------------------------------------- //
// Shared routes — present on BOTH `landing` and `app` targets.     //
// Static imports OK because both builds need these routes.         //
// ---------------------------------------------------------------- //
// IndexScreen itself is target-aware: it renders the pre-ceremony
// hero on the landing target (zkqes.org root) and the existing
// register-flow landing on the app target (app.zkqes.org). See
// `routes/index.tsx`.

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: IndexScreen,
});

const ceremonyRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/ceremony',
  component: CeremonyIndex,
});

const ceremonyContributeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/ceremony/contribute',
  component: CeremonyContribute,
});

const ceremonyStatusRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/ceremony/status',
  component: CeremonyStatus,
});

const ceremonyVerifyRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/ceremony/verify',
  component: CeremonyVerify,
});

const integrationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/integrations',
  component: IntegrationsScreen,
});

const sharedRoutes: AnyRoute[] = [
  indexRoute,
  ceremonyRoute,
  ceremonyContributeRoute,
  ceremonyStatusRoute,
  ceremonyVerifyRoute,
  integrationsRoute,
];

// ---------------------------------------------------------------- //
// App-only routes — register + rotate flow + UA mint pipeline.     //
// Excluded from `landing` builds per BRAND.md §Domains.            //
//                                                                   //
// **Lazy-loaded via `lazyRouteComponent`** — converts the static     //
// imports to dynamic ones so the heavy app deps (wagmi, metamask    //
// SDK, snarkjs, the V5 prover worker, the SDK's witness builder)    //
// don't anchor into the landing bundle. The dynamic imports live    //
// inside the `IS_APP_TARGET ? ... : []` branch; with                 //
// `IS_APP_TARGET === false` becoming a compile-time constant after  //
// Vite's env replacement, terser/esbuild eliminates the dead         //
// branch and the dynamic imports are never emitted. Verified         //
// empirically — landing build drops from ~13 MB (C2) to a small      //
// fraction (C3 commit footer reports the exact delta).               //
//                                                                   //
// Adding a new route to this set: just append another entry. Adding  //
// a new SHARED route (visible on both targets): add to               //
// `sharedRoutes` above instead, with a static import.                //
// ---------------------------------------------------------------- //

// Negated check so the default (env var unset) keeps the app routes
// — preserves the existing pages.yml workflow's behaviour, which
// builds without setting VITE_TARGET. Only an explicit
// `VITE_TARGET=landing` drops the app routes.
const appOnlyRoutes: AnyRoute[] = import.meta.env.VITE_TARGET !== 'landing'
  ? [
      createRoute({
        getParentRoute: () => rootRoute,
        path: '/ua/cli',
        component: lazyRouteComponent(
          () => import('./routes/ua/cli'),
          'CliInstall',
        ),
      }),
      createRoute({
        getParentRoute: () => rootRoute,
        path: '/ua/submit',
        component: lazyRouteComponent(
          () => import('./routes/ua/submit'),
          'SubmitScreen',
        ),
      }),
      createRoute({
        getParentRoute: () => rootRoute,
        path: '/ua/mint',
        component: lazyRouteComponent(
          () => import('./routes/ua/mint'),
          'MintScreen',
        ),
      }),
      createRoute({
        getParentRoute: () => rootRoute,
        path: '/ua/registerV5',
        component: lazyRouteComponent(
          () => import('./routes/ua/registerV5'),
          'RegisterV5Screen',
        ),
      }),
      createRoute({
        getParentRoute: () => rootRoute,
        path: '/ua/mintNft',
        component: lazyRouteComponent(
          () => import('./routes/ua/mintNft'),
          'MintNftScreen',
        ),
      }),
      createRoute({
        getParentRoute: () => rootRoute,
        path: '/ua/use-desktop',
        component: lazyRouteComponent(
          () => import('./routes/ua/useDesktop'),
          'UseDesktopScreen',
        ),
      }),
      createRoute({
        getParentRoute: () => rootRoute,
        path: '/account/rotate',
        component: lazyRouteComponent(
          () => import('./routes/account/rotate'),
          'AccountRotateScreen',
        ),
      }),
    ]
  : [];

const routeTree = rootRoute.addChildren([...sharedRoutes, ...appOnlyRoutes]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
