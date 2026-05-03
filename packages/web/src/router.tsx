import {
  createRootRoute,
  createRoute,
  createRouter,
  type AnyRoute,
  Outlet,
} from '@tanstack/react-router';
import { IS_APP_TARGET } from './lib/buildTarget';
import { IndexScreen } from './routes/index';
import { CliInstall } from './routes/ua/cli';
import { SubmitScreen } from './routes/ua/submit';
import { MintScreen } from './routes/ua/mint';
import { MintNftScreen } from './routes/ua/mintNft';
import { RegisterV5Screen } from './routes/ua/registerV5';
import { UseDesktopScreen } from './routes/ua/useDesktop';
import { IntegrationsScreen } from './routes/integrations';
import { CeremonyIndex } from './routes/ceremony/index';
import { CeremonyContribute } from './routes/ceremony/contribute';
import { CeremonyStatus } from './routes/ceremony/status';
import { CeremonyVerify } from './routes/ceremony/verify';
import { AccountRotateScreen } from './routes/account/rotate';

function RootLayout() {
  return <Outlet />;
}

const rootRoute = createRootRoute({ component: RootLayout });

// ---------------------------------------------------------------- //
// Shared routes — present on BOTH `landing` and `app` targets.     //
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

// ---------------------------------------------------------------- //
// App-only routes — register + rotate flow + UA mint pipeline.     //
// Excluded from `landing` builds per BRAND.md §Domains: zkqes.org  //
// root surfaces ceremony recruitment ONLY; the register flow lives //
// at app.zkqes.org. Adding any of these routes to a `landing` build //
// is a brand-decision regression — surface to lead before expanding //
// the conditional set.                                              //
// ---------------------------------------------------------------- //

const cliRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/ua/cli',
  component: CliInstall,
});

const submitRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/ua/submit',
  component: SubmitScreen,
});

const mintRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/ua/mint',
  component: MintScreen,
});

const registerV5Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/ua/registerV5',
  component: RegisterV5Screen,
});

const mintNftRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/ua/mintNft',
  component: MintNftScreen,
});

const useDesktopRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/ua/use-desktop',
  component: UseDesktopScreen,
});

const accountRotateRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/account/rotate',
  component: AccountRotateScreen,
});

// Filter the route tree by build target. Tree-shaking eliminates the
// component imports for the excluded routes from the final bundle on
// the landing target — verified via `pnpm -F @qkb/web build` for the
// landing target showing no `registerV5`/`account/rotate` chunks.
const sharedRoutes: AnyRoute[] = [
  indexRoute,
  ceremonyRoute,
  ceremonyContributeRoute,
  ceremonyStatusRoute,
  ceremonyVerifyRoute,
  integrationsRoute,
];

const appOnlyRoutes: AnyRoute[] = [
  cliRoute,
  submitRoute,
  mintRoute,
  registerV5Route,
  mintNftRoute,
  useDesktopRoute,
  accountRotateRoute,
];

const routeTree = rootRoute.addChildren([
  ...sharedRoutes,
  ...(IS_APP_TARGET ? appOnlyRoutes : []),
]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
