import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from '@tanstack/react-router';
import { IndexScreen } from './routes/index';
import { CliInstall } from './routes/ua/cli';
import { SubmitScreen } from './routes/ua/submit';
import { MintScreen } from './routes/ua/mint';

function RootLayout() {
  return <Outlet />;
}

const rootRoute = createRootRoute({ component: RootLayout });

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: IndexScreen,
});

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

const routeTree = rootRoute.addChildren([indexRoute, cliRoute, submitRoute, mintRoute]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
