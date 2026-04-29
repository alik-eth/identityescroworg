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
import { MintNftScreen } from './routes/ua/mintNft';
import { RegisterV5Screen } from './routes/ua/registerV5';
import { UseDesktopScreen } from './routes/ua/useDesktop';
import { IntegrationsScreen } from './routes/integrations';

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

const integrationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/integrations',
  component: IntegrationsScreen,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  cliRoute,
  submitRoute,
  mintRoute,
  registerV5Route,
  mintNftRoute,
  useDesktopRoute,
  integrationsRoute,
]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
