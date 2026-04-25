import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  Link,
} from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { LanguageSwitch } from './components/LanguageSwitch';
import { RoleProvider, RoleSwitcher } from './components/RoleSwitcher';
import { IndexScreen } from './routes/index';
import { EscrowSetupScreen } from './routes/escrowSetup';
import { EscrowRecoverScreen } from './routes/escrowRecover';
import { EscrowNotaryScreen } from './routes/escrowNotary';
import { CustodianLayout } from './routes/custodian';
import { CustodianIndex } from './routes/custodian.index';
import { CustodianAgentLayout } from './routes/custodian.$agentId';
import { CustodianInbox } from './routes/custodian.$agentId.inbox';
import { CustodianReleases } from './routes/custodian.$agentId.releases';
import { CustodianKeys } from './routes/custodian.$agentId.keys';
import { buildUaRoutes } from './routes/ua/routes';

function RootLayoutInner() {
  const { t } = useTranslation();
  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-slate-800/80 bg-slate-900/70 backdrop-blur supports-[backdrop-filter]:bg-slate-900/50">
        <div className="mx-auto max-w-5xl px-6 py-4 flex items-center justify-between gap-6">
          <Link to="/" className="flex items-center gap-3 group">
            <span className="font-mono text-[11px] tracking-widest text-emerald-400/90 uppercase">
              {t('app.logoMark')}
            </span>
            <h1 className="text-xl font-serif italic text-slate-100 group-hover:text-emerald-300 transition-colors">
              {t('app.title')}
            </h1>
          </Link>
          <div className="flex items-center gap-3">
            <RoleSwitcher />
            <LanguageSwitch />
          </div>
        </div>
      </header>
      <main className="flex-1 mx-auto w-full max-w-5xl px-6 py-10">
        <Outlet />
      </main>
      <footer className="border-t border-slate-800/80 py-4 text-center font-mono text-[10px] tracking-widest text-slate-600 uppercase">
        {t('app.footer')}
      </footer>
    </div>
  );
}

function RootLayout() {
  return (
    <RoleProvider>
      <RootLayoutInner />
    </RoleProvider>
  );
}

const rootRoute = createRootRoute({ component: RootLayout });

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: IndexScreen,
});

const escrowSetupRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/escrow/setup',
  component: EscrowSetupScreen,
});

const escrowRecoverRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/escrow/recover',
  component: EscrowRecoverScreen,
});

const escrowNotaryRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/escrow/notary',
  component: EscrowNotaryScreen,
});

const custodianRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/custodian',
  component: CustodianLayout,
});

const custodianIndexRoute = createRoute({
  getParentRoute: () => custodianRoute,
  path: '/',
  component: CustodianIndex,
});

const custodianAgentRoute = createRoute({
  getParentRoute: () => custodianRoute,
  path: '$agentId',
  component: CustodianAgentLayout,
});

const custodianAgentIndexRoute = createRoute({
  getParentRoute: () => custodianAgentRoute,
  path: '/',
  component: CustodianInbox,
});

const custodianInboxRoute = createRoute({
  getParentRoute: () => custodianAgentRoute,
  path: 'inbox',
  component: CustodianInbox,
});

const custodianReleasesRoute = createRoute({
  getParentRoute: () => custodianAgentRoute,
  path: 'releases',
  component: CustodianReleases,
});

const custodianKeysRoute = createRoute({
  getParentRoute: () => custodianAgentRoute,
  path: 'keys',
  component: CustodianKeys,
});

const { uaRoute, children: uaChildren } = buildUaRoutes(rootRoute);

const routeTree = rootRoute.addChildren([
  indexRoute,
  escrowSetupRoute,
  escrowRecoverRoute,
  escrowNotaryRoute,
  custodianRoute.addChildren([
    custodianIndexRoute,
    custodianAgentRoute.addChildren([
      custodianAgentIndexRoute,
      custodianInboxRoute,
      custodianReleasesRoute,
      custodianKeysRoute,
    ]),
  ]),
  uaRoute.addChildren(uaChildren),
]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
