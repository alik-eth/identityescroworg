import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  Link,
} from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { LanguageSwitch } from './components/LanguageSwitch';
import { IndexScreen } from './routes/index';
import { GenerateScreen } from './routes/generate';
import { SignScreen } from './routes/sign';
import { UploadScreen } from './routes/upload';
import { RegisterScreen } from './routes/register';
import { EscrowSetupScreen } from './routes/escrowSetup';
import { EscrowRecoverScreen } from './routes/escrowRecover';

const STEPS = [
  { to: '/generate', key: 'nav.generate' },
  { to: '/sign', key: 'nav.sign' },
  { to: '/upload', key: 'nav.upload' },
  { to: '/register', key: 'nav.register' },
] as const;

function RootLayout() {
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
          <nav className="hidden md:flex items-center gap-1 text-sm">
            {STEPS.map((step, i) => (
              <Link
                key={step.to}
                to={step.to}
                className="px-3 py-1.5 rounded-full text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 transition-colors"
                activeProps={{
                  className:
                    'px-3 py-1.5 rounded-full text-emerald-300 bg-emerald-500/10 border border-emerald-500/30',
                }}
              >
                <span className="font-mono text-[10px] text-slate-500 mr-1">
                  {String(i + 1).padStart(2, '0')}
                </span>
                {t(step.key)}
              </Link>
            ))}
          </nav>
          <LanguageSwitch />
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

const rootRoute = createRootRoute({ component: RootLayout });

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: IndexScreen,
});

const generateRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/generate',
  component: GenerateScreen,
});

const signRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/sign',
  component: SignScreen,
});

const uploadRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/upload',
  component: UploadScreen,
});

const registerRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/register',
  component: RegisterScreen,
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

const routeTree = rootRoute.addChildren([
  indexRoute,
  generateRoute,
  signRoute,
  uploadRoute,
  registerRoute,
  escrowSetupRoute,
  escrowRecoverRoute,
]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
