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

function RootLayout() {
  const { t } = useTranslation();
  return (
    <div>
      <header>
        <h1>{t('app.title')}</h1>
        <nav>
          <Link to="/">{t('nav.home')}</Link>{' '}
          <Link to="/generate">{t('nav.generate')}</Link>{' '}
          <Link to="/sign">{t('nav.sign')}</Link>{' '}
          <Link to="/upload">{t('nav.upload')}</Link>{' '}
          <Link to="/register">{t('nav.register')}</Link>
        </nav>
        <LanguageSwitch />
      </header>
      <main>
        <Outlet />
      </main>
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

const routeTree = rootRoute.addChildren([
  indexRoute,
  generateRoute,
  signRoute,
  uploadRoute,
  registerRoute,
]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
