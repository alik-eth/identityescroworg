import { createRoute, type AnyRoute } from '@tanstack/react-router';
import { GenerateScreen } from '../generate';
import { SignScreen } from '../sign';
import { UploadScreen } from '../upload';
import { RegisterScreen } from '../register';
import { UaIndex } from './index';
import { UaProveAgeScreen } from './proveAge';
import { UaLayout } from './layout';

export function buildUaRoutes(parent: AnyRoute) {
  const uaRoute = createRoute({
    getParentRoute: () => parent,
    path: '/ua',
    component: UaLayout,
  });

  const children = [
    createRoute({
      getParentRoute: () => uaRoute,
      path: '/',
      component: UaIndex,
    }),
    createRoute({
      getParentRoute: () => uaRoute,
      path: 'generate',
      component: GenerateScreen,
    }),
    createRoute({
      getParentRoute: () => uaRoute,
      path: 'sign',
      component: SignScreen,
    }),
    createRoute({
      getParentRoute: () => uaRoute,
      path: 'upload',
      component: UploadScreen,
    }),
    createRoute({
      getParentRoute: () => uaRoute,
      path: 'register',
      component: RegisterScreen,
    }),
    createRoute({
      getParentRoute: () => uaRoute,
      path: 'prove-age',
      component: UaProveAgeScreen,
    }),
  ];

  return { uaRoute, children };
}

// Convenience for tests: returns just the children of the UA layout without
// requiring a real root route. Builds a throwaway parent inline.
export function uaRouteTreeChildren() {
  const stubParent = createRoute({
    // @ts-expect-error — intentional stub parent for test inspection only;
    //   not added to any tree.
    getParentRoute: () => null,
    path: '/',
  });
  const { children } = buildUaRoutes(stubParent as unknown as AnyRoute);
  return children;
}
