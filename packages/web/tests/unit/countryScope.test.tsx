import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { renderHook } from '@testing-library/react';
import {
  CountryProvider,
  useCountry,
  useOptionalCountry,
} from '../../src/components/CountryScope';
import { uaRouteTreeChildren } from '../../src/routes/ua/routes';

describe('CountryProvider / useCountry', () => {
  it('exposes the config via useCountry when rendered inside the provider', () => {
    const { result } = renderHook(() => useCountry(), {
      wrapper: ({ children }) => (
        <CountryProvider country="UA">{children}</CountryProvider>
      ),
    });
    expect(result.current.country).toBe('UA');
    expect(result.current.config.registry).toBe(
      '0x4c8541f4Ff16AE2650C4e146587E81eD56A2456C',
    );
    expect(result.current.config.registryVersion).toBe('v4');
  });

  it('useCountry throws outside the provider', () => {
    // renderHook captures the throw into result.error (React 18 + RTL)
    expect(() => renderHook(() => useCountry())).toThrowError(
      /CountryProvider/,
    );
  });

  it('useOptionalCountry returns null outside the provider', () => {
    const { result } = renderHook(() => useOptionalCountry());
    expect(result.current).toBe(null);
  });

  it('renders children with the data-country attribute on the scope element', () => {
    render(
      <CountryProvider country="UA">
        <span>scoped</span>
      </CountryProvider>,
    );
    const scope = screen.getByTestId('country-scope');
    expect(scope).toHaveAttribute('data-country', 'UA');
    expect(screen.getByText('scoped')).toBeInTheDocument();
  });
});

describe('UA route tree', () => {
  it('exposes index + generate + register + prove-age + sign + upload routes', () => {
    // `options.path` is runtime-present on every concrete Route but isn't
    // in the narrowed public type — cast for test-only introspection.
    const paths = uaRouteTreeChildren()
      .map((r) => (r.options as unknown as { path: string }).path)
      .sort();
    expect(paths).toEqual(
      ['/', 'generate', 'prove-age', 'register', 'sign', 'upload'].sort(),
    );
  });

  it('all UA children route to the UA parent (country-scoped)', () => {
    const kids = uaRouteTreeChildren();
    for (const r of kids) {
      const parent = (r.options as unknown as { getParentRoute: () => { options: { path: string } } })
        .getParentRoute();
      expect(parent.options.path).toBe('/ua');
    }
  });
});
