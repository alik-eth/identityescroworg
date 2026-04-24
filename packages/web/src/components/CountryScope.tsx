import { createContext, useContext, useMemo, type ReactNode } from 'react';
import {
  getCountryConfig,
  type CountryConfig,
  type SupportedCountry,
} from '../lib/countryConfig';

export interface CountryScopeValue {
  readonly country: SupportedCountry;
  readonly config: CountryConfig;
}

const CountryContext = createContext<CountryScopeValue | null>(null);

interface CountryProviderProps {
  readonly country: SupportedCountry;
  readonly children: ReactNode;
}

export function CountryProvider({ country, children }: CountryProviderProps) {
  const value = useMemo<CountryScopeValue>(
    () => ({ country, config: getCountryConfig(country) }),
    [country],
  );
  return (
    <CountryContext.Provider value={value}>
      <div data-testid="country-scope" data-country={country}>
        {children}
      </div>
    </CountryContext.Provider>
  );
}

export function useCountry(): CountryScopeValue {
  const ctx = useContext(CountryContext);
  if (!ctx) {
    throw new Error(
      'useCountry must be used inside a <CountryProvider>. ' +
        'Routes under /ua/* are wrapped automatically; legacy V3 routes must not call this.',
    );
  }
  return ctx;
}

export function useOptionalCountry(): CountryScopeValue | null {
  return useContext(CountryContext);
}
