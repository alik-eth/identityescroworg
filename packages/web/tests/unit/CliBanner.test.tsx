// Unit tests for CliBanner — the install-qkb nudge that renders only
// when useCliPresence reports CLI absent and the user has not
// dismissed it. Tests pin:
//   - hidden during 'detecting' (no flash before first probe resolves)
//   - hidden when CLI is 'present'
//   - rendered when 'absent' and not dismissed
//   - clicking dismiss persists to localStorage and unmounts the banner
//   - reading a previously-set dismiss flag suppresses render even when 'absent'
//   - CTA points to /ua/cli
//
// react-i18next + @tanstack/react-router are mocked at module level so
// the component renders standalone (no Router provider, no i18n init
// — same posture as use-chain-deployment.test.tsx, which is the
// closest existing pattern in this repo).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';

// Hoisted mock for useCliPresence — let tests set the status before
// rendering. The hook lives in a deeper module path; we replace the
// whole import with a controllable function.
const cliPresenceState = { status: 'absent' as 'detecting' | 'present' | 'absent' };
vi.mock('../../src/hooks/useCliPresence', () => ({
  useCliPresence: () => ({
    status: cliPresenceState.status,
    cliStatus: null,
    recheck: vi.fn(),
  }),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (_key: string, defaultValue?: string) => defaultValue ?? _key,
  }),
}));

vi.mock('@tanstack/react-router', () => ({
  Link: ({
    children,
    to,
    ...rest
  }: {
    children: React.ReactNode;
    to: string;
    [key: string]: unknown;
  }) => (
    <a href={to} {...rest}>
      {children}
    </a>
  ),
}));

import { CliBanner, CLI_BANNER_DISMISSED_KEY } from '../../src/components/ua/v5/CliBanner';

beforeEach(() => {
  cliPresenceState.status = 'absent';
  window.localStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('CliBanner', () => {
  it('does not render during "detecting" state (avoid flash before first probe)', () => {
    cliPresenceState.status = 'detecting';
    render(<CliBanner />);
    expect(screen.queryByTestId('cli-banner')).toBeNull();
  });

  it('does not render when CLI is present', () => {
    cliPresenceState.status = 'present';
    render(<CliBanner />);
    expect(screen.queryByTestId('cli-banner')).toBeNull();
  });

  it('renders when CLI is absent and never dismissed', () => {
    cliPresenceState.status = 'absent';
    render(<CliBanner />);
    expect(screen.getByTestId('cli-banner')).toBeInTheDocument();
  });

  it('CTA links to /ua/cli', () => {
    cliPresenceState.status = 'absent';
    render(<CliBanner />);
    const cta = screen.getByTestId('cli-banner-cta');
    expect(cta.getAttribute('href')).toBe('/ua/cli');
  });

  it('clicking dismiss removes the banner and persists the flag', () => {
    cliPresenceState.status = 'absent';
    render(<CliBanner />);
    expect(screen.getByTestId('cli-banner')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('cli-banner-dismiss'));

    expect(screen.queryByTestId('cli-banner')).toBeNull();
    expect(window.localStorage.getItem(CLI_BANNER_DISMISSED_KEY)).toBe('1');
  });

  it('does not render when localStorage flag is already set (returning user)', () => {
    window.localStorage.setItem(CLI_BANNER_DISMISSED_KEY, '1');
    cliPresenceState.status = 'absent';
    render(<CliBanner />);
    expect(screen.queryByTestId('cli-banner')).toBeNull();
  });

  it('renders an aria-label for assistive tech', () => {
    cliPresenceState.status = 'absent';
    render(<CliBanner />);
    const banner = screen.getByTestId('cli-banner');
    // The aria-label uses the title copy; testing-library's getByRole
    // path would also work but we want to pin the testid + role pair.
    expect(banner.getAttribute('role')).toBe('complementary');
    expect(banner.getAttribute('aria-label')).toBeTruthy();
  });

  it('is resilient to localStorage throwing on read (sandboxed iframe / SSR)', () => {
    // Simulate a localStorage that throws on get — banner must still
    // render rather than crash the parent tree.
    const original = window.localStorage.getItem.bind(window.localStorage);
    vi.spyOn(window.localStorage, 'getItem').mockImplementation((key) => {
      if (key === CLI_BANNER_DISMISSED_KEY) throw new Error('quota');
      return original(key);
    });
    cliPresenceState.status = 'absent';
    render(<CliBanner />);
    expect(screen.getByTestId('cli-banner')).toBeInTheDocument();
  });
});
