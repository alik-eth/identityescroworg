// Coverage: each `denied` branch + the `ready` happy-path of
// assessDeviceCapability(). The tests reach into globalThis.navigator
// directly because jsdom's navigator is a getter-only proxy that we
// can't reassign — instead we mutate properties on it via Object.defineProperty.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  assessDeviceCapability,
  isInAppWebView,
} from '../../src/lib/deviceGate';

type FakeStorage = {
  persist?: () => Promise<boolean>;
  estimate?: () => Promise<{ quota?: number; usage?: number }>;
};

interface NavOverrides {
  storage?: FakeStorage | undefined;
  userAgent?: string;
  deviceMemory?: number | undefined;
}

function withNavigator(overrides: NavOverrides, run: () => Promise<void> | void) {
  const original: Record<string, PropertyDescriptor | undefined> = {
    storage: Object.getOwnPropertyDescriptor(navigator, 'storage'),
    userAgent: Object.getOwnPropertyDescriptor(navigator, 'userAgent'),
    deviceMemory: Object.getOwnPropertyDescriptor(navigator, 'deviceMemory'),
  };

  if ('storage' in overrides) {
    Object.defineProperty(navigator, 'storage', {
      configurable: true,
      value: overrides.storage,
    });
  }
  if (overrides.userAgent !== undefined) {
    Object.defineProperty(navigator, 'userAgent', {
      configurable: true,
      value: overrides.userAgent,
    });
  }
  if ('deviceMemory' in overrides) {
    Object.defineProperty(navigator, 'deviceMemory', {
      configurable: true,
      value: overrides.deviceMemory,
    });
  }

  const restore = () => {
    for (const [key, desc] of Object.entries(original)) {
      if (desc) {
        Object.defineProperty(navigator, key, desc);
      } else {
        // Property didn't exist originally; remove the override.
        delete (navigator as unknown as Record<string, unknown>)[key];
      }
    }
  };

  try {
    return Promise.resolve(run()).finally(restore);
  } catch (err) {
    restore();
    throw err;
  }
}

const FLAGSHIP_UA =
  'Mozilla/5.0 (Linux; Android 14; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36';

const READY_STORAGE: FakeStorage = {
  persist: () => Promise.resolve(true),
  estimate: () => Promise.resolve({ quota: 4_000_000_000, usage: 0 }),
};

describe('isInAppWebView', () => {
  it('flags Telegram in-app browser', () => {
    expect(
      isInAppWebView(
        'Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/126.0.0.0 Telegram/10.13.0',
      ),
    ).toBe(true);
  });

  it('flags Instagram in-app browser', () => {
    expect(
      isInAppWebView(
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Instagram 320.0.0.0',
      ),
    ).toBe(true);
  });

  it('flags Facebook in-app browser via FBAN/FBAV', () => {
    expect(
      isInAppWebView(
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) FBAN/FBIOS;FBAV/450.0.0',
      ),
    ).toBe(true);
  });

  it('flags generic Android WebView (`; wv)`)', () => {
    expect(
      isInAppWebView(
        'Mozilla/5.0 (Linux; Android 14; Pixel 8; wv) AppleWebKit/537.36 Chrome/126.0',
      ),
    ).toBe(true);
  });

  it('does not flag mobile Safari on iPhone 15', () => {
    expect(
      isInAppWebView(
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile/15E148 Safari/604.1',
      ),
    ).toBe(false);
  });

  it('does not flag Chrome on Pixel 9', () => {
    expect(isInAppWebView(FLAGSHIP_UA)).toBe(false);
  });
});

describe('assessDeviceCapability', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('denies with no-storage-api when navigator.storage missing', async () => {
    await withNavigator(
      { storage: undefined, userAgent: FLAGSHIP_UA, deviceMemory: 8 },
      async () => {
        const result = await assessDeviceCapability();
        expect(result).toEqual({
          kind: 'denied',
          reason: 'no-storage-api',
        });
      },
    );
  });

  it('denies with no-storage-api when persist() is missing', async () => {
    await withNavigator(
      {
        storage: {
          estimate: () => Promise.resolve({ quota: 4_000_000_000 }),
        },
        userAgent: FLAGSHIP_UA,
        deviceMemory: 8,
      },
      async () => {
        const result = await assessDeviceCapability();
        expect(result).toEqual({
          kind: 'denied',
          reason: 'no-storage-api',
        });
      },
    );
  });

  it('denies with webview-detected for Telegram in-app browser', async () => {
    await withNavigator(
      {
        storage: READY_STORAGE,
        userAgent:
          'Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/126.0.0.0 Telegram/10.13.0',
        deviceMemory: 8,
      },
      async () => {
        const result = await assessDeviceCapability();
        expect(result).toEqual({
          kind: 'denied',
          reason: 'webview-detected',
        });
      },
    );
  });

  it('denies with low-quota when quota < 3 GB', async () => {
    await withNavigator(
      {
        storage: {
          persist: () => Promise.resolve(true),
          estimate: () => Promise.resolve({ quota: 1_500_000_000 }),
        },
        userAgent: FLAGSHIP_UA,
        deviceMemory: 8,
      },
      async () => {
        const result = await assessDeviceCapability();
        expect(result).toEqual({ kind: 'denied', reason: 'low-quota' });
      },
    );
  });

  it('denies with persist-denied when persist() returns false', async () => {
    await withNavigator(
      {
        storage: {
          persist: () => Promise.resolve(false),
          estimate: () => Promise.resolve({ quota: 4_000_000_000 }),
        },
        userAgent: FLAGSHIP_UA,
        deviceMemory: 8,
      },
      async () => {
        const result = await assessDeviceCapability();
        expect(result).toEqual({ kind: 'denied', reason: 'persist-denied' });
      },
    );
  });

  it('denies with low-ram when deviceMemory < 4', async () => {
    await withNavigator(
      {
        storage: READY_STORAGE,
        userAgent: FLAGSHIP_UA,
        deviceMemory: 2,
      },
      async () => {
        const result = await assessDeviceCapability();
        expect(result).toEqual({ kind: 'denied', reason: 'low-ram' });
      },
    );
  });

  it('skips the deviceMemory check when undefined (Safari)', async () => {
    await withNavigator(
      {
        storage: READY_STORAGE,
        userAgent: FLAGSHIP_UA,
        deviceMemory: undefined,
      },
      async () => {
        const result = await assessDeviceCapability();
        expect(result).toEqual({
          kind: 'ready',
          quotaBytes: 4_000_000_000,
          persistGranted: true,
        });
      },
    );
  });

  it('returns ready when all gates pass on a flagship device', async () => {
    await withNavigator(
      {
        storage: READY_STORAGE,
        userAgent: FLAGSHIP_UA,
        deviceMemory: 8,
      },
      async () => {
        const result = await assessDeviceCapability();
        expect(result).toEqual({
          kind: 'ready',
          quotaBytes: 4_000_000_000,
          persistGranted: true,
        });
      },
    );
  });
});
