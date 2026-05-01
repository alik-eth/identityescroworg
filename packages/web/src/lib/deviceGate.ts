// Device-capability gate for the V5 in-browser prover.
//
// Per spec amendment 9c866ad (review pass 5), mobile-browser is now a hard
// acceptance gate narrowed to flagship 2024+ phones (Pixel 9 + iPhone 15
// Safari) with `navigator.storage.persist()` granted. Out-of-gate devices
// (mid-range Android, iOS WebView, <8 GB RAM phones, older browsers) MUST
// be detected and rerouted to a "use desktop" page BEFORE zkey download
// to prevent OOM / quota-exhaustion failures.
//
// This module does the detection. Routing is the caller's responsibility
// (Step 1 of /ua/registerV5 → /ua/use-desktop on `denied`).

export type DeviceCapability =
  | { kind: 'ready'; quotaBytes: number; persistGranted: true }
  | {
      kind: 'denied';
      reason:
        | 'no-storage-api'
        | 'low-quota'
        | 'persist-denied'
        | 'webview-detected'
        | 'low-ram'
        | 'old-browser';
    };

// Minimum storage quota the prover needs cached (zkey + wasm + ptau slice).
// Spec §Risks pegs this at ~2.5 GB worst-case; we round to 3 GB to leave
// headroom for the browser's own cache eviction policy.
const MIN_QUOTA_BYTES = 3_000_000_000;

// In-app webview UA-string patterns. These browsers either don't expose
// the Storage API at full quota, gate persist() behind opaque rules, or
// kill the tab on backgrounding mid-proof. All three break the V5 flow.
//
// Order matters only for performance; any match short-circuits.
const WEBVIEW_PATTERNS: readonly RegExp[] = [
  /Telegram/i,
  /Instagram/i,
  /\bFBAN\b|\bFBAV\b|\bFB_IAB\b/, // Facebook in-app browser markers
  /TwitterAndroid|Twitter for/i,
  /\bLine\//i,
  /MicroMessenger/i, // WeChat
  /KAKAOTALK/i,
  /; wv\)/i, // Android WebView generic marker
];

export function isInAppWebView(userAgent: string): boolean {
  return WEBVIEW_PATTERNS.some((re) => re.test(userAgent));
}

export async function assessDeviceCapability(): Promise<DeviceCapability> {
  // SSR / no-navigator environments (extremely old browsers, headless tools
  // without UA shimming). Treat as old-browser rather than crashing.
  if (typeof navigator === 'undefined') {
    return { kind: 'denied', reason: 'old-browser' };
  }

  // Step 1: Storage API feature detect.
  const storage = (navigator as Navigator).storage as
    | (StorageManager & { persist?: () => Promise<boolean>; estimate?: () => Promise<StorageEstimate> })
    | undefined;
  if (
    !storage ||
    typeof storage.persist !== 'function' ||
    typeof storage.estimate !== 'function'
  ) {
    return { kind: 'denied', reason: 'no-storage-api' };
  }

  // Step 2: in-app WebView sniff (Telegram, Instagram, Facebook, Twitter,
  // Line, WeChat, KakaoTalk, generic Android WebView).
  if (isInAppWebView(navigator.userAgent ?? '')) {
    return { kind: 'denied', reason: 'webview-detected' };
  }

  // Step 3: quota check. Sub-3 GB allocation can't host the full zkey +
  // wasm + ptau slice without eviction churn.
  const estimate = await storage.estimate();
  const quota = estimate.quota ?? 0;
  if (quota < MIN_QUOTA_BYTES) {
    return { kind: 'denied', reason: 'low-quota' };
  }

  // Step 4: persist() grant. Without it the browser is free to evict the
  // zkey under memory pressure mid-proof, which we have no way to recover
  // from. A `false` return means the user (or browser policy) refused.
  const persisted = await storage.persist();
  if (!persisted) {
    return { kind: 'denied', reason: 'persist-denied' };
  }

  // Step 5: optional deviceMemory check. Chrome/Edge/Opera expose this;
  // Safari/Firefox return undefined — skip the check rather than fail
  // them (they get filtered by other gates anyway).
  const deviceMemory = (navigator as Navigator & { deviceMemory?: number })
    .deviceMemory;
  if (typeof deviceMemory === 'number' && deviceMemory < 4) {
    return { kind: 'denied', reason: 'low-ram' };
  }

  return { kind: 'ready', quotaBytes: quota, persistGranted: true };
}
