import { useEffect, useRef } from 'react';

/**
 * Privacy invariant: when sensitive material (recipient hybrid sk, Phase 1
 * binding artifacts, recovery material R) is in memory, the tab should
 * prompt the user before navigating away. Browsers ultimately control
 * whether the prompt renders; we attach regardless.
 *
 * Bookkeeping: multiple components may simultaneously hold sensitive state;
 * we track them via a Set of symbolic tokens so the last one to clear
 * removes the handler.
 */

const tokens = new Set<symbol>();
let installed = false;

function onUnload(e: BeforeUnloadEvent): void {
  if (tokens.size === 0) return;
  e.preventDefault();
  // Legacy browsers require a truthy returnValue to trigger the prompt.
  e.returnValue = '';
}

function install(): void {
  if (installed) return;
  if (typeof window === 'undefined') return;
  installed = true;
  window.addEventListener('beforeunload', onUnload);
}

export function useSensitiveSessionGuard(active: boolean): void {
  const tok = useRef(Symbol('sensitive')).current;
  useEffect(() => {
    install();
    if (active) tokens.add(tok);
    else tokens.delete(tok);
    return () => {
      tokens.delete(tok);
    };
  }, [active, tok]);
}

/**
 * Runtime self-check: scan known storage keys for sensitive material that
 * must never be persisted. Clears any offenders defensively. Call at
 * provider mount time; log (not throw) so a stray test harness doesn't
 * brick the app.
 */
export function assertNoPersistence(): void {
  if (typeof window === 'undefined') return;
  const offenders = [
    'qkb.recipientSk',
    'qie.recipientSk',
    'qie.bindingSigma',
    'qie.recoveryR',
    'qie.phase1Artifacts',
  ];
  for (const k of offenders) {
    try {
      if (window.localStorage?.getItem(k) !== null) {
        // biome-ignore lint/suspicious/noConsole: intentional privacy alarm
        console.error(`PRIVACY BREAKAGE: ${k} persisted to localStorage. Clearing.`);
        window.localStorage.removeItem(k);
      }
      if (window.sessionStorage?.getItem(k) !== null) {
        // biome-ignore lint/suspicious/noConsole: intentional privacy alarm
        console.error(`PRIVACY BREAKAGE: ${k} persisted to sessionStorage. Clearing.`);
        window.sessionStorage.removeItem(k);
      }
    } catch {
      // storage access may throw in sandboxed contexts; best-effort scrub
    }
  }
}

/** Test-only: reset the internal token set so unit tests don't leak across cases. */
export function _resetSessionGuardForTests(): void {
  tokens.clear();
}
