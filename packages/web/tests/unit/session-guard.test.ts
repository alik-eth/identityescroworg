import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import {
  useSensitiveSessionGuard,
  assertNoPersistence,
  _resetSessionGuardForTests,
} from '../../src/lib/session-guard';

describe('session-guard', () => {
  beforeEach(() => {
    _resetSessionGuardForTests();
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it('attaches beforeunload once when any hook is active', () => {
    const addSpy = vi.spyOn(window, 'addEventListener');
    renderHook(() => useSensitiveSessionGuard(true));
    renderHook(() => useSensitiveSessionGuard(true));
    const beforeUnloadCalls = addSpy.mock.calls.filter(
      (c) => (c[0] as string) === 'beforeunload',
    );
    expect(beforeUnloadCalls.length).toBe(1);
    addSpy.mockRestore();
  });

  it('beforeunload handler prompts when any token is active', () => {
    renderHook(() => useSensitiveSessionGuard(true));
    const event = new Event('beforeunload', { cancelable: true }) as BeforeUnloadEvent;
    Object.defineProperty(event, 'returnValue', { writable: true, value: undefined });
    window.dispatchEvent(event);
    // The handler sets returnValue to '' to trigger the browser prompt.
    expect(event.returnValue).toBe('');
  });

  it('beforeunload handler is a no-op when no tokens are active', () => {
    renderHook(() => useSensitiveSessionGuard(false));
    const event = new Event('beforeunload') as BeforeUnloadEvent;
    Object.defineProperty(event, 'returnValue', { writable: true, value: undefined });
    window.dispatchEvent(event);
    expect(event.returnValue).toBeUndefined();
  });

  it('cleanup on unmount releases token', () => {
    const { unmount } = renderHook(() => useSensitiveSessionGuard(true));
    unmount();
    const event = new Event('beforeunload') as BeforeUnloadEvent;
    Object.defineProperty(event, 'returnValue', { writable: true, value: undefined });
    window.dispatchEvent(event);
    expect(event.returnValue).toBeUndefined();
  });

  it('assertNoPersistence clears offender keys and logs', () => {
    window.localStorage.setItem('qkb.recipientSk', 'leak');
    window.sessionStorage.setItem('qie.bindingSigma', 'leak');
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    assertNoPersistence();
    expect(window.localStorage.getItem('qkb.recipientSk')).toBeNull();
    expect(window.sessionStorage.getItem('qie.bindingSigma')).toBeNull();
    expect(err).toHaveBeenCalled();
    err.mockRestore();
  });

  it('assertNoPersistence is silent when storage is clean', () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    assertNoPersistence();
    expect(err).not.toHaveBeenCalled();
    err.mockRestore();
  });
});
