import { describe, expect, it } from 'vitest';
import {
  ALL_ERROR_CODES,
  BundleError,
  ZkqesError,
  localizeError,
  type ErrorCode,
} from '../src/errors/index.js';

describe('ZkqesError', () => {
  it('carries code, messageKey, and optional details', () => {
    const err = new ZkqesError('binding.size', { reason: 'too big', actual: 4096 });
    expect(err.code).toBe('binding.size');
    expect(err.messageKey).toBe('errors.binding.size');
    expect(err.details).toEqual({ reason: 'too big', actual: 4096 });
    expect(err.message).toBe('binding.size: too big');
  });

  it('falls back to code-only message when no reason', () => {
    const err = new ZkqesError('cades.parse');
    expect(err.message).toBe('cades.parse');
  });
});

describe('BundleError', () => {
  it('only accepts bundle.* codes via the type system at compile time', () => {
    const err = new BundleError('bundle.malformed', { offset: 42 });
    expect(err.name).toBe('BundleError');
    expect(err.code).toBe('bundle.malformed');
    expect(err).toBeInstanceOf(ZkqesError);
  });
});

describe('ALL_ERROR_CODES', () => {
  it('contains every union member exactly once', () => {
    const set = new Set<ErrorCode>(ALL_ERROR_CODES);
    expect(set.size).toBe(ALL_ERROR_CODES.length);
  });
});

describe('localizeError', () => {
  it('returns the localized string when the i18n key resolves', () => {
    const i18n = { t: (k: string) => (k === 'errors.binding.size' ? 'Too large' : k) };
    const err = new ZkqesError('binding.size');
    expect(localizeError(err, i18n)).toBe('Too large');
  });

  it('returns the raw code when i18n echoes the key back unchanged', () => {
    const i18n = { t: (k: string) => k };
    const err = new ZkqesError('binding.size');
    expect(localizeError(err, i18n)).toBe('binding.size');
  });

  it('returns the message for non-ZkqesError Error instances', () => {
    expect(localizeError(new Error('boom'), { t: (k) => k })).toBe('boom');
  });

  it('returns the fallback for unknown thrown values', () => {
    expect(localizeError('not an error', { t: (k) => k }, 'fallback')).toBe('fallback');
  });
});
