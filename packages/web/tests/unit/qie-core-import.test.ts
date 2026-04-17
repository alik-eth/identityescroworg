import { describe, it, expect } from 'vitest';
import { hybridEncapsulate, splitShares } from '@qkb/qie-core';

describe('@qkb/qie-core workspace import', () => {
  it('exports hybridEncapsulate and splitShares as functions', () => {
    expect(typeof hybridEncapsulate).toBe('function');
    expect(typeof splitShares).toBe('function');
  });
});
