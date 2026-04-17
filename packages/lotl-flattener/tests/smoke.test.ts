import { describe, expect, test } from 'vitest';

describe('smoke', () => {
  test('harness runs', () => {
    expect(1 + 1).toBe(2);
  });
});
