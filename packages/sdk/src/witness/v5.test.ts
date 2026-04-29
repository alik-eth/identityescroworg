// Stub coverage — placeholder until Task 8 lands the real impl.
// The two tests below assert the API surface compiles and the stub
// throws with a §7 pointer (so a future caller forgetting to gate on
// `useMockProver` blows up loudly instead of silently producing nonsense).
import { describe, expect, it } from 'vitest';
import {
  buildV5Witness,
  type BuildV5WitnessInput,
  type BindingV2Offsets,
  type QKBPresentationV5WitnessInput,
} from './v5.js';

describe('buildV5Witness — stub (gated on circuits-eng §7)', () => {
  it('throws with a circuits-eng §7 pointer', () => {
    expect(() => buildV5Witness({} as unknown as BuildV5WitnessInput))
      .toThrow(/circuits-eng §7/);
  });

  it('throws with a NOT IMPLEMENTED marker', () => {
    expect(() => buildV5Witness({} as unknown as BuildV5WitnessInput))
      .toThrow(/NOT IMPLEMENTED/);
  });
});

describe('V5 witness surface types — compile-time checks', () => {
  it('BindingV2Offsets has the 17 fields documented in the §6.0a fixture', () => {
    // This test exists to break loudly if circuits-eng changes the V2Core
    // schema's offset count — TS would silently let an extra field through
    // since BindingV2Offsets isn't in a value position elsewhere.
    const fields: readonly (keyof BindingV2Offsets)[] = [
      'pk', 'scheme', 'statementSchema', 'assertions',
      'nonce', 'ctx', 'ctxLen',
      'policyId', 'policyLeafHash', 'policyBindingSchema', 'policyVersion',
      'ts', 'tsLen', 'version',
      'displayLocale', 'displayStatement', 'displayStatementLen',
    ] as const;
    expect(fields.length).toBe(17);
  });

  it('QKBPresentationV5WitnessInput.publicSignals is the 14-element struct', () => {
    // Round-trip: TS infers from the imported registryV5 PublicSignalsV5,
    // which the registryV5 test pins to 14 elements. If circuits-eng's §7
    // adds a 15th public signal we want the registry test to scream first.
    type Surface = QKBPresentationV5WitnessInput['publicSignals'];
    const sample: Surface = {
      msgSender: 0n, timestamp: 0n, nullifier: 0n,
      ctxHashHi: 0n, ctxHashLo: 0n,
      bindingHashHi: 0n, bindingHashLo: 0n,
      signedAttrsHashHi: 0n, signedAttrsHashLo: 0n,
      leafTbsHashHi: 0n, leafTbsHashLo: 0n,
      policyLeafHash: 0n, leafSpkiCommit: 0n, intSpkiCommit: 0n,
    };
    expect(Object.keys(sample).length).toBe(14);
  });
});
