import { describe, expect, it } from 'vitest';
import {
  V5_PROVER_ARTIFACTS,
  assertV5ArtifactsConfigured,
  isV5ArtifactsConfigured,
} from '../../src/lib/circuitArtifacts';

describe('V5_PROVER_ARTIFACTS', () => {
  it('exposes the V5 single-circuit envelope (qkb/2.0, ~3M constraints)', () => {
    expect(V5_PROVER_ARTIFACTS.schemaVersion).toBe('zkqes/2.0');
    expect(V5_PROVER_ARTIFACTS.expectedConstraintCount).toBe(3_000_000);
    expect(V5_PROVER_ARTIFACTS.expectedZkeyBytes).toBe(1_500_000_000);
  });

  it('ships placeholder URLs + sha256s pre-ceremony', () => {
    // Until lead pumps real ceremony artifacts the URLs MUST be sentinels.
    // If a future commit lands real URLs by mistake before §9.6 closes,
    // this test is the brake.
    expect(V5_PROVER_ARTIFACTS.wasmUrl).toMatch(/^__V5_PROVER_/);
    expect(V5_PROVER_ARTIFACTS.zkeyUrl).toMatch(/^__V5_PROVER_/);
    expect(V5_PROVER_ARTIFACTS.wasmSha256).toMatch(/^__V5_PROVER_/);
    expect(V5_PROVER_ARTIFACTS.zkeySha256).toMatch(/^__V5_PROVER_/);
  });
});

describe('assertV5ArtifactsConfigured', () => {
  it('throws with a ceremony-pump pointer when artifacts unconfigured', () => {
    expect(() => assertV5ArtifactsConfigured()).toThrow(
      /not yet configured.*Phase 2 ceremony pump/i,
    );
  });
});

describe('isV5ArtifactsConfigured', () => {
  it('returns false when artifacts unconfigured (UI-gating predicate)', () => {
    expect(isV5ArtifactsConfigured()).toBe(false);
  });
});
