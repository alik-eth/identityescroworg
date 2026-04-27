import { describe, it, expect } from 'vitest';
import { resolveLandingState, type LandingInputs } from '../../src/lib/landingState';

const base: LandingInputs = {
  walletConnected: false,
  chainOk: false,
  registered: false,
  minted: false,
  nowSeconds: 1700000000,
  mintDeadline: 1800000000,
  nextTokenId: 7,
  mintedTokenId: 0,
};

describe('landing button state machine', () => {
  it('disconnected → connect prompt', () => {
    expect(resolveLandingState(base).label).toMatch(/connect wallet/i);
    expect(resolveLandingState(base).action).toBe('connect');
  });

  it('connected wrong-chain → switch chain', () => {
    expect(resolveLandingState({ ...base, walletConnected: true }).action).toBe('switchChain');
  });

  it('connected correct-chain unregistered → begin verification', () => {
    const r = resolveLandingState({ ...base, walletConnected: true, chainOk: true });
    expect(r.action).toBe('routeToCli');
  });

  it('registered, not minted, in window → mint cta with next-id', () => {
    const r = resolveLandingState({
      ...base, walletConnected: true, chainOk: true, registered: true,
    });
    expect(r.action).toBe('routeToMint');
    expect(r.label).toContain('7');
  });

  it('registered + minted → view certificate', () => {
    const r = resolveLandingState({
      ...base, walletConnected: true, chainOk: true,
      registered: true, minted: true, mintedTokenId: 3,
    });
    expect(r.action).toBe('viewCertificate');
    expect(r.label).toContain('3');
  });

  it('registered, not minted, after deadline → window closed', () => {
    const r = resolveLandingState({
      ...base, walletConnected: true, chainOk: true,
      registered: true, nowSeconds: 1900000000,
    });
    expect(r.action).toBe('mintClosed');
    expect(r.disabled).toBe(true);
  });
});
