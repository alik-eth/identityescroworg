import { describe, expect, it } from 'vitest';
import {
  resolveLandingState,
  resolveSecondaryCtas,
  type LandingInputs,
} from '../../src/lib/landingState';

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

  it('connected correct-chain unregistered → V5 register flow (NOT V4 CLI)', () => {
    // Plan §10 amendment: the browser-side V5 flow is now the primary
    // entry; CLI is offered as a secondary CTA. Pinning this prevents
    // a future change accidentally re-routing the unregistered default
    // back to the V4 CLI path.
    const r = resolveLandingState({ ...base, walletConnected: true, chainOk: true });
    expect(r.action).toBe('routeToRegisterV5');
  });

  it('registered, not minted, in window → V5 mint route with next-id', () => {
    // V5 mint route lives at /ua/mintNft; the V4 /ua/mint stays for
    // V4 regression but is no longer the default mint target.
    const r = resolveLandingState({
      ...base, walletConnected: true, chainOk: true, registered: true,
    });
    expect(r.action).toBe('routeToMintNft');
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

describe('landing button — secondary CTAs', () => {
  it('shows the CLI link to unregistered users (offline-signing path)', () => {
    expect(
      resolveSecondaryCtas({ ...base, walletConnected: true, chainOk: true })
        .showCliLink,
    ).toBe(true);
  });

  it('hides the CLI link once registered (avoids confusing post-register UI)', () => {
    expect(
      resolveSecondaryCtas({
        ...base, walletConnected: true, chainOk: true, registered: true,
      }).showCliLink,
    ).toBe(false);
  });

  it('shows view-certificate link only post-mint', () => {
    expect(
      resolveSecondaryCtas({
        ...base, walletConnected: true, chainOk: true,
        registered: true, minted: true, mintedTokenId: 3,
      }).showViewCertificate,
    ).toBe(true);
    expect(
      resolveSecondaryCtas({
        ...base, walletConnected: true, chainOk: true, registered: true,
      }).showViewCertificate,
    ).toBe(false);
  });
});
