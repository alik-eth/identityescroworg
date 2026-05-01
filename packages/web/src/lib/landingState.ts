export interface LandingInputs {
  walletConnected: boolean;
  chainOk: boolean;
  registered: boolean;
  minted: boolean;
  nowSeconds: number;
  mintDeadline: number;
  nextTokenId: number;
  mintedTokenId: number;
}

export type LandingAction =
  | 'connect'
  | 'switchChain'
  | 'routeToRegisterV5'
  | 'routeToCli'
  | 'routeToMint'
  | 'routeToMintNft'
  | 'viewCertificate'
  | 'mintClosed';

export interface LandingState {
  label: string;
  action: LandingAction;
  disabled: boolean;
}

/**
 * Resolve the primary landing CTA's label + action. The V5 unregistered
 * path defaults to the browser-side register flow (`/ua/registerV5`);
 * users who prefer offline / scriptable signing can reach the CLI via
 * a secondary CTA on the landing (see `LANDING_SECONDARY_CTAS`).
 *
 * The state machine is intentionally pure (no wagmi reads, no DOM,
 * no clock) so it's exhaustively testable — current coverage in
 * `tests/unit/landingState.test.ts` exercises every branch.
 */
export function resolveLandingState(i: LandingInputs): LandingState {
  if (!i.walletConnected) {
    return { label: 'Connect wallet to begin', action: 'connect', disabled: false };
  }
  if (!i.chainOk) {
    return { label: 'Switch network to continue', action: 'switchChain', disabled: false };
  }
  if (!i.registered) {
    return { label: 'Begin verification', action: 'routeToRegisterV5', disabled: false };
  }
  if (i.minted) {
    return {
      label: `View your certificate №${i.mintedTokenId}`,
      action: 'viewCertificate',
      disabled: false,
    };
  }
  if (i.nowSeconds > i.mintDeadline) {
    const closedDate = new Date(i.mintDeadline * 1000).toISOString().slice(0, 10);
    return {
      label: `Mint window closed ${closedDate}`,
      action: 'mintClosed',
      disabled: true,
    };
  }
  return {
    label: `Mint certificate №${i.nextTokenId}`,
    action: 'routeToMintNft',
    disabled: false,
  };
}

/**
 * Secondary CTAs surfaced beneath the primary landing button. Visibility
 * is state-aware: the CLI link is offered to anyone who prefers
 * offline/scriptable signing; the "view certificate" link only renders
 * once the user has minted.
 */
export interface SecondaryCtas {
  /** Show "Use the CLI instead" link beneath the primary CTA. */
  showCliLink: boolean;
  /** Show "View your certificate" link (post-mint). */
  showViewCertificate: boolean;
}

export function resolveSecondaryCtas(i: LandingInputs): SecondaryCtas {
  return {
    showCliLink: !i.registered,
    showViewCertificate: i.minted,
  };
}
