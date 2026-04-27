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
  | 'routeToCli'
  | 'routeToMint'
  | 'viewCertificate'
  | 'mintClosed';

export interface LandingState {
  label: string;
  action: LandingAction;
  disabled: boolean;
}

export function resolveLandingState(i: LandingInputs): LandingState {
  if (!i.walletConnected) {
    return { label: 'Connect wallet to begin', action: 'connect', disabled: false };
  }
  if (!i.chainOk) {
    return { label: 'Switch network to continue', action: 'switchChain', disabled: false };
  }
  if (!i.registered) {
    return { label: 'Begin verification', action: 'routeToCli', disabled: false };
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
    action: 'routeToMint',
    disabled: false,
  };
}
