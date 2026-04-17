/**
 * /register — Step 4 of the binding flow.
 *
 * Reads proof + publicSignals from sessionStorage and submits a `register()`
 * call to the QKBRegistry on Sepolia via the user's EIP-1193 wallet. The
 * registry address is a TODO-stub today — the lead pumps the deployed
 * Sepolia address into the repo after the contracts worker's Sepolia deploy,
 * and this file then just reads it from `fixtures/contracts/sepolia.json`.
 *
 * The wallet + submit pipeline is injectable:
 *   - `window.__QKB_ETHEREUM__` lets Playwright stub EIP-1193 without a real
 *     MetaMask.
 *   - `window.__QKB_SUBMIT_TX__` lets Playwright bypass ABI encoding and
 *     return a deterministic tx hash + bound address for assertion.
 *
 * Both hooks are `undefined` in the production bundle; the default path
 * falls back to the real `window.ethereum` and a minimal hand-rolled
 * `eth_sendTransaction` flow. ABI encoding of the `register(proof,inputs)`
 * calldata is out of scope for this commit — it will land once the
 * contracts worker pumps the Sepolia deployment.
 */
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { PhaseCard } from '../components/PhaseCard';
import { loadSession } from '../lib/session';

// TODO: lead pumps real address after `DeployQKBRegistry.s.sol` runs on Sepolia.
// The constant lives here so a find-and-replace during the pump step is a
// one-liner. Do NOT hardcode it in routes/tests — always import.
const REGISTRY_ADDRESS_SEPOLIA = '0x0000000000000000000000000000000000000000';

type Eip1193Request = (args: { method: string; params?: unknown[] }) => Promise<unknown>;
interface Eip1193Provider {
  request: Eip1193Request;
  isMetaMask?: boolean;
}

interface SubmitTxInput {
  from: string;
  to: string;
  proof: unknown;
  publicSignals: readonly string[];
}

interface SubmitTxResult {
  txHash: string;
  pkAddr: string;
}

declare global {
  interface Window {
    ethereum?: Eip1193Provider;
    __QKB_ETHEREUM__?: Eip1193Provider;
    __QKB_SUBMIT_TX__?: (input: SubmitTxInput) => Promise<SubmitTxResult>;
  }
}

export function RegisterScreen() {
  const { t } = useTranslation();
  const session = useMemo(() => loadSession(), []);

  const [address, setAddress] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);
  const [pkAddr, setPkAddr] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!session.proof || !session.publicSignals) {
    return (
      <PhaseCard step={4} total={4} accent="purple" title={t('register.heading')}>
        <p data-testid="register-missing" className="text-amber-300">
          {t('register.noBundle')}
        </p>
      </PhaseCard>
    );
  }

  const getProvider = (): Eip1193Provider | null => {
    if (typeof window === 'undefined') return null;
    return window.__QKB_ETHEREUM__ ?? window.ethereum ?? null;
  };

  const onConnect = async (): Promise<void> => {
    setError(null);
    const provider = getProvider();
    if (!provider) {
      setError(t('register.noWallet'));
      return;
    }
    try {
      const accounts = (await provider.request({ method: 'eth_requestAccounts' })) as string[];
      setAddress(accounts[0] ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const onSubmit = async (): Promise<void> => {
    setError(null);
    const provider = getProvider();
    if (!provider || !address) {
      setError(t('register.noWallet'));
      return;
    }
    setSubmitting(true);
    try {
      const submit =
        window.__QKB_SUBMIT_TX__ ??
        (async (input: SubmitTxInput): Promise<SubmitTxResult> => {
          // Default path: fall back to eth_sendTransaction with empty data
          // until the contracts worker's ABI + deployed address are pumped.
          // This keeps the screen exercise-able in the happy-path Playwright
          // suite without blocking on the ABI pump.
          const tx = (await provider.request({
            method: 'eth_sendTransaction',
            params: [{ from: input.from, to: input.to, data: '0x' }],
          })) as string;
          return { txHash: tx, pkAddr: input.from };
        });
      const result = await submit({
        from: address,
        to: REGISTRY_ADDRESS_SEPOLIA,
        proof: session.proof,
        publicSignals: session.publicSignals!,
      });
      setTxHash(result.txHash);
      setPkAddr(result.pkAddr);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <PhaseCard step={4} total={4} accent="purple" title={t('register.heading')}>
      <p className="text-slate-400 mb-5">{t('register.intro')}</p>

      {!address ? (
        <button
          type="button"
          onClick={onConnect}
          data-testid="connect-wallet"
          className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white text-sm font-semibold rounded-md"
        >
          {t('register.connect')}
        </button>
      ) : (
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-500 uppercase tracking-widest">
              {t('register.connected')}
            </label>
            <div
              data-testid="wallet-address"
              className="font-mono text-[11px] text-emerald-300 break-all rounded border border-slate-700 bg-slate-900/50 px-3 py-2"
            >
              {address}
            </div>
          </div>

          <button
            type="button"
            onClick={onSubmit}
            disabled={submitting}
            data-testid="submit-register"
            className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-700 disabled:text-slate-500 text-slate-900 text-sm font-semibold rounded-md"
          >
            {submitting ? t('register.submitting') : t('register.submit')}
          </button>
        </div>
      )}

      {txHash && (
        <div data-testid="register-success" className="mt-6 space-y-3">
          <p className="text-emerald-300 text-sm">{t('register.success')}</p>
          <div>
            <label className="block text-xs font-mono text-slate-500 uppercase tracking-widest">
              {t('register.txHash')}
            </label>
            <div
              data-testid="tx-hash"
              className="font-mono text-[11px] text-slate-200 break-all rounded border border-slate-700 bg-slate-900/50 px-3 py-2"
            >
              {txHash}
            </div>
          </div>
          {pkAddr && (
            <div>
              <label className="block text-xs font-mono text-slate-500 uppercase tracking-widest">
                {t('register.pkAddr')}
              </label>
              <div
                data-testid="pk-addr"
                className="font-mono text-[11px] text-slate-200 break-all rounded border border-slate-700 bg-slate-900/50 px-3 py-2"
              >
                {pkAddr}
              </div>
            </div>
          )}
        </div>
      )}

      {error && (
        <div
          data-testid="register-error"
          role="alert"
          className="mt-5 text-red-400 text-sm border border-red-500/40 bg-red-500/10 px-3 py-2 rounded"
        >
          {error}
        </div>
      )}
    </PhaseCard>
  );
}
