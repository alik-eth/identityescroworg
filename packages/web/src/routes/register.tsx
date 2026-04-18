/**
 * /register — Step 4 of the binding flow.
 *
 * Reads the split-proof bundle (proofLeaf + publicLeaf, proofChain +
 * publicChain — 2026-04-18 pivot) from sessionStorage and submits a
 * `register(proofLeaf, leafInputs, proofChain, chainInputs)` call to
 * QKBRegistryV3 on Sepolia via the user's EIP-1193 wallet. The registry
 * address is still a TODO-stub today — the lead pumps the deployed
 * Sepolia address into `fixtures/contracts/sepolia.json` after the V3
 * deploy; this file then imports it.
 *
 * The wallet + submit pipeline is injectable:
 *   - `window.__QKB_ETHEREUM__` lets Playwright stub EIP-1193 without a real
 *     MetaMask.
 *   - `window.__QKB_SUBMIT_TX__` lets Playwright bypass ABI encoding and
 *     return a deterministic tx hash + bound address for assertion.
 *
 * Both hooks are `undefined` in the production bundle; the default path
 * falls back to the real `window.ethereum` and a minimal hand-rolled
 * `eth_sendTransaction` flow. ABI encoding of the V3 split-proof calldata
 * is still a follow-up — it lands when the Sepolia V3 deploy address is
 * pumped (orchestration §S5).
 */
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { PhaseCard } from '../components/PhaseCard';
import { localizeError } from '../lib/errors';
import type { Groth16Proof } from '../lib/prover';
import { classifyWalletRevert } from '../lib/registry';
import { loadSession } from '../lib/session';

// TODO: lead pumps real address after `DeployQKBRegistry.s.sol` runs on Sepolia.
// The constant lives here so a find-and-replace during the pump step is a
// one-liner. Do NOT hardcode it in routes/tests — always import.
const REGISTRY_ADDRESS_SEPOLIA = '0x7F36aF783538Ae8f981053F2b0E45421a1BF4815';

type Eip1193Request = (args: { method: string; params?: unknown[] }) => Promise<unknown>;
interface Eip1193Provider {
  request: Eip1193Request;
  isMetaMask?: boolean;
}

interface SubmitTxInput {
  from: string;
  to: string;
  // Split-proof pivot (2026-04-18): V3's register() takes a leaf proof +
  // leaf 13-signal inputs AND a chain proof + chain 3-signal inputs. The
  // opaque `Groth16Proof` shape carries the snarkjs a/b/c triples; the
  // submit-tx implementation is responsible for packing them into the
  // Solidity struct layout and encoding the register(...) calldata.
  proofLeaf: Groth16Proof;
  publicLeaf: readonly string[];
  proofChain: Groth16Proof;
  publicChain: readonly string[];
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

  // Split-proof session (2026-04-18 pivot). Fall back to legacy single-proof
  // fields so a mid-flight session upgrade path doesn't wipe the user's work,
  // but refuse to proceed without the full split bundle because V3's
  // register() requires BOTH proofs.
  const proofLeaf = session.proofLeaf ?? null;
  const proofChain = session.proofChain ?? null;
  const publicLeaf = session.publicLeaf ?? null;
  const publicChain = session.publicChain ?? null;

  if (!proofLeaf || !proofChain || !publicLeaf || !publicChain) {
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
        proofLeaf,
        publicLeaf,
        proofChain,
        publicChain,
      });
      setTxHash(result.txHash);
      setPkAddr(result.pkAddr);
    } catch (err) {
      // Map V3 custom-error selectors (NullifierUsed, RootMismatch,
      // AlreadyBound, BindingTooOld, AgeExceeded) to localized QkbError copy
      // before falling back to the raw wallet message.
      const classified = classifyWalletRevert(err);
      if (classified) {
        setError(localizeError(classified, { t }));
      } else {
        setError(err instanceof Error ? err.message : String(err));
      }
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
