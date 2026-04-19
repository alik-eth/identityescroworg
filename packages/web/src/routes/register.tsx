/**
 * /register — Step 4 of the binding flow.
 *
 * Reads the split-proof bundle (proofLeaf + publicLeaf, proofChain +
 * publicChain — 2026-04-18 pivot) from sessionStorage, ABI-encodes a V3
 * `register(proofLeaf, leafInputs, proofChain, chainInputs)` call against
 * the pumped QKBRegistryV3 ABI, and submits via the user's EIP-1193
 * wallet. Registry address + chainId come from the lead-pumped
 * `fixtures/contracts/sepolia.json`.
 *
 * The wallet + submit pipeline is injectable:
 *   - `window.__QKB_ETHEREUM__` lets Playwright stub EIP-1193 without a real
 *     MetaMask.
 *   - `window.__QKB_SUBMIT_TX__` lets Playwright bypass ABI encoding and
 *     return a deterministic tx hash + bound address for assertion. The
 *     default path does real calldata encoding + eth_sendTransaction.
 */
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { PhaseCard } from '../components/PhaseCard';
import { localizeError } from '../lib/errors';
import type { Groth16Proof } from '../lib/prover';
import {
  assertRegisterArgsShape,
  buildRegisterArgsFromSignals,
  classifyWalletRevert,
  encodeV3RegisterCalldata,
} from '../lib/registry';
import { loadSession } from '../lib/session';
import sepoliaV3 from '../../fixtures/contracts/sepolia.json';

// V3 deploy coordinates pumped from the contracts worker post-deploy.
// `registryVersion: "v3"` gates the import; a regression to V2 should
// surface as a loud boot-time assert here rather than a silent calldata
// mismatch at submit time.
const REGISTRY_ADDRESS_SEPOLIA = sepoliaV3.registry as `0x${string}`;
if (sepoliaV3.registryVersion !== 'v3') {
  // Throw at module load — if this SPA bundle was built against a stale
  // sepolia.json, /register would otherwise send V3-shaped calldata to a
  // V2 contract address. Fail loud.
  throw new Error(
    `sepolia.json registryVersion must be 'v3' (got '${sepoliaV3.registryVersion}')`,
  );
}

type Eip1193Request = (args: { method: string; params?: unknown[] }) => Promise<unknown>;
interface Eip1193Provider {
  request: Eip1193Request;
  isMetaMask?: boolean;
}

interface SubmitTxInput {
  from: string;
  to: string;
  /** Uncompressed secp256k1 pubkey from /generate — used only for shape
   *  validation via assertRegisterArgsShape; V3 register() derives the
   *  bound address on-chain from leafInputs.pkX/pkY, not from msg.sender. */
  pk: `0x04${string}`;
  // Split-proof pivot (2026-04-18): V3's register() takes a leaf proof +
  // leaf 13-signal inputs AND a chain proof + chain 3-signal inputs. The
  // opaque `Groth16Proof` shape carries the snarkjs a/b/c triples.
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
    const sessionPk = session.pubkeyUncompressedHex;
    if (!sessionPk) {
      setError(t('register.noBundle'));
      return;
    }
    // Normalize to the `0x04...` uncompressed-SEC1 form the V3 LeafInputs
    // expects. /generate stores either `04...` or `0x04...` depending on
    // bundle vintage; tolerate both.
    const normalizedPk = (sessionPk.startsWith('0x04')
      ? sessionPk
      : sessionPk.startsWith('04')
        ? `0x${sessionPk}`
        : null) as `0x04${string}` | null;
    if (!normalizedPk) {
      setError(t('register.noBundle'));
      return;
    }

    setSubmitting(true);
    try {
      const submit =
        window.__QKB_SUBMIT_TX__ ??
        (async (input: SubmitTxInput): Promise<SubmitTxResult> => {
          // Default path: ABI-encode the V3 register(proofLeaf, leafInputs,
          // proofChain, chainInputs) calldata and ship it via
          // eth_sendTransaction. buildRegisterArgsFromSignals projects the
          // session-persisted publicLeaf/publicChain arrays into the
          // Solidity struct shapes; assertRegisterArgsShape catches drift
          // (e.g. a leaf/chain leafSpkiCommit mismatch) before we hit the
          // wallet.
          const args = buildRegisterArgsFromSignals(
            input.pk,
            input.proofLeaf,
            input.publicLeaf,
            input.proofChain,
            input.publicChain,
          );
          assertRegisterArgsShape(args);
          const data = encodeV3RegisterCalldata(args);
          const tx = (await provider.request({
            method: 'eth_sendTransaction',
            params: [{ from: input.from, to: input.to, data }],
          })) as string;
          // V3 derives the bound address on-chain from leafInputs.pkX/pkY
          // via QKBVerifier.toPkAddress — the SPA doesn't observe the
          // derivation, so we surface input.from as a placeholder pkAddr
          // until a BindingRegistered event listener lands.
          return { txHash: tx, pkAddr: input.from };
        });
      const result = await submit({
        from: address,
        to: REGISTRY_ADDRESS_SEPOLIA,
        pk: normalizedPk,
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
