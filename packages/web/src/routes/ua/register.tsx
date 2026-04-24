/**
 * /ua/register — Step 4 of the UA QKB/2.0 flow.
 *
 * Session invariants (per M9 spec):
 *   - session.country === "UA" AND session.bindingV2 present: required to even
 *     render the submit path. Missing → show the "no V2 bundle" banner with a
 *     link back to /ua/generate.
 *   - session.{proofLeafV4, publicLeafV4, proofChainV4, publicChainV4}: set by
 *     /ua/upload. Missing → surface the "no V4 proof bundle" banner and link
 *     back to /ua/upload.
 *
 * Submit path: build RegisterArgsV4 from the V4 public signals, ABI-encode
 * via `encodeV4RegisterCalldata`, ship through `eth_sendTransaction`. On
 * revert, `classifyV4WalletRevert` maps the custom-error selector to a typed
 * QkbError so the UI shows "Nullifier already used" instead of the raw
 * hex-selector message.
 *
 * Playwright hook: `window.__QKB_SUBMIT_TX_V4__` short-circuits the encode +
 * submit path and returns a deterministic tx hash. Same shape as the V3
 * register hook so tests can keep the same stubbing pattern.
 */
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from '@tanstack/react-router';
import { PhaseCard } from '../../components/PhaseCard';
import { useCountry } from '../../components/CountryScope';
import { localizeError } from '../../lib/errors';
import {
  assertRegisterArgsV4Shape,
  classifyV4WalletRevert,
  encodeV4RegisterCalldata,
  leafInputsV4AgeFromPublicSignals,
  type LeafInputsV4AgeCapable,
} from '../../lib/registryV4';
import { loadSession } from '../../lib/session';
import type { Groth16Proof } from '../../lib/prover';
import {
  packProof as packGroth16Proof,
  type ChainInputs,
  type SolidityProof,
} from '../../lib/registry';

type Eip1193Request = (args: { method: string; params?: unknown[] }) => Promise<unknown>;
interface Eip1193Provider {
  request: Eip1193Request;
  isMetaMask?: boolean;
}

interface SubmitTxV4Input {
  readonly from: string;
  readonly to: `0x${string}`;
  readonly pk: `0x04${string}`;
  readonly proofLeaf: Groth16Proof;
  readonly publicLeaf: readonly string[];
  readonly proofChain: Groth16Proof;
  readonly publicChain: readonly string[];
}

interface SubmitTxV4Result {
  readonly txHash: string;
  readonly pkAddr: string;
}

declare global {
  interface Window {
    ethereum?: Eip1193Provider;
    __QKB_ETHEREUM__?: Eip1193Provider;
    __QKB_SUBMIT_TX_V4__?: (input: SubmitTxV4Input) => Promise<SubmitTxV4Result>;
  }
}

export function UaRegisterScreen() {
  const { t } = useTranslation();
  const { config } = useCountry();
  const navigate = useNavigate();
  const session = useMemo(() => loadSession(), []);

  const [address, setAddress] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);
  const [pkAddr, setPkAddr] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Hard session-invariant guards (per team-lead's note 3).
  const missingV2 = session.country !== 'UA' || !session.bindingV2;
  const missingProofs =
    !session.proofLeafV4 ||
    !session.proofChainV4 ||
    !session.publicLeafV4 ||
    !session.publicChainV4;

  useEffect(() => {
    // When the user land-deeps here without having gone through /ua/generate,
    // bounce them back so they don't fill out a stale form. Same for the
    // proof bundle — /ua/upload is the producer.
    if (missingV2) {
      const timer = setTimeout(() => navigate({ to: '/ua/generate' }), 2500);
      return () => clearTimeout(timer);
    }
    return undefined;
  }, [missingV2, navigate]);

  if (missingV2) {
    return (
      <PhaseCard step={4} total={4} accent="purple" title={t('register.heading')}>
        <p data-testid="register-missing-v2" className="text-amber-300">
          {t('ua.register.missingV2')}
        </p>
        <p className="mt-3 text-xs text-slate-500">
          <Link to="/ua/generate" className="underline text-emerald-400">
            {t('ua.register.backToGenerate')}
          </Link>
        </p>
      </PhaseCard>
    );
  }

  if (missingProofs) {
    return (
      <PhaseCard step={4} total={4} accent="purple" title={t('register.heading')}>
        <p data-testid="register-missing-proof" className="text-amber-300">
          {t('ua.register.missingProof')}
        </p>
        <p className="mt-3 text-xs text-slate-500">
          <Link to="/ua/upload" className="underline text-emerald-400">
            {t('ua.register.backToUpload')}
          </Link>
        </p>
      </PhaseCard>
    );
  }

  const proofLeaf = session.proofLeafV4!;
  const publicLeaf = session.publicLeafV4!;
  const proofChain = session.proofChainV4!;
  const publicChain = session.publicChainV4!;
  const sessionPk = session.pubkeyUncompressedHex ?? '';
  const normalizedPk = (
    sessionPk.startsWith('0x04')
      ? sessionPk
      : sessionPk.startsWith('04')
        ? `0x${sessionPk}`
        : null
  ) as `0x04${string}` | null;

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
      try {
        await provider.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: `0x${config.chainId.toString(16)}` }],
        });
      } catch (switchErr) {
        console.warn('[qkb/ua] wallet_switchEthereumChain failed', switchErr);
      }
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
    if (!normalizedPk) {
      setError(t('ua.register.missingV2'));
      return;
    }
    setSubmitting(true);
    try {
      const currentChain = (await provider.request({ method: 'eth_chainId' })) as string;
      const currentChainId = parseInt(currentChain, 16);
      if (currentChainId !== config.chainId) {
        setError(
          t('ua.register.wrongChain', {
            expected: config.chainId,
            actual: currentChainId,
          }),
        );
        setSubmitting(false);
        return;
      }
      const submit =
        window.__QKB_SUBMIT_TX_V4__ ??
        (async (input: SubmitTxV4Input): Promise<SubmitTxV4Result> => {
          const leafInputs: LeafInputsV4AgeCapable = leafInputsV4AgeFromPublicSignals(
            input.publicLeaf,
          );
          const chainInputs: ChainInputs = {
            rTL: toHex32(input.publicChain[0]!),
            algorithmTag: input.publicChain[1] === '1' ? 1 : 0,
            leafSpkiCommit: toHex32(input.publicChain[2]!),
          };
          const args = {
            pk: input.pk,
            proofLeaf: packGroth16Proof(input.proofLeaf) as SolidityProof,
            leafInputs,
            proofChain: packGroth16Proof(input.proofChain) as SolidityProof,
            chainInputs,
          };
          assertRegisterArgsV4Shape(args);
          const data = encodeV4RegisterCalldata(args, {
            dobCommit: leafInputs.dobCommit,
            dobSupported: leafInputs.dobSupported,
          });
          const tx = (await provider.request({
            method: 'eth_sendTransaction',
            params: [{ from: input.from, to: input.to, data }],
          })) as string;
          // V4 derives the bound address on-chain from leafInputs.pkX/pkY via
          // `_pkAddressFromLimbs`; we don't observe it in the response, so
          // surface `from` as a placeholder until a BindingRegistered event
          // listener lands.
          return { txHash: tx, pkAddr: input.from };
        });
      const result = await submit({
        from: address,
        to: config.registry,
        pk: normalizedPk,
        proofLeaf,
        publicLeaf,
        proofChain,
        publicChain,
      });
      setTxHash(result.txHash);
      setPkAddr(result.pkAddr);
    } catch (err) {
      console.error('[qkb/ua] register failure:', err);
      const classified = classifyV4WalletRevert(err);
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
      <p className="text-slate-400 mb-3">{t('ua.register.intro')}</p>
      <dl className="mb-6 grid grid-cols-1 gap-2 text-[11px] font-mono text-slate-500 sm:grid-cols-2">
        <div>
          <dt className="uppercase tracking-widest text-[10px] text-slate-600">
            {t('ua.register.registry')}
          </dt>
          <dd className="break-all text-slate-300" data-testid="ua-register-addr">
            {config.registry}
          </dd>
        </div>
        <div>
          <dt className="uppercase tracking-widest text-[10px] text-slate-600">
            {t('ua.register.chainId')}
          </dt>
          <dd className="text-slate-300">{config.chainId}</dd>
        </div>
      </dl>

      {!address ? (
        <button
          type="button"
          onClick={() => void onConnect()}
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
            onClick={() => void onSubmit()}
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

function toHex32(v: string): `0x${string}` {
  const big = v.startsWith('0x') ? BigInt(v) : BigInt(v);
  return `0x${big.toString(16).padStart(64, '0')}` as `0x${string}`;
}
