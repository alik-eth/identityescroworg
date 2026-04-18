/**
 * /upload — Step 3 of the binding flow.
 *
 * Accepts a .p7s emitted by an external QES tool, runs the full off-circuit
 * verification (lib/qesVerify.ts), then builds a zero-knowledge proof using
 * the swappable IProver. Default prover is `MockProver` so the happy-path
 * Playwright suite runs in seconds; the real SnarkjsProver is opted in by
 * setting `window.__QKB_REAL_PROVER__ = true` in the nightly e2e (and
 * eventually by a UI toggle once the 3-minute proving time is acceptable).
 *
 * Success path writes `cadesB64`, `proof`, `publicSignals`, `leafCertDerB64`,
 * `intCertDerB64`, `circuitVersion`, `trustedListRoot`, `algorithmTag` into
 * sessionStorage and redirects to /register. Failures render a typed error
 * banner via localizeError().
 */
import { useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from '@tanstack/react-router';
import { PhaseCard } from '../components/PhaseCard';
import { parseCades } from '../lib/cades';
import { verifyQes, type TrustedCasFile, type VerifyInput, type VerifyOk } from '../lib/qesVerify';
import { buildLeafWitness } from '../lib/witness';
import {
  MockProver,
  type IProver,
  type ProofProgress,
  type ProofStage,
  type ProveResult,
} from '../lib/prover';
import { loadArtifacts, validateUrlsJson } from '../lib/circuitArtifacts';
import urlsJson from '../../fixtures/circuits/urls.json';
import {
  loadSession,
  saveSession,
  b64ToBytes,
  bytesToB64,
  hexToBytes,
} from '../lib/session';
import { localizeError, QkbError } from '../lib/errors';

type Status = 'idle' | 'parsing' | 'verifying' | 'proving' | 'done' | 'error';

declare global {
  interface Window {
    __QKB_REAL_PROVER__?: boolean;
    __QKB_PROVER__?: IProver;
    /**
     * Test-only escape hatch for the Playwright flow suite. When set, the
     * /upload screen skips the real verifyQes() call and uses this verifier
     * instead. Production builds never touch this — it's a `window.` hook
     * purely for the flow harness to inject a deterministic Ok result
     * without having to rebuild the trusted-cas fixture to match a
     * browser-minted test CA chain.
     */
    __QKB_VERIFY__?: (input: VerifyInput) => Promise<VerifyOk>;
  }
}

export function UploadScreen() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const session = useMemo(() => loadSession(), []);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [status, setStatus] = useState<Status>('idle');
  const [stage, setStage] = useState<ProofStage | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  if (!session.bcanonB64 || !session.pubkeyUncompressedHex) {
    return (
      <PhaseCard step={3} total={4} accent="amber" title={t('upload.heading')}>
        <p data-testid="upload-missing" className="text-amber-300">
          {t('upload.missingBinding')}
        </p>
      </PhaseCard>
    );
  }

  const onPick = (): void => fileInputRef.current?.click();

  const onFile = async (file: File): Promise<void> => {
    setError(null);
    setStatus('parsing');
    try {
      const sessionBindingBytes = b64ToBytes(session.bcanonB64!);
      const pkBytes = hexToBytes(session.pubkeyUncompressedHex!);

      const p7sBuf = new Uint8Array(await file.arrayBuffer());
      const parsed = parseCades(p7sBuf);

      // If the user's QES tool produced an *attached* CAdES (Diia default,
      // many Szafir variants), the binding JSON lives inside the CMS as
      // `embeddedContent`. Use that as the source of truth. Detached CAdES
      // falls back to the session copy.
      //
      // When the embedded copy differs from the session copy we must bail
      // hard: the proof commits to the signed pk, the on-chain register()
      // call needs msg.sender's pk to match — so a stale session copy
      // would silently produce a proof of the wrong key, failing at
      // registry.register() on Sepolia with no clear message. Parse the
      // embedded binding, extract its `pk`, and compare against the
      // session pk.
      const bindingBytes = parsed.embeddedContent ?? sessionBindingBytes;
      if (
        parsed.embeddedContent &&
        !bytesEqual(parsed.embeddedContent, sessionBindingBytes)
      ) {
        const signedPkHex = extractPkFromEmbedded(parsed.embeddedContent);
        const sessionPkHex = (session.pubkeyUncompressedHex ?? '').toLowerCase();
        const signedPkNorm = signedPkHex.toLowerCase().replace(/^0x/, '');
        const sessionPkNorm = sessionPkHex.replace(/^0x/, '');
        if (signedPkNorm !== sessionPkNorm) {
          throw new QkbError('binding.pkMismatch', {
            signedPk: signedPkHex,
            sessionPk: sessionPkHex,
          });
        }
      }

      setStatus('verifying');
      const trustedCas = await fetchTrustedCas();
      const verifier = window.__QKB_VERIFY__ ?? verifyQes;
      const verified = await verifier({
        parsed,
        binding: session.binding!,
        bindingBytes,
        expectedPk: pkBytes,
        trustedCas,
      });

      // Build witness for the leaf circuit. Split-proof pivot: the leaf is
      // derived from the same shared derivations as the chain, but this
      // screen still drives only the leaf proof — W2 pumps the chain proof
      // into the register() call once the chain zkey URL lands from the
      // circuits ceremony.
      const witness = await buildLeafWitness({
        parsed,
        binding: session.binding!,
        bindingBytes,
      });

      setStatus('proving');
      const prover = await pickProver();
      const controller = new AbortController();
      abortRef.current = controller;
      const start = Date.now();

      let wasmUrl = '';
      let zkeyUrl = '';
      if (window.__QKB_REAL_PROVER__) {
        const urls = validateUrlsJson(urlsJson, 'ecdsa');
        const artifacts = await loadArtifacts('ecdsa', urls, { signal: controller.signal });
        wasmUrl = blobUrl(artifacts.wasmBytes, 'application/wasm');
        zkeyUrl = blobUrl(artifacts.zkeyBytes, 'application/octet-stream');
      }

      const result: ProveResult = await prover.prove(witness as unknown as Record<string, unknown>, {
        wasmUrl,
        zkeyUrl,
        signal: controller.signal,
        onProgress: (p: ProofProgress) => {
          setStage(p.stage);
          if (p.elapsedMs !== undefined) setElapsedMs(p.elapsedMs);
          else setElapsedMs(Date.now() - start);
        },
      });

      saveSession({
        cadesB64: bytesToB64(p7sBuf),
        proof: result.proof,
        publicSignals: result.publicSignals,
        leafCertDerB64: bytesToB64(parsed.leafCertDer),
        intCertDerB64: bytesToB64(parsed.intermediateCertDer ?? new Uint8Array()),
        trustedListRoot: trustedCas.cas[0]?.poseidonHash ?? '0x',
        circuitVersion:
          (urlsJson as { ceremony?: { circuit?: string } }).ceremony?.circuit ??
          'QKBPresentationEcdsaLeaf',
        algorithmTag: verified.algorithmTag,
      });
      setStatus('done');
    } catch (err) {
      setStatus('error');
      // Surface the raw error object + details to the browser console so
      // parse failures can be diagnosed (QkbError stores the specific
      // reason in .details which the localized banner swallows).
      console.error('[qkb] upload failure:', err);
      const base = localizeError(err, { t });
      const details =
        err && typeof err === 'object' && 'details' in err
          ? (err as { details?: Record<string, unknown> }).details
          : undefined;
      const reason = details && typeof details.reason === 'string' ? details.reason : undefined;
      setError(reason ? `${base} [${reason}]` : base);
    } finally {
      abortRef.current = null;
    }
  };

  const onCancel = (): void => abortRef.current?.abort();

  return (
    <PhaseCard step={3} total={4} accent="amber" title={t('upload.heading')}>
      <p className="text-slate-400 mb-5">{t('upload.intro')}</p>

      <div
        data-testid="drop-zone"
        onClick={onPick}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          const f = e.dataTransfer.files[0];
          if (f) void onFile(f);
        }}
        className="cursor-pointer rounded-xl border-2 border-dashed border-slate-700 hover:border-emerald-500/60 px-6 py-10 text-center text-slate-400 text-sm"
      >
        {t('upload.dropP7s')}
        <input
          ref={fileInputRef}
          type="file"
          accept=".p7s,application/pkcs7-signature,application/x-pkcs7-signature"
          data-testid="file-input"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void onFile(f);
          }}
        />
      </div>

      {status === 'verifying' && (
        <p data-testid="upload-verifying" className="mt-5 text-sm text-slate-300">
          {t('upload.verifying')}
        </p>
      )}

      {status === 'proving' && (
        <div className="mt-5 space-y-2" data-testid="upload-proving">
          <p className="text-sm text-slate-300">{t('upload.proving')}</p>
          <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
            <span data-testid="prove-stage">{stage && t(`upload.stage${cap(stage)}`)}</span>
            <span>·</span>
            <span>
              {t('upload.elapsed')} {(elapsedMs / 1000).toFixed(1)}s
            </span>
          </div>
          <button
            type="button"
            onClick={onCancel}
            className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded"
          >
            {t('upload.cancelProof')}
          </button>
        </div>
      )}

      {status === 'done' && (
        <div data-testid="upload-done" className="mt-5 space-y-3">
          <p className="text-emerald-300 text-sm">{t('upload.proofReady')}</p>
          <button
            type="button"
            onClick={() => navigate({ to: '/register' })}
            data-testid="upload-next"
            className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-900 text-sm font-semibold rounded"
          >
            {t('common.continue')}
          </button>
        </div>
      )}

      {error && (
        <div
          data-testid="upload-error"
          role="alert"
          className="mt-5 text-red-400 text-sm border border-red-500/40 bg-red-500/10 px-3 py-2 rounded"
        >
          {error}
        </div>
      )}
    </PhaseCard>
  );
}

async function pickProver(): Promise<IProver> {
  if (typeof window !== 'undefined' && window.__QKB_PROVER__) return window.__QKB_PROVER__;
  if (typeof window !== 'undefined' && window.__QKB_REAL_PROVER__) {
    // Lazy-load the SnarkjsProver path so a default SPA build doesn't bundle
    // the snarkjs dependency — that keeps the static tarball small and
    // lets Task-15 ship the mock flow without snarkjs installed at all.
    const mod = await import('../lib/prover');
    return new mod.SnarkjsProver();
  }
  return new MockProver();
}

async function fetchTrustedCas(): Promise<TrustedCasFile> {
  const res = await fetch('./trusted-cas/trusted-cas.json');
  if (!res.ok) throw new Error(`trusted-cas fetch failed: ${res.status}`);
  return (await res.json()) as TrustedCasFile;
}

function blobUrl(bytes: Uint8Array, type: string): string {
  const ab = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(ab).set(bytes);
  return URL.createObjectURL(new Blob([ab], { type }));
}

function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Pull the `pk` hex string out of a JCS-canonical binding JSON buffer.
 * Parsing the JSON is safe here — it came out of a QES signature so
 * its shape has already been vouched for; a malformed one would later
 * blow up in the witness offset scan. Returns empty string on parse
 * failure so the pk-mismatch check simply trips the hard error below.
 */
function extractPkFromEmbedded(content: Uint8Array): string {
  try {
    const json = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(content));
    return typeof json?.pk === 'string' ? json.pk : '';
  } catch {
    return '';
  }
}
