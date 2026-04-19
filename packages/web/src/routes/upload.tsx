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
import { buildInclusionPath, type LayersFile } from '../lib/merkleLookup';
import { buildPhase2Witness } from '../lib/witness';
import {
  MockProver,
  proveSplit,
  type IProver,
  type ProofStage,
  type SplitProgress,
} from '../lib/prover';
import { getProverConfig } from '../lib/prover.config';
import {
  loadSession,
  saveSession,
  b64ToBytes,
  bytesToB64,
  hexToBytes,
} from '../lib/session';
import { localizeError, QkbError } from '../lib/errors';
import {
  buildWitnessBundle,
  downloadJson,
  parseProofBundle,
} from '../lib/witnessExport';

type Status =
  | 'idle'
  | 'parsing'
  | 'verifying'
  | 'proving'
  | 'awaiting-offline-proof'
  | 'done'
  | 'error';

type ProveMode = 'mock' | 'offline';

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
  // Split-proof UX: track whether we're currently working on the leaf or
  // chain proof so the progress banner can render "1 / 2 leaf" / "2 / 2
  // chain" copy.
  const [proofSide, setProofSide] = useState<'leaf' | 'chain' | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const [proveMode, setProveMode] = useState<ProveMode>('offline');
  const proofImportRef = useRef<HTMLInputElement>(null);

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
      console.info('[qkb] upload sizes', {
        p7s: p7sBuf.length,
        embeddedContent: parsed.embeddedContent?.length ?? null,
        sessionBinding: sessionBindingBytes.length,
        signedAttrsDer: parsed.signedAttrsDer.length,
        leafCertDer: parsed.leafCertDer.length,
      });

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

      // Split-proof pivot (2026-04-18): build leaf + chain witnesses from
      // the same shared derivations (Bcanon offsets, RDN subject-serial
      // scan, leaf SPKI offsets, leafSpkiCommit, nullifier).
      //
      // trustedListRoot is the Merkle tree root from flattener's
      // `root.json` (rTL), NOT any individual CA's leaf hash. The chain
      // circuit proves MerkleProofPoseidon(intPoseidon, path, indices) ===
      // rTL; the proof only verifies when all three pieces come from the
      // same committed flattener snapshot.
      const { rTL: treeRoot, merklePath, merkleIndices } =
        await fetchMerkleProofForIntermediate(verified.intermediateCertDer);
      const trustedListRoot = treeRoot;
      const witness = await buildPhase2Witness({
        parsed,
        binding: session.binding!,
        bindingBytes,
        trustedListRoot,
        // qesVerify LOTL-resolves the intermediate for leaf-only CAdES
        // (Diia). Thread it through so the witness builder doesn't re-
        // resolve or trip the `no-intermediate` guard when the CMS
        // shipped leaf-only.
        intermediateCertDer: verified.intermediateCertDer,
        merklePath,
        merkleIndices,
      });

      // Shared context saved regardless of mode — /register consumes these
      // fields independent of how the proofs were produced.
      const sharedSave = {
        cadesB64: bytesToB64(p7sBuf),
        leafCertDerB64: bytesToB64(parsed.leafCertDer),
        intCertDerB64: bytesToB64(verified.intermediateCertDer),
        trustedListRoot:
          typeof trustedListRoot === 'string' ? trustedListRoot : String(trustedListRoot),
        circuitVersion: 'QKBPresentationEcdsaLeaf+Chain',
        algorithmTag: verified.algorithmTag,
      } as const;

      if (proveMode === 'offline') {
        // Offline proving path: write a witness bundle the user feeds to
        // `qkb prove` on their host, then re-imports the proofs. The
        // browser prover path OOMs on the 4.5 GB leaf zkey; qkb-cli with
        // --max-old-space-size=16384 handles it fine.
        saveSession(sharedSave);
        const bundle = buildWitnessBundle({
          witness,
          algorithmTag: verified.algorithmTag,
          circuitVersion: 'QKBPresentationEcdsaLeaf+Chain',
        });
        downloadJson('witness.json', bundle);
        setStatus('awaiting-offline-proof');
        return;
      }

      setStatus('proving');
      const prover = await pickProver();
      const controller = new AbortController();
      abortRef.current = controller;
      const start = Date.now();

      const algo = verified.algorithmTag === 1 ? 'ecdsa' : 'rsa';
      const artifacts = getProverConfig(algo);

      const result = await proveSplit(witness, {
        prover,
        artifacts,
        algorithmTag: verified.algorithmTag,
        signal: controller.signal,
        onProgress: (p: SplitProgress) => {
          setStage(p.stage);
          setProofSide(p.side);
          if (p.elapsedMs !== undefined) setElapsedMs(p.elapsedMs);
          else setElapsedMs(Date.now() - start);
        },
      });

      saveSession({
        ...sharedSave,
        proofLeaf: result.proofLeaf,
        publicLeaf: result.publicLeaf,
        proofChain: result.proofChain,
        publicChain: result.publicChain,
      });
      setStatus('done');
    } catch (err) {
      setStatus('error');
      // Surface the raw error object + details to the browser console so
      // parse failures can be diagnosed (QkbError stores the specific
      // reason in .details which the localized banner swallows).
      console.error('[qkb] upload failure:', err);
      if (err && typeof err === 'object' && 'details' in err) {
        console.error('[qkb] upload failure details:', (err as { details?: unknown }).details);
      }
      const base = localizeError(err, { t });
      const details =
        err && typeof err === 'object' && 'details' in err
          ? (err as { details?: Record<string, unknown> }).details
          : undefined;
      const tag = details
        ? [details.reason, details.field, details.got, details.max]
            .filter((v) => v !== undefined && v !== null)
            .join('/')
        : '';
      setError(tag ? `${base} [${tag}]` : base);
    } finally {
      abortRef.current = null;
    }
  };

  const onCancel = (): void => abortRef.current?.abort();

  const onImportProofFile = async (file: File): Promise<void> => {
    setError(null);
    try {
      const raw = await file.text();
      const bundle = parseProofBundle(raw);
      saveSession({
        proofLeaf: bundle.proofLeaf as never,
        publicLeaf: bundle.publicLeaf,
        proofChain: bundle.proofChain as never,
        publicChain: bundle.publicChain,
        circuitVersion: bundle.circuitVersion,
        algorithmTag: bundle.algorithmTag,
      });
      setStatus('done');
    } catch (err) {
      console.error('[qkb] import proof failure:', err);
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const onPickProof = (): void => proofImportRef.current?.click();

  return (
    <PhaseCard step={3} total={4} accent="amber" title={t('upload.heading')}>
      <p className="text-slate-400 mb-5">{t('upload.intro')}</p>

      <fieldset className="mb-5 rounded-lg border border-slate-700 px-4 py-3 text-xs">
        <legend className="px-2 text-slate-400 uppercase tracking-widest text-[10px]">
          Proving mode
        </legend>
        <div className="flex flex-col gap-2 mt-1">
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="radio"
              name="prove-mode"
              data-testid="prove-mode-offline"
              checked={proveMode === 'offline'}
              onChange={() => setProveMode('offline')}
              className="mt-[3px] accent-emerald-500"
            />
            <span>
              <strong className="font-semibold text-emerald-200">
                Offline proving (real)
              </strong>
              <br />
              <span className="text-slate-400">
                Download a witness bundle, run <code className="text-emerald-300">qkb prove</code>{' '}
                locally, re-upload the proof. Required for real Sepolia submits —
                browser tabs OOM on the 4.5 GB leaf zkey.
              </span>
            </span>
          </label>
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="radio"
              name="prove-mode"
              data-testid="prove-mode-mock"
              checked={proveMode === 'mock'}
              onChange={() => setProveMode('mock')}
              className="mt-[3px] accent-amber-500"
            />
            <span>
              <strong className="font-semibold text-amber-200">
                Mock prover (UI testing only)
              </strong>
              <br />
              <span className="text-slate-400">
                Emits fake Groth16 points. On-chain register{' '}
                <strong>will revert with InvalidProof</strong>. Use for local
                /register UI checks, not real submits.
              </span>
            </span>
          </label>
        </div>
      </fieldset>

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
            {proofSide && (
              <>
                <span data-testid="prove-side">
                  {proofSide === 'leaf' ? '1 / 2 leaf' : '2 / 2 chain'}
                </span>
                <span>·</span>
              </>
            )}
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

      {status === 'awaiting-offline-proof' && (
        <div
          data-testid="upload-awaiting-offline"
          className="mt-5 space-y-3 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100"
        >
          <p className="font-semibold">
            Witness bundle downloaded. Run the CLI to produce real proofs:
          </p>
          <pre className="overflow-x-auto rounded bg-slate-900/70 border border-slate-700 px-3 py-2 text-[11px] text-emerald-300 font-mono">
{`NODE_OPTIONS=--max-old-space-size=16384 \\
  pnpm --filter @qkb/cli start -- prove ~/Downloads/witness.json`}
          </pre>
          <p className="text-xs text-slate-400">
            Outputs <code className="text-emerald-300">./proofs/proof-bundle.json</code>.
            First run downloads ~6.4 GB of ceremony artifacts; subsequent runs hit the
            local cache. Plan for ~6–20 min proving time depending on CPU.
          </p>
          <div className="flex gap-2 pt-1">
            <button
              type="button"
              onClick={onPickProof}
              data-testid="import-proof-pick"
              className="px-3 py-1.5 bg-emerald-500 hover:bg-emerald-400 text-slate-900 text-xs font-semibold rounded"
            >
              Import proof bundle
            </button>
            <input
              ref={proofImportRef}
              type="file"
              accept=".json,application/json"
              data-testid="proof-import-input"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void onImportProofFile(f);
              }}
            />
          </div>
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

/**
 * Match the verified intermediate to a flattener-committed CA entry and
 * derive the Merkle inclusion path + indices + tree root the chain
 * circuit expects. All three must come from the same flattener snapshot —
 * mixing a cached `root.json` with a newer `layers.json` produces a proof
 * that looks valid locally but reverts on-chain with RootMismatch.
 */
async function fetchMerkleProofForIntermediate(
  intermediateDer: Uint8Array,
): Promise<{ rTL: string; merklePath: string[]; merkleIndices: number[] }> {
  const [rootRes, trustedCasRes, layersRes] = await Promise.all([
    fetch('./trusted-cas/root.json'),
    fetch('./trusted-cas/trusted-cas.json'),
    fetch('./trusted-cas/layers.json'),
  ]);
  if (!rootRes.ok) throw new Error(`root.json fetch failed: ${rootRes.status}`);
  if (!trustedCasRes.ok) throw new Error(`trusted-cas.json fetch failed: ${trustedCasRes.status}`);
  if (!layersRes.ok) throw new Error(`layers.json fetch failed: ${layersRes.status}`);

  const root = (await rootRes.json()) as { rTL: string; treeDepth: number };
  const trustedCas = (await trustedCasRes.json()) as TrustedCasFile;
  const layers = (await layersRes.json()) as LayersFile;

  if (layers.depth !== root.treeDepth) {
    throw new Error(
      `flattener depth mismatch: root.json=${root.treeDepth} vs layers.json=${layers.depth}`,
    );
  }

  const intB64 = toBase64(intermediateDer);
  const entry = trustedCas.cas.find((c) => c.certDerB64 === intB64);
  if (!entry) {
    throw new Error(
      `intermediate cert not found in trusted-cas.json — cannot build Merkle proof (is the flattener snapshot stale?)`,
    );
  }

  const leafHash = layers.layers[0]?.[entry.merkleIndex];
  const entryHash = entry.poseidonHash;
  if (!leafHash || !entryHash || leafHash.toLowerCase() !== entryHash.toLowerCase()) {
    throw new Error(
      `layers[0][${entry.merkleIndex}] (${leafHash}) disagrees with trusted-cas.cas.poseidonHash (${entryHash}) — stale pump`,
    );
  }

  // Delegate to merkleLookup — it fills missing siblings with zero-subtree
  // hashes (zero[level] = Poseidon(zero[level-1], zero[level-1])), not
  // literal 0, matching MerkleProofPoseidon's on-circuit expectation.
  const proof = await buildInclusionPath(entry.merkleIndex, layers);

  const computedRootHex = proof.rootHex.toLowerCase();
  if (computedRootHex !== root.rTL.toLowerCase()) {
    throw new Error(
      `computed inclusion-path root ${computedRootHex} disagrees with committed root ${root.rTL} — stale layers.json`,
    );
  }

  return { rTL: root.rTL, merklePath: proof.pathHex, merkleIndices: proof.indices };
}

function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
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
