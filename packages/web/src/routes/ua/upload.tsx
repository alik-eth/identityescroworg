/**
 * /ua/upload — Step 3 of the UA QKB/2.0 flow.
 *
 * Accepts a .p7s produced by Diia QES against the QKB/2.0 binding emitted
 * by /ua/generate. Runs the existing V3 CMS + QES verification pipeline,
 * builds a Phase-2 witness against the JCS-canonicalised V2 binding, then
 * extends the V3 public-leaf (13 signals) to the V4 UA shape (16 signals)
 * via `buildUaLeafPublicSignalsV4`, which prepends the Diia DOB extraction.
 *
 * Proving strategy (Commit 4b):
 *   - Default: `MockProver` so the click-through UX works instantly against
 *     the real UA registry calldata in Commit 4. A real zkey run stays a
 *     follow-up since the 3.8 GB UA leaf zkey OOMs browsers — rapidsnark
 *     CLI path will land after this.
 *   - Tests: `window.__QKB_PROVER__` injection keeps Playwright + vitest on
 *     the deterministic MockProver path.
 *
 * Session invariants (enforced before any work):
 *   - `session.country === "UA"` AND `session.bindingV2` AND `session.bcanonV2B64`
 *     required. Missing → "missing V2 bundle" banner linking back to /ua/generate.
 */
import { useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from '@tanstack/react-router';
import { PhaseCard } from '../../components/PhaseCard';
import { useCountry } from '../../components/CountryScope';
import { parseCades } from '../../lib/cades';
import { verifyQes, type TrustedCasFile, type VerifyInput, type VerifyOk } from '../../lib/qesVerify';
import { buildInclusionPath, type LayersFile } from '../../lib/merkleLookup';
import type { TrustedCa } from '../../lib/merkleLookup';
import { buildPhase2Witness } from '../../lib/witness';
import {
  MockProver,
  proveSplit,
  type IProver,
  type SplitProgress,
  type ProofStage,
} from '../../lib/prover';
import {
  buildPolicyInclusionProof,
  buildPolicyTreeFromLeaves,
} from '../../lib/policyTree';
import { buildPolicyLeafV1 } from '../../lib/bindingV2';
import uaPolicySeed from '../../../../../fixtures/declarations/ua/policy-v1.json';
import {
  buildUaLeafPublicSignalsV4,
} from '../../lib/uaProofPipeline';
import {
  loadSession,
  saveSession,
  b64ToBytes,
  bytesToB64,
  hexToBytes,
} from '../../lib/session';
import { localizeError, QkbError } from '../../lib/errors';

type Status =
  | 'idle'
  | 'parsing'
  | 'verifying'
  | 'witness'
  | 'proving'
  | 'done'
  | 'error';

declare global {
  interface Window {
    __QKB_UA_PROVER__?: IProver;
    __QKB_UA_VERIFY__?: (input: VerifyInput) => Promise<VerifyOk>;
    __QKB_UA_TRUSTED_CAS__?: TrustedCasFile;
    __QKB_UA_LAYERS__?: LayersFile;
    __QKB_UA_MERKLE_ROOT__?: { rTL: string; treeDepth: number };
  }
}

export function UaUploadScreen() {
  const { t } = useTranslation();
  const { country } = useCountry();
  const navigate = useNavigate();
  const session = useMemo(() => loadSession(), []);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [status, setStatus] = useState<Status>('idle');
  const [stage, setStage] = useState<ProofStage | null>(null);
  const [proofSide, setProofSide] = useState<'leaf' | 'chain' | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const missingV2 =
    session.country !== 'UA' ||
    !session.bindingV2 ||
    !session.bcanonV2B64 ||
    !session.pubkeyUncompressedHex;

  if (missingV2) {
    return (
      <PhaseCard step={3} total={4} accent="amber" title={t('upload.heading')}>
        <p data-testid="upload-missing-v2" className="text-amber-300">
          {t('ua.upload.missingV2')}
        </p>
        <p className="mt-3 text-xs text-slate-500">
          <Link to="/ua/generate" className="underline text-emerald-400">
            {t('ua.register.backToGenerate')}
          </Link>
        </p>
      </PhaseCard>
    );
  }

  const onPick = (): void => fileInputRef.current?.click();

  const onFile = async (file: File): Promise<void> => {
    setError(null);
    setStatus('parsing');
    setStage(null);
    setProofSide(null);
    setElapsedMs(0);
    try {
      const sessionBindingBytes = b64ToBytes(session.bcanonV2B64!);
      const pkBytes = hexToBytes(session.pubkeyUncompressedHex!);

      const p7sBuf = new Uint8Array(await file.arrayBuffer());
      const parsed = parseCades(p7sBuf);

      // Per V3 upload: prefer embedded content when the CMS was attached,
      // and enforce pk agreement. The same invariant applies here — the
      // user's fresh Diia sign should be over the exact bytes we built.
      const bindingBytes = parsed.embeddedContent ?? sessionBindingBytes;

      setStatus('verifying');
      const trustedCas =
        window.__QKB_UA_TRUSTED_CAS__ ?? (await fetchTrustedCas());
      const verifier = window.__QKB_UA_VERIFY__ ?? verifyQes;
      const verified = await verifier({
        parsed,
        binding: session.bindingV2! as unknown as Parameters<typeof verifyQes>[0]['binding'],
        bindingBytes,
        expectedPk: pkBytes,
        trustedCas,
      });

      setStatus('witness');
      const {
        rTL: trustedListRoot,
        merklePath,
        merkleIndices,
      } = await fetchMerkleProofForIntermediate(verified.intermediateCertDer, trustedCas);

      const baseWitness = await buildPhase2Witness({
        parsed,
        binding: session.bindingV2! as unknown as Parameters<
          typeof buildPhase2Witness
        >[0]['binding'],
        bindingBytes,
        trustedListRoot,
        intermediateCertDer: verified.intermediateCertDer,
        merklePath,
        merkleIndices,
      });

      // Build the single-leaf UA policy tree (depth 4, 16 slots, 1 filled)
      // and drive the V4 policy-inclusion proof + DOB extraction.
      const policyLeaf = buildPolicyLeafV1({
        policyId: uaPolicySeed.policyId,
        policyVersion: uaPolicySeed.policyVersion,
        contentHash: uaPolicySeed.contentHash as `0x${string}`,
        metadataHash: uaPolicySeed.metadataHash as `0x${string}`,
      });
      const policyTree = await buildPolicyTreeFromLeaves([policyLeaf], 16);
      const policyProof = await buildPolicyInclusionProof(policyTree, 0);

      const uaSignals = await buildUaLeafPublicSignalsV4({
        baseWitness,
        binding: session.bindingV2!,
        policyProof,
        leafDER: parsed.leafCertDer,
      });

      const sharedSave = {
        country,
        cadesB64: bytesToB64(p7sBuf),
        leafCertDerB64: bytesToB64(parsed.leafCertDer),
        intCertDerB64: bytesToB64(verified.intermediateCertDer),
        trustedListRoot:
          typeof trustedListRoot === 'string' ? trustedListRoot : String(trustedListRoot),
        circuitVersion: 'QKBPresentationEcdsaLeafV4_UA+Chain',
        algorithmTag: verified.algorithmTag,
      } as const;

      setStatus('proving');
      const prover = window.__QKB_UA_PROVER__ ?? new MockProver({ delayMs: 50 });
      const controller = new AbortController();
      abortRef.current = controller;
      const start = Date.now();

      const result = await proveSplit(uaSignals.witnessV4 as never, {
        prover,
        artifacts: {
          leaf: { wasmUrl: '', zkeyUrl: '' },
          chain: { wasmUrl: '', zkeyUrl: '' },
        } as never,
        algorithmTag: verified.algorithmTag,
        signal: controller.signal,
        onProgress: (p: SplitProgress) => {
          setStage(p.stage);
          setProofSide(p.side);
          setElapsedMs(p.elapsedMs ?? Date.now() - start);
        },
      });

      // V3's proveSplit returns (publicLeaf=13 signals). We replace with the
      // V4 16-signal publicLeafV4 we derived above so the register step sees
      // the ring the UA verifier expects.
      saveSession({
        ...sharedSave,
        proofLeafV4: result.proofLeaf,
        publicLeafV4: uaSignals.publicLeafV4,
        proofChainV4: result.proofChain,
        publicChainV4: result.publicChain,
      });
      setStatus('done');
      navigate({ to: '/ua/register' });
    } catch (err) {
      console.error('[qkb/ua] upload failure:', err);
      setStatus('error');
      const base = localizeError(err, { t });
      const tag =
        err && typeof err === 'object' && 'details' in err
          ? Object.values((err as { details?: Record<string, unknown> }).details ?? {})
              .filter((v) => v !== undefined && v !== null)
              .join('/')
          : '';
      setError(tag ? `${base} [${tag}]` : base);
    } finally {
      abortRef.current = null;
    }
  };

  return (
    <PhaseCard step={3} total={4} accent="amber" title={t('upload.heading')}>
      <p className="text-slate-400 mb-5">{t('ua.upload.intro')}</p>
      <div className="space-y-4">
        <button
          type="button"
          onClick={onPick}
          disabled={status !== 'idle' && status !== 'error' && status !== 'done'}
          data-testid="pick-p7s"
          className="px-4 py-2 bg-amber-600 hover:bg-amber-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-semibold rounded-md"
        >
          {t('upload.pick')}
        </button>
        <input
          ref={fileInputRef}
          type="file"
          accept=".p7s,.p7m,.pkcs7,application/pkcs7-signature"
          hidden
          data-testid="p7s-input"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void onFile(f);
          }}
        />
        <div className="text-xs font-mono text-slate-500" data-testid="upload-status">
          status: {status}
          {stage ? ` • stage: ${stage}` : ''}
          {proofSide ? ` • side: ${proofSide}` : ''}
          {elapsedMs ? ` • elapsed: ${Math.floor(elapsedMs / 1000)}s` : ''}
        </div>
        {status === 'done' && (
          <p data-testid="upload-done" className="text-emerald-300 text-sm">
            {t('ua.upload.done')}
          </p>
        )}
        {error && (
          <div
            data-testid="upload-error"
            role="alert"
            className="text-red-400 text-sm border border-red-500/40 bg-red-500/10 px-3 py-2 rounded"
          >
            {error}
          </div>
        )}
      </div>
    </PhaseCard>
  );
}

async function fetchTrustedCas(): Promise<TrustedCasFile> {
  const res = await fetch('./trusted-cas/trusted-cas.json');
  if (!res.ok) {
    throw new QkbError('qes.unknownCA', { reason: 'trusted-cas-fetch', status: res.status });
  }
  return (await res.json()) as TrustedCasFile;
}

/**
 * Resolve the flattener Merkle proof for an intermediate CA DER.
 *
 * TODO(extract): V3 `/upload` has a near-identical helper. A shared
 * `src/lib/merkleProof.ts` would eliminate the duplication — deferred out
 * of Commit 4b to keep the blast radius tight.
 */
async function fetchMerkleProofForIntermediate(
  intermediateDer: Uint8Array,
  preloadedTrustedCas: TrustedCasFile,
): Promise<{ rTL: string; merklePath: string[]; merkleIndices: number[] }> {
  const [rootRes, layersRes] = await Promise.all([
    fetch('./trusted-cas/root.json'),
    fetch('./trusted-cas/layers.json'),
  ]);
  if (!rootRes.ok) {
    throw new QkbError('registry.rootMismatch', { reason: 'root-fetch', status: rootRes.status });
  }
  if (!layersRes.ok) {
    throw new QkbError('registry.rootMismatch', { reason: 'layers-fetch', status: layersRes.status });
  }
  const root =
    window.__QKB_UA_MERKLE_ROOT__ ??
    ((await rootRes.json()) as { rTL: string; treeDepth: number });
  const layers = window.__QKB_UA_LAYERS__ ?? ((await layersRes.json()) as LayersFile);

  if (layers.depth !== root.treeDepth) {
    throw new QkbError('registry.rootMismatch', {
      reason: 'depth-disagreement',
      rootDepth: root.treeDepth,
      layersDepth: layers.depth,
    });
  }

  const intB64 = bytesToB64(intermediateDer);
  const entry = preloadedTrustedCas.cas.find((c: TrustedCa) => c.certDerB64 === intB64);
  if (!entry) {
    throw new QkbError('qes.unknownCA', { reason: 'intermediate-not-in-snapshot' });
  }

  const proof = await buildInclusionPath(entry.merkleIndex, layers);
  if (proof.rootHex.toLowerCase() !== root.rTL.toLowerCase()) {
    throw new QkbError('registry.rootMismatch', {
      reason: 'computed-root-disagrees',
      computed: proof.rootHex,
      committed: root.rTL,
    });
  }
  return { rTL: root.rTL, merklePath: proof.pathHex, merkleIndices: proof.indices };
}
