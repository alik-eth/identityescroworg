/**
 * /account/rotate — V5.2 wallet-rotation flow for registered identities.
 *
 * V5.2 (keccak-on-chain amendment) deltas vs V5.1:
 *   - public-signal layout drops msgSender and grows by four bindingPk*
 *     16-byte BE limbs (slots 18-21) — see `buildWitnessV5_2`.
 *   - rotateWallet() in `qkbRegistryV5_2Abi` accepts the new 22-field sig
 *     tuple; selector shifts to `0x9849ff37` (vs V5.1 `0x07d19c50`).
 *   - The auth-hash flow is byte-identical (no chain change to the EIP-191
 *     wrapper). walletSecret derivation (HKDF for EOA / Argon2id for SCW
 *     — SCW path remains gated here to V5.3 like in V5.1) is unchanged.
 *
 * Six-stage sequence (codex-corrected from the V5.1 first draft for 3
 * bugs around wallet-address capture, oldWalletSecret derivation, and
 * rotationOldCommitment sourcing — those fixes carry over verbatim):
 *
 *   1. connect      — connect NEW wallet and CAPTURE its address into state
 *                     so all subsequent steps reference the locked-in new
 *                     address rather than the currently-connected wallet.
 *   2. diia         — upload new p7s + canonical binding bytes; extract the
 *                     subjectSerial bytes; compute identityFingerprint
 *                     off-chain via `computeIdentityFingerprint` (no
 *                     signing required); read identityCommitments[fp] from
 *                     the registry via wagmi useReadContract.
 *   3. derive-new   — sign with NEW wallet for HKDF → newWalletSecret.
 *   4. derive-old   — switch to OLD wallet. Two signatures in this stage:
 *                     (a) HKDF for oldWalletSecret, (b) auth hash signing.
 *                     The auth hash binds (chainId, registry, fingerprint,
 *                     LOCKED newWalletAddress) — anti-replay across chains
 *                     and deploys, byte-identical to the contracts-eng
 *                     `_rotateAuthSig` helper.
 *   5. prove        — switch back to NEW wallet. Auto-runs buildWitnessV5_2
 *                     with rotationMode=1, both wallet secrets, and
 *                     rotationOldCommitment from the chain read; runs
 *                     snarkjs prove via Web Worker.
 *   6. submit       — submit rotateWallet() tx from the NEW wallet.
 *
 * IRREVERSIBILITY WARNING is displayed at stages 1 and 6.
 *
 * Spec reference: orchestration §1.3 + contracts-eng `_rotateAuthSig` test
 * helper at `arch-contracts/packages/contracts/test/QKBRegistryV5_2.t.sol`.
 */
import { useEffect, useState } from 'react';
import { Buffer } from 'buffer';
import { useTranslation } from 'react-i18next';
import { useNavigate } from '@tanstack/react-router';
import { encodePacked, keccak256 } from 'viem';
import {
  useAccount,
  useChainId,
  usePublicClient,
  useReadContract,
  useWalletClient,
  useWriteContract,
  useWaitForTransactionReceipt,
} from 'wagmi';
import {
  deploymentForChainId,
  qkbRegistryV5_2Abi,
  parseP7s,
  findSubjectSerial,
  computeIdentityFingerprint,
  publicSignalsV5_2FromArray,
  proveV5,
  buildWitnessV5_2,
  MockProver,
  type Groth16ProofV5_2,
  type PublicSignalsV5_2,
  type CircuitArtifactUrls,
} from '@qkb/sdk';
import { SnarkjsWorkerProver } from '@qkb/sdk/prover/snarkjsWorker';
import {
  isV5ArtifactsConfigured,
  V5_PROVER_ARTIFACTS,
} from '../../../lib/circuitArtifacts';
import {
  deriveWalletSecretEoa,
  isSmartContractWallet,
  type GetCodeClient,
} from '../../../lib/walletSecret';
import { PaperGrain } from '../../PaperGrain';
import { DocumentFooter } from '../../DocumentFooter';

type FlowStep =
  | 'connect'
  | 'diia'
  | 'derive-new'
  | 'derive-old'
  | 'prove'
  | 'submit'
  | 'done';

const ZERO_ADDR = '0x0000000000000000000000000000000000000000';
const ZERO_BYTES32 = `0x${'00'.repeat(32)}` as const;

/**
 * Compute the EIP-191 inner-hash the OLD wallet must sign to authorise
 * rotation to `newWallet`. Mirrors contracts-eng `_rotateAuthSig`:
 *
 *   innerHash = keccak256(abi.encodePacked(
 *     "qkb-rotate-auth-v1",   // string, no length prefix
 *     uint256(chainId),        // 32 bytes BE
 *     address(registry),       // 20 bytes BE
 *     fingerprint,             // bytes32 (= uint256 under abi.encodePacked)
 *     address(newWallet),      // 20 bytes BE
 *   ))
 *
 * The wallet then runs `signMessage({ message: { raw: innerHash } })` —
 * viem applies `"\x19Ethereum Signed Message:\n32"` automatically,
 * matching the contract's `ECDSA.recover(toEthSignedMessageHash(...), sig)`.
 *
 * IMPORTANT: `newWallet` MUST be the LOCKED new wallet address captured at
 * the connect step, NOT the currently-connected wallet (which becomes the
 * old wallet during the sign-old stage).
 */
function computeRotationAuthHash(
  chainId: number,
  registryAddress: `0x${string}`,
  identityFingerprint: bigint,
  newWalletAddress: `0x${string}`,
): `0x${string}` {
  return keccak256(
    encodePacked(
      ['string', 'uint256', 'address', 'uint256', 'address'],
      [
        'qkb-rotate-auth-v1',
        BigInt(chainId),
        registryAddress,
        identityFingerprint,
        newWalletAddress,
      ],
    ),
  );
}

/**
 * Convert a bigint to bytes32 hex (0x-prefixed, 64 hex chars). Used to
 * pass the off-chain-computed fingerprint into wagmi's bytes32 mapping read.
 */
function bigIntToBytes32Hex(v: bigint): `0x${string}` {
  return `0x${v.toString(16).padStart(64, '0')}` as `0x${string}`;
}

export function RotateWalletFlow() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { address: connectedAddress } = useAccount();
  const chainId = useChainId();
  const dep = deploymentForChainId(chainId);
  const publicClient = usePublicClient();
  const { data: walletClient } = useWalletClient();

  const { writeContract, data: txHash, isPending: txPending, error: writeError } =
    useWriteContract();
  const { isSuccess: txMined } = useWaitForTransactionReceipt({ hash: txHash });

  const [step, setStep] = useState<FlowStep>('connect');

  // newWalletAddress: LOCKED at connect-step advance. Distinct from
  // `connectedAddress` because the user switches wallets between steps.
  const [newWalletAddress, setNewWalletAddress] = useState<`0x${string}` | null>(null);

  const [p7s, setP7s] = useState<Uint8Array | null>(null);
  const [bindingBytes, setBindingBytes] = useState<Uint8Array | null>(null);
  const [subjectSerialBytes, setSubjectSerialBytes] = useState<Uint8Array | null>(null);
  const [fingerprint, setFingerprint] = useState<bigint | null>(null);

  const [newWalletSecret, setNewWalletSecret] = useState<Uint8Array | null>(null);
  const [oldWalletSecret, setOldWalletSecret] = useState<Uint8Array | null>(null);
  const [oldWalletAuthSig, setOldWalletAuthSig] = useState<`0x${string}` | null>(null);

  const [proof, setProof] = useState<Groth16ProofV5_2 | null>(null);
  const [publicSignals, setPublicSignals] = useState<PublicSignalsV5_2 | null>(null);

  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isWorking, setIsWorking] = useState(false);

  const useMockProver =
    typeof import.meta !== 'undefined' &&
    import.meta.env?.VITE_USE_MOCK_PROVER === '1';
  const realProverConfigured = isV5ArtifactsConfigured();
  const v5Deployed = !!dep && dep.registryV5 !== ZERO_ADDR;

  // Reactive read: identityCommitments[fingerprint] from the registry.
  // Fires automatically once both fingerprint and dep are present.
  // Returns 0x000…000 if the fingerprint has never been registered (the
  // submit step will refuse in that case — there is nothing to rotate).
  const fingerprintHex = fingerprint !== null ? bigIntToBytes32Hex(fingerprint) : ZERO_BYTES32;
  const { data: rotationOldCommitmentHex } = useReadContract({
    address: dep?.registryV5,
    abi: qkbRegistryV5_2Abi,
    functionName: 'identityCommitments',
    args: [fingerprintHex],
    query: {
      enabled: v5Deployed && fingerprint !== null,
    },
  });
  const rotationOldCommitment: bigint | null =
    rotationOldCommitmentHex && rotationOldCommitmentHex !== ZERO_BYTES32
      ? BigInt(rotationOldCommitmentHex)
      : null;

  if (txMined) {
    void navigate({ to: '/' });
  }

  // ---- Step handlers ----

  const handleP7sUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const buf = new Uint8Array(await file.arrayBuffer());
    setP7s(buf);
    setErrorMsg(null);
    // Eagerly compute subjectSerial + fingerprint so the chain-read can fire.
    try {
      const cms = parseP7s(Buffer.from(buf));
      const serial = findSubjectSerial(cms.leafCertDer);
      const sBytes = cms.leafCertDer.subarray(
        serial.offset,
        serial.offset + serial.length,
      );
      setSubjectSerialBytes(sBytes);
      const fp = await computeIdentityFingerprint(sBytes);
      setFingerprint(fp);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    }
  };

  const handleBindingUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const buf = new Uint8Array(await file.arrayBuffer());
    setBindingBytes(buf);
    setErrorMsg(null);
  };

  /** Stage 1 → 2: lock the new wallet address. */
  const onAdvanceFromConnect = () => {
    if (!connectedAddress) {
      setErrorMsg(t('accountRotate.connect.noWallet'));
      return;
    }
    setNewWalletAddress(connectedAddress);
    setErrorMsg(null);
    setStep('diia');
  };

  /** Stage 2 → 3: confirm we have files + chain-read landed. */
  const onAdvanceFromDiia = () => {
    if (!p7s || !bindingBytes || fingerprint === null) {
      setErrorMsg(t('accountRotate.diia.filesRequired'));
      return;
    }
    if (rotationOldCommitment === null) {
      setErrorMsg(t('accountRotate.diia.noPriorIdentity'));
      return;
    }
    setErrorMsg(null);
    setStep('derive-new');
  };

  /** Stage 3: NEW wallet signs personal_sign for HKDF → newWalletSecret. */
  const onDeriveNew = async () => {
    if (!walletClient || !newWalletAddress || !subjectSerialBytes) {
      setErrorMsg(t('accountRotate.deriveNew.walletRequired'));
      return;
    }
    if (connectedAddress?.toLowerCase() !== newWalletAddress.toLowerCase()) {
      setErrorMsg(t('accountRotate.deriveNew.wrongWallet'));
      return;
    }
    setErrorMsg(null);
    setIsWorking(true);
    setStatusMsg(t('accountRotate.deriveNew.signing'));
    try {
      // SCW gate (Task 5 will wire the modal).
      if (publicClient) {
        const scw = await isSmartContractWallet(
          publicClient as unknown as GetCodeClient,
          newWalletAddress,
        );
        if (scw) throw new Error(t('accountRotate.deriveNew.scwNotSupported'));
      }
      const secret = await deriveWalletSecretEoa(walletClient, subjectSerialBytes);
      setNewWalletSecret(secret);
      setStatusMsg(null);
      setStep('derive-old');
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setIsWorking(false);
    }
  };

  /** Stage 4: OLD wallet signs HKDF + auth hash. Two signatures, one stage. */
  const onDeriveOldAndSign = async () => {
    if (
      !walletClient
      || !connectedAddress
      || !subjectSerialBytes
      || fingerprint === null
      || !newWalletAddress
      || !dep
    ) {
      setErrorMsg(t('accountRotate.deriveOld.walletRequired'));
      return;
    }
    if (connectedAddress.toLowerCase() === newWalletAddress.toLowerCase()) {
      setErrorMsg(t('accountRotate.deriveOld.stillNewWallet'));
      return;
    }
    setErrorMsg(null);
    setIsWorking(true);
    try {
      setStatusMsg(t('accountRotate.deriveOld.signingHkdf'));
      const oldSecret = await deriveWalletSecretEoa(walletClient, subjectSerialBytes);

      setStatusMsg(t('accountRotate.deriveOld.signingAuth'));
      const authHash = computeRotationAuthHash(
        chainId,
        dep.registryV5,
        fingerprint,
        newWalletAddress,
      );
      const sig = await walletClient.signMessage({ message: { raw: authHash } });

      setOldWalletSecret(oldSecret);
      setOldWalletAuthSig(sig);
      setStatusMsg(null);
      setStep('prove');
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setIsWorking(false);
    }
  };

  /** Stage 5: build witness with rotationMode=1, prove. */
  const onProve = async () => {
    if (
      !p7s
      || !bindingBytes
      || !newWalletSecret
      || !oldWalletSecret
      || !newWalletAddress
      || rotationOldCommitment === null
    ) {
      setErrorMsg(t('accountRotate.prove.missingInputs'));
      return;
    }
    setErrorMsg(null);
    setIsWorking(true);
    setStatusMsg(t('accountRotate.prove.building'));
    try {
      const cms = parseP7s(Buffer.from(p7s));

      // SPKIs: derive from the certs in the .p7s. parseP7s returns leafCertDer
      // and (optionally) intCertDer. For the rotate flow we expect both — Diia
      // .p7s embeds the full chain. If absent, the user must re-export with
      // both certs, same as the register flow's gate.
      if (!cms.intCertDer) {
        throw new Error(t('accountRotate.prove.noIntCert'));
      }
      const leafSpki = extractSpki(cms.leafCertDer);
      const intSpki = extractSpki(cms.intCertDer);

      const witness = await buildWitnessV5_2({
        bindingBytes: Buffer.from(bindingBytes),
        leafCertDer: cms.leafCertDer,
        leafSpki,
        intSpki,
        signedAttrsDer: cms.signedAttrsDer,
        signedAttrsMdOffset: cms.signedAttrsMdOffset,
        walletSecret: Buffer.from(newWalletSecret),
        oldWalletSecret: Buffer.from(oldWalletSecret),
        rotationMode: 1,
        rotationOldCommitment,
        rotationNewWalletAddress: BigInt(newWalletAddress),
      });

      setStatusMsg(t('accountRotate.prove.proving'));

      const artifacts: CircuitArtifactUrls = {
        wasmUrl: V5_PROVER_ARTIFACTS.wasmUrl,
        zkeyUrl: V5_PROVER_ARTIFACTS.zkeyUrl,
        zkeySha256: V5_PROVER_ARTIFACTS.zkeySha256,
      };

      let proofResult: Groth16ProofV5_2;
      let signals: PublicSignalsV5_2;

      if (useMockProver) {
        const mockProver = new MockProver({ delayMs: 30, result: {
          proof: {
            pi_a: ['0x1', '0x2', '0x1'],
            pi_b: [['0x3', '0x4'], ['0x5', '0x6'], ['0x1', '0x0']],
            pi_c: ['0x7', '0x8', '0x1'],
            protocol: 'groth16', curve: 'bn128',
          },
          // 22-signal canned output (V5.2 FROZEN layout). Deltas vs V5.1:
          //   - msgSender removed (slot 0 in V5.1) — slots 1-18 shift to 0-17.
          //   - bindingPk* limbs added at slots 18-21 (synthetic <2^128).
          // Slot 13 holds identityFingerprint (was slot 14 in V5.1);
          // slot 15 is rotationMode=1; slot 17 is rotationNewWallet.
          publicSignals: [
            String(Math.floor(Date.now() / 1000)),           // 0  timestamp
            '0',                                              // 1  nullifier (unused under rotation mode)
            '0', '0',                                         // 2-3 ctxHashHi/Lo (unused)
            '6', '7', '8', '9', '10', '11', '12', '13', '14', // 4-12 unchanged
            String(fingerprint),                              // 13 identityFingerprint
            '16',                                             // 14 identityCommitment (new)
            '1',                                              // 15 rotationMode
            String(rotationOldCommitment),                    // 16 rotationOldCommitment
            String(BigInt(newWalletAddress)),                 // 17 rotationNewWallet
            '100', '101', '102', '103',                       // 18-21 bindingPk* limbs (synthetic)
          ],
        }});
        const r = await proveV5(witness as Record<string, unknown>, { prover: mockProver, artifacts });
        signals = publicSignalsV5_2FromArray(r.publicSignals);
        proofResult = unpackProof(r.proof);
      } else {
        const proverWorker = new Worker(
          new URL('../../../workers/v5-prover.worker.ts', import.meta.url),
          { type: 'module' },
        );
        const prover = new SnarkjsWorkerProver({ worker: proverWorker, terminateAfterProve: true });
        const r = await proveV5(witness as Record<string, unknown>, { prover, artifacts });
        signals = publicSignalsV5_2FromArray(r.publicSignals);
        proofResult = unpackProof(r.proof);
      }

      setProof(proofResult);
      setPublicSignals(signals);
      setStatusMsg(null);
      setStep('submit');
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setIsWorking(false);
    }
  };

  /** Stage 6: submit rotateWallet() from the NEW wallet. */
  const onSubmit = () => {
    if (!proof || !publicSignals || !oldWalletAuthSig || !dep || !newWalletAddress) {
      setErrorMsg(t('accountRotate.submit.missingData'));
      return;
    }
    if (connectedAddress?.toLowerCase() !== newWalletAddress.toLowerCase()) {
      setErrorMsg(t('accountRotate.submit.switchToNew'));
      return;
    }
    setErrorMsg(null);
    writeContract({
      address: dep.registryV5,
      abi: qkbRegistryV5_2Abi,
      functionName: 'rotateWallet',
      args: [proof, publicSignals, oldWalletAuthSig],
    });
  };

  // Auto-fire the prove step on entering 'prove' (no user click — the
  // prior stage already collected all inputs).
  useEffect(() => {
    if (step === 'prove' && !isWorking && !proof) {
      void onProve();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  // ---- Render ----

  return (
    <main className="relative min-h-screen">
      <PaperGrain />
      <div className="doc-grid pt-24 relative z-10">
        <div />
        <div className="max-w-3xl space-y-12">
          <header className="space-y-4">
            <h1
              className="text-5xl leading-none"
              style={{ color: 'var(--ink)' }}
            >
              {t('accountRotate.title')}
            </h1>
            <p
              className="text-base max-w-prose"
              style={{ color: 'var(--ink)', opacity: 0.85 }}
            >
              {t('accountRotate.lede')}
            </p>
            <p
              className="text-xs text-mono"
              style={{ color: 'var(--ink)', opacity: 0.6 }}
              data-testid="rotate-step-indicator"
            >
              {t(`accountRotate.steps.${step}`)}
            </p>
          </header>
          <hr className="rule" />

          {step === 'connect' && (
            <section aria-labelledby="rotate-connect-heading" className="space-y-6">
              <h2 id="rotate-connect-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
                {t('accountRotate.connect.title')}
              </h2>
              <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
                {t('accountRotate.connect.body')}
              </p>
              <aside
                className="p-4 space-y-2 border"
                style={{ borderColor: 'var(--seal)', color: 'var(--seal)' }}
                data-testid="rotate-warning-irreversible"
              >
                <p className="text-sm font-semibold">{t('accountRotate.connect.warningTitle')}</p>
                <p className="text-sm">{t('accountRotate.connect.warningBody')}</p>
              </aside>
              {connectedAddress ? (
                <div className="space-y-2">
                  <p className="text-sm" style={{ color: 'var(--ink)', opacity: 0.7 }}>
                    {t('accountRotate.connect.newWallet')} {connectedAddress.slice(0, 6)}…{connectedAddress.slice(-4)}
                  </p>
                  {errorMsg && (
                    <p className="text-sm" role="alert" style={{ color: 'var(--seal)' }}>{errorMsg}</p>
                  )}
                  <button
                    type="button"
                    onClick={onAdvanceFromConnect}
                    data-testid="rotate-advance-to-diia"
                    className="px-6 py-3 text-mono text-sm"
                    style={{ background: 'var(--sovereign)', color: 'var(--bone)' }}
                  >
                    {t('accountRotate.connect.advance')}
                  </button>
                </div>
              ) : (
                <p className="text-sm" style={{ color: 'var(--ink)', opacity: 0.7 }}>
                  {t('accountRotate.connect.noWallet')}
                </p>
              )}
            </section>
          )}

          {step === 'diia' && newWalletAddress && (
            <section aria-labelledby="rotate-diia-heading" className="space-y-6">
              <h2 id="rotate-diia-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
                {t('accountRotate.diia.title')}
              </h2>
              <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
                {t('accountRotate.diia.body')}
              </p>
              <p className="text-sm text-mono" style={{ color: 'var(--ink)', opacity: 0.6 }}>
                {t('accountRotate.diia.lockedNew')} {newWalletAddress.slice(0, 6)}…{newWalletAddress.slice(-4)}
              </p>
              <div className="space-y-4">
                <div className="space-y-1">
                  <label htmlFor="rotate-binding-upload" className="text-sm text-mono"
                    style={{ color: 'var(--ink)', opacity: 0.7 }}>
                    {t('accountRotate.diia.bindingLabel')}
                  </label>
                  <input
                    id="rotate-binding-upload" type="file" accept=".json"
                    data-testid="rotate-binding-input"
                    onChange={handleBindingUpload}
                    style={{ color: 'var(--ink)' }}
                  />
                </div>
                <div className="space-y-1">
                  <label htmlFor="rotate-p7s-upload" className="text-sm text-mono"
                    style={{ color: 'var(--ink)', opacity: 0.7 }}>
                    {t('accountRotate.diia.p7sLabel')}
                  </label>
                  <input
                    id="rotate-p7s-upload" type="file" accept=".p7s"
                    data-testid="rotate-p7s-input"
                    onChange={handleP7sUpload}
                    style={{ color: 'var(--ink)' }}
                  />
                </div>
              </div>
              {fingerprint !== null && (
                <p className="text-xs font-mono break-all" data-testid="rotate-fingerprint"
                  style={{ color: 'var(--ink)', opacity: 0.6 }}>
                  fingerprint: {bigIntToBytes32Hex(fingerprint)}
                </p>
              )}
              {fingerprint !== null && rotationOldCommitment !== null && (
                <p className="text-xs font-mono break-all" data-testid="rotate-old-commitment"
                  style={{ color: 'var(--ink)', opacity: 0.6 }}>
                  rotationOldCommitment (on-chain read): {bigIntToBytes32Hex(rotationOldCommitment)}
                </p>
              )}
              {fingerprint !== null && rotationOldCommitment === null && (
                <p className="text-sm" role="status" data-testid="rotate-no-prior-identity"
                  style={{ color: 'var(--seal)' }}>
                  {t('accountRotate.diia.noPriorIdentity')}
                </p>
              )}
              {errorMsg && (
                <p className="text-sm" role="alert" style={{ color: 'var(--seal)' }}>{errorMsg}</p>
              )}
              <div className="flex gap-4">
                <button type="button" onClick={() => setStep('connect')}
                  className="px-6 py-3 text-mono text-sm"
                  style={{ border: '1px solid var(--ink)', color: 'var(--ink)' }}>
                  {t('accountRotate.back')}
                </button>
                <button type="button" onClick={onAdvanceFromDiia}
                  disabled={!p7s || !bindingBytes || fingerprint === null || rotationOldCommitment === null}
                  data-testid="rotate-advance-to-derive-new"
                  className="px-6 py-3 text-mono text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                  style={{ background: 'var(--sovereign)', color: 'var(--bone)' }}>
                  {t('accountRotate.diia.advance')}
                </button>
              </div>
            </section>
          )}

          {step === 'derive-new' && newWalletAddress && (
            <section aria-labelledby="rotate-derive-new-heading" className="space-y-6">
              <h2 id="rotate-derive-new-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
                {t('accountRotate.deriveNew.title')}
              </h2>
              <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
                {t('accountRotate.deriveNew.body')}
              </p>
              <p className="text-sm text-mono" style={{ color: 'var(--ink)', opacity: 0.6 }}>
                {t('accountRotate.deriveNew.expected')} {newWalletAddress.slice(0, 6)}…{newWalletAddress.slice(-4)}
              </p>
              {connectedAddress && connectedAddress.toLowerCase() !== newWalletAddress.toLowerCase() && (
                <p className="text-sm" role="status"
                  style={{ color: 'var(--seal)' }} data-testid="rotate-wrong-wallet-derive-new">
                  {t('accountRotate.deriveNew.wrongWallet')}
                </p>
              )}
              {statusMsg && (
                <p className="text-sm" role="status" style={{ color: 'var(--ink)', opacity: 0.7 }}>
                  {statusMsg}
                </p>
              )}
              {errorMsg && (
                <p className="text-sm" role="alert" style={{ color: 'var(--seal)' }}>{errorMsg}</p>
              )}
              <div className="flex gap-4">
                <button type="button" onClick={() => setStep('diia')} disabled={isWorking}
                  className="px-6 py-3 text-mono text-sm disabled:opacity-50"
                  style={{ border: '1px solid var(--ink)', color: 'var(--ink)' }}>
                  {t('accountRotate.back')}
                </button>
                <button type="button" onClick={onDeriveNew}
                  disabled={isWorking
                    || !connectedAddress
                    || connectedAddress.toLowerCase() !== newWalletAddress.toLowerCase()}
                  data-testid="rotate-derive-new-cta"
                  className="px-6 py-3 text-mono text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                  style={{ background: 'var(--sovereign)', color: 'var(--bone)' }}>
                  {isWorking ? t('accountRotate.running') : t('accountRotate.deriveNew.cta')}
                </button>
              </div>
            </section>
          )}

          {step === 'derive-old' && newWalletAddress && fingerprint !== null && dep && (
            <section aria-labelledby="rotate-derive-old-heading" className="space-y-6">
              <h2 id="rotate-derive-old-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
                {t('accountRotate.deriveOld.title')}
              </h2>
              <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
                {t('accountRotate.deriveOld.body')}
              </p>
              <p className="text-sm" style={{ color: 'var(--ink)', opacity: 0.7 }}>
                {t('accountRotate.deriveOld.switchHint')}
              </p>
              <div className="p-4 space-y-2 font-mono text-xs break-all"
                style={{ background: 'var(--rule)', color: 'var(--ink)' }}
                data-testid="rotate-auth-hash">
                <p className="text-xs uppercase tracking-wide" style={{ opacity: 0.6 }}>
                  {t('accountRotate.deriveOld.authHashLabel')}
                </p>
                <p>{computeRotationAuthHash(chainId, dep.registryV5, fingerprint, newWalletAddress)}</p>
              </div>
              {connectedAddress && connectedAddress.toLowerCase() === newWalletAddress.toLowerCase() && (
                <p className="text-sm" role="status"
                  style={{ color: 'var(--seal)' }} data-testid="rotate-still-new-wallet">
                  {t('accountRotate.deriveOld.stillNewWallet')}
                </p>
              )}
              {statusMsg && (
                <p className="text-sm" role="status" style={{ color: 'var(--ink)', opacity: 0.7 }}>
                  {statusMsg}
                </p>
              )}
              {errorMsg && (
                <p className="text-sm" role="alert" style={{ color: 'var(--seal)' }}>{errorMsg}</p>
              )}
              <div className="flex gap-4">
                <button type="button" onClick={() => setStep('derive-new')} disabled={isWorking}
                  className="px-6 py-3 text-mono text-sm disabled:opacity-50"
                  style={{ border: '1px solid var(--ink)', color: 'var(--ink)' }}>
                  {t('accountRotate.back')}
                </button>
                <button type="button" onClick={onDeriveOldAndSign}
                  disabled={isWorking
                    || !connectedAddress
                    || connectedAddress.toLowerCase() === newWalletAddress.toLowerCase()}
                  data-testid="rotate-derive-old-cta"
                  className="px-6 py-3 text-mono text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                  style={{ background: 'var(--sovereign)', color: 'var(--bone)' }}>
                  {isWorking ? t('accountRotate.running') : t('accountRotate.deriveOld.cta')}
                </button>
              </div>
            </section>
          )}

          {step === 'prove' && (
            <section aria-labelledby="rotate-prove-heading" className="space-y-6">
              <h2 id="rotate-prove-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
                {t('accountRotate.prove.title')}
              </h2>
              <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
                {t('accountRotate.prove.body')}
              </p>
              {!realProverConfigured && !useMockProver && (
                <p className="text-sm" role="status" data-testid="rotate-ceremony-pending"
                  style={{ color: 'var(--ink)', opacity: 0.6 }}>
                  {t('accountRotate.prove.ceremonyPending')}
                </p>
              )}
              {statusMsg && (
                <p className="text-sm" role="status" data-testid="rotate-status"
                  style={{ color: 'var(--ink)', opacity: 0.7 }}>
                  {statusMsg}
                </p>
              )}
              {errorMsg && (
                <p className="text-sm" role="alert" style={{ color: 'var(--seal)' }}>{errorMsg}</p>
              )}
              {/* Auto-runs via useEffect on stage entry; back button only. */}
              <button type="button" onClick={() => setStep('derive-old')} disabled={isWorking}
                className="px-6 py-3 text-mono text-sm disabled:opacity-50"
                style={{ border: '1px solid var(--ink)', color: 'var(--ink)' }}>
                {t('accountRotate.back')}
              </button>
            </section>
          )}

          {step === 'submit' && newWalletAddress && (
            <section aria-labelledby="rotate-submit-heading" className="space-y-6">
              <h2 id="rotate-submit-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
                {t('accountRotate.submit.title')}
              </h2>
              <aside
                className="p-4 space-y-2 border"
                style={{ borderColor: 'var(--seal)', color: 'var(--seal)' }}
                data-testid="rotate-warning-final">
                <p className="text-sm font-semibold">{t('accountRotate.submit.warningTitle')}</p>
                <p className="text-sm">{t('accountRotate.submit.warningBody')}</p>
              </aside>
              <p className="text-sm" style={{ color: 'var(--ink)', opacity: 0.7 }}>
                {t('accountRotate.submit.switchBackHint')} {newWalletAddress.slice(0, 6)}…{newWalletAddress.slice(-4)}
              </p>
              <p className="text-sm text-mono" style={{ color: 'var(--ink)', opacity: 0.5 }}>
                {t('accountRotate.submit.currentlyConnected')}{' '}
                {connectedAddress ? `${connectedAddress.slice(0, 6)}…${connectedAddress.slice(-4)}` : '—'}
              </p>
              {connectedAddress && connectedAddress.toLowerCase() !== newWalletAddress.toLowerCase() && (
                <p className="text-sm" role="status"
                  style={{ color: 'var(--seal)' }} data-testid="rotate-switch-to-new-wallet">
                  {t('accountRotate.submit.switchToNew')}
                </p>
              )}
              {!v5Deployed && (
                <p className="text-sm" role="status" data-testid="rotate-awaiting-deploy"
                  style={{ color: 'var(--ink)', opacity: 0.6 }}>
                  {t('accountRotate.submit.awaitingDeploy')}
                </p>
              )}
              {txHash && (
                <p className="text-sm text-mono" data-testid="rotate-tx-hash">
                  tx: {txHash.slice(0, 12)}…
                </p>
              )}
              {writeError && (
                <p className="text-sm" role="alert" style={{ color: 'var(--seal)' }}>{writeError.message}</p>
              )}
              {errorMsg && (
                <p className="text-sm" role="alert" style={{ color: 'var(--seal)' }}>{errorMsg}</p>
              )}
              <div className="flex gap-4">
                <button type="button" onClick={() => setStep('derive-old')} disabled={txPending}
                  className="px-6 py-3 text-mono text-sm disabled:opacity-50"
                  style={{ border: '1px solid var(--ink)', color: 'var(--ink)' }}>
                  {t('accountRotate.back')}
                </button>
                <button type="button" onClick={onSubmit}
                  disabled={txPending || !v5Deployed
                    || (connectedAddress?.toLowerCase() !== newWalletAddress.toLowerCase())}
                  data-testid="rotate-submit-cta"
                  className="px-6 py-3 text-mono text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                  style={{ background: 'var(--sovereign)', color: 'var(--bone)' }}>
                  {t('accountRotate.submit.cta')}
                </button>
              </div>
            </section>
          )}
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}

// ---- helpers (private) ----

/**
 * Extract the 91-byte canonical P-256 SubjectPublicKeyInfo bytes from a
 * cert DER. Same approach Step4ProveAndRegister uses; lifted here to avoid
 * cross-file import.
 */
function extractSpki(certDer: Buffer): Buffer {
  // Lazy require to avoid a top-level pkijs load on every component mount.
  // pkijs is heavy; keeping it inside this helper means the connect/diia
  // stages don't pay its bundle cost.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { fromBER } = require('asn1js') as typeof import('asn1js');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { Certificate } = require('pkijs') as typeof import('pkijs');
  const ab = new ArrayBuffer(certDer.length);
  new Uint8Array(ab).set(certDer);
  const asn = fromBER(ab);
  if (asn.offset === -1) throw new Error('extractSpki: invalid BER');
  const cert = new Certificate({ schema: asn.result });
  return Buffer.from(new Uint8Array(cert.subjectPublicKeyInfo.toSchema().toBER(false)));
}

function unpackProof(p: { pi_a: readonly string[]; pi_b: readonly (readonly string[])[]; pi_c: readonly string[] }): Groth16ProofV5_2 {
  return {
    a: [BigInt(p.pi_a[0] ?? '0'), BigInt(p.pi_a[1] ?? '0')] as const,
    b: [
      [BigInt(p.pi_b[0]?.[0] ?? '0'), BigInt(p.pi_b[0]?.[1] ?? '0')] as const,
      [BigInt(p.pi_b[1]?.[0] ?? '0'), BigInt(p.pi_b[1]?.[1] ?? '0')] as const,
    ] as const,
    c: [BigInt(p.pi_c[0] ?? '0'), BigInt(p.pi_c[1] ?? '0')] as const,
  };
}
