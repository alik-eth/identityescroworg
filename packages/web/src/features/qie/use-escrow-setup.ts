import { useCallback, useState } from 'react';
import {
  buildEscrowConfig,
  computeEscrowId,
  encryptRecovery,
  hybridEncapsulate,
  splitShares,
  wrapShare,
  type EscrowAgentEntry,
  type EscrowConfig,
  type HybridPublicKey,
} from '@qkb/qie-core';

/**
 * Browser-side hybrid-KEM + Shamir envelope builder and fan-out POSTer.
 *
 * Given a holder-side recovery secret R plus a set of custodian agents,
 * the hook:
 *   1. Builds a canonical EscrowConfig (qie-core buildEscrowConfig).
 *   2. Derives the escrowId = sha256(JCS(config)).
 *   3. Splits a fresh 32-byte k_esc into n Shamir shares (threshold t).
 *   4. Encrypts R under k_esc with escrowId as AAD (encR).
 *   5. For each agent, hybrid-encapsulates with their pk, wraps the agent's
 *      share under the resulting shared secret with
 *      AAD = utf8(escrowId || agent_id), and POSTs
 *      `{escrowId, config, ct:{kem_ct, wrap}, encR}` to the agent.
 *   6. Surfaces per-agent ack progress for the UI.
 *
 * Transport is `fetch`-compatible and injectable; the random source is
 * also injectable so tests can pin k_esc and each encapsulation's
 * ephemeral entropy.
 */

export interface AgentDescriptor {
  id: string;
  url: string;
  hybridPk: HybridPublicKey;
}

export interface EscrowSetupInput {
  /** Holder's recovery material (arbitrary byte string, typically <= a few KB). */
  R: Uint8Array;
  /** Holder's uncompressed secp256k1 public key, 0x04-prefixed. */
  holderPk: `0x04${string}`;
  agents: AgentDescriptor[];
  threshold: number;
  recipientHybridPk: HybridPublicKey;
  arbitrator: { chainId: number; address: `0x${string}`; kind: 'authority' };
  /** Unix seconds. */
  expiry: number;
  jurisdiction: string;
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface UseEscrowSetupState {
  phase: 'idle' | 'submitting' | 'done' | 'error';
  escrowId?: `0x${string}`;
  error?: string;
  acks: Record<string, 'pending' | 'ok' | 'fail'>;
}

export interface UseEscrowSetupReturn {
  state: UseEscrowSetupState;
  submit: (input: EscrowSetupInput) => Promise<void>;
}

const DEFAULT_FETCH: FetchLike =
  typeof globalThis.fetch === 'function'
    ? (input, init) => globalThis.fetch(input, init)
    : () => Promise.reject(new Error('fetch is not available'));

function bytesToHex(b: Uint8Array): string {
  return '0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function hybridPkToWire(pk: HybridPublicKey): { x25519: string; mlkem: string } {
  return { x25519: bytesToHex(pk.x25519), mlkem: bytesToHex(pk.mlkem) };
}

function dehydrateConfig(cfg: EscrowConfig): unknown {
  return {
    version: cfg.version,
    pk: cfg.pk,
    agents: cfg.agents.map((a) => ({
      agent_id: a.agent_id,
      hybrid_pk: hybridPkToWire(a.hybrid_pk),
      endpoint: a.endpoint,
    })),
    threshold: cfg.threshold,
    recipient_hybrid_pk: hybridPkToWire(cfg.recipient_hybrid_pk),
    arbitrator: cfg.arbitrator,
    expiry: cfg.expiry,
    jurisdiction: cfg.jurisdiction,
    unlock_predicate: cfg.unlock_predicate,
  };
}

/** WebCrypto-backed 32-byte secret generator, injectable for tests. */
export type RandomBytesFn = (len: number) => Uint8Array;

const DEFAULT_RANDOM: RandomBytesFn = (len) => {
  if (typeof globalThis.crypto?.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues unavailable');
  }
  const out = new Uint8Array(len);
  globalThis.crypto.getRandomValues(out);
  return out;
};

export interface BuildEnvelopeResult {
  config: EscrowConfig;
  escrowId: `0x${string}`;
  encR: Uint8Array;
  /** Aligned with `config.agents[i]`. */
  perAgent: Array<{
    agent_id: string;
    kem_ct: { x25519_ct: Uint8Array; mlkem_ct: Uint8Array };
    wrap: Uint8Array;
  }>;
}

/**
 * Pure envelope construction — no network, no React state. Exported so the
 * unit tests can round-trip unwrap each share and confirm threshold
 * reconstruction recovers k_esc.
 */
export function buildSetupEnvelope(
  input: EscrowSetupInput,
  randomBytes: RandomBytesFn = DEFAULT_RANDOM,
): BuildEnvelopeResult {
  const agentsCfg: EscrowAgentEntry[] = input.agents.map((a) => ({
    agent_id: a.id,
    hybrid_pk: a.hybridPk,
    endpoint: a.url,
  }));

  const config = buildEscrowConfig({
    pk: input.holderPk,
    agents: agentsCfg,
    threshold: input.threshold,
    recipient_hybrid_pk: input.recipientHybridPk,
    arbitrator: {
      chain_id: input.arbitrator.chainId,
      address: input.arbitrator.address,
      kind: input.arbitrator.kind,
    },
    expiry: input.expiry,
    jurisdiction: input.jurisdiction,
  });

  const escrowId = computeEscrowId(config);
  const k_esc = randomBytes(32);
  const encR = encryptRecovery(k_esc, input.R, escrowId);
  const shares = splitShares(k_esc, input.agents.length, input.threshold);

  const encoder = new TextEncoder();
  const perAgent = input.agents.map((a, i) => {
    const { ct: kem_ct, ss } = hybridEncapsulate(a.hybridPk);
    const aad = encoder.encode(escrowId + a.id);
    const wrap = wrapShare(ss, shares[i]!, aad);
    return { agent_id: a.id, kem_ct, wrap };
  });

  return { config, escrowId, encR, perAgent };
}

export function useEscrowSetup(
  options: { fetchImpl?: FetchLike; randomBytes?: RandomBytesFn } = {},
): UseEscrowSetupReturn {
  const fetchImpl = options.fetchImpl ?? DEFAULT_FETCH;
  const rng = options.randomBytes ?? DEFAULT_RANDOM;
  const [state, setState] = useState<UseEscrowSetupState>({ phase: 'idle', acks: {} });

  const submit = useCallback(
    async (input: EscrowSetupInput) => {
      const acks: Record<string, 'pending' | 'ok' | 'fail'> = {};
      for (const a of input.agents) acks[a.id] = 'pending';

      let envelope: BuildEnvelopeResult;
      try {
        envelope = buildSetupEnvelope(input, rng);
      } catch (e) {
        setState({
          phase: 'error',
          acks,
          error: e instanceof Error ? e.message : String(e),
        });
        return;
      }

      setState({ phase: 'submitting', escrowId: envelope.escrowId, acks });

      const configWire = dehydrateConfig(envelope.config);
      const encRHex = bytesToHex(envelope.encR);

      try {
        for (let i = 0; i < input.agents.length; i++) {
          const agent = input.agents[i]!;
          const pa = envelope.perAgent[i]!;
          const url = new URL('/escrow', agent.url).toString();
          const body = {
            escrowId: envelope.escrowId,
            config: configWire,
            ct: {
              kem_ct: {
                x25519_ct: bytesToHex(pa.kem_ct.x25519_ct),
                mlkem_ct: bytesToHex(pa.kem_ct.mlkem_ct),
              },
              wrap: bytesToHex(pa.wrap),
            },
            encR: encRHex,
          };
          const res = await fetchImpl(url, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            cache: 'no-store',
            body: JSON.stringify(body),
          });
          if (!res.ok) {
            throw new Error(`agent ${agent.id} rejected with HTTP ${res.status}`);
          }
          acks[agent.id] = 'ok';
          setState({ phase: 'submitting', escrowId: envelope.escrowId, acks: { ...acks } });
        }
        setState({ phase: 'done', escrowId: envelope.escrowId, acks });
      } catch (e) {
        setState({
          phase: 'error',
          escrowId: envelope.escrowId,
          acks,
          error: e instanceof Error ? e.message : String(e),
        });
      }
    },
    [fetchImpl, rng],
  );

  return { state, submit };
}
