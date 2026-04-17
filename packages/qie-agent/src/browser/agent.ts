// makeBrowserAgent — in-browser QIE agent factory.
//
// Collapses the Fastify route handlers from src/routes/*.ts into a direct
// function API over a localStorage-backed StorageAdapter, so the web SPA
// can run a custodian agent without an HTTP hop. Behavior mirrors the
// Node server's POST /escrow / POST /escrow/:id/release paths:
//   - escrowId ≡ hash(config) verification.
//   - replay guard on release nonces.
//   - Ed25519 ack signature on deposit.
//   - release gate: state → expiry → predicate → ciphertext reveal.
//
// This file MUST NOT import anything that pulls Node APIs into the bundle:
// no src/server.ts, no src/storage/fs.ts, no src/watcher.ts, no src/qes-verify.ts
// (uses node:fs for LOTL load paths). Crypto comes from @noble/*, hybrid KEM
// helpers from @qkb/qie-core (pure).

import {
  computeEscrowId,
  evaluatePredicate,
  generateHybridKeypair,
  hybridDecapsulate,
  jcsCanonicalize,
  QIE_ERRORS,
  type Evidence,
  type HybridPublicKey,
  type HybridSecretKey,
} from "@qkb/qie-core";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import { signAck, ackPublicKey } from "../ack.js";
import { ReplayGuard } from "../replay.js";
import type { EscrowRecord } from "../storage/types.js";
import {
  bytes2hex,
  dehydrateConfig,
  hex2bytes,
  hydrateConfig,
  type WireEscrowConfig,
  type WireWrappedCt,
} from "../wire.js";
import { LocalStorageAdapter } from "./storage.localstorage.js";

const DEMO_AGENT_IDS = ["agent-a", "agent-b", "agent-c"] as const;
export type DemoAgentId = typeof DEMO_AGENT_IDS[number];

const REPLAY_WINDOW_MS = 5 * 60 * 1000;

export interface OnEscrowReceivedBody {
  escrowId: `0x${string}`;
  config: WireEscrowConfig | unknown;
  ct: WireWrappedCt;
  encR: string;
}

export interface ReleaseRequest {
  evidence:
    | { kind: "A"; chainId: number; txHash: `0x${string}`; logIndex: number }
    | { kind: "C"; countersig: { p7s: string; cert: string } };
  recipient_nonce: string;
  recipient_pk?: string;
  on_behalf_of?: {
    recipient_pk: string;
    notary_cert: string;
    notary_sig: string;
  };
}

export type ReleaseResponse =
  | { ok: true; ct: EscrowRecord["ct"]; encR: string }
  | { ok: false; code: string; message: string; httpStatus: number };

export interface ChainEvents {
  onUnlock?: (ev: { escrowId: string; recipientHybridPk: string }) => void;
  onUnlockEvidence?: (ev: {
    escrowId: string;
    kindHash: string;
    referenceHash: string;
    evidenceHash: string;
    issuedAt: number;
  }) => void;
  onRevoked?: (ev: { escrowId: string }) => void;
}

export interface BrowserAgent {
  agentId: DemoAgentId;
  hybridPublicKey: HybridPublicKey;
  ackPublicKey: Uint8Array;
  onEscrowReceived(body: OnEscrowReceivedBody): Promise<{ agent_id: string; ackSig: string }>;
  listInbox(): EscrowRecord[];
  getEscrow(escrowId: string): EscrowRecord | null;
  release(escrowId: string, request: ReleaseRequest): Promise<ReleaseResponse>;
  observeChain(watcher: ChainEvents): () => void;
  tombstone(escrowId: string, reason: string): Promise<void>;
  /** Decapsulate the stored hybrid KEM ciphertext. Browser-only escape hatch
   *  for the demo's "show me R" debug view. */
  decapsulate(ct: { x25519_ct: Uint8Array; mlkem_ct: Uint8Array }): Uint8Array;
}

export interface MakeBrowserAgentOpts {
  agentId: DemoAgentId;
  storage?: Storage;
  /**
   * Optional RPC factory map for A-path predicate evaluation. In the demo
   * this is wired to viem against local anvil. Missing key → A-path fails
   * with `QIE_PREDICATE_UNSATISFIED`.
   */
  chainRpc?: Record<number, () => {
    getLog: (tx: `0x${string}`, idx: number) => Promise<{ address: string; topics: string[]; data: string } | null>;
  }>;
  /**
   * Optional C-path CAdES verifier. Demo can plug in the same browser
   * verifier used by `packages/web/src/lib/qesVerify.ts`. Default rejects
   * (safe) when absent.
   */
  qesVerify?: (p7s: Uint8Array, cert: Uint8Array, message: Uint8Array) => Promise<boolean>;
  /** Optional on-chain state reader (viem publicClient.readContract). */
  escrowStateReader?: (
    escrowId: string,
  ) => Promise<"NONE" | "ACTIVE" | "RELEASE_PENDING" | "RELEASED" | "REVOKED">;
  /** Optional notary verifier — same shape as server ctx.notaryVerify. */
  notaryVerify?: (
    notarySig: Uint8Array,
    notaryCert: Uint8Array,
    payloadJcs: Uint8Array,
  ) => Promise<{ chain: "trusted" | "untrusted"; sigValid: boolean; subject?: string }>;
}

interface PersistedKeys {
  hybrid: { x25519_sk: string; x25519_pk: string; mlkem_sk: string; mlkem_pk: string };
  ack_sk: string;
}

function getBackend(storage?: Storage): Storage {
  const s = storage ?? (globalThis as { localStorage?: Storage }).localStorage;
  if (!s) throw new Error("makeBrowserAgent: no localStorage available");
  return s;
}

function loadOrMintKeys(
  agentId: DemoAgentId,
  backend: Storage,
): { hybridPk: HybridPublicKey; hybridSk: HybridSecretKey; ackSk: Uint8Array } {
  const keyKey = `qie.demo.agent.${agentId}.keypair`;
  const raw = backend.getItem(keyKey);
  if (raw) {
    try {
      const p = JSON.parse(raw) as PersistedKeys;
      return {
        hybridPk: { x25519: hex2bytes(p.hybrid.x25519_pk), mlkem: hex2bytes(p.hybrid.mlkem_pk) },
        hybridSk: { x25519: hex2bytes(p.hybrid.x25519_sk), mlkem: hex2bytes(p.hybrid.mlkem_sk) },
        ackSk: hex2bytes(p.ack_sk),
      };
    } catch {
      // fall through and regenerate
    }
  }
  const { pk, sk } = generateHybridKeypair();
  const ackSk = randomBytes(32);
  const persisted: PersistedKeys = {
    hybrid: {
      x25519_sk: bytes2hex(sk.x25519),
      x25519_pk: bytes2hex(pk.x25519),
      mlkem_sk: bytes2hex(sk.mlkem),
      mlkem_pk: bytes2hex(pk.mlkem),
    },
    ack_sk: bytes2hex(ackSk),
  };
  backend.setItem(keyKey, JSON.stringify(persisted));
  return { hybridPk: pk, hybridSk: sk, ackSk };
}

const NOTARY_ATTEST_DOMAIN = "qie-notary-recover/v1";

export async function makeBrowserAgent(opts: MakeBrowserAgentOpts): Promise<BrowserAgent> {
  if (!DEMO_AGENT_IDS.includes(opts.agentId)) {
    throw new Error(`unknown demo agent id: ${opts.agentId}`);
  }
  const backend = getBackend(opts.storage);
  const { hybridPk, hybridSk, ackSk } = loadOrMintKeys(opts.agentId, backend);
  const ackPub = ackPublicKey(ackSk);
  const storageOpts = opts.storage !== undefined
    ? { agentId: opts.agentId, storage: opts.storage }
    : { agentId: opts.agentId };
  const store = new LocalStorageAdapter(storageOpts);
  const replay = new ReplayGuard(REPLAY_WINDOW_MS);
  const watchers = new Set<ChainEvents>();

  return {
    agentId: opts.agentId,
    hybridPublicKey: hybridPk,
    ackPublicKey: ackPub,

    async onEscrowReceived(body) {
      if (!body?.escrowId || !body?.config || !body?.ct || !body?.encR) {
        throw new Error("QIE_BAD_REQUEST: missing fields");
      }
      const cfg = hydrateConfig(body.config as WireEscrowConfig);
      const recomputed = computeEscrowId(cfg);
      if (recomputed.toLowerCase() !== body.escrowId.toLowerCase()) {
        throw new Error(`${QIE_ERRORS.CONFIG_MISMATCH}: escrowId != hash(config)`);
      }
      if (!cfg.agents.some(a => a.agent_id === opts.agentId)) {
        throw new Error("QIE_BAD_REQUEST: agent_id not in config");
      }
      const existing = await store.get(body.escrowId);
      if (existing) throw new Error("QIE_DUPLICATE: already stored");
      await store.put(body.escrowId, {
        escrowId: body.escrowId,
        config: body.config,
        ct: body.ct as EscrowRecord["ct"],
        encR: body.encR,
        state: "active",
        createdAt: Math.floor(Date.now() / 1000),
      });
      const ackSig = signAck(ackSk, body.escrowId, opts.agentId);
      return { agent_id: opts.agentId, ackSig: bytes2hex(ackSig) };
    },

    listInbox() {
      return store.list();
    },

    getEscrow(escrowId) {
      // sync-ish: LocalStorageAdapter.get is async-marked but backs onto
      // synchronous localStorage. Mirror the sync semantics here for React.
      const raw = backend.getItem(`qie.demo.agent.${opts.agentId}.escrow.${escrowId.toLowerCase()}`);
      if (!raw) return null;
      try { return JSON.parse(raw) as EscrowRecord; } catch { return null; }
    },

    async release(escrowId, body) {
      if (!body?.evidence || !body?.recipient_nonce) {
        return { ok: false, code: "QIE_BAD_REQUEST", message: "missing fields", httpStatus: 400 };
      }
      if (!replay.check(escrowId, body.recipient_nonce)) {
        return { ok: false, code: QIE_ERRORS.REPLAY_DETECTED, message: "nonce replayed", httpStatus: 409 };
      }
      const rec = await store.get(escrowId);
      if (!rec) return { ok: false, code: QIE_ERRORS.ESCROW_NOT_FOUND, message: "no such escrow", httpStatus: 404 };
      if (rec.state === "revoked") {
        return { ok: false, code: QIE_ERRORS.ESCROW_REVOKED, message: "revoked", httpStatus: 409 };
      }

      if (opts.escrowStateReader) {
        const onChain = await opts.escrowStateReader(escrowId);
        if (onChain !== "RELEASE_PENDING" && onChain !== "RELEASED") {
          return {
            ok: false,
            code: QIE_ERRORS.ESCROW_WRONG_STATE,
            message: `on-chain state is ${onChain}`,
            httpStatus: 409,
          };
        }
      }

      if (body.on_behalf_of) {
        if (!body.recipient_pk) {
          return { ok: false, code: QIE_ERRORS.NOTARY_MISMATCH, message: "recipient_pk required with on_behalf_of", httpStatus: 400 };
        }
        if (body.on_behalf_of.recipient_pk !== body.recipient_pk) {
          return { ok: false, code: QIE_ERRORS.NOTARY_MISMATCH, message: "on_behalf_of.recipient_pk mismatch", httpStatus: 400 };
        }
        if (!opts.notaryVerify) {
          return { ok: false, code: QIE_ERRORS.NOTARY_CHAIN_UNTRUSTED, message: "no notary verifier", httpStatus: 403 };
        }
        const payloadJcs = new TextEncoder().encode(jcsCanonicalize({
          domain: NOTARY_ATTEST_DOMAIN,
          escrowId,
          recipient_pk: body.recipient_pk,
        }));
        const result = await opts.notaryVerify(
          hex2bytes(body.on_behalf_of.notary_sig),
          hex2bytes(body.on_behalf_of.notary_cert),
          payloadJcs,
        );
        if (result.chain === "untrusted") {
          return { ok: false, code: QIE_ERRORS.NOTARY_CHAIN_UNTRUSTED, message: "notary cert not in LOTL", httpStatus: 403 };
        }
        if (!result.sigValid) {
          return { ok: false, code: QIE_ERRORS.NOTARY_SIG_BAD, message: "notary signature invalid", httpStatus: 403 };
        }
      }

      const cfg = hydrateConfig(rec.config as WireEscrowConfig);
      if (cfg.expiry && cfg.expiry < Math.floor(Date.now() / 1000)) {
        return { ok: false, code: QIE_ERRORS.ESCROW_EXPIRED, message: "expired", httpStatus: 409 };
      }
      const ev: Evidence = body.evidence.kind === "A"
        ? body.evidence
        : {
          kind: "C",
          countersig: {
            p7s: hex2bytes(body.evidence.countersig.p7s),
            cert: hex2bytes(body.evidence.countersig.cert),
          },
        };
      const result = await evaluatePredicate(ev, cfg, {
        rpc: (chainId) => {
          const f = opts.chainRpc?.[chainId];
          if (!f) throw new Error(`no RPC for chain ${chainId}`);
          return f();
        },
        qesVerify: opts.qesVerify ?? (async () => false),
      });
      if (!result.ok) {
        return {
          ok: false,
          code: QIE_ERRORS.PREDICATE_UNSATISFIED,
          message: result.message,
          httpStatus: 403,
        };
      }
      return { ok: true, ct: rec.ct, encR: rec.encR };
    },

    observeChain(watcher) {
      watchers.add(watcher);
      return () => {
        watchers.delete(watcher);
      };
    },

    async tombstone(escrowId, _reason) {
      await store.delete(escrowId);
    },

    decapsulate(ct) {
      return hybridDecapsulate(hybridSk, ct);
    },
  };
}

// Silence unused-var warnings for helpers we export for browser callers.
void dehydrateConfig;
void ed25519;
