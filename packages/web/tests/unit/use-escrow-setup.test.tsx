import { describe, it, expect, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import {
  generateHybridKeypair,
  hybridDecapsulate,
  reconstructShares,
  unwrapShare,
  decryptRecovery,
  computeEscrowId,
  type HybridPublicKey,
  type HybridSecretKey,
} from '@qkb/qie-core';
import {
  useEscrowSetup,
  buildSetupEnvelope,
  type AgentDescriptor,
  type EscrowSetupInput,
} from '../../src/features/qie/use-escrow-setup';

function hexToBytes(hex: string): Uint8Array {
  const s = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Arbitrary uncompressed secp256k1 point — shape-only, not verified here.
const HOLDER_PK =
  '0x04' +
  'a'.repeat(128) as `0x04${string}`;

function makeFixture(n: number, threshold: number): {
  input: EscrowSetupInput;
  agentSks: HybridSecretKey[];
  agentPks: HybridPublicKey[];
} {
  const kps = Array.from({ length: n }, () => generateHybridKeypair());
  const agents: AgentDescriptor[] = kps.map((kp, i) => ({
    id: `agent-${i}`,
    url: `https://a${i}.example/`,
    hybridPk: kp.pk,
  }));
  const recipient = generateHybridKeypair();
  const R = new TextEncoder().encode('top-secret-recovery-material');
  const input: EscrowSetupInput = {
    R,
    holderPk: HOLDER_PK,
    agents,
    threshold,
    recipientHybridPk: recipient.pk,
    arbitrator: {
      chainId: 11155111,
      address: '0x' + '1'.repeat(40) as `0x${string}`,
      kind: 'authority',
    },
    expiry: 1_800_000_000,
    jurisdiction: 'UA',
  };
  return { input, agentSks: kps.map((kp) => kp.sk), agentPks: kps.map((kp) => kp.pk) };
}

describe('buildSetupEnvelope — real qie-core round-trip', () => {
  it('produces per-agent wraps that each decapsulate and unwrap to their share', () => {
    const { input, agentSks } = makeFixture(3, 2);
    const env = buildSetupEnvelope(input);
    expect(env.perAgent).toHaveLength(3);
    expect(env.escrowId).toBe(computeEscrowId(env.config));

    const encoder = new TextEncoder();
    const recovered = env.perAgent.map((pa, i) => {
      const ss = hybridDecapsulate(agentSks[i]!, pa.kem_ct);
      const aad = encoder.encode(env.escrowId + pa.agent_id);
      return unwrapShare(ss, pa.wrap, aad);
    });
    // Threshold = 2: any t shares reconstruct k_esc, decrypt(encR) == R.
    const k_esc_ab = reconstructShares([recovered[0]!, recovered[1]!]);
    const decryptedAB = decryptRecovery(k_esc_ab, env.encR, env.escrowId);
    expect(new TextDecoder().decode(decryptedAB)).toBe('top-secret-recovery-material');

    const k_esc_bc = reconstructShares([recovered[1]!, recovered[2]!]);
    expect(decryptRecovery(k_esc_bc, env.encR, env.escrowId)).toEqual(decryptedAB);
  });

  it('uses the injected random source so k_esc is deterministic in tests', () => {
    const { input } = makeFixture(2, 2);
    const rng = (len: number) => new Uint8Array(len).fill(7);
    const a = buildSetupEnvelope(input, rng);
    const b = buildSetupEnvelope(input, rng);
    // encR is IV-randomised inside @noble/ciphers, so we compare only the
    // deterministic pieces: the config + escrowId.
    expect(a.escrowId).toBe(b.escrowId);
    expect(a.config).toEqual(b.config);
  });
});

describe('useEscrowSetup — real envelope wiring', () => {
  it('POSTs one envelope per agent and transitions idle -> submitting -> done', async () => {
    const { input, agentSks } = makeFixture(2, 2);
    const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
    const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, body: JSON.parse(String(init?.body ?? 'null')) });
      return new Response('{}', { status: 200 });
    });

    const { result } = renderHook(() => useEscrowSetup({ fetchImpl }));
    expect(result.current.state.phase).toBe('idle');

    await act(async () => {
      await result.current.submit(input);
    });

    await waitFor(() => expect(result.current.state.phase).toBe('done'));
    expect(calls).toHaveLength(2);
    expect(calls[0]!.url).toBe('https://a0.example/escrow');
    expect(calls[1]!.url).toBe('https://a1.example/escrow');

    // Body shape matches the agent's PostEscrowBody.
    const body0 = calls[0]!.body as {
      escrowId: `0x${string}`;
      config: { agents: Array<{ agent_id: string }> };
      ct: { kem_ct: { x25519_ct: string; mlkem_ct: string }; wrap: string };
      encR: string;
    };
    expect(body0.escrowId).toBe(result.current.state.escrowId);
    expect(body0.config.agents.map((a) => a.agent_id)).toEqual(['agent-0', 'agent-1']);
    expect(body0.ct.kem_ct.x25519_ct).toMatch(/^0x[0-9a-f]+$/);
    expect(body0.ct.wrap).toMatch(/^0x[0-9a-f]+$/);
    expect(body0.encR).toMatch(/^0x[0-9a-f]+$/);

    // Round-trip: decrypt using the matching agent secret keys to confirm
    // real crypto was used (no stubbing, no placeholders).
    const encoder = new TextEncoder();
    const shares = calls.map((c, i) => {
      const body = c.body as {
        escrowId: `0x${string}`;
        ct: { kem_ct: { x25519_ct: string; mlkem_ct: string }; wrap: string };
      };
      const kem_ct = {
        x25519_ct: hexToBytes(body.ct.kem_ct.x25519_ct),
        mlkem_ct: hexToBytes(body.ct.kem_ct.mlkem_ct),
      };
      const ss = hybridDecapsulate(agentSks[i]!, kem_ct);
      const aad = encoder.encode(body.escrowId + `agent-${i}`);
      return unwrapShare(ss, hexToBytes(body.ct.wrap), aad);
    });
    const k_esc = reconstructShares(shares);
    const encRHex = (calls[0]!.body as { encR: string }).encR;
    const R = decryptRecovery(k_esc, hexToBytes(encRHex), result.current.state.escrowId!);
    expect(new TextDecoder().decode(R)).toBe('top-secret-recovery-material');
  });

  it('marks the failing agent and stops on first HTTP error', async () => {
    const { input } = makeFixture(2, 2);
    const fetchImpl = vi.fn(async (url: string) =>
      url.includes('a1.example')
        ? new Response('nope', { status: 500 })
        : new Response('{}', { status: 200 }),
    );

    const { result } = renderHook(() => useEscrowSetup({ fetchImpl }));
    await act(async () => {
      await result.current.submit(input);
    });
    await waitFor(() => expect(result.current.state.phase).toBe('error'));
    expect(result.current.state.error).toMatch(/agent agent-1/);
    expect(result.current.state.acks['agent-0']).toBe('ok');
    expect(result.current.state.acks['agent-1']).toBe('pending');
  });

  it('surfaces build errors without any network call', async () => {
    const { input } = makeFixture(2, 2);
    const bad: EscrowSetupInput = { ...input, threshold: 99 }; // t > n
    const fetchImpl = vi.fn(async () => new Response('{}'));

    const { result } = renderHook(() => useEscrowSetup({ fetchImpl }));
    await act(async () => {
      await result.current.submit(bad);
    });
    await waitFor(() => expect(result.current.state.phase).toBe('error'));
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(result.current.state.error).toMatch(/threshold/);
  });
});
