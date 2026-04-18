# Phase 1 -> Phase 2 Registry Migration

Phase 2 (QIE) requires a fresh deployment of `QKBRegistry`: Solidity
contracts are non-upgradeable, and Phase 2 extends the storage layout
with

- nullifier maps (`usedNullifiers`, `nullifierToPk`, `revokedNullifiers`),
- the `Binding` struct (adds `algorithmTag` + `nullifier`),
- the escrow surface (`escrows`, register/revoke, getters),
- dual-verifier slots (`rsaVerifier` + `ecdsaVerifier`).

Phase 1's deployed `QKBRegistry` at
`0x7F36aF783538Ae8f981053F2b0E45421a1BF4815` on Sepolia cannot absorb
these extensions. Deploying `QKBRegistryV2` at a fresh address is the
intended migration path.

## For Holders

1. Your Phase 1 QES-bound material — the `(B, sigma_QES, cert_QES)`
   envelope — is unchanged. Nothing in your QES certificate needs to
   rotate.
2. Re-generate a 14-signal Groth16 proof against the Phase 2
   `QKBPresentation` circuit (the Web app will do this transparently).
   The new proof adds `rTL`, `algorithmTag`, and `nullifier` to the
   public signals.
3. Submit `register(proof, inputs)` against the v2 contract address
   (see `fixtures/qie/arbitrators/sepolia.json -> registry_v2`).
4. Your Phase 1 v1 binding remains valid at the v1 address for
   historical audit. Only v2 participates in Phase 2 escrow flows and
   nullifier-based revocation.

## For Relying Parties

Check both v1 (`fixtures/contracts/sepolia.json -> registry`) and v2
(`fixtures/qie/arbitrators/sepolia.json -> registry_v2`) addresses
when confirming a binding exists. Either is authoritative for the QKB
claim in isolation, but:

- only v2 carries `isEscrowActive(pkAddr)`,
- only v2 observes admin-published nullifier revocation via
  `revokedNullifiers`,
- only v2 enforces the on-chain `rTL == trustedListRoot` check
  (v1's split-proof fallback couldn't carry the root).

New relying-party integrations should target v2 exclusively.

## Deploy steps

1. Circuits-eng ships fresh 14-signal `QKBGroth16VerifierRSA.sol` and
   `QKBGroth16VerifierEcdsa.sol` from the Phase 2 ceremony
   (`performance-12x` Fly machine — spec §14.2).
2. Lead deploys each verifier to Sepolia and records the addresses.
3. Lead runs `DeployRegistryV2.s.sol` with
   `RSA_VERIFIER_ADDR`, `ECDSA_VERIFIER_ADDR`, `ROOT_TL`,
   `ADMIN_PRIVATE_KEY`, `ADMIN_ADDRESS` set in `.env`.
4. Resulting address is written to
   `fixtures/qie/arbitrators/sepolia.json` under `registry_v2`.
5. Lead pumps the new fixtures to web + qie worktrees.

## Notes on `revokeEscrow` auth

Phase 1 public signals authenticate pk ownership only — no
escrow-specific signals exist. The contract relies on

> A valid Phase-1 proof for this pk implies the Holder, implies
> authority to revoke the Holder's own escrow.

We intentionally do NOT add `escrowId` as a public signal in any
circuit: that would require re-proving (and potentially a fresh
ceremony) for every revoke. The existing per-pk proof is sufficient.

---

## V2 -> V3 (Split-Proof Pivot, 2026-04-18)

### Why

Phase 2 shipped a unified 14-signal presentation circuit (`QKBPresentation.circom`)
targeting V2. Setting up the Groth16 proving key for that circuit
**fails deterministically** on every RAM budget we can provision — the
circuit compiles to ~10.85 M R1CS constraints and snarkjs /
ffjavascript hits V8's 4 GiB ArrayBuffer per-object limit inside the
native tauG1/tauG2 section readers during `groth16 setup`. Confirmed
across four attempts on a Fly `performance-12x:98304MB` VM (80 GiB
Node heap, 96 GiB physical). Not fixable by adding RAM; the limit is
V8 + ffjavascript-native.

Spec: `docs/superpowers/specs/2026-04-18-split-proof-pivot.md`.

The pivot reverts to Phase-1's §5.4 split architecture:

- **Leaf circuit** — 13 public signals, ~7.68 M constraints. Carries
  per-person data: `pkX` / `pkY` limbs, `ctxHash`, `declHash`,
  `timestamp`, `nullifier`, and a `leafSpkiCommit` output that glues to
  the chain proof. pow-24 ptau, ~30 GB setup peak — fits a
  `performance-4x:16384MB` Fly box.
- **Chain circuit** — 5 public signals, ~3.20 M constraints. Carries
  trusted-list Merkle inclusion: `rTL`, `algorithmTag`, and the same
  `leafSpkiCommit`. pow-22 ptau, ~12 GB setup peak. Shares layout
  across RSA and ECDSA.

`QKBVerifier.verify` is rewritten to take both proofs and require
`leafInputs.leafSpkiCommit == chainInputs.leafSpkiCommit` on-chain.

### V3 is a fresh contract, not an upgrade

Storage layout changes — two verifier slots become four
(`rsaLeafVerifier`, `rsaChainVerifier`, `ecdsaLeafVerifier`,
`ecdsaChainVerifier`), and the `VerifierUpdated` event gains an
`isLeaf` discriminator. V3 is therefore deployed at a fresh address
via `script/DeployRegistryV3.s.sol`.

### V2 Sepolia deploy is abandoned

V2 on Sepolia at `0xcac30ff7B0566b6E991061cAA5C169c82A4319a4` never
held any real registrations — it was deployed with stub verifiers
only while the unified ceremony was still being attempted. Nothing
needs to migrate out of V2. Consider the address dead.

### For Holders

There are no V2 -> V3 holders to migrate: V2 had zero real
registrations. Submit your first registration directly to V3 at the
address published in `fixtures/qie/arbitrators/sepolia.json ->
registry_v3`, using the split-proof pair (two Groth16 proofs built
from the same CAdES `.p7s` — the Web app handles this transparently).

The Phase-1 V1 registry at
`0x7F36aF783538Ae8f981053F2b0E45421a1BF4815` remains valid for its
Phase-1 bindings. V1 and V3 coexist; a Phase-1 holder who never
rotated to V2 (i.e. everyone) can optionally re-register against V3
to gain escrow eligibility + nullifier-based Sybil protection.

### For Relying Parties

- **New integrations**: query V3 only.
- **Existing Phase-1 integrations**: continue reading V1 for legacy
  bindings; add a V3 read for any Phase-2 functionality (escrow,
  nullifier revocation).
- **Do not** query V2 — it is empty and will never hold data.

### Deploy steps (V3)

1. Circuits-eng ships split-proof leaf + chain verifiers per algorithm
   from the pow-24 + pow-22 ceremonies:
   `QKBGroth16VerifierEcdsaLeaf.sol`,
   `QKBGroth16VerifierEcdsaChain.sol`,
   (RSA variants deferred until real RSA QES test material lands).
2. Lead deploys each verifier to Sepolia and records the four
   addresses.
3. Lead runs `DeployRegistryV3.s.sol` with
   `RSA_LEAF_VERIFIER_ADDR`, `RSA_CHAIN_VERIFIER_ADDR`,
   `ECDSA_LEAF_VERIFIER_ADDR`, `ECDSA_CHAIN_VERIFIER_ADDR`, `ROOT_TL`,
   `ADMIN_PRIVATE_KEY`, `ADMIN_ADDRESS` set in `.env` (omit the four
   verifier envs and set `USE_STUB_VERIFIER=true` for anvil dry-runs
   only).
4. Resulting address is written to
   `fixtures/qie/arbitrators/sepolia.json` under `registry_v3`.
5. Lead pumps the new fixtures to web + qie worktrees.

### Gas note

`QKBRegistryV3.register` costs ~600k on mainnet (two Groth16 pairings).
See `packages/contracts/CLAUDE.md` §8.1 for the target + rationale.
