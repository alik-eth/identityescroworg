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
