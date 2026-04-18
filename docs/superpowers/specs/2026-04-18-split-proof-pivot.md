# Split-Proof Pivot — Spec Amendment

> Amends §14.3 of `2026-04-17-qie-phase2-design.md` and §13.1-§13.4 of `packages/contracts/CLAUDE.md`. Date: 2026-04-18. Status: authoritative. Supersedes the "Phase 2 restores unified 14-signal layout" decision.

## Motivation

Phase 2's unified circuit — adding nullifier + chain-validation to the Phase-1 leaf — reaches 10.85 M constraints. snarkjs / ffjavascript fails `groth16 setup` on this size **deterministically** with `std::bad_alloc` inside the native tauG1/tauG2 section readers, at every Node heap budget we can provision on Fly (tested up to 80 GiB on `performance-12x:98304MB`, same failure at the same log line). Diagnosis: V8 ArrayBuffer 4 GiB per-object cap inside ffjavascript native bindings. Not fixable by more RAM.

Phase 1's §5.4 fallback already specified the split: leaf-side circuit carrying per-person data + chain-side circuit carrying trusted-list membership, glued on-chain via `leafSpkiCommit` equality. `QKBPresentationEcdsaLeaf.circom` exists and compiles; `QKBPresentationEcdsaChain.circom` was never written. Phase 2 is reverting to this architecture.

## New architecture

Two Groth16 circuits per algorithm, two ceremonies per algorithm, two proofs per register/revoke call, one on-chain equality check glueing them.

### Leaf circuit — `QKBPresentationEcdsaLeaf.circom`

Carries R_QKB constraints 1, 2, 5, 6 + the new nullifier primitive (§14.4). Witnesses a single QES: the leaf cert, the signed binding, the declaration, the context hash.

**Public signals (13):**
```
[0..3]   pkX limbs (4 × uint64 LE)
[4..7]   pkY limbs (4 × uint64 LE)
[8]      ctxHash
[9]      declHash
[10]     timestamp
[11]     nullifier         — NEW, §14.4 person-level
[12]     leafSpkiCommit    — output; glue to chain proof
```

Target size: ~7.68 M constraints (Phase-1 leaf at 7.63 M + ~50 k for X509SubjectSerial + Poseidon-5 + Poseidon-2). Ceremony: pow-24 ptau (2^24 = 16.77 M capacity), `performance-4x:16384MB` Fly machine.

### Chain circuit — `QKBPresentationEcdsaChain.circom`

Carries R_QKB constraints 3, 4. Witnesses the chain: leaf TBS, intermediate cert DER, intermediate signature over leaf TBS, Merkle proof for intermediate under `rTL`.

**Public signals (5):**
```
[0]      rTL               — trusted-list Merkle root
[1]      algorithmTag      — 0=RSA, 1=ECDSA
[2]      leafSpkiCommit    — output; must equal leaf proof's leafSpkiCommit
[3..?]   (none further)
```

Target size: ~3.2 M constraints (unified total minus leaf minus nullifier ≈ 10.85 M − 7.68 M). Ceremony: pow-22 ptau (2^22 = 4.19 M capacity), `performance-4x:16384MB`.

### On-chain equality glue

`QKBVerifier.verify(proofLeaf, inputsLeaf, proofChain, inputsChain)`:

1. Call leaf Groth16 verifier with `inputsLeaf` (13 signals).
2. Call chain Groth16 verifier with `inputsChain` (5 signals).
3. Require `inputsLeaf.leafSpkiCommit == inputsChain.leafSpkiCommit`.
4. Require `DeclarationHashes.isAllowed(inputsLeaf.declHash)`.

If any step fails, revert. `toPkAddress` consumes `inputsLeaf.pkX / pkY`, unchanged.

## Interface impact

### `QKBVerifier.Inputs` splits into two structs

```solidity
struct LeafInputs {
    uint256[4] pkX;
    uint256[4] pkY;
    bytes32    ctxHash;
    bytes32    declHash;
    uint64     timestamp;
    bytes32    nullifier;
    bytes32    leafSpkiCommit;
}

struct ChainInputs {
    bytes32  rTL;
    uint8    algorithmTag;
    bytes32  leafSpkiCommit;
}
```

### `IGroth16Verifier` widens to two distinct interfaces

```solidity
interface IGroth16LeafVerifier {
    function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[13] input)
        external view returns (bool);
}
interface IGroth16ChainVerifier {
    function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[5] input)
        external view returns (bool);
}
```

### `QKBRegistryV3` — fresh deploy

V2's storage is keyed to a single-proof interface. V3 is a fresh contract (not upgrade) absorbing:

- `rsaLeafVerifier`, `rsaChainVerifier`, `ecdsaLeafVerifier`, `ecdsaChainVerifier` — four settable slots, four admin rotators.
- `register(proofLeaf, leafInputs, proofChain, chainInputs)` — split signature.
- `registerEscrow(...)` / `revokeEscrow(...)` — same split-signature pattern.
- Revert taxonomy adds `LeafSpkiCommitMismatch()`; `UnknownAlgorithm` still fires on `chainInputs.algorithmTag` not in {0,1}; all other errors carry over.

V2 stays deployed on Sepolia for reference but accumulates no further registrations. Sepolia V3 deploy at fresh address replaces it for the demo.

### Web witness builder

Rewritten to emit two witness objects from the same CAdES input, compute both Groth16 proofs in parallel (two `snarkjs.groth16.fullProve` calls, ~1.5× single-proof wall time on consumer hardware), and submit both to `register(...)`. Shared fields (pkX/pkY, ctxHash, declHash, timestamp, leafSpkiCommit, nullifier) are computed once and threaded into both witnesses.

## Why this is cheaper than one unified ceremony

| Size | Unified | Split-leaf | Split-chain |
|---|---|---|---|
| Constraints | 10.85 M | ~7.68 M | ~3.2 M |
| Minimum ptau | 2^25 (37 GB) | 2^24 (18 GB) | 2^22 (4.5 GB) |
| Setup peak RAM (measured / est) | >80 GB (fails) | ~30 GB | ~12 GB |
| Fly VM | performance-12x:98304MB (fails) | performance-4x:16384MB | performance-4x:16384MB |
| Zkey size | ~8 GB | ~5.5 GB | ~2.3 GB |
| .wasm size | ~44 MB | ~30 MB | ~14 MB |

Both leaf + chain ceremonies succeed on a $0.20/hour VM. Prover wall time client-side: leaf ~40 s, chain ~20 s, total ~60 s, vs ~50 s for the unified proof — ~20 % slower for the user, but we actually get to ship.

## Backwards compatibility

None. V2 is abandoned. Holders who registered against V2 (none exist yet — V2 was deployed today with stub verifiers only) would need to re-register against V3.

## Constraint budget

| Circuit | Estimate |
|---|---|
| Leaf ECDSA | 7.68 M (7.63 M base + 50 k nullifier) |
| Chain ECDSA | 3.20 M (hashSA + EcdsaP256Verify + PoseidonChunkHashVar + Merkle-16) |
| Leaf RSA | 5.5 M (deferred until we have real RSA QES material) |
| Chain RSA | 4.5 M (deferred) |

Cap per circuit: 15 M (pow-24 leaves 7 M headroom, pow-22 leaves 1 M headroom for chain).

## Out of scope

- RSA variant. Same split applies; execute when real RSA QES test material lands.
- Native setup tooling (rapidsnark is prove-only; no known Rust Groth16 setup at this scale). Investigated and declined.
