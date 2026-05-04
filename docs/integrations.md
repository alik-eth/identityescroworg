# Integrating with zkqes Verification

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

This guide explains how to gate your contract or webapp on whether a
caller has registered as a verified Ukrainian via the zkqes protocol.

## On-chain (Solidity)

See `@zkqes/contracts-sdk` package. The minimal pattern:

```solidity
import { Verified, IZkqesRegistry } from "@zkqes/contracts-sdk/Verified.sol";

contract MyDApp is Verified {
    constructor(IZkqesRegistry r) Verified(r) {}
    function privileged() external onlyVerifiedUkrainian { /* ... */ }
}
```

Pass the registry address from `fixtures/contracts/<network>.json` to the
constructor.

## Off-chain (TypeScript, viem)

See `@zkqes/sdk` package:

```ts
import { isVerified } from '@zkqes/sdk';
import { createPublicClient, http } from 'viem';
import { base } from 'viem/chains';
import { ZKQES_DEPLOYMENTS } from '@zkqes/sdk/deployments';

const client = createPublicClient({ chain: base, transport: http() });
const ok = await isVerified(
  client,
  ZKQES_DEPLOYMENTS.base.registry,
  '0xUserAddress'
);
```

## Trust model

`registry.isVerified(addr)` returns `true` iff `addr` is the wallet that
submitted the `register(...)` transaction with a valid Diia QES Groth16
proof. The registry is the authoritative source for verification —
gating the certificate NFT, your DAO, your airdrop, etc., should all
read this same contract.

The `ZkqesCertificate` contract is one example consumer; your contract
follows the same pattern.

## Caveats

- A verified user can transfer their wallet but NOT their identity. A
  fresh registration from a new wallet will be blocked because the
  nullifier is already consumed.
- The `tokenIdByNullifier` mapping in the NFT contract gates one mint
  per identity, even across wallet transfers.
- Mint window in `ZkqesCertificate` is one-shot at deploy. Your own
  contract is free to set its own time semantics.

## Audit + bug bounty

The zkqes protocol contracts are open source and unaudited as of this
release. See `SECURITY.md` for vulnerability disclosure. Independent
audit before mainnet usage is the consumer's responsibility.
