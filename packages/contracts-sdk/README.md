# @qkb/contracts-sdk

Solidity SDK for gating contracts on QKB-verified Ukrainian identity.

## Install

**Foundry:**
```bash
forge install qkb-eth/contracts-sdk
```

Then add to `remappings.txt`:
```
@qkb/contracts-sdk/=lib/contracts-sdk/src/
```

**npm (for Hardhat):**
```bash
npm install @qkb/contracts-sdk
```

## Usage

```solidity
import { Verified, IQKBRegistry } from "@qkb/contracts-sdk/Verified.sol";

contract UkrainianDAO is Verified {
    constructor(IQKBRegistry registry) Verified(registry) {}

    function castVote(uint256 proposalId) external onlyVerifiedUkrainian {
        // Only verified Ukrainian holders may call.
    }
}
```

## Deployed registries

| Network | Address |
|---|---|
| Base mainnet (chainId 8453) | (TBD on launch) |
| Sepolia (chainId 11155111)  | see `fixtures/contracts/sepolia.json` in the QKB repo |

## License

MIT.
