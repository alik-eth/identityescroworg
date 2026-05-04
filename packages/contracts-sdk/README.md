# @zkqes/contracts-sdk

Solidity SDK for gating contracts on zkqes-verified Ukrainian identity.

## Install

**Foundry:**
```bash
forge install alik-eth/zkqes
```

Then add to `remappings.txt`:
```
@zkqes/contracts-sdk/=lib/contracts-sdk/src/
```

**npm (for Hardhat):**
```bash
npm install @zkqes/contracts-sdk
```

## Usage

```solidity
import { Verified, IZkqesRegistry } from "@zkqes/contracts-sdk/Verified.sol";

contract UkrainianDAO is Verified {
    constructor(IZkqesRegistry registry) Verified(registry) {}

    function castVote(uint256 proposalId) external onlyVerifiedUkrainian {
        // Only verified Ukrainian holders may call.
    }
}
```

## Deployed registries

| Network | Address |
|---|---|
| Base mainnet (chainId 8453) | (TBD on launch) |
| Sepolia (chainId 11155111)  | see `fixtures/contracts/sepolia.json` in the zkqes repo |

## License

MIT.
