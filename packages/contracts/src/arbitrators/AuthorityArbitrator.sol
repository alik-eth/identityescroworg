// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { IArbitrator } from "./IArbitrator.sol";

/// @notice Arbitrator that emits `Unlock` iff a designated off-chain
///         authority (a judge, a regulator, a court clerk, etc.) produces
///         a secp256k1 signature over `keccak256(abi.encode(escrowId,
///         recipientHybridPk, evidenceHash))`.
///
///         `evidenceHash` is included in the signed digest to bind the
///         release decision to a specific off-chain artefact (court order
///         DOI, docket PDF hash, etc.). The same evidenceHash cannot be
///         replayed — a fresh authority signature is required for each
///         release. This is a one-shot release pattern: duplicate submission
///         reverts.
contract AuthorityArbitrator is IArbitrator {
    address public immutable authority;
    mapping(bytes32 => bool) public evidenceHashUsed;

    constructor(address _authority) {
        require(_authority != address(0), "AuthorityArbitrator: zero authority");
        authority = _authority;
    }

    /// @notice Anyone can submit (the authority signature is the auth).
    ///         Callers should expect this to revert when evidence is reused
    ///         or the signature is not by `authority`.
    function requestUnlock(
        bytes32 escrowId,
        bytes calldata recipientHybridPk,
        bytes32 evidenceHash,
        bytes calldata authoritySig
    ) external {
        require(!evidenceHashUsed[evidenceHash], "AuthorityArbitrator: evidence replayed");
        bytes32 digest = keccak256(abi.encode(escrowId, recipientHybridPk, evidenceHash));
        address signer = _recover(digest, authoritySig);
        require(signer == authority, "AuthorityArbitrator: bad authority sig");
        evidenceHashUsed[evidenceHash] = true;
        emit Unlock(escrowId, recipientHybridPk);
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "AuthorityArbitrator: bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(digest, v, r, s);
    }
}
