// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { IArbitrator } from "./IArbitrator.sol";
import { IRegistryGate } from "./IRegistryGate.sol";

/// @notice Arbitrator that emits `Unlock` iff a designated off-chain
///         authority (a judge, a regulator, a court clerk, etc.) produces
///         a secp256k1 signature over the release digest.
///
///         MVP refinement §0.2 — the digest now binds six fields: the
///         escrowId, the recipient hybrid-KEM pk, the opaque evidenceHash,
///         the kindHash (keccak of "death_certificate" | "court_order" | …),
///         an opaque 32-byte referenceHash (e.g. sha256 of an ISO reference
///         string), and the authority's `issuedAt` timestamp. The three
///         metadata fields are surfaced on-chain via a second, additive
///         `UnlockEvidence` event so agents can record provenance without
///         breaking the frozen `IArbitrator.Unlock(bytes32,bytes)`
///         invariant.
///
///         §0.3 — before emitting either event, the arbitrator calls
///         `IRegistryGate(registry).notifyReleasePending(escrowId)` so the
///         on-chain state-machine hop ACTIVE → RELEASE_PENDING happens
///         atomically with the release. A revert in the registry (wrong
///         arbitrator, wrong state, unknown id) aborts the whole release.
///
///         `evidenceHash` is still the replay-protection primitive — a
///         fresh authority signature is required for each release.
contract AuthorityArbitrator is IArbitrator {
    address public immutable authority;
    IRegistryGate public immutable registry;
    mapping(bytes32 => bool) public evidenceHashUsed;

    /// @dev Additive to `IArbitrator.Unlock` — carries the release evidence
    ///      metadata so agents and UIs can display provenance. Emitted
    ///      immediately before `Unlock`.
    event UnlockEvidence(
        bytes32 indexed escrowId,
        bytes32 kindHash,
        bytes32 referenceHash,
        bytes32 evidenceHash,
        uint64  issuedAt
    );

    error ZeroAddr();
    error EvidenceReplayed();
    error BadAuthoritySig();
    error BadSigLength();

    constructor(address _authority, address _registry) {
        if (_authority == address(0) || _registry == address(0)) revert ZeroAddr();
        authority = _authority;
        registry = IRegistryGate(_registry);
    }

    /// @notice Anyone can submit (the authority signature is the auth).
    ///         Callers should expect this to revert when evidence is reused,
    ///         the signature is not by `authority`, or the registry rejects
    ///         the state-machine hop.
    function requestUnlock(
        bytes32 escrowId,
        bytes calldata recipientHybridPk,
        bytes32 evidenceHash,
        bytes32 kindHash,
        bytes32 referenceHash,
        uint64  issuedAt,
        bytes calldata authoritySig
    ) external {
        if (evidenceHashUsed[evidenceHash]) revert EvidenceReplayed();
        bytes32 digest = keccak256(abi.encode(
            escrowId, recipientHybridPk, evidenceHash, kindHash, referenceHash, issuedAt
        ));
        if (_recover(digest, authoritySig) != authority) revert BadAuthoritySig();
        evidenceHashUsed[evidenceHash] = true;

        // Registry hook FIRST so a revert in the registry stops the whole
        // release — agents watching `Unlock` must never see a release that
        // the registry state machine hasn't accepted.
        registry.notifyReleasePending(escrowId);

        emit UnlockEvidence(escrowId, kindHash, referenceHash, evidenceHash, issuedAt);
        emit Unlock(escrowId, recipientHybridPk);
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert BadSigLength();
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
