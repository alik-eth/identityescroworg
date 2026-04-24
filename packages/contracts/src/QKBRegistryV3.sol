// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {
    QKBVerifier,
    IGroth16LeafVerifier,
    IGroth16ChainVerifier
} from "./QKBVerifier.sol";
import { IRegistryGate } from "./arbitrators/IRegistryGate.sol";

/// @notice Split-proof register-then-authenticate registry for QKB-bound
///         secp256k1 keys. Fresh deploy (NOT an upgrade of V2 — storage
///         layout changes). Per the 2026-04-18 split-proof pivot, a
///         registration carries two Groth16 proofs:
///
///           1. Leaf proof (13 public signals) — holder binding data: pk,
///              ctx, declaration, timestamp, scoped credential nullifier,
///              plus a `leafSpkiCommit` glue output.
///           2. Chain proof (5 public signals) — trusted-list membership:
///              rTL, algorithmTag (0 = RSA, 1 = ECDSA), and the same
///              `leafSpkiCommit` (must equal the leaf's).
///
///         The registry holds four settable verifier slots — one leaf
///         verifier + one chain verifier per algorithm — and dispatches
///         on `chainInputs.algorithmTag`. The leaf circuit carries no
///         `algorithmTag`; it is authoritative on the chain side only.
///
///         Spec:  `docs/superpowers/specs/2026-04-18-split-proof-pivot.md`
///         Orch:  `docs/superpowers/plans/2026-04-18-split-proof-orchestration.md`
///
///         V2 registry remains deployed at Sepolia
///         `0xcac30ff7B0566b6E991061cAA5C169c82A4319a4` (abandoned; stub
///         verifiers only, zero real registrations). Relying parties
///         should dual-lookup — prefer V3, fall back to V2 only for the
///         (unlikely) Phase-1 legacy holder population.
contract QKBRegistryV3 is IRegistryGate {
    /// @dev Domain string for the `expire` signature digest. Must stay in
    ///      lock-step with `test/helpers/SignatureHelpers.sol::EXPIRE_DOMAIN`.
    string private constant EXPIRE_DOMAIN = "QKB_EXPIRE_V1";

    uint8 internal constant ALG_RSA = 0;
    uint8 internal constant ALG_ECDSA = 1;

    enum Status {
        NONE,
        ACTIVE,
        EXPIRED
    }

    struct Binding {
        Status status;
        uint8 algorithmTag;
        uint64 boundAt;
        uint64 expiredAt;
        bytes32 ctxHash;
        bytes32 declHash;
        bytes32 nullifier;
    }

    /// @dev Maximum age of a binding proof, measured against
    ///      `leafInputs.timestamp` at `register` time. Per spec §6.2.
    uint64 public constant MAX_AGE = 90 days;

    // -------------------------------------------------------------------
    // Verifier slots — four slots, one leaf + one chain per algorithm.
    // -------------------------------------------------------------------

    IGroth16LeafVerifier  public rsaLeafVerifier;
    IGroth16ChainVerifier public rsaChainVerifier;
    IGroth16LeafVerifier  public ecdsaLeafVerifier;
    IGroth16ChainVerifier public ecdsaChainVerifier;

    bytes32 public trustedListRoot;
    address public admin;

    mapping(address => Binding) public bindings;

    /// @dev Scoped credential nullifier primitive (spec §14.4). This prevents
    ///      duplicate registration for the same context + QES identifier
    ///      namespace; it is not a pan-eIDAS natural-person deduplicator.
    mapping(bytes32 => bool)    public usedNullifiers;
    mapping(bytes32 => address) public nullifierToPk;
    mapping(bytes32 => bytes32) public revokedNullifiers;

    /// @dev QIE escrow state machine (MVP refinement §0.3) — unchanged
    ///      from V2 semantics.
    enum EscrowState { NONE, ACTIVE, RELEASE_PENDING, RELEASED, REVOKED }

    uint64 public constant RELEASE_TIMEOUT = 48 hours;

    struct EscrowEntry {
        bytes32 escrowId;
        address arbitrator;
        uint64 expiry;
        uint64 releasePendingAt;
        EscrowState state;
    }

    mapping(address => EscrowEntry) public escrows;
    mapping(bytes32 => address)     public escrowIdToPkAddr;

    // -------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------

    event BindingRegistered(
        address indexed pkAddr,
        uint8 indexed algorithmTag,
        bytes32 ctxHash,
        bytes32 declHash,
        bytes32 nullifier
    );
    event BindingExpired(address indexed pkAddr);
    event TrustedListRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);
    /// @dev Split-proof rotation event. `isLeaf` discriminates the four
    ///      rotation streams so indexers can cleanly follow each slot
    ///      without relying on address comparisons.
    event VerifierUpdated(
        uint8 indexed algorithmTag,
        bool  indexed isLeaf,
        address oldVerifier,
        address newVerifier
    );
    event NullifierRevoked(bytes32 indexed nullifier, address indexed pkAddr, bytes32 reasonHash);
    event EscrowRegistered(address indexed pkAddr, bytes32 indexed escrowId, address arbitrator, uint64 expiry);
    event EscrowRevoked(address indexed pkAddr, bytes32 indexed escrowId, bytes32 reasonHash);
    event EscrowReleasePendingRequested(bytes32 indexed escrowId, address indexed arbitrator, uint64 at);
    event EscrowReleased(bytes32 indexed escrowId, address indexed arbitrator);
    event EscrowReleaseCancelled(bytes32 indexed escrowId, address indexed pkAddr);

    // -------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------

    error AlreadyBound();
    error BindingTooOld();
    error BindingFromFuture();
    error InvalidProof();
    error UnknownAlgorithm();
    error RootMismatch();
    error NullifierUsed();
    error NullifierAlreadyRevoked();
    error UnknownNullifier();
    error NotBound();
    error BadExpireSig();
    error NotAdmin();
    error ZeroAddress();
    error EscrowExists();
    error NoEscrow();
    error EscrowAlreadyRevoked();
    error EscrowExpiryInPast();
    error EscrowReleasePending();
    error EscrowAlreadyReleased();
    error NotArbitrator();
    error UnknownEscrowId();
    error WrongState();
    /// @dev Split-proof glue: leaf and chain proofs disagree on the SPKI
    ///      they attest to. Unique to V3.
    error LeafSpkiCommitMismatch();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor(
        IGroth16LeafVerifier  rsaLeaf_,
        IGroth16ChainVerifier rsaChain_,
        IGroth16LeafVerifier  ecdsaLeaf_,
        IGroth16ChainVerifier ecdsaChain_,
        bytes32 initialRoot,
        address initialAdmin
    ) {
        if (address(rsaLeaf_)    == address(0)) revert ZeroAddress();
        if (address(rsaChain_)   == address(0)) revert ZeroAddress();
        if (address(ecdsaLeaf_)  == address(0)) revert ZeroAddress();
        if (address(ecdsaChain_) == address(0)) revert ZeroAddress();
        if (initialAdmin         == address(0)) revert ZeroAddress();

        rsaLeafVerifier    = rsaLeaf_;
        rsaChainVerifier   = rsaChain_;
        ecdsaLeafVerifier  = ecdsaLeaf_;
        ecdsaChainVerifier = ecdsaChain_;
        trustedListRoot    = initialRoot;
        admin              = initialAdmin;

        emit AdminTransferred(address(0), initialAdmin);
        emit TrustedListRootUpdated(bytes32(0), initialRoot);
        emit VerifierUpdated(ALG_RSA,   true,  address(0), address(rsaLeaf_));
        emit VerifierUpdated(ALG_RSA,   false, address(0), address(rsaChain_));
        emit VerifierUpdated(ALG_ECDSA, true,  address(0), address(ecdsaLeaf_));
        emit VerifierUpdated(ALG_ECDSA, false, address(0), address(ecdsaChain_));
    }

    // -------------------------------------------------------------------
    // Register
    // -------------------------------------------------------------------

    /// @notice Register a fresh QKB binding. Dispatch on
    ///         `chainInputs.algorithmTag` — the authoritative tag lives on
    ///         the chain side per orchestration §2.2. Leaf carries no
    ///         algorithmTag (it is credential-binding data).
    ///
    ///         Ordering: dispatch → rTL equality → proof verify (which
    ///         also short-circuits on declHash whitelist + leafSpkiCommit
    ///         mismatch) → timestamp window → nullifier uniqueness → pk
    ///         uniqueness. The Groth16 calls are the expensive step, so
    ///         cheap checks come first.
    function register(
        QKBVerifier.Proof       calldata proofLeaf,
        QKBVerifier.LeafInputs  calldata leafInputs,
        QKBVerifier.Proof       calldata proofChain,
        QKBVerifier.ChainInputs calldata chainInputs
    ) external {
        (IGroth16LeafVerifier lv, IGroth16ChainVerifier cv) = _dispatch(chainInputs.algorithmTag);

        if (chainInputs.rTL != trustedListRoot) revert RootMismatch();
        if (leafInputs.leafSpkiCommit != chainInputs.leafSpkiCommit) revert LeafSpkiCommitMismatch();

        if (!QKBVerifier.verify(lv, cv, proofLeaf, leafInputs, proofChain, chainInputs)) {
            revert InvalidProof();
        }

        if (leafInputs.timestamp > block.timestamp) revert BindingFromFuture();
        if (block.timestamp > uint256(leafInputs.timestamp) + MAX_AGE) revert BindingTooOld();
        if (usedNullifiers[leafInputs.nullifier]) revert NullifierUsed();

        address pkAddr = QKBVerifier.toPkAddress(leafInputs.pkX, leafInputs.pkY);
        if (bindings[pkAddr].status != Status.NONE) revert AlreadyBound();

        usedNullifiers[leafInputs.nullifier] = true;
        nullifierToPk[leafInputs.nullifier]  = pkAddr;

        bindings[pkAddr] = Binding({
            status:       Status.ACTIVE,
            algorithmTag: chainInputs.algorithmTag,
            boundAt:      uint64(block.timestamp),
            expiredAt:    0,
            ctxHash:      leafInputs.ctxHash,
            declHash:     leafInputs.declHash,
            nullifier:    leafInputs.nullifier
        });

        emit BindingRegistered(
            pkAddr,
            chainInputs.algorithmTag,
            leafInputs.ctxHash,
            leafInputs.declHash,
            leafInputs.nullifier
        );
    }

    // -------------------------------------------------------------------
    // Expire
    // -------------------------------------------------------------------

    /// @notice Tear down a binding. `sig` must be a secp256k1 signature by
    ///         the bound key over `keccak256(abi.encode(EXPIRE_DOMAIN,
    ///         pkAddr, block.chainid, boundAt))`. Unchanged from V2.
    function expire(address pkAddr, bytes calldata sig) external {
        Binding storage b = bindings[pkAddr];
        if (b.status != Status.ACTIVE) revert NotBound();

        bytes32 digest = keccak256(abi.encode(EXPIRE_DOMAIN, pkAddr, block.chainid, b.boundAt));
        address recovered = _recover(digest, sig);
        if (recovered != pkAddr) revert BadExpireSig();

        b.status = Status.EXPIRED;
        b.expiredAt = uint64(block.timestamp);
        emit BindingExpired(pkAddr);
    }

    function _recover(bytes32 digest, bytes calldata sig) private pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 0x20))
            v := byte(0, calldataload(add(sig.offset, 0x40)))
        }
        return ecrecover(digest, v, r, s);
    }

    // -------------------------------------------------------------------
    // Admin — root + admin transfer + verifier rotation
    // -------------------------------------------------------------------

    function updateTrustedListRoot(bytes32 newRoot) external onlyAdmin {
        bytes32 old = trustedListRoot;
        trustedListRoot = newRoot;
        emit TrustedListRootUpdated(old, newRoot);
    }

    function setAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        address old = admin;
        admin = newAdmin;
        emit AdminTransferred(old, newAdmin);
    }

    function setRsaLeafVerifier(IGroth16LeafVerifier newVerifier) external onlyAdmin {
        if (address(newVerifier) == address(0)) revert ZeroAddress();
        address old = address(rsaLeafVerifier);
        rsaLeafVerifier = newVerifier;
        emit VerifierUpdated(ALG_RSA, true, old, address(newVerifier));
    }

    function setRsaChainVerifier(IGroth16ChainVerifier newVerifier) external onlyAdmin {
        if (address(newVerifier) == address(0)) revert ZeroAddress();
        address old = address(rsaChainVerifier);
        rsaChainVerifier = newVerifier;
        emit VerifierUpdated(ALG_RSA, false, old, address(newVerifier));
    }

    function setEcdsaLeafVerifier(IGroth16LeafVerifier newVerifier) external onlyAdmin {
        if (address(newVerifier) == address(0)) revert ZeroAddress();
        address old = address(ecdsaLeafVerifier);
        ecdsaLeafVerifier = newVerifier;
        emit VerifierUpdated(ALG_ECDSA, true, old, address(newVerifier));
    }

    function setEcdsaChainVerifier(IGroth16ChainVerifier newVerifier) external onlyAdmin {
        if (address(newVerifier) == address(0)) revert ZeroAddress();
        address old = address(ecdsaChainVerifier);
        ecdsaChainVerifier = newVerifier;
        emit VerifierUpdated(ALG_ECDSA, false, old, address(newVerifier));
    }

    // -------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------

    /// @notice True iff the binding for `pkAddr` was active at time `t`.
    ///         Matches V2 semantics including DB-CRL override.
    function isActiveAt(address pkAddr, uint64 t) external view returns (bool) {
        Binding storage b = bindings[pkAddr];
        if (b.status == Status.NONE) return false;
        if (t < b.boundAt) return false;
        if (revokedNullifiers[b.nullifier] != bytes32(0)) return false;
        if (b.status == Status.ACTIVE) return true;
        return t < b.expiredAt;
    }

    function revokeNullifier(bytes32 nullifier, bytes32 reasonHash) external onlyAdmin {
        if (reasonHash == bytes32(0)) revert ZeroAddress();
        if (!usedNullifiers[nullifier]) revert UnknownNullifier();
        if (revokedNullifiers[nullifier] != bytes32(0)) revert NullifierAlreadyRevoked();
        revokedNullifiers[nullifier] = reasonHash;
        emit NullifierRevoked(nullifier, nullifierToPk[nullifier], reasonHash);
    }

    // -------------------------------------------------------------------
    // QIE escrow surface
    // -------------------------------------------------------------------

    /// @notice Attach an escrow commitment to an existing QKB binding.
    ///         Authentication is a fresh split-proof pair proving pk
    ///         ownership (same gate as `register` minus the uniqueness
    ///         checks).
    function registerEscrow(
        bytes32 escrowId,
        address arbitrator,
        uint64 expiry,
        QKBVerifier.Proof       calldata proofLeaf,
        QKBVerifier.LeafInputs  calldata leafInputs,
        QKBVerifier.Proof       calldata proofChain,
        QKBVerifier.ChainInputs calldata chainInputs
    ) external {
        if (arbitrator == address(0)) revert ZeroAddress();
        if (expiry <= block.timestamp) revert EscrowExpiryInPast();

        address pkAddr = _authorizeBinding(proofLeaf, leafInputs, proofChain, chainInputs);
        if (escrows[pkAddr].state != EscrowState.NONE) revert EscrowExists();

        escrows[pkAddr] = EscrowEntry({
            escrowId:         escrowId,
            arbitrator:       arbitrator,
            expiry:           expiry,
            releasePendingAt: 0,
            state:            EscrowState.ACTIVE
        });
        escrowIdToPkAddr[escrowId] = pkAddr;
        emit EscrowRegistered(pkAddr, escrowId, arbitrator, expiry);
    }

    function revokeEscrow(
        bytes32 reasonHash,
        QKBVerifier.Proof       calldata proofLeaf,
        QKBVerifier.LeafInputs  calldata leafInputs,
        QKBVerifier.Proof       calldata proofChain,
        QKBVerifier.ChainInputs calldata chainInputs
    ) external {
        address pkAddr = _authorizeBinding(proofLeaf, leafInputs, proofChain, chainInputs);
        EscrowEntry storage e = escrows[pkAddr];
        if (e.state == EscrowState.NONE)            revert NoEscrow();
        if (e.state == EscrowState.REVOKED)         revert EscrowAlreadyRevoked();
        if (e.state == EscrowState.RELEASE_PENDING) revert EscrowReleasePending();
        if (e.state == EscrowState.RELEASED)        revert EscrowAlreadyReleased();
        e.state = EscrowState.REVOKED;
        emit EscrowRevoked(pkAddr, e.escrowId, reasonHash);
    }

    function notifyReleasePending(bytes32 escrowId) external {
        address pkAddr = escrowIdToPkAddr[escrowId];
        if (pkAddr == address(0)) revert UnknownEscrowId();
        EscrowEntry storage e = escrows[pkAddr];
        if (msg.sender != e.arbitrator) revert NotArbitrator();
        if (e.state != EscrowState.ACTIVE) revert WrongState();
        e.state = EscrowState.RELEASE_PENDING;
        e.releasePendingAt = uint64(block.timestamp);
        emit EscrowReleasePendingRequested(escrowId, msg.sender, uint64(block.timestamp));
    }

    function finalizeRelease(bytes32 escrowId) external {
        address pkAddr = escrowIdToPkAddr[escrowId];
        if (pkAddr == address(0)) revert UnknownEscrowId();
        EscrowEntry storage e = escrows[pkAddr];
        if (msg.sender != e.arbitrator) revert NotArbitrator();
        if (e.state != EscrowState.RELEASE_PENDING) revert WrongState();
        if (block.timestamp < uint256(e.releasePendingAt) + RELEASE_TIMEOUT) revert WrongState();
        e.state = EscrowState.RELEASED;
        emit EscrowReleased(escrowId, msg.sender);
    }

    function cancelReleasePending(
        QKBVerifier.Proof       calldata proofLeaf,
        QKBVerifier.LeafInputs  calldata leafInputs,
        QKBVerifier.Proof       calldata proofChain,
        QKBVerifier.ChainInputs calldata chainInputs
    ) external {
        address pkAddr = _authorizeBinding(proofLeaf, leafInputs, proofChain, chainInputs);
        EscrowEntry storage e = escrows[pkAddr];
        if (e.state != EscrowState.RELEASE_PENDING) revert WrongState();
        if (block.timestamp >= uint256(e.releasePendingAt) + RELEASE_TIMEOUT) revert WrongState();
        e.state = EscrowState.ACTIVE;
        e.releasePendingAt = 0;
        emit EscrowReleaseCancelled(e.escrowId, pkAddr);
    }

    function escrowCommitment(address pkAddr) external view returns (bytes32) {
        EscrowEntry storage e = escrows[pkAddr];
        if (e.state != EscrowState.ACTIVE) return bytes32(0);
        if (e.expiry <= block.timestamp) return bytes32(0);
        return e.escrowId;
    }

    function isEscrowActive(address pkAddr) external view returns (bool) {
        EscrowEntry storage e = escrows[pkAddr];
        if (e.state != EscrowState.ACTIVE) return false;
        if (e.expiry <= block.timestamp) return false;
        return true;
    }

    // -------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------

    /// @dev Dispatch on `algorithmTag` and return the matching leaf + chain
    ///      verifier pair. Extracted so `register` / `registerEscrow` /
    ///      `revokeEscrow` / `cancelReleasePending` share the exact same
    ///      dispatch semantics.
    function _dispatch(uint8 algorithmTag)
        internal
        view
        returns (IGroth16LeafVerifier lv, IGroth16ChainVerifier cv)
    {
        if (algorithmTag == ALG_RSA) {
            lv = rsaLeafVerifier;
            cv = rsaChainVerifier;
        } else if (algorithmTag == ALG_ECDSA) {
            lv = ecdsaLeafVerifier;
            cv = ecdsaChainVerifier;
        } else {
            revert UnknownAlgorithm();
        }
    }

    /// @dev Shared authentication gate for the escrow surface. Same as
    ///      `register`'s front half minus the timestamp-age and pk / nullifier-
    ///      uniqueness clauses (those only apply to first-time binding).
    ///      Requires the pk to already be bound with status == ACTIVE.
    function _authorizeBinding(
        QKBVerifier.Proof       calldata proofLeaf,
        QKBVerifier.LeafInputs  calldata leafInputs,
        QKBVerifier.Proof       calldata proofChain,
        QKBVerifier.ChainInputs calldata chainInputs
    ) internal view returns (address pkAddr) {
        (IGroth16LeafVerifier lv, IGroth16ChainVerifier cv) = _dispatch(chainInputs.algorithmTag);

        if (chainInputs.rTL != trustedListRoot) revert RootMismatch();
        if (leafInputs.leafSpkiCommit != chainInputs.leafSpkiCommit) revert LeafSpkiCommitMismatch();

        if (!QKBVerifier.verify(lv, cv, proofLeaf, leafInputs, proofChain, chainInputs)) {
            revert InvalidProof();
        }

        pkAddr = QKBVerifier.toPkAddress(leafInputs.pkX, leafInputs.pkY);
        if (bindings[pkAddr].status != Status.ACTIVE) revert NotBound();
    }
}
