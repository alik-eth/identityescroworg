// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { QKBVerifier, IGroth16Verifier } from "./QKBVerifier.sol";

/// @notice Reference register-then-authenticate registry for QKB-bound
///         secp256k1 keys. Phase 2 (Sprint 0) restores the dual-verifier
///         dispatch path from the original QKB design: the registry holds
///         both an RSA and an ECDSA Groth16 verifier, and `register`
///         dispatches on the proof's `algorithmTag` public signal.
///
///         Legal `algorithmTag` values (per orchestration §2.0):
///           0 = RSA-PKCS#1 v1.5 2048
///           1 = ECDSA P-256
///         anything else reverts `UnknownAlgorithm`.
///
///         `trustedListRoot` is admin-rotatable state; `register` enforces
///         `i.rTL == trustedListRoot` (S0.3 — restored after Phase-1 drop).
contract QKBRegistry {
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

    /// @dev Maximum age of a binding proof, measured against `i.timestamp` at
    ///      `register` time. Per spec §6.2.
    uint64 public constant MAX_AGE = 90 days;

    IGroth16Verifier public rsaVerifier;
    IGroth16Verifier public ecdsaVerifier;
    bytes32 public trustedListRoot;
    address public admin;
    mapping(address => Binding) public bindings;

    /// @dev Nullifier primitive (spec §14.4). `usedNullifiers[n]` guards
    ///      against two Holders with the same QES cert subject registering
    ///      under the same ctxHash. `nullifierToPk` lets relying parties
    ///      look up the pkAddr a given nullifier attests to.
    ///      `revokedNullifiers[n]` carries the admin-published revocation
    ///      reason hash (Sedelmeir-style DB-CRL pattern).
    mapping(bytes32 => bool) public usedNullifiers;
    mapping(bytes32 => address) public nullifierToPk;
    mapping(bytes32 => bytes32) public revokedNullifiers;

    /// @dev QIE escrow state (spec §2, §14). Keyed by `pkAddr` — the same
    ///      key space the Phase-1 binding table uses. Each binding has at
    ///      most one escrow attached at a time.
    struct EscrowEntry {
        bytes32 escrowId;
        address arbitrator;
        uint64 expiry;
        bool revoked;
    }

    mapping(address => EscrowEntry) public escrows;

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
    event VerifierUpdated(uint8 indexed algorithmTag, address oldVerifier, address newVerifier);
    /// @dev `reasonHash` is an opaque digest of the off-chain revocation
    ///      justification (e.g. sha256 of a CSV-SR row). The chain does
    ///      not interpret it; relying parties cross-reference off-chain.
    event NullifierRevoked(bytes32 indexed nullifier, address indexed pkAddr, bytes32 reasonHash);
    event EscrowRegistered(address indexed pkAddr, bytes32 indexed escrowId, address arbitrator, uint64 expiry);
    event EscrowRevoked(address indexed pkAddr, bytes32 indexed escrowId, bytes32 reasonHash);

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

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor(
        IGroth16Verifier rsa_,
        IGroth16Verifier ecdsa_,
        bytes32 initialRoot,
        address initialAdmin
    ) {
        if (address(rsa_) == address(0)) revert ZeroAddress();
        if (address(ecdsa_) == address(0)) revert ZeroAddress();
        if (initialAdmin == address(0)) revert ZeroAddress();
        rsaVerifier = rsa_;
        ecdsaVerifier = ecdsa_;
        trustedListRoot = initialRoot;
        admin = initialAdmin;
        emit AdminTransferred(address(0), initialAdmin);
        emit TrustedListRootUpdated(bytes32(0), initialRoot);
        emit VerifierUpdated(ALG_RSA, address(0), address(rsa_));
        emit VerifierUpdated(ALG_ECDSA, address(0), address(ecdsa_));
    }

    /// @notice Register a fresh QKB binding. See spec §6.2 steps 1–7.
    ///         Dispatch on `i.algorithmTag`: route verification through
    ///         `rsaVerifier` or `ecdsaVerifier` per the restored §2.0
    ///         convention. Unknown tags revert `UnknownAlgorithm`. `i.rTL`
    ///         must equal `trustedListRoot` (S0.3).
    function register(QKBVerifier.Proof calldata p, QKBVerifier.Inputs calldata i) external {
        IGroth16Verifier v;
        if (i.algorithmTag == ALG_RSA) {
            v = rsaVerifier;
        } else if (i.algorithmTag == ALG_ECDSA) {
            v = ecdsaVerifier;
        } else {
            revert UnknownAlgorithm();
        }

        if (i.rTL != trustedListRoot) revert RootMismatch();
        if (!QKBVerifier.verify(v, p, i)) revert InvalidProof();
        if (i.timestamp > block.timestamp) revert BindingFromFuture();
        if (block.timestamp > uint256(i.timestamp) + MAX_AGE) revert BindingTooOld();
        if (usedNullifiers[i.nullifier]) revert NullifierUsed();

        address pkAddr = QKBVerifier.toPkAddress(i.pkX, i.pkY);
        if (bindings[pkAddr].status != Status.NONE) revert AlreadyBound();

        usedNullifiers[i.nullifier] = true;
        nullifierToPk[i.nullifier] = pkAddr;

        bindings[pkAddr] = Binding({
            status: Status.ACTIVE,
            algorithmTag: i.algorithmTag,
            boundAt: uint64(block.timestamp),
            expiredAt: 0,
            ctxHash: i.ctxHash,
            declHash: i.declHash,
            nullifier: i.nullifier
        });
        emit BindingRegistered(pkAddr, i.algorithmTag, i.ctxHash, i.declHash, i.nullifier);
    }

    /// @notice Tear down a binding. `sig` must be a secp256k1 signature by
    ///         the bound key over `keccak256(abi.encode(EXPIRE_DOMAIN,
    ///         pkAddr, block.chainid, boundAt))`. Already-expired and never-
    ///         bound entries both revert with `NotBound`.
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

    /// @notice True iff the binding for `pkAddr` was active at time `t`.
    ///         Pre-bind (`t < boundAt`) and post-expire (`t >= expiredAt`)
    ///         both return false. Unknown bindings return false.
    function isActiveAt(address pkAddr, uint64 t) external view returns (bool) {
        Binding storage b = bindings[pkAddr];
        if (b.status == Status.NONE) return false;
        if (t < b.boundAt) return false;
        // Sedelmeir-style DB-CRL: an admin-revoked nullifier marks the
        // binding as no longer authoritative regardless of status.
        if (revokedNullifiers[b.nullifier] != bytes32(0)) return false;
        if (b.status == Status.ACTIVE) return true;
        return t < b.expiredAt;
    }

    /// @notice Admin revocation of a registered nullifier. Publishes a
    ///         `reasonHash` (opaque to chain) and flips the Sedelmeir-style
    ///         CRL bit — the mapped binding's `isActiveAt` returns false
    ///         from this point onward. Callable only for nullifiers that
    ///         were previously seen by `register`. Non-zero `reasonHash`
    ///         required so the event carries meaningful audit info.
    function revokeNullifier(bytes32 nullifier, bytes32 reasonHash) external onlyAdmin {
        if (reasonHash == bytes32(0)) revert ZeroAddress();
        if (!usedNullifiers[nullifier]) revert UnknownNullifier();
        if (revokedNullifiers[nullifier] != bytes32(0)) revert NullifierAlreadyRevoked();
        revokedNullifiers[nullifier] = reasonHash;
        emit NullifierRevoked(nullifier, nullifierToPk[nullifier], reasonHash);
    }

    // ---------------------------------------------------------------------
    // QIE escrow surface (Phase 2)
    // ---------------------------------------------------------------------

    /// @notice Attach an escrow commitment (`escrowId`) to an existing
    ///         QKB binding. Authorisation is a fresh Phase-1 Groth16 proof
    ///         of the same pk — we re-run the full `register`-style check
    ///         (rTL + nullifier + algorithmTag dispatch + declHash
    ///         whitelist inside QKBVerifier.verify) and then bind the
    ///         escrow under `pkAddr = toPkAddress(i.pkX, i.pkY)`.
    ///
    ///         Invariants enforced:
    ///           - The binding must already exist (caller is the Holder,
    ///             hence has already registered).
    ///           - Proof must verify against the algorithmTag-selected verifier.
    ///           - `rTL == trustedListRoot` (proofs stale on root rotation
    ///             can't open escrows).
    ///           - No prior escrow entry for the same pkAddr.
    ///           - `expiry` is strictly in the future.
    ///
    ///         Spec §14 note: we intentionally do NOT add `escrowId` as a
    ///         public signal in any circuit — that would force a fresh
    ///         ceremony for every escrow registration. The existing pk
    ///         ownership proof is sufficient authentication.
    function registerEscrow(
        bytes32 escrowId,
        address arbitrator,
        uint64 expiry,
        QKBVerifier.Proof calldata p,
        QKBVerifier.Inputs calldata i
    ) external {
        if (arbitrator == address(0)) revert ZeroAddress();
        if (expiry <= block.timestamp) revert EscrowExpiryInPast();

        address pkAddr = _authorizeBinding(p, i);
        if (escrows[pkAddr].escrowId != bytes32(0)) revert EscrowExists();

        escrows[pkAddr] = EscrowEntry({
            escrowId: escrowId,
            arbitrator: arbitrator,
            expiry: expiry,
            revoked: false
        });
        emit EscrowRegistered(pkAddr, escrowId, arbitrator, expiry);
    }

    /// @notice Revoke a previously registered escrow. Same Groth16-based
    ///         auth as `registerEscrow` — the Holder re-proves pk ownership.
    ///         `reasonHash` is opaque on-chain; relying parties cross-
    ///         reference it to an off-chain justification if needed.
    function revokeEscrow(
        bytes32 reasonHash,
        QKBVerifier.Proof calldata p,
        QKBVerifier.Inputs calldata i
    ) external {
        address pkAddr = _authorizeBinding(p, i);
        EscrowEntry storage e = escrows[pkAddr];
        if (e.escrowId == bytes32(0)) revert NoEscrow();
        if (e.revoked) revert EscrowAlreadyRevoked();
        e.revoked = true;
        emit EscrowRevoked(pkAddr, e.escrowId, reasonHash);
    }

    /// @notice Current escrow commitment for a pk, or zero if none / revoked
    ///         / expired. Relying parties should prefer `isEscrowActive` for
    ///         the boolean path.
    function escrowCommitment(address pkAddr) external view returns (bytes32) {
        EscrowEntry storage e = escrows[pkAddr];
        if (e.escrowId == bytes32(0)) return bytes32(0);
        if (e.revoked) return bytes32(0);
        if (e.expiry <= block.timestamp) return bytes32(0);
        return e.escrowId;
    }

    function isEscrowActive(address pkAddr) external view returns (bool) {
        EscrowEntry storage e = escrows[pkAddr];
        if (e.escrowId == bytes32(0)) return false;
        if (e.revoked) return false;
        if (e.expiry <= block.timestamp) return false;
        return true;
    }

    /// @dev Groth16-proof-based authorisation gate shared by
    ///      `registerEscrow` and `revokeEscrow`. Mirrors the same checks
    ///      `register()` performs minus the pk-uniqueness / timestamp-age
    ///      clauses (those apply only to first-time binding).
    function _authorizeBinding(
        QKBVerifier.Proof calldata p,
        QKBVerifier.Inputs calldata i
    ) internal view returns (address pkAddr) {
        IGroth16Verifier v;
        if (i.algorithmTag == ALG_RSA) {
            v = rsaVerifier;
        } else if (i.algorithmTag == ALG_ECDSA) {
            v = ecdsaVerifier;
        } else {
            revert UnknownAlgorithm();
        }
        if (i.rTL != trustedListRoot) revert RootMismatch();
        if (!QKBVerifier.verify(v, p, i)) revert InvalidProof();

        pkAddr = QKBVerifier.toPkAddress(i.pkX, i.pkY);
        if (bindings[pkAddr].status != Status.ACTIVE) revert NotBound();
    }

    // ---------------------------------------------------------------------
    // Admin verifier setters
    // ---------------------------------------------------------------------

    function setRsaVerifier(IGroth16Verifier newVerifier) external onlyAdmin {
        if (address(newVerifier) == address(0)) revert ZeroAddress();
        address old = address(rsaVerifier);
        rsaVerifier = newVerifier;
        emit VerifierUpdated(ALG_RSA, old, address(newVerifier));
    }

    function setEcdsaVerifier(IGroth16Verifier newVerifier) external onlyAdmin {
        if (address(newVerifier) == address(0)) revert ZeroAddress();
        address old = address(ecdsaVerifier);
        ecdsaVerifier = newVerifier;
        emit VerifierUpdated(ALG_ECDSA, old, address(newVerifier));
    }
}
