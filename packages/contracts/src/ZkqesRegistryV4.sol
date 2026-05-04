// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {
    IGroth16LeafVerifierV4,
    IGroth16ChainVerifierV4,
    IGroth16AgeVerifierV4
} from "./ZkqesVerifierV4Draft.sol";

/// @notice Per-country QKB/2 registry. Constructor-frozen country tag; admin-
///         rotatable trust roots + verifier addresses.
contract ZkqesRegistryV4 {
    // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
    string public constant VERSION = "QKB/2.0";
    string public country;

    bytes32 public trustedListRoot;
    bytes32 public policyRoot;

    IGroth16LeafVerifierV4  public leafVerifier;
    IGroth16ChainVerifierV4 public chainVerifier;
    IGroth16AgeVerifierV4   public ageVerifier;

    address public admin;

    error OnlyAdmin();

    event TrustedListRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event PolicyRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event VerifierUpdated(bytes32 indexed kind, address oldV, address newV);
    event AdminTransferred(address oldAdmin, address newAdmin);

    bytes32 private constant _LEAF  = keccak256("leaf");
    bytes32 private constant _CHAIN = keccak256("chain");
    bytes32 private constant _AGE   = keccak256("age");

    modifier onlyAdmin() {
        if (msg.sender != admin) revert OnlyAdmin();
        _;
    }

    constructor(
        string memory country_,
        bytes32 trustedListRoot_,
        bytes32 policyRoot_,
        address leafVerifier_,
        address chainVerifier_,
        address ageVerifier_,
        address admin_
    ) {
        country         = country_;
        trustedListRoot = trustedListRoot_;
        policyRoot      = policyRoot_;
        leafVerifier    = IGroth16LeafVerifierV4(leafVerifier_);
        chainVerifier   = IGroth16ChainVerifierV4(chainVerifier_);
        ageVerifier     = IGroth16AgeVerifierV4(ageVerifier_);
        admin           = admin_;
    }

    function setTrustedListRoot(bytes32 newRoot) external onlyAdmin {
        emit TrustedListRootUpdated(trustedListRoot, newRoot);
        trustedListRoot = newRoot;
    }

    function setPolicyRoot(bytes32 newRoot) external onlyAdmin {
        emit PolicyRootUpdated(policyRoot, newRoot);
        policyRoot = newRoot;
    }

    function setLeafVerifier(address v) external onlyAdmin {
        emit VerifierUpdated(_LEAF, address(leafVerifier), v);
        leafVerifier = IGroth16LeafVerifierV4(v);
    }

    function setChainVerifier(address v) external onlyAdmin {
        emit VerifierUpdated(_CHAIN, address(chainVerifier), v);
        chainVerifier = IGroth16ChainVerifierV4(v);
    }

    function setAgeVerifier(address v) external onlyAdmin {
        emit VerifierUpdated(_AGE, address(ageVerifier), v);
        ageVerifier = IGroth16AgeVerifierV4(v);
    }

    function setAdmin(address newAdmin) external onlyAdmin {
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }

    // ---------- register ----------

    struct G16Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    struct ChainProof {
        G16Proof proof;
        uint256 rTL;
        uint256 algorithmTag;
        uint256 leafSpkiCommit;
    }

    struct LeafProof {
        G16Proof proof;
        uint256[4] pkX;
        uint256[4] pkY;
        uint256 ctxHash;
        uint256 policyLeafHash;
        uint256 policyRoot_;
        uint256 timestamp;
        uint256 nullifier;
        uint256 leafSpkiCommit;
        uint256 dobCommit;
        uint256 dobSupported;
    }

    struct Binding {
        address pk;
        uint256 ctxHash;
        uint256 policyLeafHash;
        uint256 timestamp;
        uint256 dobCommit;
        bool    dobAvailable;
        uint256 ageVerifiedCutoff;
        bool    revoked;
    }

    mapping(bytes32 => Binding) public bindings;
    mapping(bytes32 => bool)    public usedNullifiers;
    mapping(address => bytes32) public nullifierOf;

    error NotOnTrustedList();
    error InvalidLeafSpkiCommit();
    error InvalidPolicyRoot();
    error AlgorithmNotSupported();
    error DuplicateNullifier();
    error InvalidProof();

    event BindingRegistered(
        bytes32 indexed id,
        address indexed pk,
        uint256 ctxHash,
        uint256 policyLeafHash,
        uint256 timestamp,
        bool dobAvailable
    );

    function register(ChainProof calldata cp, LeafProof calldata lp)
        external
        returns (bytes32 bindingId)
    {
        if (cp.rTL != uint256(trustedListRoot))     revert NotOnTrustedList();
        if (cp.leafSpkiCommit != lp.leafSpkiCommit) revert InvalidLeafSpkiCommit();
        if (lp.policyRoot_ != uint256(policyRoot))  revert InvalidPolicyRoot();
        if (cp.algorithmTag > 1)                    revert AlgorithmNotSupported();

        uint256[3] memory chainInput = [cp.rTL, cp.algorithmTag, cp.leafSpkiCommit];
        if (!chainVerifier.verifyProof(cp.proof.a, cp.proof.b, cp.proof.c, chainInput))
            revert InvalidProof();

        uint256[16] memory leafInput;
        for (uint i = 0; i < 4; i++) {
            leafInput[i]     = lp.pkX[i];
            leafInput[i + 4] = lp.pkY[i];
        }
        leafInput[8]  = lp.ctxHash;
        leafInput[9]  = lp.policyLeafHash;
        leafInput[10] = lp.policyRoot_;
        leafInput[11] = lp.timestamp;
        leafInput[12] = lp.nullifier;
        leafInput[13] = lp.leafSpkiCommit;
        leafInput[14] = lp.dobCommit;
        leafInput[15] = lp.dobSupported;
        if (!leafVerifier.verifyProof(lp.proof.a, lp.proof.b, lp.proof.c, leafInput))
            revert InvalidProof();

        bindingId = bytes32(lp.nullifier);
        if (usedNullifiers[bindingId]) revert DuplicateNullifier();
        usedNullifiers[bindingId] = true;

        address pkAddr = _pkAddressFromLimbs(lp.pkX, lp.pkY);
        bool dobAvail = lp.dobSupported == 1;
        bindings[bindingId] = Binding({
            pk: pkAddr,
            ctxHash: lp.ctxHash,
            policyLeafHash: lp.policyLeafHash,
            timestamp: lp.timestamp,
            dobCommit: lp.dobCommit,
            dobAvailable: dobAvail,
            ageVerifiedCutoff: 0,
            revoked: false
        });
        nullifierOf[msg.sender] = bindingId;
        emit BindingRegistered(
            bindingId, pkAddr, lp.ctxHash, lp.policyLeafHash, lp.timestamp, dobAvail
        );
    }

    function isVerified(address holder) external view returns (bool) {
        return nullifierOf[holder] != bytes32(0);
    }

    /// @dev Reassemble 4x64-bit little-endian limbs into secp256k1 affine
    ///      coordinates and derive the canonical Ethereum address
    ///      `keccak256(x32 || y32)[12:]`. Mirrors `ZkqesVerifierV2.toPkAddress`.
    function _pkAddressFromLimbs(uint256[4] calldata pkX, uint256[4] calldata pkY)
        private pure returns (address)
    {
        uint256 x = pkX[0] | (pkX[1] << 64) | (pkX[2] << 128) | (pkX[3] << 192);
        uint256 y = pkY[0] | (pkY[1] << 64) | (pkY[2] << 128) | (pkY[3] << 192);
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes32(x), bytes32(y))))));
    }

    // ---------- proveAdulthood ----------

    struct AgeProof {
        G16Proof proof;
        uint256 dobCommit;
        uint256 ageCutoffDate;
        uint256 ageQualified;
    }

    error AgeProofMismatch();
    error AgeNotQualified();
    error DobNotAvailable();
    error NotMonotonic();
    error BindingNotFound();

    event AdulthoodProven(bytes32 indexed id, uint256 ageCutoffDate);

    function proveAdulthood(
        bytes32 id,
        AgeProof calldata ap,
        uint256 ageCutoffDate
    ) external {
        Binding storage b = bindings[id];
        if (b.pk == address(0))                 revert BindingNotFound();
        if (!b.dobAvailable)                    revert DobNotAvailable();
        if (ageCutoffDate < b.ageVerifiedCutoff) revert NotMonotonic();
        if (ap.dobCommit != b.dobCommit)        revert AgeProofMismatch();
        if (ap.ageCutoffDate != ageCutoffDate)  revert AgeProofMismatch();
        if (ap.ageQualified != 1)               revert AgeNotQualified();

        uint256[3] memory input = [ap.dobCommit, ap.ageCutoffDate, ap.ageQualified];
        if (!ageVerifier.verifyProof(ap.proof.a, ap.proof.b, ap.proof.c, input))
            revert InvalidProof();

        b.ageVerifiedCutoff = ageCutoffDate;
        emit AdulthoodProven(id, ageCutoffDate);
    }

    // ---------- registerWithAge facade ----------

    function registerWithAge(
        ChainProof calldata cp,
        LeafProof calldata lp,
        AgeProof calldata ap,
        uint256 ageCutoffDate
    ) external returns (bytes32 bindingId) {
        bindingId = this.register(cp, lp);
        Binding storage b = bindings[bindingId];
        if (!b.dobAvailable)                   revert DobNotAvailable();
        if (ap.dobCommit != b.dobCommit)       revert AgeProofMismatch();
        if (ap.ageCutoffDate != ageCutoffDate) revert AgeProofMismatch();
        if (ap.ageQualified != 1)              revert AgeNotQualified();

        uint256[3] memory input = [ap.dobCommit, ap.ageCutoffDate, ap.ageQualified];
        if (!ageVerifier.verifyProof(ap.proof.a, ap.proof.b, ap.proof.c, input))
            revert InvalidProof();

        b.ageVerifiedCutoff = ageCutoffDate;
        emit AdulthoodProven(bindingId, ageCutoffDate);
    }

    // ---------- revoke + selfRevoke ----------

    error SelfRevokeSigInvalid();
    error BindingRevoked();

    event BindingRevokedEv(bytes32 indexed id, bytes32 reason);

    function revoke(bytes32 id, bytes32 reason) external onlyAdmin {
        Binding storage b = bindings[id];
        if (b.pk == address(0)) revert BindingNotFound();
        if (b.revoked)          revert BindingRevoked();
        b.revoked = true;
        emit BindingRevokedEv(id, reason);
    }

    function selfRevoke(bytes32 id, bytes calldata signature) external {
        Binding storage b = bindings[id];
        if (b.pk == address(0)) revert BindingNotFound();
        if (b.revoked)          revert BindingRevoked();
        bytes32 payload = keccak256(abi.encodePacked("qkb-self-revoke/v1", id));
        address recovered = _ecrecover(payload, signature);
        if (recovered != b.pk) revert SelfRevokeSigInvalid();
        b.revoked = true;
        emit BindingRevokedEv(id, bytes32("self"));
    }

    function _ecrecover(bytes32 hash, bytes calldata sig) private pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(hash, v, r, s);
    }
}
