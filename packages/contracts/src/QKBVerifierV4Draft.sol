// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @notice Unified Groth16 verifier interface for the QKB/2 leaf circuit
///         (16 public signals):
///           [0..3]  pkX[4]
///           [4..7]  pkY[4]
///           [8]     ctxHash
///           [9]     policyLeafHash
///           [10]    policyRoot
///           [11]    timestamp
///           [12]    nullifier
///           [13]    leafSpkiCommit
///           [14]    dobCommit
///           [15]    dobSupported
interface IGroth16LeafVerifierV4 {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[16] calldata input
    ) external view returns (bool);
}

/// @notice Draft split-proof Groth16 verifier interface — chain side.
///         Kept identical to the current split chain circuit:
///           [0]     rTL
///           [1]     algorithmTag
///           [2]     leafSpkiCommit
interface IGroth16ChainVerifierV4 {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[3] calldata input
    ) external view returns (bool);
}

/// @notice Draft Groth16 verifier interface for the age circuit:
///           [0]     dobCommit
///           [1]     ageCutoffDate
///           [2]     ageQualified
interface IGroth16AgeVerifierV4 {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[3] calldata input
    ) external view returns (bool);
}

/// @notice Draft verifier library for the `QKB/2` + optional age architecture.
///         This file is intentionally forward-looking and MUST NOT be wired
///         into the live registry path until successor circuits and verifiers
///         exist.
library QKBVerifierV4Draft {
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    struct ChainSignals {
        bytes32 rTL;
        uint8 algorithmTag;
        bytes32 leafSpkiCommit;
    }

    struct LeafSignals {
        uint256[4] pkX;
        uint256[4] pkY;
        bytes32 ctxHash;
        bytes32 policyLeafHash;
        bytes32 policyRoot;
        uint64 timestamp;
        bytes32 nullifier;
        bytes32 leafSpkiCommit;
        bytes32 dobCommit;
        uint8 dobSupported;
    }

    struct AgeSignals {
        bytes32 dobCommit;
        uint32 ageCutoffDate;
        uint8 ageQualified;
    }

    function verify(
        IGroth16LeafVerifierV4 lv,
        IGroth16ChainVerifierV4 cv,
        IGroth16AgeVerifierV4 av,
        Proof memory proofLeaf,
        LeafSignals memory inputsLeaf,
        Proof memory proofChain,
        ChainSignals memory inputsChain,
        Proof memory proofAge,
        AgeSignals memory inputsAge,
        bool requireAgeQualification
    ) internal view returns (bool) {
        if (inputsLeaf.leafSpkiCommit != inputsChain.leafSpkiCommit) return false;
        if (requireAgeQualification) {
            if (inputsLeaf.dobSupported != 1) return false;
            if (inputsLeaf.dobCommit != inputsAge.dobCommit) return false;
            if (inputsAge.ageQualified != 1) return false;
        }

        uint256[16] memory leafArr;
        leafArr[0] = inputsLeaf.pkX[0];
        leafArr[1] = inputsLeaf.pkX[1];
        leafArr[2] = inputsLeaf.pkX[2];
        leafArr[3] = inputsLeaf.pkX[3];
        leafArr[4] = inputsLeaf.pkY[0];
        leafArr[5] = inputsLeaf.pkY[1];
        leafArr[6] = inputsLeaf.pkY[2];
        leafArr[7] = inputsLeaf.pkY[3];
        leafArr[8] = uint256(inputsLeaf.ctxHash);
        leafArr[9] = uint256(inputsLeaf.policyLeafHash);
        leafArr[10] = uint256(inputsLeaf.policyRoot);
        leafArr[11] = uint256(inputsLeaf.timestamp);
        leafArr[12] = uint256(inputsLeaf.nullifier);
        leafArr[13] = uint256(inputsLeaf.leafSpkiCommit);
        leafArr[14] = uint256(inputsLeaf.dobCommit);
        leafArr[15] = uint256(inputsLeaf.dobSupported);

        uint256[3] memory chainArr;
        chainArr[0] = uint256(inputsChain.rTL);
        chainArr[1] = uint256(inputsChain.algorithmTag);
        chainArr[2] = uint256(inputsChain.leafSpkiCommit);

        uint256[3] memory ageArr;
        ageArr[0] = uint256(inputsAge.dobCommit);
        ageArr[1] = uint256(inputsAge.ageCutoffDate);
        ageArr[2] = uint256(inputsAge.ageQualified);

        if (!lv.verifyProof(proofLeaf.a, proofLeaf.b, proofLeaf.c, leafArr)) return false;
        if (!cv.verifyProof(proofChain.a, proofChain.b, proofChain.c, chainArr)) return false;
        if (requireAgeQualification && !av.verifyProof(proofAge.a, proofAge.b, proofAge.c, ageArr)) return false;
        return true;
    }
}
