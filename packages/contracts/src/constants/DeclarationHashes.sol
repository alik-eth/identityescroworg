// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Whitelisted SHA-256 digests of the canonical Quantum-Key-Binding
///         declaration texts. Values are mirrored from
///         `fixtures/declarations/digests.json` and MUST stay in lock-step with
///         `circuits/binding/DeclarationWhitelist.circom` and the web i18n
///         declaration strings. Any drift is a breaking change.
library DeclarationHashes {
    /// @dev sha256("...EN canonical declaration...") — see fixtures/declarations/en.txt
    bytes32 internal constant EN = 0xf83a393242585b93dea1474fbfc92a06dd90629f3e159b0d230548274315c89b;

    /// @dev sha256("...UK canonical declaration...") — see fixtures/declarations/uk.txt
    bytes32 internal constant UK = 0x692d0666a14c9e70ebadbfb864a18e152a70be061924902423e52b4ae21492b7;

    function isAllowed(bytes32 h) internal pure returns (bool) {
        return h == EN || h == UK;
    }
}
