// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @notice Whitelisted declaration digests as emitted by the circuit's
///         `Bits256ToField`: sha256(declaration) interpreted as a
///         big-endian 256-bit integer, reduced mod the BN254 scalar field p.
///         These are NOT the raw sha256 bytes32 — both raw EN and UK digests
///         have their high bit set and therefore overflow p, so the circuit
///         reports them reduced. The contract-side whitelist must match the
///         circuit's actual field-element output.
///
///         Raw sha256 references (pre-reduction):
///           EN sha256: f83a393242585b93dea1474fbfc92a06dd90629f3e159b0d230548274315c89b
///           UK sha256: 692d0666a14c9e70ebadbfb864a18e152a70be061924902423e52b4ae21492b7
///
///         BN254 scalar field p:
///           0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
library DeclarationHashes {
    /// @dev sha256("...EN canonical declaration...") mod p.
    bytes32 internal constant EN = 0x0644b0f3dc603ac3450feabf38427035148cd934dd766836cf9b7c439315c896;

    /// @dev sha256("...UK canonical declaration...") mod p.
    bytes32 internal constant UK = 0x08646980dee95e1d7b0d344b619edd5ada08ed7525b1af019c214023021492b5;

    function isAllowed(bytes32 h) internal pure returns (bool) {
        return h == EN || h == UK;
    }
}
