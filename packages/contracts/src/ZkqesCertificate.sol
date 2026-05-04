// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { ERC721 } from "openzeppelin-contracts/token/ERC721/ERC721.sol";
import { CertificateRenderer } from "./CertificateRenderer.sol";

interface IZkqesRegistry {
    function isVerified(address holder)  external view returns (bool);
    function nullifierOf(address holder) external view returns (bytes32);
    function trustedListRoot()           external view returns (bytes32);
}

/// @notice ERC-721 transferable certificate, mintable only by verified Ukrainians
///         while the mint window is open. One mint per nullifier (per identity).
contract ZkqesCertificate is ERC721 {
    IZkqesRegistry public immutable registry;
    uint64       public immutable mintDeadline;
    string       public chainLabel;

    mapping(bytes32 => uint256) public tokenIdByNullifier;
    mapping(uint256 => bytes32) private _nullifierByTokenId;
    uint256 private _nextTokenId;

    event CertificateMinted(
        uint256 indexed tokenId,
        address indexed holder,
        bytes32 indexed nullifier,
        uint64 mintTimestamp
    );

    constructor(
        IZkqesRegistry _registry,
        uint64 _mintDeadline,
        string memory _chainLabel
    ) ERC721("Verified Identity Certificate", "VIC") {
        registry     = _registry;
        mintDeadline = _mintDeadline;
        chainLabel   = _chainLabel;
    }

    function mint() external returns (uint256 tokenId) {
        require(block.timestamp <= mintDeadline,    "MINT_CLOSED");
        bytes32 nullifier = registry.nullifierOf(msg.sender);
        require(nullifier != bytes32(0),            "NOT_VERIFIED");
        require(tokenIdByNullifier[nullifier] == 0, "ALREADY_MINTED");

        tokenId = ++_nextTokenId;
        tokenIdByNullifier[nullifier]   = tokenId;
        _nullifierByTokenId[tokenId]    = nullifier;
        _safeMint(msg.sender, tokenId);
        emit CertificateMinted(tokenId, msg.sender, nullifier, uint64(block.timestamp));
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId);
        bytes32 nullifier = _nullifierByTokenId[tokenId];
        return CertificateRenderer.tokenURI(tokenId, nullifier, chainLabel, uint64(block.timestamp));
    }
}
