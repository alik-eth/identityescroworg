// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Base64 } from "openzeppelin-contracts/utils/Base64.sol";
import { Strings } from "openzeppelin-contracts/utils/Strings.sol";
import { SigilRenderer } from "./SigilRenderer.sol";

library CertificateRenderer {
    using Strings for uint256;
    using Strings for uint64;

    string private constant BONE      = "#F4EFE6";
    string private constant INK       = "#14130E";
    string private constant SOVEREIGN = "#1F2D5C";
    string private constant RULE      = "#C8BFA8";

    function tokenURI(
        uint256 tokenId,
        bytes32 nullifier,
        string memory chainLabel,
        uint64 mintTimestamp
    ) internal pure returns (string memory) {
        string memory svg = _renderSvg(tokenId, nullifier, chainLabel, mintTimestamp);
        bytes memory json = abi.encodePacked(
            '{"name":"Verified Identity Certificate ',
            unicode"№", tokenId.toString(),
            '","description":"On-chain attestation of verified Ukrainian identity, issued by ZkqesRegistryV4.",',
            '"image":"data:image/svg+xml;base64,', Base64.encode(bytes(svg)), '",',
            '"attributes":[',
              '{"trait_type":"Network","value":"', chainLabel, '"},',
              '{"trait_type":"Sigil","value":"0x', _hex16(nullifier), '"}',
            ']}'
        );
        return string.concat("data:application/json;base64,", Base64.encode(json));
    }

    function _renderSvg(
        uint256 tokenId,
        bytes32 nullifier,
        string memory chainLabel,
        uint64 mintTimestamp
    ) private pure returns (string memory) {
        return string.concat(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 600" width="800" height="600">',
            '<rect width="800" height="600" fill="', BONE, '"/>',
            '<rect x="12" y="12" width="776" height="576" fill="none" stroke="', SOVEREIGN, '" stroke-width="1.5"/>',
            '<text x="400" y="120" font-family="serif" font-size="44" font-weight="700" text-anchor="middle" fill="', INK, '" letter-spacing="2">',
              'VERIFIED IDENTITY',
            '</text>',
            '<text x="400" y="160" font-family="serif" font-size="22" text-anchor="middle" fill="', INK, '" letter-spacing="6">',
              unicode"·  UKRAINE  ·",
            '</text>',
            '<line x1="120" y1="200" x2="680" y2="200" stroke="', RULE, '" stroke-width="1"/>',
            '<text x="400" y="280" font-family="serif" font-size="120" text-anchor="middle" fill="', SOVEREIGN, '">',
              unicode"№", tokenId.toString(),
            '</text>',
            SigilRenderer.render(nullifier),
            '<line x1="120" y1="540" x2="680" y2="540" stroke="', RULE, '" stroke-width="1"/>',
            '<text x="400" y="565" font-family="monospace" font-size="11" text-anchor="middle" fill="', INK, '">',
              'Issued ', uint256(mintTimestamp).toString(),
              unicode" · Network ", chainLabel,
            '</text>',
            '</svg>'
        );
    }

    function _hex16(bytes32 v) private pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory out = new bytes(32);
        for (uint i = 0; i < 16; i++) {
            out[i*2]   = alphabet[uint8(v[i] >> 4)];
            out[i*2+1] = alphabet[uint8(v[i] & 0x0F)];
        }
        return string(out);
    }
}
