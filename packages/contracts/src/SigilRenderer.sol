// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @notice Renders a nullifier-deterministic geometric sigil as an SVG fragment.
/// @dev    16 bytes of nullifier → 8 nibbles (primitives) + 8 nibbles (sizes/rotations).
///         Outer ring + 4 concentric staggered polygons, sienna cross-mark overlay.
library SigilRenderer {
    string private constant SOVEREIGN = "#1F2D5C";
    string private constant SEAL      = "#8B3A1B";

    function render(bytes32 nullifier) internal pure returns (string memory) {
        // Take low 16 bytes of nullifier as deterministic seed
        uint128 seed = uint128(uint256(nullifier));
        // 8 nibbles for vertex counts (3..18 sides), 8 for rotations (0..360°)
        string memory rings = _renderRings(seed);
        return string.concat(
            '<g transform="translate(400,420)">',
            '<circle r="64" fill="none" stroke="', SOVEREIGN, '" stroke-width="1.2"/>',
            rings,
            '<path d="M -8 0 L 8 0 M 0 -8 L 0 8" stroke="', SEAL, '" stroke-width="2.2"/>',
            '</g>'
        );
    }

    function _renderRings(uint128 seed) private pure returns (string memory acc) {
        // 4 concentric polygons, each radius shrinks by 12px
        for (uint i = 0; i < 4; i++) {
            uint8 sidesNibble = uint8((seed >> (i * 4)) & 0x0F);
            uint8 rotNibble   = uint8((seed >> (64 + i * 4)) & 0x0F);
            uint8 sides   = sidesNibble + 3;            // 3..18
            uint16 radius = uint16(56 - i * 12);        // 56, 44, 32, 20
            uint16 rotation = uint16(rotNibble) * 22;   // 0..330° in 22° steps
            acc = string.concat(acc, _polygon(sides, radius, rotation));
        }
    }

    function _polygon(uint8 sides, uint16 radius, uint16 rotation) private pure returns (string memory) {
        // Build SVG <polygon points="x1,y1 x2,y2 …">
        bytes memory pts;
        for (uint i = 0; i < sides; i++) {
            // angle in tenths of degrees: i * 3600 / sides + rotation*10
            uint32 deg10 = uint32(i) * 3600 / sides + uint32(rotation) * 10;
            (int256 cx, int256 cy) = _cosSinFixed(deg10);
            // x = (radius * cx) / 1e6, y = (radius * cy) / 1e6
            int256 x = (int256(uint256(radius)) * cx) / 1_000_000;
            int256 y = (int256(uint256(radius)) * cy) / 1_000_000;
            pts = abi.encodePacked(pts, _itoa(x), ",", _itoa(y), " ");
        }
        return string.concat(
            '<polygon points="', string(pts),
            '" fill="none" stroke="', SOVEREIGN, '" stroke-width="0.9"/>'
        );
    }

    /// @dev Returns (cos, sin) * 1e6 for an angle expressed in tenths of degrees.
    ///      Uses a 16-entry LUT every 22.5° plus linear interpolation for sub-step
    ///      precision — sufficient for visual rendering, no need for full trig.
    function _cosSinFixed(uint32 deg10) private pure returns (int256 cosV, int256 sinV) {
        // LUT for cosine at 22.5° steps, scaled by 1e6
        int256[17] memory cosTable = [
            int256(1_000_000),  923_879,  707_106,  382_683,
            0,         -382_683, -707_106, -923_879,
            -1_000_000,-923_879, -707_106, -382_683,
            0,          382_683,  707_106,  923_879,
            1_000_000
        ];
        uint32 norm = deg10 % 3600;
        uint32 idx = norm * 16 / 3600;
        uint32 frac = (norm * 16) - idx * 3600;
        int256 c0 = cosTable[idx];
        int256 c1 = cosTable[idx + 1];
        cosV = c0 + (c1 - c0) * int256(uint256(frac)) / 3600;

        // sin(x) = cos(x - 90°). 90° = 900 in deg10.
        uint32 sinDeg10 = (norm + 3600 - 900) % 3600;
        uint32 sIdx = sinDeg10 * 16 / 3600;
        uint32 sFrac = (sinDeg10 * 16) - sIdx * 3600;
        int256 s0 = cosTable[sIdx];
        int256 s1 = cosTable[sIdx + 1];
        sinV = s0 + (s1 - s0) * int256(uint256(sFrac)) / 3600;
    }

    function _itoa(int256 v) private pure returns (string memory) {
        if (v < 0) return string.concat("-", _utoa(uint256(-v)));
        return _utoa(uint256(v));
    }

    function _utoa(uint256 v) private pure returns (string memory) {
        if (v == 0) return "0";
        bytes memory rev;
        while (v > 0) {
            rev = abi.encodePacked(uint8(48 + v % 10), rev);
            v /= 10;
        }
        return string(rev);
    }
}
