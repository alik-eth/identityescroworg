// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { QKBVerifier } from "../src/QKBVerifier.sol";

/// @notice Pinned-vector "fuzz" for QKBVerifier.toPkAddress.
///         Foundry exposes vm.addr(priv) for the Ethereum address but not the
///         underlying secp256k1 affine coordinates, so a true Solidity-side
///         fuzzer cannot derive the (x, y) input QKBVerifier needs. We use a
///         pinned table of (priv, x, y) vectors generated offline with
///         python's `ecdsa` library and assert toPkAddress(LE-limbs of x,y)
///         equals vm.addr(priv) for each. forge-std treats this as a single
///         test that exercises 18 independent ground-truth points.
contract QKBVerifierVectorsTest is Test {
    struct Vec {
        uint256 priv;
        uint256 x;
        uint256 y;
    }

    function _splitLE(uint256 v) internal pure returns (uint256[4] memory out) {
        out[0] = v & type(uint64).max;
        out[1] = (v >> 64) & type(uint64).max;
        out[2] = (v >> 128) & type(uint64).max;
        out[3] = (v >> 192) & type(uint64).max;
    }

    function _vectors() internal pure returns (Vec[18] memory v) {
        v[0] = Vec(0x1, 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8);
        v[1] = Vec(0x2, 0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5, 0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a);
        v[2] = Vec(0x3, 0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9, 0x388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672);
        v[3] = Vec(0x4, 0xe493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13, 0x51ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922);
        v[4] = Vec(0x5, 0x2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4, 0xd8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6);
        v[5] = Vec(0x6, 0xfff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556, 0xae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297);
        v[6] = Vec(0x7, 0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc, 0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da);
        v[7] = Vec(0x8, 0x2f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01, 0x5c4da8a741539949293d082a132d13b4c2e213d6ba5b7617b5da2cb76cbde904);
        v[8] = Vec(0x9, 0xacd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe, 0xcc338921b0a7d9fd64380971763b61e9add888a4375f8e0f05cc262ac64f9c37);
        v[9] = Vec(0xa, 0xa0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7, 0x893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7);
        v[10] = Vec(0xb, 0x774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb, 0xd984a032eb6b5e190243dd56d7b7b365372db1e2dff9d6a8301d74c9c953c61b);
        v[11] = Vec(0xc, 0xd01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a, 0xa9f34ffdc815e0d7a8b64537e17bd81579238c5dd9a86d526b051b13f4062327);
        v[12] = Vec(0xd, 0xf28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8, 0x0ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81);
        v[13] = Vec(0xe, 0x499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4, 0xcac2f6c4b54e855190f044e4a7b3d464464279c27a3f95bcc65f40d403a13f5b);
        v[14] = Vec(0xf, 0xd7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e, 0x581e2872a86c72a683842ec228cc6defea40af2bd896d3a5c504dc9ff6a26b58);
        v[15] = Vec(0x10, 0xe60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a, 0xf7e3507399e595929db99f34f57937101296891e44d23f0be1f32cce69616821);
        // Larger privkeys — exercise full-width X, Y.
        v[16] = Vec(0x1234567890abcdef, 0xf973a0b87062c389d125d8199e803b832b6ac6bf7867a4f6cd87506060fc4c58, 0x4b4a0a3f26c988c54c236b224c48bb605b265949e65c098ecd87a581ca10e25d);
        v[17] = Vec(0xdeadbeefcafebabe, 0x7b516c10e892837032b70e618565a6bc510bdb48af9382db97da876979d51b5c, 0x0ddbf4389bd716b8ca83adaad0d78c4ed1444c8c92c58fda261adf8700956437);
    }

    function test_toPkAddress_matchesVmAddr_acrossPinnedVectors() public view {
        Vec[18] memory vs = _vectors();
        for (uint256 idx = 0; idx < vs.length; ++idx) {
            address derived = QKBVerifier.toPkAddress(_splitLE(vs[idx].x), _splitLE(vs[idx].y));
            address expected = vm.addr(vs[idx].priv);
            assertEq(derived, expected, "toPkAddress vs vm.addr mismatch");
        }
    }
}
