pragma circom 2.1.9;

include "./RsaSpkiExtract.circom";

// MAX_LEN = 512 covers the 294-byte SPKI test fixture with headroom for
// other real-world SPKI sizes (2048-bit RSA SPKIs are ~294 bytes, 3072-bit
// ~422 bytes; enlarge if testing 4096-bit keys).
component main = RsaSpkiExtract2048(512);
