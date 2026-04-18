pragma circom 2.1.9;

include "./X509SubjectSerial.circom";

// Test wrapper. MAX_CERT=2048 mirrors the main ECDSA/RSA circuit buffers
// so the circuit-tester compile exercises the realistic constraint cost.
component main = X509SubjectSerial(2048);
