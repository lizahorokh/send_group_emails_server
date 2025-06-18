pragma circom 2.1.6;

include "circom-ecdsa/circuits/bigint.circom";
include "power65537.circom";

// proves that user knows an RSA double_blind_signature for a message, given l public keys (i.e. values of n)
template GroupSignature(l) {
    var d = 65537;
    var n = 120;
    var k = 35;
    signal input message[5];
    signal input double_blind_hash[k];
    signal input keys[l][k];
    signal input double_blind_signature[k];
    signal input correctKey[k];
    signal equal[l]; // helper to check if correctKey is in the list of keys
    signal accum[l]; // helper to check if correctKey is in the list of keys
    signal keyValid;
    signal power[k];
    signal keyWorks;
    
    // checks that correctKey is in the list of keys
    for (var i = 0; i < l; i++) {
        equal[i] <== BigIsEqual(k)([keys[i], correctKey]);
    }
    accum[0] <== 1 - equal[0];
    for (var i = 1; i < l; i++) {
        accum[i] <== accum[i-1] * (1-equal[i]);
    }
    keyValid <== 1-accum[l-1];
    keyValid === 1;
    
    // checks that correctKey is compatible with the double_blind_signature and message
    power <== Power65537(n, k)(a <== double_blind_signature, m <== correctKey);
    keyWorks <== BigIsEqual(k)([power, double_blind_hash]);
    keyWorks === 1;
}


component main {public [message, keys]} = GroupSignature(10);