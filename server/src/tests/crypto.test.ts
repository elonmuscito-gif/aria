import { encryptSecret, decryptSecret } from '../utils/crypto.js';
import assert from 'assert';

console.log('Running crypto tests...');

// Test 1: Round-trip encryption/decryption
const plaintext = 'test-hmac-secret-12345';
const did = 'did:agentrust:test-uuid-1234';

const encrypted = encryptSecret(plaintext, did);
const decrypted = decryptSecret(encrypted, did);
assert.strictEqual(decrypted, plaintext, 'Round-trip failed');
console.log('✅ Test 1: Crypto round-trip passes');

// Test 2: Encrypted format includes v1 prefix
assert.ok(encrypted.startsWith('v1:'), 'Missing v1 prefix');
console.log('✅ Test 2: v1 prefix format correct');

// Test 3: Wrong AAD fails decryption
let aadFailed = false;
try {
  decryptSecret(encrypted, 'did:agentrust:wrong-uuid');
} catch {
  aadFailed = true;
}
assert.ok(aadFailed, 'Wrong AAD should reject');
console.log('✅ Test 3: Wrong AAD correctly rejected');

// Test 4: Tampered ciphertext fails
const tampered = encrypted.slice(0, -10) + 'aaaaaaaaaa';
let tamperFailed = false;
try {
  decryptSecret(tampered, did);
} catch {
  tamperFailed = true;
}
assert.ok(tamperFailed, 'Tampered ciphertext should fail');
console.log('✅ Test 4: Tampered ciphertext rejected');

// Test 5: Each encryption produces different output (random IV)
const enc1 = encryptSecret(plaintext, did);
const enc2 = encryptSecret(plaintext, did);
assert.notStrictEqual(enc1, enc2, 'IVs should be random');
console.log('✅ Test 5: Random IV - each encryption unique');

console.log('\nAll crypto tests passed (5/5)');
