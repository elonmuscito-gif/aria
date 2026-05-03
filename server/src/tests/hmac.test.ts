import { createHmac } from 'crypto';
import assert from 'assert';

console.log('Running HMAC tests...');

// Test 1: HMAC signature is deterministic
const secret = 'test-secret-123';
const payload = 'event1:did:test:read:data:success:2026-01-01T00:00:00Z';

const sig1 = createHmac('sha256', secret).update(payload).digest('hex');
const sig2 = createHmac('sha256', secret).update(payload).digest('hex');
assert.strictEqual(sig1, sig2, 'HMAC must be deterministic');
console.log('✅ Test 1: HMAC deterministic');

// Test 2: HMAC output length
assert.strictEqual(sig1.length, 64, 'SHA256 must be 64 hex chars');
console.log('✅ Test 2: HMAC length correct');

// Test 3: Different secrets produce different signatures
const sig3 = createHmac('sha256', 'different-secret').update(payload).digest('hex');
assert.notStrictEqual(sig1, sig3, 'Different secrets = different sigs');
console.log('✅ Test 3: Different secrets produce different sigs');

// Test 4: Different payloads produce different signatures
const sig4 = createHmac('sha256', secret).update(payload + 'x').digest('hex');
assert.notStrictEqual(sig1, sig4, 'Different payloads = different sigs');
console.log('✅ Test 4: Different payloads produce different sigs');

console.log('\nAll HMAC tests passed (4/4)');
