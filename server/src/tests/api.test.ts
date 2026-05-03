import assert from 'assert';

const BASE_URL = process.env.TEST_URL || 'https://ariatrust.org';

console.log(`Running API tests against ${BASE_URL}...`);

async function runTests() {
  // Test 1: Health endpoint responds
  const healthRes = await fetch(`${BASE_URL}/health`);
  assert.strictEqual(healthRes.status, 200, 'Health must return 200');
  const health = await healthRes.json();
  assert.strictEqual(health.status, 'ok', 'Health status must be ok');
  console.log('✅ Test 1: /health returns 200 ok');

  // Test 2: Unauthenticated request rejected
  const unauthRes = await fetch(`${BASE_URL}/v1/agents`);
  assert.strictEqual(unauthRes.status, 401, 'Should reject unauthenticated');
  console.log('✅ Test 2: Unauthenticated request rejected');

  // Test 3: Invalid Content-Type rejected
  const badCT = await fetch(`${BASE_URL}/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: 'not json'
  });
  assert.strictEqual(badCT.status, 400, 'Bad Content-Type rejected');
  console.log('✅ Test 3: Invalid Content-Type rejected');

  // Test 4: Malformed JSON rejected
  const badJSON = await fetch(`${BASE_URL}/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{invalid json'
  });
  assert.strictEqual(badJSON.status, 400, 'Bad JSON rejected');
  console.log('✅ Test 4: Malformed JSON rejected');

  console.log('\nAll API tests passed (4/4)');
}

runTests().catch((err) => {
  console.error('❌ Test failed:', err.message);
  process.exit(1);
});
