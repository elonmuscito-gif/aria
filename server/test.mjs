const BASE_URL = process.env.TEST_URL || "http://localhost:3001";
const TEST_EMAIL = `test-${Date.now()}@example.com`;
const TEST_PASSWORD = "testpassword123";

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`✗ ${name}: ${e.message}`);
    failed++;
  }
}

async function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function request(path, options = {}) {
  const url = `${BASE_URL}${path}`;
  const res = await globalThis.fetch(url, options);
  const json = await res.json();
  return { status: res.status, json };
}

console.log(`Running ARIA tests against ${BASE_URL}\n`);

await test("GET /health → expect status ok", async () => {
  const { status, json } = await request("/health");
  assert(status === 200, `expected 200, got ${status}`);
  assert(json.status === "ok", `expected status ok, got ${json.status}`);
});

await test("POST /v1/auth/register → expect api_key returned", async () => {
  const { status, json } = await request("/v1/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD }),
  });
  assert(status === 201, `expected 201, got ${status}`);
  assert(json.api_key, "expected api_key in response");
});

await test("POST /v1/auth/login → expect api_key returned", async () => {
  const { status, json } = await request("/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD }),
  });
  assert(status === 200, `expected 200, got ${status}`);
  assert(json.api_key, "expected api_key in response");
});

console.log(`\n--- Results ---`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);

process.exit(failed > 0 ? 1 : 0);