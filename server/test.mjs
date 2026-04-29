const BASE_URL = process.env.TEST_URL || "http://localhost:3001";
const TEST_EMAIL = `test-${Date.now()}@example.com`;
const TEST_PASSWORD = "testpassword123";

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`PASS ${name}`);
    passed++;
  } catch (e) {
    console.log(`FAIL ${name}: ${e.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function request(path, options = {}) {
  const url = `${BASE_URL}${path}`;
  const res = await globalThis.fetch(url, options);
  const text = await res.text();
  const json = text ? JSON.parse(text) : {};
  return { status: res.status, json };
}

console.log(`Running ARIA tests against ${BASE_URL}\n`);

await test("GET /health -> status ok", async () => {
  const { status, json } = await request("/health");
  assert(status === 200, `expected 200, got ${status}`);
  assert(json.status === "ok", `expected status ok, got ${json.status}`);
});

await test("POST /v1/auth/register -> creates unverified account", async () => {
  const { status, json } = await request("/v1/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD }),
  });
  assert(status === 201, `expected 201, got ${status}`);
  assert(!json.api_key, "register must not issue api_key before email verification");
  assert(json.message, "expected confirmation message");
});

await test("POST /v1/auth/login -> blocks unverified account", async () => {
  const { status, json } = await request("/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD }),
  });
  assert(status === 403, `expected 403, got ${status}`);
  assert(json.code === "EMAIL_NOT_VERIFIED", `expected EMAIL_NOT_VERIFIED, got ${json.code}`);
});

console.log("\n--- Results ---");
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);

process.exit(failed > 0 ? 1 : 0);
