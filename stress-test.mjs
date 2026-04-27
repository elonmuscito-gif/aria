import { spawn } from 'child_process';
import { createInterface } from 'readline';

const BASE_URL = "http://127.0.0.1:3000";
let serverRunning = false;

console.log('=== ARIA STRESS TEST ===\n');

// Start server
console.log('[1] Starting ARIA server...');
const server = spawn('node', ['--import', 'tsx', 'src/index.ts'], {
  cwd: './server',
  stdio: ['ignore', 'pipe', 'pipe']
});

server.stdout.on('data', (d) => {
  const msg = d.toString();
  process.stdout.write('[server] ' + msg);
  if (msg.includes('ARIA Internal API running')) {
    serverRunning = true;
  }
});

server.stderr.on('data', (d) => process.stderr.write('[server error] ' + d.toString()));

// Wait for server to be ready
await new Promise(r => setTimeout(r, 4000));

if (!serverRunning) {
  console.error('Server failed to start');
  process.exit(1);
}

let tests = 0;
let passed = 0;
let failed = 0;

async function test(name, fn) {
  tests++;
  try {
    await fn();
    passed++;
    console.log(`✓ ${name}`);
  } catch (e) {
    failed++;
    console.log(`✗ ${name}: ${e.message}`);
  }
}

async function request(path, options = {}) {
  const url = `${BASE_URL}${path}`;
  try {
    const res = await globalThis.fetch(url, options);
    let json;
    try { json = await res.json(); } catch { json = null; }
    return { status: res.status, json, ok: res.ok };
  } catch (e) {
    return { status: 0, json: null, ok: false, error: e.message };
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

console.log('\n[2] Running tests...\n');

// Test 1: Health Check
await test("GET /health → 200 OK", async () => {
  const { status, json } = await request("/health");
  assert(status === 200, `expected 200, got ${status}`);
  console.log("  ↳ DB Status:", json?.db || "N/A");
  console.log("  ↳ Uptime:", json?.uptime || "N/A", "seconds");
});

// Test 2: Setup (create user and agent)
let API_KEY = null;
let AGENT_DID = null;
let AGENT_SECRET = null;

await test("POST /v1/setup → Create user and agent", async () => {
  const uniqueEmail = `stress-${Date.now()}@example.com`;
  const { status, json } = await request("/v1/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      owner_email: uniqueEmail,
      setup_key: "6696479d57464dc05fd14f961e4ed1ae92d27526d1460f825d266b2e6f93f188",
      name: "StressTestAgent",
      scope: ["send:email", "read:data", "write:data"]
    })
  });
  
  assert(status === 200 || status === 201, `expected 200/201, got ${status}`);
  assert(!!json?.api_key, "expected api_key");
  API_KEY = json.api_key;
  AGENT_DID = json.agent?.did;
  AGENT_SECRET = json.agent?.secret;
  console.log("  ↳ API Key:", API_KEY ? "received" : "missing");
  console.log("  ↳ Agent DID:", AGENT_DID || "none");
});

// Test 3: Auth with wrong credentials
await test("POST /v1/auth/login → 401 with wrong password", async () => {
  const { status, json } = await request("/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: "nonexistent@example.com",
      password: "wrongpassword"
    })
  });
  assert(status === 401, `expected 401, got ${status}`);
  console.log("  ↳ Error:", json?.error || "N/A");
});

// Test 4: Invalid setup key
await test("POST /v1/setup → 401 with invalid setup key", async () => {
  const { status } = await request("/v1/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      owner_email: "test2@example.com",
      setup_key: "invalid-key",
      name: "TestAgent"
    })
  });
  assert(status === 401, `expected 401, got ${status}`);
});

// Test 5: Route not found
await test("GET /nonexistent → 404 Not Found", async () => {
  const { status } = await request("/nonexistent");
  assert(status === 404, `expected 404, got ${status}`);
});

// Test 6: Protected route without auth
await test("GET /v1/agents → 401 without auth", async () => {
  const { status } = await request("/v1/agents");
  assert(status === 401, `expected 401, got ${status}`);
});

// Test 7: Invalid JSON
if (API_KEY) {
  await test("POST /v1/events → 400 with malformed JSON", async () => {
    const { status } = await request("/v1/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: "invalid json{"
    });
    assert(status >= 400, `expected 4xx, got ${status}`);
  });
}

// Test 8: Create agent
if (API_KEY) {
  await test("POST /v1/agents → Create new agent", async () => {
    const { status, json } = await request("/v1/agents", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: JSON.stringify({
        name: "LoadTestAgent-" + Date.now(),
        scope: ["test:action", "read:info"]
      })
    });
    assert(status === 201, `expected 201, got ${status}`);
    console.log("  ↳ DID:", json?.did);
    console.log("  ↳ Signing Version:", json?.signingVersion);
  });
  
  await test("GET /v1/agents → List agents", async () => {
    const { status, json } = await request("/v1/agents", {
      method: "GET",
      headers: { "Authorization": `Bearer ${API_KEY}` }
    });
    assert(status === 200, `expected 200, got ${status}`);
    console.log("  ↳ Count:", json?.length || 0);
  });
}

// Test 9: Agent details
if (API_KEY && AGENT_DID) {
  await test("GET /v1/agents/:did → Get agent details", async () => {
    const { status, json } = await request(`/v1/agents/${AGENT_DID}`, {
      method: "GET",
      headers: { "Authorization": `Bearer ${API_KEY}` }
    });
    assert(status === 200, `expected 200, got ${status}`);
    console.log("  ↳ Scope:", json?.scope?.length || 0, "items");
    console.log("  ↳ Total events:", json?.total_events || 0);
  });
}

// Test 10: Event with invalid signature
async function createHmac(payload, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

if (API_KEY && AGENT_DID && AGENT_SECRET) {
  await test("POST /v1/events → Event with invalid signature", async () => {
    const eId = "sig-test-" + Date.now();
    const ts = new Date().toISOString();
    const { status, json } = await request("/v1/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: JSON.stringify({
        eventId: eId,
        agentDid: AGENT_DID,
        action: "test:action",
        outcome: "success",
        withinScope: true,
        durationMs: 100,
        timestamp: ts,
        signature: "0".repeat(64)
      })
    });
    console.log("  ↳ Status:", status);
    console.log("  ↳ Signature valid:", json?.signature_valid || "N/A");
  });
  
  // Test 11: Valid event
  await test("POST /v1/events → Record valid event", async () => {
    const eId = "valid-" + Date.now();
    const ts = new Date().toISOString();
    const payload = `${eId}:${AGENT_DID}:test:action:success:${ts}`;
    const sig = await createHmac(payload, AGENT_SECRET);
    
    const { status, json } = await request("/v1/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: JSON.stringify({
        eventId: eId,
        agentDid: AGENT_DID,
        action: "test:action",
        outcome: "success",
        withinScope: true,
        durationMs: 150,
        timestamp: ts,
        signature: sig
      })
    });
    assert(status === 202, `expected 202, got ${status}`);
    console.log("  ↳ Event accepted");
  });
  
  // Test 12: Batch events
  await test("POST /v1/events/batch → Record batch of events", async () => {
    const events = [];
    for (let i = 0; i < 5; i++) {
      const eId = `batch-${Date.now()}-${i}`;
      const ts = new Date().toISOString();
      const p = `${eId}:${AGENT_DID}:test:action:success:${ts}`;
      const s = await createHmac(p, AGENT_SECRET);
      events.push({
        eventId: eId,
        agentDid: AGENT_DID,
        action: "test:action",
        outcome: "success",
        withinScope: true,
        durationMs: 100,
        timestamp: ts,
        signature: s
      });
    }
    
    const { status, json } = await request("/v1/events/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: JSON.stringify(events)
    });
    assert(status === 200, `expected 200, got ${status}`);
    console.log("  ↳ Accepted:", json?.accepted || 0);
    console.log("  ↳ Rejected:", json?.rejected || 0);
  });
  
  // Test 13: List events
  await test("GET /v1/events → List events", async () => {
    const { status, json } = await request("/v1/events?limit=10", {
      method: "GET",
      headers: { "Authorization": `Bearer ${API_KEY}` }
    });
    assert(status === 200, `expected 200, got ${status}`);
    console.log("  ↳ Count:", json?.length || 0);
  });
  
  // Test 14: Scope violation
  await test("POST /v1/events → Scope violation (action outside scope)", async () => {
    const eId = "scope-viol-" + Date.now();
    const ts = new Date().toISOString();
    const p = `${eId}:${AGENT_DID}:delete:all:success:${ts}`;
    const sig = await createHmac(p, AGENT_SECRET);
    
    const { status, json } = await request("/v1/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: JSON.stringify({
        eventId: eId,
        agentDid: AGENT_DID,
        action: "delete:all",
        outcome: "success",
        withinScope: false,
        durationMs: 200,
        timestamp: ts,
        signature: sig
      })
    });
    assert(status === 202, `expected 202, got ${status}`);
    console.log("  ↳ Event recorded with scope violation");
  });
}

// Test 15: Rapid requests (rate limit)
if (API_KEY && AGENT_DID && AGENT_SECRET) {
  await test("Rate Limit: 100+ rapid requests", async () => {
    let accepted = 0;
    let limited = 0;
    const promises = [];
    
    for (let i = 0; i < 120; i++) {
      const eId = `rate-${Date.now()}-${i}`;
      const ts = new Date().toISOString();
      const p = `${eId}:${AGENT_DID}:test:action:success:${ts}`;
      const s = await createHmac(p, AGENT_SECRET);
      
      const req = request("/v1/events", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${API_KEY}`
        },
        body: JSON.stringify({
          eventId: eId,
          agentDid: AGENT_DID,
          action: "test:action",
          outcome: "success",
          withinScope: true,
          durationMs: 50,
          timestamp: ts,
          signature: s
        })
      }).then(r => {
        if (r.status === 202) accepted++;
        if (r.status === 429) limited++;
      });
      promises.push(req);
    }
    
    await Promise.all(promises);
    console.log("  ↳ Accepted (202):", accepted);
    console.log("  ↳ Rate limited (429):", limited);
  });
}

// Test 16: Disallowed email domain
await test("POST /v1/auth/register → 400 with disposable email", async () => {
  const { status, json } = await request("/v1/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: "test@mailinator.com",
      password: "password123"
    })
  });
  assert(status === 400, `expected 400, got ${status}`);
  console.log("  ↳ Error:", json?.error || "N/A");
});

// Test 17: Weak password
await test("POST /v1/auth/register → 400 with weak password", async () => {
  const { status, json } = await request("/v1/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: `test-${Date.now()}@example.com`,
      password: "short"
    })
  });
  assert(status === 400, `expected 400, got ${status}`);
  console.log("  ↳ Error:", json?.error || "N/A");
});

// RESULTS
console.log('\n=== RESULTS ===');
console.log(`Total: ${tests}`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Success rate: ${Math.round((passed/tests)*100)}%`);

// Cleanup
server.kill();
process.exit(failed > 0 ? 1 : 0);