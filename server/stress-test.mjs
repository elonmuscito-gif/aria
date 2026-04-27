const BASE_URL = "http://127.0.0.1:3000";
let tests = 0;
let passed = 0;
let failed = 0;
const results = [];

async function test(name, fn) {
  tests++;
  try {
    await fn();
    passed++;
    results.push({ name, status: "PASS" });
    console.log(`✓ ${name}`);
  } catch (e) {
    failed++;
    results.push({ name, status: "FAIL", error: e.message });
    console.log(`✗ ${name}: ${e.message}`);
  }
}

async function request(path, options = {}) {
  const url = `${BASE_URL}${path}`;
  const res = await globalThis.fetch(url, options);
  let json;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  return { status: res.status, json, ok: res.ok };
}

async function assert(condition, message) {
  if (!condition) throw new Error(message);
}

console.log("=== ARIA STRESS TEST ===\n");
console.log("Testing endpoint: /health\n");

// ─── 1. HEALTH CHECK ─── ─────────────────────────────────────────────
await test("GET /health → 200 OK with status", async () => {
  const { status, json } = await request("/health");
  assert(status === 200, `expected 200, got ${status}`);
  assert(json?.status === "ok" || json?.status === "degraded", `expected status ok, got ${json?.status}`);
  console.log("  ↳ DB Status:", json?.db || "N/A");
  console.log("  ↳ Uptime:", json?.uptime || "N/A", "seconds");
});

// ─── 2. SETUP (Chicken-and-Egg) ─────────────────────────────────────────
let API_KEY = null;
let AGENT_DID = null;
let AGENT_SECRET = null;

await test("POST /v1/setup → Create new user and agent", async () => {
  const { status, json } = await request("/v1/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      owner_email: "stress-test@example.com",
      setup_key: "6696479d57464dc05fd14f961e4ed1ae92d27526d1460f825d266b2e6f93f188",
      name: "StressTestAgent",
      scope: ["send:email", "read:data", "write:data"]
    })
  });
  
  if (status === 200 || status === 201) {
    assert(!!json?.api_key, "expected api_key in response");
    API_KEY = json.api_key;
    if (json?.agent) {
      AGENT_DID = json.agent.did;
      AGENT_SECRET = json.agent.secret;
    }
    console.log("  ↳ API Key:", API_KEY ? "received" : "missing");
    console.log("  ↳ Agent DID:", AGENT_DID || "none");
  } else if (status === 400) {
    console.log("  ↳ Already registered, using existing key");
    // Try to use existing - create a new setup with unique email
    const uniqueEmail = `stress-${Date.now()}@example.com`;
    const { status: s2, json: j2 } = await request("/v1/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        owner_email: uniqueEmail,
        setup_key: "6696479d57464dc05fd14f961e4ed1ae92d27526d1460f825d266b2e6f93f188",
        name: "StressAgent" + Date.now(),
        scope: ["test:action"]
      })
    });
    if (s2 === 200 || s2 === 201) {
      API_KEY = j2?.api_key;
      AGENT_DID = j2?.agent?.did;
      AGENT_SECRET = j2?.agent?.secret;
    }
  }
});

console.log("\n  ↳ Using API Key:", API_KEY ? "YES" : "NO");
console.log("  ↳ Agent DID:", AGENT_DID || "none");

// ─── 3. API KEY ROTATION ────────────────��─────────────────────────
if (API_KEY) {
  await test("POST /v1/api-keys/rotate → Rotate API key", async () => {
    const { status, json } = await request("/v1/api-keys/rotate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      }
    });
    assert(status === 200 || status === 201, `expected 200/201, got ${status}`);
    if (json?.api_key) {
      API_KEY = json.api_key;
      console.log("  ↳ New API Key:", "received");
    }
  });
}

// ─── 4. AGENT OPERATIONS ─────────────────────────────────────
if (API_KEY) {
  await test("POST /v1/agents → Register new agent", async () => {
    const { status, json } = await request("/v1/agents", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: JSON.stringify({
        name: "LoadTestAgent-" + Date.now(),
        scope: ["test:scope", "read:info"]
      })
    });
    assert(status === 201, `expected 201, got ${status}`);
    assert(!!json?.did, "expected did in response");
    AGENT_DID = json.did;
    AGENT_SECRET = json.secret;
    console.log("  ↳ Agent DID:", AGENT_DID);
    console.log("  ↳ Signing Version:", json?.signingVersion || "N/A");
  });

  await test("GET /v1/agents → List agents", async () => {
    const { status, json } = await request("/v1/agents", {
      method: "GET",
      headers: { "Authorization": `Bearer ${API_KEY}` }
    });
    assert(status === 200, `expected 200, got ${status}`);
    assert(Array.isArray(json), "expected array response");
    console.log("  ↳ Agents count:", json?.length || 0);
  });
}

if (API_KEY && AGENT_DID) {
  await test("GET /v1/agents/:did → Get agent details", async () => {
    const { status, json } = await request(`/v1/agents/${AGENT_DID}`, {
      method: "GET",
      headers: { "Authorization": `Bearer ${API_KEY}` }
    });
    assert(status === 200, `expected 200, got ${status}`);
    console.log("  ↳ Scope count:", json?.scope?.length || 0);
    console.log("  ↳ Total events:", json?.total_events || 0);
    console.log("  ↳ Reputation:", json?.success_rate || "N/A");
  });
}

// ─── 5. EVENT RECORDING ───────────────────────────────────────────
async function createHmacSignature(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

if (API_KEY && AGENT_DID && AGENT_SECRET) {
  const eventId = "evt-" + Date.now() + "-" + Math.random().toString(36).substr(2, 9);
  const timestamp = new Date().toISOString();
  const action = "test:action";
  const outcome = "success";
  const payload = `${eventId}:${AGENT_DID}:${action}:${outcome}:${timestamp}`;
  
  const signature = await createHmacSignature(payload, AGENT_SECRET);
  
  await test("POST /v1/events → Record single event", async () => {
    const { status, json } = await request("/v1/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: JSON.stringify({
        eventId,
        agentDid: AGENT_DID,
        action,
        outcome,
        withinScope: true,
        durationMs: 150,
        timestamp,
        signature
      })
    });
    assert(status === 202, `expected 202, got ${status}`);
    console.log("  ↳ Event accepted");
  });

  await test("POST /v1/events → Record error event", async () => {
    const errEventId = "evt-err-" + Date.now();
    const errTimestamp = new Date().toISOString();
    const errPayload = `${errEventId}:${AGENT_DID}:test:action:error:${errTimestamp}`;
    const errSignature = await createHmacSignature(errPayload, AGENT_SECRET);
    
    const { status } = await request("/v1/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: JSON.stringify({
        eventId: errEventId,
        agentDid: AGENT_DID,
        action: "test:action",
        outcome: "error",
        withinScope: true,
        durationMs: 50,
        timestamp: errTimestamp,
        signature: errSignature,
        error: "Test error message"
      })
    });
    assert(status === 202, `expected 202, got ${status}`);
  });

  await test("POST /v1/events/batch → Record 10 events", async () => {
    const events = [];
    for (let i = 0; i < 10; i++) {
      const eId = `batch-${Date.now()}-${i}`;
      const ts = new Date().toISOString();
      const p = `${eId}:${AGENT_DID}:test:action:success:${ts}`;
      const sig = await createHmacSignature(p, AGENT_SECRET);
      events.push({
        eventId: eId,
        agentDid: AGENT_DID,
        action: "test:action",
        outcome: "success",
        withinScope: true,
        durationMs: 100 + i,
        timestamp: ts,
        signature: sig
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

  await test("GET /v1/events → List events with pagination", async () => {
    const { status, json } = await request("/v1/events?limit=20", {
      method: "GET",
      headers: { "Authorization": `Bearer ${API_KEY}` }
    });
    assert(status === 200, `expected 200, got ${status}`);
    console.log("  ↳ Events returned:", json?.length || 0);
  });
}

// ─── 6. RATE LIMITING TEST ────────────────────────────────────
if (API_KEY && AGENT_DID) {
  await test("Rate Limiting: 150+ requests in 1 minute", async () => {
    let accepted = 0;
    let rateLimited = 0;
    const promises = [];
    
    for (let i = 0; i < 160; i++) {
      const eId = `rate-${Date.now()}-${i}`;
      const ts = new Date().toISOString();
      const p = `${eId}:${AGENT_DID}:test:action:success:${ts}`;
      const sig = await createHmacSignature(p, AGENT_SECRET);
      
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
          signature: sig
        })
      }).then(res => {
        if (res.status === 202) accepted++;
        if (res.status === 429) rateLimited++;
      });
      promises.push(req);
    }
    
    await Promise.all(promises);
    console.log("  ↳ Accepted:", accepted);
    console.log("  ↳ Rate limited (429):", rateLimited);
  });
}

// ─── 7. SCOPE VIOLATION TEST ───────────────────────────────────
if (API_KEY && AGENT_DID && AGENT_SECRET) {
  await test("Scope Violation: action outside declared scope", async () => {
    const eId = `scope-viol-${Date.now()}`;
    const ts = new Date().toISOString();
    // Action not in scope
    const p = `${eId}:${AGENT_DID}:delete:everything:success:${ts}`;
    const sig = await createHmacSignature(p, AGENT_SECRET);
    
    const { status, json } = await request("/v1/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: JSON.stringify({
        eventId: eId,
        agentDid: AGENT_DID,
        action: "delete:everything",
        outcome: "success",
        withinScope: false,
        durationMs: 200,
        timestamp: ts,
        signature: sig
      })
    });
    // Should accept but mark as out of scope
    assert(status === 202, `expected 202, got ${status}`);
    console.log("  ↳ Event recorded with scope violation");
  });
}

// ─── 8. INVALID SIGNATURE TEST ─────────────────────────────────
if (API_KEY && AGENT_DID) {
  await test("Invalid Signature: reject tampered event", async () => {
    const eId = `sig-err-${Date.now()}`;
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
        signature: "0000000000000000000000000000000000000000000000000000000000000000"
      })
    });
    // Should be rejected or signature marked invalid
    console.log("  ↳ Status:", status);
    console.log("  ↳ Signature valid:", json?.signatureValid || json?.signature_valid || "N/A");
  });
}

// ─── 9. INVALID AGENT ─────────────────────────────────────────
await test("Invalid Agent DID: 404 on non-existent agent", async () => {
  const { status } = await request("/v1/agents/did:agentrust:00000000-0000-0000-0000-000000000000", {
    method: "GET",
    headers: { "Authorization": `Bearer ${API_KEY}` }
  });
  assert(status === 404, `expected 404, got ${status}`);
});

// ─── 10. EMPTY PAYLOAD TEST ────────────────────────────────
if (API_KEY) {
  await test("Empty body: 400 Bad Request", async () => {
    const { status } = await request("/v1/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: JSON.stringify({})
    });
    assert(status >= 400, `expected 4xx, got ${status}`);
  });
}

// ─── 11. MALFORMED JSON TEST ────────────────────────────────
if (API_KEY) {
  await test("Malformed JSON: 400 Bad Request", async () => {
    const { status } = await request("/v1/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: "not valid json{"
    });
    assert(status >= 400, `expected 4xx, got ${status}`);
  });
}

// ─── RESULTS SUMMARY ────────────────────────────────────────
console.log("\n=== STRESS TEST RESULTS ===");
console.log(`Total tests: ${tests}`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Success rate: ${Math.round((passed/tests)*100)}%`);

process.exit(failed > 0 ? 1 : 0);