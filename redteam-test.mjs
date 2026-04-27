const BASE_URL = "http://127.0.0.1:3000";
let tests = 0;
let passed = 0;
let failed = 0;

const LOG = [];

async function test(name, fn) {
  tests++;
  try {
    await fn();
    passed++;
    console.log(`✓ ${name}`);
    LOG.push({ name, status: "PASS" });
  } catch (e) {
    failed++;
    console.log(`✗ ${name}: ${e.message}`);
    LOG.push({ name, status: "FAIL", error: e.message });
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

function assert(cond, msg) { if (!cond) throw new Error(msg); }

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

console.log("=== ARIA RED TEAM STRESS TEST ===\n");

// Obtener credenciales frescas
console.log("[1] Obteniendo credenciales新鲜的...");
const uniqueEmail = `redteam-${Date.now()}@example.com`;
const setupRes = await request("/v1/setup", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    owner_email: uniqueEmail,
    setup_key: "6696479d57464dc05fd14f961e4ed1ae92d27526d1460f825d266b2e6f93f188",
    name: "RedTeamAgent",
    scope: ["test:action", "send:email", "process:data"]
  })
});

let API_KEY = setupRes.json?.api_key || null;
let AGENT_DID = setupRes.json?.agent?.did || null;
let AGENT_SECRET = setupRes.json?.agent?.secret || null;

console.log("  ↳ API_KEY:", API_KEY ? "OK" : "FALTA");
console.log("  ↳ DID:", AGENT_DID || "FALTA");
console.log("  ↳ SECRET:", AGENT_SECRET ? "OK" : "FALTA");

// Si no hay agent, crear uno directamente
if (!AGENT_SECRET && API_KEY) {
  console.log("[2] Creando agente directamente...");
  const agentRes = await request("/v1/agents", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`
    },
    body: JSON.stringify({
      name: "RedTeamDirect",
      scope: ["test:action"]
    })
  });
  AGENT_DID = agentRes.json?.did || null;
  AGENT_SECRET = agentRes.json?.secret || null;
  console.log("  ↳ Nuevo DID:", AGENT_DID);
}

if (!API_KEY || !AGENT_SECRET) {
  console.error("NO SE PUDIERON OBTENER CREDENCIALES");
  process.exit(1);
}

// ==================== TAREA 1 ====================
console.log("\n=== TAREA 1: DATOS IMPOSIBLES ===\n");

// T1.1: Duración gigante (1 millón ms)
await test("T1.1: durationMs = 1,000,000 (16+ min)", async () => {
  const eId = "imp-1m-" + Date.now();
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
      eventId: eId, agentDid: AGENT_DID, action: "test:action",
      outcome: "success", withinScope: true, durationMs: 1000000,
      timestamp: ts, signature: sig
    })
  });
  console.log("     Status:", status, "| Aceptado:", status === 202);
  assert(status === 202, `expected 202, got ${status}`);
});

// T1.2: Timestamp 1900
await test("T1.2: timestamp = 1900-01-01 (126 años atrás)", async () => {
  const eId = "imp-1900-" + Date.now();
  const ts = "1900-01-01T00:00:00.000Z";
  const payload = `${eId}:${AGENT_DID}:test:action:success:${ts}`;
  const sig = await createHmac(payload, AGENT_SECRET);
  
  const { status } = await request("/v1/events", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`
    },
    body: JSON.stringify({
      eventId: eId, agentDid: AGENT_DID, action: "test:action",
      outcome: "success", withinScope: true, durationMs: 100,
      timestamp: ts, signature: sig
    })
  });
  console.log("     Status:", status, "| Aceptado:", status === 202);
  assert(status >= 200 && status < 300, `expected 2xx, got ${status}`);
});

// T1.3: Outcome inválido
await test("T1.3: outcome = 'INFINITY' (string inválido)", async () => {
  const eId = "imp-inf-" + Date.now();
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
      eventId: eId, agentDid: AGENT_DID, action: "test:action",
      outcome: "INFINITY", withinScope: true, durationMs: 100,
      timestamp: ts, signature: sig
    })
  });
  console.log("     Status:", status, "| outcome:", json?.outcome || "N/A");
  // ARIA debería rechazar o aceptar y marcar como inválido
});

// T1.4: Acción fuera del scope
await test("T1.4: action='delete:universe' (fuera del scope)", async () => {
  const eId = "imp-scope-" + Date.now();
  const ts = new Date().toISOString();
  const payload = `${eId}:${AGENT_DID}:delete:universe:success:${ts}`;
  const sig = await createHmac(payload, AGENT_SECRET);
  
  const { status, json } = await request("/v1/events", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`
    },
    body: JSON.stringify({
      eventId: eId, agentDid: AGENT_DID, action: "delete:universe",
      outcome: "success", withinScope: false, durationMs: 100,
      timestamp: ts, signature: sig
    })
  });
  console.log("     Status:", status, "| withinScope:", json?.withinScope || json?.server_within_scope);
});

// T1.5: Duración negativa
await test("T1.5: durationMs = -5000 (negativo!)", async () => {
  const eId = "imp-neg-" + Date.now();
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
      eventId: eId, agentDid: AGENT_DID, action: "test:action",
      outcome: "success", withinScope: true, durationMs: -5000,
      timestamp: ts, signature: sig
    })
  });
  console.log("     Status:", status, "| durationMs:", json?.durationMs);
  assert(status === 202, `expected 202, got ${status}`);
});

// ==================== TAREA 2 ====================
console.log("\n=== TAREA 2: LÍMITES Y VOLUMEN ===\n");

// T2.1: Array vacío masivo
await test("T2.1: Batch con 10,000 eventos vacíos", async () => {
  const events = Array(10000).fill({ eventId: "empty", agentDid: AGENT_DID });
  
  const { status, json } = await request("/v1/events/batch", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`
    },
    body: JSON.stringify(events)
  });
  console.log("     Status:", status, "| rejected:", json?.rejected);
  assert(status >= 200, `expected 2xx, got ${status}`);
});

// T2.2: Nombre gigante
await test("T2.2: Agent name = 50,000 'A's", async () => {
  const giantName = "A".repeat(50000);
  
  const { status } = await request("/v1/agents", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`
    },
    body: JSON.stringify({ name: giantName, scope: ["test"] })
  });
  console.log("     Status:", status);
  assert(status >= 400, `expected 4xx, got ${status}`);
});

// T2.3: Scope gigante
await test("T2.3: Agent scope = 5,000 elementos", async () => {
  const giantScope = Array(5000).fill(0).map((_, i) => `action:${i}`);
  
  const { status } = await request("/v1/agents", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`
    },
    body: JSON.stringify({ name: "GiantScope", scope: giantScope })
  });
  console.log("     Status:", status);
});

// ==================== TAREA 3 ====================
console.log("\n=== TAREA 3: SABOTAJE DE SECUENCIA ===\n");

// T3.1: DID falso
await test("T3.1: agentDid = DID falso (no existe)", async () => {
  const fakeDid = "did:agentrust:00000000-0000-0000-0000-000000000000";
  const eId = "fake-" + Date.now();
  const ts = new Date().toISOString();
  const sig = "0".repeat(64);
  
  const { status } = await request("/v1/events", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`
    },
    body: JSON.stringify({
      eventId: eId, agentDid: fakeDid, action: "test:action",
      outcome: "success", withinScope: true, durationMs: 100,
      timestamp: ts, signature: sig
    })
  });
  console.log("     Status:", status, "| Expected 404:", status === 404);
  assert(status === 404, `expected 404, got ${status}`);
});

// T3.2: Duplicate eventId
await test("T3.2: Mismo eventId enviado dos veces", async () => {
  const eId = "dup-" + Date.now();
  const ts = new Date().toISOString();
  const payload = `${eId}:${AGENT_DID}:test:action:success:${ts}`;
  const sig = await createHmac(payload, AGENT_SECRET);
  
  // First
  await request("/v1/events", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`
    },
    body: JSON.stringify({
      eventId: eId, agentDid: AGENT_DID, action: "test:action",
      outcome: "success", withinScope: true, durationMs: 100,
      timestamp: ts, signature: sig
    })
  });
  
  // Second (duplicate)
  const { status, json } = await request("/v1/events", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`
    },
    body: JSON.stringify({
      eventId: eId, agentDid: AGENT_DID, action: "test:action",
      outcome: "success", withinScope: true, durationMs: 100,
      timestamp: ts, signature: sig
    })
  });
  console.log("     Duplicate Status:", status);
});

// T3.3: Firma incorrecta
await test("T3.3: Firma con secret incorrecto", async () => {
  const eId = "badsig-" + Date.now();
  const ts = new Date().toISOString();
  const badSecret = "0000000000000000000000000000000000000000";
  const payload = `${eId}:${AGENT_DID}:test:action:success:${ts}`;
  const sig = await createHmac(payload, badSecret);
  
  const { status, json } = await request("/v1/events", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`
    },
    body: JSON.stringify({
      eventId: eId, agentDid: AGENT_DID, action: "test:action",
      outcome: "success", withinScope: true, durationMs: 100,
      timestamp: ts, signature: sig
    })
  });
  console.log("     Status:", status, "| signature_valid:", json?.signature_valid);
});

// ==================== TAREA 4 ====================
console.log("\n=== TAREA 4: DATOS ESPECIALES ===\n");

// T4.1: String en campo numérico
await test("T4.1: durationMs = 'Infinity' (string)", async () => {
  const eId = "str-inf-" + Date.now();
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
      eventId: eId, agentDid: AGENT_DID, action: "test:action",
      outcome: "success", withinScope: true, durationMs: "Infinity",
      timestamp: ts, signature: sig
    })
  });
  console.log("     Status:", status, "| durationMs:", json?.durationMs);
});

// T4.2: NaN
await test("T4.2: durationMs = NaN", async () => {
  const eId = "nan-" + Date.now();
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
      eventId: eId, agentDid: AGENT_DID, action: "test:action",
      outcome: "success", withinScope: true, durationMs: NaN,
      timestamp: ts, signature: sig
    })
  });
  console.log("     Status:", status);
});

// T4.3: null body
await test("T4.3: Body = null", async () => {
  const { status } = await request("/v1/events", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`
    },
    body: "null"
  });
  console.log("     Status:", status);
  assert(status >= 400, `expected 4xx, got ${status}`);
});

// T4.4: Array body
await test("T4.4: Body = []", async () => {
  const { status } = await request("/v1/events", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`
    },
    body: "[]"
  });
  console.log("     Status:", status);
  assert(status >= 400, `expected 4xx, got ${status}`);
});

// ==================== RESULTADOS ====================
console.log("\n=== RESULTADOS ===");
console.log(`Total: ${tests}`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Success rate: ${Math.round((passed/tests)*100)}%`);

// Resumen por categoría
console.log("\n=== RESUMEN POR TAREA ===");
LOG.forEach(l => console.log(`  ${l.status}: ${l.name}`));