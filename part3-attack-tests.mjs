// PART 3: Attack Tests A01-A43 — Production
const BASE = "https://ariatrust.org";
const KEY  = "2d0d93ee-35f8-4edf-a154-1bea58e1b9e6";
const DID  = "did:agentrust:afa32b33-fa1e-4a28-ad02-5fcdf85e6374";
const SECRET = "60a4d9ed47534569937653e467b2ee316ab6c38793714926961a307761d2c187";

const R = {};
let score = 0;

async function hmac(text, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const buf = await crypto.subtle.sign("HMAC", key, enc.encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,"0")).join("");
}

async function req(path, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 25000);
  try {
    const res = await fetch(BASE + path, { ...opts, signal: ctrl.signal });
    clearTimeout(t);
    let json = null, text = "";
    try { text = await res.text(); json = JSON.parse(text); } catch {}
    return { status: res.status, json, text };
  } catch(e) {
    clearTimeout(t);
    if (e.name === "AbortError") return { status: 524, timeout: true, error: "TIMEOUT" };
    return { status: 0, dropped: true, error: e.message };
  }
}

function mark(id, pass, note) {
  R[id] = { pass, note };
  if (pass) score++;
  console.log(`${pass ? "✓" : "✗"} ${id}: ${note}`);
}

const AUTH    = { "Authorization": `Bearer ${KEY}` };
const CT_JSON = { "Content-Type": "application/json" };

// ── SQL INJECTION ─────────────────────────────────────────────────
console.log("\n=== SQL INJECTION ===");
{
  const r = await req("/v1/agents", {
    method: "POST",
    headers: { ...AUTH, ...CT_JSON },
    body: JSON.stringify({ name: "'; DROP TABLE agents; --", scope: ["test"] })
  });
  mark("A01", r.status !== 500 && r.status !== 0, `status=${r.status}`);
}
{
  const r = await req("/v1/agents?name='; DROP TABLE agents; --", { headers: AUTH });
  mark("A02", r.status !== 500, `status=${r.status}`);
}
{
  const r = await req("/v1/auth/login", {
    method: "POST", headers: CT_JSON,
    body: JSON.stringify({ email: "admin'--", password: "x" })
  });
  mark("A03", r.status === 401 || r.status === 400 || r.status === 429,
    `status=${r.status}`);
}

// ── XSS ──────────────────────────────────────────────────────────
console.log("\n=== XSS ===");
{
  const r = await req("/v1/agents", {
    method: "POST", headers: { ...AUTH, ...CT_JSON },
    body: JSON.stringify({ name: "<script>alert(1)</script>", scope: ["test"] })
  });
  mark("A04", r.status !== 500 && r.status !== 0, `status=${r.status}`);
}
{
  const eId = `xss-${Date.now()}`;
  const ts  = new Date().toISOString();
  const action = "<img src=x onerror=alert(1)>";
  const sig = await hmac(`${eId}:${DID}:${action}:success:${ts}`, SECRET);
  const r = await req("/v1/events", {
    method: "POST", headers: { ...AUTH, ...CT_JSON },
    body: JSON.stringify({ eventId: eId, agentDid: DID, action,
      outcome: "success", withinScope: true, durationMs: 100, timestamp: ts, signature: sig })
  });
  mark("A05", r.status !== 500 && r.status !== 0, `status=${r.status}`);
}

// ── JSON ATTACKS ──────────────────────────────────────────────────
console.log("\n=== JSON ATTACKS ===");
{
  let o = { val: "deep" };
  for (let i = 0; i < 9; i++) o = { n: o };   // 10 levels deep
  const r = await req("/v1/agents", {
    method: "POST", headers: { ...AUTH, ...CT_JSON },
    body: JSON.stringify(o)
  });
  mark("A06", r.status === 400, `status=${r.status} code=${r.json?.code}`);
}
{
  const body = '{"name":"x","pad":"' + "A".repeat(1.15 * 1024 * 1024) + '"}';
  const r = await req("/v1/agents", {
    method: "POST", headers: { ...AUTH, ...CT_JSON }, body
  });
  mark("A07", r.status === 413, `status=${r.status}`);
}
{
  const r = await req("/v1/agents", {
    method: "POST", headers: { ...AUTH, ...CT_JSON },
    body: JSON.stringify({ name: "x", scope: new Array(10000).fill(null) })
  });
  mark("A08", r.status === 400 || r.status === 413, `status=${r.status}`);
}
{
  const r = await req("/v1/agents", {
    method: "POST", headers: { ...AUTH, ...CT_JSON }, body: "null"
  });
  mark("A09", r.status >= 400, `status=${r.status}`);
}
{
  const r = await req("/v1/agents", {
    method: "POST", headers: { ...AUTH, ...CT_JSON }, body: '{"broken'
  });
  mark("A10", r.status === 400, `status=${r.status}`);
}

// ── AUTHENTICATION ATTACKS ────────────────────────────────────────
console.log("\n=== AUTHENTICATION ATTACKS ===");
{ const r = await req("/v1/agents");
  mark("A11", r.status === 401, `status=${r.status}`); }
{ const r = await req("/v1/agents", { headers: { "Authorization": "Bearer " } });
  mark("A12", r.status === 401, `status=${r.status}`); }
{ const r = await req("/v1/agents", { headers: { "Authorization": "Bearer '; DROP TABLE users; --" } });
  mark("A13", r.status === 401, `status=${r.status}`); }
{ const r = await req("/v1/agents", { headers: { "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.abc123" } });
  mark("A14", r.status === 401, `status=${r.status}`); }
{ const r = await req("/v1/agents", { headers: { "Authorization": "Bearer " + "A".repeat(10000) } });
  mark("A15", r.status === 401, `status=${r.status}`); }

// ── REPLAY ATTACKS ────────────────────────────────────────────────
console.log("\n=== REPLAY ATTACKS ===");
{
  const eId = `replay-${Date.now()}`;
  const ts  = new Date().toISOString();
  const sig = await hmac(`${eId}:${DID}:test:action:success:${ts}`, SECRET);
  const body = JSON.stringify({ eventId: eId, agentDid: DID, action: "test:action",
    outcome: "success", withinScope: true, durationMs: 100, timestamp: ts, signature: sig });
  const h = { ...AUTH, ...CT_JSON };
  const r1 = await req("/v1/events", { method: "POST", headers: h, body });
  const r2 = await req("/v1/events", { method: "POST", headers: h, body });
  mark("A17", r2.status === 409, `first=${r1.status} replay=${r2.status}`);
}
{
  const eId = `past-${Date.now()}`;
  const ts  = new Date(Date.now() - 6 * 60 * 1000).toISOString();
  const sig = await hmac(`${eId}:${DID}:test:action:success:${ts}`, SECRET);
  const r = await req("/v1/events", {
    method: "POST", headers: { ...AUTH, ...CT_JSON },
    body: JSON.stringify({ eventId: eId, agentDid: DID, action: "test:action",
      outcome: "success", withinScope: true, durationMs: 100, timestamp: ts, signature: sig })
  });
  mark("A18", r.status === 400, `status=${r.status} code=${r.json?.code}`);
}
{
  const eId = `future-${Date.now()}`;
  const ts  = new Date(Date.now() + 6 * 60 * 1000).toISOString();
  const sig = await hmac(`${eId}:${DID}:test:action:success:${ts}`, SECRET);
  const r = await req("/v1/events", {
    method: "POST", headers: { ...AUTH, ...CT_JSON },
    body: JSON.stringify({ eventId: eId, agentDid: DID, action: "test:action",
      outcome: "success", withinScope: true, durationMs: 100, timestamp: ts, signature: sig })
  });
  mark("A19", r.status === 400, `status=${r.status} code=${r.json?.code}`);
}

// ── BUSINESS LOGIC ────────────────────────────────────────────────
console.log("\n=== BUSINESS LOGIC ===");
{
  const r = await req("/v1/agents", {
    method: "POST", headers: { ...AUTH, ...CT_JSON },
    body: JSON.stringify({ name: "hijack", did: "did:agentrust:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", scope: ["test"] })
  });
  const hijacked = r.json?.did === "did:agentrust:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
  mark("A32", !hijacked && r.status !== 500,
    `status=${r.status} returned_did=${(r.json?.did||"none").substring(0,40)}`);
}
{
  const r = await req("/v1/agents", {
    headers: { "Authorization": "Bearer 00000000-dead-beef-cafe-ffffffffffff" }
  });
  const emptyList = r.status === 200 && Array.isArray(r.json) && r.json.length === 0;
  mark("A33", r.status === 401 || emptyList, `status=${r.status}`);
}
{
  const r = await req("/v1/webhooks/00000000-dead-beef-cafe-ffffffffffff", {
    method: "DELETE", headers: AUTH
  });
  mark("A34", r.status === 403 || r.status === 404, `status=${r.status}`);
}
{
  const fakeDid = "did:agentrust:00000000-dead-beef-cafe-ffffffffffff";
  const eId = `a35-${Date.now()}`;
  const ts  = new Date().toISOString();
  const sig = await hmac(`${eId}:${fakeDid}:test:action:success:${ts}`, SECRET);
  const r = await req("/v1/events", {
    method: "POST", headers: { ...AUTH, ...CT_JSON },
    body: JSON.stringify({ eventId: eId, agentDid: fakeDid, action: "test:action",
      outcome: "success", withinScope: true, durationMs: 100, timestamp: ts, signature: sig })
  });
  mark("A35", r.status >= 400, `status=${r.status}`);
}
{
  const r = await req("/v1/auth/rotate", {
    method: "POST",
    headers: { "Authorization": "Bearer 00000000-dead-beef-cafe-ffffffffffff", ...CT_JSON },
    body: "{}"
  });
  mark("A36", r.status === 401 || r.status === 404, `status=${r.status}`);
}

// ── PARAMETER POLLUTION ───────────────────────────────────────────
console.log("\n=== PARAMETER POLLUTION ===");
{
  const r = await req("/v1/events?limit=99999", { headers: AUTH });
  const items = r.json?.events ?? r.json?.data ?? (Array.isArray(r.json) ? r.json : []);
  const count = Array.isArray(items) ? items.length : 0;
  mark("A37", r.status !== 500 && (r.status === 400 || count <= 100),
    `status=${r.status} items=${count}`);
}
{
  const r = await req("/v1/agents?name[]=a&name[]=b", { headers: AUTH });
  mark("A38", r.status !== 500, `status=${r.status}`);
}
{
  const r = await req("/v1/agents", {
    method: "POST", headers: { ...AUTH, ...CT_JSON },
    body: JSON.stringify({ name: "a39", scope: ["test"],
      __proto__: "hack", constructor: "evil", isAdmin: true })
  });
  mark("A39", r.status !== 500, `status=${r.status} isAdmin=${r.json?.isAdmin}`);
}

// ── HEADER ATTACKS ────────────────────────────────────────────────
console.log("\n=== HEADER ATTACKS (A41-A43, A40 after rate-limit) ===");
{
  const r = await req("/v1/agents", {
    method: "POST",
    headers: { ...AUTH, "Content-Type": "text/plain" },
    body: JSON.stringify({ name: "test", scope: ["test"] })
  });
  mark("A41", r.status === 400 || r.status === 415, `status=${r.status}`);
}
{
  const r = await req("/v1/agents", {
    headers: { ...AUTH, "Accept": "application/xml" }
  });
  const isJson = r.json !== null;
  mark("A42", r.status !== 500 && isJson, `status=${r.status} isJson=${isJson}`);
}
{
  const r = await req("/v1/agents", {
    method: "POST", headers: AUTH,
    body: JSON.stringify({ name: "test", scope: ["test"] })
  });
  mark("A43", r.status === 400 || r.status === 415, `status=${r.status}`);
}

// ── RATE LIMITS ───────────────────────────────────────────────────
console.log("\n=== RATE LIMITS ===");
{
  // A30: Register rate limit
  let hit = false;
  for (let i = 0; i < 6 && !hit; i++) {
    const r = await req("/v1/auth/register", {
      method: "POST", headers: CT_JSON,
      body: JSON.stringify({ email: `rl${Date.now()}${i}@x.com`, password: "Test123!" })
    });
    if (r.status === 404) { mark("A30", false, "endpoint 404 (not found)"); hit = true; break; }
    if (r.status === 429) { hit = true; mark("A30", true, `429 at attempt #${i+1}`); }
  }
  if (!R["A30"]) mark("A30", false, "no 429 after 6 register attempts");
}
{
  // A31: Setup rate limit
  let hit = false;
  for (let i = 0; i < 6 && !hit; i++) {
    const r = await req("/v1/setup", {
      method: "POST", headers: CT_JSON,
      body: JSON.stringify({ owner_email: `s${Date.now()}${i}@t.com`,
        setup_key: "wrong", name: "x", scope: ["x"] })
    });
    if (r.status === 429) { hit = true; mark("A31", true, `429 at attempt #${i+1}`); }
  }
  if (!R["A31"]) mark("A31", false, "no 429 after 6 setup attempts");
}
{
  // A16 + A29: Login rate limit; then A40 (XFF spoof test)
  let hit = false, hitAt = -1;
  for (let i = 0; i < 8 && !hit; i++) {
    const r = await req("/v1/auth/login", {
      method: "POST", headers: CT_JSON,
      body: JSON.stringify({ email: "nobody@nope.invalid", password: "Wrong!" })
    });
    if (r.status === 429) { hit = true; hitAt = i + 1; }
  }
  mark("A16", hit, hit ? `429 at attempt #${hitAt}` : "no 429 after 8 attempts");
  mark("A29", hit, hit ? `same counter hit #${hitAt}` : "no 429 after 8 attempts");

  // A40: with rate limit active, spoof X-Forwarded-For — should still be blocked
  if (hit) {
    const r40 = await req("/v1/auth/login", {
      method: "POST",
      headers: { ...CT_JSON, "X-Forwarded-For": "9.9.9.9" },
      body: JSON.stringify({ email: "nobody@nope.invalid", password: "Wrong!" })
    });
    mark("A40", r40.status === 429,
      `status=${r40.status} (429=not bypassed=PASS; other=bypassed=FAIL)`);
  } else {
    mark("A40", false, "cannot test — rate limit never triggered");
  }
}

// ── MEMBRANE ATTACKS ──────────────────────────────────────────────
console.log("\n=== MEMBRANE ATTACKS ===");
const MEMBRANE = [
  ["/admin","A20"], ["/.env","A21"], ["/debug","A22"], ["/swagger","A23"],
  ["/graphql","A24"], ["/actuator","A25"], ["/internal","A26"], ["/config","A27"]
];
for (const [path, id] of MEMBRANE) {
  const r = await req(path);
  const dropped = r.dropped || r.status === 0 || r.timeout;
  mark(id, dropped,
    `status=${r.status} dropped=${!!r.dropped} timeout=${!!r.timeout} err=${(r.error||"").substring(0,60)}`);
}

// A28: push to 11 total, then test if IP is blocked for normal traffic
console.log("  [A28] Sending 3 more suspicious paths (total=11)...");
await req("/wp-admin");
await req("/phpmyadmin");
await req("/api/swagger.json");
const a28 = await req("/v1/agents", { headers: AUTH });
mark("A28", a28.status === 403 || a28.status === 429 || !!a28.dropped || !!a28.timeout,
  `after-11-paths normal-req status=${a28.status} dropped=${!!a28.dropped}`);

// ── FINAL SCORE ───────────────────────────────────────────────────
console.log("\n══════════════════════════════════");
console.log(`  SCORE: ${score} / 43`);
console.log("══════════════════════════════════\n");
const ids = Object.keys(R).sort((a,b) => {
  const n = x => parseInt(x.replace("A",""),10);
  return n(a) - n(b);
});
for (const id of ids) {
  const {pass, note} = R[id];
  console.log(`  ${pass ? "✓" : "✗"} ${id}: ${note}`);
}
