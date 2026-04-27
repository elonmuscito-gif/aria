import { spawn } from 'child_process';

// Start server and run test
const server = spawn('node', ['--import', 'tsx', 'src/index.ts'], {
  cwd: './server',
  stdio: ['ignore', 'pipe', 'pipe'],
  detached: true
});

server.stdout.on('data', d => process.stdout.write('[srv] ' + d));
server.stderr.on('data', d => process.stderr.write('[srv] ' + d));

// Wait for server, then run test
setTimeout(async () => {
  console.log('Running test...');
  
  const BASE_URL = "http://127.0.0.1:3000";
  let tests = 0, passed = 0, failed = 0;
  
  async function test(name, fn) {
    tests++;
    try { await fn(); passed++; console.log(`✓ ${name}`); }
    catch (e) { failed++; console.log(`✗ ${name}: ${e.message}`); }
  }
  
  async function request(path, opts = {}) {
    const res = await fetch(BASE_URL + path, opts);
    let json;
    try { json = await res.json(); } catch { json = null; }
    return { status: res.status, json };
  }
  
  function assert(c, m) { if (!c) throw new Error(m); }
  
  async function createHmac(payload, secret) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
    return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  // Get credentials
  const email = `redteam${Date.now()}@example.com`;
  const setup = await request('/v1/setup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      owner_email: email,
      setup_key: '6696479d57464dc05fd14f961e4ed1ae92d27526d1460f825d266b2e6f93f188',
      name: 'RedTeam',
      scope: ['test:action']
    })
  });
  
  const API_KEY = setup.json?.api_key;
  const AGENT_DID = setup.json?.agent?.did;
  const AGENT_SECRET = setup.json?.agent?.secret;
  
  console.log('Credenciales:', API_KEY ? 'OK' : 'FAIL');
  
  if (!API_KEY || !AGENT_SECRET) {
    console.error('NO CREDENCIALES');
    process.exit(1);
  }
  
  // === TAREA 1: DATOS IMPOSIBLES ===
  console.log('\n=== TAREA 1: DATOS IMPOSIBLES ===');
  
  await test('T1.1: durationMs = 1,000,000', async () => {
    const eId = 'imp-1m-' + Date.now();
    const ts = new Date().toISOString();
    const payload = `${eId}:${AGENT_DID}:test:action:success:${ts}`;
    const sig = await createHmac(payload, AGENT_SECRET);
    const { status } = await request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify({ eventId: eId, agentDid: AGENT_DID, action: 'test:action', outcome: 'success', withinScope: true, durationMs: 1000000, timestamp: ts, signature: sig })
    });
    console.log('  Status:', status);
    assert(status === 202, `expected 202, got ${status}`);
  });
  
  await test('T1.2: timestamp = 1900', async () => {
    const eId = 'imp-1900-' + Date.now();
    const ts = '1900-01-01T00:00:00.000Z';
    const payload = `${eId}:${AGENT_DID}:test:action:success:${ts}`;
    const sig = await createHmac(payload, AGENT_SECRET);
    const { status } = await request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify({ eventId: eId, agentDid: AGENT_DID, action: 'test:action', outcome: 'success', withinScope: true, durationMs: 100, timestamp: ts, signature: sig })
    });
    console.log('  Status:', status);
  });
  
  await test('T1.3: outcome = INFINITY', async () => {
    const eId = 'imp-inf-' + Date.now();
    const ts = new Date().toISOString();
    const payload = `${eId}:${AGENT_DID}:test:action:success:${ts}`;
    const sig = await createHmac(payload, AGENT_SECRET);
    const { status, json } = await request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify({ eventId: eId, agentDid: AGENT_DID, action: 'test:action', outcome: 'INFINITY', withinScope: true, durationMs: 100, timestamp: ts, signature: sig })
    });
    console.log('  Status:', status);
  });
  
  await test('T1.4: action fuera del scope', async () => {
    const eId = 'imp-scope-' + Date.now();
    const ts = new Date().toISOString();
    const payload = `${eId}:${AGENT_DID}:delete:universe:success:${ts}`;
    const sig = await createHmac(payload, AGENT_SECRET);
    const { status } = await request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify({ eventId: eId, agentDid: AGENT_DID, action: 'delete:universe', outcome: 'success', withinScope: false, durationMs: 100, timestamp: ts, signature: sig })
    });
    console.log('  Status:', status);
  });
  
  await test('T1.5: durationMs negativo', async () => {
    const eId = 'imp-neg-' + Date.now();
    const ts = new Date().toISOString();
    const payload = `${eId}:${AGENT_DID}:test:action:success:${ts}`;
    const sig = await createHmac(payload, AGENT_SECRET);
    const { status } = await request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify({ eventId: eId, agentDid: AGENT_DID, action: 'test:action', outcome: 'success', withinScope: true, durationMs: -5000, timestamp: ts, signature: sig })
    });
    console.log('  Status:', status);
    assert(status === 202, `expected 202, got ${status}`);
  });
  
  // === TAREA 2: LÍMITES ===
  console.log('\n=== TAREA 2: LÍMITES ===');
  
  await test('T2.1: 10,000 eventos vacíos', async () => {
    const events = Array(10000).fill({ eventId: 'x', agentDid: AGENT_DID });
    const { status } = await request('/v1/events/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify(events)
    });
    console.log('  Status:', status);
  });
  
  await test('T2.2: nombre de 50,000 caracteres', async () => {
    const giant = 'A'.repeat(50000);
    const { status } = await request('/v1/agents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify({ name: giant, scope: ['test'] })
    });
    console.log('  Status:', status);
    assert(status >= 400, `expected 4xx, got ${status}`);
  });
  
  await test('T2.3: scope con 5,000 elementos', async () => {
    const scope = Array(5000).fill(0).map((_, i) => `action:${i}`);
    const { status } = await request('/v1/agents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify({ name: 'BigScope', scope })
    });
    console.log('  Status:', status);
  });
  
  // === TAREA 3: SECUENCIA ===
  console.log('\n=== TAREA 3: SECUENCIA ===');
  
  await test('T3.1: DID falso', async () => {
    const fake = 'did:agentrust:00000000-0000-0000-0000-000000000000';
    const { status } = await request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify({ eventId: 'fake', agentDid: fake, action: 'test', outcome: 'success', withinScope: true, durationMs: 100, timestamp: new Date().toISOString(), signature: '0'.repeat(64) })
    });
    console.log('  Status:', status, '(esperado 404)');
  });
  
  await test('T3.2: duplicate eventId', async () => {
    const eId = 'dup-' + Date.now();
    const ts = new Date().toISOString();
    const payload = `${eId}:${AGENT_DID}:test:action:success:${ts}`;
    const sig = await createHmac(payload, AGENT_SECRET);
    await request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify({ eventId: eId, agentDid: AGENT_DID, action: 'test:action', outcome: 'success', withinScope: true, durationMs: 100, timestamp: ts, signature: sig })
    });
    const { status } = await request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify({ eventId: eId, agentDid: AGENT_DID, action: 'test:action', outcome: 'success', withinScope: true, durationMs: 100, timestamp: ts, signature: sig })
    });
    console.log('  Duplicate Status:', status);
  });
  
  await test('T3.3: firma incorrecta', async () => {
    const eId = 'badsig-' + Date.now();
    const ts = new Date().toISOString();
    const sig = await createHmac(`${eId}:${AGENT_DID}:test:success:${ts}`, 'WRONG');
    const { status, json } = await request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify({ eventId: eId, agentDid: AGENT_DID, action: 'test:action', outcome: 'success', withinScope: true, durationMs: 100, timestamp: ts, signature: sig })
    });
    console.log('  Status:', status, '| sig_valid:', json?.signature_valid);
  });
  
  // === TAREA 4: ESPECIALES ===
  console.log('\n=== TAREA 4: ESPECIALES ===');
  
  await test('T4.1: durationMs como string', async () => {
    const eId = 'str-' + Date.now();
    const ts = new Date().toISOString();
    const sig = await createHmac(`${eId}:${AGENT_DID}:test:action:success:${ts}`, AGENT_SECRET);
    const { status } = await request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify({ eventId: eId, agentDid: AGENT_DID, action: 'test:action', outcome: 'success', withinScope: true, durationMs: 'Infinity', timestamp: ts, signature: sig })
    });
    console.log('  Status:', status);
  });
  
  await test('T4.2: NaN', async () => {
    const eId = 'nan-' + Date.now();
    const ts = new Date().toISOString();
    const sig = await createHmac(`${eId}:${AGENT_DID}:test:action:success:${ts}`, AGENT_SECRET);
    const { status } = await request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: JSON.stringify({ eventId: eId, agentDid: AGENT_DID, action: 'test:action', outcome: 'success', withinScope: true, durationMs: NaN, timestamp: ts, signature: sig })
    });
    console.log('  Status:', status);
  });
  
  await test('T4.3: null body', async () => {
    const { status } = await request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: 'null'
    });
    console.log('  Status:', status, '(esperado 400+)');
  });
  
  await test('T4.4: array body', async () => {
    const { status } = await request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
      body: '[]'
    });
    console.log('  Status:', status);
  });
  
  // === RESULTADOS ===
  console.log('\n=== RESULTADOS ===');
  console.log(`Total: ${tests} | Passed: ${passed} | Failed: ${failed}`);
  console.log(`Tasa de éxito: ${Math.round((passed/tests)*100)}%`);
  
  server.kill();
  process.exit(failed > 0 ? 1 : 0);
}, 4000);