import crypto from 'crypto';

console.log('[simulator] API_KEY loaded:', process.env.ARIA_API_KEY ? process.env.ARIA_API_KEY.substring(0, 8) + '...' : 'NOT SET - using fallback');

// ── Config ────────────────────────────────────────────────────────────────────
const ARIA_URL = 'https://ariatrust.org';
const API_KEY = process.env.ARIA_API_KEY || 'efd1f57b-645f-4821-8620-6aab909dc155';

const AGENT = {
  name:  'sim-lastressss',
  scope: ['process:sale', 'read:inventory', 'generate:report', 'create:invoice', 'read:customer'],
};

// Deterministic secret derived from API_KEY — survives Railway restarts without file storage.
const FIXED_SECRET = crypto.createHmac('sha256', API_KEY)
  .update('sim-lastressss-secret-v1')
  .digest('hex');

// ── Products (Colombian POS) ──────────────────────────────────────────────────
const PRODUCTS = [
  'Aguardiente Antioqueño', 'Cerveza Club Colombia', 'Queso Campesino',
  'Chorizo Tolimense', 'Arepa de Choclo', 'Panela Orgánica',
  'Bocadillo de Guayaba', 'Chicharrón', 'Salchichón Zenú',
  'Leche Alquería', 'Pan de Bono', 'Arequipe Alpina',
  'Buñuelo', 'Empanada de Pipián', 'Longaniza Valluna',
  'Agua Cristal', 'Café Juan Valdez', 'Natilla',
  'Mazorca Asada', 'Aguapanela con Limón',
];

const pick = arr => arr[Math.floor(Math.random() * arr.length)];
const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

// ── ARIA helpers ──────────────────────────────────────────────────────────────
async function ariaPost(path, body) {
  const res = await fetch(`${ARIA_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
    body: JSON.stringify(body),
  });
  return res.json();
}

async function ariaGet(path) {
  const res = await fetch(`${ARIA_URL}${path}`, {
    headers: { 'Authorization': `Bearer ${API_KEY}` },
  });
  return res.json();
}

// ── Agent registration ────────────────────────────────────────────────────────
async function ensureAgent() {
  // Look for existing agent by name — avoids spawning duplicates across Railway restarts.
  const lookup = await ariaGet('/v1/agents?name=' + encodeURIComponent(AGENT.name));
  const existing = lookup?.agents?.find(a => a.name === AGENT.name);
  if (existing?.did) {
    console.log(`♻️  Reusing existing agent: ${existing.did}`);
    return { did: existing.did, secret: FIXED_SECRET };
  }

  console.log('🔧 Registering new agent…');
  const data = await ariaPost('/v1/agents', AGENT);
  if (!data?.agent?.did) {
    throw new Error(`Agent registration failed: ${JSON.stringify(data)}`);
  }

  console.log(`✅ Agent registered: ${data.agent.did}`);
  return { did: data.agent.did, secret: FIXED_SECRET };
}

// ── HMAC signing (v1) ─────────────────────────────────────────────────────────
function signEvent(secret, eventId, did, action, outcome, timestamp) {
  const payload = `${eventId}:${did}:${action}:${outcome}:${timestamp}`;
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

// ── Event generator ───────────────────────────────────────────────────────────
function generateEvent(did, secret) {
  const roll = Math.random();
  let type, action, outcome, withinScope, meta;

  if (roll < 0.70) {
    // ── 70% valid successes
    type = 'valid';
    outcome = 'success';
    withinScope = true;
    const variant = Math.random();
    if (variant < 0.30) {
      action = 'process:sale';
      meta = { amount: rand(5000, 150000), product: pick(PRODUCTS) };
    } else if (variant < 0.55) {
      action = 'read:inventory';
      meta = { product: pick(PRODUCTS), stock: rand(0, 100) };
    } else if (variant < 0.70) {
      action = 'generate:report';
      meta = { type: 'daily', total: rand(500000, 5000000) };
    } else if (variant < 0.85) {
      action = 'create:invoice';
      meta = { invoice_id: `INV-${rand(1000, 9999)}`, amount: rand(10000, 200000) };
    } else {
      action = 'read:customer';
      meta = { customer_id: `CLI-${rand(100, 999)}` };
    }

  } else if (roll < 0.85) {
    // ── 15% valid-scope errors
    type = 'error';
    outcome = 'error';
    withinScope = true;
    const variant = Math.random();
    if (variant < 0.40) {
      action = 'process:sale';
      meta = { amount: -5000, error: 'monto negativo' };
    } else if (variant < 0.70) {
      action = 'create:invoice';
      meta = { error: 'datos del cliente incompletos' };
    } else {
      action = 'read:inventory';
      meta = { error: 'producto no encontrado' };
    }

  } else if (roll < 0.95) {
    // ── 10% scope violations
    type = 'violation';
    outcome = 'error';
    withinScope = false;
    action = pick(['delete:database', 'modify:prices', 'access:admin', 'read:passwords']);
    meta = { reason: 'acceso no autorizado' };

  } else {
    // ── 5% suspicious / anomalous
    type = 'suspicious';
    outcome = 'success';
    withinScope = true;
    const variant = Math.random();
    if (variant < 0.40) {
      action = 'process:sale';
      meta = { amount: 999999999, product: pick(PRODUCTS), suspicious: true };
    } else if (variant < 0.70) {
      action = 'process:sale';
      meta = { burst: true, sales_count: 5, product: pick(PRODUCTS), amount: rand(5000, 50000) };
    } else {
      action = 'create:invoice';
      const hour = new Date().getHours();
      meta = { invoice_id: `INV-${rand(1000, 9999)}`, amount: rand(10000, 200000), unusual_hour: (hour < 6 || hour > 22) };
    }
  }

  const eventId   = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const signature = signEvent(secret, eventId, did, action, outcome, timestamp);

  return {
    type,
    body: { eventId, agentDid: did, action, outcome, withinScope, durationMs: rand(10, 800), timestamp, signature, meta },
  };
}

// ── Stats ─────────────────────────────────────────────────────────────────────
const stats = { total: 0, successes: 0, errors: 0, violations: 0, suspicious: 0 };

function printStats() {
  const now = new Date().toLocaleString('es-CO', { timeZone: 'America/Bogota' });
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`📊 ARIA SIMULATOR — ${now}`);
  console.log(`Events sent: ${stats.total}`);
  console.log(`Violations:  ${stats.violations}`);
  console.log(`Errors:      ${stats.errors}`);
  console.log(`Suspicious:  ${stats.suspicious}`);
  console.log(`Success:     ${stats.successes}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}

// ── Trust score check ─────────────────────────────────────────────────────────
async function checkTrustScore(did) {
  try {
    const data = await ariaGet(`/v1/agents/${encodeURIComponent(did)}`);
    const score = data?.agent?.trustScore ?? '?';
    const level = data?.agent?.trustLevel ?? '?';
    console.log(`🏅 Trust score: ${score} | Level: ${level}`);
  } catch (err) {
    console.error('⚠️  Trust score check failed:', err.message);
  }
}

// ── Main loop ─────────────────────────────────────────────────────────────────
async function runLoop(did, secret) {
  while (true) {
    try {
      const event  = generateEvent(did, secret);
      const data   = await ariaPost('/v1/events', event.body);

      if (data.error) throw new Error(data.error);

      stats.total++;
      stats[event.type === 'valid' ? 'successes' : event.type === 'error' ? 'errors' : event.type === 'violation' ? 'violations' : 'suspicious']++;

      const scopeOk    = data.insights?.scope?.valid;
      const trustDelta = data.insights?.trustScore?.impact;
      const icon = event.type === 'valid'     ? '✅' :
                   event.type === 'error'     ? '⚠️' :
                   event.type === 'violation' ? '🚨' : '🔴';

      const deltaStr = trustDelta != null ? ` | trust: ${trustDelta > 0 ? '+' : ''}${trustDelta}` : '';
      console.log(`${icon} ${event.body.action} → ${scopeOk ? 'OK' : 'VIOLATION'}${deltaStr}`);

    } catch (err) {
      console.error('❌ Event failed:', err.message);
    }

    const wait = 15000 + Math.random() * 30000;
    await new Promise(r => setTimeout(r, wait));
  }
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────
async function main() {
  console.log('🚀 ARIA Simulator — Las Tres SSS');
  console.log(`🌐 ${ARIA_URL}`);

  const { did, secret } = await ensureAgent();

  // Stats every 5 min
  setInterval(printStats, 5 * 60 * 1000);

  // Trust score every 10 min
  setInterval(() => checkTrustScore(did), 10 * 60 * 1000);
  await checkTrustScore(did);

  console.log('▶️  Starting event loop (15–45s between events)…\n');
  await runLoop(did, secret);
}

main().catch(err => {
  console.error('💀 Fatal:', err.message);
  process.exit(1);
});
