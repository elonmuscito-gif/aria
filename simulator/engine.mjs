import { randomUUID, createHmac } from "crypto";

const BASE_URL = process.env.ARIA_BASE_URL || "http://127.0.0.1:3001";
const API_KEY = process.env.ARIA_API_KEY || "your-api-key-here";
const LOOP_DELAY_MS = 5000;
const EVENTS_PER_AGENT = 3;

// Función de utilidad para esperar
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// NUEVA FUNCIÓN: Registrar un agente y obtener sus credenciales
async function registerHonestAgent() {
  console.log("📝 Registrando agente de prueba en ARIA...");
  
  const res = await fetch(`${BASE_URL}/v1/agents`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`,
    },
    body: JSON.stringify({
      name: "Simulator Honest Agent",
      // NO enviamos hardwareFingerprint para que use el modo HMAC clásico (V1)
      scope: ["send:email", "read:data", "analyze:log"], 
    }),
  });

  if (!res.ok) {
    throw new Error(`Failed to register agent: ${res.status} ${await res.text()}`);
  }

  const data = await res.json();
  console.log(`✅ Agente registrado con DID: ${data.agent.did}`);
  // Extraemos la clave secreta que nos dio ARIA (Modo clásico)
  return { did: data.agent.did, secret: data.secret };
}

// NUEVA FUNCIÓN: Construir evento con la firma real del agente registrado
function buildEvent(agentDid, agentSecret, action, outcome) {
  const eventId = randomUUID();
  const timestamp = new Date().toISOString();
  
  // Generamos la firma exactamente igual que lo hace verifySignatureV1 en el servidor
  const payload = `${eventId}:${agentDid}:${action}:${outcome}:${timestamp}`;
  const signature = createHmac("sha256", agentSecret).update(payload).digest("hex");

  return {
    eventId,
    agentDid,
    action,
    outcome,
    withinScope: outcome !== "anomaly",
    durationMs: Math.floor(Math.random() * 1200) + 20,
    timestamp,
    signature, // <-- Firma real calculada con la clave que nos dio el servidor
    meta: { simulated: true },
  };
}

async function safeFetch(url, options) {
  for (let attempt = 1; attempt <= 5; attempt++) {
    const res = await fetch(url, options);
    if (res.status !== 429) return res;
    console.warn(`Rate limited (429), esperando ${attempt * 5000} ms antes de reintentar...`);
    await sleep(attempt * 5000);
  }
  throw new Error("Too many requests after retries");
}

async function sendBatch(events) {
  const res = await safeFetch(`${BASE_URL}/v1/events/batch`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`,
    },
    body: JSON.stringify({ events }),
  });

  const body = await res.json().catch(() => null);
  const accepted = body?.accepted || 0;
  const rejected = body?.rejected || 0;
  console.log(`-> Batch enviado: ${events.length} eventos | Status: ${res.status} | Aceptados: ${accepted} | Rechazados: ${rejected}`);
}

async function runSimulator() {
  console.log("🚀 ARIA Simulator iniciado en modo continuo...\n");

  // 1. Registrar al agente ANTES del bucle infinito
  const agent = await registerHonestAgent();

  // 2. Bucle infinito de simulación
  while (true) {
    // Ya no necesitamos fetchAgents(), usamos directamente el agente que acabamos de crear
    const action = "send:email"; // Usamos una acción que sí está en su scope
    const events = [];

    for (let i = 0; i < EVENTS_PER_AGENT; i++) {
      const outcomeRoll = Math.random();
      const outcome = outcomeRoll < 0.1 ? "anomaly"
                    : outcomeRoll < 0.2 ? "error"
                    : "success";

      // Le pasamos la clave secreta real a buildEvent
      events.push(buildEvent(agent.did, agent.secret, action, outcome));
    }

    if (events.length > 0) {
      await sendBatch(events);
    }

    console.log("Esperando antes de la siguiente oleada...\n");
    await sleep(LOOP_DELAY_MS);
  }
}

runSimulator().catch((err) => {
  console.error("Simulator failed:", err);
  process.exit(1);
});