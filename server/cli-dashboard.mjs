const API_BASE_URL = process.env.ARIA_BASE_URL ?? "http://127.0.0.1:3001";
const API_KEY = process.env.ARIA_API_KEY ?? "password";

function maskDid(did) {
  if (typeof did !== "string") return "unknown";
  const prefix = did.slice(0, 10);
  const suffix = did.slice(-4);
  return `${prefix}...${suffix}`;
}

function ago(timestamp) {
  if (!timestamp) return "--";
  const now = Date.now();
  const then = new Date(timestamp).getTime();
  if (Number.isNaN(then)) return "invalid";
  const seconds = Math.floor((now - then) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

async function fetchJson(path) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      "Content-Type": "application/json",
    },
  });

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const message = data?.error ?? `HTTP ${res.status}`;
    throw new Error(`Failed ${path}: ${message}`);
  }

  return data;
}

function printHeader() {
  console.log("ARIA CLI DASHBOARD");
  console.log(`Server: ${API_BASE_URL}`);
  console.log("=".repeat(60));
}

function printSection(title) {
  console.log(`\n${title}`);
  console.log("-".repeat(title.length));
}

async function run() {}
  printHeader();

  const health = await fetchJson("/health");
  const agentsResponse = await fetchJson("/v1/agents");
  const eventsResponse = await fetchJson("/v1/events?limit=20");

  const agents = Array.isArray(agentsResponse.agents) ? agentsResponse.agents : [];
  const events = Array.isArray(eventsResponse.events) ? eventsResponse.events : [];

  printSection("STATUS");
  console.log(`Status      : ${health.status ?? "unknown"}`);
  console.log(`DB          : ${health.db ?? "unknown"}`);
  console.log(`Uptime      : ${Math.floor((health.uptime ?? 0) / 60)}m ${Math.floor((health.uptime ?? 0) % 60)}s`);
  console.log(`Timestamp   : ${health.ts ?? "--"}`);

  const totalEvents = agents.reduce((sum, a) => sum + (a.total_events || 0), 0);
  const totalAnomalies = agents.reduce((sum, a) => sum + (a.anomaly_count || 0), 0);
  const avgSuccess = agents.length
    ? agents.reduce((sum, a) => sum + Number(a.success_rate || 0), 0) / agents.length
    : 0;

  printSection("SUMMARY");
  console.log(`Agents      : ${agents.length}`);
  console.log(`Events      : ${totalEvents}`);
  console.log(`Anomalies   : ${totalAnomalies}`);
  console.log(`Avg success : ${avgSuccess.toFixed(1)}%`);

   printSection("AGENTS");
  if (!agents.length) {
    console.log("No agents found.");
  } else {
    // Encabezado con anchos fijos para que las columnas nunca se desordenen
    console.log(`  ${"NAME".padEnd(32)} ${"DID".padEnd(18)} ${"SCOPE".padEnd(18)} ${"EVENTS".padStart(6)} ${"ANOM".padStart(5)} ${"RATE".padStart(6)} ${"LAST SEEN"}`);
    console.log(`  ${"-".repeat(32)} ${"-".repeat(18)} ${"-".repeat(18)} ${"-".repeat(6)} ${"-".repeat(5)} ${"-".repeat(6)} ${"-".repeat(10)}`);
    
    for (const agent of agents) {
      const name = (agent.name || "unnamed").substring(0, 30);
      const did = maskDid(agent.masked_did ?? agent.did ?? "unknown");
      const scope = agent.scope_summary || "No scope";
      const scopeInfo = (agent.scope_count || 0) > 1 ? `${scope}+${agent.scope_count - 1}` : scope;
      const events = String(agent.total_events || 0);
      const anom = String(agent.anomaly_count || 0);
      const rate = `${Number(agent.success_rate ?? 0).toFixed(1)}%`;
      const seen = agent.last_seen ? ago(agent.last_seen) : "never";

      // padEnd añade espacios a la derecha, padStart a la izquierda. Así todo queda alineado.
      console.log(`  ${name.padEnd(32)} ${did.padEnd(18)} ${scopeInfo.padEnd(18)} ${events.padStart(6)} ${anom.padStart(5)} ${rate.padStart(6)} ${seen}`);
    }
  }

  printSection("RECENT EVENTS");
  if (!events.length) {
    console.log("No recent events.");
  } else {
    console.log(`  ${"TIME".padEnd(10)} ${"AGENT".padEnd(30)} ${"ACTION".padEnd(18)} ${"OUTCOME".padEnd(10)} ${"FLAGS"}`);
    console.log(`  ${"-".repeat(10)} ${"-".repeat(30)} ${"-".repeat(18)} ${"-".repeat(10)} ${"-".repeat(15)}`);

    for (const event of events) {
      const time = event.client_ts ? ago(event.client_ts) : "--";
      const agentName = (event.agent_name || event.agent_did || "unknown").substring(0, 28);
      const action = event.action || "unknown";
      const outcome = event.outcome || "unknown";
      
      // Banderas de seguridad visual
      let flags = "";
      if (!event.within_scope) flags += "[SCOPE] ";
      if (event.signature_valid === false) flags += "[BAD SIG]";

      console.log(`  ${time.padEnd(10)} ${agentName.padEnd(30)} ${action.padEnd(18)} ${outcome.padEnd(10)} ${flags}`);
    }
  }

  console.log("\nUse environment variables ARIA_BASE_URL and ARIA_API_KEY to configure.");