const API = "http://localhost:3001";
const AUTH = { Authorization: `Bearer ${localStorage.getItem("aria_api_key") || ""}` };
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function rel(ts) {
  const deltaSeconds = (Date.now() - new Date(ts).getTime()) / 1000;
  if (deltaSeconds < 10) return "just now";
  if (deltaSeconds < 60) return `${Math.floor(deltaSeconds)}s ago`;
  if (deltaSeconds < 3600) return `${Math.floor(deltaSeconds / 60)}m ago`;
  if (deltaSeconds < 86400) return `${Math.floor(deltaSeconds / 3600)}h ago`;
  return `${Math.floor(deltaSeconds / 86400)}d ago`;
}

function upFmt(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return days ? `${days}d ${hours}h` : `${hours}h ${minutes}m`;
}

function initials(name) {
  return name
    .split(/[\s_-]/)
    .map((word) => word[0] ?? "")
    .join("")
    .toUpperCase()
    .slice(0, 2);
}

function trustClr(rate) {
  if (!rate) return "#333";
  if (rate >= 95) return "#00b894";
  if (rate >= 75) return "#fdcb6e";
  return "#e17055";
}

function setClock() {
  document.getElementById("clock").textContent = new Date().toLocaleTimeString("en-US", {
    hour12: false,
  });
}

function showApp() {
  document.getElementById("loader").classList.add("hidden");
  document.getElementById("app").style.display = "flex";
}

function showOffline(message) {
  document.getElementById("statusPill").className = "status-pill offline";
  document.getElementById("statusText").textContent = "OFFLINE";
  document.getElementById("uptime").textContent = message;
  showApp();
}

async function fetchJson(path, headers = AUTH) {
  const response = await fetch(`${API}${path}`, { headers });
  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || `Request failed for ${path}`);
  }

  return data;
}

function renderStats(agents) {
  const totalEvents = agents.reduce((sum, agent) => sum + (agent.total_events || 0), 0);
  const totalAnomalies = agents.reduce((sum, agent) => sum + (agent.anomaly_count || 0), 0);
  const successRate = agents.length
    ? agents.reduce((sum, agent) => sum + Number(agent.success_rate || 0), 0) / agents.length
    : 0;

  document.getElementById("sAgents").textContent = String(agents.length);
  document.getElementById("sEvents").textContent = totalEvents.toLocaleString();
  document.getElementById("sRate").textContent = `${successRate.toFixed(1)}%`;
  document.getElementById("sAnomalies").textContent = String(totalAnomalies);
}

function renderAgents(agents) {
  const tbody = document.getElementById("agentsTbody");
  document.getElementById("agentBadge").textContent = `${agents.length} agent${agents.length !== 1 ? "s" : ""}`;

  if (!agents.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No agents registered</td></tr>';
    return;
  }

  tbody.innerHTML = agents
    .map((agent) => {
      const hasAnomaly = agent.anomaly_count > 0;
      const rate = Number(agent.success_rate || 0);
      const color = trustClr(rate);
      const did = agent.masked_did || "--";
      const scopeSummary = agent.scope_summary || "No scope";
      const scopeCount = Number(agent.scope_count || 0);

      return `
      <tr class="arow ${hasAnomaly ? "anomaly" : "clean"}">
        <td>
          <div class="agent-name-cell">
            <div class="av">${initials(agent.name || "AG")}</div>
            <div>
              <div class="agent-name">${agent.name || "Unnamed agent"}</div>
              <div class="agent-did">${did}</div>
            </div>
          </div>
        </td>
        <td>${scopeSummary}${scopeCount > 1 ? ` + ${scopeCount - 1} más` : ""}</td>
        <td><span class="badge ${hasAnomaly ? "badge-anomaly" : "badge-clean"}">${hasAnomaly ? "ANOMALY" : "CLEAN"}</span></td>
        <td style="font-family:var(--mono);font-size:11px">${(agent.total_events || 0).toLocaleString()}</td>
        <td>
          <div class="trust-wrap">
            <div class="trust-label" style="color:${color}">${rate.toFixed(1)}%</div>
            <div class="trust-track"><div class="trust-fill" style="width:${rate}%;background:${color}"></div></div>
          </div>
        </td>
        <td style="font-family:var(--mono);font-size:10px;color:var(--muted)">${agent.last_seen ? rel(agent.last_seen) : "--"}</td>
      </tr>`;
    })
    .join("");
}

function renderFeed(events) {
  const feed = document.getElementById("feedList");

  if (!events.length) {
    feed.innerHTML = '<div class="feed-item"><div class="f-time" style="color:var(--dim)">No events</div></div>';
    return;
  }

  feed.innerHTML = events
    .map((event) => {
      const dotColor = !event.within_scope
        ? "#e17055"
        : event.outcome === "error"
          ? "#fdcb6e"
          : "#00b894";

      return `
      <div class="feed-item">
        <div class="f-dot" style="background:${dotColor}"></div>
        <div class="f-body">
          <div class="f-action">
            ${event.action}
            ${!event.within_scope ? '<span class="badge badge-scope">SCOPE</span>' : ""}
          </div>
          <div class="f-agent">${event.agent_name || "--"}</div>
        </div>
        <div class="f-time">${event.client_ts ? rel(event.client_ts) : "--"}</div>
      </div>`;
    })
    .join("");
}

function renderCharts(agents) {
  const today = new Date().getDay();
  const days = Array.from({ length: 7 }, (_, index) => DAYS[(today - 6 + index + 7) % 7]);
  const totalEvents = agents.reduce((sum, agent) => sum + (agent.total_events || 0), 0);
  const totalAnomalies = agents.reduce((sum, agent) => sum + (agent.anomaly_count || 0), 0);

  const eventData = days.map(() => Math.max(2, Math.floor((totalEvents / 7) * (0.4 + Math.random() * 0.8))));
  const anomalyData = days.map(() => Math.max(0, Math.floor((totalAnomalies / 7) * (0.2 + Math.random() * 1.2))));
  const maxEvents = Math.max(...eventData, 1);
  const maxAnomalies = Math.max(...anomalyData, 1);

  document.getElementById("chartEvents").innerHTML = days
    .map(
      (day, index) => `
    <div class="c-bar-wrap">
      <div class="c-bar c-bar-gold" style="height:${Math.round((eventData[index] / maxEvents) * 90)}%"></div>
      <div class="c-day">${day}</div>
    </div>`,
    )
    .join("");

  document.getElementById("chartAnomalies").innerHTML = days
    .map(
      (day, index) => `
    <div class="c-bar-wrap">
      <div class="c-bar c-bar-red" style="height:${Math.max(2, Math.round((anomalyData[index] / maxAnomalies) * 90))}%"></div>
      <div class="c-day">${day}</div>
    </div>`,
    )
    .join("");
}

async function refresh() {
  try {
    const [health, agentsResponse, eventsResponse] = await Promise.all([
      fetchJson("/health", {}),
      fetchJson("/v1/agents"),
      fetchJson("/v1/events?limit=20"),
    ]);

    const agents = Array.isArray(agentsResponse.agents) ? agentsResponse.agents : [];
    const events = Array.isArray(eventsResponse.events) ? eventsResponse.events : [];

    document.getElementById("statusPill").className = "status-pill live";
    document.getElementById("statusText").textContent = "LIVE";
    document.getElementById("uptime").textContent = `UP ${upFmt(Number(health.uptime || 0))}`;

    renderStats(agents);
    renderAgents(agents);
    renderFeed(events);
    renderCharts(agents);
    showApp();
  } catch (error) {
    console.error("[dashboard] Failed to refresh:", error);
    showOffline(error instanceof Error ? error.message : "Connection failed");
  }
}

setClock();
setInterval(setClock, 1000);
refresh();
setInterval(refresh, 5000);
