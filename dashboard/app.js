const API = 'http://localhost:3001';
const KEY = 'password';

async function loadAgents() {
  try {
    const res = await fetch(`${API}/v1/agents`, {
      headers: { 'Authorization': `Bearer ${KEY}` }
    });
    const data = await res.json();
    const agents = data.agents;

    if (!Array.isArray(agents)) {
      document.getElementById('agents-list').innerHTML =
        `<div class="error">Error: ${data.error || 'Unexpected response'}</div>`;
      return;
    }

    document.getElementById('total-agents').textContent = agents.length;
    document.getElementById('total-events').textContent =
      agents.reduce((s, a) => s + (a.total_events || 0), 0);
    document.getElementById('total-anomalies').textContent =
      agents.reduce((s, a) => s + (a.anomaly_count || 0), 0);

    const list = document.getElementById('agents-list');
    if (agents.length === 0) {
      list.innerHTML = '<div class="loading">No agents registered yet.</div>';
      return;
    }

    const maskDid = (did) => {
      if (typeof did !== 'string') return 'unknown';
      const prefix = did.slice(0, 10);
      const suffix = did.slice(-4);
      return `${prefix}...${suffix}`;
    };

    const displayScope = (scope) => {
      if (!Array.isArray(scope) || scope.length === 0) return 'No scope';
      if (scope.length === 1) return scope[0];
      return `${scope[0]} + ${scope.length - 1} más`;
    };

    list.innerHTML = agents.map(a => `
      <div class="agent">
        <div>
          <div class="name">${a.name}</div>
          <div class="did">${maskDid(a.did)}</div>
          <div class="scope">${displayScope(a.scope)}</div>
        </div>
        <div>
          <div class="badge ${a.anomaly_count > 0 ? 'anomaly' : ''}">
            ${a.anomaly_count > 0 ? `${a.anomaly_count} ANOMALIES` : 'CLEAN'}
          </div>
          <div style="color:#4a5568;font-size:10px;margin-top:6px;text-align:right">
            ${a.total_events} events
          </div>
        </div>
      </div>
    `).join('');

  } catch (err) {
    document.getElementById('agents-list').innerHTML =
      `<div class="error">Cannot connect to server. Is it running?</div>`;
  }
}

loadAgents();
setInterval(loadAgents, 5000);
