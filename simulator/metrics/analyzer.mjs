export function analyzeResults(results) {
  let totalEvents = 0;

  let summary = {
    totalAgents: results.length,
    totalEvents: 0,
    anomalies: [],
    byAgent: [],
  };

  for (const r of results) {
    totalEvents += r.sent;

    if (r.name === "spam" && r.sent > 50) {
      summary.anomalies.push("Spam detectado");
    }

    if (r.name === "invalid" && r.sent > 0) {
      summary.anomalies.push("Firmas inválidas detectadas");
    }

    summary.byAgent.push({
      name: r.name,
      sent: r.sent,
    });
  }

  summary.totalEvents = totalEvents;

  return summary;
}