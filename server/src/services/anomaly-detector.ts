import { query } from "../db/pool.js";
import { triggerWebhooks } from "./webhook.js";

// Security limit: A specific agent cannot generate more than 100 stored anomalies.
// If it exceeds 100, new ones are ignored. This prevents disk fill-up attacks.
const MAX_ANOMALIES_PER_AGENT = 100;

export async function recordAnomaly(params: {
  agentId: string;
  eventId: string;
  action: string;
  type: string;
}) {
  const { agentId, eventId, action, type } = params;

  try {
    const eventLookup = await query<{ id: string }>(
      "SELECT id FROM events WHERE event_id = $1 AND agent_id = $2",
      [eventId, agentId],
    );

    const internalEventId = eventLookup.rows[0]?.id;
    if (!internalEventId) return;

    await query(
      `INSERT INTO anomalies (event_id, agent_id, action, reason, detected_at, acknowledged)
       SELECT $1, $2, $3, $4, NOW(), false
       WHERE (
         SELECT COUNT(*) FROM anomalies
         WHERE agent_id = $2
         AND acknowledged = false
       ) < $5`,
      [internalEventId, agentId, action, type, MAX_ANOMALIES_PER_AGENT],
    );

    console.warn(`[anomaly-detector] Recorded ${type} for agent ${agentId}`);

    const agentInfo = await query<{ user_id: string | null; did: string; name: string }>(
      `SELECT ak.user_id, a.did, a.name
       FROM agents a
       JOIN api_keys ak ON ak.id = a.api_key_id
       WHERE a.id = $1`,
      [agentId],
    );
    const info = agentInfo.rows[0];
    if (info?.user_id) {
      const severity =
        type === "scope_violation" || type === "hardware_conflict" || type === "signature_failure" ? "CRITICAL"
        : type === "rate_limit_exceeded" ? "HIGH"
        : "MEDIUM";
      triggerWebhooks(info.user_id, type, {
        alert: "ANOMALY_DETECTED",
        severity,
        agent: { did: info.did, name: info.name },
        reason: type,
        action,
        timestamp: new Date().toISOString(),
      }).catch(() => {});
    }
  } catch (err) {
    console.error("[anomaly-detector] Failed to record anomaly (non-critical):", err instanceof Error ? err.message : String(err));
  }
}

// Archive old or acknowledged anomalies to keep the main table fast. History is never lost.
export async function cleanupOldAnomalies() {
  try {
    await query(
      "ALTER TABLE anomalies ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT 'legacy'",
    );

    await query(
      "ALTER TABLE anomalies_archive ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT 'legacy'",
    );

    await query(
      `INSERT INTO anomalies_archive
        (id, event_id, agent_id, action, reason, detected_at, acknowledged)
       SELECT id, event_id, agent_id, action, reason, detected_at, acknowledged
       FROM anomalies
       WHERE detected_at < NOW() - INTERVAL '90 days'
          OR acknowledged = true
       ON CONFLICT (id) DO NOTHING`,
    );

    const result = await query(
      `DELETE FROM anomalies
       WHERE detected_at < NOW() - INTERVAL '90 days'
          OR acknowledged = true`,
    );
    console.log(`[anomaly-detector] Archived and deleted ${result.rowCount} old anomalies`);
  } catch (err) {
    console.error("[anomaly-detector] Cleanup failed:", err instanceof Error ? err.message : String(err));
  }
}

cleanupOldAnomalies().catch(console.error);

setInterval(async () => {
  await cleanupOldAnomalies();
  console.log("[anomaly-detector] Archived old anomalies");
}, 24 * 60 * 60 * 1000);
