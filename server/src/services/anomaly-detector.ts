import { query } from "../db/pool.js";
import { triggerWebhooks } from "./webhook.js";

// Security limit: A specific agent cannot generate more than 100 stored anomalies.
// If it exceeds 100, new ones are ignored. This prevents disk fill-up attacks.
const MAX_ANOMALIES_PER_AGENT = 100;

export async function recordAnomaly(params: {
  agentId: string;
  eventId: string;
  action: string;
  type: string; // e.g: "hardware_conflict", "scope_violation", "rate_limit_exceeded"
}) {
  const { agentId, eventId, action, type } = params;

  try {
    // event_id column is UUID — skip if the caller passed a non-UUID string
    const isValidUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(eventId);
    if (!isValidUUID) return;

    // Atomic INSERT: count check + insert in one statement, no race condition possible
    await query(
      `INSERT INTO anomalies (event_id, agent_id, action, detected_at, acknowledged)
       SELECT $1, $2, $3, NOW(), false
       WHERE (
         SELECT COUNT(*) FROM anomalies
         WHERE agent_id = $2
         AND acknowledged = false
       ) < $4`,
      [eventId, agentId, action, MAX_ANOMALIES_PER_AGENT],
    );

    console.warn(`[anomaly-detector] Recorded ${type} for agent ${agentId}`);

    // Fire webhook — non-blocking, never throws
    const agentInfo = await query<{ user_id: string | null; did: string; name: string }>(
      `SELECT ak.user_id, a.did, a.name
       FROM agents a
       JOIN api_keys ak ON ak.id = a.api_key_id
       WHERE a.id = $1`,
      [agentId]
    );
    const info = agentInfo.rows[0];
    if (info?.user_id) {
      const severity =
        type === 'scope_violation' || type === 'hardware_conflict' ? 'CRITICAL'
        : type === 'rate_limit_exceeded' ? 'HIGH'
        : 'MEDIUM';
      triggerWebhooks(info.user_id, type, {
        alert: 'ANOMALY_DETECTED',
        severity,
        agent: { did: info.did, name: info.name },
        reason: type,
        action,
        timestamp: new Date().toISOString(),
      }).catch(() => {});
    }
  } catch (err) {
    // If anomaly insertion fails, it should NOT crash the server.
    // The original event was already saved, life goes on.
    console.error("[anomaly-detector] Failed to record anomaly (non-critical):", err instanceof Error ? err.message : String(err));
  }
}

// Archive old or acknowledged anomalies to keep the main table fast. History is never lost.
export async function cleanupOldAnomalies() {
  try {
    // Step 1: Copy to archive first
    await query(
      `INSERT INTO anomalies_archive
        (id, event_id, agent_id, action, detected_at, acknowledged)
       SELECT id, event_id, agent_id, action, detected_at, acknowledged
       FROM anomalies
       WHERE detected_at < NOW() - INTERVAL '90 days'
          OR acknowledged = true
       ON CONFLICT (id) DO NOTHING`
    );

    // Step 2: Then delete from main table
    const result = await query(
      `DELETE FROM anomalies 
       WHERE detected_at < NOW() - INTERVAL '90 days'
          OR acknowledged = true`
    );
    console.log(`[anomaly-detector] Archived and deleted ${result.rowCount} old anomalies`);
  } catch (err) {
    console.error("[anomaly-detector] Cleanup failed:", err instanceof Error ? err.message : String(err));
  }
}

// Run cleanup on startup
cleanupOldAnomalies().catch(console.error);

// Schedule cleanup to run every 24 hours
setInterval(async () => {
  await cleanupOldAnomalies();
  console.log('[anomaly-detector] Archived old anomalies');
}, 24 * 60 * 60 * 1000);