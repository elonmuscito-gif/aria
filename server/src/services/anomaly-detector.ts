import { query } from "../db/pool.js";

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
    // 1. Check how many anomalies this agent has to prevent disk DoS
    const countResult = await query<{ count: string }>(
      `SELECT COUNT(*) as count FROM anomalies WHERE agent_id = $1`,
      [agentId],
    );

    const currentCount = parseInt(countResult.rows[0]?.count || "0", 10);

    if (currentCount >= MAX_ANOMALIES_PER_AGENT) {
      // Agent already has too many anomalies recorded.
      // Skip to protect ARIA's disk.
      // The original event is already stored in the 'events' table with its meta.
      return;
    }

    // 2. If we have space, record the anomaly
    // event_id column is UUID — skip if the caller passed a non-UUID string
    const isValidUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(eventId);
    if (!isValidUUID) return;

    await query(
      `INSERT INTO anomalies (event_id, agent_id, action)
       VALUES ($1, $2, $3)`,
      [eventId, agentId, action],
    );
    
    console.warn(`[anomaly-detector] Recorded ${type} for agent ${agentId}`);
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