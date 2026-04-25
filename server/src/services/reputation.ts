import { syncToPublicTable } from "./sync-public-reputation";
import { query } from "../db/pool.js";
import { triggerWebhooks } from "./webhook.js";

class ReputationQueue {
  private pending = new Set<string>();
  private timer: ReturnType<typeof setTimeout> | null = null;
  private readonly DEBOUNCE_MS = 3000;

  push(agentId: string): void {
    this.pending.add(agentId);
    this.schedule();
  }

  private schedule(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => this.flush(), this.DEBOUNCE_MS);
  }

  private async flush(): Promise<void> {
    if (this.pending.size === 0) return;
    const batch = [...this.pending];
    this.pending.clear();
    this.timer = null;

    for (const agentId of batch) {
      await computeReputationIncremental(agentId).catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`[reputation] Failed for agent ${agentId}:`, message);
        if (!message.includes("connection")) {
           this.pending.add(agentId);
           this.schedule();
        }
      });
    }
  }
}

export const reputationQueue = new ReputationQueue();

async function computeReputationIncremental(agentId: string): Promise<void> {
  const lastSnap = await query<{ last_computed_at: string | null; prev_success_rate: string | null }>(
    `SELECT last_computed_at, success_rate AS prev_success_rate
     FROM reputation_snapshots WHERE agent_id = $1`,
    [agentId],
  );

  const lastComputedAt = lastSnap.rows[0]?.last_computed_at ?? null;
  const prevScore = parseFloat(lastSnap.rows[0]?.prev_success_rate ?? '100');

  const result = await query<{
    total: string;
    success_count: string;
    error_count: string;
    anomaly_count: string;
    scope_violation_count: string;
    hardware_conflict_count: string;
  }>(
    `SELECT
       COUNT(*)                                                              AS total,
       COUNT(*) FILTER (WHERE outcome = 'success')                          AS success_count,
       COUNT(*) FILTER (WHERE outcome = 'error')                            AS error_count,
       COUNT(*) FILTER (WHERE outcome = 'anomaly')                          AS anomaly_count,
       COUNT(*) FILTER (WHERE server_within_scope = false)                  AS scope_violation_count,
COUNT(*) FILTER (WHERE (meta->>'hardware_conflict')::boolean = true) AS hardware_conflict_count
     FROM events
     WHERE agent_id = $1
       AND ($2::timestamp IS NULL OR recorded_at > $2)`,
    [agentId, lastComputedAt],
  );

  const row = result.rows[0];
  if (!row || parseInt(row.total, 10) === 0) return;

  const historical = lastSnap.rows[0] ? await getHistoricalTotals(agentId) : getZeroTotals();

  const newTotal = historical.total + parseInt(row.total, 10);
  const newSuccess = historical.success + parseInt(row.success_count, 10);
  const newErrors = historical.errors + parseInt(row.error_count, 10);
  const newAnomalies = historical.anomalies + parseInt(row.anomaly_count, 10);
  const newScopeViolations = historical.scopeViolations + parseInt(row.scope_violation_count, 10);
  const newHardwareConflicts = historical.hardwareConflicts + parseInt(row.hardware_conflict_count, 10);
  
  const successRate = newTotal > 0 ? ((newSuccess / newTotal) * 100).toFixed(2) : null;

  // --- THE BRAIN: FINAL SCORE CALCULATION ---
  // 1. Success adds +1 point
  const successPoints = newSuccess;

  // 2. Normal errors subtract -1 (Forgivable)
  const errorPoints = newErrors * -1;

  // 3. Scope anomalies subtract -5 (Danger)
  const anomalyPoints = newAnomalies * -5;

  // 4. Capital crimes (Hardware or Fake signatures) subtract -100 (Near death)
  const criticalPoints = (newScopeViolations + newHardwareConflicts) * -100;

  // Score cannot be less than 0 or greater than 100
  const finalScore = Math.max(0, Math.min(100, successPoints + errorPoints + anomalyPoints + criticalPoints));

  const trustLevel = finalScore >= 80 ? 'TRUSTED' : finalScore >= 50 ? 'NEUTRAL' : 'UNTRUSTED';

  await query(
    `INSERT INTO reputation_snapshots
       (agent_id, total_events, success_count, error_count, anomaly_count,
        scope_violation_count, hardware_conflict_count, success_rate, top_actions,
        final_score, trust_level, last_computed_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'[]',$9,$10,NOW())
     ON CONFLICT (agent_id) DO UPDATE SET
       total_events             = EXCLUDED.total_events,
       success_count            = EXCLUDED.success_count,
       error_count              = EXCLUDED.error_count,
       anomaly_count            = EXCLUDED.anomaly_count,
       scope_violation_count    = EXCLUDED.scope_violation_count,
       hardware_conflict_count  = EXCLUDED.hardware_conflict_count,
       success_rate             = EXCLUDED.success_rate,
       top_actions              = EXCLUDED.top_actions,
       final_score              = EXCLUDED.final_score,
       trust_level              = EXCLUDED.trust_level,
       last_computed_at         = NOW()`,
    [agentId, newTotal, newSuccess, newErrors, newAnomalies,
     newScopeViolations, newHardwareConflicts, successRate,
     finalScore, trustLevel],
  );

  // --- THE TRACTOR: Sync to public table for the web ---
  syncToPublicTable(agentId, finalScore).catch(() => {});

  // Fire critical trust alert when score drops below 20 from a non-critical state
  if (finalScore < 20 && prevScore >= 20) {
    const agentInfo = await query<{ user_id: string | null; did: string; name: string }>(
      `SELECT ak.user_id, a.did, a.name
       FROM agents a
       JOIN api_keys ak ON ak.id = a.api_key_id
       WHERE a.id = $1`,
      [agentId]
    );
    const info = agentInfo.rows[0];
    if (info?.user_id) {
      triggerWebhooks(info.user_id, 'trust_score_critical', {
        alert: 'TRUST_SCORE_CRITICAL',
        severity: 'CRITICAL',
        agent: { did: info.did, name: info.name, trustScore: finalScore },
        reason: 'trust_score_critical',
        timestamp: new Date().toISOString(),
      }).catch(() => {});
    }
  }
}

async function getHistoricalTotals(agentId: string): Promise<{
  total: number; success: number; errors: number; anomalies: number; scopeViolations: number; hardwareConflicts: number;
}> {
  const res = await query<{
    total_events: string; success_count: string; error_count: string; anomaly_count: string;
    scope_violation_count: string; hardware_conflict_count: string;
  }>(
    `SELECT total_events, success_count, error_count, anomaly_count, scope_violation_count, hardware_conflict_count 
     FROM reputation_snapshots WHERE agent_id = $1`,
    [agentId],
  );
  const r = res.rows[0]!;
  return {
    total: parseInt(r.total_events, 10),
    success: parseInt(r.success_count, 10),
    errors: parseInt(r.error_count, 10),
    anomalies: parseInt(r.anomaly_count, 10),
    scopeViolations: parseInt(r.scope_violation_count, 10),
    hardwareConflicts: parseInt(r.hardware_conflict_count, 10),
  };
}

function getZeroTotals(): {
  total: number; success: number; errors: number; anomalies: number; scopeViolations: number; hardwareConflicts: number;
} {
  return { total: 0, success: 0, errors: 0, anomalies: 0, scopeViolations: 0, hardwareConflicts: 0 };
}