import { syncToPublicTable } from "./sync-public-reputation.js";
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
  const lastSnap = await query<{ prev_score: string | null }>(
    `SELECT final_score AS prev_score FROM reputation_snapshots WHERE agent_id = $1`,
    [agentId],
  );
  const prevScore = parseFloat(lastSnap.rows[0]?.prev_score ?? '100');

  // STEP 1 — Query success rate by time window
  const windowResult = await query<{
    total_7d: string;
    success_7d: string;
    total_14d: string;
    success_14d: string;
    total_30d: string;
    success_30d: string;
    scope_violations_30d: string;
    hardware_conflicts_30d: string;
    anomalies_30d: string;
  }>(`
    SELECT
      COUNT(*) FILTER (
        WHERE recorded_at > NOW() - INTERVAL '7 days'
      ) AS total_7d,
      COUNT(*) FILTER (
        WHERE recorded_at > NOW() - INTERVAL '7 days'
        AND outcome = 'success'
        AND server_within_scope = true
      ) AS success_7d,
      COUNT(*) FILTER (
        WHERE recorded_at > NOW() - INTERVAL '14 days'
      ) AS total_14d,
      COUNT(*) FILTER (
        WHERE recorded_at > NOW() - INTERVAL '14 days'
        AND outcome = 'success'
        AND server_within_scope = true
      ) AS success_14d,
      COUNT(*) FILTER (
        WHERE recorded_at > NOW() - INTERVAL '30 days'
      ) AS total_30d,
      COUNT(*) FILTER (
        WHERE recorded_at > NOW() - INTERVAL '30 days'
        AND outcome = 'success'
        AND server_within_scope = true
      ) AS success_30d,
      COUNT(*) FILTER (
        WHERE recorded_at > NOW() - INTERVAL '30 days'
        AND server_within_scope = false
      ) AS scope_violations_30d,
      COUNT(*) FILTER (
        WHERE recorded_at > NOW() - INTERVAL '30 days'
        AND (meta->>'hardware_conflict')::boolean = true
      ) AS hardware_conflicts_30d,
      COUNT(*) FILTER (
        WHERE recorded_at > NOW() - INTERVAL '30 days'
        AND outcome = 'anomaly'
      ) AS anomalies_30d
    FROM events
    WHERE agent_id = $1
  `, [agentId]);

  const w = windowResult.rows[0];
  if (!w) return;

  // STEP 2 — Calculate weighted success rate
  const total7d = parseInt(w.total_7d) || 0;
  const total14d = parseInt(w.total_14d) || 0;
  const total30d = parseInt(w.total_30d) || 0;

  if (total30d === 0) return;

  const rate7d = total7d > 0
    ? (parseInt(w.success_7d) / total7d) * 100
    : null;

  const rate14d = total14d > 0
    ? (parseInt(w.success_14d) / total14d) * 100
    : null;

  const rate30d = total30d > 0
    ? (parseInt(w.success_30d) / total30d) * 100
    : null;

  let weightedRate: number;
  if (rate7d !== null && rate14d !== null) {
    weightedRate = (rate7d * 0.5) + (rate14d * 0.3) + ((rate30d ?? rate14d) * 0.2);
  } else if (rate14d !== null) {
    weightedRate = (rate14d * 0.6) + ((rate30d ?? rate14d) * 0.4);
  } else {
    weightedRate = rate30d ?? 50;
  }

  const baseScore = Math.min(85, weightedRate * 0.85);

  // STEP 3 — Apply critical penalties with decay
  const scopeViolations = parseInt(w.scope_violations_30d) || 0;
  const hardwareConflicts = parseInt(w.hardware_conflicts_30d) || 0;
  const anomalies = parseInt(w.anomalies_30d) || 0;

  const scopePenalty = scopeViolations === 0 ? 0
    : scopeViolations === 1 ? 15
    : scopeViolations === 2 ? 25
    : Math.min(50, 25 + (scopeViolations - 2) * 5);

  const hardwarePenalty = hardwareConflicts === 0 ? 0
    : hardwareConflicts === 1 ? 20
    : Math.min(40, 20 + (hardwareConflicts - 1) * 10);

  const anomalyPenalty = Math.min(20, anomalies * 3);

  const totalPenalty = scopePenalty + hardwarePenalty + anomalyPenalty;

  // STEP 4 — Calculate final score
  const finalScore = Math.max(0, Math.min(100,
    Math.round(baseScore - totalPenalty)
  ));

  const trustLevel = finalScore >= 80 ? 'TRUSTED'
    : finalScore >= 50 ? 'NEUTRAL'
    : 'UNTRUSTED';

  // STEP 5 — Keep existing totals for display purposes
  const totalsResult = await query<{
    total_events: string;
    success_count: string;
    error_count: string;
    anomaly_count: string;
    scope_violation_count: string;
    hardware_conflict_count: string;
  }>(`
    SELECT
      COUNT(*) AS total_events,
      COUNT(*) FILTER (WHERE outcome = 'success') AS success_count,
      COUNT(*) FILTER (WHERE outcome = 'error') AS error_count,
      COUNT(*) FILTER (WHERE outcome = 'anomaly') AS anomaly_count,
      COUNT(*) FILTER (WHERE server_within_scope = false) AS scope_violation_count,
      COUNT(*) FILTER (
        WHERE (meta->>'hardware_conflict')::boolean = true
      ) AS hardware_conflict_count
    FROM events
    WHERE agent_id = $1
  `, [agentId]);

  const totals = totalsResult.rows[0];
  if (!totals) return;

  const successRate = parseInt(totals.total_events) > 0
    ? ((parseInt(totals.success_count) / parseInt(totals.total_events)) * 100).toFixed(2)
    : null;

  // STEP 6 — Upsert reputation snapshot
  await query(`
    INSERT INTO reputation_snapshots
      (agent_id, total_events, success_count, error_count, anomaly_count,
       scope_violation_count, hardware_conflict_count, success_rate, top_actions,
       final_score, trust_level, last_computed_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'[]',$9,$10,NOW())
    ON CONFLICT (agent_id) DO UPDATE SET
      total_events            = EXCLUDED.total_events,
      success_count           = EXCLUDED.success_count,
      error_count             = EXCLUDED.error_count,
      anomaly_count           = EXCLUDED.anomaly_count,
      scope_violation_count   = EXCLUDED.scope_violation_count,
      hardware_conflict_count = EXCLUDED.hardware_conflict_count,
      success_rate            = EXCLUDED.success_rate,
      top_actions             = EXCLUDED.top_actions,
      final_score             = EXCLUDED.final_score,
      trust_level             = EXCLUDED.trust_level,
      last_computed_at        = NOW()
  `, [
    agentId,
    totals.total_events,
    totals.success_count,
    totals.error_count,
    totals.anomaly_count,
    totals.scope_violation_count,
    totals.hardware_conflict_count,
    successRate,
    finalScore,
    trustLevel,
  ]);

  syncToPublicTable(agentId, finalScore).catch(() => {});

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

export async function applyReputationDecay(): Promise<void> {
  try {
    const result = await query<{ agent_id: string; final_score: number }>(`
      SELECT rs.agent_id, rs.final_score
      FROM reputation_snapshots rs
      WHERE rs.final_score != 50
      AND NOT EXISTS (
        SELECT 1 FROM events e
        WHERE e.agent_id = rs.agent_id
        AND e.recorded_at > NOW() - INTERVAL '7 days'
      )
    `);

    for (const row of result.rows) {
      const current = row.final_score;
      const decay = current > 50 ? -2 : 2;
      const newScore = Math.max(0, Math.min(100, current + decay));
      const trustLevel = newScore >= 80 ? 'TRUSTED'
        : newScore >= 50 ? 'NEUTRAL'
        : 'UNTRUSTED';

      await query(`
        UPDATE reputation_snapshots
        SET final_score = $1, trust_level = $2
        WHERE agent_id = $3
      `, [newScore, trustLevel, row.agent_id]);
    }

    console.log(`[reputation] Decay applied to ${result.rows.length} agents`);
  } catch (err) {
    console.error('[reputation] Decay error:',
      err instanceof Error ? err.message : 'Unknown error');
  }
}

setInterval(applyReputationDecay, 24 * 60 * 60 * 1000);
setTimeout(applyReputationDecay, 60 * 1000);