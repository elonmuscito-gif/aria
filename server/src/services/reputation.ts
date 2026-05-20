import { syncToPublicTable } from "./sync-public-reputation.js";
import { query } from "../db/pool.js";
import { triggerWebhooks } from "./webhook.js";
import { analyzeAgentBehavior } from "./pattern-detector.js";
import { createWitnessCheck } from "./shadow-witness.js";
import { createTemporalAnchor } from "./temporal-anchor.js";

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

  // ── DIMENSION 1: Success Rate (40 pts) ──────────
  // Based on last 30 days, rate not count
  const successResult = await query<{
    total: string;
    successes: string;
  }>(`
    SELECT
      COUNT(*) FILTER (WHERE outcome != 'blocked') AS total,
      COUNT(*) FILTER (WHERE outcome = 'success') AS successes
    FROM events
    WHERE agent_id = $1
      AND recorded_at > NOW() - INTERVAL '30 days'
  `, [agentId]);

  const s = successResult.rows[0];
  const total30d = parseInt(s?.total ?? '0');

  if (total30d === 0) return;

  const successRate = total30d > 0
    ? parseInt(s?.successes ?? '0') / total30d
    : 0;

  // 40 points scaled by success rate
  const dim1 = Math.round(successRate * 40);

  // ── DIMENSION 2: Scope Compliance (30 pts) ──────
  // Rate of actions within declared scope
  const scopeResult = await query<{
    total: string;
    within_scope: string;
  }>(`
    SELECT
      COUNT(*) FILTER (WHERE outcome != 'blocked') AS total,
      COUNT(*) FILTER (WHERE server_within_scope = true AND outcome != 'blocked') AS within_scope
    FROM events
    WHERE agent_id = $1
      AND recorded_at > NOW() - INTERVAL '30 days'
  `, [agentId]);

  const sc = scopeResult.rows[0];
  const scopeTotal = parseInt(sc?.total ?? '0');
  const scopeRate = scopeTotal > 0
    ? parseInt(sc?.within_scope ?? '0') / scopeTotal
    : 1;

  // 30 points scaled by compliance rate
  // Below 80% compliance = 0 points
  let dim2 = 0;
  if (scopeRate >= 0.99) dim2 = 30;
  else if (scopeRate >= 0.95) dim2 = 27;
  else if (scopeRate >= 0.90) dim2 = 22;
  else if (scopeRate >= 0.85) dim2 = 16;
  else if (scopeRate >= 0.80) dim2 = 10;
  else dim2 = 0;

  // ── DIMENSION 3: Consistency (15 pts) ───────────
  // How consistent is daily behavior (stddev of daily counts)
  const consistencyResult = await query<{
    stddev: string | null;
    avg_daily: string | null;
  }>(`
    SELECT
      STDDEV(daily_count) AS stddev,
      AVG(daily_count) AS avg_daily
    FROM (
      SELECT
        DATE_TRUNC('day', recorded_at) AS day,
        COUNT(*) AS daily_count
      FROM events
      WHERE agent_id = $1
        AND recorded_at > NOW() - INTERVAL '30 days'
      GROUP BY DATE_TRUNC('day', recorded_at)
    ) daily
  `, [agentId]);

  const cs = consistencyResult.rows[0];
  const stddev = parseFloat(cs?.stddev ?? '0') || 0;
  const avgDaily = parseFloat(cs?.avg_daily ?? '1') || 1;
  const coeffVariation = stddev / avgDaily;

  // Low variation = consistent = more points
  let dim3 = 0;
  if (coeffVariation < 0.1) dim3 = 15;
  else if (coeffVariation < 0.25) dim3 = 12;
  else if (coeffVariation < 0.5) dim3 = 9;
  else if (coeffVariation < 0.75) dim3 = 5;
  else dim3 = 2;

  // ── DIMENSION 4: Clean History (10 pts) ─────────
  // Critical incidents in last 90 days
  const historyResult = await query<{
    hardware_conflicts: string;
    signature_failures: string;
  }>(`
    SELECT
      COUNT(*) FILTER (
        WHERE (meta->>'hardware_conflict')::boolean = true
      ) AS hardware_conflicts,
      COUNT(*) FILTER (
        WHERE signature_valid = false
      ) AS signature_failures
    FROM events
    WHERE agent_id = $1
      AND recorded_at > NOW() - INTERVAL '90 days'
  `, [agentId]);

  const hs = historyResult.rows[0];
  const hardwareConflicts = parseInt(hs?.hardware_conflicts ?? '0');
  const signatureFailures = parseInt(hs?.signature_failures ?? '0');
  const criticalIncidents = hardwareConflicts + signatureFailures;

  let dim4 = 0;
  if (criticalIncidents === 0) dim4 = 10;
  else if (criticalIncidents === 1) dim4 = 5;
  else if (criticalIncidents === 2) dim4 = 2;
  else dim4 = 0;

  // ── DIMENSION 5: Recent Trend (5 pts) ───────────
  // Compare last 7 days vs previous 7 days
  const trendResult = await query<{
    recent_success_rate: string | null;
    previous_success_rate: string | null;
  }>(`
    SELECT
      AVG(CASE
        WHEN recorded_at > NOW() - INTERVAL '7 days'
        THEN CASE WHEN outcome = 'success' THEN 1.0 ELSE 0.0 END
      END) AS recent_success_rate,
      AVG(CASE
        WHEN recorded_at BETWEEN
          NOW() - INTERVAL '14 days' AND
          NOW() - INTERVAL '7 days'
        THEN CASE WHEN outcome = 'success' THEN 1.0 ELSE 0.0 END
      END) AS previous_success_rate
    FROM events
    WHERE agent_id = $1
      AND recorded_at > NOW() - INTERVAL '14 days'
      AND outcome != 'blocked'
  `, [agentId]);

  const tr = trendResult.rows[0];
  const recentRate = parseFloat(tr?.recent_success_rate ?? '0') || 0;
  const previousRate = parseFloat(tr?.previous_success_rate ?? '0') || 0;

  let dim5 = 0;
  if (previousRate === 0) {
    dim5 = 3; // No history to compare
  } else {
    const diff = recentRate - previousRate;
    if (diff > 0.05) dim5 = 5;       // Improving
    else if (diff > -0.05) dim5 = 3; // Stable
    else dim5 = 0;                    // Worsening
  }

  // ── FINAL SCORE ──────────────────────────────────
  const rawScore = dim1 + dim2 + dim3 + dim4 + dim5;

  // Cap at 95 — never 100 (always uncertainty)
  const finalScore = Math.min(95, Math.max(0, rawScore));

  const trustLevel = finalScore >= 80 ? 'TRUSTED'
    : finalScore >= 50 ? 'NEUTRAL'
    : 'UNTRUSTED';

  // ── TOTALS FOR DISPLAY ───────────────────────────
  const totalsResult = await query<{
    total_events: string;
    success_count: string;
    error_count: string;
    anomaly_count: string;
    blocked_count: string;
    scope_violation_count: string;
    hardware_conflict_count: string;
  }>(`
    SELECT
      COUNT(*) AS total_events,
      COUNT(*) FILTER (WHERE outcome = 'success') AS success_count,
      COUNT(*) FILTER (WHERE outcome = 'error') AS error_count,
      COUNT(*) FILTER (WHERE outcome = 'anomaly') AS anomaly_count,
      COUNT(*) FILTER (WHERE outcome = 'blocked') AS blocked_count,
      COUNT(*) FILTER (
        WHERE server_within_scope = false AND outcome != 'blocked'
      ) AS scope_violation_count,
      COUNT(*) FILTER (
        WHERE (meta->>'hardware_conflict')::boolean = true
      ) AS hardware_conflict_count
    FROM events
    WHERE agent_id = $1
  `, [agentId]);

  const totals = totalsResult.rows[0];
  if (!totals) return;

  const effectiveTotal = parseInt(totals.total_events) -
    parseInt(totals.blocked_count ?? '0');

  const successRateDisplay = effectiveTotal > 0
    ? ((parseInt(totals.success_count) /
        effectiveTotal) * 100).toFixed(2)
    : null;

  // ── UPSERT SNAPSHOT ──────────────────────────────
  await query(`
    INSERT INTO reputation_snapshots
      (agent_id, total_events, success_count, error_count,
       anomaly_count, blocked_count, scope_violation_count,
       hardware_conflict_count, success_rate, top_actions,
       final_score, trust_level, last_computed_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'[]',$10,$11,NOW())
    ON CONFLICT (agent_id) DO UPDATE SET
      total_events            = EXCLUDED.total_events,
      success_count           = EXCLUDED.success_count,
      error_count             = EXCLUDED.error_count,
      anomaly_count           = EXCLUDED.anomaly_count,
      blocked_count           = EXCLUDED.blocked_count,
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
    totals.blocked_count,
    totals.scope_violation_count,
    totals.hardware_conflict_count,
    successRateDisplay,
    finalScore,
    trustLevel,
  ]);

  // Keep existing hooks
  syncToPublicTable(agentId, finalScore).catch(() => {});
  setImmediate(() => {
    analyzeAgentBehavior(agentId).catch(() => {});
  });
  setImmediate(() => {
    createWitnessCheck(agentId).catch(() => {});
  });
  setImmediate(async () => {
    try {
      const countResult = await query<{ count: string }>(
        `SELECT total_events FROM reputation_snapshots
         WHERE agent_id = $1`,
        [agentId]
      );
      const eventCount = parseInt(countResult.rows[0]?.count ?? '0');
      if (eventCount % 100 === 0) {
        await createTemporalAnchor(agentId);
      }
    } catch {}
  });

  // Critical score alert
  const lastSnap = await query<{ prev_score: string | null }>(
    `SELECT final_score AS prev_score
     FROM reputation_snapshots WHERE agent_id = $1`,
    [agentId]
  );
  const prevScore = parseFloat(lastSnap.rows[0]?.prev_score ?? '100');

  if (finalScore < 20 && prevScore >= 20) {
    const agentInfo = await query<{
      user_id: string | null; did: string; name: string
    }>(
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
        agent: {
          did: info.did,
          name: info.name,
          trustScore: finalScore
        },
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

const DECAY_LOCK_ID = 123456789;

async function runDecayWithLock(): Promise<void> {
  try {
    const lockResult = await query<{ acquired: boolean }>(`
      SELECT pg_try_advisory_lock(${DECAY_LOCK_ID}) AS acquired
    `);
    const acquired = lockResult.rows[0]?.acquired;
    if (!acquired) {
      console.log('[reputation] Decay lock not acquired — another instance is running it');
      return;
    }
    try {
      await applyReputationDecay();
    } finally {
      await query(`SELECT pg_advisory_unlock(${DECAY_LOCK_ID})`);
    }
  } catch (err) {
    console.error('[reputation] Decay lock error:',
      err instanceof Error ? err.message : 'Unknown');
  }
}

setInterval(runDecayWithLock, 24 * 60 * 60 * 1000);
setTimeout(runDecayWithLock, 60 * 1000);