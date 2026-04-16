import { syncToPublicTable } from "./sync-public-reputation";
import { query } from "../db/pool.js";

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
  const lastSnap = await query<{ last_computed_at: string | null }>(
    `SELECT last_computed_at FROM reputation_snapshots WHERE agent_id = $1`,
    [agentId],
  );

  const lastComputedAt = lastSnap.rows[0]?.last_computed_at ?? null;

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

  await query(
    `INSERT INTO reputation_snapshots
       (agent_id, total_events, success_count, error_count, anomaly_count,
        scope_violation_count, hardware_conflict_count, success_rate, top_actions, last_computed_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'[]',NOW())
     ON CONFLICT (agent_id) DO UPDATE SET
       total_events             = EXCLUDED.total_events,
       success_count            = EXCLUDED.success_count,
       error_count              = EXCLUDED.error_count,
       anomaly_count            = EXCLUDED.anomaly_count,
       scope_violation_count    = EXCLUDED.scope_violation_count,
       hardware_conflict_count  = EXCLUDED.hardware_conflict_count,
       success_rate             = EXCLUDED.success_rate,
       top_actions              = EXCLUDED.top_actions,
       last_computed_at         = NOW()`,
    [agentId, newTotal, newSuccess, newErrors, newAnomalies,
     newScopeViolations, newHardwareConflicts, successRate],
  );

  // --- EL CEREBRO: CÁLCULO DE PUNTUACIÓN FINAL ---
  // 1. Éxito vale +1 punto
  const successPoints = newSuccess;
  
  // 2. Errores normales restan -1 (Perdonables)
  const errorPoints = newErrors * -1;
  
  // 3. Anomalías de scope restan -5 (Peligro)
  const anomalyPoints = newAnomalies * -5;
  
  // 4. Crímenes capitales (Hardware o Firmas falsas) restan -100 (Casi la muerte)
  const criticalPoints = (newScopeViolations + newHardwareConflicts) * -100;

  // El puntaje no puede ser menor a 0 ni mayor a 100
  const finalScore = Math.max(0, Math.min(100, successPoints + errorPoints + anomalyPoints + criticalPoints));

  // --- EL TRACTOR: Sincronizar con la mesa pública para la web ---
  syncToPublicTable(agentId, finalScore).catch(() => {});
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