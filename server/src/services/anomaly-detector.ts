import { query } from "../db/pool.js";

// Límite de seguridad: Un agiente específico no puede generar más de 100 anomalías almacenadas.
// Si supera las 100, las nuevas se ignoran. Esto evita que un atacante nos llene el disco duro.
const MAX_ANOMALIES_PER_AGENT = 100;

export async function recordAnomaly(params: {
  agentId: string;
  eventId: string;
  action: string;
  type: string; // ej: "hardware_conflict", "scope_violation", "rate_limit_exceeded"
}) {
  const { agentId, eventId, action, type } = params;

  try {
    // 1. Verificar cuántas anomalías tiene este agente para evitar el DoS de disco
    const countResult = await query<{ count: string }>(
      `SELECT COUNT(*) as count FROM anomalies WHERE agent_id = $1`,
      [agentId],
    );

    const currentCount = parseInt(countResult.rows[0]?.count || "0", 10);

    if (currentCount >= MAX_ANOMALIES_PER_AGENT) {
      // El agente ya tiene demasiadas anomalías registradas. 
      // No guardamos más para proteger el disco duro de ARIA.
      // El evento original de todas formas ya quedó guardado en la tabla 'events' con su meta.
      return;
    }

    // 2. Si tenemos espacio, guardamos la anomalía
    await query(
      `INSERT INTO anomalies (event_id, agent_id, action)
       VALUES ($1, $2, $3)`,
      [eventId, agentId, action],
    );
    
    console.warn(`[anomaly-detector] Recorded ${type} for agent ${agentId}`);
  } catch (err) {
    // Si falla la inserción en la tabla de anomalías, NO debe tirar todo el servidor.
    // El evento original ya se guardó, la vida continúa.
    console.error("[anomaly-detector] Failed to record anomaly (non-critical):", err instanceof Error ? err.message : String(err));
  }
}

// FUNCIÓN DE LIMPIEZA: Para ejecutarla mediante un "Cron Job" una vez al mes
// Borra anomalías reconocidas o mayores a 30 días para mantener la base de datos ligera
export async function cleanupOldAnomalies() {
  try {
    const result = await query(
      `DELETE FROM anomalies WHERE acknowledged = true OR detected_at < NOW() - INTERVAL '30 days'`,
    );
    console.log(`[anomaly-detector] Cleanup: deleted ${result.rowCount} old anomalies`);
  } catch (err) {
    console.error("[anomaly-detector] Cleanup failed:", err instanceof Error ? err.message : String(err));
  }
}