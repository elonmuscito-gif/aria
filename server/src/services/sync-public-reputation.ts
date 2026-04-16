import { query } from "../db/pool.js";

export async function syncToPublicTable(agentId: string, score: number): Promise<void> {
  const trustLevel = score >= 80 ? "Trusted" : score >= 50 ? "Neutral" : "Untrusted";
  try {
    await query(`
      INSERT INTO public_agent_reputation (did, score, trust_level, last_updated)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (did) DO UPDATE SET
        score = EXCLUDED.score,
        trust_level = EXCLUDED.trust_level,
        last_updated = NOW()
    `, [agentId, score, trustLevel]);
  } catch (err) {
    console.error("Error syncing to public table:", err instanceof Error ? err.message : String(err));
  }
}