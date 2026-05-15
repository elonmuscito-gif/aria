import { query } from '../db/pool.js';

export async function createWitnessCheck(
  agentId: string,
  windowHours: number = 24
): Promise<void> {
  try {
    const sources = await query<{
      id: string;
      action_pattern: string;
      name: string;
    }>(`
      SELECT id, action_pattern, name
      FROM witness_sources
      WHERE (agent_id = $1 OR agent_id IS NULL)
        AND active = true
        AND user_id = (
          SELECT ak.user_id
          FROM agents a
          JOIN api_keys ak ON ak.id = a.api_key_id
          WHERE a.id = $1
        )
    `, [agentId]);

    if (sources.rows.length === 0) return;

    const windowEnd = new Date();
    const windowStart = new Date(
      windowEnd.getTime() - windowHours * 60 * 60 * 1000
    );

    for (const source of sources.rows) {
      const pattern = source.action_pattern;
      const isWildcard = pattern.endsWith(':*');
      const prefix = isWildcard ? pattern.slice(0, -1) : null;

      const countResult = await query<{ count: string }>(`
        SELECT COUNT(*) AS count
        FROM events
        WHERE agent_id = $1
          AND outcome = 'success'
          AND client_ts BETWEEN $2 AND $3
          AND (
            ($4::boolean = true AND action LIKE $5)
            OR
            ($4::boolean = false AND action = $6)
          )
      `, [
        agentId,
        windowStart,
        windowEnd,
        isWildcard,
        isWildcard ? `${prefix}%` : null,
        isWildcard ? null : pattern
      ]);

      const agentReported = parseInt(countResult.rows[0]?.count ?? '0');
      if (agentReported === 0) continue;

      await query(`
        INSERT INTO witness_checks
          (witness_source_id, agent_id, action_pattern,
           window_start, window_end, agent_reported, status)
        VALUES ($1,$2,$3,$4,$5,$6,'pending')
        ON CONFLICT DO NOTHING
      `, [source.id, agentId, pattern, windowStart, windowEnd, agentReported]);

      console.log(
        `[witness] Created check for agent ${agentId}: ` +
        `${agentReported} ${pattern} events pending verification`
      );
    }
  } catch (err) {
    console.error('[witness] createWitnessCheck failed:',
      err instanceof Error ? err.message : 'Unknown');
  }
}

export async function resolveWitnessCheck(
  checkId: string,
  witnessConfirmed: number,
  notes?: string
): Promise<{ status: 'verified' | 'discrepancy'; delta: number }> {
  const checkResult = await query<{
    id: string;
    agent_reported: number;
  }>(
    'SELECT id, agent_reported FROM witness_checks WHERE id = $1',
    [checkId]
  );

  const check = checkResult.rows[0];
  if (!check) throw new Error('Witness check not found');

  const delta = check.agent_reported - witnessConfirmed;
  const tolerance = Math.ceil(check.agent_reported * 0.02);
  const status: 'verified' | 'discrepancy' =
    Math.abs(delta) <= tolerance ? 'verified' : 'discrepancy';

  await query(`
    UPDATE witness_checks
    SET witness_confirmed = $1,
        status            = $2,
        discrepancy_delta = $3,
        notes             = $4,
        resolved_at       = NOW()
    WHERE id = $5
  `, [witnessConfirmed, status, delta, notes ?? null, checkId]);

  if (status === 'discrepancy') {
    console.warn(
      `[witness] DISCREPANCY detected for check ${checkId}: ` +
      `agent reported ${check.agent_reported}, ` +
      `witness confirmed ${witnessConfirmed}, delta: ${delta}`
    );
  }

  return { status, delta };
}

export async function getWitnessSummary(agentId: string): Promise<{
  total_checks: number;
  verified: number;
  discrepancies: number;
  pending: number;
  trust_modifier: number;
}> {
  const result = await query<{
    total_checks: string;
    verified: string;
    discrepancies: string;
    pending: string;
  }>(`
    SELECT
      COUNT(*) AS total_checks,
      COUNT(*) FILTER (WHERE status = 'verified')    AS verified,
      COUNT(*) FILTER (WHERE status = 'discrepancy') AS discrepancies,
      COUNT(*) FILTER (WHERE status = 'pending')     AS pending
    FROM witness_checks
    WHERE agent_id = $1
      AND created_at > NOW() - INTERVAL '30 days'
  `, [agentId]);

  const r = result.rows[0] ?? {
    total_checks: '0', verified: '0', discrepancies: '0', pending: '0'
  };

  const totalChecks = parseInt(r.total_checks);
  const discrepancies = parseInt(r.discrepancies);
  const trustModifier = totalChecks > 0
    ? Math.max(-25, discrepancies * -5)
    : 0;

  return {
    total_checks: totalChecks,
    verified: parseInt(r.verified),
    discrepancies,
    pending: parseInt(r.pending),
    trust_modifier: trustModifier
  };
}
