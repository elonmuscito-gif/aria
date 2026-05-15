import { Router } from 'express';
import { query } from '../db/pool.js';
import { requireApiKey } from '../middleware/auth.js';
import { resolveWitnessCheck, getWitnessSummary } from '../services/shadow-witness.js';

export const witnessRouter = Router();
witnessRouter.use(requireApiKey);

// POST /v1/witness/sources — Register external witness source
witnessRouter.post('/sources', async (req, res) => {
  const { agentDid, name, source_type, action_pattern } = req.body as {
    agentDid?: string;
    name?: string;
    source_type?: string;
    action_pattern?: string;
  };

  if (!name || !source_type || !action_pattern) {
    return res.status(400).json({
      error: 'name, source_type and action_pattern required',
      code: 'MISSING_FIELDS'
    });
  }

  const validTypes = ['webhook', 'manual', 'api_counter'];
  if (!validTypes.includes(source_type)) {
    return res.status(400).json({
      error: `source_type must be one of: ${validTypes.join(', ')}`,
      code: 'INVALID_SOURCE_TYPE'
    });
  }

  try {
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );
    const userId = keyResult.rows[0]?.user_id;

    if (!userId) {
      return res.status(403).json({
        error: 'Witness sources require a verified account',
        code: 'NO_USER_ACCOUNT'
      });
    }

    let agentId: string | null = null;
    if (agentDid) {
      const agentResult = await query<{ id: string }>(
        'SELECT id FROM agents WHERE did = $1 AND user_id = $2',
        [agentDid, userId]
      );
      agentId = agentResult.rows[0]?.id ?? null;
    }

    const result = await query<{
      id: string;
      name: string;
      source_type: string;
      action_pattern: string;
      created_at: string;
    }>(`
      INSERT INTO witness_sources
        (user_id, agent_id, name, source_type, action_pattern)
      VALUES ($1,$2,$3,$4,$5)
      RETURNING id, name, source_type, action_pattern, created_at
    `, [userId, agentId, name, source_type, action_pattern]);

    return res.status(201).json({
      source: result.rows[0],
      message: 'Witness source registered. ' +
        'ARIA will now create verification checks for matching agent events.'
    });
  } catch (err) {
    console.error('[witness] POST /sources error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({ error: 'Service unavailable', code: 'INTERNAL_ERROR' });
  }
});

// POST /v1/witness/confirm/:checkId — External source confirms event count
witnessRouter.post('/confirm/:checkId', async (req, res) => {
  const { confirmed_count, notes } = req.body as {
    confirmed_count?: number;
    notes?: string;
  };

  if (typeof confirmed_count !== 'number' || confirmed_count < 0) {
    return res.status(400).json({
      error: 'confirmed_count must be a non-negative number',
      code: 'INVALID_COUNT'
    });
  }

  try {
    const result = await resolveWitnessCheck(
      req.params.checkId,
      confirmed_count,
      notes
    );

    return res.json({
      checkId: req.params.checkId,
      status: result.status,
      delta: result.delta,
      message: result.status === 'verified'
        ? 'Event counts verified — agent behavior confirmed'
        : `Discrepancy detected: agent reported ${result.delta} more events than confirmed`
    });
  } catch (err) {
    console.error('[witness] POST /confirm error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({ error: 'Service unavailable', code: 'INTERNAL_ERROR' });
  }
});

// GET /v1/witness/checks — List verification checks
witnessRouter.get('/checks', async (req, res) => {
  try {
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );
    const userId = keyResult.rows[0]?.user_id;

    const result = await query(`
      SELECT
        wc.id, wc.action_pattern, wc.window_start,
        wc.window_end, wc.agent_reported,
        wc.witness_confirmed, wc.status,
        wc.discrepancy_delta, wc.created_at,
        a.name AS agent_name, a.did AS agent_did,
        ws.name AS source_name
      FROM witness_checks wc
      JOIN agents a ON a.id = wc.agent_id
      JOIN witness_sources ws ON ws.id = wc.witness_source_id
      WHERE a.user_id = $1
      ORDER BY wc.created_at DESC
      LIMIT 50
    `, [userId]);

    return res.json({ checks: result.rows });
  } catch (err) {
    console.error('[witness] GET /checks error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({ error: 'Service unavailable', code: 'INTERNAL_ERROR' });
  }
});

// GET /v1/witness/agents/:did — Witness summary for agent
witnessRouter.get('/agents/:did', async (req, res) => {
  try {
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );
    const userId = keyResult.rows[0]?.user_id ?? null;

    const agentResult = await query<{ id: string }>(
      `SELECT id FROM agents
       WHERE did = $1 AND (
         (user_id = $2 AND $2 IS NOT NULL)
         OR api_key_id = $3
       )`,
      [req.params.did, userId, req.apiKeyId]
    );

    if (!agentResult.rows[0]) {
      return res.status(404).json({ error: 'Agent not found', code: 'NOT_FOUND' });
    }

    const summary = await getWitnessSummary(agentResult.rows[0].id);

    return res.json({
      agent_did: req.params.did,
      witness: summary,
      verification_status:
        summary.total_checks === 0 ? 'unregistered' :
        summary.discrepancies > 0  ? 'discrepancy'  :
        summary.pending > 0        ? 'pending'       :
        'verified'
    });
  } catch (err) {
    console.error('[witness] GET /agents/:did error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({ error: 'Service unavailable', code: 'INTERNAL_ERROR' });
  }
});
