import { Router } from 'express';
import { query } from '../db/pool.js';
import { requireApiKey } from '../middleware/auth.js';
import { requireFeature } from '../middleware/plans.js';
import {
  createTemporalAnchor,
  verifyEventProof,
  getAnchorSummary
} from '../services/temporal-anchor.js';

export const temporalRouter = Router();
temporalRouter.use(requireApiKey);

// POST /v1/temporal/anchor/:did — manually trigger anchor creation
temporalRouter.post('/anchor/:did', requireFeature('temporalAnchor'), async (req, res) => {
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
      return res.status(404).json({
        error: 'Agent not found',
        code: 'NOT_FOUND'
      });
    }

    const anchorHash = await createTemporalAnchor(
      agentResult.rows[0].id
    );

    if (!anchorHash) {
      return res.json({
        message: 'No new events to anchor',
        anchor_hash: null
      });
    }

    return res.status(201).json({
      anchor_hash: anchorHash,
      created_at: new Date().toISOString(),
      message: 'Temporal anchor created successfully'
    });
  } catch (err) {
    console.error('[temporal] POST /anchor error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

// GET /v1/temporal/verify/:eventId — verify event is in anchor chain
temporalRouter.get('/verify/:eventId', async (req, res) => {
  try {
    const proof = await verifyEventProof(req.params.eventId);
    return res.json(proof);
  } catch (err) {
    console.error('[temporal] GET /verify error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

// GET /v1/temporal/anchors/:did — anchor chain summary
temporalRouter.get('/anchors/:did', async (req, res) => {
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
      return res.status(404).json({
        error: 'Agent not found',
        code: 'NOT_FOUND'
      });
    }

    const summary = await getAnchorSummary(agentResult.rows[0].id);

    return res.json({
      agent_did: req.params.did,
      temporal_anchor: summary
    });
  } catch (err) {
    console.error('[temporal] GET /anchors error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

// GET /v1/temporal/anchors/:did/list — list all anchors
temporalRouter.get('/anchors/:did/list', async (req, res) => {
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
      return res.status(404).json({
        error: 'Agent not found',
        code: 'NOT_FOUND'
      });
    }

    const anchors = await query(`
      SELECT
        id, anchor_hash, event_count,
        last_event_id, anchor_time,
        previous_anchor_id, metadata
      FROM temporal_anchors
      WHERE agent_id = $1
      ORDER BY anchor_time DESC
      LIMIT 20
    `, [agentResult.rows[0].id]);

    return res.json({
      agent_did: req.params.did,
      anchors: anchors.rows
    });
  } catch (err) {
    console.error('[temporal] GET /anchors/list error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});
