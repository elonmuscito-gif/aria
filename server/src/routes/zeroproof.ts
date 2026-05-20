import { Router } from 'express';
import { query } from '../db/pool.js';
import { requireApiKey } from '../middleware/auth.js';
import { requireFeature } from '../middleware/plans.js';
import {
  generateInnocenceProof,
  generateConsistencyProof,
  generateLimitsProof,
  verifyZeroProof
} from '../services/zeroproof.js';

export const zeroproofRouter = Router();
zeroproofRouter.use(requireApiKey);

async function getAgentId(
  did: string,
  userId: string | null,
  apiKeyId: string
): Promise<string | null> {
  const result = await query<{ id: string }>(
    `SELECT id FROM agents
     WHERE did = $1 AND (
       (user_id = $2 AND $2 IS NOT NULL)
       OR api_key_id = $3
     )`,
    [did, userId, apiKeyId]
  );
  return result.rows[0]?.id ?? null;
}

async function getUserId(
  apiKeyId: string
): Promise<string | null> {
  const result = await query<{ user_id: string | null }>(
    'SELECT user_id FROM api_keys WHERE id = $1',
    [apiKeyId]
  );
  return result.rows[0]?.user_id ?? null;
}

zeroproofRouter.post('/innocence', requireFeature('zeroproof'), async (req, res) => {
  const { agentDid, forbidden_pattern, window_days } =
    req.body as {
      agentDid?: string;
      forbidden_pattern?: string;
      window_days?: number;
    };

  if (!agentDid || !forbidden_pattern) {
    return res.status(400).json({
      error: 'agentDid and forbidden_pattern required',
      code: 'MISSING_FIELDS'
    });
  }

  try {
    const userId = await getUserId(req.apiKeyId);
    const agentId = await getAgentId(
      agentDid, userId, req.apiKeyId
    );

    if (!agentId) {
      return res.status(404).json({
        error: 'Agent not found',
        code: 'NOT_FOUND'
      });
    }

    const proof = await generateInnocenceProof(
      agentId,
      forbidden_pattern,
      window_days ?? 30
    );

    return res.status(201).json(proof);
  } catch (err) {
    console.error('[zeroproof] POST /innocence error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

zeroproofRouter.post('/consistency', requireFeature('zeroproof'), async (req, res) => {
  const { agentDid, min_success_rate, window_days } =
    req.body as {
      agentDid?: string;
      min_success_rate?: number;
      window_days?: number;
    };

  if (!agentDid) {
    return res.status(400).json({
      error: 'agentDid required',
      code: 'MISSING_FIELDS'
    });
  }

  try {
    const userId = await getUserId(req.apiKeyId);
    const agentId = await getAgentId(
      agentDid, userId, req.apiKeyId
    );

    if (!agentId) {
      return res.status(404).json({
        error: 'Agent not found',
        code: 'NOT_FOUND'
      });
    }

    const proof = await generateConsistencyProof(
      agentId,
      min_success_rate ?? 90,
      window_days ?? 30
    );

    return res.status(201).json(proof);
  } catch (err) {
    console.error('[zeroproof] POST /consistency error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

zeroproofRouter.post('/limits', requireFeature('zeroproof'), async (req, res) => {
  const { agentDid, max_events_per_hour, window_days } =
    req.body as {
      agentDid?: string;
      max_events_per_hour?: number;
      window_days?: number;
    };

  if (!agentDid) {
    return res.status(400).json({
      error: 'agentDid required',
      code: 'MISSING_FIELDS'
    });
  }

  try {
    const userId = await getUserId(req.apiKeyId);
    const agentId = await getAgentId(
      agentDid, userId, req.apiKeyId
    );

    if (!agentId) {
      return res.status(404).json({
        error: 'Agent not found',
        code: 'NOT_FOUND'
      });
    }

    const proof = await generateLimitsProof(
      agentId,
      max_events_per_hour ?? 100,
      window_days ?? 30
    );

    return res.status(201).json(proof);
  } catch (err) {
    console.error('[zeroproof] POST /limits error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

zeroproofRouter.get('/verify/:proofId', async (req, res) => {
  try {
    const result = await verifyZeroProof(req.params.proofId);
    return res.json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown';
    if (msg === 'Proof not found') {
      return res.status(404).json({
        error: 'Proof not found',
        code: 'NOT_FOUND'
      });
    }
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

zeroproofRouter.get('/list/:did', async (req, res) => {
  try {
    const userId = await getUserId(req.apiKeyId);
    const agentId = await getAgentId(
      req.params.did, userId, req.apiKeyId
    );

    if (!agentId) {
      return res.status(404).json({
        error: 'Agent not found',
        code: 'NOT_FOUND'
      });
    }

    const proofs = await query(`
      SELECT id, proof_type, claim, merkle_root,
             verified, created_at, expires_at
      FROM zero_proofs
      WHERE agent_id = $1
        AND expires_at > NOW()
      ORDER BY created_at DESC
      LIMIT 20
    `, [agentId]);

    return res.json({
      agent_did: req.params.did,
      proofs: proofs.rows
    });
  } catch (err) {
    console.error('[zeroproof] GET /list error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});
