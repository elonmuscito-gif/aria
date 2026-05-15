import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import { query } from '../db/pool.js';
import { requireApiKey } from '../middleware/auth.js';
import { sendGateRequestEmail } from '../services/email.js';
import { getRedisClient } from '../utils/redis.js';

export const gateRouter = Router();

const APPROVAL_TIMEOUT_MINUTES = 5;

const _gateRedis = getRedisClient();

const gateRequestLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const cfIp = req.headers['cf-connecting-ip'];
    if (cfIp && typeof cfIp === 'string') return cfIp;
    return req.ip?.replace(/^::ffff:/, '') ?? 'unknown';
  },
  store: _gateRedis ? (() => {
    try {
      return new RedisStore({
        sendCommand: (...args: string[]) => (_gateRedis as any).call(...args)
      });
    } catch { return undefined; }
  })() : undefined,
  handler: (_req, res) => {
    res.status(429).json({
      error: 'Too many gate requests. Max 10 per minute.',
      code: 'RATE_LIMITED'
    });
  }
});

function gatePage(
  title: string,
  message: string,
  color: string
): string {
  return `<!DOCTYPE html>
<html>
<head>
  <title>ARIA Gate</title>
  <meta charset="UTF-8">
  <style>
    body {
      font-family: system-ui, sans-serif;
      background: #04060d;
      color: #f8f4ee;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
    }
    .card {
      background: #07090f;
      border: 1px solid rgba(255,255,255,0.08);
      border-top: 3px solid ${color};
      border-radius: 8px;
      padding: 40px;
      text-align: center;
      max-width: 420px;
      width: 90%;
    }
    h1 { color: ${color}; margin-bottom: 16px; font-size: 22px; }
    p { color: rgba(248,244,238,0.65); line-height: 1.6;
        margin-bottom: 24px; }
    a {
      display: inline-block;
      padding: 10px 24px;
      border: 1px solid rgba(201,168,76,0.3);
      color: #c9a84c;
      text-decoration: none;
      border-radius: 5px;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>${title}</h1>
    <p>${message}</p>
    <a href="/app">Back to dashboard</a>
  </div>
</body>
</html>`;
}

// ── GET /v1/gate/approve/:id — Email link: directly approves the request ──
gateRouter.get('/approve/:id', async (req, res) => {
  try {
    const result = await query<{
      id: string; agent_name: string; action: string;
    }>(
      `UPDATE gate_requests
       SET status = 'approved',
           resolved_at = NOW(),
           resolved_by = 'email_link'
       WHERE id = $1
         AND status = 'pending'
         AND timeout_at > NOW()
       RETURNING id, agent_name, action`,
      [req.params.id]
    );

    if (!result.rows[0]) {
      return res.send(gatePage(
        'Already Resolved',
        'This request has already been resolved or expired.',
        '#ffbd2e'
      ));
    }

    const r = result.rows[0];
    return res.send(gatePage(
      'Action Approved',
      `Agent <strong>${r.agent_name}</strong> will proceed with
       <span style="font-family:monospace;color:#e8c87a">
       ${r.action}</span>.`,
      '#28c841'
    ));
  } catch (err) {
    console.error('[gate] GET /approve error:', err);
    return res.status(500).send('Server error');
  }
});

// ── GET /v1/gate/deny-page/:id — Email link: directly denies the request ──
gateRouter.get('/deny-page/:id', async (req, res) => {
  try {
    const result = await query<{
      id: string; agent_name: string; action: string;
    }>(
      `UPDATE gate_requests
       SET status = 'denied',
           resolved_at = NOW(),
           resolved_by = 'email_link'
       WHERE id = $1
         AND status = 'pending'
       RETURNING id, agent_name, action`,
      [req.params.id]
    );

    if (!result.rows[0]) {
      return res.send(gatePage(
        'Already Resolved',
        'This request has already been resolved or expired.',
        '#ffbd2e'
      ));
    }

    const r = result.rows[0];
    return res.send(gatePage(
      'Action Denied',
      `Agent <strong>${r.agent_name}</strong> has been blocked
       from executing
       <span style="font-family:monospace;color:#e8c87a">
       ${r.action}</span>.`,
      '#c94c4c'
    ));
  } catch (err) {
    console.error('[gate] GET /deny-page error:', err);
    return res.status(500).send('Server error');
  }
});

// ── POST /v1/gate/approve/:id (no auth — UUID is the secret) ─────────────
gateRouter.post('/approve/:id', async (req, res) => {
  try {
    const result = await query<{ id: string; status: string }>(
      `UPDATE gate_requests
       SET status = 'approved',
           resolved_at = NOW(),
           resolved_by = 'email-link'
       WHERE id = $1
         AND status = 'pending'
         AND timeout_at > NOW()
       RETURNING id, status`,
      [req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: 'Gate request not found, already resolved, or timed out',
        code: 'NOT_FOUND'
      });
    }

    return res.json({
      requestId: result.rows[0].id,
      status: 'approved',
      message: 'Action approved'
    });
  } catch (err) {
    console.error('[gate] POST /approve error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

// ── POST /v1/gate/deny/:id (no auth — UUID is the secret) ────────────────
gateRouter.post('/deny/:id', async (req, res) => {
  try {
    const result = await query<{ id: string; status: string }>(
      `UPDATE gate_requests
       SET status = 'denied',
           resolved_at = NOW(),
           resolved_by = 'email-link'
       WHERE id = $1
         AND status = 'pending'
       RETURNING id, status`,
      [req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: 'Gate request not found or already resolved',
        code: 'NOT_FOUND'
      });
    }

    return res.json({
      requestId: result.rows[0].id,
      status: 'denied',
      message: 'Action denied'
    });
  } catch (err) {
    console.error('[gate] POST /deny error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

// ── POST /v1/gate/request ─────────────────────────────────────────────────
// SDK calls this when agent attempts a gated action.
// Returns { requestId, status } immediately.
gateRouter.post('/request', gateRequestLimiter, requireApiKey, async (req, res) => {
  const { agentDid, action, context } = req.body as {
    agentDid?: string;
    action?: string;
    context?: Record<string, unknown>;
  };

  if (!agentDid || !action) {
    return res.status(400).json({
      error: 'agentDid and action are required',
      code: 'MISSING_FIELDS'
    });
  }

  try {
    // Get agent and owner info
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );
    const userId = keyResult.rows[0]?.user_id ?? null;

    const agentResult = await query<{
      id: string; name: string; did: string;
    }>(
      `SELECT id, name, did FROM agents
       WHERE did = $1 AND (
         user_id = $2 OR api_key_id = $3
       )`,
      [agentDid, userId, req.apiKeyId]
    );

    if (!agentResult.rows[0]) {
      return res.status(404).json({
        error: 'Agent not found',
        code: 'AGENT_NOT_FOUND'
      });
    }

    const agent = agentResult.rows[0];
    const timeoutAt = new Date(
      Date.now() + APPROVAL_TIMEOUT_MINUTES * 60 * 1000
    );

    // Check if action matches auto_block rules
    const blockRules = await query<{ id: string }>(
      `SELECT id FROM gate_rules
       WHERE agent_id = $1
       AND rule_type = 'auto_block'
       AND ($2 LIKE REPLACE(action_pattern, '*', '%')
            OR action_pattern = $2)`,
      [agent.id, action]
    );

    if (blockRules.rows.length > 0) {
      // Auto-block — no approval needed
      const result = await query<{ id: string }>(
        `INSERT INTO gate_requests
           (agent_id, agent_name, agent_did, action, context,
            status, timeout_at, user_id, owner_email)
         VALUES ($1,$2,$3,$4,$5,'auto_blocked',$6,$7,$8)
         RETURNING id`,
        [agent.id, agent.name, agent.did, action,
         context ?? {}, timeoutAt, userId, req.ownerEmail]
      );
      return res.status(200).json({
        requestId: result.rows[0]!.id,
        status: 'auto_blocked',
        message: 'Action automatically blocked by gate rules'
      });
    }

    // Create pending gate request
    const result = await query<{ id: string }>(
      `INSERT INTO gate_requests
         (agent_id, agent_name, agent_did, action, context,
          status, timeout_at, user_id, owner_email)
       VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,$8)
       RETURNING id`,
      [agent.id, agent.name, agent.did, action,
       context ?? {}, timeoutAt, userId, req.ownerEmail]
    );

    const requestId = result.rows[0]!.id;

    // Send email notification (non-blocking)
    sendGateRequestEmail(
      req.ownerEmail,
      agent.name,
      action,
      requestId,
      APPROVAL_TIMEOUT_MINUTES
    ).catch((err: unknown) => {
      console.error('[gate] Failed to send email:',
        err instanceof Error ? err.message : 'Unknown');
    });

    return res.status(201).json({
      requestId,
      status: 'pending',
      timeoutAt: timeoutAt.toISOString(),
      message: 'Approval request created. Owner has been notified.'
    });
  } catch (err) {
    console.error('[gate] POST /request error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

// ── GET /v1/gate/request/:id ──────────────────────────────────────────────
// SDK polls this to check approval status.
gateRouter.get('/request/:id', requireApiKey, async (req, res) => {
  try {
    const result = await query<{
      id: string; status: string; timeout_at: string;
      resolved_at: string | null; action: string;
      agent_name: string;
    }>(
      `SELECT id, status, timeout_at, resolved_at,
              action, agent_name
       FROM gate_requests
       WHERE id = $1 AND owner_email = $2`,
      [req.params.id, req.ownerEmail]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: 'Gate request not found',
        code: 'NOT_FOUND'
      });
    }

    const request = result.rows[0];

    // Auto-timeout if expired
    if (
      request.status === 'pending' &&
      new Date() > new Date(request.timeout_at)
    ) {
      await query(
        `UPDATE gate_requests
         SET status = 'timeout', resolved_at = NOW()
         WHERE id = $1`,
        [request.id]
      );
      request.status = 'timeout';
    }

    return res.json({
      requestId: request.id,
      status: request.status,
      action: request.action,
      agentName: request.agent_name,
      timeoutAt: request.timeout_at,
      resolvedAt: request.resolved_at
    });
  } catch (err) {
    console.error('[gate] GET /request/:id error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

// ── GET /v1/gate/pending ──────────────────────────────────────────────────
// Dashboard lists pending approvals for this user.
gateRouter.get('/pending', requireApiKey, async (req, res) => {
  try {
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );
    const userId = keyResult.rows[0]?.user_id ?? null;

    // Auto-expire timed out requests first
    await query(
      `UPDATE gate_requests
       SET status = 'timeout', resolved_at = NOW()
       WHERE status = 'pending'
         AND timeout_at < NOW()
         AND (user_id = $1 OR owner_email = $2)`,
      [userId, req.ownerEmail]
    );

    const result = await query(
      `SELECT id, agent_name, agent_did, action,
              status, requested_at, timeout_at, context
       FROM gate_requests
       WHERE status = 'pending'
         AND (user_id = $1 OR owner_email = $2)
       ORDER BY requested_at DESC
       LIMIT 20`,
      [userId, req.ownerEmail]
    );

    return res.json({ requests: result.rows });
  } catch (err) {
    console.error('[gate] GET /pending error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});
